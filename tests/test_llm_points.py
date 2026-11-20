"""Unit tests for Stage-2 LLM decision points (pure parse / validate / ground).

The LLM wrappers' network behavior is not unit-tested; the parsing,
target-validation and grounding gates are - they are where hallucination and
ungrounded findings would leak in. One wrapper-level contract IS covered with
a fake client (same pattern as test_m3_judge): evidence_verdict's judge call
must disable DashScope hidden thinking and stay a no-op elsewhere
(eval/jev_probe: 1240 tok / 22.5s per call ON vs 122 tok / 2.7s OFF).
"""

from __future__ import annotations

import types

import pytest

from mcp_redteam.agent.llm_points import (
    evidence_verdict,
    ground_evidence_verdict,
    hypotheses_to_candidates,
    parse_evidence_verdict,
    parse_hypotheses,
)
from mcp_redteam.contracts import (
    AttackTrace,
    LlmEvidenceVerdict,
    LlmHypothesis,
    McpCall,
    VulnClass,
)


def _mkcall(text: str, name: str = "read_vault", args: dict | None = None) -> McpCall:
    return McpCall(
        kind="call_tool", name=name, args=args or {}, result_text=text, elapsed_ms=1,
    )


# ── hypothesis parsing ───────────────────────────────────────────────────────

def test_parse_hypotheses_keeps_only_grounded():
    content = (
        '{"hypotheses": ['
        '{"vuln_class": "auth_bypass", "target": "read_vault", "reason": "try owner=empty"},'
        '{"vuln_class": "ssrf", "target": "fake_tool", "reason": "invented"},'
        '{"vuln_class": "not_a_class", "target": "read_vault", "reason": "bad class"}'
        "]}"
    )
    hs = parse_hypotheses(content, ["read_vault"], [], set())
    assert len(hs) == 1
    assert hs[0].vuln_class == VulnClass.AUTH_BYPASS
    assert hs[0].target == "read_vault"


def test_parse_hypotheses_skips_existing_and_dedupes():
    content = (
        '{"hypotheses": ['
        '{"vuln_class": "auth_bypass", "target": "read_vault", "reason": "r"},'
        '{"vuln_class": "auth_bypass", "target": "read_vault", "reason": "dup"}'
        "]}"
    )
    existing = {(VulnClass.AUTH_BYPASS.value, "read_vault")}
    assert parse_hypotheses(content, ["read_vault"], [], existing) == []
    hs = parse_hypotheses(content, ["read_vault"], [], set())
    assert len(hs) == 1


def test_parse_hypotheses_caps_count():
    content = (
        '{"hypotheses": ['
        '{"vuln_class": "auth_bypass", "target": "a", "reason": "1"},'
        '{"vuln_class": "auth_bypass", "target": "b", "reason": "2"},'
        '{"vuln_class": "auth_bypass", "target": "c", "reason": "3"}'
        "]}"
    )
    hs = parse_hypotheses(content, ["a", "b", "c"], [], set(), max_hypotheses=2)
    assert len(hs) == 2


def test_hypotheses_to_candidates_tags_and_scores():
    hs = [LlmHypothesis(vuln_class=VulnClass.AUTH_BYPASS, target="read_vault", reason="r")]
    cs = hypotheses_to_candidates(hs, ["read_vault"], [], "llm-hyp")
    assert len(cs) == 1
    assert cs[0].target_kind == "tool"
    assert cs[0].score == 0.99
    assert cs[0].reason.startswith("[llm-hyp]")


def test_hypotheses_to_candidates_resource_kind():
    hs = [LlmHypothesis(vuln_class=VulnClass.DIRECT_PROMPT_INJECTION, target="notes://{id}", reason="r")]
    cs = hypotheses_to_candidates(hs, [], ["notes://{id}"], "llm-hyp")
    assert cs[0].target_kind == "resource"


# ── evidence verdict parsing / grounding ─────────────────────────────────────

def test_parse_evidence_verdict_grounded():
    calls = [
        McpCall(kind="list_tools", result_text="- read_vault: read secret by name", elapsed_ms=1),
        _mkcall("s3cr3t-abc123", args={"owner": "", "name": "admin_vault"}),
    ]
    content = (
        '{"is_finding": true, "vuln_class": "auth_bypass", "evidence_call_index": 1, '
        '"evidence_text": "s3cr3t-abc123", "confidence": 0.9, "reason": "empty owner read secret"}'
    )
    v = parse_evidence_verdict(content, calls)
    assert v is not None and v.is_finding
    assert v.evidence_call_index == 1
    assert v.vuln_class == VulnClass.AUTH_BYPASS


def test_parse_evidence_verdict_drops_ungrounded():
    calls = [_mkcall("ok", args={"owner": "admin", "name": "x"})]
    content = (
        '{"is_finding": true, "vuln_class": "auth_bypass", "evidence_call_index": 0, '
        '"evidence_text": "NOT IN RESULT", "confidence": 0.9, "reason": "x"}'
    )
    assert parse_evidence_verdict(content, calls) is None


def test_parse_evidence_verdict_no_finding():
    content = '{"is_finding": false}'
    assert parse_evidence_verdict(content, [_mkcall("x")]) is not None
    assert parse_evidence_verdict(content, [_mkcall("x")]).is_finding is False


def test_ground_rejects_bad_index_and_empty_text():
    calls = [_mkcall("secret")]
    v1 = LlmEvidenceVerdict(
        is_finding=True, vuln_class=VulnClass.AUTH_BYPASS,
        evidence_call_index=5, evidence_text="secret", confidence=0.9,
    )
    assert not ground_evidence_verdict(v1, calls)
    v2 = LlmEvidenceVerdict(
        is_finding=True, vuln_class=VulnClass.AUTH_BYPASS,
        evidence_call_index=0, evidence_text="", confidence=0.9,
    )
    assert not ground_evidence_verdict(v2, calls)


# ── evidence_verdict judge-call kwargs contract (fake client) ────────────────

@pytest.fixture(autouse=True)
def _no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """chat_create_with_retry sleeps >=2s between calls; disable in tests."""
    monkeypatch.setattr("mcp_redteam.models.chat._MIN_INTERVAL_SEC", 0.0)


class _JudgeMsg:
    def __init__(self, content: str) -> None:
        self.content = content


class _JudgeChoice:
    def __init__(self, content: str) -> None:
        self.message = _JudgeMsg(content)


class _JudgeResp:
    def __init__(self, content: str) -> None:
        self.choices = [_JudgeChoice(content)]
        self.usage = None


class _JudgeCompletions:
    def __init__(self, response: _JudgeResp) -> None:
        self.response = response
        self.captured: dict = {}

    def create(self, **kwargs: object) -> _JudgeResp:
        self.captured = kwargs
        return self.response


class _JudgeClient:
    def __init__(self, completions: _JudgeCompletions) -> None:
        self.chat = types.SimpleNamespace(completions=completions)


def _judge_spec(provider: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        model="judge-x", temperature=0.0, seed=None, provider=provider,
    )


def _empty_trace() -> AttackTrace:
    # strategy_card_slug must equal vuln_class.value (AttackTrace validator).
    return AttackTrace(
        vuln_class=VulnClass.AUTH_BYPASS, target="read_vault",
        strategy_card_slug="auth_bypass",
    )


@pytest.mark.parametrize("provider,expect_kwarg", [
    ("dashscope", True),
    ("deepseek", False),
])
def test_evidence_verdict_thinking_kwarg_per_provider(
    provider: str, expect_kwarg: bool,
):
    completions = _JudgeCompletions(_JudgeResp('{"is_finding": false}'))
    verdict = evidence_verdict(
        _empty_trace(), _JudgeClient(completions), _judge_spec(provider),
    )
    assert verdict is not None and verdict.is_finding is False
    if expect_kwarg:
        assert completions.captured["extra_body"] == {"enable_thinking": False}
    else:
        assert "extra_body" not in completions.captured
