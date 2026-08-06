"""Unit tests for Stage-2 LLM decision points (pure parse / validate / ground).

The LLM wrappers themselves are not unit-tested (network); the parsing,
target-validation and grounding gates are - they are where hallucination and
ungrounded findings would leak in.
"""

from __future__ import annotations

from mcp_redteam.agent.llm_points import (
    ground_evidence_verdict,
    hypotheses_to_candidates,
    parse_evidence_verdict,
    parse_hypotheses,
)
from mcp_redteam.contracts import LlmEvidenceVerdict, LlmHypothesis, McpCall, VulnClass


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
