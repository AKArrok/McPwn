"""M3 acceptance judge unit tests.

Covers parse_m3_report (valid JSON / code fence / regex fallback / invalid ->
None / reason truncation), assemble_report aggregation matrix (all pass, one
fail, one inconclusive, fail + inconclusive, llm_ruling override), the
make_m3_judge_fn failure path + judge-token counting, write_m3_report file
output, and that the judge fn sends the externalized system template
(HANDOFF rule 3: no inline prompt).
"""
from __future__ import annotations

import json
import types

import pytest

from mcp_redteam.judge.m3 import (
    _JUDGE_M3_SYSTEM_TMPL,
    M3JudgeInput,
    assemble_report,
    make_m3_judge_fn,
    parse_m3_report,
    write_m3_report,
)

_PASS_CRITERIA = {
    "recall_llm_ge_hardcoded": "pass",
    "fpr_llm_le_hardcoded": "pass",
    "chain_9010_real": "inconclusive",
    "avg_findings_llm_ge_hardcoded": "pass",
    "planner_non_fallback_ge_0_8": "pass",
}


@pytest.fixture(autouse=True)
def _no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """chat_create_with_retry sleeps >=2s between calls; disable in tests."""
    monkeypatch.setattr("mcp_redteam.models.chat._MIN_INTERVAL_SEC", 0.0)


def _input(**overrides: object) -> M3JudgeInput:
    data = {
        "hardcoded_summary": {"findings": 3, "recall": 0.8},
        "llm_summary": {"findings": 4, "recall": 0.8},
        "criteria": dict(_PASS_CRITERIA),
        "metrics": {
            "recall_hardcoded": 0.8,
            "recall_llm": 0.8,
            "fpr_hardcoded": 0.0,
            "fpr_llm": 0.0,
            "avg_findings_hardcoded": 3.0,
            "avg_findings_llm": 4.0,
            "planner_non_fallback_rate": 0.9,
            "hallucination_rate": 0.0,
            "n_ports_compared": 10,
        },
        "chain_excerpt": {
            "attack_calls": [{"name": "read_note"}, {"name": "send_email"}],
            "judge_verdict": {"steered": True, "evidence_call_index": 0},
            "prior_link_hints": ["note body consumed by send_email subject"],
        },
        "planner_excerpt": "decision 1: fallback; decision 2: llm",
        "planner_fallback_rate": 0.1,
        "evidence_refs": ["runs/baseline/scan_result.json", "runs/llm/scan_result.json"],
    }
    data.update(overrides)
    return M3JudgeInput(**data)


# ── parse_m3_report ──────────────────────────────────────────────────────────


def test_parse_valid_json():
    got = parse_m3_report('{"chain_9010_real": "pass", "reason": "real composition"}')
    assert got == {"chain_9010_real": "pass", "reason": "real composition"}


def test_parse_code_fence():
    got = parse_m3_report(
        '```json\n{"chain_9010_real": "fail", "reason": "no composition"}\n```'
    )
    assert got == {"chain_9010_real": "fail", "reason": "no composition"}


def test_parse_regex_fallback():
    got = parse_m3_report(
        'Verdict follows: {"chain_9010_real": "inconclusive", "reason": "no trace"} -- end'
    )
    assert got == {"chain_9010_real": "inconclusive", "reason": "no trace"}


def test_parse_invalid_returns_none():
    assert parse_m3_report("not json at all") is None
    assert parse_m3_report("") is None
    assert parse_m3_report('{"chain_9010_real": "maybe", "reason": "x"}') is None
    assert parse_m3_report('{"reason": "missing ruling key"}') is None


def test_parse_reason_truncated_to_500():
    long_reason = "x" * 600
    got = parse_m3_report(
        json.dumps({"chain_9010_real": "pass", "reason": long_reason})
    )
    assert got is not None
    assert got["chain_9010_real"] == "pass"
    assert len(got["reason"]) == 500


# ── assemble_report aggregation matrix ───────────────────────────────────────


def test_assemble_all_pass():
    criteria = {**_PASS_CRITERIA, "chain_9010_real": "pass"}
    rep = assemble_report(_input(criteria=criteria), None)
    assert rep.verdict == "pass"
    assert rep.criteria["chain_9010_real"] == "pass"


def test_assemble_one_fail_is_fail():
    criteria = {**_PASS_CRITERIA, "fpr_llm_le_hardcoded": "fail"}
    rep = assemble_report(_input(criteria=criteria), None)
    assert rep.verdict == "fail"


def test_assemble_inconclusive_without_fail_is_inconclusive():
    rep = assemble_report(_input(), None)
    assert rep.verdict == "inconclusive"
    assert rep.criteria["chain_9010_real"] == "inconclusive"


def test_assemble_fail_plus_inconclusive_is_fail():
    criteria = {
        **_PASS_CRITERIA,
        "recall_llm_ge_hardcoded": "inconclusive",
        "fpr_llm_le_hardcoded": "fail",
    }
    rep = assemble_report(_input(criteria=criteria), None)
    assert rep.verdict == "fail"


def test_assemble_llm_ruling_overrides_chain_9010():
    inp = _input()
    rep = assemble_report(
        inp,
        {"chain_9010_real": "pass", "reason": "real multi-step composition"},
    )
    assert rep.criteria["chain_9010_real"] == "pass"
    assert rep.verdict == "pass"
    assert rep.reason == "real multi-step composition"


def test_assemble_invalid_llm_ruling_ignored():
    inp = _input()
    rep = assemble_report(inp, {"chain_9010_real": "maybe", "reason": "x"})
    assert rep.criteria["chain_9010_real"] == "inconclusive"
    assert rep.reason == "x"


def test_assemble_no_llm_fallback_reason_and_metadata():
    inp = _input(planner_fallback_rate=0.23, evidence_refs=["a.json"])
    rep = assemble_report(inp, None, judge_model="m", judge_tokens=42)
    assert (
        rep.reason
        == "judge LLM unavailable; report assembled from deterministic criteria only"
    )
    assert rep.planner_fallback_rate == 0.23
    assert rep.evidence_refs == ["a.json"]
    assert rep.metrics["n_ports_compared"] == 10
    assert rep.judge_model == "m"
    assert rep.judge_tokens == 42


# ── make_m3_judge_fn ─────────────────────────────────────────────────────────


class _Msg:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _Msg(content)


class _Usage:
    def __init__(self, prompt: int, completion: int) -> None:
        self.prompt_tokens = prompt
        self.completion_tokens = completion


class _Resp:
    def __init__(self, content: str, usage: _Usage | None = None) -> None:
        self.choices = [_Choice(content)]
        self.usage = usage


class _FakeCompletions:
    def __init__(self, response: _Resp, exc: Exception | None = None) -> None:
        self.response = response
        self.exc = exc
        self.captured: dict = {}

    def create(self, **kwargs: object) -> _Resp:
        self.captured = kwargs
        if self.exc is not None:
            raise self.exc
        return self.response


class _FakeClient:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.chat = types.SimpleNamespace(completions=completions)


def _spec() -> types.SimpleNamespace:
    return types.SimpleNamespace(model="m3-judge", temperature=0.0)


def test_judge_fn_returns_none_when_llm_raises():
    completions = _FakeCompletions(_Resp("{}"), exc=RuntimeError("boom"))
    client = _FakeClient(completions)
    fn = make_m3_judge_fn(client, _spec())
    assert fn(_input()) is None


def test_judge_fn_counts_usage_tokens():
    resp = _Resp(
        '{"chain_9010_real": "pass", "reason": "real composition"}',
        usage=_Usage(120, 30),
    )
    completions = _FakeCompletions(resp)
    client = _FakeClient(completions)
    fn = make_m3_judge_fn(client, _spec())
    report = fn(_input())
    assert report is not None
    assert report.judge_tokens == 150
    assert report.judge_model == "m3-judge"
    assert report.criteria["chain_9010_real"] == "pass"


def test_judge_fn_usage_none_zero_tokens():
    resp = _Resp('{"chain_9010_real": "fail", "reason": "no composition"}')
    completions = _FakeCompletions(resp)
    client = _FakeClient(completions)
    fn = make_m3_judge_fn(client, _spec())
    report = fn(_input())
    assert report is not None
    assert report.judge_tokens == 0
    assert report.verdict == "fail"


def test_judge_fn_sends_external_system_template():
    resp = _Resp('{"chain_9010_real": "inconclusive", "reason": "no trace"}')
    completions = _FakeCompletions(resp)
    client = _FakeClient(completions)
    fn = make_m3_judge_fn(client, _spec())
    fn(_input())
    msgs = completions.captured["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"] == _JUDGE_M3_SYSTEM_TMPL.render()
    user = msgs[1]["content"]
    assert "## Code-computed criteria" in user
    assert "## Metrics" in user
    assert "## 9010 chain trace excerpt" in user
    assert "## Planner decision excerpt" in user
    assert "recall_llm_ge_hardcoded" in user


# ── write_m3_report ──────────────────────────────────────────────────────────


def test_write_m3_report_files(tmp_path):
    inp = _input()
    report = assemble_report(
        inp,
        {"chain_9010_real": "pass", "reason": "real composition"},
        judge_model="m",
        judge_tokens=7,
    )
    json_path, md_path = write_m3_report(report, tmp_path)
    assert json_path.name == "judge_report.json"
    assert md_path.name == "judge_report.md"
    assert json_path.exists() and md_path.exists()
    blob = json.loads(json_path.read_text(encoding="utf-8"))
    assert blob["verdict"] == "pass"
    assert blob["criteria"]["chain_9010_real"] == "pass"
    assert blob["planner_fallback_rate"] == 0.1
    assert blob["judge_tokens"] == 7
    md = md_path.read_text(encoding="utf-8")
    assert "# M3 Acceptance Judge Report" in md
    assert "**pass**" in md
    assert "- model: m" in md
    assert "| criterion | result |" in md
    assert "recall_llm_ge_hardcoded | pass" in md
    assert "| metric | value |" in md
    assert "chain_9010_real" in md
    assert "real composition" in md
    assert "runs/baseline/scan_result.json" in md


def test_write_m3_report_creates_parent_dirs(tmp_path):
    out = tmp_path / "nested" / "out"
    report = assemble_report(_input(), None)
    json_path, md_path = write_m3_report(report, out)
    assert json_path.parent == out
    assert json_path.exists() and md_path.exists()
