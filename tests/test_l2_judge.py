"""L2 judge twin tests (grounding gate + narrow L2 judge).

(a) steered+L1->finding; (b) steered no L1->no finding (L2 alone<0.6);
(c) not steered->no L2; (d) unparseable judge->no signal/no crash;
(e) non-L2 class->judge not called; + judge token accounting.
"""
from __future__ import annotations

from mcp_redteam.agent.verifier import JudgeVerdict, build_findings
from mcp_redteam.contracts import AttackTrace, McpCall, VulnClass
from mcp_redteam.orchestrator.budget import TokenBudget


def _note(content: str, result: str = "ok") -> McpCall:
    return McpCall(kind="call_tool", name="add_note", args={"content": content}, result_text=result, elapsed_ms=1)


def _read(text: str) -> McpCall:
    return McpCall(kind="read_resource", name=None, args=None, result_text=text, elapsed_ms=1)


def _indirect(attack_calls, final: str = "") -> AttackTrace:
    return AttackTrace(
        vuln_class=VulnClass.INDIRECT_INJECTION,
        target="notes://x",
        strategy_card_slug="indirect_injection",
        recon_calls=[],
        attack_calls=attack_calls,
        final_llm_output=final,
    )


_L1_CALLS = [_note("hello INJECTION_MARKER_abc1"), _read("latest note: hello INJECTION_MARKER_abc1")]
_BENIGN_CALLS = [_note("hello world"), _read("latest note: hello world")]


class FakeJudge:
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = 0

    def __call__(self, trace, budget):
        self.calls += 1
        if budget is not None:
            budget.add("judge", 10, 5)
        return self.verdict


def test_a_steered_with_l1_makes_finding():
    j = FakeJudge(JudgeVerdict(steered=True, evidence_call_index=1, reason="r"))
    b = TokenBudget(max_tokens_total=99999)
    f, _ = build_findings([_indirect(_L1_CALLS)], trace_dir=None, budget=b, judge_fn=j)
    assert f, "expected finding (L1+L2)"
    ids = {s.signal_id for s in f[0].signals}
    assert "stored_injection_roundtrip" in ids and "llm_judged_injection" in ids, ids
    assert f[0].confidence >= 0.6, f[0].confidence
    assert j.calls == 1
    assert b.judge_tokens == 15 and b.attacker_tokens == 0, (b.judge_tokens, b.attacker_tokens)


def test_b_steered_without_l1_no_finding():
    j = FakeJudge(JudgeVerdict(steered=True, evidence_call_index=0, reason="r"))
    f, per = build_findings([_indirect(_BENIGN_CALLS)], trace_dir=None, judge_fn=j)
    assert not f, "L2 alone must not cross 0.6"
    sigs = per["indirect_injection::notes://x"]
    assert any(s.signal_id == "llm_judged_injection" for s in sigs), "L2 signal still recorded in traces"


def test_c_not_steered_no_l2():
    j = FakeJudge(JudgeVerdict(steered=False, evidence_call_index=None, reason=""))
    f, per = build_findings([_indirect(_BENIGN_CALLS)], trace_dir=None, judge_fn=j)
    assert not f
    assert not any(s.signal_id == "llm_judged_injection" for s in per["indirect_injection::notes://x"])


def test_d_unparseable_judge_no_signal_no_crash():
    j = FakeJudge(None)
    f, per = build_findings([_indirect(_BENIGN_CALLS)], trace_dir=None, judge_fn=j)
    assert not f
    assert not any(s.signal_id == "llm_judged_injection" for s in per["indirect_injection::notes://x"])


def test_e_non_l2_class_judge_not_called():
    j = FakeJudge(JudgeVerdict(steered=True, evidence_call_index=0, reason="r"))
    trace = AttackTrace(
        vuln_class=VulnClass.PATH_TRAVERSAL,
        target="read_file",
        strategy_card_slug="path_traversal",
        recon_calls=[],
        attack_calls=[_note("x")],
        final_llm_output="",
    )
    _, _ = build_findings([trace], trace_dir=None, judge_fn=j)
    assert j.calls == 0, "judge must not run for non-L2 classes"


def test_j_steered_out_of_range_index_downgraded():
    """Anti-hallucination gate: a steered verdict citing a call index that
    does not exist must NOT add an L2 signal (the judge LLM may fabricate an
    anchor). The verdict is still persisted on the trace for debugging, but
    it cannot contribute confidence to a finding."""
    j = FakeJudge(JudgeVerdict(steered=True, evidence_call_index=999, reason="r"))
    trace = _indirect(_BENIGN_CALLS)
    f, per = build_findings([trace], trace_dir=None, judge_fn=j)
    assert not f
    sigs = per["indirect_injection::notes://x"]
    assert not any(
        s.signal_id == "llm_judged_injection" for s in sigs
    ), "out-of-range citation must not become a signal"
    assert trace.judge_verdict is not None, "verdict still persisted for debugging"
    assert trace.judge_verdict.steered is True
    assert trace.judge_verdict.evidence_call_index == 999


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    print("all L2 judge tests PASS")


def test_f_verdict_persisted_when_steered():
    """L2 judge verdict must be written back to trace.judge_verdict so a
    later debug pass (or a second scan reading the saved trace) sees what the
    judge actually said, not just the L2 signal we ended up emitting."""
    verdict = JudgeVerdict(steered=True, evidence_call_index=1, reason="narrative test reason")
    j = FakeJudge(verdict)
    trace = _indirect(_L1_CALLS)
    f, _ = build_findings([trace], trace_dir=None, judge_fn=j)
    assert trace.judge_verdict is not None, "verdict must be persisted on trace"
    assert trace.judge_verdict.steered is True
    assert trace.judge_verdict.evidence_call_index == 1
    assert trace.judge_verdict.reason == "narrative test reason"
    assert f, "L1+L2 should produce a finding"


def test_g_verdict_persisted_when_not_steered():
    """A non-steering verdict (steered=False) must ALSO be persisted. Otherwise
    the only debug signal for a 9006/9010 miss is "the signal didn't fire",
    which doesn't tell us what the judge thought."""
    verdict = JudgeVerdict(steered=False, evidence_call_index=None, reason="no steering here")
    j = FakeJudge(verdict)
    trace = _indirect(_BENIGN_CALLS)
    f, _ = build_findings([trace], trace_dir=None, judge_fn=j)
    assert trace.judge_verdict is not None
    assert trace.judge_verdict.steered is False
    assert trace.judge_verdict.reason == "no steering here"
    assert not f, "no L1 + L2 not-steered = no finding"


def test_h_verdict_persisted_when_judge_unparseable():
    """When the judge returns None (LLM error / JSON unparseable), we must
    not pretend we have a verdict. trace.judge_verdict should stay None so
    downstream consumers can distinguish "judge said no" from "judge silent"."""
    j = FakeJudge(None)
    trace = _indirect(_BENIGN_CALLS)
    build_findings([trace], trace_dir=None, judge_fn=j)
    assert trace.judge_verdict is None


def test_i_judge_verdict_serialized_in_trace_json():
    """A trace saved to disk must carry judge_verdict in its JSON. This is
    the whole point of the M2.5 fix: debugging 9006/9010 must not require
    re-running with a side-channel capture."""
    import json
    verdict = JudgeVerdict(steered=False, evidence_call_index=2, reason="r")
    j = FakeJudge(verdict)
    trace = _indirect(_BENIGN_CALLS)
    build_findings([trace], trace_dir=None, judge_fn=j)
    blob = json.loads(trace.model_dump_json())
    assert "judge_verdict" in blob
    assert blob["judge_verdict"] is not None
    assert blob["judge_verdict"]["steered"] is False
    assert blob["judge_verdict"]["evidence_call_index"] == 2
