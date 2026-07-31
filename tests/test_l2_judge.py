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


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS", name)
    print("all L2 judge tests PASS")
