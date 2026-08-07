"""LLM-hypothesis budget pool (fix for the fetch real-target finding).

Regression: on the real fetch target, llm_points hypothesis generation gave
every LLM hypothesis score=0.99, so a WRONG LLM lead (command_injection on a
tool recon already classified as SSRF) ran first and burned the shared 30k
budget - the correct recon candidate never executed (llm round missed 3/3
while the standard scan hit on the first try). The fix bounds LLM-hypothesis
candidates to a pool (default half the attacker budget) without changing the
score order, so vault/delegate unknown-shape discovery is untouched.
"""

from __future__ import annotations

from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import VulnClass
from mcp_redteam.orchestrator.budget import TokenBudget


def _mk_candidate(origin: str = "recon") -> Candidate:
    return Candidate(
        vuln_class=VulnClass.SSRF,
        target="fetch",
        target_kind="tool",
        score=0.85,
        reason="r",
        origin=origin,  # type: ignore[arg-type]
    )


def test_candidate_origin_defaults_to_recon():
    c = _mk_candidate("recon")
    assert c.origin == "recon"
    # constructors that omit the field keep working (recon path)
    c2 = Candidate(
        vuln_class=VulnClass.SSRF, target="t", target_kind="tool",
        score=0.5, reason="r",
    )
    assert c2.origin == "recon"


def test_pool_unbounded_by_default():
    b = TokenBudget(max_tokens_total=30000)
    assert b.llm_hyp_remaining is None
    assert b.charge_llm_hyp(100, 50) is True  # no-op when unset
    assert b.attacker_tokens == 0  # charge must not double-count tokens


def test_pool_charges_and_exhausts():
    b = TokenBudget(max_tokens_total=30000, llm_hyp_remaining=1000)
    assert b.charge_llm_hyp(400, 100) is True   # 500 used, 500 left
    assert b.llm_hyp_remaining == 500
    assert b.charge_llm_hyp(400, 100) is False  # 500 used, exactly 0 left
    assert b.llm_hyp_remaining == 0
    assert b.charge_llm_hyp(1, 1) is False      # exhausted
    assert b.llm_hyp_remaining == 0             # clamps at 0


def test_pool_does_not_affect_attacker_total():
    b = TokenBudget(max_tokens_total=30000, llm_hyp_remaining=1000)
    b.charge_llm_hyp(400, 100)
    # charge_llm_hyp only consults the pool; caller still calls budget.add()
    # for the global attacker counter.
    b.add("attacker", 400, 100)
    assert b.attacker_tokens == 500


def test_pool_zero_skips_everything():
    b = TokenBudget(max_tokens_total=30000, llm_hyp_remaining=0)
    assert b.charge_llm_hyp(1, 1) is False


def test_origin_llm_hypothesis_marks_hypotheses():
    from mcp_redteam.agent.llm_points import hypotheses_to_candidates
    from mcp_redteam.contracts import LlmHypothesis

    hs = [LlmHypothesis(vuln_class=VulnClass.AUTH_BYPASS, target="fetch", reason="x")]
    cands = hypotheses_to_candidates(hs, tools=["fetch"], resources=[], tag="hyp")
    assert len(cands) == 1
    assert cands[0].origin == "llm_hypothesis"
    assert cands[0].score == 0.99


def test_resolve_llm_hyp_budget_semantics():
    from mcp_redteam.orchestrator.runner import _resolve_llm_hyp_budget

    # default: 40% of max_tokens
    assert _resolve_llm_hyp_budget(30000, None) == 12000
    # -1 disables the pool (legacy unbounded, unknown-shape experiments)
    assert _resolve_llm_hyp_budget(30000, -1) is None
    # explicit override wins
    assert _resolve_llm_hyp_budget(30000, 5000) == 5000
