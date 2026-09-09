"""Graph nodes: thin closures over live handles (grill decision 4 / 甲-2).

Each node keeps the exact semantics of the ``runner.scan`` stage it wraps
(grill decision 3 / 甲: scan-level graph, ``execute_one`` stays a black
box). Live handles - session, attacker, budget, clock - arrive via
``GraphDeps`` closure injection, never through state, so the state stays
serialisable (future C stage can checkpoint it).

The four pure helpers imported from ``runner`` are safe to import here:
``runner`` lazy-imports ``langgraph.graph`` only inside ``_scan_graph``, so
by the time this module loads the runner module is fully initialised.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mcp_redteam.agent.executor import execute_one
from mcp_redteam.agent.llm_points import (
    generate_hypotheses,
    retrospective_hypotheses,
    tool_summary,
)
from mcp_redteam.agent.planner import PlannedCandidate, plan, plan_llm
from mcp_redteam.agent.recon import recon
from mcp_redteam.agent.verifier import build_findings, verify_trace
from mcp_redteam.contracts import (
    AttackTrace,
    PlannerDecision,
    ScanResult,
    TargetSpec,
    VulnClass,
)
from mcp_redteam.langgraph.state import McPwnState
from mcp_redteam.models.chat import ModelSpec
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.orchestrator.scan_meta import (
    config_snapshot,
    messages_sha1,
    safe_git_sha,
    stop_reason,
)
from mcp_redteam.targets.mcp_client import McpSession


@dataclass
class GraphDeps:
    """Live handles injected into node closures (never checkpointed).

    ``decisions`` (M3 audit) and ``result`` (scan output) are caller-owned
    mutable refs - same pattern as ``runner.scan``'s ``decisions`` param.
    """

    session: McpSession
    attacker: tuple[Any, ModelSpec]
    budget: TokenBudget
    clock: WallClock
    sse_url: str
    sandbox_root: str | None
    judge_fn: Any | None
    evidence_judge_fn: Callable[[AttackTrace], Any] | None
    evidence_judge_model: str
    decisions: list[PlannerDecision] | None
    port: int
    seed: int | None
    llm_points: bool = False
    # Connection spec (transport/url/command/env); None keeps legacy parity
    # with tests that construct GraphDeps by hand without a spec.
    spec: TargetSpec | None = None
    result: ScanResult | None = field(default=None)


def recon_node(deps: GraphDeps):
    """``agent/recon.recon``: list tools + resources, classify candidates."""

    async def node(state: McPwnState) -> dict[str, Any]:
        recon_calls, candidates, tools_seen, resources_seen, static_hits = await recon(
            deps.session
        )
        from mcp_redteam.agent.supplychain import vet_target_spec

        if deps.spec is not None:
            static_hits = static_hits + vet_target_spec(deps.spec)
        return {
            "recon_calls": recon_calls,
            "candidates": candidates,
            "tools_seen": tools_seen,
            "resources_seen": resources_seen,
            "static_hits": static_hits,
        }

    return node


def hypothesis_node(deps: GraphDeps):
    """Stage-2 LLM point 1: hypothesis generation after recon, before plan.

    Additive only - never reorders candidates (M3 permutation lesson). No-op
    unless ``llm_points`` (attacker budget, same as runner.scan).
    """

    async def node(state: McPwnState) -> dict[str, Any]:
        if not deps.llm_points:
            return {}
        extra = generate_hypotheses(
            state["candidates"],
            state["tools_seen"],
            state["resources_seen"],
            deps.attacker[0],
            deps.attacker[1],
            budget=deps.budget,
            tool_descriptions=tool_summary(state["recon_calls"]),
            sse_url=deps.sse_url,
        )
        if not extra:
            return {}
        return {"candidates": state["candidates"] + extra}

    return node


def plan_node(deps: GraphDeps):
    """``planner.plan`` / ``plan_llm`` -> ordered PlannedCandidate list."""

    async def node(state: McPwnState) -> dict[str, Any]:
        candidates = state["candidates"]
        if state.get("planner_mode") == "llm":
            planned = plan_llm(
                candidates,
                state["tools_seen"],
                state["resources_seen"],
                deps.attacker[0],
                deps.attacker[1],
                sse_url=deps.sse_url,
            )
        else:
            planned = [
                PlannedCandidate(c, "fallback")
                for c in plan(candidates, max_candidates=state.get("max_candidates", 20))
            ]
        return {"planned": planned, "executed_count": 0}

    return node


def execute_node(deps: GraphDeps):
    """``executor.execute_one`` for the next planned candidate.

    Returns ``{"traces": [trace]}`` - the operator.add reducer appends it to
    the running list; the inner ``max_inner_steps`` LLM loop stays a black
    box (grill decision 3 / 甲).

    Pre-flight guard (review fix): if budget/clock are already exhausted
    after recon+plan, or the plan is empty, skip execution - ``signal_gate``
    then routes straight to verify, mirroring ``runner.scan``'s loop-top
    break instead of running candidate 0 on an exhausted budget.
    """

    async def node(state: McPwnState) -> dict[str, Any]:
        idx = state["executed_count"]
        planned = state["planned"]
        if deps.budget.exceeded() or deps.clock.exceeded():
            return {}
        if idx >= len(planned):
            return {}
        pc = planned[idx]
        # LLM-hypothesis pool exhausted: skip remaining LLM hypotheses so recon
        # candidates (possibly the correct class) still get executed.
        if (
            pc.candidate.origin == "llm_hypothesis"
            and deps.budget.llm_hyp_remaining is not None
            and deps.budget.llm_hyp_remaining <= 0
        ):
            if deps.decisions is not None and not state.get("followup_wave", False):
                deps.decisions.append(PlannerDecision(
                    port=deps.port,
                    index=idx,
                    vuln_class=pc.candidate.vuln_class.value,
                    target=pc.candidate.target,
                    source=pc.source,
                    planned=True,
                    executed=False,
                    skip_reason="budget_llm_hyp_pool",
                ))
            return {"executed_count": idx + 1}
        trace = await execute_one(
            session=deps.session,
            candidate=pc.candidate,
            attacker=deps.attacker,
            budget=deps.budget,
            clock=deps.clock,
            sse_url=deps.sse_url,
            recon_calls=state["recon_calls"],
            max_inner_steps=state.get("max_inner_steps", 12),
            sandbox_root=deps.sandbox_root,
            prior_evidence=state.get("prior_evidence"),
        )
        if deps.decisions is not None and not state.get("followup_wave", False):
            deps.decisions.append(PlannerDecision(
                port=deps.port,
                index=idx,
                vuln_class=pc.candidate.vuln_class.value,
                target=pc.candidate.target,
                source=pc.source,
                planned=True,
                executed=True,
                skip_reason=None,
            ))
        out: dict[str, Any] = {"traces": [trace], "executed_count": idx + 1}

        # Cross-candidate memory (grill decision 5/P): record hit summaries
        # into prior_evidence; after a strong hit promote any remaining
        # chain_composition candidates so they run while prior hits are hot.
        signals, _ = verify_trace(trace, deps.sandbox_root)
        if signals:
            out["prior_evidence"] = [
                f"{trace.vuln_class.value} on {trace.target}: "
                f"{s.signal_id} ({s.severity})"
                for s in signals[:3]
            ]
            if any(s.severity in {"high", "critical"} for s in signals):
                reordered = promote_chains(planned, idx + 1, True)
                if reordered is not None:
                    out["planned"] = reordered
        return out

    return node


def promote_chains(
    planned: list[PlannedCandidate],
    executed_count: int,
    strong_hit: bool,
) -> list[PlannedCandidate] | None:
    """Promote remaining chain_composition candidates after a strong hit.

    Pure function (unit-testable): returns a reordered plan with all
    remaining chain candidates moved to the front of the unexecuted tail, or
    ``None`` when nothing changes (no strong hit / no chains left / plan
    exhausted). Never drops candidates - only reorders the unexecuted tail,
    so the finding set stays parity with ``runner.scan``.
    """
    if not strong_hit or executed_count >= len(planned):
        return None
    remaining = planned[executed_count:]
    chains = [
        p for p in remaining
        if p.candidate.vuln_class == VulnClass.CHAIN_COMPOSITION
    ]
    if not chains:
        return None
    rest = [
        p for p in remaining
        if p.candidate.vuln_class != VulnClass.CHAIN_COMPOSITION
    ]
    return planned[:executed_count] + chains + rest


def signal_gate(deps: GraphDeps):
    """Conditional edge after each candidate (grill decision 5 / P).

    Never early-converges - every planned candidate runs, so the finding set
    stays parity with ``runner.scan``. Three routes:
    - ``execute``: more candidates remain.
    - ``retrospective``: first wave ended with zero hits AND llm_points AND
      enough budget margin - a second bounded follow-up wave (runner.scan
      lines 272-304 semantics). Fires at most once (retro_fired).
    - ``verify``: budget/clock exhausted or plan exhausted with nothing to
      retrofit.
    """

    _RETRO_MARGIN = 8000

    def gate(state: McPwnState) -> Literal["execute", "retrospective", "verify"]:
        if deps.budget.exceeded() or deps.clock.exceeded():
            return "verify"
        if state["executed_count"] >= len(state["planned"]):
            if (
                deps.llm_points
                and not state.get("retro_fired", False)
                and deps.budget.counted_tokens
                < deps.budget.max_tokens_total - _RETRO_MARGIN
            ):
                found_any = any(
                    verify_trace(t, deps.sandbox_root)[0]
                    for t in state["traces"]
                )
                if not found_any:
                    return "retrospective"
            return "verify"
        return "execute"

    return gate


def retrospective_node(deps: GraphDeps):
    """Stage-2 LLM point 2: zero-finding retrospective, second bounded wave.

    Follow-ups append to the planned list after the first wave; the same
    execute loop and budget/clock gates apply (runner.scan 290-304). Note:
    follow-ups are not added to the M3 decisions bookkeeping, matching
    runner.scan which only records the first wave there.
    """

    async def node(state: McPwnState) -> dict[str, Any]:
        followups = retrospective_hypotheses(
            state["traces"],
            state["tools_seen"],
            state["resources_seen"],
            deps.attacker[0],
            deps.attacker[1],
            budget=deps.budget,
            tool_descriptions=tool_summary(state["recon_calls"]),
            sse_url=deps.sse_url,
        )
        extra = [
            PlannedCandidate(c, "fallback")
            for c in plan(followups, max_candidates=state.get("max_candidates", 20))
        ]
        return {
            "planned": state["planned"] + extra,
            "retro_fired": True,
            "followup_wave": True,
        }

    return node


def verify_node(deps: GraphDeps):
    """``verifier.build_findings`` over all traces + M3 skip-bookkeeping."""

    async def node(state: McPwnState) -> dict[str, Any]:
        # Parity with runner.scan lines 222-238: when budget/clock stopped
        # the loop, every planned-but-unexecuted candidate is recorded with
        # the skip reason so the decisions file covers the full plan.
        if deps.decisions is not None and not state.get("followup_wave", False):
            done = state["executed_count"]
            if deps.budget.exceeded() or deps.clock.exceeded():
                skip = "budget" if deps.budget.exceeded() else "budget_time"
                for j in range(done, len(state["planned"])):
                    pc = state["planned"][j]
                    deps.decisions.append(PlannerDecision(
                        port=deps.port,
                        index=j,
                        vuln_class=pc.candidate.vuln_class.value,
                        target=pc.candidate.target,
                        source=pc.source,
                        planned=True,
                        executed=False,
                        skip_reason=skip,
                    ))
        trace_dir = Path(state["out_dir"]) / "traces"
        trace_dir.mkdir(exist_ok=True)
        findings, _ = build_findings(
            traces=state["traces"],
            trace_dir=trace_dir,
            budget=deps.budget,
            judge_fn=deps.judge_fn,
            sandbox_root=deps.sandbox_root,
            evidence_judge_fn=deps.evidence_judge_fn,
        )
        return {"findings": findings}

    return node


def assemble_result(
    deps: GraphDeps,
    state: McPwnState,
    error: str | None = None,
) -> ScanResult:
    """Build the ScanResult from final/partial graph state.

    Shared by ``report_node`` (happy path) and ``_scan_graph``'s error branch
    (partial state recovered via MemorySaver ``get_state``) so both paths
    assemble identical reproducibility metadata.
    """
    return ScanResult(
        run_id=state["run_id"],
        sse_url=deps.sse_url,
        transport=deps.spec.transport.value if deps.spec else "sse",
        target_spec=deps.spec.model_dump(mode="json") if deps.spec else None,
        started_at=state["started_at"],
        wall_seconds=time.perf_counter() - state["wall_start"],
        attacker_tokens=deps.budget.attacker_tokens,
        judge_tokens=deps.budget.judge_tokens,
        tools_seen=state.get("tools_seen", []),
        resources_seen=state.get("resources_seen", []),
        traces=state.get("traces", []),
        static_hits=state.get("static_hits", []),
        findings=state.get("findings", []),
        stop_reason=stop_reason(deps.budget, deps.clock, error),
        git_sha=safe_git_sha(),
        config_snapshot=config_snapshot(),
        attacker_model=deps.attacker[1].model,
        attacker_temperature=deps.attacker[1].temperature,
        attack_messages_sha1=messages_sha1(state.get("traces", [])),
        seed=deps.seed,
        evidence_judge_model=deps.evidence_judge_model,
        sandbox_root=deps.sandbox_root,
    )


def report_node(deps: GraphDeps):
    """Assemble ScanResult, write scan_result.json, stash result in deps."""

    async def node(state: McPwnState) -> dict[str, Any]:
        result = assemble_result(deps, state, error=state.get("error"))
        (Path(state["out_dir"]) / "scan_result.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )
        deps.result = result
        return {"stop_reason": result.stop_reason}

    return node
