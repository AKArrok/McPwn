"""Top-level scan driver: `scan(target)` -> `ScanResult`.

``target`` is a URL (SSE or streamable HTTP), a stdio launch command, or an
already-built ``TargetSpec`` - see ``contracts.TargetSpec``. Downstream stages
only see the transport-neutral endpoint display string.

Wires together agent stages (recon -> planner -> executor -> verifier), owns the
shared TokenBudget + WallClock, and writes trace/finding artefacts to disk.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from mcp_redteam.agent.executor import execute_one
from mcp_redteam.agent.llm_points import (
    evidence_verdict,
    generate_hypotheses,
    retrospective_hypotheses,
    tool_summary,
)
from mcp_redteam.agent.planner import PlannedCandidate, plan, plan_llm
from mcp_redteam.agent.recon import recon
from mcp_redteam.agent.verifier import (
    _METADATA_ONLY_SIGNALS,
    build_findings,
    make_judge_fn,
    verify_trace,
)
from mcp_redteam.contracts import (
    AttackTrace,
    PlannerDecision,
    ScanResult,
    TargetSpec,
)
from mcp_redteam.models.chat import make_client
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.orchestrator.scan_meta import (
    config_snapshot,
    iso_now,
    messages_sha1,
    safe_git_sha,
    stop_reason,
)
from mcp_redteam.targets.mcp_client import McpSession
from mcp_redteam.vulns.registry import lint_all_cards

DEFAULT_MAX_TOKENS = 30000
DEFAULT_WALL_SECONDS = 240
DEFAULT_MAX_INNER_STEPS = 12
DEFAULT_MAX_CANDIDATES = 20

# Default share of attacker budget reserved for LLM-hypothesis candidates
# (see scan(..., llm_hyp_budget)). 40%: enough for the vault/delegate
# unknown-shape exploit chains to produce >=1 finding, while leaving recon
# candidates (which may be the correct classification, e.g. SSRF on fetch)
# roughly 60% to complete their probe chains. Tuned on the fetch real target
# (llm round: wrong lead truncated at pool, recon SSRF then executes).
_LLM_HYP_BUDGET_FRACTION = 0.4


def _resolve_llm_hyp_budget(max_tokens: int, override: int | None) -> int | None:
    """LLM-hypothesis pool size.

    - ``None`` (default): auto = 40% of max_tokens (protects recon candidates
      from being starved by wrong LLM hypotheses; real-target default).
    - ``-1``: disable the pool entirely (legacy unbounded behaviour) - used by
      unknown-shape experiments (vault/delegate) whose recon candidates are
      all misclassified and whose discovery REQUIRES the LLM hypothesis to
      explore freely.
    - any other int: explicit pool size.
    """
    if override == -1:
        return None
    if override is not None:
        return override
    return int(max_tokens * _LLM_HYP_BUDGET_FRACTION)

_log = logging.getLogger(__name__)


def _new_run_id() -> str:
    return f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _normalize_target(
    target: str | TargetSpec, sse_headers: dict[str, str] | None
) -> TargetSpec:
    """Accept a URL / stdio command string or a ready ``TargetSpec``.

    ``sse_headers`` (legacy CLI ``--headers``) overrides the spec's own
    headers when both are given.
    """
    spec = target if isinstance(target, TargetSpec) else TargetSpec.parse(target)
    if sse_headers:
        spec = spec.model_copy(update={"headers": sse_headers})
    return spec


def _port_from_spec(spec: TargetSpec) -> int:
    """Extract the port from an HTTP target URL like http://127.0.0.1:9010/sse.

    stdio targets have no port; runs key off the command instead (0 here,
    callers that need a stable per-target number hash the display string).
    """
    if spec.url:
        m = re.search(r":(\d+)/", spec.url)
        if m:
            return int(m.group(1))
    return 0


def _make_judge_fn_or_none():
    """Best-effort L2 judge twin. None if the judge role is unconfigured so the
    scan proceeds without L2 coverage instead of crashing (HANDOFF Q8: judge is
    out-of-band and optional).
    """
    try:
        jclient, jspec = make_client("judge")
    except Exception:  # judge optional - missing API key / role
        return None
    return make_judge_fn(jclient, jspec)


def _make_evidence_judge_fn(attacker, budget):
    """Evidence judge prefers the judge-role model (tokens stay out-of-band).
    Falls back to the attacker client with a loud warning when the judge role
    is unconfigured so llm_points keeps working in key-limited environments.
    Returns (callable, model_name) - the model is recorded on ScanResult so
    the "judge out-of-band" claim is auditable.
    """
    try:
        jclient, jspec = make_client("judge")
    except Exception as exc:  # judge optional - missing API key / role
        _log.warning(
            "judge role unavailable for evidence judge (%s); "
            "falling back to attacker model %s",
            exc, attacker[1].model,
        )
        jclient, jspec = attacker
    return (
        lambda trace: evidence_verdict(trace, jclient, jspec, budget),
        jspec.model,
    )


def _early_evidence_judge(trace, sandbox_root, evidence_judge_fn) -> None:
    """Judge a single trace right after it ran (decision point 3, per-trace).

    Runs only when the deterministic vuln-signal set is empty (metadata-class
    signals such as shadow/rug probes are scan side-effects and must not
    block the judge - real-target regression: filesystem allowlist-escape).
    The verdict lands on the trace so the retrospective can feed it back to
    the attacker: a judge that debunks a hallucinated "I got in" gives the
    attacker the concrete reason to retry differently.
    """
    if trace.llm_evidence_verdict is not None:
        return
    signals, _ = verify_trace(trace, sandbox_root)
    vuln_signals = [s for s in signals if s.signal_id not in _METADATA_ONLY_SIGNALS]
    if not vuln_signals:
        try:
            trace.llm_evidence_verdict = evidence_judge_fn(trace)
        except Exception:
            _log.warning("early evidence judge failed for %s@%s",
                         trace.vuln_class, trace.target)


async def scan(
    sse_url: str | TargetSpec,
    out_dir: Path,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    wall_seconds: int = DEFAULT_WALL_SECONDS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_inner_steps: int = DEFAULT_MAX_INNER_STEPS,
    attacker_temperature: float | None = None,
    sse_headers: dict[str, str] | None = None,
    sandbox_root: str | None = None,
    planner_mode: Literal["hardcoded", "llm"] = "hardcoded",
    decisions: list[PlannerDecision] | None = None,
    llm_points: bool = False,
    seed: int | None = None,
    graph: bool = False,
    llm_hyp_budget: int | None = None,
) -> ScanResult:
    """Scan one MCP target (SSE / streamable HTTP URL, stdio command, or
    ``TargetSpec``). Write traces/findings under `out_dir`.

    ``graph=True`` runs the same pipeline as an explicit LangGraph state
    machine (``mcp_redteam/langgraph/``); the hand-written loop below stays
    as the default path and parity anchor (HANDOFF_LANGGRAPH §4.3).

    ``llm_hyp_budget`` bounds how much attacker budget LLM-hypothesis
    candidates may consume in total (default: 40% of ``max_tokens``). A
    wrong LLM lead (e.g. command_injection on a tool recon already classified
    as SSRF) must not starve the recon candidates behind it. Pass ``-1`` to
    disable the pool (legacy unbounded behaviour - used by unknown-shape
    experiments whose discovery requires free LLM-hypothesis exploration);
    pass 0 to make every LLM-hypothesis candidate skip immediately; any other
    int is an explicit pool size.
    """
    if graph:
        return await _scan_graph(
            sse_url,  # raw str | TargetSpec; _scan_graph normalizes
            out_dir=out_dir,
            max_tokens=max_tokens,
            wall_seconds=wall_seconds,
            max_candidates=max_candidates,
            max_inner_steps=max_inner_steps,
            attacker_temperature=attacker_temperature,
            sse_headers=sse_headers,
            sandbox_root=sandbox_root,
            planner_mode=planner_mode,
            decisions=decisions,
            llm_points=llm_points,
            seed=seed,
            llm_hyp_budget=llm_hyp_budget,
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    trace_dir = out_dir / "traces"
    trace_dir.mkdir(exist_ok=True)

    spec = _normalize_target(sse_url, sse_headers)
    endpoint = spec.display

    lint_errors = lint_all_cards()
    if lint_errors:
        raise RuntimeError("Strategy card lint failed:\n  " + "\n  ".join(lint_errors))

    run_id = _new_run_id()
    started_at = iso_now()
    wall_start = time.perf_counter()

    budget = TokenBudget(max_tokens_total=max_tokens)
    budget.llm_hyp_remaining = _resolve_llm_hyp_budget(max_tokens, llm_hyp_budget)
    clock = WallClock(wall_seconds=wall_seconds)
    attacker = make_client("attacker", temperature=attacker_temperature, seed=seed)
    judge_fn = _make_judge_fn_or_none()
    # Stage-2 evidence judge: constructed up-front so every zero-signal trace
    # is judged IMMEDIATELY after execution (not at the end). The verdict feeds
    # the retrospective (decision point 2): a judge that debunks a "I got in"
    # hallucination gives the attacker the real reason to retry differently.
    evidence_judge_fn = None
    evidence_judge_model = ""
    if llm_points:
        evidence_judge_fn, evidence_judge_model = _make_evidence_judge_fn(
            attacker, budget
        )

    traces: list[AttackTrace] = []
    tools_seen: list[str] = []
    resources_seen: list[str] = []
    error: str | None = None

    try:
        async with McpSession(spec) as session:
            recon_calls, candidates, tools_seen, resources_seen = await recon(session)

            # Stage-2 LLM decision point 1: hypothesis generation. Additive
            # only - never reorders candidates (M3 permutation lesson).
            if llm_points:
                extra = generate_hypotheses(
                    candidates,
                    tools_seen,
                    resources_seen,
                    attacker[0],
                    attacker[1],
                    budget=budget,
                    tool_descriptions=tool_summary(recon_calls),
                    sse_url=endpoint,
                )
                candidates = candidates + extra

            if planner_mode == "llm":
                planned = plan_llm(
                    candidates,
                    tools_seen,
                    resources_seen,
                    attacker[0],
                    attacker[1],
                    sse_url=endpoint,
                )
            else:
                planned = [
                    PlannedCandidate(c, "fallback")
                    for c in plan(candidates, max_candidates=max_candidates)
                ]

            port = _port_from_spec(spec)
            for index, pc in enumerate(planned):
                # LLM-hypothesis pool exhausted: skip remaining LLM
                # hypotheses so recon candidates (possibly the correct class,
                # e.g. SSRF on fetch) still get executed.
                if (
                    pc.candidate.origin == "llm_hypothesis"
                    and budget.llm_hyp_remaining is not None
                    and budget.llm_hyp_remaining <= 0
                ):
                    if decisions is not None:
                        decisions.append(PlannerDecision(
                            port=port,
                            index=index,
                            vuln_class=pc.candidate.vuln_class.value,
                            target=pc.candidate.target,
                            source=pc.source,
                            planned=True,
                            executed=False,
                            skip_reason="budget_llm_hyp_pool",
                        ))
                    continue
                if budget.exceeded() or clock.exceeded():
                    if decisions is not None:
                        # Record every planned-but-unexecuted candidate so the
                        # decisions file always covers the full plan (M3 judge
                        # intent-vs-execution separation).
                        skip = "budget" if budget.exceeded() else "budget_time"
                        for j in range(index, len(planned)):
                            pc_j = planned[j]
                            decisions.append(PlannerDecision(
                                port=port,
                                index=j,
                                vuln_class=pc_j.candidate.vuln_class.value,
                                target=pc_j.candidate.target,
                                source=pc_j.source,
                                planned=True,
                                executed=False,
                                skip_reason=skip,
                            ))
                    break
                trace = await execute_one(
                    session=session,
                    candidate=pc.candidate,
                    attacker=attacker,
                    budget=budget,
                    clock=clock,
                    sse_url=endpoint,
                    recon_calls=recon_calls,
                    max_inner_steps=max_inner_steps,
                    sandbox_root=sandbox_root,
                )
                traces.append(trace)
                # Evidence-judge THIS trace now (zero-signal only) so the
                # retrospective below can consume the verdict and tell the
                # attacker to retry differently when a claim was debunked.
                if evidence_judge_fn is not None:
                    _early_evidence_judge(trace, sandbox_root, evidence_judge_fn)
                if decisions is not None:
                    decisions.append(PlannerDecision(
                        port=port,
                        index=index,
                        vuln_class=pc.candidate.vuln_class.value,
                        target=pc.candidate.target,
                        source=pc.source,
                        planned=True,
                        executed=True,
                        skip_reason=None,
                    ))

            # Stage-2 LLM decision point 2: retrospective review of a
            # zero-finding wave. Runs only when nothing was found, budget/clock
            # remain, and the experiment flag is on; follow-ups are a second
            # bounded wave inside the same session.
            # Retrospective fires only when enough budget remains for a
            # follow-up wave to actually run (margin, not "not exceeded" -
            # otherwise a budget-starving wrong lead would silently disable
            # the safety net).
            _retro_margin = 8000
            if (
                llm_points
                and not clock.exceeded()
                and budget.counted_tokens < budget.max_tokens_total - _retro_margin
            ):
                found_any = any(verify_trace(t, sandbox_root)[0] for t in traces)
                if not found_any:
                    followups = retrospective_hypotheses(
                        traces,
                        tools_seen,
                        resources_seen,
                        attacker[0],
                        attacker[1],
                        budget=budget,
                        tool_descriptions=tool_summary(recon_calls),
                        sse_url=endpoint,
                    )
                    for fc in plan(followups, max_candidates=max_candidates):
                        if budget.exceeded() or clock.exceeded():
                            break
                        follow_trace = await execute_one(
                            session=session,
                            candidate=fc,
                            attacker=attacker,
                            budget=budget,
                            clock=clock,
                            sse_url=endpoint,
                            recon_calls=recon_calls,
                            max_inner_steps=max_inner_steps,
                            sandbox_root=sandbox_root,
                        )
                        traces.append(follow_trace)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    findings, _ = build_findings(
        traces, trace_dir=trace_dir, budget=budget, judge_fn=judge_fn,
        sandbox_root=sandbox_root, evidence_judge_fn=evidence_judge_fn,
    )
    wall_elapsed = time.perf_counter() - wall_start

    result = ScanResult(
        run_id=run_id,
        sse_url=endpoint,
        transport=spec.transport.value,
        target_spec=spec.model_dump(mode="json"),
        started_at=started_at,
        wall_seconds=wall_elapsed,
        attacker_tokens=budget.attacker_tokens,
        judge_tokens=budget.judge_tokens,
        tools_seen=tools_seen,
        resources_seen=resources_seen,
        traces=traces,
        findings=findings,
        stop_reason=stop_reason(budget, clock, error),
        git_sha=safe_git_sha(),
        config_snapshot=config_snapshot(),
        attacker_model=attacker[1].model,
        attacker_temperature=attacker[1].temperature,
        attack_messages_sha1=messages_sha1(traces),
        seed=seed,
        evidence_judge_model=evidence_judge_model,
        sandbox_root=sandbox_root,
    )

    (out_dir / "scan_result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8"
    )
    return result


async def _scan_graph(
    sse_url: str | TargetSpec,
    out_dir: Path,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    wall_seconds: int = DEFAULT_WALL_SECONDS,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_inner_steps: int = DEFAULT_MAX_INNER_STEPS,
    attacker_temperature: float | None = None,
    sse_headers: dict[str, str] | None = None,
    sandbox_root: str | None = None,
    planner_mode: Literal["hardcoded", "llm"] = "hardcoded",
    decisions: list[PlannerDecision] | None = None,
    llm_points: bool = False,
    seed: int | None = None,
    llm_hyp_budget: int | None = None,
) -> ScanResult:
    """LangGraph-shaped twin of ``scan`` (grill decision 7a / graph=True).

    Owns the session lifetime and the ScanResult construction; the graph
    (``mcp_redteam/langgraph/``) only orchestrates. Mirrors ``scan``'s
    lint gate, budget/clock semantics, M3 decisions bookkeeping and
    reproducibility metadata so a parity test can compare the two field by
    field.
    """
    from mcp_redteam.langgraph.graph import build_graph
    from mcp_redteam.langgraph.nodes import GraphDeps, assemble_result
    from mcp_redteam.langgraph.state import McPwnState

    out_dir.mkdir(parents=True, exist_ok=True)
    trace_dir = out_dir / "traces"
    trace_dir.mkdir(exist_ok=True)

    spec = _normalize_target(sse_url, sse_headers)
    endpoint = spec.display

    lint_errors = lint_all_cards()
    if lint_errors:
        raise RuntimeError("Strategy card lint failed:\n  " + "\n  ".join(lint_errors))

    run_id = _new_run_id()
    started_at = iso_now()
    wall_start = time.perf_counter()

    budget = TokenBudget(max_tokens_total=max_tokens)
    budget.llm_hyp_remaining = _resolve_llm_hyp_budget(max_tokens, llm_hyp_budget)
    clock = WallClock(wall_seconds=wall_seconds)
    attacker = make_client("attacker", temperature=attacker_temperature, seed=seed)
    judge_fn = _make_judge_fn_or_none()

    # Stage-2 LLM evidence judge (unknown-shape verdicts): judge role
    # preferred, attacker fallback, tokens out-of-band - same as scan().
    evidence_judge_fn = None
    evidence_judge_model = ""
    if llm_points:
        evidence_judge_fn, evidence_judge_model = _make_evidence_judge_fn(
            attacker, budget
        )

    deps = GraphDeps(
        session=None,  # type: ignore[arg-type] - bound inside the session ctx
        attacker=attacker,
        budget=budget,
        clock=clock,
        sse_url=endpoint,
        sandbox_root=sandbox_root,
        judge_fn=judge_fn,
        evidence_judge_fn=evidence_judge_fn,
        evidence_judge_model=evidence_judge_model,
        decisions=decisions,
        port=_port_from_spec(spec),
        seed=seed,
        llm_points=llm_points,
        spec=spec,
    )

    initial_state: McPwnState = {
        "sse_url": endpoint,
        "out_dir": str(out_dir),
        "planner_mode": planner_mode,
        "max_candidates": max_candidates,
        "max_inner_steps": max_inner_steps,
        "llm_points": llm_points,
        "sandbox_root": sandbox_root,
        "run_id": run_id,
        "started_at": started_at,
        "wall_start": wall_start,
        "traces": [],
        "prior_evidence": [],
    }

    config: dict[str, Any] = {"configurable": {"thread_id": run_id}}
    app = None
    try:
        async with McpSession(spec) as session:
            deps.session = session
            app = build_graph(deps)
            await app.ainvoke(initial_state, config)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        _log.exception("graph scan failed: %s", exc)
        # Recover partial work committed before the failure (MemorySaver),
        # mirroring runner.scan which keeps partial traces and still builds
        # findings on error. Fall back to the initial state if the graph
        # never committed a checkpoint.
        partial: McPwnState = dict(initial_state)
        if app is not None:
            try:
                partial = dict(app.get_state(config).values)
            except Exception:
                partial = dict(initial_state)
        deps.result = assemble_result(deps, partial, error=error)
        (out_dir / "scan_result.json").write_text(
            deps.result.model_dump_json(indent=2), encoding="utf-8"
        )

    assert deps.result is not None, "graph scan produced no result"
    return deps.result
