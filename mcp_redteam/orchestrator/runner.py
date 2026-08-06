"""Top-level scan driver: `scan(sse_url)` -> `ScanResult`.

Wires together agent stages (recon -> planner -> executor -> verifier), owns the
shared TokenBudget + WallClock, and writes trace/finding artefacts to disk.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
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
from mcp_redteam.agent.verifier import build_findings, make_judge_fn, verify_trace
from mcp_redteam.contracts import (
    AttackTrace,
    PlannerDecision,
    ScanResult,
    ScanStopReason,
)
from mcp_redteam.models.chat import load_registry, make_client
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.targets.mcp_client import McpSession
from mcp_redteam.vulns.registry import lint_all_cards

DEFAULT_MAX_TOKENS = 30000
DEFAULT_WALL_SECONDS = 240
DEFAULT_MAX_INNER_STEPS = 12
DEFAULT_MAX_CANDIDATES = 20

_log = logging.getLogger(__name__)


def _new_run_id() -> str:
    return f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _port_from_url(sse_url: str) -> int:
    """Extract the port from an SSE URL like http://127.0.0.1:9010/sse."""
    m = re.search(r":(\d+)/", sse_url)
    return int(m.group(1)) if m else 0


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


def _safe_git_sha() -> str:
    """Best-effort current HEAD; empty string outside a git repo or on error.

    Used as a reproducibility anchor in ``ScanResult.git_sha`` so a months-old
    ``scan_result.json`` can be tied back to the code that produced it.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _config_snapshot() -> dict[str, Any]:
    """Snapshot of the parsed models.yaml registry. Empty dict on any error."""
    try:
        return load_registry()
    except Exception:
        return {}


def _messages_sha1(traces: list[AttackTrace]) -> str:
    """SHA-1 of every attacker_message across traces, ordered and serialised.

    Behavioural-drift detection: if the same scan against the same target
    produces a different ``attack_messages_sha1`` between runs, the attacker
    LLM took a different decision path even if the findings look identical.
    """
    h = hashlib.sha1()
    for trace in traces:
        for msg in trace.attacker_messages:
            h.update(json.dumps(msg, sort_keys=True, default=str).encode("utf-8"))
            h.update(b"\n")
    return h.hexdigest()


def _stop_reason(budget: TokenBudget, clock: WallClock, error: str | None) -> ScanStopReason:
    if error:
        return "error"
    if budget.exceeded():
        return "budget_tokens"
    if clock.exceeded():
        return "budget_time"
    return "completed"


async def scan(
    sse_url: str,
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
) -> ScanResult:
    """Scan one MCP SSE endpoint. Write traces/findings under `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    trace_dir = out_dir / "traces"
    trace_dir.mkdir(exist_ok=True)

    lint_errors = lint_all_cards()
    if lint_errors:
        raise RuntimeError("Strategy card lint failed:\n  " + "\n  ".join(lint_errors))

    run_id = _new_run_id()
    started_at = _iso_now()
    wall_start = time.perf_counter()

    budget = TokenBudget(max_tokens_total=max_tokens)
    clock = WallClock(wall_seconds=wall_seconds)
    attacker = make_client("attacker", temperature=attacker_temperature, seed=seed)
    judge_fn = _make_judge_fn_or_none()

    traces: list[AttackTrace] = []
    tools_seen: list[str] = []
    resources_seen: list[str] = []
    error: str | None = None

    try:
        async with McpSession(sse_url, headers=sse_headers) as session:
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
                    sse_url=sse_url,
                )
                candidates = candidates + extra

            if planner_mode == "llm":
                planned = plan_llm(
                    candidates,
                    tools_seen,
                    resources_seen,
                    attacker[0],
                    attacker[1],
                    sse_url=sse_url,
                )
            else:
                planned = [
                    PlannedCandidate(c, "fallback")
                    for c in plan(candidates, max_candidates=max_candidates)
                ]

            port = _port_from_url(sse_url)
            for index, pc in enumerate(planned):
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
                    sse_url=sse_url,
                    recon_calls=recon_calls,
                    max_inner_steps=max_inner_steps,
                    sandbox_root=sandbox_root,
                )
                traces.append(trace)
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
                        sse_url=sse_url,
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
                            sse_url=sse_url,
                            recon_calls=recon_calls,
                            max_inner_steps=max_inner_steps,
                            sandbox_root=sandbox_root,
                        )
                        traces.append(follow_trace)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    # Stage-2 LLM decision point 3: evidence judgment. Only active under
    # llm_points; the closure grounds every verdict on real call results.
    evidence_judge_fn = None
    evidence_judge_model = ""
    if llm_points:
        evidence_judge_fn, evidence_judge_model = _make_evidence_judge_fn(
            attacker, budget
        )

    findings, _ = build_findings(
        traces, trace_dir=trace_dir, budget=budget, judge_fn=judge_fn,
        sandbox_root=sandbox_root, evidence_judge_fn=evidence_judge_fn,
    )
    wall_elapsed = time.perf_counter() - wall_start

    result = ScanResult(
        run_id=run_id,
        sse_url=sse_url,
        started_at=started_at,
        wall_seconds=wall_elapsed,
        attacker_tokens=budget.attacker_tokens,
        judge_tokens=budget.judge_tokens,
        tools_seen=tools_seen,
        resources_seen=resources_seen,
        traces=traces,
        findings=findings,
        stop_reason=_stop_reason(budget, clock, error),
        git_sha=_safe_git_sha(),
        config_snapshot=_config_snapshot(),
        attacker_model=attacker[1].model,
        attacker_temperature=attacker[1].temperature,
        attack_messages_sha1=_messages_sha1(traces),
        seed=seed,
        evidence_judge_model=evidence_judge_model,
        sandbox_root=sandbox_root,
    )

    (out_dir / "scan_result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8"
    )
    return result
