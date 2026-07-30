"""Top-level scan driver: `scan(sse_url)` -> `ScanResult`.

Wires together agent stages (recon -> planner -> executor -> verifier), owns the
shared TokenBudget + WallClock, and writes trace/finding artefacts to disk.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from mcp_redteam.agent.executor import execute_one
from mcp_redteam.agent.planner import plan
from mcp_redteam.agent.recon import recon
from mcp_redteam.agent.verifier import build_findings
from mcp_redteam.contracts import AttackTrace, ScanResult, ScanStopReason
from mcp_redteam.models.chat import make_client
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.targets.mcp_client import McpSession
from mcp_redteam.vulns.registry import lint_all_cards

DEFAULT_MAX_TOKENS = 30000
DEFAULT_WALL_SECONDS = 240
DEFAULT_MAX_INNER_STEPS = 12
DEFAULT_MAX_CANDIDATES = 20


def _new_run_id() -> str:
    return f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    attacker = make_client("attacker")

    traces: list[AttackTrace] = []
    tools_seen: list[str] = []
    resources_seen: list[str] = []
    error: str | None = None

    try:
        async with McpSession(sse_url) as session:
            recon_calls, candidates, tools_seen, resources_seen = await recon(session)
            ordered = plan(candidates, max_candidates=max_candidates)

            for candidate in ordered:
                if budget.exceeded() or clock.exceeded():
                    break
                trace = await execute_one(
                    session=session,
                    candidate=candidate,
                    attacker=attacker,
                    budget=budget,
                    clock=clock,
                    sse_url=sse_url,
                    recon_calls=recon_calls,
                    max_inner_steps=max_inner_steps,
                )
                traces.append(trace)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    findings, _ = build_findings(traces, trace_dir=trace_dir)
    wall_elapsed = time.perf_counter() - wall_start

    result = ScanResult(
        run_id=run_id,
        sse_url=sse_url,
        started_at=started_at,
        wall_seconds=wall_elapsed,
        attacker_tokens=budget.attacker_tokens,
        victim_tokens=budget.victim_tokens,
        judge_tokens=budget.judge_tokens,
        tools_seen=tools_seen,
        resources_seen=resources_seen,
        traces=traces,
        findings=findings,
        stop_reason=_stop_reason(budget, clock, error),
    )

    (out_dir / "scan_result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8"
    )
    return result
