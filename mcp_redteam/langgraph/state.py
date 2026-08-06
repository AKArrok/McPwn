"""Graph state: serialisable data only (grill decision 4 / 甲-2).

Session, attacker client, TokenBudget and WallClock are *not* in state -
they are live handles injected into node closures via ``GraphDeps``
(``nodes.py``). Keeping them out means the state can be dumped, diffed and
(in a future C stage) checkpointed without pickle/API-key hazards.

Cumulative fields use ``Annotated[list, operator.add]`` reducers: LangGraph
overwrites state keys by default, so ``traces`` / ``prior_evidence`` would
be clobbered on every node return without a reducer.
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from mcp_redteam.agent.planner import PlannedCandidate
from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import (
    AttackTrace,
    Finding,
    McpCall,
    ScanStopReason,
)


class McPwnState(TypedDict, total=False):
    """Serialisable scan state carried between graph nodes."""

    # ── inputs ─────────────────────────────────────────────────────────
    sse_url: str
    out_dir: str  # Path kept as str so state stays JSON/pickle friendly
    planner_mode: Literal["hardcoded", "llm"]
    max_candidates: int
    max_inner_steps: int
    llm_points: bool
    sandbox_root: str | None
    run_id: str
    started_at: str
    wall_start: float  # time.perf_counter() anchor for wall_seconds

    # ── recon output ───────────────────────────────────────────────────
    recon_calls: list[McpCall]
    candidates: list[Candidate]
    tools_seen: list[str]
    resources_seen: list[str]

    # ── plan output + execution cursor ─────────────────────────────────
    planned: list[PlannedCandidate]
    executed_count: int

    # ── cumulative (reducers append across candidate loop) ─────────────
    traces: Annotated[list[AttackTrace], operator.add]
    prior_evidence: Annotated[list[str], operator.add]  # hit summaries (B)
    retro_fired: bool  # retrospective second wave ran (llm_points only)
    followup_wave: bool  # executing retrospective follow-ups (no M3 decisions)

    # ── result ─────────────────────────────────────────────────────────
    findings: list[Finding]
    stop_reason: ScanStopReason
    error: str | None
