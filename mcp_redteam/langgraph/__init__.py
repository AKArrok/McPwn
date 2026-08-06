"""LangGraph orchestration layer (HANDOFF_LANGGRAPH).

Explicit state-machine expression of ``runner.scan``'s recon → plan →
execute → verify → report pipeline. The old ``runner.scan`` stays as the
fallback and parity anchor; this package only adds the graph-shaped view.

Decision log (grill session, all confirmed):
- scope B: commit 1 = parity skeleton, commit 2 = prior_evidence memory
- topology: one scan-level graph, inner `execute_one` loop stays a black box
- state: serialisable data only; session/attacker/budget/clock injected via
  closure (GraphDeps) - no checkpoint-hostile objects in state
- signal_gate: records hits + chain priority; never early-converges
- interface: `scan(..., graph=False)` switches; old path untouched
"""

from mcp_redteam.langgraph.graph import build_graph

__all__ = ["build_graph"]
