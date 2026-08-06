"""Graph assembly: recon → plan → execute(loop) → verify → report.

Commit 1 (parity) topology - scan-level graph with a loop edge carrying the
candidate cursor, inner LLM loop untouched (grill decision 3 / 甲):

    START → recon → plan → execute ⇄ execute (via signal_gate)
                              └→ verify → report → END

``_scan_graph`` (in ``runner.py``) owns the session lifetime and calls
``build_graph`` inside it; the graph itself never opens sessions.
"""

from __future__ import annotations

from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from mcp_redteam.langgraph.nodes import (
    GraphDeps,
    execute_node,
    hypothesis_node,
    plan_node,
    recon_node,
    report_node,
    retrospective_node,
    signal_gate,
    verify_node,
)
from mcp_redteam.langgraph.state import McPwnState


def build_graph(deps: GraphDeps) -> Any:
    """Compile the scan graph with all handles injected via ``deps``."""
    graph = StateGraph(McPwnState)
    graph.add_node("recon", recon_node(deps))
    graph.add_node("hypothesis", hypothesis_node(deps))
    graph.add_node("plan", plan_node(deps))
    graph.add_node("execute", execute_node(deps))
    graph.add_node("retrospective", retrospective_node(deps))
    graph.add_node("verify", verify_node(deps))
    graph.add_node("report", report_node(deps))

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "hypothesis")
    graph.add_edge("hypothesis", "plan")
    graph.add_edge("plan", "execute")
    graph.add_conditional_edges(
        "execute",
        signal_gate(deps),
        {
            "execute": "execute",
            "retrospective": "retrospective",
            "verify": "verify",
        },
    )
    graph.add_edge("retrospective", "execute")  # second bounded wave
    graph.add_edge("verify", "report")
    graph.add_edge("report", END)
    # MemorySaver keeps the last committed node state so a mid-scan node
    # failure can recover partial traces via app.get_state(config) instead
    # of discarding all work (runner.scan keeps partial traces on error).
    return graph.compile(checkpointer=MemorySaver())
