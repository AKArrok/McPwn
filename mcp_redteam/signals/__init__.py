"""Generic MCP vulnerability signals (HANDOFF paragraph 6)."""

from mcp_redteam.signals.detectors import (
    DETECTORS,
    SIGNAL_META,
    compute_confidence,
    compute_finding_severity,
    run_all_signals,
)

__all__ = [
    "DETECTORS",
    "SIGNAL_META",
    "compute_confidence",
    "compute_finding_severity",
    "run_all_signals",
]
