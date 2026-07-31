"""Generic MCP vulnerability signals (HANDOFF paragraph 6)."""

from mcp_redteam.signals.detectors import (
    _RUG_PULL_MARKER,
    _SHADOW_PAIR_ARG_KEY,
    DETECTORS,
    SIGNAL_META,
    _find_shadow_pair,
    _parse_list_tools_lookup,
    compute_confidence,
    compute_finding_severity,
    run_all_signals,
)

__all__ = [
    "DETECTORS",
    "SIGNAL_META",
    "_RUG_PULL_MARKER",
    "_SHADOW_PAIR_ARG_KEY",
    "_find_shadow_pair",
    "_parse_list_tools_lookup",
    "compute_confidence",
    "compute_finding_severity",
    "run_all_signals",
]
