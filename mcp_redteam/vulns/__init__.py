"""Vuln-class strategy cards + registry (HANDOFF paragraph 4)."""

from mcp_redteam.vulns.registry import (
    StrategyCard,
    load_card,
    load_all_cards,
    lint_all_cards,
    VULN_SLUGS,
)

__all__ = ["StrategyCard", "load_card", "load_all_cards", "lint_all_cards", "VULN_SLUGS"]
