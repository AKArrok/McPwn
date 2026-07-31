"""Vuln-class strategy cards + registry (HANDOFF paragraph 4)."""

from mcp_redteam.vulns.registry import (
    VULN_SLUGS,
    StrategyCard,
    lint_all_cards,
    load_all_cards,
    load_card,
)

__all__ = ["VULN_SLUGS", "StrategyCard", "lint_all_cards", "load_all_cards", "load_card"]
