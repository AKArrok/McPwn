"""Lint every vuln-class strategy card at import time."""

from __future__ import annotations

from mcp_redteam.contracts import VulnClass
from mcp_redteam.vulns.registry import lint_all_cards, load_all_cards, load_card


def test_all_cards_lint_clean():
    errors = lint_all_cards()
    assert not errors, f"strategy card lint failed:\n{errors}"


def test_all_vuln_classes_have_cards():
    cards = load_all_cards()
    for v in VulnClass:
        assert v.value in cards


def test_load_card_by_enum():
    card = load_card(VulnClass.PATH_TRAVERSAL)
    assert "## When to use" in card.text
    assert "## Templates" in card.text
    assert card.templates
