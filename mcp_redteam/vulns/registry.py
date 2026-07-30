"""Vuln-class strategy card registry.

Each card is a Markdown file with four mandatory sections (HANDOFF paragraph 4):
    ## When to use
    ## Objective
    ## Playbook
    ## Templates

The registry does the following:
- Loads a card by VulnClass slug.
- Lint on load: verifies all four sections exist.
- Lint on load: verifies no obvious answer-leaking strings (e.g. exact known
  DVMCP passwords) appear in Templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files

from mcp_redteam.contracts import VulnClass

VULN_SLUGS: list[str] = [v.value for v in VulnClass]

_REQUIRED_SECTIONS: list[str] = [
    "## When to use",
    "## Objective",
    "## Playbook",
    "## Templates",
]

# Strings that would let the agent "cheat" by literally quoting known DVMCP
# answers. HANDOFF paragraph 4 mandates this lint. Only real signal-match
# strings belong here - namespace URIs like `internal://` are generic heuristic
# knowledge and MUST stay allowed (see review issue #7).
_FORBIDDEN_ANSWER_STRINGS: list[str] = [
    "super_secret_password123",
    "sk-a1b2c3d4e5f6g7h8i9j0",
    "root:x:0:0",
]


@dataclass(frozen=True, slots=True)
class StrategyCard:
    slug: str
    text: str
    templates: list[str]


def _load_card_text(slug: str) -> str:
    """Load a strategy card Markdown file from the vulns package resources."""
    return (
        files("mcp_redteam.vulns")
        .joinpath("cards")
        .joinpath(f"{slug}.md")
        .read_text(encoding="utf-8")
    )


def _extract_templates(text: str) -> list[str]:
    """Parse `## Templates` bullet list into raw payload strings.

    Accepts fenced code blocks and inline backticks around each item.
    """
    lines = text.splitlines()
    templates: list[str] = []
    in_section = False
    in_code_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            in_section = stripped.lower().startswith("## templates")
            in_code_fence = False
            continue
        if not in_section:
            continue
        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence and stripped:
            templates.append(stripped)
            continue
        if stripped.startswith("- "):
            item = stripped[2:].strip()
            if item.startswith("`") and item.endswith("`"):
                item = item[1:-1]
            templates.append(item)
    return templates


def _lint_sections(slug: str, text: str) -> None:
    for section in _REQUIRED_SECTIONS:
        if section not in text:
            raise ValueError(f"[card={slug}] missing required section: {section!r}")


def _lint_forbidden(slug: str, text: str) -> None:
    templates_start = text.find("## Templates")
    if templates_start == -1:
        return
    templates_block = text[templates_start:]
    for forbidden in _FORBIDDEN_ANSWER_STRINGS:
        if forbidden in templates_block:
            raise ValueError(
                f"[card={slug}] Templates section contains forbidden answer string "
                f"{forbidden!r} - the agent would be cheating"
            )


def load_card(vuln_class: VulnClass | str) -> StrategyCard:
    slug = vuln_class.value if isinstance(vuln_class, VulnClass) else vuln_class
    try:
        text = _load_card_text(slug)
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"strategy card {slug}.md not found in mcp_redteam/vulns/cards/"
        ) from e
    _lint_sections(slug, text)
    _lint_forbidden(slug, text)
    templates = _extract_templates(text)
    return StrategyCard(slug=slug, text=text, templates=templates)


def load_all_cards() -> dict[str, StrategyCard]:
    return {slug: load_card(slug) for slug in VULN_SLUGS}


def lint_all_cards() -> list[str]:
    """Load every card; return list of error messages (empty if all pass)."""
    errors: list[str] = []
    for slug in VULN_SLUGS:
        try:
            load_card(slug)
        except (FileNotFoundError, ValueError) as e:
            errors.append(str(e))
    return errors
