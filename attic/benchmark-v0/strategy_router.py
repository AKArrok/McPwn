"""Hardcoded strategy router (M2 交付形态).

每个 challenge 映射到一张策略卡文件。M4 的 LLM selector 会替换本文件,但接口
保持不变(`select(challenge_id) -> StrategyCard`)。

加载策略卡时做 Templates 敏感串 lint(HANDOFF Q3),不符合的模板会抛。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files

STRATEGY_BY_CHALLENGE: dict[str, str] = {
    "01": "direct_override",  # M2 会补
    "02": "tool_desc_probe",
    "03": "perm_expansion",   # M2 会补
    "04": "rug_trigger_probe",
    "05": "tool_desc_probe",
    "06": "indirect_payload",
    "07": "token_exfil",
    "08": "code_exec_escape",
    "09": "cmd_injection",
    "10": "chain",
}


@dataclass(frozen=True, slots=True)
class StrategyCard:
    name: str
    text: str
    templates: list[str]


_TEMPLATE_LINT: dict[str, callable] = {
    "tool_desc_probe": lambda t: (
        t.split()[0] in {"ls", "pwd", "whoami", "date"}
        and re.search(r";|\||&&|\$\(", t) is not None
    ),
}

_LINT_REQUIRE_ANY_MATCH: dict[str, re.Pattern] = {
    "tool_desc_probe": re.compile(r"\bid\b|passwd"),
}


def _load_card_text(name: str) -> str:
    return (
        files("mcp_redteam.attackers.agents.strategies")
        .joinpath(f"{name}.md")
        .read_text(encoding="utf-8")
    )


def _extract_templates(text: str) -> list[str]:
    """Parse ``## Templates`` bullet list into raw strings."""
    lines = text.splitlines()
    templates: list[str] = []
    in_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            in_section = stripped.lower().startswith("## templates")
            continue
        if not in_section:
            continue
        if stripped.startswith("- "):
            item = stripped[2:].strip()
            # allow surrounding backticks
            if item.startswith("`") and item.endswith("`"):
                item = item[1:-1]
            templates.append(item)
    return templates


def load_card(challenge_id: str) -> StrategyCard:
    if challenge_id not in STRATEGY_BY_CHALLENGE:
        raise KeyError(f"no strategy mapped for challenge {challenge_id!r}")
    name = STRATEGY_BY_CHALLENGE[challenge_id]
    try:
        text = _load_card_text(name)
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"strategy card {name}.md missing — expected in strategies/"
        ) from e
    templates = _extract_templates(text)

    lint = _TEMPLATE_LINT.get(name)
    if lint is not None:
        bad = [t for t in templates if not lint(t)]
        if bad:
            raise ValueError(
                f"[strategy={name}] {len(bad)} template(s) failed shape lint: {bad}"
            )
    require = _LINT_REQUIRE_ANY_MATCH.get(name)
    if require is not None and not any(require.search(t) for t in templates):
        raise ValueError(
            f"[strategy={name}] no template matches {require.pattern!r} — needs at least one "
            "sensitive-target template"
        )

    return StrategyCard(name=name, text=text, templates=templates)


def select(challenge_id: str) -> StrategyCard:
    return load_card(challenge_id)
