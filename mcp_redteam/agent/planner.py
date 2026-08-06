"""Planner: turn recon candidates into an ordered attack plan.

M2 交付形态: hard-coded heuristic (candidate.score).
M3: `plan_llm` asks the attacker LLM to produce the complete ordered plan for
one server. Any LLM failure (unparseable JSON, missing candidates, 429/timeout)
falls back to the hardcoded score order and marks the whole plan
`source="fallback"` so the M3 judge can measure the real LLM decision share.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from importlib.resources import files
from typing import TYPE_CHECKING, Literal

from jinja2 import Template

from mcp_redteam.agent.recon import Candidate
from mcp_redteam.judge.parse import parse_json_object
from mcp_redteam.models.chat import chat_create_with_retry

if TYPE_CHECKING:
    from openai import OpenAI

    from mcp_redteam.models.chat import ModelSpec

_log = logging.getLogger(__name__)

# M3 planner prompt is externalized (HANDOFF rule 3): static instructions in
# planner_system.md, loaded via jinja2 Template; no inline prompt strings.
_PLANNER_SYSTEM_TMPL = Template(
    files("mcp_redteam.attackers.agents")
    .joinpath("planner_system.md")
    .read_text(encoding="utf-8")
)


@dataclass(frozen=True, slots=True)
class PlannedCandidate:
    """One entry in the ordered plan produced by a planner.

    ``candidate`` is the recon Candidate being planned; ``source`` marks whether
    this plan came from the LLM ("llm") or the hardcoded fallback ("fallback").
    A single plan is all-llm or all-fallback - never mixed.
    """

    candidate: Candidate
    source: Literal["llm", "fallback"]


def plan(candidates: list[Candidate], max_candidates: int = 20) -> list[Candidate]:
    """Sort by score desc, cap length. Stable within same score."""
    ordered = sorted(candidates, key=lambda c: c.score, reverse=True)
    return ordered[:max_candidates]


def _fallback_plan(candidates: list[Candidate]) -> list[PlannedCandidate]:
    """Hardcoded score-ordered plan with no truncation.

    The M3 decisions contract requires the complete sequence to cover every
    recon candidate (executed or not) so the judge can separate "never
    planned" from "planned but starved by budget" on 9010. Capping here would
    drop tail candidates from the decisions file and break that separation, so
    the fallback plan is the same score order with max_candidates = len.
    """
    return [
        PlannedCandidate(c, "fallback")
        for c in plan(candidates, max_candidates=len(candidates))
    ]


def _build_user_message(
    candidates: list[Candidate],
    tools_seen: list[str],
    resources_seen: list[str],
    sse_url: str | None,
) -> str:
    """Compact planner input: tools/resources summary + the full candidate set."""
    rows = [
        {
            "vuln_class": c.vuln_class.value,
            "target": c.target,
            "kind": c.target_kind,
            "score": c.score,
            "reason": c.reason,
        }
        for c in candidates
    ]
    parts = [
        f"MCP server: {sse_url}" if sse_url else "MCP server: (unknown)",
        f"Tools: {json.dumps(tools_seen, ensure_ascii=False)}",
        f"Resources: {json.dumps(resources_seen, ensure_ascii=False)}",
        "Recon candidates:",
        json.dumps(rows, ensure_ascii=False, indent=2),
        "Produce the complete ordered plan as JSON covering every candidate exactly once.",
        "Respond with JSON only.",
    ]
    return "\n".join(parts)


def _entry_key(entry: dict) -> tuple[str, str] | None:
    """(vuln_class, target) key of a plan entry, or None when malformed."""
    vclass = entry.get("vuln_class")
    target = entry.get("target")
    if not isinstance(vclass, str) or not isinstance(target, str):
        return None
    return (vclass, target)


def plan_llm(
    candidates: list[Candidate],
    tools_seen: list[str],
    resources_seen: list[str],
    client: OpenAI,
    model_spec: ModelSpec,
    sse_url: str | None = None,
) -> list[PlannedCandidate]:
    """Ask the attacker LLM for the complete ordered plan; fallback on failure.

    The LLM must return a JSON object ``{"plan": [{"vuln_class", "target",
    "reason"}, ...]}`` whose entries are a permutation of the recon
    ``candidates`` - every candidate exactly once, no invented entries. Any
    failure - unparseable JSON, missing candidates, LLM exception (429/timeout
    included, already retried by ``chat_create_with_retry``) - returns the
    hardcoded score-ordered plan with every entry ``source="fallback"``.
    """
    if not candidates:
        return []
    user_message = _build_user_message(candidates, tools_seen, resources_seen, sse_url)
    try:
        resp = chat_create_with_retry(
            client,
            model=model_spec.model,
            temperature=model_spec.temperature,
            messages=[
                {"role": "system", "content": _PLANNER_SYSTEM_TMPL.render()},
                {"role": "user", "content": user_message},
            ],
        )
    except Exception:  # noqa: BLE001 - planner failure is a fallback, not a crash
        _log.warning("planner LLM call failed; falling back to hardcoded plan")
        return _fallback_plan(candidates)
    content = (resp.choices[0].message.content or "").strip()
    obj = parse_json_object(content)
    if obj is None or not isinstance(obj.get("plan"), list):
        _log.warning("planner returned unparseable/non-list JSON; fallback")
        return _fallback_plan(candidates)

    by_key: dict[tuple[str, str], Candidate] = {
        (c.vuln_class.value, c.target): c for c in candidates
    }
    planned: list[PlannedCandidate] = []
    used: set[tuple[str, str]] = set()
    hallucinated = 0
    for entry in obj["plan"]:
        if not isinstance(entry, dict):
            continue
        key = _entry_key(entry)
        if key is None or key not in by_key or key in used:
            hallucinated += 1
            continue
        planned.append(PlannedCandidate(by_key[key], "llm"))
        used.add(key)
    if len(used) != len(candidates):
        missing = [
            c.target
            for c in candidates
            if (c.vuln_class.value, c.target) not in used
        ]
        _log.warning(
            "planner omitted %d/%d candidates (%s); fallback",
            len(candidates) - len(used),
            len(candidates),
            missing[:5],
        )
        return _fallback_plan(candidates)
    if hallucinated:
        _log.warning(
            "planner emitted %d invented/duplicate entries; dropped (hallucination)",
            hallucinated,
        )
    return planned