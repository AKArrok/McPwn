"""M3 acceptance judge: the LLM rules only on chain_9010_real.

The five M3 criteria are computed by deterministic code in eval/dvmcp; this
module only (a) assembles the judge LLM prompt, (b) parses its single ruling on
``chain_9010_real``, (c) merges that ruling into the deterministic criteria, and
(d) writes the human-readable report. The judge never recomputes numbers and
never raises: any LLM failure yields None and the report is assembled from
deterministic criteria only (9010 stays inconclusive).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from jinja2 import Template
from pydantic import BaseModel, ConfigDict, Field

from mcp_redteam.contracts import M3JudgeReport
from mcp_redteam.judge.parse import parse_json_object
from mcp_redteam.models.chat import chat_create_with_retry

if TYPE_CHECKING:
    from openai import OpenAI

    from mcp_redteam.models.chat import ModelSpec

_log = logging.getLogger(__name__)

_RULING_VALUES = frozenset({"pass", "fail", "inconclusive"})
_REASON_MAX = 500
_MAX_FIELD_CHARS = 4000

# M3 judge prompt is externalized (HANDOFF rule 3): static instructions in
# judge_m3_system.md, loaded via jinja2 Template; no inline prompt strings.
_JUDGE_M3_SYSTEM_TMPL = Template(
    files("mcp_redteam.judge.agents")
    .joinpath("judge_m3_system.md")
    .read_text(encoding="utf-8")
)


class M3JudgeInput(BaseModel):
    """Everything the M3 judge callable needs, assembled by deterministic code.

    ``criteria`` holds the five code-computed criteria and ``metrics`` the
    code-computed numbers. The judge LLM only overrides ``chain_9010_real``
    after reading ``chain_excerpt`` (attack calls, judge_verdict, prior-link
    hints) and ``planner_excerpt``.
    """

    model_config = ConfigDict(extra="forbid")

    hardcoded_summary: dict
    llm_summary: dict
    criteria: dict[str, Literal["pass", "fail", "inconclusive"]]
    metrics: dict[str, float | int | None]
    chain_excerpt: dict
    planner_excerpt: str
    planner_fallback_rate: float | None = None
    evidence_refs: list[str] = Field(default_factory=list)


def parse_m3_report(content: str) -> dict | None:
    """Parse the M3 judge's single ruling; None on any failure.

    Expects ``{"chain_9010_real": "pass"|"fail"|"inconclusive", "reason": str}``.
    Missing/invalid ``chain_9010_real`` -> None; ``reason`` is truncated to 500
    chars.
    """
    obj = parse_json_object(content)
    if obj is None:
        _log.warning("M3 judge returned unparseable JSON: %r", (content or "")[:200])
        return None
    ruling = obj.get("chain_9010_real")
    if ruling not in _RULING_VALUES:
        _log.warning("M3 judge ruling invalid: %r", ruling)
        return None
    reason = str(obj.get("reason", ""))
    return {"chain_9010_real": ruling, "reason": reason[:_REASON_MAX]}


def assemble_report(
    inp: M3JudgeInput,
    llm_ruling: dict | None,
    judge_model: str = "",
    judge_tokens: int = 0,
) -> M3JudgeReport:
    """Merge the judge's chain_9010_real ruling into the deterministic report.

    Overall verdict is conservative (locked): any criterion "fail" -> "fail";
    otherwise any "inconclusive" -> "inconclusive"; otherwise "pass". A valid
    ``llm_ruling`` overrides only ``chain_9010_real``; every other criterion is
    code-computed and passed through untouched.
    """
    criteria = dict(inp.criteria)
    if llm_ruling is not None and llm_ruling.get("chain_9010_real") in _RULING_VALUES:
        criteria["chain_9010_real"] = llm_ruling["chain_9010_real"]
    verdict: Literal["pass", "fail", "inconclusive"] = "pass"
    for value in criteria.values():
        if value == "fail":
            verdict = "fail"
            break
        if value == "inconclusive":
            verdict = "inconclusive"
    reason = (
        llm_ruling.get("reason", "")
        if llm_ruling
        else "judge LLM unavailable; report assembled from deterministic criteria only"
    )
    return M3JudgeReport(
        verdict=verdict,
        criteria=criteria,
        metrics=dict(inp.metrics),
        planner_fallback_rate=inp.planner_fallback_rate,
        evidence_refs=list(inp.evidence_refs),
        reason=reason,
        judge_model=judge_model,
        judge_tokens=judge_tokens,
    )


def _dump(obj, limit: int = _MAX_FIELD_CHARS) -> str:
    """json.dumps with ensure_ascii=False, truncated defensively when huge."""
    text = json.dumps(obj, ensure_ascii=False)
    if len(text) > limit:
        text = text[:limit] + "…[truncated]"
    return text


def _build_m3_user_message(inp: M3JudgeInput) -> str:
    """Compact user message: code-computed criteria/metrics + chain/planner evidence."""
    return "\n".join(
        [
            "M3 A/B acceptance input (numbers are code-computed; do not recompute).",
            "",
            "## Code-computed criteria",
            _dump(inp.criteria),
            "",
            "## Metrics",
            _dump(inp.metrics),
            "",
            "## 9010 chain trace excerpt",
            _dump(inp.chain_excerpt),
            "",
            "## Planner decision excerpt",
            (inp.planner_excerpt or "")[:_MAX_FIELD_CHARS],
            "",
            "Rule on chain_9010_real only. Respond with JSON only.",
        ]
    )


def make_m3_judge_fn(
    client: OpenAI, spec: ModelSpec
) -> Callable[[M3JudgeInput], M3JudgeReport | None]:
    """Build a sync M3 acceptance judge callable closed over an OpenAI client.

    The callable never raises: LLM failure or an unparseable ruling both yield
    None so the deterministic harness falls back to an inconclusive 9010
    criterion. Judge tokens are counted into ``M3JudgeReport.judge_tokens``
    (prompt + completion, 0 when usage is None) - never the attacker budget.
    """

    def _judge(inp: M3JudgeInput) -> M3JudgeReport | None:
        try:
            resp = chat_create_with_retry(
                client,
                model=spec.model,
                temperature=spec.temperature,
                messages=[
                    {"role": "system", "content": _JUDGE_M3_SYSTEM_TMPL.render()},
                    {"role": "user", "content": _build_m3_user_message(inp)},
                ],
            )
        except Exception:  # noqa: BLE001
            _log.exception("M3 judge LLM call failed; report assembled deterministically")
            return None
        usage = getattr(resp, "usage", None)
        judge_tokens = 0
        if usage is not None:
            judge_tokens = (getattr(usage, "prompt_tokens", 0) or 0) + (
                getattr(usage, "completion_tokens", 0) or 0
            )
        content = (resp.choices[0].message.content or "").strip()
        ruling = parse_m3_report(content)
        if ruling is None:
            return None
        return assemble_report(
            inp, ruling, judge_model=spec.model, judge_tokens=judge_tokens
        )

    return _judge


def _fmt_metric(value: float | None) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    return str(value)


def _render_report_markdown(report: M3JudgeReport) -> str:
    """Human-readable judge_report.md body (report formatter, not an LLM prompt)."""
    criteria_rows = "\n".join(f"| {k} | {v} |" for k, v in report.criteria.items())
    metrics_rows = "\n".join(
        f"| {k} | {_fmt_metric(v)} |" for k, v in report.metrics.items()
    )
    refs = "\n".join(f"- {r}" for r in report.evidence_refs) or "- (none)"
    chain = report.criteria.get("chain_9010_real", "inconclusive")
    return "\n".join(
        [
            "# M3 Acceptance Judge Report",
            "",
            "## Verdict",
            f"**{report.verdict}**",
            "",
            "## Judge",
            f"- model: {report.judge_model or 'n/a'}",
            f"- tokens: {report.judge_tokens}",
            "",
            "## Evidence refs (baseline + LLM eval)",
            refs,
            "",
            "## Criteria",
            "| criterion | result |",
            "|---|---|",
            criteria_rows,
            "",
            "## Metrics",
            "| metric | value |",
            "|---|---|",
            metrics_rows,
            "",
            "## 9010 chain note",
            (
                f"`chain_9010_real` = **{chain}**. This is the only criterion ruled by "
                "the LLM judge; all other criteria are code-computed and listed for audit."
            ),
            "",
            "## Reason",
            report.reason,
        ]
    )


def write_m3_report(report: M3JudgeReport, out_dir: Path) -> tuple[Path, Path]:
    """Write judge_report.json + judge_report.md under out_dir; returns their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "judge_report.json"
    md_path = out_dir / "judge_report.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(_render_report_markdown(report), encoding="utf-8")
    return json_path, md_path
