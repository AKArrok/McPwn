"""Stage-2 LLM decision points: hypothesis generation / retrospective / evidence judge.

Experiment: an "unknown-shape" vuln (vault-mcp CWE-639) that recon classes and the
signal library structurally miss. These three LLM points are the 提能 increment.
They are NOT a permutation planner (M3 lesson): they never reorder existing
candidates; they only (a) add new hypotheses after recon, (b) add follow-up
hypotheses after a zero-finding wave, and (c) ground a finding on real call
evidence when no signal fired. All prompts are externalized in
``mcp_redteam/attackers/agents/*.md`` (HANDOFF rule 3).
"""

from __future__ import annotations

import json
import logging
import os
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Template

from mcp_redteam.agent.recon import Candidate, _parse_list_tools_text
from mcp_redteam.contracts import (
    AttackTrace,
    LlmEvidenceVerdict,
    LlmHypothesis,
    McpCall,
    VulnClass,
)
from mcp_redteam.judge.parse import parse_json_object
from mcp_redteam.models.chat import chat_create_with_retry
from mcp_redteam.orchestrator.budget import TokenBudget

if TYPE_CHECKING:
    from openai import OpenAI

    from mcp_redteam.models.chat import ModelSpec

_log = logging.getLogger(__name__)

_AGENTS_OVERRIDE_DIR = os.environ.get("MCPWN_AGENTS_OVERRIDE_DIR")


def _load_agents_prompt(name: str) -> str:
    """Load an agent system prompt, preferring MCPWN_AGENTS_OVERRIDE_DIR.

    Fail-fast: when the override dir is set but the file is missing, raise -
    a silent fallback would quietly run a STRIPPED arm with HINTED prompts,
    invalidating the prompt ablation (ABLATION_PLAN.md §5).
    """
    if _AGENTS_OVERRIDE_DIR:
        p = Path(_AGENTS_OVERRIDE_DIR) / name
        if not p.exists():
            raise FileNotFoundError(
                f"override prompt {name!r} missing in "
                f"MCPWN_AGENTS_OVERRIDE_DIR={_AGENTS_OVERRIDE_DIR}"
            )
        return p.read_text(encoding="utf-8")
    return (
        files("mcp_redteam.attackers.agents")
        .joinpath(name)
        .read_text(encoding="utf-8")
    )


_HYPOTHESIS_TMPL = Template(_load_agents_prompt("hypothesis_system.md"))
_RETROSPECTIVE_TMPL = Template(_load_agents_prompt("retrospective_system.md"))
_EVIDENCE_JUDGE_TMPL = Template(_load_agents_prompt("evidence_judge_system.md"))

# LLM-proposed candidates outrank every recon regex hit so the novel lead is
# probed before budget pressure starves it (baseline showed recon's wrong
# path_traversal lead consumed all 22 calls).
_LLM_HYP_SCORE = 0.99
_MAX_HYPOTHESES = 4
_TRACE_RESULT_CAP = 300


# ── pure parsing / validation (unit-testable, no LLM) ────────────────────────


def parse_hypotheses(
    content: str,
    tools: list[str],
    resources: list[str],
    existing: set[tuple[str, str]],
    max_hypotheses: int = _MAX_HYPOTHESES,
) -> list[LlmHypothesis]:
    """Parse the hypothesis JSON; keep only grounded, non-duplicate entries."""
    obj = parse_json_object(content)
    if obj is None or not isinstance(obj.get("hypotheses"), list):
        return []
    valid_targets = set(tools) | set(resources)
    out: list[LlmHypothesis] = []
    seen: set[tuple[str, str]] = set()
    for entry in obj["hypotheses"]:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target")
        reason = entry.get("reason")
        if not isinstance(target, str) or not isinstance(reason, str):
            continue
        if target not in valid_targets:
            _log.warning("llm hypothesis dropped: invented target %r", target)
            continue
        try:
            vclass = VulnClass(entry.get("vuln_class"))
        except (ValueError, TypeError):
            _log.warning("llm hypothesis dropped: bad vuln_class %r", entry.get("vuln_class"))
            continue
        key = (vclass.value, target)
        if key in existing or key in seen:
            continue
        seen.add(key)
        out.append(LlmHypothesis(vuln_class=vclass, target=target, reason=reason[:400]))
        if len(out) >= max_hypotheses:
            break
    return out


def hypotheses_to_candidates(
    hypotheses: list[LlmHypothesis],
    tools: list[str],
    resources: list[str],
    tag: str,
) -> list[Candidate]:
    """Turn validated hypotheses into executable recon-style candidates."""
    tool_set = set(tools)
    out: list[Candidate] = []
    for h in hypotheses:
        kind = "tool" if h.target in tool_set else "resource"
        out.append(Candidate(
            vuln_class=h.vuln_class,
            target=h.target,
            target_kind=kind,
            score=_LLM_HYP_SCORE,
            reason=f"[{tag}] {h.reason}",
        ))
    return out


def _parse_evidence_verdict(content: str) -> LlmEvidenceVerdict | None:
    """Structural parse of the evidence-judge JSON (no grounding yet)."""
    obj = parse_json_object(content)
    if obj is None:
        return None
    is_finding = bool(obj.get("is_finding", False))
    if not is_finding:
        return LlmEvidenceVerdict(is_finding=False)
    try:
        vclass = VulnClass(obj.get("vuln_class"))
    except (ValueError, TypeError):
        vclass = None
    idx = obj.get("evidence_call_index")
    if not isinstance(idx, int):
        idx = None
    confidence = obj.get("confidence")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    return LlmEvidenceVerdict(
        is_finding=True,
        vuln_class=vclass,
        evidence_call_index=idx,
        evidence_text=str(obj.get("evidence_text", "")).strip(),
        confidence=max(0.0, min(1.0, confidence)),
        reason=str(obj.get("reason", ""))[:200],
    )


def ground_evidence_verdict(
    verdict: LlmEvidenceVerdict,
    calls: list[McpCall],
) -> bool:
    """Grounding gate: evidence must be a verbatim substring of a real call
    result at the cited index. The attacker's final message is never evidence.
    """
    if not verdict.is_finding:
        return False
    if verdict.evidence_call_index is None:
        return False
    idx = verdict.evidence_call_index
    if not (0 <= idx < len(calls)):
        return False
    result = calls[idx].result_text or ""
    return bool(verdict.evidence_text) and verdict.evidence_text in result


def parse_evidence_verdict(
    content: str,
    calls: list[McpCall],
) -> LlmEvidenceVerdict | None:
    """Parse + ground. Returns None when unparseable or evidence ungrounded."""
    verdict = _parse_evidence_verdict(content)
    if verdict is None:
        return None
    if verdict.is_finding and not ground_evidence_verdict(verdict, calls):
        _log.warning(
            "evidence judge returned ungrounded finding (idx=%r text=%r); dropped",
            verdict.evidence_call_index,
            (verdict.evidence_text or "")[:80],
        )
        return None
    return verdict


# ── message builders ─────────────────────────────────────────────────────────


def tool_summary(recon_calls: list[McpCall]) -> str:
    """Reconstruct 'name: description' lines from the list_tools recon call."""
    for call in recon_calls:
        if call.kind != "list_tools":
            continue
        pairs = _parse_list_tools_text(call.result_text)
        if pairs:
            return "\n".join(f"- {n}: {d}" for n, d in pairs)
    return ""


def _tools_fallback(tools: list[str], resources: list[str]) -> str:
    parts = []
    if tools:
        parts.append("Tools:\n" + "\n".join(f"- {t}" for t in tools))
    if resources:
        parts.append("Resources:\n" + "\n".join(f"- {r}" for r in resources))
    return "\n".join(parts) or "(none)"


def _trace_lines(trace: AttackTrace) -> list[str]:
    calls = list(trace.recon_calls) + list(trace.attack_calls)
    lines: list[str] = []
    for i, c in enumerate(calls):
        text = (c.result_text or "").replace("\n", " ")[:_TRACE_RESULT_CAP]
        args = json.dumps(c.args, ensure_ascii=False) if c.args else ""
        lines.append(f"[{i}] {c.kind} | {c.name or '-'} | {args} | {text}")
    if trace.final_llm_output:
        lines.append(f"final: {(trace.final_llm_output or '')[:200]}")
    return lines


def _count_into_budget(budget: TokenBudget | None, resp: object, source: str) -> None:
    if budget is None:
        return
    usage = getattr(resp, "usage", None)
    if usage is None:
        return
    pin = getattr(usage, "prompt_tokens", 0) or 0
    pout = getattr(usage, "completion_tokens", 0) or 0
    budget.add(source, pin, pout)  # type: ignore[arg-type]


# ── LLM decision points ──────────────────────────────────────────────────────


def generate_hypotheses(
    candidates: list[Candidate],
    tools: list[str],
    resources: list[str],
    client: OpenAI,
    model_spec: ModelSpec,
    budget: TokenBudget | None = None,
    tool_descriptions: str = "",
    sse_url: str | None = None,
    max_hypotheses: int = _MAX_HYPOTHESES,
    n_samples: int = 2,
) -> list[Candidate]:
    """Post-recon LLM hypothesis generation. Additive; [] on any failure.

    ``n_samples`` independent LLM samples are unioned (dedup by class+target)
    to cut single-sample variance - this is still the hypothesis decision
    point, not a permutation, and all tokens count into the attacker budget.
    """
    existing = {(c.vuln_class.value, c.target) for c in candidates}
    body = tool_descriptions or _tools_fallback(tools, resources)
    user_message = "\n".join([
        f"MCP server: {sse_url}" if sse_url else "MCP server: (unknown)",
        body,
        "Existing recon candidates (do not repeat):",
        json.dumps([
            {"vuln_class": c.vuln_class.value, "target": c.target, "reason": c.reason}
            for c in candidates
        ], ensure_ascii=False),
        f"Produce JSON {{'hypotheses': [...]}} with at most {max_hypotheses} entries.",
        "Respond with JSON only.",
    ])
    merged: list[LlmHypothesis] = []
    merged_keys: set[tuple[str, str]] = set()
    for _ in range(max(1, n_samples)):
        try:
            resp = chat_create_with_retry(
                client,
                model=model_spec.model,
                temperature=model_spec.temperature,
                seed=model_spec.seed,
                messages=[
                    {"role": "system", "content": _HYPOTHESIS_TMPL.render(
                        max_hypotheses=max_hypotheses)},
                    {"role": "user", "content": user_message},
                ],
            )
        except Exception:  # noqa: BLE001 - additive point; failure is not a crash
            _log.warning("hypothesis generation sample failed; continuing")
            continue
        _count_into_budget(budget, resp, "attacker")
        content = (resp.choices[0].message.content or "").strip()
        _log.info("hypothesis sample raw: %r", content[:500])
        for h in parse_hypotheses(content, tools, resources, existing, max_hypotheses):
            key = (h.vuln_class.value, h.target)
            if key not in merged_keys:
                merged_keys.add(key)
                merged.append(h)
    if not merged:
        _log.warning("hypothesis generation yielded no valid hypotheses")
        return []
    _log.info("llm hypothesis generated %d new candidate(s)", len(merged))
    return hypotheses_to_candidates(merged, tools, resources, "llm-hyp")


def retrospective_hypotheses(
    traces: list[AttackTrace],
    tools: list[str],
    resources: list[str],
    client: OpenAI,
    model_spec: ModelSpec,
    budget: TokenBudget | None = None,
    tool_descriptions: str = "",
    sse_url: str | None = None,
    max_hypotheses: int = _MAX_HYPOTHESES,
) -> list[Candidate]:
    """Post-wave LLM retrospective: review zero-finding traces, propose follow-ups."""
    if not traces:
        return []
    body = tool_descriptions or _tools_fallback(tools, resources)
    transcript_parts = []
    for i, trace in enumerate(traces):
        transcript_parts.append(
            f"--- trace {i}: vuln_class={trace.vuln_class.value} target={trace.target} ---\n"
            + "\n".join(_trace_lines(trace))
        )
    user_message = "\n".join([
        f"MCP server: {sse_url}" if sse_url else "MCP server: (unknown)",
        body,
        "Zero-finding trace(s):",
        "\n".join(transcript_parts),
        f"Produce JSON {{'hypotheses': [...]}} with at most {max_hypotheses} entries.",
        "Respond with JSON only.",
    ])
    try:
        resp = chat_create_with_retry(
            client,
            model=model_spec.model,
            temperature=model_spec.temperature,
            seed=model_spec.seed,
            messages=[
                {"role": "system", "content": _RETROSPECTIVE_TMPL.render(
                    max_hypotheses=max_hypotheses)},
                {"role": "user", "content": user_message},
            ],
        )
    except Exception:  # noqa: BLE001 - additive point; failure is not a crash
        _log.warning("retrospective failed; continuing without follow-ups")
        return []
    _count_into_budget(budget, resp, "attacker")
    content = (resp.choices[0].message.content or "").strip()
    _log.info("retrospective raw: %r", content[:500])
    hypotheses = parse_hypotheses(content, tools, resources, set(), max_hypotheses)
    if not hypotheses:
        return []
    _log.info("llm retrospective proposed %d follow-up candidate(s)", len(hypotheses))
    return hypotheses_to_candidates(hypotheses, tools, resources, "llm-retro")


def evidence_verdict(
    trace: AttackTrace,
    client: OpenAI,
    model_spec: ModelSpec,
    budget: TokenBudget | None = None,
) -> LlmEvidenceVerdict | None:
    """LLM evidence judgment for a zero-signal trace. Grounded or None.

    Runs like the existing L2 judge: counted out-of-band (judge source) so it
    never starves the attacker budget. None on any failure / ungrounded.
    """
    calls = list(trace.recon_calls) + list(trace.attack_calls)
    user_message = "\n".join([
        f"Hypothesis: vuln_class={trace.vuln_class.value} target={trace.target}",
        "Trace calls (index | kind | name | args | result):",
        "\n".join(_trace_lines(trace)),
        "Decide whether a real call result is evidence of a vulnerability. JSON only.",
    ])
    try:
        resp = chat_create_with_retry(
            client,
            model=model_spec.model,
            temperature=model_spec.temperature,
            seed=model_spec.seed,
            messages=[
                {"role": "system", "content": _EVIDENCE_JUDGE_TMPL.render()},
                {"role": "user", "content": user_message},
            ],
        )
    except Exception:  # noqa: BLE001 - judge silence is not a crash
        _log.warning("evidence judge call failed")
        return None
    _count_into_budget(budget, resp, "judge")
    content = (resp.choices[0].message.content or "").strip()
    return parse_evidence_verdict(content, calls)
