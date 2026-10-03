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
from typing import TYPE_CHECKING, Any

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
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.victims.agents.tool_schema_builder import build_openai_tools

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

# Scout prompt is opt-in (MCPWN_HYP_SCOUT=1) and therefore loaded lazily:
# eager loading at import time forced every MCPWN_AGENTS_OVERRIDE_DIR
# consumer (ablation arms) to ship a scout override even though the scout
# never runs there. Fail-fast is preserved where it matters - an ablation
# run that actually enables the scout without shipping its override raises
# on first use instead of silently running HINTED prompts.
_SCOUT_TMPL: Template | None = None


def _get_scout_tmpl() -> Template:
    global _SCOUT_TMPL
    if _SCOUT_TMPL is None:
        _SCOUT_TMPL = Template(_load_agents_prompt("hyp_scout_system.md"))
    return _SCOUT_TMPL

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
            origin="llm_hypothesis",
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
    budget.add_usage(source, usage)  # type: ignore[arg-type]


# ── LLM decision points ──────────────────────────────────────────────────────


# Structured-delegation scout (eval/unknown_shape/scout_exp): the FRAMEWORK
# spawns this probe subagent, so adoption does not depend on the main model's
# own choice. Hardened per scout_exp PLAN §7 Gate 1: probes capped at 4 calls
# / 2 turns / 3.5k attacker tokens so the "scout tax" stays ~<=3.5k (v1 spent
# 6.5-8.5k and starved the attack wave at 16k). The JSON final request omits
# tools entirely (cheaper, and immune to tool_choice quirks).
_SCOUT_MAX_TURNS = 2
_SCOUT_MAX_CALLS = 4
_SCOUT_PROBE_RESULT_CAP = 1200
# Hard token cap for the whole scout (probes + JSON final). The scout shares
# the attacker budget with the actual attack wave; without a cap it starved
# the first trace (smoke: scout 8.5k of 16k -> trace ran with 0 attack calls).
_SCOUT_TOKEN_CAP = 3500


async def scout_hypotheses(
    session: Any,
    candidates: list[Candidate],
    tools: list[str],
    resources: list[str],
    client: OpenAI,
    model_spec: ModelSpec,
    budget: TokenBudget | None = None,
    clock: WallClock | None = None,
    tool_descriptions: str = "",
    sse_url: str | None = None,
    max_hypotheses: int = _MAX_HYPOTHESES,
) -> list[Candidate]:
    """Pre-attack hypothesis scout: few cheap live probes, then JSON hypotheses.

    Additive; [] on any failure. Probes are NOT appended to any trace
    (grounding discipline: evidence must come from a real attack trace) -
    the scout's observations reach the attacker as ``[llm-scout]`` reason
    digests on the candidates it proposes. Run BEFORE ``generate_hypotheses``
    so dedup keeps the scout's grounded candidates over schema guesses.
    """
    existing = {(c.vuln_class.value, c.target) for c in candidates}
    surface = tool_descriptions or _tools_fallback(tools, resources)
    try:
        scout_tools = build_openai_tools(await session.raw_list_tools())
    except Exception:  # noqa: BLE001 - additive point; failure is not a crash
        _log.warning("scout: raw_list_tools failed; skipping scout")
        return []

    system_prompt = _get_scout_tmpl().render(
        sse_url=sse_url or "(unknown)",
        tool_surface=surface,
        vuln_classes=", ".join(vc.value for vc in VulnClass),
        max_calls=_SCOUT_MAX_CALLS,
        max_turns=_SCOUT_MAX_TURNS,
        max_hypotheses=max_hypotheses,
    )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                "开始侦察: 用少量真实探测调用检验哪些漏洞方向真的成立, "
                "然后按系统提示输出仅含 JSON 的最终答复。"
            ),
        },
    ]

    scout_calls: list[McpCall] = []
    probe_digest: list[str] = []
    scout_tokens = 0

    def _charge(resp: object) -> None:
        nonlocal scout_tokens
        if budget is None:
            return
        usage = getattr(resp, "usage", None)
        if usage is None:
            return
        scout_tokens += (getattr(usage, "prompt_tokens", 0) or 0) + (
            getattr(usage, "completion_tokens", 0) or 0
        )
        _count_into_budget(budget, resp, "attacker")

    for _turn in range(_SCOUT_MAX_TURNS):
        if budget is not None and budget.exceeded():
            break
        if clock is not None and clock.exceeded():
            break
        # Cap check MUST sit before the next LLM call: breaking after an
        # assistant tool_calls entry was appended (but before its tool
        # results) would leave dangling tool_calls and the next request
        # would 400 - the root cause of the v1 "JSON final failed" batch.
        if scout_tokens >= _SCOUT_TOKEN_CAP:
            _log.info(
                "scout: token cap %d reached after %d probe(s); forcing JSON final",
                _SCOUT_TOKEN_CAP, len(scout_calls),
            )
            break
        try:
            resp = chat_create_with_retry(
                client,
                model=model_spec.model,
                temperature=model_spec.temperature,
                seed=model_spec.seed,
                messages=messages,
                tools=scout_tools,
                tool_choice="auto",
            )
        except Exception:  # noqa: BLE001 - additive point; failure is not a crash
            _log.warning("scout: probe turn failed; continuing")
            break
        _charge(resp)
        msg = resp.choices[0].message
        tool_calls = getattr(msg, "tool_calls", None) or []
        entry: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if tool_calls:
            entry["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"},
                }
                for tc in tool_calls
            ]
        messages.append(entry)
        if not tool_calls:
            break  # scout went straight to its JSON final
        executed_ids: set[str] = set()
        for tc in tool_calls:
            if len(scout_calls) >= _SCOUT_MAX_CALLS:
                break
            fn_name = tc.function.name
            raw = tc.function.arguments or ""
            try:
                args = json.loads(raw) if raw.strip().startswith("{") else {}
            except json.JSONDecodeError:
                args = {"_raw": raw}
            if not isinstance(args, dict):
                args = {}
            try:
                if fn_name == "read_resource":
                    call = await session.read_resource(args.get("uri", ""))
                else:
                    call = await session.call_tool(fn_name, args)
            except Exception as exc:
                call = McpCall(
                    kind="call_tool", name=fn_name, args=args,
                    result_text=f"[mcp error] {type(exc).__name__}: {exc}", elapsed_ms=0,
                )
            scout_calls.append(call)
            probe_digest.append(
                f"{call.name}({json.dumps(call.args, ensure_ascii=False)[:100]}) "
                f"-> {(call.result_text or '')[:160]}"
            )
            executed_ids.add(tc.id)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": (call.result_text or "")[:_SCOUT_PROBE_RESULT_CAP]})
        # Close any tool_calls skipped by the per-scan call cap so the next
        # request is well-formed (every tool_call_id needs a tool message).
        for tc in tool_calls:
            if tc.id not in executed_ids:
                messages.append({
                    "role": "tool", "tool_call_id": tc.id,
                    "content": "[scout call cap reached: probe skipped]",
                })

    if scout_calls:
        _log.info("scout probes (%d): %s", len(scout_calls), " | ".join(probe_digest)[:1500])

    # Force the JSON final even when the probe loop ended on tool calls.
    # The request omits tools entirely: the scout must answer in JSON anyway,
    # and dropping the tool schemas makes this call cheaper and immune to
    # tool_choice quirks.
    final_content = ""
    for m in reversed(messages):
        if m.get("role") == "assistant":
            final_content = m.get("content") or ""
            break
    if "hypotheses" not in final_content:
        if budget is not None and budget.exceeded():
            _log.warning("scout: budget exhausted before JSON final; dropping scout")
            return []
        try:
            resp = chat_create_with_retry(
                client,
                model=model_spec.model,
                temperature=model_spec.temperature,
                seed=model_spec.seed,
                messages=messages + [{"role": "user", "content": "现在输出仅含 JSON 的最终答复。"}],
            )
            _charge(resp)
            final_content = resp.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001 - additive point; failure is not a crash
            _log.warning("scout: JSON final failed (%s: %s); no scout candidates",
                         type(exc).__name__, str(exc)[:300])
            return []
    _log.info("scout: spent ~%d attacker tokens", scout_tokens)

    hypotheses = parse_hypotheses(final_content, tools, resources, existing, max_hypotheses)
    if not hypotheses:
        _log.warning("scout yielded no valid hypotheses (probes=%d)", len(scout_calls))
        return []
    _log.info("scout proposed %d grounded candidate(s)", len(hypotheses))
    return hypotheses_to_candidates(hypotheses, tools, resources, "llm-scout")


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
        verdict = trace.llm_evidence_verdict
        verdict_line = ""
        if verdict is not None:
            verdict_line = (
                f"\n[evidence judge] is_finding={verdict.is_finding} "
                f"confidence={verdict.confidence} "
                f"reason={verdict.reason!r}"
            )
        transcript_parts.append(
            f"--- trace {i}: vuln_class={trace.vuln_class.value} target={trace.target} ---\n"
            + "\n".join(_trace_lines(trace))
            + verdict_line
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
