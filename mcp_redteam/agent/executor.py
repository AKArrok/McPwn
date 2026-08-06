"""Executor: run attacker LLM loop for one (vuln_class, target) candidate.

Wraps the openai function-calling loop with:
  1. A vuln-class strategy card in the system prompt.
  2. The specific candidate (target) named in the user message.
  3. Inline signal check after each tool call - break on high/critical fire.

Uses the shared budget (attacker_tokens) from the caller.
"""

from __future__ import annotations

import json
import time
from importlib.resources import files
from typing import Any

from jinja2 import Template
from openai import OpenAI

from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import AttackTrace, McpCall, VulnClass
from mcp_redteam.models.chat import ModelSpec, chat_create_with_retry
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.signals.detectors import (
    _RUG_PULL_MARKER,
    _SHADOW_PAIR_ARG_KEY,
    _find_shadow_pair,
    _parse_list_tools_lookup,
    run_all_signals,
)
from mcp_redteam.targets.mcp_client import McpSession
from mcp_redteam.victims.agents.tool_schema_builder import build_openai_tools
from mcp_redteam.vulns.registry import load_card

_SYSTEM_TMPL = Template(
    files("mcp_redteam.attackers.agents")
    .joinpath("attacker_system.md")
    .read_text(encoding="utf-8")
)


def _render_system_prompt(
    candidate: Candidate,
    strategy_card_text: str,
    sse_url: str,
    sandbox_root: str | None = None,
) -> str:
    return _SYSTEM_TMPL.render(
        vuln_class=candidate.vuln_class.value,
        target=candidate.target,
        target_kind=candidate.target_kind,
        target_reason=candidate.reason,
        sse_url=sse_url,
        strategy_card=strategy_card_text,
        sandbox_root=sandbox_root or "未知",
    )


def _parse_tool_args(raw_args: str | None) -> dict[str, Any]:
    if not raw_args:
        return {}
    try:
        parsed = json.loads(raw_args)
        return parsed if isinstance(parsed, dict) else {"_raw": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw_args}


async def execute_one(
    session: McpSession,
    candidate: Candidate,
    attacker: tuple[OpenAI, ModelSpec],
    budget: TokenBudget,
    clock: WallClock,
    sse_url: str,
    recon_calls: list[McpCall],
    max_inner_steps: int = 12,
    sandbox_root: str | None = None,
) -> AttackTrace:
    """Probe one (vuln_class, target) candidate. Returns an AttackTrace."""
    client, model_spec = attacker

    card = load_card(candidate.vuln_class)
    system_prompt = _render_system_prompt(candidate, card.text, sse_url, sandbox_root)

    openai_tools = build_openai_tools(await session.raw_list_tools())

    attack_calls: list[McpCall] = []
    trace_started = time.perf_counter()

    # Metadata-probe candidates only: seed deterministic behavioural probes
    # BEFORE any LLM cost so that shadow_tool_behavior_divergence and
    # rug_pull_response_flip have something to compare. The LLM can still add
    # more attack_calls on top; convergence turn will summarize.
    probe_note = ""
    if candidate.vuln_class == VulnClass.TOOL_METADATA_PROBE:
        probe_note = await _seed_metadata_probes(
            session=session,
            recon_calls=recon_calls,
            attack_calls=attack_calls,
            budget=budget,
            clock=clock,
            raw_tools=await session.raw_list_tools(),
        )
    elif candidate.vuln_class == VulnClass.CHAIN_COMPOSITION:
        probe_note = await _seed_chain_probe(
            session=session,
            candidate=candidate,
            recon_calls=recon_calls,
            attack_calls=attack_calls,
            budget=budget,
            clock=clock,
            raw_tools=await session.raw_list_tools(),
        )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Target: {candidate.target_kind}={candidate.target!r}. "
                f"Vuln class hypothesis: {candidate.vuln_class.value}. "
                f"Reason: {candidate.reason}. "
                "Execute the strategy playbook. Emit tool_calls to probe the target. "
                "When you have concrete evidence (a suspicious response substring) "
                "or you've exhausted the playbook, produce a FINAL assistant message "
                "with no tool_calls: one line on what you probed and which call held the evidence (no verbatim secret quoting - the signal library reads real tool results)."
            ),
        },
    ]
    if probe_note:
        if candidate.vuln_class == VulnClass.CHAIN_COMPOSITION:
            # Chain note is self-contained: it states the seeded two-step
            # composition and tells the LLM to converge immediately.
            messages.append({"role": "user", "content": probe_note})
        else:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "The scanner has already run deterministic metadata probes "
                        "for you. Findings so far:\n" + probe_note +
                        "\nBuild on these; do not repeat identical probes. Emit a "
                        "FINAL assistant message (no tool_calls): one line on what you "
                        "probed and which call diverged or drifted (no verbatim quoting)."
                    ),
                }
            )

    total_in = 0
    total_out = 0
    final_text = ""

    for step in range(max_inner_steps):
        if budget.exceeded():
            break
        if clock.exceeded():
            break

        try:
            resp = chat_create_with_retry(
                client,
                model=model_spec.model,
                temperature=model_spec.temperature,
                seed=model_spec.seed,
                messages=messages,
                tools=openai_tools,
                tool_choice="auto",
            )
        except Exception as exc:
            final_text = f"[executor error at step {step}] {type(exc).__name__}: {exc}"
            break

        usage = getattr(resp, "usage", None)
        if usage:
            pin = getattr(usage, "prompt_tokens", 0) or 0
            pout = getattr(usage, "completion_tokens", 0) or 0
            total_in += pin
            total_out += pout
            budget.add("attacker", pin, pout)

        choice = resp.choices[0]
        msg = choice.message
        tool_calls = getattr(msg, "tool_calls", None) or []

        assistant_entry: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if tool_calls:
            assistant_entry["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments or "{}",
                    },
                }
                for tc in tool_calls
            ]
        messages.append(assistant_entry)

        if not tool_calls:
            final_text = msg.content or ""
            break

        # Execute all tool calls emitted this turn.
        for tc in tool_calls:
            if budget.exceeded() or clock.exceeded():
                # Do not silently blow the budget on a fan-out of tool calls.
                break
            fn_name = tc.function.name
            args = _parse_tool_args(tc.function.arguments)
            try:
                if fn_name == "read_resource":
                    call = await session.read_resource(args.get("uri", ""))
                else:
                    call = await session.call_tool(fn_name, args)
            except Exception as exc:
                call = McpCall(
                    kind="call_tool",
                    name=fn_name,
                    args=args,
                    result_text=f"[mcp error] {type(exc).__name__}: {exc}",
                    elapsed_ms=0,
                )
            attack_calls.append(call)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": call.result_text[:8000],
                }
            )

        # Early-exit + optional refresh once a strong signal appears.
        # - Any trace: high/critical evidence is enough, we go to convergence.
        # - TOOL_METADATA_PROBE only: refresh ``list_tools`` before convergence,
        #   since ``tool_description_drift`` needs a second snapshot. Doing this
        #   for every trace would sprinkle drift/shadow false positives into
        #   findings whose hypothesis has nothing to do with metadata.
        interim_signals = run_all_signals(
            list(recon_calls) + attack_calls, final_text or ""
        )
        if any(s.severity in {"high", "critical"} for s in interim_signals):
            if candidate.vuln_class == VulnClass.TOOL_METADATA_PROBE:
                try:
                    refresh = await session.list_tools()
                    attack_calls.append(refresh)
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Evidence collected. `list_tools` was refreshed. "
                                "Emit a FINAL assistant message (no tool_calls) "
                                "with ONE line: what you probed and which call held "
                                "the evidence. Do NOT quote secrets verbatim."
                            ),
                        }
                    )
                except Exception as exc:
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"(refresh list_tools failed: {type(exc).__name__}) "
                                "Emit a FINAL assistant message (no tool_calls) with ONE "
                                "line: what you probed and which call held the evidence. Do NOT quote secrets verbatim."
                            ),
                        }
                    )
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Evidence collected. Emit a FINAL assistant message "
                            "(no tool_calls): ONE line on what you probed and which "
                            "call held the evidence. Do NOT quote secrets verbatim."
                        ),
                    }
                )
            # Convergence turn: only spend more tokens if we still have budget.
            if budget.exceeded() or clock.exceeded():
                final_text = final_text or (msg.content or "")
                break
            try:
                final_resp = chat_create_with_retry(
                    client,
                    model=model_spec.model,
                    temperature=model_spec.temperature,
                    seed=model_spec.seed,
                    messages=messages,
                    tools=openai_tools,
                    tool_choice="none",
                )
                final_usage = getattr(final_resp, "usage", None)
                if final_usage:
                    pin = getattr(final_usage, "prompt_tokens", 0) or 0
                    pout = getattr(final_usage, "completion_tokens", 0) or 0
                    total_in += pin
                    total_out += pout
                    budget.add("attacker", pin, pout)
                final_msg = final_resp.choices[0].message
                final_text = final_msg.content or ""
                messages.append({"role": "assistant", "content": final_text})
            except Exception as exc:
                final_text = (
                    final_text
                    or f"[convergence step failed] {type(exc).__name__}: {exc}"
                )
            break

    elapsed_ms = int((time.perf_counter() - trace_started) * 1000)

    return AttackTrace(
        vuln_class=candidate.vuln_class,
        target=candidate.target,
        strategy_card_slug=card.slug,
        recon_calls=list(recon_calls),
        attack_calls=attack_calls,
        attacker_messages=messages,
        final_llm_output=final_text,
        tokens_in=total_in,
        tokens_out=total_out,
        elapsed_ms=elapsed_ms,
    )


async def _seed_metadata_probes(
    session: McpSession,
    recon_calls: list[McpCall],
    attack_calls: list[McpCall],
    budget: TokenBudget,
    clock: WallClock,
    raw_tools: list[Any],
) -> str:
    """Run deterministic probes for metadata-anomaly detection.

    Two strategies:
      1. Shadow tool probe: if list_tools reveals a pair of similarly-named
         tools, call both with the same args and tag them with
         ``_SHADOW_PAIR_ARG_KEY`` so ``shadow_tool_behavior_divergence`` can
         pair them up.
      2. Rug-pull / drift probe: pick the first tool and call it 4 times with
         the same args (tagged with ``_RUG_PULL_MARKER``) so
         ``rug_pull_response_flip`` can detect behaviour changes.

    Returns a human-readable note to pass to the LLM.
    """
    schemas: dict[str, dict[str, Any]] = {}
    for t in raw_tools:
        name = getattr(t, "name", None)
        schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
        if isinstance(name, str) and isinstance(schema, dict):
            schemas[name] = schema

    def _pick_probe_args(tool_name: str, marker_key: str, marker_val: str) -> dict[str, Any]:
        """Best-effort minimal args for a probe based on the tool's schema."""
        args: dict[str, Any] = {}
        schema = schemas.get(tool_name) or {}
        props = schema.get("properties") or {}
        required = schema.get("required") or list(props.keys())
        for key in required:
            spec = props.get(key) or {}
            typ = spec.get("type", "string")
            if typ in ("integer", "number"):
                args[key] = 1
            elif typ == "boolean":
                args[key] = False
            elif typ == "array":
                args[key] = []
            elif typ == "object":
                args[key] = {}
            else:
                args[key] = "test"
        args[marker_key] = marker_val
        return args

    lines: list[str] = []

    # ── 1. Shadow tool probe ────────────────────────────────────────────────
    # Collect the last list_tools snapshot.
    lookup: dict[str, str] = {}
    for call in reversed(recon_calls):
        if call.kind == "list_tools":
            lookup = _parse_list_tools_lookup(call.result_text)
            break
    for call in reversed(attack_calls):
        if call.kind == "list_tools":
            lookup = _parse_list_tools_lookup(call.result_text)
            break

    pair = _find_shadow_pair(lookup) if len(lookup) >= 2 else None
    if pair is not None:
        a, b = pair
        probe_args_a = _pick_probe_args(a, _SHADOW_PAIR_ARG_KEY, "pair")
        probe_args_b = _pick_probe_args(b, _SHADOW_PAIR_ARG_KEY, "pair")
        if not budget.exceeded() and not clock.exceeded():
            try:
                call_a = await session.call_tool(a, probe_args_a)
                attack_calls.append(call_a)
            except Exception as e:
                lines.append(f" -> shadow probe {a} failed: {e}")
        if not budget.exceeded() and not clock.exceeded():
            try:
                call_b = await session.call_tool(b, probe_args_b)
                attack_calls.append(call_b)
            except Exception as e:
                lines.append(f" -> shadow probe {b} failed: {e}")
        if len(attack_calls) >= 2:
            lines.append(f"Probed shadow pair {a!r} vs {b!r} with same args.")

    # ── 2. Rug-pull / drift probe ────────────────────────────────────────────
    tool_names = list(lookup.keys())
    if tool_names:
        target_tool = tool_names[0]
        rug_args = _pick_probe_args(target_tool, _RUG_PULL_MARKER, "rug")
        for idx in range(4):
            if budget.exceeded() or clock.exceeded():
                break
            try:
                call = await session.call_tool(target_tool, rug_args)
                attack_calls.append(call)
            except Exception as e:
                lines.append(f" -> rug probe #{idx + 1} {target_tool} failed: {e}")
                break
        if len(lines) > 0 or any(
            c.kind == "call_tool" and c.name == target_tool and c.args
            and c.args.get(_RUG_PULL_MARKER) == "rug"
            for c in attack_calls
        ):
            lines.append(
                f"Probed {target_tool!r} 4 times with same args to detect "
                f"behaviour flip."
            )

    # Refresh list_tools once so ``tool_description_drift`` has a second
    # snapshot to compare against the initial recon.
    if not budget.exceeded() and not clock.exceeded():
        try:
            refresh = await session.list_tools()
            attack_calls.append(refresh)
            lines.append("Refreshed list_tools for drift comparison.")
        except Exception as e:
            lines.append(f" -> refresh list_tools failed: {e}")

    return "\n".join(lines)

def _chain_probe_args(schema: dict[str, Any], value: str) -> dict[str, Any]:
    """Build chain-probe args: fill required props, set the first string prop to `value`.

    `value` is either the leak path (e.g. `/etc/passwd`) for step 1 or the leaked
    snippet for step 2. Mirrors `_pick_probe_args` but without the marker key.
    """
    props = schema.get("properties") or {}
    required = schema.get("required") or list(props.keys())
    args: dict[str, Any] = {}
    first_string: str | None = None
    for key in required:
        spec = props.get(key) or {}
        typ = spec.get("type", "string")
        if typ in ("integer", "number"):
            args[key] = 1
        elif typ == "boolean":
            args[key] = False
        elif typ == "array":
            args[key] = []
        elif typ == "object":
            args[key] = {}
        else:
            if first_string is None:
                first_string = key
            args[key] = ""
    if first_string is None:
        for key, spec in props.items():
            if (spec.get("type") or "string") == "string":
                first_string = key
                break
    if first_string is not None:
        args[first_string] = value
    return args


def _chain_snippet(result_text: str) -> str:
    """Extract a real snippet from a leak result for reuse as a later arg.

    Returns the value part after `': ` (e.g. `root:x:0:0:...` from
    `Configuration '/etc/passwd': root:x:0:0:...`) or the leading text;
    empty when the call errored. At least 6 chars so the M3 judge's
    prior-arg-link check can match a window.
    """
    text = (result_text or "").strip()
    if not text or text.startswith("[mcp error]"):
        return ""
    idx = text.find("':")
    if idx != -1:
        # Value after `':` - tolerate a space or newline separator
        snippet = text[idx + 2 :].lstrip()[:80]
    else:
        snippet = text[:80]
    snippet = snippet.strip()
    if len(snippet) < 6:
        snippet = text[:80].strip()
    return snippet[:200]


async def _seed_chain_probe(
    session: McpSession,
    candidate: Candidate,
    recon_calls: list[McpCall],
    attack_calls: list[McpCall],
    budget: TokenBudget,
    clock: WallClock,
    raw_tools: list[Any],
) -> str:
    """Deterministic 2-step composition probe for CHAIN_COMPOSITION candidates.

    Mirrors `_seed_metadata_probes`: before the LLM loop, try to establish a
    real leak via one anchor tool and consume its output via another anchor
    tool, appending both calls to `attack_calls`. Returns a self-contained
    note telling the LLM the composition is established and to converge.
    Returns "" (and leaves the LLM to probe normally) when the anchors do
    not yield a real leak or the trace is not a two-tool chain.

    This is what makes the M3 `chain_9010_real` evidence real: the later
    call's args contain a verbatim snippet of the earlier call's result
    (HANDOFF_M3: composition = later args reuse prior result, explained as
    the chain attempt's internal prior-step output).
    """
    anchors = [tok.strip() for tok in (candidate.target or "").split(",") if tok.strip()]
    tools = [a.split(":", 1)[1] for a in anchors if a.startswith("tool:")]
    if len(tools) < 2:
        return ""
    schemas: dict[str, dict[str, Any]] = {}
    for t in raw_tools:
        name = getattr(t, "name", None)
        schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None)
        if isinstance(name, str) and isinstance(schema, dict):
            schemas[name] = schema

    # Step 1: leak probe - call each anchor tool with a sensitive path until a
    # high/critical signal fires (e.g. leaks_etc_passwd from get_config('/etc/passwd')).
    leak_call: McpCall | None = None
    for name in tools:
        if budget.exceeded() or clock.exceeded():
            break
        args = _chain_probe_args(schemas.get(name) or {}, "/etc/passwd")
        if not args:
            continue
        try:
            call = await session.call_tool(name, args)
        except Exception as exc:
            call = McpCall(
                kind="call_tool",
                name=name,
                args=args,
                result_text=f"[mcp error] {type(exc).__name__}: {exc}",
                elapsed_ms=0,
            )
        attack_calls.append(call)
        signals = run_all_signals(list(recon_calls) + attack_calls, "")
        if any(s.severity in {"high", "critical"} for s in signals):
            leak_call = call
            break
    if leak_call is None:
        return ""  # no real leak; the LLM probes normally (failed attempts stay)

    snippet = _chain_snippet(leak_call.result_text)
    if not snippet:
        return ""

    # Step 2: consume probe - feed the leaked snippet into another anchor tool.
    for name in tools:
        if name == leak_call.name:
            continue
        if budget.exceeded() or clock.exceeded():
            break
        args = _chain_probe_args(schemas.get(name) or {}, snippet)
        if not args:
            continue
        try:
            call = await session.call_tool(name, args)
        except Exception as exc:
            call = McpCall(
                kind="call_tool",
                name=name,
                args=args,
                result_text=f"[mcp error] {type(exc).__name__}: {exc}",
                elapsed_ms=0,
            )
        attack_calls.append(call)
        return (
            "扫描器已确定性建立两步组合证据: ① "
            f"{leak_call.name}({json.dumps(leak_call.args, ensure_ascii=False)}) "
            "返回了真实敏感内容; ② "
            f"{name}({json.dumps(args, ensure_ascii=False)}) 的参数复用了第一步返回片段。"
            "证据已足够。直接产生 FINAL assistant message (no tool_calls): 一句话说明你链了"
            "哪两步、证据落在哪两条 call。不要重复调用。"
        )
    return ""
