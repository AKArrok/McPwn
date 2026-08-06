"""Verifier: given an AttackTrace, produce a Finding (or None).

M0-M2: signals-based verifier. LLM twin ('llm_judged_injection' signal) is a
placeholder detector that returns None; wiring it to an actual LLM call is M2/M3.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from jinja2 import Template

from mcp_redteam.agent.llm_points import ground_evidence_verdict
from mcp_redteam.contracts import (
    FINDING_CONFIDENCE_THRESHOLD,
    AttackTrace,
    EvidenceSignal,
    Finding,
    FindingSeverity,
    JudgeVerdict,
    LlmEvidenceVerdict,
    McpCall,
    VulnClass,
)
from mcp_redteam.judge.parse import parse_judge_json
from mcp_redteam.signals import (
    compute_confidence,
    compute_finding_severity,
    run_all_signals,
)

if TYPE_CHECKING:
    from openai import OpenAI

    from mcp_redteam.models.chat import ModelSpec
    from mcp_redteam.orchestrator.budget import TokenBudget

_log = logging.getLogger(__name__)

# Re-export the threshold under the historical name so external code / tests
# that imported ``verifier.CONFIDENCE_THRESHOLD`` still work.
CONFIDENCE_THRESHOLD = FINDING_CONFIDENCE_THRESHOLD

# Signals that constitute valid evidence for a tool_metadata_probe finding.
# Leak/behavioral signals are excluded: a tool_metadata_probe trace that calls
# a vulnerable tool will trip leak detectors, but that evidence belongs to the
# tool's own vuln_class (e.g. path_traversal), not to metadata probing.
_METADATA_ONLY_SIGNALS = frozenset({
    "tool_description_drift",
    "shadow_tool_pair",
    "shadow_tool_behavior_divergence",
    "rug_pull_response_flip",
    "suspicious_error_pitch",
    "stored_injection_roundtrip",
})


def verify_trace(
    trace: AttackTrace, sandbox_root: str | None = None
) -> tuple[list[EvidenceSignal], float]:
    """Run all signals over the trace's recon_calls + attack_calls + final output.

    Signals get the *full* evidence stream so cross-call detectors like
    `tool_description_drift` can compare a recon list_tools against a refreshed
    one that executor added mid-attack. `source_call_index` refers to the
    combined list.

    Returns (signals, confidence).
    """
    all_calls = list(trace.recon_calls) + list(trace.attack_calls)
    signals = run_all_signals(all_calls, trace.final_llm_output, sandbox_root=sandbox_root)
    # tool_metadata_probe traces must only produce metadata-class evidence;
    # leak/behavioral signals that fired because the probed tool happens to be
    # vulnerable (e.g. DVMCP-9001 get_user_info leaks credentials) would
    # produce a spurious finding under the wrong vuln_class.
    if trace.vuln_class == VulnClass.TOOL_METADATA_PROBE:
        signals = [s for s in signals if s.signal_id in _METADATA_ONLY_SIGNALS]
    confidence = compute_confidence(signals)
    return signals, confidence


def _minimal_poc(trace: AttackTrace, signals: list[EvidenceSignal]) -> list[McpCall]:
    """Return the minimal replayable attack_call sequence.

    Because `verify_trace` feeds the combined list `recon_calls + attack_calls`
    into detectors, `source_call_index` refers to the combined list index.
    We subtract `len(recon_calls)` to get the index into `attack_calls`.
    If no signal has a usable index, keep all attack_calls.
    """
    if not trace.attack_calls:
        return []
    recon_offset = len(trace.recon_calls)
    attack_indices = []
    for s in signals:
        if s.source_call_index is None:
            continue
        adjusted = s.source_call_index - recon_offset
        if adjusted >= 0:
            attack_indices.append(adjusted)
    if not attack_indices:
        return list(trace.attack_calls)
    max_attack_idx = max(attack_indices)
    return list(trace.attack_calls[: max_attack_idx + 1])


def _pick_top_signal(signals: list[EvidenceSignal]) -> EvidenceSignal:
    order = ["info", "low", "medium", "high", "critical"]
    return max(signals, key=lambda s: order.index(s.severity))


_REMEDIATION: dict[str, str] = {
    "direct_prompt_injection":
        "Isolate resource templates from LLM-consumed context; sanitize URI parameters and refuse "
        "sensitive-namespace resource reads inside user-controllable flows.",
    "command_injection":
        "Never pass tool arguments through a shell. Use argv-style APIs and strict allow-lists.",
    "path_traversal":
        "Constrain file paths to a whitelisted root; resolve to absolute path and reject anything "
        "outside the root. Reject `..`, symlinks, and URL-encoded traversal.",
    "auth_bypass":
        "Require cryptographically-verifiable tokens; enforce non-empty auth and role checks server-side.",
    "tool_metadata_probe":
        "Freeze tool descriptions and lists after startup; detect and reject shadow-name registrations.",
    "indirect_injection":
        "Do not feed tool outputs back into the same LLM without provenance markers; strip or "
        "quarantine embedded instructions in user documents before summarization.",
    "chain_composition":
        "Assume any single-class defense can be bypassed by composition; layer authz + input "
        "validation + output filtering.",
    "ssrf":
        "Never fetch user-supplied URLs server-side; allowlist destinations (no loopback, "
        "private ranges, or cloud metadata endpoints) and restrict URL schemes to http(s).",
}


_L2_CLASSES = frozenset({VulnClass.INDIRECT_INJECTION, VulnClass.CHAIN_COMPOSITION})


# Re-export JudgeVerdict from contracts for backward compat. Canonical
# type lives in mcp_redteam.contracts (pydantic) so it can be a field on
# AttackTrace. Tests and external consumers can still import from here.
__all__ = [
    "CONFIDENCE_THRESHOLD",
    "JudgeFn",
    "JudgeVerdict",
    "build_findings",
    "make_judge_fn",
    "verify_trace",
]


# Sync callable: build_findings runs outside the async MCP session.
JudgeFn = Callable[[AttackTrace, "TokenBudget | None"], JudgeVerdict | None]


# L2 judge prompts are externalized (HANDOFF rule 3): the system
# instructions live in judge_system.md and the user layout in judge_user.md.
# Data assembly (call/action lines) stays in Python; all prose lives in the
# templates.
_JUDGE_SYSTEM_TMPL = Template(
    files("mcp_redteam.judge.agents").joinpath("judge_system.md").read_text(encoding="utf-8")
)
_JUDGE_USER_TMPL = Template(
    files("mcp_redteam.judge.agents").joinpath("judge_user.md").read_text(encoding="utf-8")
)


def _build_judge_user_message(trace: AttackTrace) -> str:
    """Render the L2 judge user message from judge_user.md (data assembly)."""
    all_calls = list(trace.recon_calls) + list(trace.attack_calls)
    call_lines = []
    for i, c in enumerate(all_calls):
        text = (c.result_text or "").replace("\n", " ")[:400]
        call_lines.append(f"[{i}] {c.kind} | {c.name!r} | {text}")
    action_lines: list[str] = []
    for m in trace.attacker_messages:
        role = m.get("role", "")
        if role == "assistant":
            tcs = m.get("tool_calls")
            content = (m.get("content") or "")[:200]
            if tcs:
                names = [t.get("function", {}).get("name", "?") for t in tcs]
                action_lines.append(f"  assistant tool_calls={names} | {content!r}")
            else:
                action_lines.append(f"  assistant final: {content!r}")
    return _JUDGE_USER_TMPL.render(
        vuln_class=trace.vuln_class.value,
        target=trace.target,
        calls="\n".join(call_lines),
        actions="\n".join(action_lines),
    )


def make_judge_fn(client: OpenAI, spec: ModelSpec) -> JudgeFn:
    """Build a sync judge callable closed over an OpenAI-compatible client.

    The callable takes (trace, budget) and returns a JudgeVerdict or None. It
    never raises: LLM call failure or unparseable JSON both yield None, so the
    verifier treats judge silence as not-steered. Judge tokens are counted
    out-of-band into budget.judge_tokens (never the attacker budget).
    """

    def _judge(trace: AttackTrace, budget: TokenBudget | None) -> JudgeVerdict | None:
        if not trace.attack_calls:
            return None
        user_msg = _build_judge_user_message(trace)
        try:
            create_kwargs: dict[str, Any] = {
                "model": spec.model,
                "temperature": spec.temperature,
                "messages": [
                    {"role": "system", "content": _JUDGE_SYSTEM_TMPL.render()},
                    {"role": "user", "content": user_msg},
                ],
            }
            if spec.seed is not None:
                create_kwargs["seed"] = spec.seed
            resp = client.chat.completions.create(**create_kwargs)
        except Exception:  # noqa: BLE001
            _log.exception("judge LLM call failed; treating as not-steered")
            return None
        usage = getattr(resp, "usage", None)
        if usage is not None and budget is not None:
            budget.add(
                "judge",
                getattr(usage, "prompt_tokens", 0) or 0,
                getattr(usage, "completion_tokens", 0) or 0,
            )
        content = (resp.choices[0].message.content or "").strip()
        return parse_judge_json(content)

    return _judge


def _maybe_add_l2_signal(
    trace: AttackTrace,
    signals: list[EvidenceSignal],
    judge_fn: JudgeFn | None,
    budget: TokenBudget | None,
) -> list[EvidenceSignal]:
    """Run the L2 judge twin on indirect/chain traces; maybe add one signal.

    Grounding contract: L2 is the ONLY signal that may carry
    source_call_index=None. It is medium severity (0.5), so it cannot cross the
    0.6 threshold alone - it needs deterministic L1 corroboration
    (stored_injection_roundtrip / tool_description_drift). The judge can
    therefore only raise confidence, never single-handedly create a finding.
    """
    if judge_fn is None or trace.vuln_class not in _L2_CLASSES or not trace.attack_calls:
        return signals
    try:
        verdict = judge_fn(trace, budget)
    except Exception:  # noqa: BLE001
        _log.exception("judge_fn raised; skipping L2 signal")
        return signals
    # Persist the verdict regardless of steered/None so debug of 9006/9010
    # no longer requires re-running the scan with a side-channel capture.
    if verdict is not None:
        trace.judge_verdict = verdict
    if verdict is None or not verdict.steered:
        return signals
    return signals + [
        EvidenceSignal(
            signal_id="llm_judged_injection",
            severity="medium",
            matched_text=f"judge:steered evidence_call_index={verdict.evidence_call_index}",
            source_call_index=verdict.evidence_call_index,
        )
    ]




_SIGNAL_TO_CLASS: dict[str, VulnClass] = {
    "unauthenticated_success": VulnClass.AUTH_BYPASS,
    "admin_action_confirmed": VulnClass.AUTH_BYPASS,
    "command_exec_uid_stdout": VulnClass.COMMAND_INJECTION,
    "command_exec_ls_root": VulnClass.COMMAND_INJECTION,
    "tool_description_drift": VulnClass.TOOL_METADATA_PROBE,
    "shadow_tool_pair": VulnClass.TOOL_METADATA_PROBE,
    "shadow_tool_behavior_divergence": VulnClass.TOOL_METADATA_PROBE,
    "rug_pull_response_flip": VulnClass.TOOL_METADATA_PROBE,
    "suspicious_error_pitch": VulnClass.TOOL_METADATA_PROBE,
    "stored_injection_roundtrip": VulnClass.INDIRECT_INJECTION,
    "llm_judged_injection": VulnClass.INDIRECT_INJECTION,
    "sandbox_escape_write": VulnClass.PATH_TRAVERSAL,
    "sandbox_escape_read": VulnClass.PATH_TRAVERSAL,
    "sandbox_escape_traversal": VulnClass.PATH_TRAVERSAL,
    "ssrf_cloud_metadata": VulnClass.SSRF,
    "ssrf_internal_service": VulnClass.SSRF,
}

_FILE_TOOL_RE = re.compile(r"file|read|download|config|manager", re.IGNORECASE)
_SHELL_TOOL_RE = re.compile(r"exec|command|shell|run|eval|evaluate", re.IGNORECASE)


def _infer_evidence_class(
    signals: list[EvidenceSignal], trace: AttackTrace
) -> VulnClass:
    """Infer the vuln class from the signals that fired, not the hypothesis.

    Leak signals (leaks_etc_passwd etc.) are context-dependent: the same
    signal can indicate path_traversal (via a file tool) or command_injection
    (via a shell tool). We look at the call that produced the leak to decide.
    """
    classes: set[VulnClass] = set()
    all_calls = list(trace.recon_calls) + list(trace.attack_calls)

    for sig in signals:
        if sig.signal_id in _SIGNAL_TO_CLASS:
            classes.add(_SIGNAL_TO_CLASS[sig.signal_id])
        elif sig.signal_id.startswith("leaks_") and sig.source_call_index is not None and sig.source_call_index < len(all_calls):
                call = all_calls[sig.source_call_index]
                if call.kind == "read_resource":
                    classes.add(VulnClass.DIRECT_PROMPT_INJECTION)
                elif call.name and _FILE_TOOL_RE.search(call.name):
                    classes.add(VulnClass.PATH_TRAVERSAL)
                elif call.name and _SHELL_TOOL_RE.search(call.name):
                    classes.add(VulnClass.COMMAND_INJECTION)

    if not classes:
        return trace.vuln_class
    if len(classes) == 1:
        return next(iter(classes))
    # Multiple distinct classes fired -> chain composition
    return VulnClass.CHAIN_COMPOSITION


def build_findings(
    traces: list[AttackTrace],
    trace_dir: Path | None = None,
    budget: TokenBudget | None = None,
    judge_fn: JudgeFn | None = None,
    sandbox_root: str | None = None,
    evidence_judge_fn: Callable[[AttackTrace], LlmEvidenceVerdict | None] | None = None,
) -> tuple[list[Finding], dict[str, list[EvidenceSignal]]]:
    """Turn every trace whose confidence >= threshold into a Finding.

    judge_fn (optional) runs the L2 judge twin only on indirect_injection /
    chain_composition traces and may add one llm_judged_injection medium signal;
    L2 alone cannot cross the 0.6 threshold (needs L1 corroboration), so the
    judge can only raise confidence, never single-handedly create a finding.
    budget counts judge tokens out-of-band. Returns (findings, per_trace).
    """
    findings: list[Finding] = []
    per_trace: dict[str, list[EvidenceSignal]] = {}

    for i, trace in enumerate(traces):
        signals, _ = verify_trace(trace, sandbox_root)
        signals = _maybe_add_l2_signal(trace, signals, judge_fn, budget)

        # Stage-2 LLM evidence judge: only for traces where the deterministic
        # signal library found nothing (unknown-shape vulns). The verdict is
        # grounding-gated - evidence must be a verbatim substring of a real
        # call result - so it cannot fabricate findings. Runs out-of-band
        # (judge source) via the caller-supplied closure.
        llm_verdict: LlmEvidenceVerdict | None = None
        if not signals and evidence_judge_fn is not None:
            verdict = evidence_judge_fn(trace)
            if verdict is not None:
                trace.llm_evidence_verdict = verdict
                all_calls = list(trace.recon_calls) + list(trace.attack_calls)
                if (
                    verdict.is_finding
                    and verdict.confidence >= CONFIDENCE_THRESHOLD
                    and ground_evidence_verdict(verdict, all_calls)
                ):
                    signals = [
                        EvidenceSignal(
                            signal_id="llm_evidence_verdict",
                            severity="high",
                            matched_text=(verdict.evidence_text or "")[:512],
                            source_call_index=verdict.evidence_call_index,
                        )
                    ]
                    llm_verdict = verdict

        confidence = compute_confidence(signals) if signals else 0.0
        trace_key = f"{trace.vuln_class.value}::{trace.target}"
        per_trace[trace_key] = signals

        if not signals or confidence < CONFIDENCE_THRESHOLD:
            continue

        top = _pick_top_signal(signals)
        raw_severity = compute_finding_severity(signals)
        # Finding.severity Literal has no 'info'; a leftover 'info'-only signal
        # set floors at 'low' (should not happen once low-severity signals are
        # added but keeps the type contract honest).
        severity: FindingSeverity = (
            "low" if raw_severity == "info" else raw_severity  # type: ignore[assignment]
        )

        trace_ref = ""
        if trace_dir is not None:
            fname = f"trace_{i:03d}_{trace.vuln_class.value}.json"
            (trace_dir / fname).write_text(
                trace.model_dump_json(indent=2), encoding="utf-8"
            )
            trace_ref = str(trace_dir / fname)

        evidence_class = _infer_evidence_class(signals, trace)
        if llm_verdict is not None and llm_verdict.vuln_class is not None:
            finding_vuln_class = llm_verdict.vuln_class
            evidence_class = llm_verdict.vuln_class
        else:
            finding_vuln_class = trace.vuln_class

        if llm_verdict is not None:
            summary = (
                f"LLM evidence judge (grounded, unknown-shape) on {trace.target!r}: "
                f"{llm_verdict.reason or 'reason n/a'} "
                f"(confidence={llm_verdict.confidence:.2f}, call "
                f"#{llm_verdict.evidence_call_index})."
            )
        else:
            summary = (
                f"Probing {trace.target!r} under hypothesis "
                f"'{trace.vuln_class.value}' fired signal(s): "
                + ", ".join(s.signal_id for s in signals)
                + f". Top signal: {top.signal_id} (severity={top.severity})."
            )

        finding = Finding(
            finding_id=Finding.compute_id(finding_vuln_class, trace.target, top.signal_id),
            vuln_class=finding_vuln_class,
            hypothesis_class=trace.vuln_class,
            evidence_class=evidence_class,
            target=trace.target,
            severity=severity,
            confidence=confidence,
            title=f"{finding_vuln_class.value.replace('_', ' ').title()} on {trace.target}",
            summary=summary,
            signals=signals,
            poc_call_sequence=_minimal_poc(trace, signals),
            remediation_hint=_REMEDIATION.get(finding_vuln_class.value, ""),
            trace_ref=trace_ref,
        )
        findings.append(finding)

    return findings, per_trace
