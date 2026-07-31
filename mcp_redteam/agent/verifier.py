"""Verifier: given an AttackTrace, produce a Finding (or None).

M0-M2: signals-based verifier. LLM twin ('llm_judged_injection' signal) is a
placeholder detector that returns None; wiring it to an actual LLM call is M2/M3.
"""

from __future__ import annotations

from pathlib import Path

from mcp_redteam.contracts import (
    FINDING_CONFIDENCE_THRESHOLD,
    AttackTrace,
    EvidenceSignal,
    Finding,
    FindingSeverity,
    McpCall,
    VulnClass,
)
from mcp_redteam.signals import (
    compute_confidence,
    compute_finding_severity,
    run_all_signals,
)

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


def verify_trace(trace: AttackTrace) -> tuple[list[EvidenceSignal], float]:
    """Run all signals over the trace's recon_calls + attack_calls + final output.

    Signals get the *full* evidence stream so cross-call detectors like
    `tool_description_drift` can compare a recon list_tools against a refreshed
    one that executor added mid-attack. `source_call_index` refers to the
    combined list.

    Returns (signals, confidence).
    """
    all_calls = list(trace.recon_calls) + list(trace.attack_calls)
    signals = run_all_signals(all_calls, trace.final_llm_output)
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
}


def build_findings(
    traces: list[AttackTrace],
    trace_dir: Path | None = None,
) -> tuple[list[Finding], dict[str, list[EvidenceSignal]]]:
    """Turn every trace whose confidence >= threshold into a Finding.

    Returns (findings, per_trace_signals). The second element lets the caller
    write full audit even for sub-threshold traces.
    """
    findings: list[Finding] = []
    per_trace: dict[str, list[EvidenceSignal]] = {}

    for i, trace in enumerate(traces):
        signals, confidence = verify_trace(trace)
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

        finding = Finding(
            finding_id=Finding.compute_id(trace.vuln_class, trace.target, top.signal_id),
            vuln_class=trace.vuln_class,
            target=trace.target,
            severity=severity,
            confidence=confidence,
            title=f"{trace.vuln_class.value.replace('_', ' ').title()} on {trace.target}",
            summary=(
                f"Probing {trace.target!r} under hypothesis "
                f"'{trace.vuln_class.value}' fired signal(s): "
                + ", ".join(s.signal_id for s in signals)
                + f". Top signal: {top.signal_id} (severity={top.severity})."
            ),
            signals=signals,
            poc_call_sequence=_minimal_poc(trace, signals),
            remediation_hint=_REMEDIATION.get(trace.vuln_class.value, ""),
            trace_ref=trace_ref,
        )
        findings.append(finding)

    return findings, per_trace
