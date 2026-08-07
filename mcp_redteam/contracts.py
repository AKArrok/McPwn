"""Cross-module data contracts. Definitive spec is HANDOFF.md paragraph 5.

Agent-first v1: McpCall retained from v0; new types added per HANDOFF paragraph 5.
Old benchmark types (Verdict, Attempt, ChallengeSpec, RunResult, FailureClass,
StopReason) have been removed. See attic/benchmark-v0/ for reference.

Any consumer/producer of these types MUST import them from here - never redefine
locally.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class VulnClass(str, Enum):
    """Eight-class MCP vulnerability taxonomy (HANDOFF paragraph 4)."""

    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "auth_bypass"
    TOOL_METADATA_PROBE = "tool_metadata_probe"
    INDIRECT_INJECTION = "indirect_injection"
    CHAIN_COMPOSITION = "chain_composition"
    SSRF = "ssrf"


McpCallKind = Literal["list_tools", "list_resources", "call_tool", "read_resource"]


class McpCall(BaseModel):
    """Unchanged from v0. One MCP action + result + timing."""

    model_config = ConfigDict(extra="forbid")

    kind: McpCallKind
    name: str | None = None
    args: dict[str, Any] | None = None
    result_text: str
    elapsed_ms: int


Severity = Literal["info", "low", "medium", "high", "critical"]
FindingSeverity = Literal["low", "medium", "high", "critical"]

# Signal severity -> confidence weight (HANDOFF paragraph 6).
# Kept here so signals/verifier/report all share the same authoritative table.
SEVERITY_WEIGHT: dict[str, float] = {
    "info": 0.0,
    "low": 0.3,
    "medium": 0.5,
    "high": 0.75,
    "critical": 0.95,
}

# Ordered severities, low -> high. Used for max-severity computation and
# stable comparisons across modules.
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# HANDOFF paragraph 5: Findings only enter findings.md when confidence >= this.
FINDING_CONFIDENCE_THRESHOLD: float = 0.6


class EvidenceSignal(BaseModel):
    """One signal firing = one piece of evidence that something suspicious happened.

    ``source_call_index`` orient: index into the *combined* list
    ``recon_calls + attack_calls`` that the detector was fed by the verifier.
    ``None`` is reserved for the L2 judge signal (``llm_judged_injection``),
    which reasons about model behaviour rather than a concrete call. Leak and
    behavioural signals are grounding-gated: they match ONLY a real
    ``McpCall.result_text`` and therefore always carry a non-``None`` index.
    Downstream consumers (verifier PoC trimming, report) MUST use this convention.
    """

    model_config = ConfigDict(extra="forbid")

    signal_id: str
    severity: Severity
    matched_text: str = Field(max_length=512)
    source_call_index: int | None = None


class AttackTrace(BaseModel):
    """Everything the agent did while probing one (vuln_class, target) pair."""

    model_config = ConfigDict(extra="forbid")

    vuln_class: VulnClass
    target: str
    strategy_card_slug: str
    recon_calls: list[McpCall] = Field(default_factory=list)
    attack_calls: list[McpCall] = Field(default_factory=list)
    attacker_messages: list[dict[str, Any]] = Field(default_factory=list)
    final_llm_output: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    elapsed_ms: int = 0
    # L2 judge verdict for indirect/chain traces; None for traces that did
    # not run the judge (off-L2-class) or where the judge returned nothing
    # usable (LLM call failed / JSON unparseable). Persisted to disk so
    # debugging 9006/9010 no longer requires re-running with a side-channel
    # verdict capture.
    judge_verdict: JudgeVerdict | None = None
    # Stage-2 LLM evidence judge verdict (unknown-shape experiment): when the
    # signal library structurally misses a flaw, this LLM decision point may
    # still ground a finding on a real call result. None = not run / nothing.
    llm_evidence_verdict: LlmEvidenceVerdict | None = None
    # Trace-level hallucination marker (diagnostic only, never a finding):
    # the attacker's final_llm_output claimed to have exfiltrated a sensitive
    # artifact (e.g. /etc/passwd, an API key) but NO signal found that content
    # in any real call result. Set by verifier.build_findings; persisted with
    # the trace so calibration runs can quantify attacker hallucination
    # without polluting findings.
    suspected_hallucination: bool = False

    @model_validator(mode="after")
    def _slug_matches_vuln_class(self) -> AttackTrace:
        # Today each VulnClass has exactly one strategy card (slug == value).
        # If that assumption ever breaks, relax this to `slug.startswith(value)`
        # or introduce an explicit mapping in vulns/registry.py.
        expected = self.vuln_class.value
        if self.strategy_card_slug != expected:
            raise ValueError(
                f"strategy_card_slug={self.strategy_card_slug!r} != "
                f"vuln_class={expected!r}"
            )
        return self


class Finding(BaseModel):
    """One suspected vulnerability, human-readable.

    ``finding_id`` is a deterministic hash of (vuln_class, target, top_signal_id).
    Use :meth:`Finding.compute_id` to construct it so producers do not diverge.
    ``confidence`` must be >= :data:`FINDING_CONFIDENCE_THRESHOLD` (0.6, HANDOFF §5);
    sub-threshold findings live in traces only.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    vuln_class: VulnClass
    target: str
    # What the recon classifier guessed; kept for backward compat.
    hypothesis_class: VulnClass | None = None
    # Inferred from the signals that fired + the call that produced them.
    # This is what the evidence actually shows, not what we guessed.
    evidence_class: VulnClass | None = None
    severity: FindingSeverity
    confidence: float = Field(ge=FINDING_CONFIDENCE_THRESHOLD, le=1.0)
    title: str
    summary: str
    signals: list[EvidenceSignal] = Field(default_factory=list)
    poc_call_sequence: list[McpCall] = Field(default_factory=list)
    remediation_hint: str = ""
    trace_ref: str = ""

    @classmethod
    def compute_id(
        cls, vuln_class: VulnClass | str, target: str, top_signal_id: str
    ) -> str:
        """Deterministic id used across producers (HANDOFF paragraph 5)."""
        slug = vuln_class.value if isinstance(vuln_class, VulnClass) else vuln_class
        h = hashlib.sha1()
        h.update(slug.encode())
        h.update(b"|")
        h.update(target.encode())
        h.update(b"|")
        h.update(top_signal_id.encode())
        return f"F-{h.hexdigest()[:10]}"


class JudgeVerdict(BaseModel):
    """One L2 judge verdict for an indirect/chain trace.

    Promoted from ``verifier.py`` dataclass to contracts so the data is
    serialisable on ``AttackTrace`` (pydantic-only contracts, HANDOFF §5).
    Contract:
      - ``steered`` True = the attacker executed an action NOT justified
        by its red-team task that traces to an instruction embedded in a
        tool/resource result (indirect prompt injection that steered the
        attacker off task).
      - ``evidence_call_index`` is the index (into recon_calls + attack_calls)
        of the call whose result carried the steering instruction, or None
        when the judge could not localise it.
      - ``reason`` is a short free-text explanation from the judge LLM,
        truncated to 200 chars at parse time.

    ``None`` (the AttackTrace default) means judge did not run or returned
    nothing usable. L2 never auto-creates a finding: it must corroborate
    an L1 signal on the same trace, see ``verifier._maybe_add_l2_signal``.
    """

    model_config = ConfigDict(extra="forbid")
    steered: bool
    evidence_call_index: int | None = None
    reason: str = ""


class LlmHypothesis(BaseModel):
    """One LLM-generated hypothesis (Stage-2 unknown-shape experiment).

    Produced by the hypothesis-generation / retrospective decision points.
    ``target`` MUST be a real tool name or resource URI from recon - invented
    targets are dropped at parse time (grounding: we only probe what exists).
    ``reason`` is actionable probe guidance shown to the attacker LLM.
    """

    model_config = ConfigDict(extra="forbid")
    vuln_class: VulnClass
    target: str
    reason: str


class LlmEvidenceVerdict(BaseModel):
    """LLM evidence-judge verdict for a trace with zero signal-library hits.

    The unknown-shape premise: a real vulnerability can exist that no detector
    in ``signals/detectors.py`` recognises. This LLM decision point may still
    emit a finding, but ONLY when grounded: ``evidence_call_index`` points at a
    real call and ``evidence_text`` is a verbatim substring of that call's
    ``result_text`` (never the attacker's final message). ``confidence`` gates
    admission (>= 0.6); the verifier maps a grounded verdict to a ``high``
    synthetic signal ``llm_evidence_verdict`` (weight 0.75) so findings still
    satisfy the HANDOFF confidence machinery. ``None`` on trace = judge did
    not run or returned nothing usable.
    """

    model_config = ConfigDict(extra="forbid")
    is_finding: bool
    vuln_class: VulnClass | None = None
    evidence_call_index: int | None = None
    evidence_text: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""


ScanStopReason = Literal[
    "completed",
    "budget_tokens",
    "budget_time",
    "user_abort",
    "error",
]


class ScanResult(BaseModel):
    """Top-level output of one ``mcpwn scan <url>`` run.

    Token accounting is split three ways per HANDOFF §6 / §9:
    attacker tokens share the ``max_tokens_total`` budget;
    ``judge_tokens`` is counted independently and MUST NOT be lumped into
    the budget. ``total_tokens`` is a derived read-only sum for reporting.

    ``stop_reason`` has no default: every scan-runner exit path must set it
    so no exception can pretend to succeed silently.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str
    sse_url: str
    started_at: str
    wall_seconds: float
    attacker_tokens: int = 0
    judge_tokens: int = 0
    tools_seen: list[str] = Field(default_factory=list)
    resources_seen: list[str] = Field(default_factory=list)
    traces: list[AttackTrace] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    stop_reason: ScanStopReason

    # Reproducibility metadata (point-in-time reproducible scans).
    # git_sha + config_snapshot + attacker_model + attacker_temperature +
    # attack_messages_sha1 answer "which code, which config, which model
    # behaviour produced this finding?" for a months-old artifact without a
    # re-run. config_snapshot is the parsed models.yaml dict;
    # attack_messages_sha1 collapses attacker_messages across all traces so
    # a behavioural drift between runs surfaces as a hash mismatch.
    git_sha: str = ""
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    attacker_model: str = ""
    attacker_temperature: float = 0.0
    attack_messages_sha1: str = ""
    # Declared sandbox root (deployment metadata, e.g. EXCEL_FILES_PATH).
    # Reproducibility anchor: which root the sandbox-escape verdict used.
    sandbox_root: str | None = None
    # Seed used for LLM sampling (provider-dependent; None = not seeded).
    # Honest "same-seed" reproducibility: scan() records the actual seed here;
    # providers that ignore seed still get drift tracked by attack_messages_sha1.
    seed: int | None = None
    # Which model performed LLM evidence judgment (judge role preferred;
    # attacker-model fallback is loud-logged). Audits the "judge out-of-band"
    # claim: tokens count as judge either way, model is recorded here.
    evidence_judge_model: str = ""

    @computed_field  # type: ignore[misc]
    @property
    def total_tokens(self) -> int:
        return self.attacker_tokens + self.judge_tokens

class PlannerDecision(BaseModel):
    """One entry in the M3 planner's complete ordered plan (HANDOFF_M3 section 2).

    The M3 judge consumes this via ``eval/dvmcp/m3_judge.py::load_planner_decisions``
    (raw dict, no re-validation), so the field names/types here are locked:
    ``port`` / ``index`` (0-based position in the port's ordered plan) /
    ``vuln_class`` / ``target`` / ``source`` (``"llm"`` or ``"fallback"``) /
    ``planned`` / ``executed`` / ``skip_reason``. ``planned``+``executed``
    separate intent from execution so the judge can distinguish "never
    planned" from "planned but starved by budget" on port 9010.
    """

    model_config = ConfigDict(extra="forbid")
    port: int
    index: int
    vuln_class: str
    target: str
    source: Literal["llm", "fallback"]
    planned: bool = True
    executed: bool = False
    skip_reason: str | None = None

class M3JudgeReport(BaseModel):
    """M3 acceptance judge output (HANDOFF_JUDGE + grill decisions).

    verdict is aggregated conservatively: any criterion "fail" -> "fail";
    otherwise any "inconclusive" -> "inconclusive"; otherwise "pass".
    criteria uses the locked keys: recall_llm_ge_hardcoded /
    fpr_llm_le_hardcoded / chain_9010_real / avg_findings_llm_ge_hardcoded /
    planner_non_fallback_ge_0_8.
    metrics holds the code-computed numbers (recall/fpr/avg_findings
    both sides, planner non-fallback rate, hallucination rate,
    n_ports_compared) so a pass/fail is independently re-verifiable
    without trusting LLM arithmetic (judge does no number inference).
    judge_model / judge_tokens record which model produced the verdict
    and the out-of-band token cost (never attacker budget).
    """

    model_config = ConfigDict(extra="forbid")
    verdict: Literal["pass", "fail", "inconclusive"]
    criteria: dict[str, Literal["pass", "fail", "inconclusive"]]
    metrics: dict[str, float | int | None]
    planner_fallback_rate: float | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    reason: str = ""
    judge_model: str = ""
    judge_tokens: int = 0
