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
    """Seven-class MCP vulnerability taxonomy (HANDOFF paragraph 4)."""

    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "auth_bypass"
    TOOL_METADATA_PROBE = "tool_metadata_probe"
    INDIRECT_INJECTION = "indirect_injection"
    CHAIN_COMPOSITION = "chain_composition"


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

    @computed_field  # type: ignore[misc]
    @property
    def total_tokens(self) -> int:
        return self.attacker_tokens + self.judge_tokens
