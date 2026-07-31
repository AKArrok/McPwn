"""PyRIT-flavored Protocol signatures — interface only, no runtime dependency on PyRIT.

Rationale: HANDOFF §5 forbids installing PyRIT (40+ heavy transitive deps). We keep the
conceptual triad (PromptTarget/Scorer/Orchestrator) so that the codebase's role
decomposition stays legible to anyone familiar with PyRIT, without paying the dependency
tax.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from mcp_redteam.contracts import AttackTrace, EvidenceSignal, ScanResult


@runtime_checkable
class PromptTarget(Protocol):
    """A model or system that consumes a prompt and returns a reply.

    In agent-first McPwn this is realized by the attacker's function-calling loop
    against the MCP server (agent-first, no resident victim LLM).
    """

    async def send(self, prompt: str, **kwargs: Any) -> str: ...


@runtime_checkable
class Scorer(Protocol):
    """Turns an `AttackTrace` into a list of `EvidenceSignal`s (agent-first v1).

    Deterministic where possible; LLM twin is a separate `llm_judged_injection`
    signal.
    """

    def score(self, trace: AttackTrace) -> list[EvidenceSignal]: ...


@runtime_checkable
class Orchestrator(Protocol):
    """Drives a full scan for one MCP endpoint (recon -> planner -> executor -> verifier)."""

    async def scan(self, sse_url: str, **kwargs: Any) -> ScanResult: ...
