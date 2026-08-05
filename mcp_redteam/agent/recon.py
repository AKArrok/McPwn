"""Recon stage: list tools + resources, tag each with candidate VulnClass.

The classifier here is deliberately dumb (name/description regex) so it is fast,
deterministic, and testable. The LLM planner (M4) may override.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_redteam.contracts import McpCall, VulnClass
from mcp_redteam.targets.mcp_client import McpSession


@dataclass(frozen=True, slots=True)
class Candidate:
    """One (vuln_class, target) probe candidate."""

    vuln_class: VulnClass
    target: str                          # tool name or resource URI
    target_kind: str                     # "tool" | "resource"
    score: float                         # heuristic priority
    reason: str                          # why we picked this


# ── classifier heuristics ────────────────────────────────────────────────────

_TOOL_PATTERNS: list[tuple[re.Pattern[str], VulnClass, str, float]] = [
    (re.compile(r"\b(exec|execute|shell|run|command|eval|evaluate)\b", re.IGNORECASE),
        VulnClass.COMMAND_INJECTION, "tool name/desc suggests shell/eval", 0.9),
    (re.compile(r"\b(file|read|open|download|config)\b", re.IGNORECASE),
        VulnClass.PATH_TRAVERSAL, "tool name/desc suggests file read", 0.8),
    (re.compile(r"\b(admin|manage|token|auth|verify|remote_access)\b", re.IGNORECASE),
        VulnClass.AUTH_BYPASS, "tool name/desc suggests auth-gated action", 0.95),
    (re.compile(r"\b(process|analyze|summarize|document|email|note)\b", re.IGNORECASE),
        VulnClass.INDIRECT_INJECTION, "tool processes user-supplied text", 0.6),
]


_RESOURCE_PATTERNS: list[tuple[re.Pattern[str], VulnClass, str, float]] = [
    (re.compile(r"\{[^}]+\}"),
        VulnClass.DIRECT_PROMPT_INJECTION, "resource URI has template parameter", 0.85),
    (re.compile(r"^(internal|admin|config|secret)://", re.IGNORECASE),
        VulnClass.DIRECT_PROMPT_INJECTION, "sensitive-namespace resource", 0.7),
]


def _classify_tool(name: str, description: str) -> list[tuple[VulnClass, str, float]]:
    """Return list of (class, reason, score) for a tool."""
    hits: list[tuple[VulnClass, str, float]] = []
    haystack = f"{name} {description}"
    for pattern, vclass, reason, score in _TOOL_PATTERNS:
        if pattern.search(haystack):
            hits.append((vclass, reason, score))
    return hits


def _classify_resource(uri: str) -> list[tuple[VulnClass, str, float]]:
    hits: list[tuple[VulnClass, str, float]] = []
    for pattern, vclass, reason, score in _RESOURCE_PATTERNS:
        if pattern.search(uri):
            hits.append((vclass, reason, score))
    return hits


# ── parsers ──────────────────────────────────────────────────────────────────


def _parse_list_tools_text(text: str) -> list[tuple[str, str]]:
    """Legacy: parse ``McpCall(kind=list_tools).result_text`` back into pairs.

    Preferred path is now :meth:`McpSession.raw_list_tools`, which returns the
    structured SDK objects directly. Kept here so tests and any external caller
    that only has the text form (e.g. replaying a stored trace) still work, but
    ``recon()`` no longer uses it.
    """
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        content = stripped[2:]
        colon_pos = content.find(":")
        if colon_pos == -1:
            out.append((content.strip(), ""))
            continue
        out.append((content[:colon_pos].strip(), content[colon_pos + 1:].strip()))
    return out


def _parse_list_resources_text(text: str) -> list[str]:
    """Extract resource URIs from list_resources result_text.

    Format: '- {uri} ({name}): {description}' per line.
    """
    uris: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        content = stripped[2:]
        # URI stops at first whitespace or parenthesis
        m = re.match(r"([^\s(]+)", content)
        if m:
            uris.append(m.group(1))
    return uris


# ── public API ───────────────────────────────────────────────────────────────


async def recon(
    session: McpSession,
) -> tuple[list[McpCall], list[Candidate], list[str], list[str]]:
    """Perform recon: list tools + list resources; classify each into candidates.

    Uses ``raw_list_tools``/``raw_list_resources`` for structured input so
    descriptions containing colons or newlines don't corrupt classification.
    The trace-friendly text form is still produced (via ``list_tools`` /
    ``list_resources``) so downstream detectors that read ``result_text`` see
    the same content.
    """
    lt_call = await session.list_tools()
    lr_call = await session.list_resources()
    recon_calls = [lt_call, lr_call]

    tools = await session.raw_list_tools()
    resources = await session.raw_list_resources()

    tool_pairs: list[tuple[str, str]] = [
        (getattr(t, "name", "") or "", getattr(t, "description", "") or "")
        for t in tools
    ]
    resource_uris: list[str] = [
        str(getattr(r, "uri", "") or "") for r in resources
    ]

    candidates: list[Candidate] = []
    for name, description in tool_pairs:
        for vclass, reason, score in _classify_tool(name, description):
            candidates.append(Candidate(
                vuln_class=vclass,
                target=name,
                target_kind="tool",
                score=score,
                reason=reason,
            ))

    for uri in resource_uris:
        for vclass, reason, score in _classify_resource(uri):
            candidates.append(Candidate(
                vuln_class=vclass,
                target=uri,
                target_kind="resource",
                score=score,
                reason=reason,
            ))

    # Chain-composition heuristic: if recon produced candidates for >= 2
    # distinct vuln classes (excluding the always-on metadata probe), add a
    # chain_composition candidate. The target is a comma-joined list of
    # kind:name tokens (e.g. "tool:read_file,resource:internal://admin")
    # that the strategy card's {{controllable_uri}}/{{file_tool}}/
    # {{admin_tool}} placeholders can latch onto. Score 0.7 is below every
    # individual class (0.95/0.9/0.85/0.8) but above INDIRECT (0.6) so
    # chain runs after individuals but before budget pressure typically
    # hits the smaller-class probes. The L2 judge will be called for this
    # trace (chain_composition is in _L2_CLASSES) so cross-trace causation
    # is also checked end-to-end.
    distinct = sorted({c.vuln_class for c in candidates
                       if c.vuln_class != VulnClass.TOOL_METADATA_PROBE},
                      key=lambda v: v.value)
    if len(distinct) >= 2:
        # Top 4 individual candidates by score (deduped) become the chain
        # target list. Capping keeps the strategy card / LLM context bounded.
        indiv = [c for c in candidates
                 if c.vuln_class != VulnClass.TOOL_METADATA_PROBE]
        indiv.sort(key=lambda c: c.score, reverse=True)
        seen: set[str] = set()
        tokens: list[str] = []
        for c in indiv:
            tok = c.target_kind + ":" + c.target
            if tok in seen:
                continue
            seen.add(tok)
            tokens.append(tok)
            if len(tokens) >= 4:
                break
        candidates.append(Candidate(
            vuln_class=VulnClass.CHAIN_COMPOSITION,
            target=",".join(tokens),
            target_kind="chain",
            score=0.7,
            reason=(
                f"{len(distinct)} distinct vuln classes in recon ("
                + ",".join(v.value for v in distinct)
                + f"); chain top-{len(tokens)} anchors"
            ),
        ))

    # ALWAYS add a tool_metadata_probe candidate whenever the server exposes
    # at least one tool. Two behavioural signals cover this class:
    #   - shadow_tool_pair / shadow_tool_behavior_divergence need >= 2 tools;
    #     the executor only fires the compare-probe when it finds a pair.
    #   - tool_description_drift / rug_pull_response_flip only need one tool
    #     (executor invokes it N times then refreshes list_tools).
    # A stricter >=2 gate hid DVMCP challenge 4 (single-tool rug pull) from
    # the pipeline entirely.
    if len(tool_pairs) >= 1:
        reason = (
            "multiple tools; probe shadow/drift/rug pull"
            if len(tool_pairs) >= 2
            else "single tool; probe drift/rug pull"
        )
        candidates.append(Candidate(
            vuln_class=VulnClass.TOOL_METADATA_PROBE,
            target="n/a",
            target_kind="meta",
            score=0.4,
            reason=reason,
        ))

    tools_seen = [name for name, _ in tool_pairs]
    return recon_calls, candidates, tools_seen, resource_uris
