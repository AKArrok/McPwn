"""Supply-chain vetting for MCP server package identities.

Given a package name (from a stdio launch command or a manifest entry),
detect:

- **typosquatting**: close-but-not-exact matches against a bundled list of
  well-known legitimate MCP server packages (public registry knowledge).
- **known-malicious**: names published as malicious by credible public
  disclosures (kept deliberately tiny; entries cite their source).

Static, offline, zero-LLM - same philosophy as ``static_scan``.
"""

from __future__ import annotations

import difflib
from typing import Any

from mcp_redteam.contracts import StaticHit

# Well-known legitimate MCP server packages (modelcontextprotocol/servers and
# popular ecosystem entries). Used ONLY as the typosquat distance baseline.
WELL_KNOWN_PACKAGES: frozenset[str] = frozenset(
    {
        "mcp-server-fetch",
        "mcp-server-filesystem",
        "mcp-server-git",
        "mcp-server-github",
        "mcp-server-memory",
        "mcp-server-sequential-thinking",
        "mcp-server-time",
        "mcp-server-everything",
        "mcp-server-puppeteer",
        "mcp-server-slack",
        "mcp-server-google-drive",
        "mcp-server-postgres",
        "mcp-server-sqlite",
        "mcp-server-brave-search",
        "mcp-server-fetch-types",
        "server-filesystem",
        "server-memory",
        "server-github",
        "server-puppeteer",
        "excel-mcp-server",
        "mcp-excel",
        "mcp-server-excel",
        "notion-mcp-server",
        "mcp-server-notion",
    }
)

# Documented malicious/impersonating MCP packages (public disclosures only).
# Sources: Koi Security "postmark-mcp" disclosure (2025-09), Invariant Labs
# tool-poisoning reports. Names only - verdicts belong to the cited reports.
KNOWN_MALICIOUS: dict[str, str] = {
    "postmark-mcp-official": "impersonates Postmark Labs' official package; "
    "exfiltrates outbound email BCCs (Koi Security disclosure 2025-09)",
    "postmark-mcp2": "known impersonation variant of postmark-mcp",
}


def _package_from_command(command: list[str]) -> str | None:
    """Best-effort package identity from a stdio launch command.

    Handles: ``uvx mcp-server-fetch``, ``npx @scope/server-x``,
    ``python -m mcp_server_fetch``, ``node dist/index.js`` (-> None).
    """
    for token in command:
        if token in ("-m", "--from", "-p"):
            continue
        if token.startswith("-"):
            continue
        if token.endswith((".py", ".js", ".exe")):
            continue
        if token in ("python", "python3", "node", "npx", "uvx", "uv"):
            continue
        return token
    return None


def vet_package_name(name: str) -> list[StaticHit]:
    """Vet one package name; returns hits (empty == nothing suspicious)."""
    name = (name or "").strip()
    if not name:
        return []
    hits: list[StaticHit] = []
    bare = name.lstrip("@").split("/", 1)[-1]  # strip npm scope
    if bare.lower() in KNOWN_MALICIOUS or name.lower() in KNOWN_MALICIOUS:
        reason = KNOWN_MALICIOUS.get(name.lower()) or KNOWN_MALICIOUS[bare.lower()]
        hits.append(
            StaticHit(
                rule_id="supplychain_known_malicious",
                severity="critical",
                subject=name,
                where="package",
                matched_text=name,
                summary=f"已知恶意/冒名 MCP 包: {reason}",
            )
        )
        return hits
    if name in WELL_KNOWN_PACKAGES:
        return hits
    matches = difflib.get_close_matches(bare, sorted(WELL_KNOWN_PACKAGES), n=2, cutoff=0.84)
    legit = {m for m in matches if m != name and abs(len(m) - len(bare)) <= 3}
    if legit:
        hits.append(
            StaticHit(
                rule_id="supplychain_typosquat",
                severity="medium",
                subject=name,
                where="package",
                matched_text=", ".join(sorted(legit)),
                summary=(
                    "包名与知名 MCP server 高度相似 (疑似 typosquat): "
                    f"{', '.join(sorted(legit))}"
                ),
            )
        )
    return hits


def vet_command(command: list[str]) -> list[StaticHit]:
    """Vet the package identity of a stdio launch command."""
    pkg = _package_from_command(command)
    return vet_package_name(pkg) if pkg else []


def vet_target_spec(spec: Any) -> list[StaticHit]:
    """Vet a TargetSpec: stdio -> package identity; HTTP -> url host check."""
    hits: list[StaticHit] = []
    command = getattr(spec, "command", None)
    if command:
        hits.extend(vet_command(command))
        return hits
    url = getattr(spec, "url", None) or ""
    if url.startswith("http://") and "127.0.0.1" not in url and "localhost" not in url:
        hits.append(
            StaticHit(
                rule_id="supplychain_plaintext_remote",
                severity="low",
                subject=url,
                where="package",
                matched_text=url,
                summary="远程目标使用明文 http:// (无 TLS), 凭证头可被中间人截获",
            )
        )
    return hits


__all__ = [
    "KNOWN_MALICIOUS",
    "WELL_KNOWN_PACKAGES",
    "vet_command",
    "vet_package_name",
    "vet_target_spec",
]
