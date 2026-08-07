"""delegate-mcp: an intentionally flawed MCP server (unknown-shape vuln, 2nd shape).

Vuln shape: broken access control (CWE-639) via *delegate grant scope* error.
``grant_access`` correctly checks that only the vault OWNER may add a delegate,
but delegates are stored in a single GLOBAL set instead of per-vault. So once
the owner delegates read access to any user, that user can read EVERY vault on
the server - including ``admin_vault`` they were never granted.

This is a different mechanism from vault-mcp (substring owner matching): no
substring logic, exact owner equality everywhere; the flaw lives in where the
grant is recorded, not how access is compared. It is also NOT in McPwn's fixed
vuln-class set and fires no signal in ``signals/detectors.py`` - same
unknown-shape premise as vault-mcp, different shape (generalization check).

Run:  python eval/generalize/delegate_server.py          (SSE on 127.0.0.1:9206)
"""

from __future__ import annotations

import argparse

from mcp.server.mcpserver import MCPServer

server = MCPServer("delegate-mcp")

# Per-vault store: name -> {"owner", "secret"}
# admin_vault's owner is a NON-GUESSABLE string (not "admin"): this is a
# deliberate isolation fixture so the only usable exploitation path is the
# grant-scope leak below - "pretend to be the owner" is not possible because
# the owner name cannot be guessed, and there is no other identity channel.
_VAULTS: dict[str, dict] = {
    "admin_vault": {
        "owner": "owner-9f7c3e21",
        "secret": "TOP-SECRET-ADMIN-VAULT-2026",
    },
}

# BUG (CWE-639): delegate grants are recorded in ONE global set shared by all
# vaults, instead of a per-vault field. Granting read access on your own vault
# therefore grants read access on every vault, including admin_vault.
_DELEGATES: set[str] = set()


def _can_read(requested_owner: str, vault: dict) -> bool:
    """Exact-match access check (NO substring bug - the flaw moved elsewhere).

    ``requested_owner == vault["owner"]`` or the owner is in the global
    delegate set. An empty string matches nothing, short prefixes match
    nothing - this shape is not bypassable by parameter tricks.
    """
    owner = vault["owner"]
    if requested_owner == owner:
        return True
    return requested_owner in _DELEGATES


@server.tool(description="Create a named vault that stores one secret under an owner.")
def create_vault(owner: str, name: str, secret: str) -> str:
    if name in _VAULTS:
        return f"error: vault {name!r} already exists"
    _VAULTS[name] = {"owner": owner, "secret": secret}
    return f"created vault {name!r} for owner {owner!r}"


@server.tool(description="Read the secret stored in a vault by name.")
def read_vault(owner: str, name: str) -> str:
    vault = _VAULTS.get(name)
    if vault is None:
        return f"error: no vault named {name!r}"
    if not _can_read(owner, vault):
        return f"error: owner {owner!r} cannot read vault {name!r}"
    return vault["secret"]


@server.tool(description="List names of vaults the given owner can read.")
def list_vaults(owner: str) -> str:
    names = [n for n, v in _VAULTS.items() if _can_read(owner, v)]
    return "vaults: " + ", ".join(names) if names else "vaults: (none)"


@server.tool(description="Add a delegate user who can read the vault.")
def grant_access(owner: str, name: str, delegate: str) -> str:
    vault = _VAULTS.get(name)
    if vault is None:
        return f"error: no vault named {name!r}"
    if owner != vault["owner"]:
        return f"error: owner {owner!r} cannot modify vault {name!r}"
    _DELEGATES.add(delegate)  # BUG: global scope, leaks to every vault
    return f"granted read access on {name!r} to {delegate!r}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="delegate-mcp SSE server (unknown-shape fixture, shape 2)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9206)
    args = parser.parse_args()
    server.run(transport="sse", host=args.host, port=args.port)
