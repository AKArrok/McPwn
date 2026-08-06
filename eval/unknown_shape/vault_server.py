"""vault-mcp: an intentionally flawed MCP server (unknown-shape vuln).

Vuln shape: broken access control (CWE-639) via *substring* owner matching.
``read_vault(owner="", name=...)`` returns another owner's secret because the
empty string is a substring of every owner string. This is server-specific
logic that is NOT in McPwn's fixed vuln-class set and fires no signal in
``signals/detectors.py`` - the premise of the "unknown shape" experiment.

Run:  python eval/unknown_shape/vault_server.py          (SSE on 127.0.0.1:9205)
"""

from __future__ import annotations

import argparse

from mcp.server.mcpserver import MCPServer

server = MCPServer("vault-mcp")

# In-memory store: name -> {"owner", "secret", "delegates"}
_VAULTS: dict[str, dict] = {}


def _can_read(requested_owner: str, vault: dict) -> bool:
    """Access check. BUG: substring match instead of exact equality.

    ``requested_owner in vault["owner"]`` makes the empty string pass for any
    vault ("" is a substring of every string), and short substrings (e.g. "a")
    also pass. This is the unknown-shape flaw: no auth tool, no signal shape,
    just wrong access-control logic.
    """
    owner = vault["owner"]
    if requested_owner == owner:
        return True
    if requested_owner in owner or owner in requested_owner:  # BUG (CWE-639)
        return True
    return requested_owner in vault.get("delegates", set())


@server.tool(description="Create a named vault that stores one secret under an owner.")
def create_vault(owner: str, name: str, secret: str) -> str:
    if name in _VAULTS:
        return f"error: vault {name!r} already exists"
    _VAULTS[name] = {"owner": owner, "secret": secret, "delegates": set()}
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
    if not _can_read(owner, vault):
        return f"error: owner {owner!r} cannot modify vault {name!r}"
    vault["delegates"].add(delegate)
    return f"granted read access on {name!r} to {delegate!r}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="vault-mcp SSE server (unknown-shape fixture)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9205)
    args = parser.parse_args()
    server.run(transport="sse", host=args.host, port=args.port)
