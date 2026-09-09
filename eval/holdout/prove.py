"""Deterministic exploit proof for the cache-mcp holdout pair.

VULNERABLE version: PASS when a cross-tenant read returns another tenant's
cached value (tenant A stores under 'config', tenant B reads it back).
FIXED version: the same sequence must be blocked ("no entry").

Usage:
    python eval/holdout/prove.py            # vulnerable version must leak
    python eval/holdout/prove.py --fixed    # fixed version must deny
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.holdout.fixtures._fresh import fresh_cache_target
from mcp_redteam.targets.mcp_client import McpSession

SECRET = "SECRET-CONF-ALICE-2026"


async def main(fixed: bool) -> None:
    port = 19216 if fixed else 19215
    async with fresh_cache_target(port, fixed=fixed) as url, McpSession(url) as s:
        set_resp = await s.call_tool(
            "cache_set",
            {"owner": "alice", "key": "config", "value": SECRET},
        )
        assert "stored" in set_resp.result_text, set_resp.result_text

        leaked = await s.call_tool(
            "cache_get", {"owner": "bob", "key": "config"}
        )
        if fixed:
            assert SECRET not in leaked.result_text, leaked.result_text
            assert "no entry" in leaked.result_text, leaked.result_text
            print("PASS (fixed): cross-tenant read denied by owner namespace")
        else:
            assert SECRET in leaked.result_text, leaked.result_text
            print(f"PASS (vuln): cross-tenant cache pollution read {SECRET}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()
    asyncio.run(main(args.fixed))
