"""Smoke test for the fresh-vault-server helper (Stage-3 state-isolation fix).

Spawns a real ``vault_server.py`` subprocess, asserts the MCP surface is up
and actually executes tools, then checks the child is gone after the context
exits. Hermetic: no LLM, no external API.
"""

from __future__ import annotations

import socket

from eval.unknown_shape._fresh_server import fresh_vault_server
from mcp_redteam.targets.mcp_client import McpSession


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _port_accepts(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


async def test_fresh_vault_server_executes_tools_and_terminates():
    port = _free_port()
    async with fresh_vault_server(port) as sse_url, McpSession(sse_url) as s:
        tools = await s.raw_list_tools()
        names = {getattr(t, "name", "") for t in tools}
        assert {"create_vault", "read_vault", "list_vaults", "grant_access"} <= names

        created = await s.call_tool(
            "create_vault",
            {"owner": "admin", "name": "smoke-vault", "secret": "s3cr3t"},
        )
        assert "created" in created.result_text
        read = await s.call_tool(
            "read_vault", {"owner": "admin", "name": "smoke-vault"}
        )
        assert read.result_text == "s3cr3t"

    # After the context exits the child must be dead: the port refuses TCP.
    assert not _port_accepts(port)
