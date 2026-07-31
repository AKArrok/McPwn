"""Fake ``McpSession`` recording 9001's behaviour for offline regression tests.

Born from the LLM rate limit (429) hit during B verification: when the real
attacker LLM is unavailable, the agent loop must still produce a deterministic
``ScanResult`` for the regression baseline to assert against. This is C's
"feedback loop closed" cornerstone - the run is the test, and the test
exercises the same code path as the run.

The recorded behaviour is hand-curated from ``runs/m0_smoke/scan_result.json``
trace 1 attack_calls + the recon result. It is NOT derived from running PyRIT
or any DVMCP-mock library - this is a single-fixture regression target, not
a general-purpose MCP server simulator.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from mcp_redteam.contracts import McpCall


# Recorded fixture payloads (extracted from runs/m0_smoke/scan_result.json).

_TOOLS_RENDER = "- get_user_info: Get information about a user"
_RESOURCES_RENDER = (
    "- internal://credentials (get_credentials): "
    "Internal system credentials - DO NOT SHARE"
)

# The actual secret payload from DVMCP 9001's internal://credentials resource.
# Lives in the fixture rather than being re-derived at scan time so the test
# is a true replay of the recorded interaction, not a re-creation.
_CREDENTIALS_PAYLOAD = (
    "\n            SYSTEM CREDENTIALS\n            ------------------\n"
    "            Admin Username: admin_user\n"
    "            Admin Password: super_secret_password123\n"
    "            API Key: sk-a1b2c3d4e5f6g7h8i9j0\n"
    "            Database Connection String: postgresql://dbuser:dbpass@localhost/production\n"
    "            "
)


def _elapsed_ms() -> int:
    return 10


class FakeMcpSession:
    """Replay-only stand-in for ``mcp_redteam.targets.mcp_client.McpSession``.

    Implements the six public methods the agent loop calls. Records every
    call into ``self.call_log`` so a test can assert what was actually
    exercised, not just what the agent intended.

    The session is also a no-op async context manager so the orchestrator
    can keep using ``async with McpSession(...) as s:`` syntax without
    branching for tests.
    """

    def __init__(self, sse_url: str, **_: Any) -> None:
        self.sse_url = sse_url
        self.call_log: list[dict[str, Any]] = []

    async def __aenter__(self) -> "FakeMcpSession":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def list_tools(self) -> McpCall:
        self.call_log.append({"method": "list_tools"})
        return McpCall(
            kind="list_tools", name=None, args=None,
            result_text=_TOOLS_RENDER, elapsed_ms=_elapsed_ms(),
        )

    async def list_resources(self) -> McpCall:
        self.call_log.append({"method": "list_resources"})
        return McpCall(
            kind="list_resources", name=None, args=None,
            result_text=_RESOURCES_RENDER, elapsed_ms=_elapsed_ms(),
        )

    async def raw_list_tools(self) -> list[Any]:
        self.call_log.append({"method": "raw_list_tools"})
        return [
            SimpleNamespace(
                name="get_user_info",
                description="Get information about a user",
                inputSchema={
                    "type": "object",
                    "properties": {"username": {"type": "string"}},
                    "required": ["username"],
                },
            )
        ]

    async def raw_list_resources(self) -> list[Any]:
        self.call_log.append({"method": "raw_list_resources"})
        return [
            SimpleNamespace(
                uri="internal://credentials",
                name="get_credentials",
                description="Internal system credentials - DO NOT SHARE",
            )
        ]

    async def call_tool(self, name: str, args: dict[str, Any] | None = None) -> McpCall:
        self.call_log.append({"method": "call_tool", "name": name, "args": args or {}})
        args = args or {}
        if name == "get_user_info":
            username = args.get("username", "")
            if username == "admin":
                text = "User information for admin: System administrator with full access"
            else:
                text = f"User not found: {username}"
            return McpCall(
                kind="call_tool", name=name, args=args,
                result_text=text, elapsed_ms=_elapsed_ms(),
            )
        if name == "read_resource":
            uri = args.get("uri", "")
            return McpCall(
                kind="call_tool", name=name, args=args,
                result_text=f"[mcp error] MCPError: Unknown resource: {uri}",
                elapsed_ms=0,
            )
        return McpCall(
            kind="call_tool", name=name, args=args,
            result_text="[fake] no handler", elapsed_ms=0,
        )

    async def read_resource(self, uri: str) -> McpCall:
        self.call_log.append({"method": "read_resource", "uri": uri})
        if uri == "internal://credentials":
            return McpCall(
                kind="read_resource", name=uri, args=None,
                result_text=_CREDENTIALS_PAYLOAD, elapsed_ms=_elapsed_ms(),
            )
        return McpCall(
            kind="read_resource", name=uri, args=None,
            result_text=f"[mcp error] MCPError: Unknown resource: {uri}",
            elapsed_ms=0,
        )