"""Minimal echo server for transport integration tests.

Usage:
    python echo_server.py <port> <stdio|streamable-http>

Exposes one tool ``echo(text) -> "echo:<text>"`` over the requested
transport. stdio ignores the port argument (kept positional for a uniform
spawn command). Works on both mcp SDK generations (1.x FastMCP and
2.0 MCPServer share the decorator + run() surface used here).
"""

from __future__ import annotations

import sys

try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer


def main() -> None:
    port = int(sys.argv[1])
    transport = sys.argv[2]
    server = MCPServer("echo-server")

    @server.tool(description="Echo back the text.")
    def echo(text: str) -> str:
        return f"echo:{text}"

    settings_fields = getattr(type(getattr(server, "settings", None)), "model_fields", {})
    if {"host", "port"}.issubset(settings_fields):
        server.settings.host = "127.0.0.1"
        server.settings.port = port
        server.run(transport=transport)
    else:
        server.run(transport=transport, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
