"""stdio→SSE bridge for the official mcp-server-fetch (real-world target).

The official fetch server only speaks stdio; McPwn's harness connects over SSE.
This bridge uses only the official mcp SDK pieces (stdio_client upstream +
low-level Server + SseServerTransport downstream) and forwards tools and calls
verbatim, so tool schemas stay byte-identical to the real server. The upstream
fetch child is spawned with the SAME venv python that runs this file.

Usage:
    <fetch-venv>/Scripts/python.exe eval/fetch_ssrf/bridge.py [--port 9210]

McPwn then connects to http://127.0.0.1:9210/sse like any SSE target.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import uvicorn
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from pydantic import RootModel
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Mount, Route

HERE = Path(__file__).resolve().parent
VENV_BIN = Path(sys.executable).resolve().parent


class _RawDict(RootModel[dict]):
    """Pass-through JSON-RPC result container (avoids SDK 1.29's strict Tool
    validation on old servers that omit inputSchema's top-level ``type``)."""

server = Server("fetch-bridge")
_tools: list[types.Tool] = []
_session: ClientSession | None = None


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return _tools


@server.call_tool()
async def call_tool(name: str, args: dict):
    if _session is None:  # pragma: no cover - upstream not up yet
        raise RuntimeError("upstream fetch session not initialized")
    # Verbatim passthrough: same CallToolResult the real server produced.
    return await _session.call_tool(name, args)


def _fetch_command() -> list[str]:
    exe = VENV_BIN / "mcp-server-fetch.exe"
    if not exe.exists():
        raise RuntimeError(
            f"mcp-server-fetch console script not found next to {sys.executable}: {exe}"
        )
    return [str(exe), "--ignore-robots-txt"]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9210)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--stdio", default=None,
        help="stdio command + args to bridge (single string, shlex-split). "
             "Default: the mcp-server-fetch console script next to this venv.",
    )
    args = parser.parse_args()

    global _tools, _session
    if args.stdio:
        import shlex

        # posix=False: keep backslashes in Windows paths intact
        parts = shlex.split(args.stdio, posix=False)
        params = StdioServerParameters(command=parts[0], args=parts[1:])
    else:
        cmd = _fetch_command()
        params = StdioServerParameters(command=cmd[0], args=cmd[1:])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        _session = session
        # Tolerant list_tools: fetch the raw JSON-RPC result and patch missing
        # top-level inputSchema "type" (old server-filesystem versions omit it,
        # which SDK 1.29's strict Tool model rejects). Patch is adapter-only -
        # the upstream server's behaviour is untouched.
        raw = await session.send_request(types.ListToolsRequest(), _RawDict)
        raw_tools = raw.root.get("tools", [])
        for t in raw_tools:
            schema = t.get("inputSchema") or {}
            schema.setdefault("type", "object")
            t["inputSchema"] = schema
        _tools = [types.Tool.model_validate(t) for t in raw_tools]

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await server.run(
                    streams[0],
                    streams[1],
                    server.create_initialization_options(),
                )
            return Response()

        app = Starlette(
            routes=[
                Route("/sse", endpoint=handle_sse, methods=["GET"]),
                Mount("/messages/", app=sse.handle_post_message),
            ]
        )
        print(
            f"[bridge] exposing {len(_tools)} tool(s) over SSE "
            f"http://{args.host}:{args.port}/sse",
            flush=True,
        )
        cfg = uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")
        await uvicorn.Server(cfg).serve()


if __name__ == "__main__":
    asyncio.run(main())
