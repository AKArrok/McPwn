"""Transport integration + TargetSpec parsing tests.

Covers the three MCP transports ``McpSession`` now speaks:

- stdio: spawns a real ``echo_server.py`` child via ``TargetSpec`` command.
- streamable HTTP: FastMCP server, auto-detected from a non-/sse URL.
- auto dispatch: ``/sse`` URLs stay on legacy SSE without a live server.

Hermetic: no LLM, no external API.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from mcp_redteam.contracts import TargetSpec, Transport
from mcp_redteam.targets.mcp_client import McpSession

HERE = Path(__file__).resolve().parent
ECHO_SERVER = HERE / "fixtures" / "echo_server.py"


# ─── TargetSpec.parse (pure, no I/O) ────────────────────────────────────────


def test_parse_sse_url_by_path():
    spec = TargetSpec.parse("http://127.0.0.1:9001/sse")
    assert spec.transport is Transport.SSE
    assert spec.url == "http://127.0.0.1:9001/sse"
    assert spec.display == "http://127.0.0.1:9001/sse"


def test_parse_other_url_prefers_streamable_http():
    spec = TargetSpec.parse("http://127.0.0.1:9000/mcp")
    assert spec.transport is Transport.STREAMABLE_HTTP


def test_parse_explicit_transport_wins():
    spec = TargetSpec.parse("http://127.0.0.1:9001/sse", transport="streamable_http")
    assert spec.transport is Transport.STREAMABLE_HTTP


def test_parse_command_implies_stdio():
    spec = TargetSpec.parse(command="uvx mcp-server-fetch --port 1")
    assert spec.transport is Transport.STDIO
    assert spec.command == ["uvx", "mcp-server-fetch", "--port", "1"]
    assert spec.display == "stdio: uvx mcp-server-fetch --port 1"


def test_parse_stdio_transport_without_command_rejected():
    with pytest.raises(ValueError, match="requires"):
        TargetSpec.parse("http://127.0.0.1:9001/sse", transport="stdio")


def test_parse_http_transport_without_url_rejected():
    with pytest.raises(ValueError, match="requires"):
        TargetSpec.parse(command=None, transport="sse")


def test_parse_conflicting_transport_and_command_rejected():
    with pytest.raises(ValueError):
        TargetSpec.parse("http://127.0.0.1:9001/sse", transport="sse", command="uvx x")


def test_mcp_session_accepts_spec_or_string():
    assert (
        McpSession(TargetSpec.parse("http://127.0.0.1:9001/sse")).spec.transport
        is Transport.SSE
    )
    assert McpSession("http://127.0.0.1:9001/sse").spec.transport is Transport.SSE


def test_mcp_session_auto_sets_sse_fallback_flag():
    # auto + non-/sse URL: streamable first, legacy SSE fallback allowed.
    s = McpSession("http://127.0.0.1:9000/mcp")
    assert s._allow_sse_fallback is True
    # explicit transport: no fallback.
    s2 = McpSession("http://127.0.0.1:9000/mcp", transport="sse")
    assert s2._allow_sse_fallback is False


# ─── Live stdio transport ───────────────────────────────────────────────────


async def test_stdio_session_lists_and_calls_tools():
    spec = TargetSpec.parse(command=[sys.executable, str(ECHO_SERVER), "0", "stdio"])
    async with McpSession(spec) as s:
        tools = await s.raw_list_tools()
        assert {t.name for t in tools} >= {"echo"}
        call = await s.call_tool("echo", {"text": "hello"})
    assert "echo:hello" in call.result_text


# ─── Live streamable HTTP transport ─────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _spawn_http_server(transport: str) -> AsyncIterator[tuple[int, asyncio.subprocess.Process]]:
    port = _free_port()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(ECHO_SERVER), str(port), transport,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        for _ in range(100):  # up to ~10s for the server to accept TCP
            if proc.returncode is not None:
                raise RuntimeError(f"echo server exited early: {proc.returncode}")
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            raise RuntimeError("echo server never became reachable")
        yield port, proc
    finally:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
        except TimeoutError:
            proc.kill()


@pytest.fixture()
async def streamable_http_server():
    async for item in _spawn_http_server("streamable-http"):
        yield item


async def test_streamable_http_session_auto_detected(streamable_http_server):
    port, _proc = streamable_http_server
    # Non-/sse path -> auto picks streamable HTTP, no fallback to SSE needed.
    async with McpSession(f"http://127.0.0.1:{port}/mcp") as s:
        assert s.spec.transport is Transport.STREAMABLE_HTTP
        tools = await s.raw_list_tools()
        assert {t.name for t in tools} >= {"echo"}
        call = await s.call_tool("echo", {"text": "hi"})
    assert "echo:hi" in call.result_text
