"""Connection-layer edge-case regression tests.

Each case here comes from an adversarial probe of the CLI/contract surface
(sept 2026 review). They lock in *rejection with a clear message* for bad
input and *target-identifying errors* for failed connects.
"""

from __future__ import annotations

import pytest

from mcp_redteam.contracts import TargetSpec, Transport
from mcp_redteam.orchestrator.runner import _port_from_spec
from mcp_redteam.targets.mcp_client import McpSession


def test_parse_rejects_url_and_command_together():
    with pytest.raises(ValueError, match="pick one"):
        TargetSpec.parse("http://h:9001/sse", command="uvx x")


def test_parse_rejects_non_http_scheme():
    for bad in ("127.0.0.1:9001/sse", "file:///tmp/x/sse", "ftp://h/sse"):
        with pytest.raises(ValueError, match="http://"):
            TargetSpec.parse(bad)


def test_parse_strips_whitespace():
    spec = TargetSpec.parse("  http://h:9001/sse  ")
    assert spec.url == "http://h:9001/sse"
    assert spec.transport is Transport.SSE


def test_parse_trailing_slash_sse_still_legacy():
    spec = TargetSpec.parse("http://h:9001/sse/")
    assert spec.transport is Transport.SSE


async def test_failed_connect_error_names_the_target():
    # Closed port: error must identify the endpoint, not a bare httpx
    # "ConnectError: All connection attempts failed".
    s = McpSession("http://127.0.0.1:59999/sse")
    with pytest.raises(RuntimeError, match="无法连接 MCP 目标 http://127.0.0.1:59999/sse"):
        await s.__aenter__()


async def test_failed_connect_rolls_back_partial_enter():
    # A port that ACCEPTS TCP but never speaks MCP: ClientSession.initialize
    # must time out (read_timeout), and the partially entered transport ctx
    # must be rolled back - a second full connect attempt then succeeds.
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        s = McpSession(
            f"http://127.0.0.1:{port}/sse", read_timeout=1.0, connect_timeout=2.0
        )
        with pytest.raises(RuntimeError, match="无法连接"):
            await s.__aenter__()
        # nothing leaked: session handle cleared
        assert s._session is None
    finally:
        server.close()


async def test_aexit_without_enter_is_safe():
    s = McpSession("http://127.0.0.1:59999/sse")
    await s.__aexit__(None, None, None)  # must not raise


def test_stdio_pseudo_ports_stable_and_distinct():
    p1 = _port_from_spec(TargetSpec.parse(command="uvx mcp-server-fetch"))
    p2 = _port_from_spec(TargetSpec.parse(command="python other.py"))
    assert p1 != p2
    assert 50000 <= p1 < 90000
    # stability: same command -> same pseudo-port (decisions file identity)
    assert _port_from_spec(TargetSpec.parse(command="uvx mcp-server-fetch")) == p1


def test_http_real_port_preserved():
    spec = TargetSpec.parse("http://127.0.0.1:9010/sse")
    assert _port_from_spec(spec) == 9010
