"""Spawn a fresh delegate-mcp SSE server per run (isolates repeated experiments).

Same protocol as eval/unknown_shape/_fresh_server.py: every run starts from
the same empty-ish state (the server file re-seeds its built-in admin_vault on
each fresh process, so N runs never share mutated delegate grants).

Usage (async context manager):

    async with fresh_delegate_server(20205) as sse_url:
        result = await scan(sse_url, ...)
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

_SERVER = Path(__file__).with_name("delegate_server.py")
_HOST = "127.0.0.1"
_READY_ATTEMPTS = 15
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 10.0
_KILL_TIMEOUT = 5.0


@asynccontextmanager
async def fresh_delegate_server(port: int) -> AsyncIterator[str]:
    """Spawn ``delegate_server.py --host 127.0.0.1 --port <port>``; yield SSE URL.

    Raises RuntimeError if the child exits before becoming ready, or
    TimeoutError if it never accepts an MCP session. Always terminates the
    child on exit (including KeyboardInterrupt / scan failure).
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(_SERVER),
        "--host",
        _HOST,
        "--port",
        str(port),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    sse_url = f"http://{_HOST}:{port}/sse"
    try:
        ready = False
        for _ in range(_READY_ATTEMPTS):
            if proc.returncode is not None:
                raise RuntimeError(
                    f"delegate server exited early with rc={proc.returncode}; "
                    f"run `python {_SERVER.name} --port {port}` manually for stderr"
                )
            try:
                async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                    await s.list_tools()
                ready = True
                break
            except Exception:  # noqa: BLE001 - readiness probe: any connect error retries
                await asyncio.sleep(_READY_DELAY)
        if not ready:
            raise TimeoutError(f"delegate server not ready at {sse_url}")
        yield sse_url
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=_KILL_TIMEOUT)
