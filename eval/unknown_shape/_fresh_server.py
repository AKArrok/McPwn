"""Spawn a fresh vault-mcp SSE server per run (isolates repeated experiments).

Stage-3 protocol fix: ``vault_server.py`` keeps its store in memory, so N
repeated scans against the same process share state (run 0's created vaults
make run 1/2 easier - a confound for the "same conditions" claim).
``fresh_vault_server`` spawns a new subprocess per context, waits until it
accepts a real MCP session, and tears it down on exit: every run starts from
the same empty store.

Usage (async context manager):

    async with fresh_vault_server(19205) as sse_url:
        result = await scan(sse_url, ...)
"""

from __future__ import annotations

import asyncio
import socket
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

_VAULT_SERVER = Path(__file__).with_name("vault_server.py")
_HOST = "127.0.0.1"
_READY_ATTEMPTS = 15
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 10.0
_KILL_TIMEOUT = 5.0
_PORT_CLOSE_ATTEMPTS = 20
_PORT_CLOSE_DELAY = 0.25


def _port_accepts(port: int) -> bool:
    try:
        with socket.create_connection((_HOST, port), timeout=1.0):
            return True
    except OSError:
        return False


@asynccontextmanager
async def fresh_vault_server(port: int) -> AsyncIterator[str]:
    """Spawn ``vault_server.py --host 127.0.0.1 --port <port>``; yield its SSE URL.

    Raises RuntimeError if the child exits before becoming ready, or
    TimeoutError if it never accepts an MCP session. Always terminates the
    child on exit (including KeyboardInterrupt / scan failure).
    """
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(_VAULT_SERVER),
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
                    f"vault server exited early with rc={proc.returncode}; "
                    f"run `python {_VAULT_SERVER.name} --port {port}` manually for stderr"
                )
            try:
                async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                    await s.list_tools()
                ready = True
                break
            except Exception:  # noqa: BLE001 - readiness probe: any connect error retries
                await asyncio.sleep(_READY_DELAY)
        if not ready:
            raise TimeoutError(f"vault server not ready at {sse_url}")
        yield sse_url
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=_KILL_TIMEOUT)
        for _ in range(_PORT_CLOSE_ATTEMPTS):
            if not await asyncio.to_thread(_port_accepts, port):
                break
            await asyncio.sleep(_PORT_CLOSE_DELAY)
