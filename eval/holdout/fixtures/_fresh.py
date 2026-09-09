"""Fresh spawner for the cache-mcp holdout pair (vuln + fixed).

Same pattern as ``eval/unknown_shape/_fresh_server.py``: spawn a fresh
subprocess per context (each run starts from the same empty store - required
for N>=5 repeats), wait until it accepts a real MCP session, tear down on exit.

Usage:

    async with fresh_cache_target(19215) as sse_url:      # vulnerable version
        ...
    async with fresh_cache_target(19215, fixed=True) as sse_url:  # fixed version
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

_CACHE_SERVER = Path(__file__).with_name("cache_server.py")
_HOST = "127.0.0.1"
_READY_ATTEMPTS = 15
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 10.0
_KILL_TIMEOUT = 5.0


@asynccontextmanager
async def fresh_cache_target(port: int, *, fixed: bool = False) -> AsyncIterator[str]:
    """Spawn ``cache_server.py [--fixed] --host 127.0.0.1 --port <port>``."""
    args = [sys.executable, str(_CACHE_SERVER), "--host", _HOST, "--port", str(port)]
    if fixed:
        args.append("--fixed")
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    sse_url = f"http://{_HOST}:{port}/sse"
    try:
        ready = False
        for _ in range(_READY_ATTEMPTS):
            if proc.returncode is not None:
                raise RuntimeError(
                    f"cache server exited early with rc={proc.returncode}; "
                    f"run `python {_CACHE_SERVER.name} --port {port}` manually for stderr"
                )
            try:
                async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                    await s.list_tools()
                ready = True
                break
            except Exception:  # noqa: BLE001 - readiness probe: any connect error retries
                await asyncio.sleep(_READY_DELAY)
        if not ready:
            raise TimeoutError(f"cache server not ready at {sse_url}")
        yield sse_url
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                proc.kill()
                await asyncio.wait_for(proc.wait(), timeout=_KILL_TIMEOUT)


__all__ = ["fresh_cache_target"]
