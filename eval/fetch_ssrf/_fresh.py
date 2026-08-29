"""Spawn the real fetch target (intranet victim + stdio→SSE bridge) per run.

Composition per run (all local, all 127.0.0.1):
  - intranet_server.py  (victim HTTP service that answers the SSRF, port 9211)
  - bridge.py           (stdio→SSE bridge around the OFFICIAL mcp-server-fetch,
                         venv python at eval/fetch_ssrf/.venv, port 9210)

The bridge child is spawned with the project-local venv python so the official
fetch server is always the same pinned version.

Usage (async context manager):

    async with fresh_fetch_target() as sse_url:
        result = await scan(sse_url, ...)
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

HERE = Path(__file__).resolve().parent
_BASE_PY = Path(sys.executable)
_VENV_PY = HERE / ".venv" / "Scripts" / "python.exe"
_INTRA_NET = HERE / "intranet_server.py"
_BRIDGE = HERE / "bridge.py"
_HOST = "127.0.0.1"
_BRIDGE_PORT = 9210
_INTRANET_PORT = 9211
_READY_ATTEMPTS = 15
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 8.0
_KILL_TIMEOUT = 5.0


def _check_venv() -> None:
    if not _VENV_PY.exists():
        raise RuntimeError(
            f"fetch venv missing at {_VENV_PY}; run: "
            f"`python -m venv eval/fetch_ssrf/.venv` then "
            f"`.venv/Scripts/pip install mcp-server-fetch \"mcp<2\"`"
        )


def _port_busy(port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((_HOST, port)) == 0


def _free_port(preferred: int) -> int:
    """Use ``preferred`` when free, else grab an ephemeral free port.

    Keeps the historical default (9210, what standalone prove.py expects)
    while a leftover process from a crashed run can no longer silently
    hang the next one.
    """
    import socket

    if not _port_busy(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((_HOST, 0))
        return s.getsockname()[1]


@asynccontextmanager
async def fresh_fetch_target(bridge_port: int | None = None) -> AsyncIterator[str]:
    """Spawn intranet victim + bridge; yield the bridge SSE URL.

    ``bridge_port`` defaults to the historical 9210 unless occupied (leftover
    process from a crashed run) in which case an ephemeral port is used.
    The intranet port (9211) is part of the SSRF signal contract and stays
    fixed: if it is busy we fail FAST instead of hanging on readiness.
    """
    _check_venv()
    if _port_busy(_INTRANET_PORT):
        raise RuntimeError(
            f"intranet port {_INTRANET_PORT} already in use - a previous "
            f"fetch target run probably leaked processes; kill them first "
            f"(Windows: `netstat -ano | findstr {_INTRANET_PORT}`)"
        )
    port = bridge_port or _free_port(_BRIDGE_PORT)
    intranet = await asyncio.create_subprocess_exec(
        str(_BASE_PY), str(_INTRA_NET), "--host", _HOST, "--port", str(_INTRANET_PORT),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    bridge = await asyncio.create_subprocess_exec(
        str(_VENV_PY), str(_BRIDGE), "--host", _HOST, "--port", str(port),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    sse_url = f"http://{_HOST}:{port}/sse"
    procs = (intranet, bridge)
    try:
        ready = False
        for _ in range(_READY_ATTEMPTS):
            if bridge.returncode is not None:
                raise RuntimeError(
                    f"fetch bridge exited early with rc={bridge.returncode}; "
                    f"run `{_VENV_PY} {_BRIDGE}` manually for stderr"
                )
            try:
                async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                    await s.list_tools()
                ready = True
                break
            except Exception:  # noqa: BLE001 - readiness probe retries
                await asyncio.sleep(_READY_DELAY)
        if not ready:
            raise TimeoutError(f"fetch target not ready at {sse_url}")
        yield sse_url
    finally:
        for p in procs:
            if p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), timeout=_STOP_TIMEOUT)
                except TimeoutError:
                    p.kill()
                    await asyncio.wait_for(p.wait(), timeout=_KILL_TIMEOUT)
