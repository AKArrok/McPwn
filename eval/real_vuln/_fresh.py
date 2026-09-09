"""Fresh spawner for the VULNERABLE filesystem server (positive target).

Official @modelcontextprotocol/server-filesystem **0.6.2** (pre-fix): the
allowlist can be escaped by (a) colliding path prefix - a sibling dir like
``<allowed>2`` or ``<allowed>-x`` passes the prefix check - and (b) ``..``
traversal. Both are fixed in 2026.7.10 (see eval/real_negative). Vulnerabilities
CVE-2025-53109 / CVE-2025-53110. The old version's inputSchemas lack the
top-level ``type`` field, so the shared bridge uses its tolerant list_tools
patch (adapter-only; upstream behaviour untouched).

Requires ``MCPWN_FS_INDEX_OLD`` = path to server-filesystem 0.6.2
dist/index.js (npm install @modelcontextprotocol/server-filesystem@0.6.2).
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_BRIDGE = ROOT / "eval" / "fetch_ssrf" / "bridge.py"
_VENV_PY = ROOT / "eval" / "fetch_ssrf" / ".venv" / "Scripts" / "python.exe"
_HOST = "127.0.0.1"
_READY_ATTEMPTS = 20
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 8.0
_KILL_TIMEOUT = 5.0


def _prepare_dirs() -> tuple[Path, Path]:
    """Allowed dir + sibling dir with an out-of-sandbox secret + an in-sandbox
    junction that points at the sibling (the allowlist escape primitive; real
    shared-dir scenario). Junction via mklink /J (no admin rights needed)."""
    base = Path(tempfile.gettempdir())
    allowed = base / "mcpwn-fs"
    outside = base / "mcpwn-fs2"
    allowed.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    (allowed / "readme.txt").write_text("in-sandbox\n", encoding="utf-8")
    (outside / "secret.txt").write_text("FS-SECRET-OUTSIDE-2026\n", encoding="utf-8")
    junction = allowed / "evil-junction"
    if not junction.exists():
        import subprocess

        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            check=False, capture_output=True,
        )
    return allowed, outside


@asynccontextmanager
async def fresh_fs_vuln_target(port: int = 9350) -> AsyncIterator[str]:
    fs_index = os.environ.get("MCPWN_FS_INDEX_OLD")
    if not fs_index or not Path(fs_index).exists():
        raise RuntimeError(
            "MCPWN_FS_INDEX_OLD must point at server-filesystem 0.6.2 dist/index.js"
        )
    allowed, _outside = _prepare_dirs()
    node = shutil.which("node") or str(
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "nodejs" / "node.exe"
    )
    stdio = f"{node} {fs_index} {allowed}"
    bridge = await asyncio.create_subprocess_exec(
        str(_VENV_PY), str(_BRIDGE), "--host", _HOST, "--port", str(port),
        "--stdio", stdio,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    sse_url = f"http://{_HOST}:{port}/sse"
    try:
        for _ in range(_READY_ATTEMPTS):
            if bridge.returncode is not None:
                raise RuntimeError(f"bridge exited early rc={bridge.returncode}")
            try:
                async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                    await s.list_tools()
                break
            except Exception:  # noqa: BLE001 - readiness probe
                await asyncio.sleep(_READY_DELAY)
        else:
            raise TimeoutError(f"filesystem 0.6.2 target not ready at {sse_url}")
        yield sse_url
    finally:
        if bridge.returncode is None:
            bridge.terminate()
            try:
                await asyncio.wait_for(bridge.wait(), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                bridge.kill()
                await asyncio.wait_for(bridge.wait(), timeout=_KILL_TIMEOUT)


__all__ = ["fresh_fs_vuln_target"]
