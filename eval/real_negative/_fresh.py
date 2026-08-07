"""Fresh spawners for the two real-world FIXED servers (negative targets).

- git: official ``mcp-server-git`` (pip, 2026.7.10) - repo_path is validated
  against the --repository root (CVE-2025-68143/44/45 + CVE-2026-27735 fixed).
- filesystem: official ``@modelcontextprotocol/server-filesystem`` (npm,
  2026.7.10) - allowlist enforced (CVE-2025-53109/53110 fixed).

Both only speak stdio; each is wrapped by the shared stdio->SSE bridge
(eval/fetch_ssrf/bridge.py) with the mcp<2 venv python.

The vulnerable versions were tried but not usable: filesystem 0.6.2 emits
inputSchemas without a top-level ``type`` field, which mcp SDK 1.29's strict
pydantic models reject at bridge startup (documented honest boundary).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp_redteam.targets.mcp_client import McpSession

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_BRIDGE = ROOT / "eval" / "fetch_ssrf" / "bridge.py"
# venv with mcp<2 + starlette + uvicorn (also has mcp-server-git installed)
_VENV_PY = ROOT / "eval" / "fetch_ssrf" / ".venv" / "Scripts" / "python.exe"
_GIT_VENV = Path(os.environ.get("MCPWN_GIT_VENV", "")) / "Scripts" / "python.exe"
_HOST = "127.0.0.1"
_READY_ATTEMPTS = 20
_READY_DELAY = 1.0
_READY_CONNECT_TIMEOUT = 5.0
_STOP_TIMEOUT = 8.0
_KILL_TIMEOUT = 5.0


def _check_venv(venv: Path, label: str) -> None:
    if not venv.exists():
        raise RuntimeError(
            f"{label} venv missing at {venv}; see eval/real_negative/README.md "
            f"for one-time setup"
        )


def _prepare_git_repo() -> Path:
    """Idempotently create a demo git repository used as --repository root."""
    repo = Path(tempfile.gettempdir()) / "mcpwn-git-repo"
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "README.md").write_text("# demo repo\nsecret: repo-secret-123456\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
            cwd=repo, check=True,
        )
    return repo


def _prepare_fs_dirs() -> tuple[Path, Path]:
    """Allowed dir + a sibling dir holding an out-of-sandbox secret."""
    base = Path(tempfile.gettempdir())
    allowed = base / "mcpwn-fs"
    outside = base / "mcpwn-fs2"
    allowed.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    (allowed / "readme.txt").write_text("in-sandbox\n", encoding="utf-8")
    (outside / "secret.txt").write_text("FS-SECRET-OUTSIDE-2026\n", encoding="utf-8")
    return allowed, outside


async def _spawn_bridge(venv: Path, port: int, stdio_cmd: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        str(venv), str(_BRIDGE), "--host", _HOST, "--port", str(port),
        "--stdio", stdio_cmd,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )


async def _wait_ready(sse_url: str, proc: asyncio.subprocess.Process) -> None:
    for _ in range(_READY_ATTEMPTS):
        if proc.returncode is not None:
            raise RuntimeError(f"bridge exited early rc={proc.returncode} at {sse_url}")
        try:
            async with McpSession(sse_url, connect_timeout=_READY_CONNECT_TIMEOUT) as s:
                await s.list_tools()
            return
        except Exception:  # noqa: BLE001 - readiness probe
            await asyncio.sleep(_READY_DELAY)
    raise TimeoutError(f"target not ready at {sse_url}")


async def _teardown(procs: list[asyncio.subprocess.Process]) -> None:
    for p in procs:
        if p.returncode is None:
            p.terminate()
            try:
                await asyncio.wait_for(p.wait(), timeout=_STOP_TIMEOUT)
            except TimeoutError:
                p.kill()
                await asyncio.wait_for(p.wait(), timeout=_KILL_TIMEOUT)


@asynccontextmanager
async def fresh_git_target(port: int = 9330) -> AsyncIterator[str]:
    """mcp-server-git (fixed) over SSE. ``MCPWN_GIT_VENV`` points at a venv
    with mcp-server-git + mcp<2 + starlette + uvicorn."""
    git_venv = _GIT_VENV if _GIT_VENV.exists() else _VENV_PY
    _check_venv(git_venv, "git")
    repo = _prepare_git_repo()
    stdio = (f"{git_venv} -m mcp_server_git --repository {repo}")
    bridge = await _spawn_bridge(git_venv, port, stdio)
    sse_url = f"http://{_HOST}:{port}/sse"
    try:
        await _wait_ready(sse_url, bridge)
        yield sse_url
    finally:
        await _teardown([bridge])


@asynccontextmanager
async def fresh_fs_target(port: int = 9340) -> AsyncIterator[str]:
    """server-filesystem (fixed) over SSE. Needs ``MCPWN_FS_INDEX`` = path to
    dist/index.js from a local ``npm install @modelcontextprotocol/server-filesystem``
    (npm registry unreachable from CI; node is required)."""
    allowed, _outside = _prepare_fs_dirs()
    fs_index = os.environ.get("MCPWN_FS_INDEX")
    if not fs_index or not Path(fs_index).exists():
        raise RuntimeError("MCPWN_FS_INDEX must point at server-filesystem dist/index.js")
    node = shutil_which("node") or (Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
                                    / "nodejs" / "node.exe")
    stdio = f"{node} {fs_index} {allowed}"
    bridge = await _spawn_bridge(_VENV_PY, port, stdio)
    sse_url = f"http://{_HOST}:{port}/sse"
    try:
        await _wait_ready(sse_url, bridge)
        yield sse_url
    finally:
        await _teardown([bridge])


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


# Re-export for convenience
__all__ = ["fresh_fs_target", "fresh_git_target"]
