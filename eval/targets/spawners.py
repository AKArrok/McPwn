"""Spawner registry for the eval target manifest.

Every spawner is an async context manager yielding an SSE url (same contract
as the per-target `_fresh.py` modules). New targets: import/adapt an existing
fresh function here (or write one) and reference its name in manifest.yaml.
"""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from eval.fetch_ssrf._fresh import fresh_fetch_target
from eval.generalize._fresh_server import fresh_delegate_server
from eval.real_negative._fresh import fresh_fs_target, fresh_git_target
from eval.real_vuln._fresh import fresh_fs_vuln_target
from eval.unknown_shape._fresh_server import fresh_vault_server


def _free_port(preferred: int) -> int:
    """Use ``preferred`` when free, else grab an ephemeral free port.

    Concurrent spawner runs (benchmark + e2e) or leftovers from a crashed
    run no longer collide on the historical fixed ports.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
        except OSError:
            s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@asynccontextmanager
async def sse(url: str) -> AsyncIterator[str]:
    """Static SSE endpoint (server expected to already be running)."""
    yield url


def _port_aware(fresh, base: int):
    """Wrap a port-parameterised fresh spawner with a free port.

    Tries the historical fixed base first (compat with docs/scripts that
    reference it), falling back to an ephemeral port when occupied.
    """

    @asynccontextmanager
    async def wrapped() -> AsyncIterator[str]:
        async with fresh(_free_port(base)) as url:
            yield url

    return wrapped


# name -> spawner (async context manager yielding SSE url)
# NOTE: port numbers kept in the same ranges as the original per-target
# scripts so nothing conflicts when several targets run in one session.
SPAWNERS: dict[str, object] = {
    "vault": _port_aware(fresh_vault_server, 19205),
    "delegate": _port_aware(fresh_delegate_server, 20105),
    "fetch": fresh_fetch_target,  # dynamic bridge port handled in _fresh.py
    "git": _port_aware(fresh_git_target, 9330),
    "filesystem": _port_aware(fresh_fs_target, 9340),
    "filesystem_vuln": _port_aware(fresh_fs_vuln_target, 9350),
}


def get_spawner(name: str, sse_url: str | None = None):
    if name == "sse":
        if not sse_url:
            raise ValueError("spawn=sse requires sse_url in the manifest entry")
        return sse(sse_url)
    if name not in SPAWNERS:
        raise KeyError(f"unknown spawner {name!r}; add it to SPAWNERS or use spawn=sse")
    # Registry stores @asynccontextmanager FACTORY functions; call to get the CM.
    return SPAWNERS[name]()


__all__ = ["get_spawner"]
