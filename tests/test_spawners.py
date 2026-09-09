"""Spawner port-hygiene tests (no servers spawned).

Regression: fixed spawner ports collided across concurrent runs and leaked
processes from crashed runs silently hung the next one. Bridge ports now
prefer the historical default but fall back to ephemeral; semantic ports
(intranet 9211) fail fast with a remediation hint instead.
"""

from __future__ import annotations

import socket

import pytest

from eval.targets.spawners import _free_port, get_spawner


def _busy_socket(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    return s


def test_free_port_prefers_default_when_free():
    # pick a port we KNOW is free, verify it comes back unchanged
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    assert _free_port(free) == free


def test_free_port_falls_back_when_busy():
    with _busy_socket(0) as s:
        busy = s.getsockname()[1]
        taken = _free_port(busy)
    assert taken != busy


def test_get_spawner_returns_context_manager():
    cm = get_spawner("vault", None)
    assert hasattr(cm, "__aenter__") and hasattr(cm, "__aexit__")


def test_fetch_target_fails_fast_on_busy_intranet(monkeypatch):
    import asyncio

    from eval.fetch_ssrf import _fresh

    s = _busy_socket(0)
    busy_port = s.getsockname()[1]
    monkeypatch.setattr(_fresh, "_INTRANET_PORT", busy_port)
    monkeypatch.setattr(_fresh, "_check_venv", lambda: None)
    try:  # socket must stay OPEN while the preflight probes the port
        with pytest.raises(RuntimeError, match="kill them first"):
            asyncio.run(_fresh.fresh_fetch_target().__aenter__())
    finally:
        s.close()
