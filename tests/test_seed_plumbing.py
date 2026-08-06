"""Seed plumbing: scan(seed) -> ModelSpec -> OpenAI-compatible `seed` param.

Rigor fix for the Stage-3 "same seed" claim: the seed must be a real,
recorded parameter, not a no-op script arg. These tests lock the plumbing
without touching the network (fake completions client).
"""

from __future__ import annotations

from types import SimpleNamespace

import mcp_redteam.models.chat as chat_mod
from mcp_redteam.models.chat import chat_create_with_retry, make_client


def _fake_completions(calls: list[dict]) -> SimpleNamespace:
    class _C:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(choices=[], usage=None)

    return SimpleNamespace(chat=SimpleNamespace(completions=_C()))


def test_chat_create_with_retry_forwards_seed_when_set(monkeypatch):
    """seed=42 must reach client.chat.completions.create as kwargs["seed"]."""
    monkeypatch.setattr(chat_mod, "_rate_limit_wait", lambda: None)
    calls: list[dict] = []
    client = _fake_completions(calls)
    chat_create_with_retry(
        client, model="m", temperature=0.7, messages=[], seed=42
    )
    assert calls[0]["seed"] == 42


def test_chat_create_with_retry_omits_seed_when_none(monkeypatch):
    """seed=None must NOT add a seed key - providers that reject unknown
    params (e.g. DeepSeek 400) stay untouched by default."""
    monkeypatch.setattr(chat_mod, "_rate_limit_wait", lambda: None)
    calls: list[dict] = []
    client = _fake_completions(calls)
    chat_create_with_retry(client, model="m", temperature=0.7, messages=[])
    assert "seed" not in calls[0]


def test_make_client_seed_override(monkeypatch):
    """make_client(seed=N) replaces spec.seed; default spec.seed is None."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    _, spec = make_client("attacker", seed=7)
    assert spec.seed == 7
    _, spec_default = make_client("attacker")
    assert spec_default.seed is None


def test_model_spec_seed_round_trip_in_scan_result(monkeypatch):
    """ModelSpec carries seed into a ScanResult-style record (contract glue)."""
    from mcp_redteam.contracts import ScanResult

    r = ScanResult(
        run_id="r", sse_url="x", started_at="t", wall_seconds=1.0,
        stop_reason="completed", seed=42,
    )
    assert r.seed == 42
