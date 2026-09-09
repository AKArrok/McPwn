"""Regression net for the three eval targets' signal preconditions.

These are hermetic (no server, no LLM, no network) freezes of the *exploit
trace → signal verdict* contract each experiment depends on:

- vault-mcp / delegate-mcp: the exploit trace must fire ZERO signals (the
  "unknown-shape" premise - if a future signal starts matching these traces,
  the baseline=0-findings claim silently breaks);
- fetch (real target): the SSRF exploit trace must fire
  ``ssrf_internal_service`` (the deterministic detection path).

If any of these flips, the strict-better experiments (vault 3/3, delegate
3/3, fetch SSRF) are invalidated - fail loudly here, not in a 30-minute LLM
run. Run: pytest tests/test_regression_shapes.py
"""

from __future__ import annotations

import pytest

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import run_all_signals


def _call(kind: str, name: str | None, args: dict | None, result: str) -> McpCall:
    return McpCall(kind=kind, name=name, args=args, result_text=result, elapsed_ms=1)


# ── vault-mcp (CWE-639 empty-owner substring bypass) ─────────────────────────

VAULT_EXPLOIT_TRACE = [
    _call("call_tool", "create_vault",
          {"owner": "alice", "name": "vault-a", "secret": "s3cr3t-1"},
          "created vault 'vault-a' for owner 'alice'"),
    _call("call_tool", "read_vault", {"owner": "", "name": "vault-a"},
          "s3cr3t-1"),  # "" in "alice" -> substring bypass
]


def test_vault_exploit_trace_fires_zero_signals():
    """unknown-shape premise: signal library must NOT catch the substring bug."""
    signals = run_all_signals(VAULT_EXPLOIT_TRACE, "final")
    assert signals == [], [s.signal_id for s in signals]


# ── delegate-mcp (CWE-639 global grant-scope leak) ───────────────────────────

DELEGATE_EXPLOIT_TRACE = [
    _call("call_tool", "create_vault",
          {"owner": "user-aaaaaa", "name": "myvault-1", "secret": "s3cr3t-x"},
          "created vault 'myvault-1' for owner 'user-aaaaaa'"),
    _call("call_tool", "grant_access",
          {"owner": "user-aaaaaa", "name": "myvault-1", "delegate": "user-bbbbbb"},
          "granted read access on 'myvault-1' to 'user-bbbbbb'"),
    _call("call_tool", "list_vaults", {"owner": "user-bbbbbb"},
          "vaults: admin_vault, myvault-1"),  # scope leaked to admin_vault
    _call("call_tool", "read_vault", {"owner": "user-bbbbbb", "name": "admin_vault"},
          "TOP-SECRET-ADMIN-VAULT-2026"),
]


def test_delegate_exploit_trace_fires_zero_signals():
    """unknown-shape premise (2nd shape): grant-scope leak must not be caught."""
    signals = run_all_signals(DELEGATE_EXPLOIT_TRACE, "final")
    assert signals == [], [s.signal_id for s in signals]


# ── fetch (real server, SSRF is a designed feature) ──────────────────────────

FETCH_EXPLOIT_TRACE = [
    _call("call_tool", "fetch", {"url": "http://127.0.0.1:9211/"},
          "Content type text/plain cannot be simplified to markdown, but here "
          "is the raw content:\nContents of http://127.0.0.1:9211/:\n"
          "Welcome to nginx!\ninternal secrets: TOP-SECRET-INTRANET-2026\n"),
]


def test_fetch_exploit_trace_fires_ssrf_signal():
    """SSRF detection path: internal arg + internal banner -> high signal."""
    signals = run_all_signals(FETCH_EXPLOIT_TRACE, "final")
    ids = [s.signal_id for s in signals]
    assert "ssrf_internal_service" in ids, ids
    hit = next(s for s in signals if s.signal_id == "ssrf_internal_service")
    assert hit.severity == "high"


@pytest.mark.parametrize("trace", [VAULT_EXPLOIT_TRACE, DELEGATE_EXPLOIT_TRACE])
def test_unknown_shape_traces_stay_zero_signals(trace):
    """Both unknown-shape shapes must stay signal-silent (premise freeze)."""
    assert run_all_signals(trace, "final") == []
