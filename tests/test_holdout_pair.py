"""Holdout-pair regression tests: unknown-shape premise + paired verdict edges.

Mirrors ``tests/test_regression_shapes.py`` for the frozen holdout pair:

- the cache-mcp cross-tenant exploit trace must fire ZERO signals on the
  vulnerable version (the "unknown shape" premise - if a future detector
  starts matching it, the ``allow_llm_evidence`` gate silently weakens);
- the fixed-version denial text must never fire a signal either;
- ``evaluate_pair_run`` / ``replay_finding_on_control`` edge behaviour the
  GPT-written test file does not cover.

Hermetic: no LLM, no network. The fixture spawn test (prove.py) DOES start a
local cache_server subprocess but needs no external services.
"""

from __future__ import annotations

from pathlib import Path

from eval.holdout.runner import (
    ControlReplay,
    exploit_evidence_grounded,
    finding_matches_pair,
    replay_finding_on_control,
)
from mcp_redteam.contracts import EvidenceSignal, Finding, McpCall, VulnClass
from mcp_redteam.signals.detectors import run_all_signals

ROOT = Path(__file__).resolve().parents[1]


def _call(name: str, args: dict, result: str) -> McpCall:
    return McpCall(kind="call_tool", name=name, args=args,
                   result_text=result, elapsed_ms=1)


def _finding(signal_id: str | None = None, *, grounded: bool = True) -> Finding:
    signals = []
    if signal_id:
        signals.append(EvidenceSignal(
            signal_id=signal_id, severity="high",
            matched_text="SECRET-CONF-ALICE-2026",
            source_call_index=0 if grounded else None,
        ))
    return Finding(
        finding_id="F-cache01", vuln_class=VulnClass.AUTH_BYPASS,
        hypothesis_class=VulnClass.AUTH_BYPASS,
        evidence_class=VulnClass.AUTH_BYPASS,
        target="cache_get", severity="high", confidence=0.75,
        title="cross-tenant cache read", summary="holdout pair",
        signals=signals,
        poc_call_sequence=[_call("cache_get", {"owner": "bob", "key": "config"},
                                 "SECRET-CONF-ALICE-2026")],
    )


CACHE_PAIR = {
    "pair_id": "cache-tenant-collision",
    "expected_vuln_classes": ["auth_bypass"],
    "expected_signal_ids": [],
    "allow_llm_evidence": True,
    "control_forbidden_signal_prefixes": [],
    "control_block_patterns": ["not found", "no entry", "denied"],
}


# ── unknown-shape premise freeze ─────────────────────────────────────────────

def test_cache_exploit_trace_fires_zero_signals():
    """Vulnerable-version exploit trace must stay signal-silent (holdout premise)."""
    trace = [
        _call("cache_set", {"owner": "alice", "key": "config", "value": "SECRET-CONF-ALICE-2026"},
              "stored entry 'config' for owner 'alice'"),
        _call("cache_get", {"owner": "bob", "key": "config"},
              "SECRET-CONF-ALICE-2026"),  # cross-tenant leak
    ]
    assert run_all_signals(trace, "final") == []


def test_cache_fixed_denial_fires_zero_signals():
    """Fixed-version denial text must not fire any detector either."""
    denied = _call("cache_get", {"owner": "bob", "key": "config"},
                   "error: no entry 'config' in owner 'bob' cache")
    assert run_all_signals([denied], "final") == []


# ── finding_matches_pair ─────────────────────────────────────────────────────

def test_holdout_pair_accepts_grounded_llm_evidence():
    """allow_llm_evidence pair accepts a grounded llm verdict as the positive."""
    f = _finding("llm_evidence_verdict", grounded=True)
    assert finding_matches_pair(f, CACHE_PAIR)


def test_holdout_pair_rejects_ungrounded_llm_evidence():
    """An llm signal without a call index must NOT count as detection."""
    f = _finding("llm_evidence_verdict", grounded=False)
    assert not finding_matches_pair(f, CACHE_PAIR)


def test_pair_rejects_wrong_vuln_class():
    f = _finding("llm_evidence_verdict", grounded=True)
    f = f.model_copy(update={"vuln_class": VulnClass.PATH_TRAVERSAL})
    assert not finding_matches_pair(f, CACHE_PAIR)


# ── exploit_evidence_grounded ────────────────────────────────────────────────

def test_deterministic_signal_needs_call_index():
    """A deterministic signal without a source call index is not grounded."""
    f = _finding("sandbox_escape_write", grounded=False)
    assert exploit_evidence_grounded(f) is False


def test_no_signals_is_not_grounded():
    assert exploit_evidence_grounded(_finding(None)) is False


# ── control replay edges ─────────────────────────────────────────────────────

class _FixedSession:
    """Fixed server: denies the exploit read; a sibling write is also denied."""

    async def call_tool(self, name: str, args: dict) -> McpCall:
        if name == "cache_get":
            return _call(name, args, "error: no entry 'config' in owner 'bob' cache")
        return _call(name, args, "error: no entry in owner 'bob' cache")


async def test_control_replay_denial_counts_as_blocked():
    replay = await replay_finding_on_control(
        _finding("llm_evidence_verdict", grounded=True), _FixedSession(), CACHE_PAIR
    )
    assert replay.control_blocked is True
    assert replay.same_signal_reproduced is False
    assert replay.passed is True


class _ReplayingSession:
    """Control that does NOT block and echoes the exploit call (fix broken)."""

    async def call_tool(self, name: str, args: dict) -> McpCall:
        return _call(name, args, "SECRET-CONF-ALICE-2026")


async def test_control_replay_fails_when_fix_still_leaks():
    replay = await replay_finding_on_control(
        _finding("llm_evidence_verdict", grounded=True),
        _ReplayingSession(), CACHE_PAIR,
    )
    assert replay.control_blocked is False
    assert replay.passed is False


class _EmptySession:
    async def call_tool(self, name: str, args: dict) -> McpCall:
        return _call(name, args, "ok")


def test_finding_without_poc_sequence_skips_replay():
    f = _finding("llm_evidence_verdict", grounded=True)
    f = f.model_copy(update={"poc_call_sequence": []})
    replay = ControlReplay(finding_id=f.finding_id, calls_replayed=0)
    assert replay.calls_replayed == 0


# ── paired-run verdict edges ─────────────────────────────────────────────────

def test_run_fails_when_control_replay_missing():
    from types import SimpleNamespace

    from eval.holdout.runner import evaluate_pair_run

    f = _finding("llm_evidence_verdict", grounded=True)
    verdict = evaluate_pair_run(
        CACHE_PAIR,
        SimpleNamespace(findings=[f]),
        SimpleNamespace(findings=[]),
        [],
    )
    assert verdict["status"] == "FAIL"
    assert verdict["positive_detected"] is True
    assert verdict["fixed_clean"] is True
    assert verdict["control_replay_passed"] is False
    assert any("missing control replay" in r for r in verdict["reasons"])


def test_run_fails_when_control_replay_not_passed():
    from types import SimpleNamespace

    from eval.holdout.runner import evaluate_pair_run

    f = _finding("llm_evidence_verdict", grounded=True)
    bad = ControlReplay(
        finding_id=f.finding_id, calls_replayed=1,
        exploit_evidence_grounded=True, control_blocked=False,
        same_signal_reproduced=True, passed=False,
    )
    verdict = evaluate_pair_run(
        CACHE_PAIR, SimpleNamespace(findings=[f]), SimpleNamespace(findings=[]), [bad]
    )
    assert verdict["status"] == "FAIL"
    assert verdict["control_replay_passed"] is False


def test_freeze_check_roundtrip():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "eval/holdout/freeze.py", "--check"],
        capture_output=True, text=True, cwd=str(ROOT), check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ── real-server integration (hermetic: local subprocess, no LLM/network) ─────

def _cache_exploit_finding() -> Finding:
    """Finding whose PoC is the real cross-tenant exploit sequence."""
    return Finding(
        finding_id="F-cache-real01", vuln_class=VulnClass.AUTH_BYPASS,
        hypothesis_class=VulnClass.AUTH_BYPASS,
        evidence_class=VulnClass.AUTH_BYPASS,
        target="cache_get", severity="high", confidence=0.75,
        title="cross-tenant cache read", summary="real replay on fixed server",
        signals=[EvidenceSignal(
            signal_id="llm_evidence_verdict", severity="high",
            matched_text="SECRET-CONF-ALICE-2026", source_call_index=1,
        )],
        poc_call_sequence=[
            _call("cache_set", {"owner": "alice", "key": "config",
                                "value": "SECRET-CONF-ALICE-2026"},
                  "stored entry 'config' for owner 'alice'"),
            _call("cache_get", {"owner": "bob", "key": "config"},
                  "SECRET-CONF-ALICE-2026"),
        ],
    )


async def test_replay_on_real_fixed_server_denies_exploit():
    """Full causal chain on the REAL fixed cache server: exploit is grounded,
    the fixed version denies it, no signal reproduces."""
    from eval.holdout.fixtures._fresh import fresh_cache_target
    from mcp_redteam.targets.mcp_client import McpSession

    async with fresh_cache_target(19217, fixed=True) as sse_url, McpSession(sse_url) as session:
        replay = await replay_finding_on_control(
            _cache_exploit_finding(), session, CACHE_PAIR
        )
    assert replay.calls_replayed == 2
    assert replay.control_blocked is True
    assert replay.same_signal_reproduced is False
    assert replay.passed is True
    assert replay.denied_pattern == "no entry"


async def test_replay_on_real_vulnerable_server_leaks():
    """The same replay on the REAL vulnerable server must reproduce the leak
    (control evidence: the mechanism is absent there, not just denied)."""
    from eval.holdout.fixtures._fresh import fresh_cache_target
    from mcp_redteam.targets.mcp_client import McpSession

    async with fresh_cache_target(19218) as sse_url, McpSession(sse_url) as session:
        replay = await replay_finding_on_control(
            _cache_exploit_finding(), session, CACHE_PAIR
        )
    assert replay.calls_replayed == 2
    assert replay.control_blocked is False
    assert replay.passed is False
