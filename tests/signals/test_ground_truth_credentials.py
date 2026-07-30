"""Regression test: the archived DVMCP-9001 ground truth fixture must still
trigger the generic credentials signals.

The fixture (``runs/manual_ground_truth/challenge_01.json``) is a v0 ``Attempt``
snapshot; we only reuse the ``mcp_calls`` result_text + target_output as inputs
for the v1 signal detectors. HANDOFF regulation #4 forbids hardcoding known
DVMCP answer strings in this file, so we assert on structural properties
(signal_id / severity / redaction) instead of literal secret substrings.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import (
    detect_leaks_api_key_shape,
    detect_leaks_hardcoded_password,
    run_all_signals,
)

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "runs"
    / "manual_ground_truth"
    / "challenge_01.json"
)


def _load_fixture() -> tuple[list[McpCall], str]:
    raw = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    calls = [
        McpCall(
            kind=c["kind"],
            name=c.get("name"),
            args=c.get("args"),
            result_text=c["result_text"],
            elapsed_ms=c["elapsed_ms"],
        )
        for c in raw["mcp_calls"]
    ]
    return calls, raw["target_output"]


def test_fixture_present():
    assert _FIXTURE.exists(), f"fixture missing: {_FIXTURE}"


def test_api_key_signal_fires_on_fixture():
    calls, output = _load_fixture()
    result = detect_leaks_api_key_shape(calls, output)
    assert result is not None, "the api-key signal must fire on the fixture"
    assert result.severity == "high"
    # matched_text is redacted for high/critical; must not leak the raw key.
    assert result.matched_text.startswith("<redacted head=")


def test_hardcoded_password_signal_fires_on_fixture():
    calls, output = _load_fixture()
    result = detect_leaks_hardcoded_password(calls, output)
    assert result is not None, "the hardcoded-password signal must fire on the fixture"
    assert result.severity == "high"


def test_full_signal_sweep_produces_high_confidence():
    """Sanity check: the whole detector suite over this fixture should yield
    at least one high-severity signal (i.e. would produce a Finding in scan)."""
    calls, output = _load_fixture()
    signals = run_all_signals(calls, output)
    ids = {s.signal_id for s in signals}
    severities = {s.severity for s in signals}
    assert "leaks_api_key_shape" in ids
    assert "leaks_hardcoded_password" in ids
    assert "high" in severities or "critical" in severities
