"""Offline regression test against the M0 (DVMCP 9001) baseline.

HANDOFF C: the run is the test, and the test exercises the same code path
as the run. With ``FakeMcpSession`` + ``FakeChatCompletions`` + a
monkeypatched ``make_client``, the entire agent loop is reproducible in CI
without DVMCP, without ``ARK_API_KEY``, and without network access. The
429 ``SetLimitExceeded`` rate limit that surfaced during B verification is
what forced this design, and the design is now load-bearing: future
regressions in the signal library, planner heuristics, or verifier dedup
break this test before they ship.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from unittest.mock import patch

from mcp_redteam.orchestrator import runner as runner_mod
from tests.fixtures.mock_mcp import FakeMcpSession
from tests.fixtures.stub_attacker import fake_make_client

BASELINE_PATH = pathlib.Path(__file__).parent / "baselines" / "m0_9001.json"


def _load_baseline() -> dict:
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def test_scan_against_m0_baseline(tmp_path) -> None:
    """Replay M0 (DVMCP 9001) offline; findings must match the baseline.

    The test is hermetic: no Docker, no LLM API, no real network. It
    exercises the same orchestrator code path as ``mcpwn scan``, only the
    leaves (McpSession, OpenAI client) are swapped for fixtures. If this
    test ever flips red on a code change, either the change is a real
    regression or the baseline itself has drifted and needs re-curation.
    """
    baseline = _load_baseline()

    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        result = asyncio.run(runner_mod.scan(
            sse_url=baseline["sse_url"],
            out_dir=tmp_path,
            max_tokens=10_000,
            wall_seconds=60,
            max_candidates=5,
        ))

    # ── structural assertions ───────────────────────────────────────────
    assert result.stop_reason in ("completed", "budget_tokens"), (
        f"scan stopped early: {result.stop_reason!r}; "
        f"finding the regression source requires a clean exit, not a crash."
    )
    assert len(result.findings) >= baseline["min_findings_count"], (
        f"expected at least {baseline['min_findings_count']} finding(s), "
        f"got {len(result.findings)}; traces={len(result.traces)}."
    )
    assert len(result.traces) <= baseline["max_candidates_explored"], (
        f"too many candidates explored: {len(result.traces)} > "
        f"baseline {baseline['max_candidates_explored']}; the planner or "
        f"recon classifier may have regressed into spraying the whole keyspace."
    )

    # ── finding-level assertions: at least one must match baseline class ─
    matched = [
        f for f in result.findings
        if f.vuln_class.value in baseline["expected_vuln_classes"]
    ]
    assert matched, (
        f"no finding with vuln_class in {baseline['expected_vuln_classes']}; "
        f"got: {[f.vuln_class.value for f in result.findings]}. "
        f"Either the classifier stopped labelling the resource correctly, or "
        f"the verifier stripped the class signal."
    )

    # Use the highest-confidence finding in the expected class as the
    # representative for signal-coverage and confidence assertions.
    top = max(matched, key=lambda f: f.confidence)
    actual_signals = {s.signal_id for s in top.signals}

    missing = set(baseline["expected_signals"]) - actual_signals
    assert not missing, (
        f"top finding missing baseline signals: {sorted(missing)}. "
        f"Either a detector stopped firing on the recorded payload, or the "
        f"replayed tool response drifted from the fixture."
    )
    assert top.confidence >= baseline["min_confidence"], (
        f"top finding confidence {top.confidence:.4f} < "
        f"baseline {baseline['min_confidence']}. Either a detector's weight "
        f"moved, a dedup rule changed, or an unexpected cross-class signal "
        f"inflated the score in a way that no longer holds."
    )

    # ── reproducibility metadata (B contract) ──────────────────────────
    # Even on a fake run the metadata fields must be filled, so a human
    # inspecting the artifact later has enough context to know what
    # produced it (C's "run is the test" closes this loop).
    assert result.attacker_model == "m0-replay", (
        f"attacker_model field not populated as expected: {result.attacker_model!r}"
    )
    assert result.attacker_temperature == 0.0
    assert isinstance(result.git_sha, str)  # may be empty outside a git checkout


def test_baseline_file_is_self_consistent() -> None:
    """The baseline file itself must satisfy the schema the test relies on.

    Catches the case where a baseline gets hand-edited and an expected
    field silently disappears, which would make the regression test pass
    on vacuous conditions.
    """
    baseline = _load_baseline()
    for key in (
        "sse_url",
        "expected_vuln_classes",
        "expected_signals",
        "min_confidence",
        "min_findings_count",
        "max_candidates_explored",
    ):
        assert key in baseline, f"baseline missing required key: {key!r}"

    assert isinstance(baseline["expected_vuln_classes"], list) and baseline["expected_vuln_classes"]
    assert isinstance(baseline["expected_signals"], list) and baseline["expected_signals"]
    assert 0.0 <= baseline["min_confidence"] <= 1.0
    assert baseline["min_findings_count"] >= 1
    assert baseline["max_candidates_explored"] >= 1