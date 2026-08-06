"""Parity: `scan(graph=False)` vs `scan(graph=True)` produce the same result.

Hermetic (no LLM, no network, no Docker): FakeMcpSession + stub attacker
replay the M0 (DVMCP 9001) decision path - the same fixture family as
``test_regression_baseline.py`` - so the graph refactor cannot silently
change scan behaviour without this test flipping red.

Non-deterministic per-run fields (run_id / started_at / wall_seconds) and
out_dir-dependent paths (trace_ref) are compared structurally, everything
else field-level.
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


def _assert_parity(old, new) -> None:
    """Field-level equality excluding per-run non-determinism.

    Commit-2 note: ``attack_messages_sha1`` and ``attacker_messages`` are NOT
    compared - the graph path injects prior_evidence user messages into later
    traces (B-stage memory), so hashes legitimately differ. The finding set
    and trace *structure* must still match runner.scan exactly; the injection
    itself is asserted in test_langgraph_memory.py.
    """
    assert new.sse_url == old.sse_url
    assert new.attacker_tokens == old.attacker_tokens
    assert new.judge_tokens == old.judge_tokens
    assert new.tools_seen == old.tools_seen
    assert new.resources_seen == old.resources_seen
    assert new.stop_reason == old.stop_reason
    assert new.attacker_model == old.attacker_model
    assert new.attacker_temperature == old.attacker_temperature
    assert new.seed == old.seed
    assert new.evidence_judge_model == old.evidence_judge_model
    assert new.sandbox_root == old.sandbox_root
    assert new.total_tokens == old.total_tokens

    # traces: same classes and targets (prompt contents intentionally differ)
    assert [t.vuln_class.value for t in new.traces] == [
        t.vuln_class.value for t in old.traces
    ]
    assert [t.target for t in new.traces] == [t.target for t in old.traces]

    # findings: identical except trace_ref absolute paths differ by out_dir
    assert [f.model_dump(exclude={"trace_ref"}) for f in new.findings] == [
        f.model_dump(exclude={"trace_ref"}) for f in old.findings
    ]
    assert [pathlib.Path(f.trace_ref).name for f in new.findings] == [
        pathlib.Path(f.trace_ref).name for f in old.findings
    ]


def _scan_both(tmp_path: pathlib.Path, **kwargs):
    """Run the runner and graph paths with identical kwargs + patch context.

    Each path gets its own decisions list; both are returned so the M3
    bookkeeping of the two paths can be compared directly.
    """
    decisions_old: list = []
    decisions_new: list = []
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        old = asyncio.run(runner_mod.scan(
            out_dir=tmp_path / "runner", decisions=decisions_old, **kwargs
        ))
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        new = asyncio.run(runner_mod.scan(
            out_dir=tmp_path / "graph", graph=True, decisions=decisions_new, **kwargs
        ))
    return old, new, decisions_old, decisions_new


def test_graph_parity_with_runner_scan(tmp_path) -> None:
    """graph=True must reproduce graph=False on the M0 baseline fixture."""
    baseline = _load_baseline()
    old, new, decisions_old, decisions_new = _scan_both(
        tmp_path,
        sse_url=baseline["sse_url"], max_tokens=10_000,
        wall_seconds=60, max_candidates=5,
    )

    _assert_parity(old, new)
    assert decisions_new == decisions_old  # M3 contract identical too

    # The graph path also writes its own scan_result.json (runner contract)
    assert (tmp_path / "graph" / "scan_result.json").is_file()


def test_graph_still_finds_m0_baseline_classes(tmp_path) -> None:
    """Graph path must not lose recall on the M0 fixture."""
    baseline = _load_baseline()
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        result = asyncio.run(runner_mod.scan(
            sse_url=baseline["sse_url"],
            out_dir=tmp_path,
            max_tokens=10_000,
            wall_seconds=60,
            max_candidates=5,
            graph=True,
        ))

    assert result.stop_reason in ("completed", "budget_tokens")
    matched = [
        f for f in result.findings
        if f.vuln_class.value in baseline["expected_vuln_classes"]
    ]
    assert matched, (
        f"graph scan lost baseline recall: "
        f"got {[f.vuln_class.value for f in result.findings]}"
    )


def test_graph_parity_m3_decisions(tmp_path) -> None:
    """Both paths must fill the M3 PlannerDecision contract identically.

    On the stub (no budget exhaustion) every planned candidate is executed,
    so both lists should be field-identical: all executed, no skip.
    """
    baseline = _load_baseline()
    old, new, decisions_old, decisions_new = _scan_both(
        tmp_path,
        sse_url=baseline["sse_url"], max_tokens=10_000,
        wall_seconds=60, max_candidates=5,
    )
    assert decisions_old, "decisions list was never populated"
    assert all(d.executed and d.skip_reason is None for d in decisions_old)
    assert [d.vuln_class for d in decisions_old] == [
        t.vuln_class.value for t in old.traces
    ]
    assert decisions_new == decisions_old
    _assert_parity(old, new)


def test_graph_parity_budget_exhaustion(tmp_path) -> None:
    """Under a tiny token budget both paths stop at the same candidate and
    record identical skip bookkeeping (runner loop-top break vs graph gate).
    """
    baseline = _load_baseline()
    decisions_old: list = []
    decisions_new: list = []
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        old = asyncio.run(runner_mod.scan(
            sse_url=baseline["sse_url"], out_dir=tmp_path / "runner",
            max_tokens=250, wall_seconds=60, max_candidates=5,
            decisions=decisions_old,
        ))
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        new = asyncio.run(runner_mod.scan(
            sse_url=baseline["sse_url"], out_dir=tmp_path / "graph",
            max_tokens=250, wall_seconds=60, max_candidates=5,
            decisions=decisions_new, graph=True,
        ))

    _assert_parity(old, new)
    assert decisions_new == decisions_old
    skipped = [d for d in decisions_new if not d.executed]
    assert skipped, "tiny budget should have skipped unexecuted candidates"
    assert all(d.skip_reason == "budget" for d in skipped)
    # Both paths stopped after the same number of executed candidates.
    assert len(old.traces) == len(new.traces) == len(decisions_new) - len(skipped)
