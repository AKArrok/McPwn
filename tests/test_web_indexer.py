"""Hermetic tests for the eval-platform runs/ indexer (mcp_redteam.web)."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp_redteam.web.indexer import RunIndex


def _scan_raw(run_id: str, **over: object) -> dict:
    """Minimal scan_result.json-shaped dict (historical-artifact tolerant)."""
    raw: dict = {
        "run_id": run_id,
        "sse_url": "http://127.0.0.1:9001/sse",
        "transport": "sse",
        "started_at": "2026-10-06T11:29:24Z",
        "wall_seconds": 12.5,
        "attacker_tokens": 100,
        "judge_tokens": 10,
        "total_tokens": 110,
        "stop_reason": "completed",
        "tools_seen": [],
        "resources_seen": [],
        "traces": [{"vuln_class": "ssrf"}],
        "findings": [
            {
                "finding_id": "F-abc1234567",
                "vuln_class": "ssrf",
                "severity": "high",
                "confidence": 0.9,
                "title": "t",
                "target": "fetch_url",
            }
        ],
        "static_hits": [],
        "git_sha": "abc123",
        "attacker_model": "m-attacker",
        "evidence_judge_model": "m-judge",
    }
    raw.update(over)
    return raw


def _write_run(runs: Path, rel: str, raw: dict | str) -> None:
    d = runs / rel
    d.mkdir(parents=True, exist_ok=True)
    text = json.dumps(raw) if isinstance(raw, dict) else raw
    (d / "scan_result.json").write_text(text, encoding="utf-8")


def _holdout_summary() -> dict:
    return {
        "protocol_version": 1,
        "protocol_sha256": "e46e" * 16,
        "repeats": 5,
        "status": "FAIL",
        "pairs": [
            {
                "pair_id": "cache-tenant-collision",
                "split": "holdout",
                "passed": 0,
                "total": 5,
                "rate": 0.0,
                "ci95": [0.0, 0.434],
                "status": "FAIL",
                "runs": [
                    {
                        "index": 0,
                        "status": "FAIL",
                        "positive_detected": True,
                        "fixed_clean": False,
                        "control_replay_passed": True,
                        "reasons": [
                            "fixed version reproduced the same vulnerability family"
                        ],
                    }
                ],
            }
        ],
    }


def test_index_experiments_and_projection(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "m2_full/port_9001", _scan_raw("scan-a"))
    _write_run(
        runs,
        "holdout/pair/run_0/vulnerable",
        _scan_raw("scan-b", stop_reason="budget_tokens", findings=[]),
    )
    idx = RunIndex(runs)
    idx.refresh()
    sums = {s.run_id: s for s in idx.summaries()}
    assert set(sums) == {"scan-a", "scan-b"}
    a = sums["scan-a"]
    assert a.experiment == "m2_full"
    assert a.scan_dir == "m2_full/port_9001"
    assert a.findings_count == 1
    assert a.trace_count == 1
    assert a.evidence_judge_model == "m-judge"
    assert sums["scan-b"].stop_reason == "budget_tokens"
    assert sums["scan-b"].experiment == "holdout"
    findings = idx.findings()
    assert len(findings) == 1
    assert findings[0].run_id == "scan-a"
    assert findings[0].scan_dir == "m2_full/port_9001"
    assert findings[0].vuln_class == "ssrf"


def test_corrupt_and_shapeless_files_skipped(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "good/run", _scan_raw("scan-ok"))
    _write_run(runs, "truncated/run", "{not json")
    _write_run(runs, "noid/run", {"sse_url": "http://x/sse"})  # no run_id
    idx = RunIndex(runs)
    idx.refresh()
    assert [s.run_id for s in idx.summaries()] == ["scan-ok"]
    assert idx.skipped == 2


def test_mtime_cache_only_reparses_changes(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "exp/run", _scan_raw("scan-1"))
    idx = RunIndex(runs)
    idx.refresh()
    assert idx.parses == 1
    idx.refresh()
    assert idx.parses == 1  # unchanged mtime+size -> cache hit
    path = runs / "exp" / "run" / "scan_result.json"
    os.utime(path, (0, 10**9))  # force mtime change without rewriting content
    idx.refresh()
    assert idx.parses == 2
    path.unlink()
    idx.refresh()
    assert idx.summaries() == []


def test_detail_rereads_artifacts(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "exp/run", _scan_raw("scan-1"))
    (runs / "exp" / "run" / "findings.json").write_text(
        json.dumps({"schema_version": 1, "findings": []}), encoding="utf-8"
    )
    (runs / "exp" / "run" / "poc").mkdir()
    (runs / "exp" / "run" / "poc" / "F-abc1234567.py").write_text(
        "# poc", encoding="utf-8"
    )
    idx = RunIndex(runs)
    idx.refresh()
    d = idx.detail("scan-1")
    assert d is not None
    assert d["summary"]["run_id"] == "scan-1"
    assert d["scan_result"]["stop_reason"] == "completed"
    assert d["findings_artifact"]["schema_version"] == 1
    assert d["poc_files"] == ["F-abc1234567.py"]
    assert d["has_benchmark"] is False
    assert idx.detail("missing") is None


def test_holdout_mirrors_protocol_summaries_only(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    (runs / "holdout").mkdir(parents=True)
    (runs / "holdout" / "summary.json").write_text(
        json.dumps(_holdout_summary()), encoding="utf-8"
    )
    # Other experiments also write summary.json with different shapes.
    other = runs / "subagent_exp" / "smoke"
    other.mkdir(parents=True)
    (other / "summary.json").write_text(json.dumps({"runs": 3}), encoding="utf-8")
    idx = RunIndex(runs)
    views = idx.holdout()
    assert [v.source for v in views] == ["holdout"]
    v = views[0]
    assert v.protocol_version == 1
    assert v.status == "FAIL"
    assert v.repeats == 5
    pair = v.pairs[0]
    assert pair.pair_id == "cache-tenant-collision"
    assert pair.rate == 0.0
    assert pair.ci95 == [0.0, 0.434]
    assert pair.runs[0].positive_detected is True
    assert pair.runs[0].fixed_clean is False
    assert pair.runs[0].reasons == [
        "fixed version reproduced the same vulnerability family"
    ]
