"""Contract round-trip tests: dump -> load must not lose or reject fields.

Regression: ``total_tokens`` used to be a ``computed_field``, so
``model_dump_json`` wrote it into scan_result.json but ``model_validate``
rejected the same file under ``extra="forbid"`` — offline re-analysis of
historical results (benchmark aggregation, M3 judge) was impossible.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_redteam.contracts import ScanResult


def _minimal_result() -> ScanResult:
    return ScanResult(
        run_id="scan-rt",
        sse_url="http://127.0.0.1:9001/sse",
        transport="sse",
        started_at="2026-08-29T00:00:00Z",
        wall_seconds=1.0,
        attacker_tokens=123,
        judge_tokens=45,
        stop_reason="completed",
    )


def test_scan_result_round_trip(tmp_path: Path):
    r = _minimal_result()
    assert r.total_tokens == 168  # derived on construction

    path = tmp_path / "scan_result.json"
    path.write_text(r.model_dump_json(indent=2), encoding="utf-8")

    r2 = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert r2.total_tokens == 168
    assert r2.model_dump() == r.model_dump()


def test_scan_result_rejects_tampered_total():
    # total_tokens is derived, so a wrong stored value is recomputed on load.
    r = _minimal_result()
    data = json.loads(r.model_dump_json())
    data["total_tokens"] = 999
    assert ScanResult.model_validate(data).total_tokens == 168
