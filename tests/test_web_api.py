"""Hermetic API tests for the eval-platform FastAPI app (``mcpwn ui``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mcp_redteam.web.app import create_app
from tests.test_web_indexer import _holdout_summary, _scan_raw, _write_run


@pytest.fixture
def client(tmp_path: Path):
    runs = tmp_path / "runs"
    _write_run(runs, "m2_full/port_9001", _scan_raw("scan-a"))
    _write_run(
        runs,
        "holdout/pair/run_0/vulnerable",
        _scan_raw(
            "scan-b",
            stop_reason="budget_tokens",
            findings=[],
            sse_url="http://127.0.0.1:19215/sse",
        ),
    )
    (runs / "holdout").mkdir(parents=True, exist_ok=True)
    (runs / "holdout" / "summary.json").write_text(
        json.dumps(_holdout_summary()), encoding="utf-8"
    )
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text(
        "<!doctype html><html><body>console</body></html>", encoding="utf-8"
    )
    app = create_app(runs_dir=runs, ui_dir=ui)
    with TestClient(app) as test_client:
        yield test_client


def test_static_ui_served_with_csp(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "console" in r.text
    csp = r.headers["content-security-policy"]
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_platform_info(client: TestClient) -> None:
    body = client.get("/api/platform").json()
    assert body["read_only"] is True
    assert body["run_count"] == 2
    assert body["skipped"] == 0


def test_list_runs_and_filters(client: TestClient) -> None:
    runs = client.get("/api/runs").json()["runs"]
    assert {r["run_id"] for r in runs} == {"scan-a", "scan-b"}
    filtered = client.get(
        "/api/runs", params={"stop_reason": "budget_tokens"}
    ).json()["runs"]
    assert [r["run_id"] for r in filtered] == ["scan-b"]
    assert client.get("/api/runs", params={"experiment": "holdout"}).json()[
        "runs"
    ] != []  # scan-b lives under holdout/pair/run_0/vulnerable
    assert client.get("/api/runs", params={"experiment": "nope"}).json()["runs"] == []
    by_target = client.get("/api/runs", params={"target": "9001"}).json()["runs"]
    assert [r["run_id"] for r in by_target] == ["scan-a"]


def test_run_detail_and_404(client: TestClient) -> None:
    body = client.get("/api/runs/scan-a").json()
    assert body["summary"]["run_id"] == "scan-a"
    assert body["scan_result"]["stop_reason"] == "completed"
    assert body["findings_artifact"] is None
    assert client.get("/api/runs/nope").status_code == 404


def test_compare_columns_and_validation(client: TestClient) -> None:
    cols = client.get(
        "/api/compare", params={"run_ids": "scan-a,scan-b,missing"}
    ).json()["columns"]
    assert cols[0]["summary"]["run_id"] == "scan-a"
    assert cols[0]["findings"][0]["finding_id"] == "F-abc1234567"
    assert cols[1]["summary"]["stop_reason"] == "budget_tokens"
    assert cols[2]["missing"] is True
    assert client.get("/api/compare", params={"run_ids": ""}).status_code == 422
    too_many = ",".join(f"r{i}" for i in range(9))
    assert client.get("/api/compare", params={"run_ids": too_many}).status_code == 422


def test_findings_endpoint_filter(client: TestClient) -> None:
    body = client.get("/api/findings").json()
    assert body["total"] == 1
    assert body["findings"][0]["run_id"] == "scan-a"
    empty = client.get("/api/findings", params={"severity": "low"}).json()
    assert empty["total"] == 0


def test_holdout_endpoint(client: TestClient) -> None:
    summaries = client.get("/api/holdout").json()["summaries"]
    assert len(summaries) == 1
    assert summaries[0]["source"] == "holdout"
    assert summaries[0]["pairs"][0]["pair_id"] == "cache-tenant-collision"
    assert summaries[0]["pairs"][0]["rate"] == 0.0
