"""Hermetic tests for the static snapshot export (mcpwn export-ui)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_redteam.web.export import export_static_site
from tests.test_web_indexer import _holdout_summary, _scan_raw, _write_run


@pytest.fixture
def seeded(tmp_path: Path) -> tuple[Path, Path]:
    runs = tmp_path / "runs"
    _write_run(runs, "m2_full/port_9001", _scan_raw("scan-a"))
    _write_run(
        runs,
        "holdout/pair/run_0/vulnerable",
        _scan_raw("scan-b", stop_reason="budget_tokens", findings=[]),
    )
    (runs / "holdout").mkdir(parents=True, exist_ok=True)
    (runs / "holdout" / "summary.json").write_text(
        json.dumps(_holdout_summary()), encoding="utf-8"
    )
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text(
        "<!doctype html><html><head><title>McPwn</title></head>"
        "<body>console</body></html>",
        encoding="utf-8",
    )
    (ui / "styles.css").write_text("body{}", encoding="utf-8")
    (ui / "app.js").write_text("// console", encoding="utf-8")
    return runs, ui


def _payload(data_js: str) -> dict:
    prefix = "window.MCPWN_EXPORT_DATA = "
    assert prefix in data_js
    return json.loads(data_js.split(prefix, 1)[1].strip().rstrip(";"))


def test_export_writes_self_contained_site(tmp_path: Path, seeded) -> None:
    runs, ui = seeded
    out = tmp_path / "site"
    report = export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out)
    assert report["run_count"] == 2
    for name in ("index.html", "styles.css", "app.js", "data.js"):
        assert (out / name).is_file()
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html
    assert "connect-src 'none'" in html
    assert '<script src="./data.js"></script>' in html
    data = _payload((out / "data.js").read_text(encoding="utf-8"))
    assert {r["run_id"] for r in data["runs"]} == {"scan-a", "scan-b"}
    assert data["findings"][0]["finding_id"] == "F-abc1234567"
    assert data["holdout"][0]["source"] == "holdout"
    assert data["holdout"][0]["pairs"][0]["ci95"] == [0.0, 0.434]


def test_export_refuses_existing_dir_without_force(tmp_path: Path, seeded) -> None:
    runs, ui = seeded
    out = tmp_path / "site"
    export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out)
    with pytest.raises(FileExistsError):
        export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out)
    report = export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out, force=True)
    assert report["run_count"] == 2  # rebuilt in place, not merged


def test_export_missing_console_file(tmp_path: Path, seeded) -> None:
    runs, ui = seeded
    (ui / "app.js").unlink()
    with pytest.raises(FileNotFoundError):
        export_static_site(runs_dir=runs, ui_dir=ui, out_dir=tmp_path / "site")


def test_export_failure_removes_partial_dir(tmp_path: Path, seeded) -> None:
    runs, ui = seeded
    out = tmp_path / "site"
    # index.html 在复制阶段存在、写回阶段会因目录被替换成文件而失败。
    (out).mkdir()
    (out / "index.html").write_text("stale", encoding="utf-8")
    with pytest.raises(FileExistsError):
        export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out)
    export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out, force=True)
    assert "stale" not in (out / "index.html").read_text(encoding="utf-8")
