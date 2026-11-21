"""Hermetic tests for the data-platform metrics layer (mcp_redteam.web.metrics)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_redteam.web.export import export_static_site
from mcp_redteam.web.indexer import RunIndex
from mcp_redteam.web.metrics import build_metrics_bundle
from tests.test_web_indexer import _holdout_summary, _scan_raw, _write_run


def _rich_raw(run_id: str, **over: object) -> dict:
    """One run with judge/evidence/hallucination traces for metric checks."""
    traces = over.pop("traces", None)
    if traces is None:
        traces = [
            {  # L2 judge, steered
                "vuln_class": "indirect_injection",
                "target": "read_resource",
                "tokens_in": 100,
                "tokens_out": 10,
                "judge_verdict": {"steered": True, "reason": "r"},
                "suspected_hallucination": False,
            },
            {  # evidence judge, finding
                "vuln_class": "auth_bypass",
                "target": "cache_get",
                "tokens_in": 200,
                "tokens_out": 20,
                "llm_evidence_verdict": {
                    "is_finding": True,
                    "vuln_class": "auth_bypass",
                    "confidence": 0.9,
                },
                "suspected_hallucination": False,
            },
            {  # hallucination marker
                "vuln_class": "auth_bypass",
                "target": "cache_get",
                "tokens_in": 50,
                "tokens_out": 5,
                "suspected_hallucination": True,
            },
        ]
    findings = over.pop("findings", None)
    if findings is None:
        findings = [
            {"vuln_class": "auth_bypass", "severity": "high", "confidence": 0.9},
            {"vuln_class": "ssrf", "severity": "medium", "confidence": 0.7},
        ]
    raw = _scan_raw(
        run_id,
        traces=traces,
        attacker_tokens_effective=800,
        **over,
    )
    raw["findings"] = findings
    return raw


def test_run_metrics_extraction(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "exp1/run", _rich_raw("scan-1"))
    idx = RunIndex(runs)
    idx.refresh()
    metrics = idx.metrics()
    assert len(metrics) == 1
    m = metrics[0]
    assert m.trace_count == 3
    assert m.findings_count == 2
    assert m.tokens_in == 350 and m.tokens_out == 35
    assert m.l2_total == 1 and m.l2_steered == 1
    assert m.evidence_total == 1 and m.evidence_finding == 1
    assert m.evidence_conf_sum == pytest.approx(0.9)
    assert m.hallucinated == 1
    assert m.traces_by_vuln_class == {
        "indirect_injection": 1,
        "auth_bypass": 2,
    }
    assert m.findings_by_vuln_class == {"auth_bypass": 1, "ssrf": 1}
    assert m.findings_by_severity == {"high": 1, "medium": 1}
    assert m.evidence_finding_by_vuln_class == {"auth_bypass": 1}
    assert m.attacker_tokens_effective == 800


def test_bundle_dimensions_and_sums(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "exp1/a", _rich_raw("scan-1"))
    _write_run(
        runs,
        "exp2/b",
        _rich_raw(
            "scan-2",
            started_at="2026-11-01T09:00:00Z",
            attacker_model="m-2",
            attacker_tokens=500,
            findings=[],
        ),
    )
    idx = RunIndex(runs)
    idx.refresh()
    bundle = build_metrics_bundle(idx.metrics(), idx.skipped)
    assert bundle.run_count == 2
    assert bundle.date_min == "2026-10-06"
    assert bundle.date_max == "2026-11-01"
    labels = {g.label: g for g in bundle.by_experiment}
    assert set(labels) == {"exp1", "exp2"}
    assert labels["exp1"].findings == 2
    assert labels["exp2"].findings == 0
    assert labels["exp1"].tokens_per_finding > 0
    assert labels["exp2"].tokens_per_finding == 0.0
    models = {g.label: g for g in bundle.by_model}
    assert set(models) == {"m-attacker", "m-2"}
    dates = [g.label for g in bundle.by_date]
    assert dates == sorted(dates)  # timeline ascending
    vuln = {g.label: g for g in bundle.by_vuln_class}
    assert vuln["auth_bypass"].traces == 4
    assert vuln["auth_bypass"].findings == 1
    assert vuln["auth_bypass"].evidence_finding == 2
    assert vuln["indirect_injection"].traces == 2
    assert vuln["ssrf"].findings == 1
    summary = bundle.summary
    assert summary.runs == 2 and summary.traces == 6 and summary.findings == 2
    assert summary.hallucinated == 2 and summary.evidence_finding == 2


def test_bundle_empty_runs(tmp_path: Path) -> None:
    bundle = build_metrics_bundle([], 0)
    assert bundle.run_count == 0
    assert bundle.by_experiment == []
    assert bundle.summary.runs == 0
    assert bundle.summary.tokens_per_finding == 0.0
    assert bundle.recommendations == []


def test_recommendations_fire_on_real_patterns(tmp_path: Path) -> None:
    """预算截断 / 低产出类 / 幻觉 / error 各触发一条带数据引用的建议。"""
    runs = tmp_path / "runs"
    # 3 条 budget_tokens 截断 run(触发规则 1)+ 1 条 error(规则 5)+ 幻觉(规则 4)
    for i in range(3):
        _write_run(
            runs,
            f"exp_a/r{i}",
            _rich_raw(f"scan-a{i}", stop_reason="budget_tokens"),
        )
    _write_run(
        runs,
        "exp_a/err",
        _rich_raw("scan-err", stop_reason="error", findings=[]),
    )
    idx = RunIndex(runs)
    idx.refresh()
    bundle = build_metrics_bundle(idx.metrics(), idx.skipped)
    labels = [r.label for r in bundle.recommendations]
    assert "预算截断占比过高" in labels
    assert "存在幻觉标记" in labels
    assert "存在 error 终止的运行" in labels
    budget_rec = next(r for r in bundle.recommendations if r.label == "预算截断占比过高")
    assert budget_rec.priority == "high"
    assert "75%" in budget_rec.evidence  # 3/4 runs 截断
    # 所有建议都带行动指向
    assert all(r.action for r in bundle.recommendations)


def test_recommendations_low_yield_class(tmp_path: Path) -> None:
    """产出率 < 30% 且探查数 >= 20 的类触发建议。"""
    runs = tmp_path / "runs"
    traces = [{"vuln_class": "indirect_injection", "target": "t", "tokens_in": 1, "tokens_out": 1} for _ in range(10)]
    findings = [{"vuln_class": "indirect_injection", "severity": "low", "confidence": 0.6}]
    for i in range(2):
        _write_run(runs, f"exp/r{i}", _rich_raw(f"scan-{i}", traces=traces, findings=findings))
    idx = RunIndex(runs)
    idx.refresh()
    bundle = build_metrics_bundle(idx.metrics(), idx.skipped)
    rec = next((r for r in bundle.recommendations if r.label.startswith("indirect_injection")), None)
    assert rec is not None
    assert rec.priority == "medium"
    assert "20 次探查" in rec.evidence  # 2 runs × 10 traces



def test_export_includes_metrics(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _write_run(runs, "exp1/a", _rich_raw("scan-1"))
    (runs / "holdout").mkdir(parents=True)
    (runs / "holdout" / "summary.json").write_text(
        json.dumps(_holdout_summary()), encoding="utf-8"
    )
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    (ui / "styles.css").write_text("body{}", encoding="utf-8")
    (ui / "app.js").write_text("// console", encoding="utf-8")
    out = tmp_path / "site"
    export_static_site(runs_dir=runs, ui_dir=ui, out_dir=out)
    prefix = "window.MCPWN_EXPORT_DATA = "
    text = (out / "data.js").read_text(encoding="utf-8")
    data = json.loads(text.split(prefix, 1)[1].strip().rstrip(";"))
    assert data["metrics"]["run_count"] == 1
    assert data["metrics"]["summary"]["evidence_finding"] == 1
    assert data["metrics"]["by_vuln_class"][0]["label"] == "auth_bypass"
