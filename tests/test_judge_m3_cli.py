"""CLI-level integration tests for `mcpwn eval dvmcp judge-m3`."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_redteam.cli import app
from mcp_redteam.contracts import M3JudgeReport
from tests.fixtures.m3_builder import build_m3_fixture

runner = CliRunner()

_CRITERIA_KEYS = {
    "recall_llm_ge_hardcoded",
    "fpr_llm_le_hardcoded",
    "chain_9010_real",
    "avg_findings_llm_ge_hardcoded",
    "planner_non_fallback_ge_0_8",
}


def _run(tmp_path: Path, scenario: str):
    root = build_m3_fixture(tmp_path, scenario)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "eval", "dvmcp", "judge-m3",
            "--baseline", str(root / "baseline"),
            "--llm", str(root / "llm"),
            "--out", str(out),
        ],
    )
    return result, out


def _load(out: Path) -> dict:
    return json.loads((out / "judge_report.json").read_text(encoding="utf-8"))


def test_judge_m3_judge_unavailable_yields_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_redteam.cli._build_m3_judge_fn", lambda judge_model: (None, ""))
    result, out = _run(tmp_path, "all_pass")
    assert result.exit_code == 0, result.output
    assert (out / "judge_report.json").exists()
    assert (out / "judge_report.md").exists()
    report = _load(out)
    assert report["verdict"] == "inconclusive"
    assert set(report["criteria"]) == _CRITERIA_KEYS
    assert report["judge_model"] == ""


def test_judge_m3_stub_judge_writes_pass_report(tmp_path, monkeypatch):
    def stub_judge(inp):
        return M3JudgeReport(
            verdict="pass",
            criteria=inp.criteria,
            metrics=inp.metrics,
            planner_fallback_rate=inp.planner_fallback_rate,
            evidence_refs=inp.evidence_refs,
            reason="stub",
            judge_model="stub",
        )

    monkeypatch.setattr("mcp_redteam.cli._build_m3_judge_fn", lambda judge_model: (stub_judge, "stub"))
    result, out = _run(tmp_path, "all_pass")
    assert result.exit_code == 0, result.output
    report = _load(out)
    assert report["verdict"] == "pass"
    assert report["judge_model"] == "stub"
    assert set(report["criteria"]) == _CRITERIA_KEYS
