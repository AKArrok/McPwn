"""CI gate tests for findings.json artifacts."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_redteam.ci import evaluate_ci_artifact, load_findings_artifact
from mcp_redteam.cli import app
from scripts.ci_artifact_smoke import main as ci_artifact_smoke_main
from scripts.package_smoke import main as package_smoke_main

runner = CliRunner()


def _artifact(
    *,
    stop_reason: str = "completed",
    findings: list[dict] | None = None,
    static_hits: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "run_id": "ci-test",
        "target": "stdio: python server.py",
        "transport": "stdio",
        "stop_reason": stop_reason,
        "counts": {
            "tools_seen": 0,
            "resources_seen": 0,
            "traces": 0,
            "findings": len(findings or []),
            "static_hits": len(static_hits or []),
        },
        "findings": findings or [],
        "static_hits": static_hits or [],
    }


def _finding(severity: str = "high") -> dict:
    return {
        "finding_id": "F-ci-test",
        "vuln_class": "auth_bypass",
        "target": "cache_get",
        "hypothesis_class": "auth_bypass",
        "evidence_class": "auth_bypass",
        "severity": severity,
        "confidence": 0.75,
        "title": "demo finding",
        "summary": "demo summary",
        "signals": [
            {
                "signal_id": "unauthenticated_success",
                "severity": severity,
                "matched_text": "sha256:demo",
                "source_call_index": 0,
            }
        ],
        "poc_call_sequence": [
            {
                "kind": "call_tool",
                "name": "cache_get",
                "args": {"owner": "bob", "key": "config"},
                "result_text": "sha256:demo",
                "elapsed_ms": 1,
            }
        ],
        "remediation_hint": "",
        "trace_ref": "",
    }


def test_ci_passes_completed_artifact_below_threshold():
    verdict = evaluate_ci_artifact(
        _artifact(findings=[{"severity": "medium"}]),
        fail_on="high",
    )

    assert verdict.exit_code == 0
    assert verdict.status == "pass"
    assert verdict.max_severity == "medium"


def test_ci_fails_on_finding_at_threshold():
    verdict = evaluate_ci_artifact(
        _artifact(findings=[{"severity": "high"}]),
        fail_on="high",
    )

    assert verdict.exit_code == 1
    assert verdict.status == "fail"
    assert verdict.blocking_count == 1


def test_ci_includes_static_hits_by_default():
    verdict = evaluate_ci_artifact(
        _artifact(static_hits=[{"severity": "critical"}]),
        fail_on="high",
    )

    assert verdict.exit_code == 1
    assert verdict.blocking_count == 1


def test_ci_can_ignore_static_hits():
    verdict = evaluate_ci_artifact(
        _artifact(static_hits=[{"severity": "critical"}]),
        fail_on="high",
        include_static=False,
    )

    assert verdict.exit_code == 0
    assert verdict.status == "pass"


def test_ci_marks_budget_scan_inconclusive_by_default():
    verdict = evaluate_ci_artifact(
        _artifact(stop_reason="budget_tokens", findings=[{"severity": "high"}]),
        fail_on="high",
    )

    assert verdict.exit_code == 3
    assert verdict.status == "inconclusive"


def test_ci_allows_inconclusive_when_requested():
    verdict = evaluate_ci_artifact(
        _artifact(stop_reason="budget_tokens", findings=[{"severity": "high"}]),
        fail_on="high",
        allow_inconclusive=True,
    )

    assert verdict.exit_code == 1
    assert verdict.status == "fail"


def test_ci_rejects_invalid_threshold():
    verdict = evaluate_ci_artifact(_artifact(), fail_on="severe")

    assert verdict.exit_code == 2
    assert verdict.status == "invalid"


def test_load_findings_artifact_accepts_output_directory(tmp_path):
    out_dir = tmp_path / "scan"
    out_dir.mkdir()
    (out_dir / "findings.json").write_text(
        json.dumps(_artifact(), ensure_ascii=False),
        encoding="utf-8",
    )

    data = load_findings_artifact(out_dir)

    assert data["run_id"] == "ci-test"


def test_ci_cli_fails_on_high_finding(tmp_path):
    out_dir = tmp_path / "scan"
    out_dir.mkdir()
    (out_dir / "findings.json").write_text(
        json.dumps(_artifact(findings=[_finding("high")]), ensure_ascii=False),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["ci", str(out_dir), "--fail-on", "high"])

    assert result.exit_code == 1
    assert "fail" in result.output


def test_ci_cli_rejects_missing_artifact(tmp_path):
    result = runner.invoke(app, ["ci", str(tmp_path / "missing")])

    assert result.exit_code == 2
    assert "invalid CI artifact" in result.output


def test_validate_artifact_cli_accepts_schema_valid_artifact(tmp_path):
    out_dir = tmp_path / "scan"
    out_dir.mkdir()
    (out_dir / "findings.json").write_text(
        json.dumps(_artifact(findings=[_finding("medium")]), ensure_ascii=False),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate-artifact", str(out_dir)])

    assert result.exit_code == 0
    assert "valid" in result.output


def test_validate_artifact_cli_rejects_schema_invalid_finding(tmp_path):
    out_dir = tmp_path / "scan"
    out_dir.mkdir()
    malformed = _finding("high")
    malformed.pop("title")
    (out_dir / "findings.json").write_text(
        json.dumps(_artifact(findings=[malformed]), ensure_ascii=False),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate-artifact", str(out_dir)])

    assert result.exit_code == 2
    assert "invalid artifact" in result.output
    assert "title" in result.output


def test_ci_artifact_smoke_script_passes():
    assert ci_artifact_smoke_main() == 0


def test_package_smoke_script_passes():
    assert package_smoke_main() == 0
