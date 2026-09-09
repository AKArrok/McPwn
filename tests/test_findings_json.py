"""Machine-readable findings.json report tests."""

from __future__ import annotations

import json

from mcp_redteam.artifacts import validate_findings_artifact
from mcp_redteam.contracts import EvidenceSignal, Finding, McpCall, ScanResult, VulnClass
from mcp_redteam.report.findings import write_findings, write_findings_json


def _finding() -> Finding:
    return Finding(
        finding_id="F-demo",
        vuln_class=VulnClass.AUTH_BYPASS,
        target="read_secret",
        severity="high",
        confidence=0.75,
        title="demo auth bypass",
        summary="read another user's secret",
        signals=[
            EvidenceSignal(
                signal_id="llm_evidence_verdict",
                severity="high",
                matched_text="sha256:demo",
                source_call_index=0,
            )
        ],
        poc_call_sequence=[
            McpCall(
                kind="call_tool",
                name="read_secret",
                args={"owner": "alice"},
                result_text="sha256:demo",
                elapsed_ms=1,
            )
        ],
    )


def _result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        run_id="scan-json-test",
        sse_url="stdio: python server.py",
        transport="stdio",
        started_at="2026-09-02T00:00:00Z",
        wall_seconds=1.0,
        attacker_tokens=10,
        judge_tokens=0,
        tools_seen=["read_secret"],
        resources_seen=[],
        traces=[],
        findings=findings or [],
        stop_reason="completed",
    )


def test_write_findings_json_has_stable_top_level_shape(tmp_path):
    path = write_findings_json(_result([_finding()]), tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["schema_version"] == 1
    assert data["run_id"] == "scan-json-test"
    assert data["target"] == "stdio: python server.py"
    assert data["counts"]["findings"] == 1
    assert data["findings"][0]["finding_id"] == "F-demo"
    assert data["findings"][0]["vuln_class"] == "auth_bypass"
    assert data["findings"][0]["poc_call_sequence"][0]["name"] == "read_secret"


def test_write_findings_json_matches_checked_in_schema(tmp_path):
    path = write_findings_json(_result([_finding()]), tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    validate_findings_artifact(data)


def test_write_findings_also_emits_json(tmp_path):
    write_findings(_result(), tmp_path)
    data = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))

    assert data["counts"]["findings"] == 0
    assert data["findings"] == []
