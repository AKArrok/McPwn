"""Regression tests for the persisted-artifact secret boundary."""

from __future__ import annotations

import json

import pytest

from mcp_redteam.contracts import (
    AttackTrace,
    Finding,
    McpCall,
    ScanResult,
    TargetSpec,
    Transport,
    VulnClass,
)
from mcp_redteam.report.findings import write_findings
from mcp_redteam.security import (
    REDACTED,
    redact_scan_result,
    redact_text,
    resolve_artifact_refs,
    resolve_artifact_values,
)


def _result() -> ScanResult:
    call = McpCall(
        kind="call_tool",
        name="read_secret",
        args={"token": "header-secret-1234"},
        result_text="Authorization: Bearer bearer-secret-1234; value=header-secret-1234",
        elapsed_ms=1,
    )
    trace = AttackTrace(
        vuln_class=VulnClass.AUTH_BYPASS,
        target="read_secret",
        strategy_card_slug=VulnClass.AUTH_BYPASS.value,
        attack_calls=[call],
        final_llm_output="the token is header-secret-1234",
    )
    finding = Finding(
        finding_id="F-secret",
        vuln_class=VulnClass.AUTH_BYPASS,
        target="read_secret",
        severity="high",
        confidence=0.75,
        title="secret boundary",
        summary="Authorization: Bearer bearer-secret-1234",
        poc_call_sequence=[call],
    )
    spec = TargetSpec(
        transport=Transport.STDIO,
        command=["python", "server.py"],
        env={"MCP_TOKEN": "header-secret-1234"},
        headers={"Authorization": "bearer-secret-1234"},
    )
    return ScanResult(
        run_id="security-test",
        sse_url=spec.display,
        transport=spec.transport.value,
        target_spec=spec.model_dump(mode="json"),
        started_at="2026-09-10T00:00:00Z",
        wall_seconds=1,
        traces=[trace],
        findings=[finding],
        stop_reason="completed",
    )


def test_redact_text_removes_known_and_credential_shaped_values():
    text = redact_text(
        "token=known-secret-1234 bearer shaped-secret-1234",
        secrets={"known-secret-1234"},
    )
    assert "known-secret-1234" not in text
    assert "shaped-secret-1234" not in text
    assert REDACTED in text
    json_text = redact_text("{\"token\": \"known-secret-1234\"}")
    assert "known-secret-1234" not in json_text


def test_redact_scan_result_replaces_target_credentials_with_references():
    safe = redact_scan_result(_result())
    encoded = json.dumps(safe.model_dump(mode="json"), ensure_ascii=False)

    assert "header-secret-1234" not in encoded
    assert "bearer-secret-1234" not in encoded
    assert safe.target_spec["env"]["MCP_TOKEN"] == "${MCP_TOKEN}"
    assert safe.target_spec["headers"]["Authorization"] == "${MCPWN_HEADER_AUTHORIZATION}"
    assert safe.findings[0].poc_call_sequence[0].args["token"] == "${MCP_TOKEN}"


def test_write_findings_persists_only_redacted_values(tmp_path):
    write_findings(_result(), tmp_path)
    persisted = "\n".join(
        path.read_text(encoding="utf-8")
        for path in tmp_path.rglob("*")
        if path.is_file()
    )

    assert "header-secret-1234" not in persisted
    assert "bearer-secret-1234" not in persisted
    assert "${MCP_TOKEN}" in persisted
    assert "resolve_artifact_values" in persisted


def test_resolve_artifact_refs_requires_local_credentials(monkeypatch):
    spec = TargetSpec(
        transport=Transport.STDIO,
        command=["python", "server.py"],
        env={"MCP_TOKEN": "${MCP_TOKEN}"},
    )
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="MCP_TOKEN"):
        resolve_artifact_refs(spec)

    monkeypatch.setenv("MCP_TOKEN", "local-only")
    resolved = resolve_artifact_refs(spec)
    assert resolved.env == {"MCP_TOKEN": "local-only"}
    assert resolve_artifact_values({"token": "${MCP_TOKEN}"}) == {
        "token": "local-only"
    }
