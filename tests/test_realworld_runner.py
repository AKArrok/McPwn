"""Unit tests for eval/realworld runner gates (no docker/LLM required)."""

from __future__ import annotations

from eval.realworld.runner import _judge
from mcp_redteam.contracts import (
    EvidenceSignal,
    Finding,
    ScanResult,
    VulnClass,
)


def _finding(signal_ids: list[str]) -> Finding:
    return Finding(
        finding_id="F-test",
        vuln_class=VulnClass.PATH_TRAVERSAL,
        target="excel-0.1.7",
        evidence_class=VulnClass.PATH_TRAVERSAL,
        severity="high",
        confidence=0.8,
        title="t",
        summary="s",
        signals=[
            EvidenceSignal(signal_id=sid, severity="high", matched_text="x")
            for sid in signal_ids
        ],
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        run_id="r",
        sse_url="http://x/sse",
        started_at="t",
        wall_seconds=1.0,
        findings=findings,
        stop_reason="completed",
    )


def test_positive_gate_hit():
    target = {
        "role": "positive",
        "expected_signals": ["sandbox_escape_write", "sandbox_escape_read"],
    }
    assert _judge(target, _result([_finding(["sandbox_escape_write"])])) is True


def test_positive_gate_miss():
    target = {"role": "positive", "expected_signals": ["sandbox_escape_write"]}
    assert _judge(target, _result([_finding(["leaks_etc_passwd"])])) is False


def test_negative_gate_no_sandbox_signals():
    target = {"role": "negative", "expected_signals": []}
    assert _judge(target, _result([_finding(["leaks_etc_passwd"])])) is True


def test_negative_gate_any_sandbox_signal_fails():
    target = {"role": "negative", "expected_signals": []}
    assert _judge(target, _result([_finding(["sandbox_escape_traversal"])])) is False


def test_negative_gate_multiple_findings_any_sandbox_fails():
    target = {"role": "negative", "expected_signals": []}
    result = _result([_finding(["leaks_etc_passwd"]), _finding(["sandbox_escape_write"])])
    assert _judge(target, result) is False