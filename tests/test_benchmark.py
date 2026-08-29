"""Benchmark report tests (pure rendering, no LLM / no server).

Covers the expectation grammar, the per-target markdown scorecard, and the
manifest matching used by `mcpwn scan` to attach a verdict section.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_redteam.contracts import (
    AttackTrace,
    EvidenceSignal,
    Finding,
    ScanResult,
    VulnClass,
)
from mcp_redteam.report.benchmark import (
    ManifestVerdict,
    build_benchmark,
    expect_ok,
    write_benchmark,
)


def _finding(cls: VulnClass, conf: float = 0.75) -> Finding:
    return Finding(
        finding_id=Finding.compute_id(cls, "tool_x", "sig_demo"),
        vuln_class=cls,
        target="tool_x",
        severity="high",
        confidence=conf,
        title=f"demo {cls.value}",
        summary="demo",
        signals=[EvidenceSignal(
            signal_id="sig_demo", severity="high",
            matched_text="demo evidence",
            source_call_index=0,
        )],
    )


def _trace(cls: VulnClass) -> AttackTrace:
    return AttackTrace(
        vuln_class=cls,
        target="tool_x",
        strategy_card_slug=cls.value,  # validator: slug must equal class value
    )


def _result(
    findings: list[Finding] | None = None,
    classes: list[VulnClass] | None = None,
) -> ScanResult:
    return ScanResult(
        run_id="scan-test",
        sse_url="stdio: uvx demo-server",
        transport="stdio",
        started_at="2026-08-29T00:00:00Z",
        wall_seconds=94.0,
        attacker_tokens=28000,
        judge_tokens=500,
        traces=[_trace(c) for c in (classes or [])],
        findings=findings or [],
        stop_reason="completed",
        attacker_model="deepseek-test",
    )


# ── expectation grammar ─────────────────────────────────────────────────────


def test_expect_ok_grammar():
    assert expect_ok(">=1", 1) and expect_ok(">=1", 3)
    assert not expect_ok(">=1", 0)
    assert expect_ok("0", 0)
    assert not expect_ok("0", 2)
    assert expect_ok("info", 0) and expect_ok("info", 5)


def test_expect_ok_rejects_unknown():
    with pytest.raises(ValueError, match="unknown expectation"):
        expect_ok(">=2", 1)


# ── rendering ───────────────────────────────────────────────────────────────


def test_benchmark_sections_and_coverage():
    md = build_benchmark(_result(
        findings=[_finding(VulnClass.SSRF)],
        classes=[VulnClass.SSRF, VulnClass.COMMAND_INJECTION],
    ), max_tokens=30000, wall_seconds=300)
    for section in ("# Benchmark — stdio: uvx demo-server",
                    "## 结果概览", "## 漏洞类覆盖", "## 预算与效率"):
        assert section in md
    # all 8 taxonomy rows are always present
    for cls in VulnClass:
        assert cls.value in md
    # finding + efficiency rows
    assert "ssrf_internal" not in md  # signals summarised by id, not here
    assert "tokens / finding" in md
    assert "28,000 / 30,000 (93%)" in md
    assert "deepseek-test" in md


def test_benchmark_without_findings_omits_findings_section():
    md = build_benchmark(_result())
    assert "## Findings" not in md
    assert "tokens / finding | —" in md


def test_benchmark_verdict_pass_fail_info():
    entry = ManifestVerdict(name="demo", baseline_expect=">=1", llm_expect="0")
    hit = _result(findings=[_finding(VulnClass.SSRF)])
    empty = _result()

    assert "✅ PASS" in build_benchmark(hit, entry=entry, mode="std")
    assert "❌ FAIL" in build_benchmark(hit, entry=entry, mode="llm")  # llm_expect=0
    assert "❌ FAIL" in build_benchmark(empty, entry=entry, mode="std")

    info_entry = ManifestVerdict(name="demo", baseline_expect="info")
    assert "INFO (仅记录)" in build_benchmark(hit, entry=info_entry, mode="std")


def test_write_benchmark_creates_file(tmp_path: Path):
    path = write_benchmark(
        _result(findings=[_finding(VulnClass.SSRF)]), tmp_path,
        entry=ManifestVerdict(name="demo", baseline_expect=">=1"),
        max_tokens=30000,
    )
    assert path == tmp_path / "benchmark.md"
    assert path.read_text(encoding="utf-8").startswith("# Benchmark —")


# ── manifest matching (scan auto-attach) ────────────────────────────────────


def test_match_manifest_entry_by_command(monkeypatch):
    from mcp_redteam import cli

    class _FakeEntry:
        name = "fake-stdio"
        label = "fake"
        baseline_expect = ">=1"
        llm_expect = "info"
        prove = False
        prove_script = None

        def spec(self):
            from mcp_redteam.contracts import TargetSpec

            return TargetSpec.parse(command="uvx fake-server")

    monkeypatch.setattr("eval.targets.run.load_manifest", lambda: [_FakeEntry()])
    from mcp_redteam.contracts import TargetSpec

    verdict = cli._match_manifest_entry(TargetSpec.parse(command="uvx fake-server"))
    assert verdict is not None and verdict.name == "fake-stdio"

    miss = cli._match_manifest_entry(TargetSpec.parse("http://127.0.0.1:1/sse"))
    assert miss is None


def test_match_manifest_entry_tolerates_missing_manifest(monkeypatch):
    import importlib

    from mcp_redteam import cli
    from mcp_redteam.contracts import TargetSpec

    run_mod = importlib.import_module("eval.targets.run")
    def _boom():
        raise RuntimeError("no manifest")
    monkeypatch.setattr(run_mod, "load_manifest", _boom)
    assert cli._match_manifest_entry(TargetSpec.parse("http://127.0.0.1:1/sse")) is None
