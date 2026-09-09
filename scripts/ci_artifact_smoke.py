"""Smoke-test the installed ``mcpwn ci`` command against synthetic artifacts.

The full scanner is intentionally not run here: this script verifies the
deterministic artifact gate that CI depends on. It is safe for GitHub Actions
because it needs no MCP server, Docker, network, or LLM credentials.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp_redteam.report.findings import FINDINGS_JSON_SCHEMA_VERSION


def _artifact(*, findings: list[dict] | None = None) -> dict:
    findings = findings or []
    return {
        "schema_version": FINDINGS_JSON_SCHEMA_VERSION,
        "run_id": "ci-artifact-smoke",
        "target": "stdio: synthetic",
        "transport": "stdio",
        "stop_reason": "completed",
        "counts": {
            "tools_seen": 0,
            "resources_seen": 0,
            "traces": 0,
            "findings": len(findings),
            "static_hits": 0,
        },
        "findings": findings,
        "static_hits": [],
    }


def _finding(severity: str) -> dict:
    return {
        "finding_id": "F-ci-smoke",
        "vuln_class": "auth_bypass",
        "target": "synthetic",
        "hypothesis_class": "auth_bypass",
        "evidence_class": "auth_bypass",
        "severity": severity,
        "confidence": 0.75,
        "title": "synthetic high finding",
        "summary": "synthetic artifact used to verify the CI gate",
        "signals": [
            {
                "signal_id": "unauthenticated_success",
                "severity": severity,
                "matched_text": "sha256:synthetic",
                "source_call_index": 0,
            }
        ],
        "poc_call_sequence": [
            {
                "kind": "call_tool",
                "name": "synthetic",
                "args": {},
                "result_text": "sha256:synthetic",
                "elapsed_ms": 1,
            }
        ],
        "remediation_hint": "",
        "trace_ref": "",
    }


def _run_gate(path: Path) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "mcp_redteam.cli", "ci", str(path), "--fail-on", "high"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    return completed.returncode


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="mcpwn-ci-smoke-") as raw_tmp:
        tmp = Path(raw_tmp)
        clean = tmp / "clean"
        clean.mkdir()
        (clean / "findings.json").write_text(
            json.dumps(_artifact(), ensure_ascii=False),
            encoding="utf-8",
        )
        risky = tmp / "risky"
        risky.mkdir()
        (risky / "findings.json").write_text(
            json.dumps(_artifact(findings=[_finding("high")]), ensure_ascii=False),
            encoding="utf-8",
        )

        clean_rc = _run_gate(clean)
        risky_rc = _run_gate(risky)
        if clean_rc != 0:
            print(f"expected clean artifact to pass with rc=0, got rc={clean_rc}")
            return 1
        if risky_rc != 1:
            print(f"expected risky artifact to fail with rc=1, got rc={risky_rc}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
