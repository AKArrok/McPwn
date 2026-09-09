"""Report renderer for ScanResult -> findings.md + findings.json + poc/."""

from mcp_redteam.report.findings import write_findings, write_findings_json

__all__ = ["write_findings", "write_findings_json"]
