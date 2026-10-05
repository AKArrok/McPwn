"""SARIF 2.1.0 export for McPwn results.

Emits `findings.sarif` next to findings.md so results drop into GitHub
Code Scanning / any SARIF consumer without a bespoke parser. Two rule
families share one run:

- dynamic findings (vuln_class + confidence, from signal-grounded probes)
- static screening hits (zero-LLM surface rules + supplychain vetting)

Level mapping: critical->error, high->error, medium->warning,
low/info->note. Confidence is carried in properties (SARIF has no native
notion) so downstream triage can sort.
"""

from __future__ import annotations

from typing import Any

from mcp_redteam import __version__
from mcp_redteam.contracts import ScanResult
from mcp_redteam.security import redact_scan_result

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule(vuln_class: str) -> dict[str, Any]:
    return {
        "id": vuln_class,
        "name": vuln_class,
        "shortDescription": {"text": f"MCP vulnerability class: {vuln_class}"},
        "defaultConfiguration": {"level": "error"},
        "properties": {"kind": "dynamic"},
    }


def _static_rule(rule_id: str, summary: str, level: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": summary},
        "defaultConfiguration": {"level": level},
        "properties": {"kind": "static"},
    }


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Render one ScanResult as a SARIF 2.1.0 log."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in result.findings:
        if f.vuln_class.value not in rules:
            rules[f.vuln_class.value] = _rule(f.vuln_class.value)
        results.append(
            {
                "ruleId": f.vuln_class.value,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {
                    "text": f"{f.title}: {f.summary} "
                    f"(confidence {f.confidence:.2f}, signals: "
                    f"{', '.join(s.signal_id for s in f.signals) or 'n/a'})"
                },
                "properties": {
                    "confidence": f.confidence,
                    "finding_id": f.finding_id,
                    "severity": f.severity,
                    "target": f.target,
                    "kind": "dynamic",
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {"name": f.target, "fullyQualifiedName": f"{f.vuln_class.value}:{f.target}"}
                        ]
                    }
                ],
            }
        )

    for h in result.static_hits:
        if h.rule_id not in rules:
            rules[h.rule_id] = _static_rule(h.rule_id, h.summary, _LEVEL.get(h.severity, "note"))
        results.append(
            {
                "ruleId": h.rule_id,
                "level": _LEVEL.get(h.severity, "note"),
                "message": {"text": f"{h.summary} [matched: {h.matched_text}]"},
                "properties": {
                    "subject": h.subject,
                    "where": h.where,
                    "severity": h.severity,
                    "kind": "static",
                },
                "locations": [
                    {"logicalLocations": [{"name": h.subject, "fullyQualifiedName": f"{h.where}:{h.subject}"}]}
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "McPwn",
                        "informationUri": "https://github.com/AKArrok/McPwn",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "run_id": result.run_id,
                    "target": result.sse_url,
                    "transport": result.transport,
                },
            }
        ],
    }


def write_sarif(result: ScanResult, out_dir) -> Any:
    """Write <out_dir>/findings.sarif; returns the path."""
    from pathlib import Path

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    import json

    path = out_dir / "findings.sarif"
    path.write_text(
        json.dumps(to_sarif(redact_scan_result(result)), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path
