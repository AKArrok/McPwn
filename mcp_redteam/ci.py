"""CI gate for an existing McPwn findings.json artifact.

This module intentionally does not run scans. It only evaluates the stable
machine-readable report produced by ``mcpwn scan`` so CI systems can make a
repeatable pass/fail decision from an already persisted artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_redteam.artifacts import ArtifactValidationError, validate_findings_artifact
from mcp_redteam.contracts import SEVERITY_ORDER
from mcp_redteam.report.findings import FINDINGS_JSON_SCHEMA_VERSION

SEVERITY_RANK: dict[str, int] = {severity: i for i, severity in enumerate(SEVERITY_ORDER)}
COMPLETED_STOP_REASON = "completed"


class CiArtifactError(ValueError):
    """Raised when a findings.json artifact is missing or malformed."""


@dataclass(frozen=True)
class CiVerdict:
    """Machine-stable CI decision for a findings.json artifact."""

    exit_code: int
    status: str
    threshold: str
    blocking_count: int
    max_severity: str | None = None
    stop_reason: str | None = None
    reason: str = ""


def resolve_findings_json(path: Path) -> Path:
    """Resolve either a scan output directory or a direct findings.json path."""
    artifact = path / "findings.json" if path.is_dir() else path
    if not artifact.exists():
        raise CiArtifactError(f"{artifact} does not exist")
    if not artifact.is_file():
        raise CiArtifactError(f"{artifact} is not a file")
    return artifact


def load_findings_artifact(path: Path) -> dict[str, Any]:
    """Load and minimally validate a findings.json artifact."""
    artifact = resolve_findings_json(path)
    try:
        data = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CiArtifactError(f"{artifact} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CiArtifactError(f"{artifact} must contain a JSON object")
    version = data.get("schema_version")
    if version != FINDINGS_JSON_SCHEMA_VERSION:
        raise CiArtifactError(
            f"{artifact} has unsupported schema_version={version!r}; "
            f"expected {FINDINGS_JSON_SCHEMA_VERSION}"
        )
    try:
        validate_findings_artifact(data)
    except ArtifactValidationError as exc:
        raise CiArtifactError(f"{artifact} does not match findings schema: {exc}") from exc
    return data


def evaluate_ci_artifact(
    data: dict[str, Any],
    *,
    fail_on: str = "high",
    include_static: bool = True,
    allow_inconclusive: bool = False,
) -> CiVerdict:
    """Return a CI verdict for one loaded findings.json object.

    Exit codes:
      0 = completed scan, no item at or above threshold
      1 = at least one finding/static hit is at or above threshold
      2 = invalid CI threshold or malformed artifact shape
      3 = scan did not complete, unless ``allow_inconclusive`` is true
    """
    if fail_on not in SEVERITY_RANK:
        return CiVerdict(
            exit_code=2,
            status="invalid",
            threshold=fail_on,
            blocking_count=0,
            reason=f"unknown severity threshold {fail_on!r}",
        )

    stop_reason = data.get("stop_reason")
    if stop_reason != COMPLETED_STOP_REASON and not allow_inconclusive:
        return CiVerdict(
            exit_code=3,
            status="inconclusive",
            threshold=fail_on,
            blocking_count=0,
            stop_reason=str(stop_reason) if stop_reason is not None else None,
            reason=f"scan stop_reason is {stop_reason!r}, not 'completed'",
        )

    try:
        items = list(_iter_severity_items(data, include_static=include_static))
    except CiArtifactError as exc:
        return CiVerdict(
            exit_code=2,
            status="invalid",
            threshold=fail_on,
            blocking_count=0,
            stop_reason=str(stop_reason) if stop_reason is not None else None,
            reason=str(exc),
        )

    threshold_rank = SEVERITY_RANK[fail_on]
    blocking = [item for item in items if SEVERITY_RANK[item["severity"]] >= threshold_rank]
    max_severity = _max_severity(item["severity"] for item in items)
    if blocking:
        return CiVerdict(
            exit_code=1,
            status="fail",
            threshold=fail_on,
            blocking_count=len(blocking),
            max_severity=max_severity,
            stop_reason=str(stop_reason) if stop_reason is not None else None,
            reason=f"{len(blocking)} item(s) at or above {fail_on}",
        )
    return CiVerdict(
        exit_code=0,
        status="pass",
        threshold=fail_on,
        blocking_count=0,
        max_severity=max_severity,
        stop_reason=str(stop_reason) if stop_reason is not None else None,
        reason=f"no findings/static hits at or above {fail_on}",
    )


def _iter_severity_items(
    data: dict[str, Any], *, include_static: bool
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for field in ("findings", "static_hits"):
        if field == "static_hits" and not include_static:
            continue
        raw_items = data.get(field, [])
        if not isinstance(raw_items, list):
            raise CiArtifactError(f"{field} must be a list")
        for index, raw in enumerate(raw_items):
            if not isinstance(raw, dict):
                raise CiArtifactError(f"{field}[{index}] must be an object")
            severity = raw.get("severity")
            if severity not in SEVERITY_RANK:
                raise CiArtifactError(f"{field}[{index}] has unknown severity {severity!r}")
            items.append({"kind": field, "severity": str(severity)})
    return items


def _max_severity(severities: Any) -> str | None:
    best: str | None = None
    best_rank = -1
    for severity in severities:
        rank = SEVERITY_RANK.get(severity, -1)
        if rank > best_rank:
            best = severity
            best_rank = rank
    return best
