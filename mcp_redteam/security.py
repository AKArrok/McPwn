"""Redaction helpers for persisted McPwn artifacts.

The live scan keeps the real target configuration in memory so the MCP client
can connect.  Anything written to disk must use this module first.  Target
environment variables and headers are represented as references (for example
``${MCPWN_HEADER_AUTHORIZATION}``) so a replay script can be repaired locally
without copying credentials into a report or a committed artifact.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mcp_redteam.contracts import AttackTrace, Finding, ScanResult, TargetSpec

REDACTED = "[REDACTED]"
_SECRET_VALUE = re.compile(
    r"(?i)(?:bearer\s+|basic\s+|(?:sk|pk|rk)-)[A-Za-z0-9._~+/=-]{8,}"
)
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:api[_-]?key|authorization|cookie|password|passwd|secret|token)\b"
    r"\s*[\"']?\s*[:=]\s*)([\"']?)([^\s,;\"'}]+)"
)
_REFERENCE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:api[_-]?key|authorization|cookie|password|passwd|secret|token)"
)


def redact_text(value: str, *, secrets: set[str] | None = None) -> str:
    """Remove known secret values and common credential-shaped substrings."""
    result = value
    for secret in sorted(secrets or (), key=len, reverse=True):
        if len(secret) >= 4:
            result = result.replace(secret, REDACTED)
    result = _SECRET_VALUE.sub(REDACTED, result)
    result = _KEY_VALUE.sub(lambda match: f"{match.group(1)}{REDACTED}", result)
    return result


def redact_url(url: str) -> str:
    """Keep URL identity while removing userinfo and query parameter values."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    if not parts.scheme or not parts.netloc:
        return redact_text(url)

    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = urlencode(
        [(key, REDACTED) for key, _ in parse_qsl(parts.query, keep_blank_values=True)]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def header_reference(name: str) -> str:
    """Return a shell-friendly environment variable name for one header."""
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", name).upper().strip("_") or "VALUE"
    return f"MCPWN_HEADER_{normalized}"


def target_secret_values(spec: TargetSpec) -> set[str]:
    """Return values that must be removed from persisted traces."""
    values = set(spec.env.values()) if spec.env else set()
    values.update(spec.headers.values() if spec.headers else ())
    return {value for value in values if value}


def target_artifact_references(spec: TargetSpec) -> dict[str, str]:
    """Map live credential values to safe replay references."""
    refs: dict[str, str] = {}
    for key, value in (spec.env or {}).items():
        if value:
            refs[value] = f"${{{key}}}"
    for key, value in (spec.headers or {}).items():
        if value:
            refs[value] = f"${{{header_reference(key)}}}"
    return refs


def redact_target_spec(spec: TargetSpec) -> dict[str, Any]:
    """Serialize a target spec without persisting environment/header values."""
    data = spec.model_dump(mode="json")
    if data.get("url"):
        data["url"] = redact_url(data["url"])
    if spec.env:
        data["env"] = {key: f"${{{key}}}" for key in spec.env}
    if spec.headers:
        data["headers"] = {key: f"${{{header_reference(key)}}}" for key in spec.headers}
    references = target_artifact_references(spec)
    data["command"] = [
        references.get(part, redact_text(part, secrets=target_secret_values(spec)))
        for part in spec.command or []
    ] or None
    return data


_REFERENCE_FIELDS = frozenset({
    "args",
    "attacker_messages",
    "command",
    "env",
    "headers",
    "poc_call_sequence",
})


def _redact_object(
    value: Any,
    *,
    secrets: set[str],
    key: str | None = None,
    references: dict[str, str] | None = None,
    allow_references: bool = False,
) -> Any:
    refs = references or {}
    if isinstance(value, str):
        if allow_references and value in refs:
            return refs[value]
        if key and _SENSITIVE_KEY.search(key):
            return REDACTED
        return redact_text(value, secrets=secrets)
    if isinstance(value, list):
        return [
            _redact_object(
                item,
                secrets=secrets,
                references=refs,
                allow_references=allow_references,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            item_key: _redact_object(
                item,
                secrets=secrets,
                key=str(item_key),
                references=refs,
                allow_references=(
                    allow_references or str(item_key) in _REFERENCE_FIELDS
                ),
            )
            for item_key, item in value.items()
        }
    return value


def redact_trace(
    trace: AttackTrace,
    *,
    secrets: set[str] | None = None,
    references: dict[str, str] | None = None,
) -> AttackTrace:
    """Return a schema-valid, redacted copy suitable for a trace file."""
    payload = _redact_object(
        trace.model_dump(mode="json"), secrets=secrets or set(), references=references
    )
    return AttackTrace.model_validate(payload)


def redact_finding(
    finding: Finding,
    *,
    secrets: set[str] | None = None,
    references: dict[str, str] | None = None,
) -> Finding:
    """Return a schema-valid, redacted copy suitable for reports and PoCs."""
    payload = _redact_object(
        finding.model_dump(mode="json"), secrets=secrets or set(), references=references
    )
    return Finding.model_validate(payload)


def redact_scan_result(result: ScanResult) -> ScanResult:
    """Return the disk-safe view of a live scan result."""
    spec = TargetSpec.model_validate(result.target_spec) if result.target_spec else None
    secrets = target_secret_values(spec) if spec else set()
    references = target_artifact_references(spec) if spec else {}
    payload = _redact_object(
        result.model_dump(mode="json"), secrets=secrets, references=references
    )
    if spec:
        payload["sse_url"] = redact_text(spec.display, secrets=secrets)
        if spec.url:
            payload["sse_url"] = redact_url(spec.url)
        payload["target_spec"] = redact_target_spec(spec)
    payload["traces"] = [
        redact_trace(trace, secrets=secrets, references=references).model_dump(mode="json")
        for trace in result.traces
    ]
    payload["findings"] = [
        redact_finding(
            finding, secrets=secrets, references=references
        ).model_dump(mode="json")
        for finding in result.findings
    ]
    return ScanResult.model_validate(payload)


def _resolve_reference(value: str, label: str) -> str:
    match = _REFERENCE.fullmatch(value)
    if not match:
        return value
    env_name = match.group(1)
    resolved = os.environ.get(env_name)
    if resolved is None:
        raise RuntimeError(
            f"replay requires environment variable {env_name} for {label}"
        )
    return resolved


def resolve_artifact_values(value: Any) -> Any:
    """Resolve safe references inside generated PoC arguments."""
    if isinstance(value, str):
        return _resolve_reference(value, "argument")
    if isinstance(value, list):
        return [resolve_artifact_values(item) for item in value]
    if isinstance(value, dict):
        return {key: resolve_artifact_values(item) for key, item in value.items()}
    return value


def resolve_artifact_refs(spec: TargetSpec) -> TargetSpec:
    """Resolve target env and header references for a local replay."""
    env = {
        key: _resolve_reference(value, f"env:{key}")
        for key, value in (spec.env or {}).items()
    }
    headers = {
        key: _resolve_reference(value, f"header:{key}")
        for key, value in (spec.headers or {}).items()
    }
    return spec.model_copy(update={"env": env or None, "headers": headers or None})
