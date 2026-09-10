"""Render ScanResult -> findings.md + findings.json + poc/*.py.

Layout under out_dir/:
    findings.md         human-readable summary
    findings.json       stable machine-readable findings list
    poc/{finding_id}.py replayable script per finding
    traces/*.json       full AttackTrace dumps (written by verifier)
    scan_result.json    complete ScanResult
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_redteam.contracts import Finding, McpCall, ScanResult
from mcp_redteam.security import redact_scan_result

FINDINGS_JSON_SCHEMA_VERSION = 1


def _fmt_call(call: McpCall) -> str:
    if call.kind == "call_tool":
        args_repr = _fmt_args_for_replay(call.args or {})
        note = (
            "  # unparsed LLM args; replay may need manual edit"
            if list((call.args or {}).keys()) == ["_raw"]
            else ""
        )
        return f"call_tool({call.name!r}, {args_repr})  # {call.elapsed_ms}ms{note}"
    if call.kind == "read_resource":
        return f"read_resource({call.name!r})  # {call.elapsed_ms}ms"
    return f"# {call.kind}  {call.elapsed_ms}ms"


def _fmt_args_for_replay(args: dict[str, Any]) -> str:
    """Render tool args as Python-source-safe literal for the PoC script.

    Handles the ``{"_raw": "<invalid json>"}`` fallback that ``executor.py``
    inserts when the attacker LLM emits arguments that don't parse as JSON:
    a naive ``repr`` would produce a call the server can't accept. Prefer the
    raw string so the replay approximates what happened on the wire.
    """
    if list(args.keys()) == ["_raw"]:
        raw = args["_raw"]
        return repr(raw)
    # Use json.dumps for stable, quote-safe output; fall back to repr for
    # non-JSON-serialisable values (rare in practice).
    try:
        return json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(args)


def _finding_section(f: Finding) -> str:
    lines: list[str] = []
    lines.append(f"## {f.title}")
    lines.append("")
    lines.append(f"- **id**: `{f.finding_id}`")
    lines.append(f"- **vuln_class**: `{f.vuln_class.value}`")
    lines.append(f"- **target**: `{f.target}`")
    lines.append(f"- **severity**: **{f.severity}**")
    lines.append(f"- **confidence**: `{f.confidence:.2f}`")
    lines.append("")
    lines.append(f"**Summary**: {f.summary}")
    lines.append("")

    lines.append("**Evidence signals**:")
    for s in f.signals:
        lines.append(f"- `{s.signal_id}` ({s.severity}): `{s.matched_text}`")
    lines.append("")

    if f.poc_call_sequence:
        lines.append("**Repro (minimal call sequence)**:")
        lines.append("```python")
        for c in f.poc_call_sequence:
            lines.append(_fmt_call(c))
        lines.append("```")
        lines.append("")

    if f.remediation_hint:
        lines.append(f"**Remediation hint**: {f.remediation_hint}")
        lines.append("")

    if f.trace_ref:
        lines.append(f"*Full trace*: `{f.trace_ref}`")
        lines.append("")

    return "\n".join(lines)


def _poc_script(f: Finding, result: ScanResult) -> str:
    """Emit a standalone replay script for one finding.

    The connection is embedded as a ``TargetSpec`` JSON blob so the script
    replays over the SAME transport the scan used - including stdio targets
    (command + env), not just HTTP endpoints.
    """
    steps_repr: list[str] = []
    for c in f.poc_call_sequence:
        if c.kind == "call_tool":
            args_literal = _fmt_args_for_replay(c.args or {})
            steps_repr.append(
                f'        call = await session.call_tool({c.name!r}, '
                f'resolve_artifact_values({args_literal})); '
                f'print({c.name!r}, "=>", call.result_text[:400])'
            )
        elif c.kind == "read_resource":
            steps_repr.append(
                f'        call = await session.read_resource({c.name!r}); '
                f'print({c.name!r}, "=>", call.result_text[:400])'
            )
    body = "\n".join(steps_repr) or "        # (no attack calls recorded)"
    if result.target_spec:
        target_block = (
            "import json\n\n"
            "from mcp_redteam.contracts import TargetSpec\n"
            "from mcp_redteam.security import (\n"
            "    resolve_artifact_refs,\n"
            "    resolve_artifact_values,\n"
            ")\n"
            "from mcp_redteam.targets.mcp_client import McpSession\n\n\n"
            f"TARGET = TargetSpec.model_validate_json(r'''"
            f"{json.dumps(result.target_spec, ensure_ascii=False)}''')"
        )
        session_expr = "McpSession(resolve_artifact_refs(TARGET))"
    else:  # legacy scan_result.json without target_spec
        target_block = (
            "from mcp_redteam.targets.mcp_client import McpSession\n\n\n"
            f"TARGET = {result.sse_url!r}"
        )
        session_expr = "McpSession(TARGET)"
    return f'''"""Replay script for finding {f.finding_id}.

Auto-generated. Verifies the same signal fires against {result.sse_url}.

Compliance: this PoC targets an intentionally-vulnerable MCP server used for
red-team research. Do NOT run against production or unauthorised systems.
"""

import asyncio

{target_block}


async def main() -> None:
    async with {session_expr} as session:
{body}


if __name__ == "__main__":
    asyncio.run(main())
'''


def write_findings(result: ScanResult, out_dir: Path) -> Path:
    """Write findings.md + findings.json + poc/*.py. Return findings.md path."""
    result = redact_scan_result(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    poc_dir = out_dir / "poc"
    poc_dir.mkdir(exist_ok=True)

    lines: list[str] = []
    lines.append(f"# McPwn scan — {result.sse_url}")
    lines.append("")
    lines.append(f"- **run_id**: `{result.run_id}`")
    lines.append(f"- **started**: {result.started_at}")
    lines.append(f"- **wall_seconds**: {result.wall_seconds:.1f}")
    lines.append(f"- **total_tokens**: {result.total_tokens}")
    lines.append(f"- **stop_reason**: `{result.stop_reason}`")
    lines.append(f"- **tools_seen**: {len(result.tools_seen)}")
    lines.append(f"- **resources_seen**: {len(result.resources_seen)}")
    lines.append(f"- **traces**: {len(result.traces)}")
    lines.append(f"- **findings**: **{len(result.findings)}**")
    lines.append("")

    if result.static_hits:
        lines.append("---")
        lines.append("")
        lines.append("## 静态预筛 (zero-LLM, 扫描前命中)")
        lines.append("")
        lines.append("| 严重级 | 规则 | 对象 | 位置 | 摘要 |")
        lines.append("|---|---|---|---|---|")
        for h in result.static_hits:
            lines.append(
                f"| {h.severity} | `{h.rule_id}` | {h.subject} | {h.where} | {h.summary} |"
            )
        lines.append("")

    if not result.findings:
        lines.append("_No findings above confidence threshold._")
    else:
        lines.append("---")
        lines.append("")
        for f in result.findings:
            lines.append(_finding_section(f))
            lines.append("---")
            lines.append("")
            script_path = poc_dir / f"{f.finding_id}.py"
            script_path.write_text(_poc_script(f, result), encoding="utf-8")

    md_path = out_dir / "findings.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    write_findings_json(result, out_dir)
    from mcp_redteam.report.sarif import write_sarif

    write_sarif(result, out_dir)
    return md_path


def write_findings_json(result: ScanResult, out_dir: Path) -> Path:
    """Write the lightweight machine-readable findings artifact."""
    result = redact_scan_result(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": FINDINGS_JSON_SCHEMA_VERSION,
        "run_id": result.run_id,
        "target": result.sse_url,
        "transport": result.transport,
        "stop_reason": getattr(result.stop_reason, "value", result.stop_reason),
        "counts": {
            "tools_seen": len(result.tools_seen),
            "resources_seen": len(result.resources_seen),
            "traces": len(result.traces),
            "findings": len(result.findings),
            "static_hits": len(result.static_hits),
        },
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "static_hits": [h.model_dump(mode="json") for h in result.static_hits],
    }
    path = out_dir / "findings.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
