"""Render ScanResult -> findings.md + poc/*.py.

Layout under out_dir/:
    findings.md         human-readable summary
    poc/{finding_id}.py replayable script per finding
    traces/*.json       full AttackTrace dumps (written by verifier)
    scan_result.json    complete ScanResult
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_redteam.contracts import Finding, McpCall, ScanResult


def _fmt_call(call: McpCall) -> str:
    if call.kind == "call_tool":
        args_repr = _fmt_args_for_replay(call.args or {})
        return f"call_tool({call.name!r}, {args_repr})  # {call.elapsed_ms}ms"
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
        return f"{raw!r}  # (unparsed LLM args, replay may need manual edit)"
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


def _poc_script(f: Finding, sse_url: str) -> str:
    """Emit a standalone replay script for one finding."""
    steps_repr: list[str] = []
    for c in f.poc_call_sequence:
        if c.kind == "call_tool":
            args_literal = _fmt_args_for_replay(c.args or {})
            steps_repr.append(
                f'        call = await session.call_tool({c.name!r}, '
                f'{args_literal}); '
                f'print({c.name!r}, "=>", call.result_text[:400])'
            )
        elif c.kind == "read_resource":
            steps_repr.append(
                f'        call = await session.read_resource({c.name!r}); '
                f'print({c.name!r}, "=>", call.result_text[:400])'
            )
    body = "\n".join(steps_repr) or "        # (no attack calls recorded)"
    return f'''"""Replay script for finding {f.finding_id}.

Auto-generated. Verifies the same signal fires against {sse_url}.

Compliance: this PoC targets an intentionally-vulnerable MCP server used for
red-team research. Do NOT run against production or unauthorised systems.
"""

import asyncio

from mcp_redteam.targets.mcp_client import McpSession


async def main() -> None:
    async with McpSession({sse_url!r}) as session:
{body}


if __name__ == "__main__":
    asyncio.run(main())
'''


def write_findings(result: ScanResult, out_dir: Path) -> Path:
    """Write findings.md + poc/*.py under out_dir. Return findings.md path."""
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
            script_path.write_text(_poc_script(f, result.sse_url), encoding="utf-8")

    md_path = out_dir / "findings.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path
