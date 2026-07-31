"""DVMCP regression runner: scan all ports, compute recall / FPR / poc_replay_pass_rate.

Output: eval_report.md under out_dir. Also writes findings.md per port.
"""

from __future__ import annotations

import random
from pathlib import Path

import yaml

from mcp_redteam.contracts import Finding, McpCall, ScanResult
from mcp_redteam.orchestrator.runner import scan
from mcp_redteam.report.findings import write_findings
from mcp_redteam.signals.detectors import run_all_signals
from mcp_redteam.targets.mcp_client import McpSession


def _load_expected() -> dict:
    path = Path(__file__).with_name("expected.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _acceptable_classes(entry: dict) -> set[str]:
    classes = {entry["primary_class"]}
    classes.update(entry.get("also_accept", []))
    return classes


async def _replay_poc(sse_url: str, finding: Finding) -> bool:
    """Replay a finding's poc_call_sequence; pass if any original signal_id refires."""
    if not finding.poc_call_sequence:
        return False
    original_ids = {s.signal_id for s in finding.signals}
    if not original_ids:
        return False
    try:
        async with McpSession(sse_url) as session:
            replayed: list[McpCall] = []
            for call in finding.poc_call_sequence:
                if call.kind == "read_resource":
                    c = await session.read_resource(call.name or "")
                elif call.kind == "call_tool":
                    c = await session.call_tool(call.name or "", call.args or {})
                else:
                    continue
                replayed.append(c)
        replay_signals = run_all_signals(replayed, "")
        replay_ids = {s.signal_id for s in replay_signals}
        return bool(original_ids & replay_ids)
    except Exception:
        return False


async def run_all(
    ports: list[int],
    out_dir: Path,
    max_tokens: int = 30000,
    wall_seconds: int = 240,
) -> Path:
    expected_data = _load_expected()
    expected_by_port: dict[int, dict] = {
        e["port"]: e for e in expected_data["expected"]
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict[int, ScanResult] = {}

    for port in ports:
        port_dir = out_dir / f"port_{port}"
        sse_url = f"http://127.0.0.1:{port}/sse"
        print(f"[eval] scanning {sse_url} ...")
        try:
            result = await scan(
                sse_url=sse_url,
                out_dir=port_dir,
                max_tokens=max_tokens,
                wall_seconds=wall_seconds,
            )
            write_findings(result, port_dir)
        except Exception as exc:
            print(f"[eval] ERROR {sse_url}: {type(exc).__name__}: {exc}")
            continue
        results[port] = result

    # ── compute metrics ──────────────────────────────────────────────────
    hit_count = 0
    total_findings = 0
    false_positives = 0
    for port, result in results.items():
        expected = expected_by_port.get(port)
        if not expected:
            continue
        acceptable = _acceptable_classes(expected)
        port_hit = False
        for f in result.findings:
            total_findings += 1
            if f.vuln_class.value in acceptable:
                port_hit = True
            else:
                false_positives += 1
        if port_hit:
            hit_count += 1

    n_ports = len(ports)
    recall = hit_count / n_ports if n_ports else 0.0
    fpr = false_positives / total_findings if total_findings else 0.0
    avg_findings = total_findings / n_ports if n_ports else 0.0

    # ── poc replay ───────────────────────────────────────────────────────
    all_findings: list[tuple[int, Finding]] = [
        (port, f) for port, result in results.items() for f in result.findings
    ]
    sample = all_findings if len(all_findings) <= 5 else random.sample(all_findings, 5)
    replay_passes = 0
    replay_total = len(sample)
    for port, f in sample:
        sse_url = f"http://127.0.0.1:{port}/sse"
        ok = await _replay_poc(sse_url, f)
        if ok:
            replay_passes += 1
    poc_replay_pass_rate = replay_passes / replay_total if replay_total else 0.0

    # ── write eval_report.md ─────────────────────────────────────────────
    lines: list[str] = []
    lines.append("# DVMCP Regression Report")
    lines.append("")
    lines.append(f"- **recall**: {recall:.2f} ({hit_count}/{n_ports})")
    lines.append(f"- **false_positive_rate**: {fpr:.2f}")
    lines.append(f"- **avg_findings_per_port**: {avg_findings:.1f}")
    lines.append(
        f"- **poc_replay_pass_rate**: {poc_replay_pass_rate:.2f} "
        f"({replay_passes}/{replay_total} sampled)"
    )
    lines.append("")
    lines.append("## Per-port summary")
    lines.append("")
    lines.append("| port | name | expected | hit? | findings |")
    lines.append("|---|---|---|---|---|")
    for port, result in results.items():
        expected = expected_by_port.get(port)
        if not expected:
            continue
        acceptable = _acceptable_classes(expected)
        port_hit = any(
            f.vuln_class.value in acceptable for f in result.findings
        )
        lines.append(
            f"| {port} | {expected['name']} | {expected['primary_class']} | "
            f"{'YES' if port_hit else 'no'} | {len(result.findings)} |"
        )
    lines.append("")

    report_path = out_dir / "eval_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
