"""Real-world harness runner: recall (positive) + precision (negative) gates.

Scans every target in ``targets.yaml`` via
``mcp_redteam.orchestrator.runner.scan`` and writes a per-target PASS/FAIL
table to ``<out_dir>/eval_report.md``:

- positive target (excel-0.1.7): PASS iff any finding carries at least one
  expected signal id (recall gate).
- negative target (excel-0.1.8): PASS iff NO finding carries any signal id
  starting with ``sandbox_escape`` (precision gate).

Usage:
    python -m eval.realworld.runner -o runs/realworld
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import yaml

from mcp_redteam.contracts import Finding, ScanResult
from mcp_redteam.orchestrator.runner import scan
from mcp_redteam.report.findings import write_findings

_SANDBOX_ESCAPE_PREFIX = "sandbox_escape"


def _load_targets() -> list[dict]:
    path = Path(__file__).with_name("targets.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["targets"]


def _finding_signal_ids(finding: Finding) -> set[str]:
    """Signal ids attached to a finding (which evidence actually fired)."""
    return {s.signal_id for s in finding.signals}


def _judge(target: dict, result: ScanResult) -> bool:
    """Return True when the target's gate passes (hit semantics as eval/dvmcp)."""
    if target["role"] == "positive":
        expected = set(target.get("expected_signals") or [])
        return any(expected & _finding_signal_ids(f) for f in result.findings)
    # negative: precision gate - zero sandbox_escape* signals allowed.
    return not any(
        s.signal_id.startswith(_SANDBOX_ESCAPE_PREFIX)
        for f in result.findings
        for s in f.signals
    )


def _expected_label(target: dict) -> str:
    if target["role"] == "positive":
        return ", ".join(target.get("expected_signals") or [])
    return "no sandbox_escape"


def _write_report(rows: list[dict], report_path: Path) -> None:
    passed = sum(1 for r in rows if r["status"] == "PASS")
    total = len(rows)

    lines: list[str] = [
        "# Real-World Harness Report (excel-mcp-server CVE-2026-40576)",
        "",
        "| name | version | role | expected | PASS/FAIL | findings |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['name']} | {r['version']} | {r['role']} | {r['expected']} | "
            f"{r['status']} | {r['findings']} |"
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **PASS**: {passed}/{total}")
    errors = [r for r in rows if r["error"]]
    if errors:
        lines.append("")
        lines.append("## Errors")
        lines.append("")
        for r in errors:
            lines.append(f"- **{r['name']}**: `{r['error']}`")
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")


async def run_all(
    out_dir: Path,
    max_tokens: int = 30000,
    wall_seconds: int = 240,
) -> Path:
    """Scan every target in targets.yaml and write ``out_dir/eval_report.md``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for target in _load_targets():
        name = target["name"]
        print(f"[realworld] scanning {target['sse_url']} ({name}) ...")
        row = {
            "name": name,
            "version": target["version"],
            "role": target["role"],
            "expected": _expected_label(target),
            "status": "FAIL",
            "findings": -1,
            "error": None,
        }
        try:
            result = await scan(
                sse_url=target["sse_url"],
                out_dir=out_dir / name,
                max_tokens=max_tokens,
                wall_seconds=wall_seconds,
                sandbox_root=target["sandbox_root"],
            )
            write_findings(result, out_dir / name)
            row["findings"] = len(result.findings)
            row["status"] = "PASS" if _judge(target, result) else "FAIL"
        except Exception as exc:  # noqa: BLE001 - keep going on per-target failure
            print(f"[realworld] ERROR {target['sse_url']}: {type(exc).__name__}: {exc}")
            row["error"] = f"{type(exc).__name__}: {exc}"
            row["status"] = "FAIL"
        rows.append(row)

    report_path = out_dir / "eval_report.md"
    _write_report(rows, report_path)
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-o", "--out", default="runs/realworld",
        help="output directory for eval_report.md and per-target findings",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=30000,
        help="attacker token budget per target",
    )
    parser.add_argument(
        "--wall-seconds", type=int, default=240,
        help="wall-clock budget per target",
    )
    args = parser.parse_args()
    report = asyncio.run(run_all(Path(args.out), args.max_tokens, args.wall_seconds))
    print(f"wrote {report}")


if __name__ == "__main__":
    main()