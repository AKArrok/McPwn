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
import json
from pathlib import Path

import yaml

from mcp_redteam.contracts import Finding, PlannerDecision, ScanResult
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


def _write_report(rows: list[dict], report_path: Path, planner_mode: str = "hardcoded") -> None:
    passed = sum(1 for r in rows if r["status"] == "PASS")
    total = len(rows)

    lines: list[str] = [
        "# Real-World Harness Report (excel-mcp-server CVE-2026-40576)",
        "",
        f"planner: `{planner_mode}`",
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


def _write_planner_decisions(decisions: list[PlannerDecision], out_dir: Path) -> Path:
    """Write the M3 planner_decisions.json contract (mirrors eval/dvmcp/runner.py).

    One file at ``out_dir`` root covering every target; entries are
    distinguished by the target's ``port``. Written in llm mode so an A/B run
    can be audited for which planner source actually produced each decision.
    """
    path = out_dir / "planner_decisions.json"
    path.write_text(
        json.dumps(
            {"decisions": [d.model_dump() for d in decisions]},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


async def run_all(
    out_dir: Path,
    max_tokens: int = 30000,
    wall_seconds: int = 240,
    planner_mode: str = "hardcoded",
) -> Path:
    """Scan every target in targets.yaml and write ``out_dir/eval_report.md``."""
    if planner_mode not in {"hardcoded", "llm"}:
        raise ValueError(f"planner_mode must be hardcoded|llm, got {planner_mode!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    decisions: list[PlannerDecision] = []
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
                planner_mode=planner_mode,
                decisions=decisions,
            )
            write_findings(result, out_dir / name)
            row["findings"] = len(result.findings)
            row["status"] = "PASS" if _judge(target, result) else "FAIL"
        except Exception as exc:  # noqa: BLE001 - keep going on per-target failure
            print(f"[realworld] ERROR {target['sse_url']}: {type(exc).__name__}: {exc}")
            row["error"] = f"{type(exc).__name__}: {exc}"
            row["status"] = "FAIL"
        rows.append(row)

    if planner_mode == "llm":
        _write_planner_decisions(decisions, out_dir)

    report_path = out_dir / "eval_report.md"
    _write_report(rows, report_path, planner_mode)
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
    parser.add_argument(
        "--planner", default="hardcoded", choices=["hardcoded", "llm"],
        help="Planner mode: hardcoded (score order) or llm (LLM decision).",
    )
    args = parser.parse_args()
    report = asyncio.run(run_all(Path(args.out), args.max_tokens, args.wall_seconds, args.planner))
    print(f"wrote {report}")


if __name__ == "__main__":
    main()