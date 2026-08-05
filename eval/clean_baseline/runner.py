"""Run `mcpwn scan` against the 3 clean FastMCP servers and report findings.

Output: ``<out_dir>/eval_report.md`` with per-variant findings count,
list of tool names + descriptions seen by the agent, and a cross-server
FPR verdict. Also writes per-port ``findings.md`` (expected empty).

Usage:
    python -m eval.clean_baseline.runner -o runs/clean_baseline_v1
"""

from __future__ import annotations

import asyncio
import socket
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the repo root. cli.py does the same so that
# `mcpwn scan` and `mcpwn eval dvmcp run` see the API keys; this
# runner is invoked directly so we must mirror the load.
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent.parent / ".env")


from mcp_redteam.orchestrator.runner import scan
from mcp_redteam.report.findings import write_findings

REPO = Path(__file__).resolve().parent.parent.parent
SERVER_MODULE = "eval.clean_baseline.servers"

VARIANTS: list[dict] = [
    {
        "kind": "noop",
        "port": 9101,
        "rationale": "empty description; tests description-regex isn't fooled by missing metadata",
    },
    {
        "kind": "summarize",
        "port": 9102,
        "rationale": "description has LLM-style instructions; tests indirect-injection doesn't fire on benign LLM-shaped text",
    },
    {
        "kind": "file_list",
        "port": 9103,
        "rationale": "path-shaped arg with strict server-side cap; tests path-traversal doesn't fire on safe file-listing",
    },
]


def _port_listening(port: int, timeout: float = 10.0) -> bool:
    """Poll TCP connect to localhost:<port> until accepted or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


async def _run_one(variant: dict, out_dir: Path) -> dict:
    """Start one server, run scan, tear down. Return a result dict."""
    port = variant["port"]
    port_dir = out_dir / f"port_{variant['kind']}_{port}"
    port_dir.mkdir(parents=True, exist_ok=True)

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", SERVER_MODULE,
        "--kind", variant["kind"], "--port", str(port),
        cwd=str(REPO),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        if not _port_listening(port):
            stderr = proc.stderr.read(500) if proc.stderr else b""
            raise RuntimeError(
                f"server {variant['kind']} did not listen on :{port} within 10s; stderr={stderr!r}"
            )

        sse_url = f"http://127.0.0.1:{port}/sse"
        print(f"[clean] scanning {sse_url} ({variant['kind']}) ...")
        result = await scan(
            sse_url=sse_url,
            out_dir=port_dir,
            max_tokens=30000,
            wall_seconds=240,
        )
        write_findings(result, port_dir)
        return {
            "kind": variant["kind"],
            "port": port,
            "rationale": variant["rationale"],
            "tools_seen": result.tools_seen,
            "resources_seen": result.resources_seen,
            "findings_count": len(result.findings),
            "findings": [
                {
                    "vuln_class": f.vuln_class.value,
                    "confidence": f.confidence,
                    "signals": [s.signal_id for s in f.signals],
                    "title": f.title,
                }
                for f in result.findings
            ],
            "traces_count": len(result.traces),
            "stop_reason": result.stop_reason,
            "wall_seconds": result.wall_seconds,
        }
    finally:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=5)


def _write_report(results: list[dict], out_dir: Path) -> Path:
    total_findings = sum(r["findings_count"] for r in results)
    n = len(results)
    fpr = total_findings / n if n else 0.0
    verdict = "PASS" if total_findings == 0 else "FAIL"

    lines: list[str] = []
    lines.append("# Clean Baseline FPR Report")
    lines.append("")
    lines.append(f"- **variants**: {n}")
    lines.append(f"- **total_findings**: {total_findings}")
    lines.append(f"- **cross_server_fpr**: {fpr:.2f}")
    lines.append(f"- **verdict**: {verdict}  (expected 0 findings on all variants)")
    lines.append("")
    lines.append("## Per-variant summary")
    lines.append("")
    lines.append("| kind | port | findings | tools_seen | stop_reason | wall_s |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        lines.append(
            f"| {r['kind']} | {r['port']} | {r['findings_count']} | "
            f"{', '.join(r['tools_seen']) or '(none)'} | {r['stop_reason']} | "
            f"{r['wall_seconds']:.1f} |"
        )
    lines.append("")
    lines.append("## Per-variant rationale + tools")
    lines.append("")
    for r in results:
        lines.append(f"### {r['kind']} (port {r['port']})")
        lines.append("")
        lines.append(f"**Rationale**: {r['rationale']}")
        lines.append("")
        if r["findings"]:
            lines.append("**Findings (UNEXPECTED - investigate):**")
            lines.append("")
            for f in r["findings"]:
                lines.append(
                    f"- `{f['vuln_class']}` (conf {f['confidence']:.2f}, "
                    f"signals {f['signals']}): {f['title']}"
                )
            lines.append("")
        else:
            lines.append("**Findings**: 0 (as expected)")
            lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "Each variant is designed to LOOK like a known vuln class shape "
        "(empty description, LLM-style prompt description, path-shaped arg) "
        "but to be provably safe. A non-zero finding here means either:"
    )
    lines.append("")
    lines.append(
        "1. **detector bug** - a regex fires on description / arg *name* "
        "without grounding in actual call output. Fix the detector (separate PR)."
    )
    lines.append(
        "2. **recon/planner bug** - the agent attempts an actually dangerous "
        "operation (e.g. path traversal that escapes the hard cap). Fix the server."
    )
    lines.append(
        "3. **legit false positive** - the detector fires on a benign "
        "pattern that we didn't anticipate. Widen the negation or accept the FPR."
    )
    lines.append("")
    lines.append(
        "Cross-server FPR=0 is the only condition under which DVMCP FPR=0 "
        "is meaningful. See `eval/dvmcp/AGENTS.md` for the DVMCP-internal "
        "cross-vuln-class FPR (which is a different question)."
    )

    report_path = out_dir / "eval_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


async def run_all(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    for v in VARIANTS:
        try:
            r = await _run_one(v, out_dir)
        except Exception as exc:  # noqa: BLE001 - keep going on per-variant failure
            print(f"[clean] ERROR {v['kind']}: {type(exc).__name__}: {exc}")
            r = {
                "kind": v["kind"],
                "port": v["port"],
                "rationale": v["rationale"],
                "tools_seen": [],
                "resources_seen": [],
                "findings_count": -1,
                "findings": [],
                "traces_count": 0,
                "stop_reason": f"error: {type(exc).__name__}",
                "wall_seconds": 0.0,
            }
        results.append(r)
    return _write_report(results, out_dir)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-o", "--out", default="runs/clean_baseline_v1",
        help="output directory for eval_report.md and per-port findings",
    )
    args = parser.parse_args()
    out = Path(args.out)
    report = asyncio.run(run_all(out))
    print(f"wrote {report}")


if __name__ == "__main__":
    main()
