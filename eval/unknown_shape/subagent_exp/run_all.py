"""Driver for the dispatch_probe subagent A/B experiment (PLAN.md §3-§5).

Runs arms serially (each run = one fresh subprocess = one fresh vault server),
collects per-run scan_result.json, computes secondary metrics, and writes a
summary + verdict table.

Usage:
    python eval/unknown_shape/subagent_exp/run_all.py --budget 20000 \
        --arms BASE,SUB --n 3 --tag main
    python eval/unknown_shape/subagent_exp/run_all.py --budget 20000 \
        --arms BASE --n 1 --tag smoke --out runs/subagent_exp_smoke
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RUN_ONE = HERE / "run_one.py"
BASE_PORT = 19500


def tokens_to_first_finding(scan_result_path: Path) -> int | None:
    """Cumulative trace tokens through the trace that first matched a finding.

    Matches by (vuln_class, target). Trace tokens exclude the pre-trace
    hypothesis-generation spend (identical config both arms). None when no
    finding or no trace matches.
    """
    if not scan_result_path.exists():
        return None
    result = json.loads(scan_result_path.read_text(encoding="utf-8"))
    findings = result.get("findings") or []
    traces = result.get("traces") or []
    if not findings or not traces:
        return None
    best = None
    for f in findings:
        cum = 0
        for trace in traces:
            cum += (trace.get("tokens_in") or 0) + (trace.get("tokens_out") or 0)
            if (
                trace.get("vuln_class") == f.get("vuln_class")
                and trace.get("target") == f.get("target")
            ):
                if best is None or cum < best:
                    best = cum
                break
    return best


def run_one(arm: str, budget: int, port: int, out_dir: Path, target: str = "vault") -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(RUN_ONE),
        "--arm", arm,
        "--budget", str(budget),
        "--port", str(port),
        "--out", str(out_dir),
        "--target", target,
    ]
    print(f"[run_all] spawn {' '.join(cmd)}", flush=True)
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, encoding="utf-8")
    wall = time.perf_counter() - started
    tail = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not tail:
        print(f"[run_all] FAILED rc={proc.returncode}\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
        return {"arm": arm, "out": str(out_dir), "error": f"rc={proc.returncode}", "driver_wall": round(wall, 1)}
    summary = json.loads(tail[-1])
    summary["driver_wall"] = round(wall, 1)
    summary["ttff_tokens"] = tokens_to_first_finding(out_dir / "scan_result.json")
    # Scout observability: the child's INFO log (stderr) carries the scout's
    # probe digest / candidate count, which never lands in scan_result.json
    # (scout probes are deliberately kept out of traces).
    scout_log = [
        ln.strip() for ln in (proc.stderr or "").splitlines()
        if "scout" in ln.lower() and "httpx" not in ln
    ]
    if scout_log:
        summary["scout_log"] = scout_log[-8:]
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budget", type=int, required=True)
    parser.add_argument("--arms", default="BASE,SUB")
    parser.add_argument("--n", type=int, default=3)
    parser.add_argument("--tag", default="main")
    parser.add_argument("--out", default="runs/subagent_exp")
    parser.add_argument("--target", default="vault", choices=["vault", "wide"])
    args = parser.parse_args()

    arms = [a.strip().upper() for a in args.arms.split(",") if a.strip()]
    root = Path(args.out) / args.tag
    root.mkdir(parents=True, exist_ok=True)

    results = []
    port = BASE_PORT
    for arm in arms:
        for i in range(args.n):
            port += 1
            res = run_one(arm, args.budget, port, root / f"{arm}_run{i}", args.target)
            results.append(res)
            print("[run_all] " + json.dumps(res, ensure_ascii=False), flush=True)

    hits = {arm: 0 for arm in arms}
    for res in results:
        if res.get("findings", 0) >= 1 and not res.get("error"):
            hits[res["arm"]] += 1

    report = {
        "budget": args.budget,
        "n": args.n,
        "tag": args.tag,
        "hits": hits,
        "results": results,
    }
    (root / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[run_all] hits per arm: {hits}  (report: {root / 'summary.json'})", flush=True)


if __name__ == "__main__":
    main()
