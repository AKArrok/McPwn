"""Mine historical scan results for enumeration bursts (zero-cost pre-study).

Question (subagent_exp PLAN §7.4 follow-up): do REAL targets in our run
history contain shapes where in-loop delegation (dispatch_probe) would have
been the rational strategy? Proxy: "enumeration bursts" - long runs of
consecutive same-tool calls inside one trace.

Definitions (locked before looking at results):
- burst tier-1: >= 6 consecutive ``call_tool`` entries with the same tool name
  in one trace's attack_calls.
- burst tier-2 (strict parameter sweep): >= 8 consecutive same-tool calls whose
  args share the same key set (same schema face, only values differ).
- token position is approximated as index/len(calls) * trace_tokens (per-call
  token usage is not recorded); documented approximation, same bias both sides.
- a burst is "post-evidence" when its trace matches a finding of the scan
  (by vuln_class+target) - i.e. the sweep happened after evidence already
  existed, the cheapest delegation win (converge instead of keep grinding).

Usage:
    python scripts/mine_enumeration_bursts.py [--min-burst 6] [--out runs/analysis/burst_mining.json]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def find_bursts(calls: list[dict], min_len: int) -> list[dict]:
    """Maximal runs of >= min_len consecutive same-name call_tool entries."""
    bursts = []
    i = 0
    n = len(calls)
    while i < n:
        c = calls[i]
        if c.get("kind") != "call_tool" or not c.get("name"):
            i += 1
            continue
        j = i
        while j + 1 < n and calls[j + 1].get("kind") == "call_tool" and calls[j + 1].get("name") == c["name"]:
            j += 1
        run_len = j - i + 1
        if run_len >= min_len:
            bursts.append({"tool": c["name"], "start": i, "len": run_len, "end": j})
        i = j + 1
    return bursts


def same_key_set(calls: list[dict], burst: dict) -> bool:
    """Tier-2 check: every call in the burst has the same arg key set."""
    keysets = {frozenset((calls[k].get("args") or {}).keys()) for k in range(burst["start"], burst["end"] + 1)}
    return len(keysets) == 1


def analyze_scan(path: Path, min_burst: int) -> dict:
    result = json.loads(path.read_text(encoding="utf-8"))
    findings = {(f.get("vuln_class"), f.get("target")) for f in result.get("findings") or []}
    out = {
        "run": str(path.relative_to(REPO / "runs")),
        "target": (result.get("sse_url") or "")[:60],
        "traces": [],
    }
    for t in result.get("traces") or []:
        calls = t.get("attack_calls") or []
        if not calls:
            continue
        trace_tokens = (t.get("tokens_in") or 0) + (t.get("tokens_out") or 0)
        is_finding_trace = (t.get("vuln_class"), t.get("target")) in findings
        bursts = []
        for b in find_bursts(calls, min_burst):
            bursts.append(
                {
                    "tool": b["tool"],
                    "len": b["len"],
                    "start": b["start"],
                    "token_pos_approx": round(b["start"] / max(1, len(calls)) * trace_tokens),
                    "strict_sweep": same_key_set(calls, b),
                    "post_evidence": is_finding_trace,
                }
            )
        if bursts:
            out["traces"].append(
                {
                    "vuln_class": t.get("vuln_class"),
                    "target": t.get("target"),
                    "n_calls": len(calls),
                    "trace_tokens": trace_tokens,
                    "is_finding_trace": is_finding_trace,
                    "bursts": bursts,
                }
            )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-burst", type=int, default=6)
    parser.add_argument("--out", default="runs/analysis/burst_mining.json")
    args = parser.parse_args()

    results = []
    for path in sorted((REPO / "runs").rglob("scan_result.json")):
        try:
            results.append(analyze_scan(path, args.min_burst))
        except Exception as exc:  # noqa: BLE001 - unreadable legacy artifacts must not kill the sweep
            results.append({"run": str(path), "error": f"{type(exc).__name__}: {exc}"})

    by_family: dict[str, list] = defaultdict(list)
    for r in results:
        if "error" in r:
            continue
        family = r["run"].split("\\")[0].split("/")[0]
        by_family[family].append(r)

    summary = {}
    for family, scans in sorted(by_family.items()):
        scans_with_bursts = [s for s in scans if s["traces"]]
        bursts = [b for s in scans_with_bursts for t in s["traces"] for b in t["bursts"]]
        strict = [b for b in bursts if b["strict_sweep"]]
        post = [b for b in bursts if b["post_evidence"]]
        summary[family] = {
            "scans": len(scans),
            "scans_with_bursts": len(scans_with_bursts),
            "bursts": len(bursts),
            "strict_sweeps": len(strict),
            "post_evidence_bursts": len(post),
            "max_burst_len": max((b["len"] for b in bursts), default=0),
            "burst_tools": sorted({b["tool"] for b in bursts})[:8],
        }

    out_path = REPO / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"min_burst": args.min_burst, "summary": summary, "detail": results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"{'family':<28} {'scans':>5} {'w/burst':>7} {'bursts':>6} {'strict':>6} {'post-ev':>7} {'max_len':>7}")
    for family, s in summary.items():
        print(
            f"{family:<28} {s['scans']:>5} {s['scans_with_bursts']:>7} {s['bursts']:>6} "
            f"{s['strict_sweeps']:>6} {s['post_evidence_bursts']:>7} {s['max_burst_len']:>7}"
        )
    print(f"\nsaved: {out_path}")


if __name__ == "__main__":
    main()
