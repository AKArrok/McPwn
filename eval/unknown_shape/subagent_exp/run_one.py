"""One subagent A/B run, spawned per-run by run_all.py.

Arm is chosen by --arm BEFORE heavy imports: executor.py reads
``MCPWN_ATTACKER_SUBAGENT`` at module import, and each run is a fresh
subprocess, so setting the env here is run-scoped (same pattern as the
prompt-ablation harness in ../ablation/).

Usage:
    python eval/unknown_shape/subagent_exp/run_one.py --arm BASE --budget 20000 \
        --port 19501 --out runs/subagent_exp/BASE_run0

Prints one compact JSON line to stdout (parent parses it). scan_result.json
is also written under --out by scan() itself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=["BASE", "SUB", "FORCE", "SCOUT"])
    parser.add_argument("--budget", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--target", default="vault", choices=["vault", "wide"])
    args = parser.parse_args()

    # FORCE is an exploratory diagnostic arm (PLAN.md §7): delegation is a
    # hard requirement, not a recommendation. SCOUT (scout_exp/PLAN.md) is
    # structured delegation at the hypothesis decision point: the FRAMEWORK
    # spawns a live-probing scout, so adoption doesn't depend on model choice.
    if args.arm == "SUB":
        os.environ["MCPWN_ATTACKER_SUBAGENT"] = "1"
    elif args.arm == "FORCE":
        os.environ["MCPWN_ATTACKER_SUBAGENT"] = "force"
    elif args.arm == "SCOUT":
        os.environ["MCPWN_HYP_SCOUT"] = "1"

    import logging

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    summary = asyncio.run(one(args.arm, args.budget, args.port, Path(args.out), args.target))
    print(json.dumps(summary, ensure_ascii=False))


async def one(arm: str, budget: int, port: int, out_dir: Path, target: str = "vault") -> dict:
    # Imported here (post-env-flag) so this module stays import-safe and the
    # executor module reads MCPWN_ATTACKER_SUBAGENT after run-scoped setup.
    from eval.unknown_shape._fresh_server import fresh_vault_server, fresh_wide_server
    from mcp_redteam.orchestrator.runner import scan

    fresh = fresh_wide_server(port) if target == "wide" else fresh_vault_server(port)
    async with fresh as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=budget,
            wall_seconds=420,
            planner_mode="hardcoded",
            llm_points=True,
            seed=None,  # DeepSeek does not support seed; drift via sha1
            llm_hyp_budget=-1,  # unknown-shape protocol: free LLM-hyp exploration
            trace_token_cap=-1,  # same protocol: unbounded single-trace spend
        )

    dispatches = 0
    subagent_calls = 0
    scout_traces = 0
    scout_findings = 0
    finding_keys = {(f.vuln_class.value, f.target) for f in result.findings}
    for trace in result.traces:
        first_user = ""
        for msg in trace.attacker_messages:
            if msg.get("role") == "user" and not first_user:
                first_user = str(msg.get("content", ""))
            if msg.get("role") == "tool" and str(msg.get("content", "")).startswith(
                "[subagent done"
            ):
                dispatches += 1
                first = str(msg.get("content", "")).splitlines()[0]
                digits = "".join(ch for ch in first if ch.isdigit())
                if digits:
                    subagent_calls += int(digits)
        # Scout-origin attribution: execute_one renders candidate.reason
        # (incl. the "[llm-scout]" tag) into the trace's first user message.
        if "[llm-scout]" in first_user:
            scout_traces += 1
            if (trace.vuln_class.value, trace.target) in finding_keys:
                scout_findings += 1

    return {
        "arm": arm,
        "port": port,
        "target": target,
        "findings": len(result.findings),
        "detail": [
            {
                "vuln_class": f.vuln_class.value,
                "target": f.target,
                "confidence": round(f.confidence, 2),
            }
            for f in result.findings
        ],
        "stop_reason": result.stop_reason,
        "attacker_tokens": result.attacker_tokens,
        "judge_tokens": result.judge_tokens,
        "wall_seconds": round(result.wall_seconds, 1),
        "traces": len(result.traces),
        "attack_calls": sum(len(t.attack_calls) for t in result.traces),
        "dispatches": dispatches,
        "subagent_calls": subagent_calls,
        "scout_traces": scout_traces,
        "scout_findings": scout_findings,
        "attack_messages_sha1": result.attack_messages_sha1,
        "evidence_judge_model": result.evidence_judge_model,
        "subagent_mode": os.environ.get("MCPWN_ATTACKER_SUBAGENT", "") or "off",
    }


if __name__ == "__main__":
    main()
