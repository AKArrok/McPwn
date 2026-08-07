"""One ablation run, spawned per-run by run_ablation.py.

The override env is injected by the parent process:
    MCPWN_AGENTS_OVERRIDE_DIR / MCPWN_CARDS_OVERRIDE_DIR  (STRIPPED arm)
    or absent                                             (HINTED arm = production prompts)

Usage:
    python eval/unknown_shape/ablation/run_one.py --arm A --port 19305 \
        --out runs/unknown_shape_ablation/A_run0 [--seed N]

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

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.unknown_shape._fresh_server import fresh_vault_server
from mcp_redteam.orchestrator.runner import scan


async def one(port: int, seed: int | None, out_dir: Path) -> dict:
    async with fresh_vault_server(port) as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=True,
            seed=seed,
            llm_hyp_budget=-1,  # unknown-shape 消融: LLM 假设需自由探索
        )
    return {
        "findings": len(result.findings),
        "detail": [
            {
                "vuln_class": f.vuln_class.value,
                "target": f.target,
                "confidence": round(f.confidence, 2),
            }
            for f in result.findings
        ],
        "seed": result.seed,
        "stop_reason": result.stop_reason,
        "attacker_tokens": result.attacker_tokens,
        "judge_tokens": result.judge_tokens,
        "attack_messages_sha1": result.attack_messages_sha1,
        "evidence_judge_model": result.evidence_judge_model,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", required=True, choices=["A", "B", "C", "D"])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = asyncio.run(one(args.port, args.seed, out_dir))
    summary["arm"] = args.arm
    summary["port"] = args.port
    summary["agents_override"] = os.environ.get("MCPWN_AGENTS_OVERRIDE_DIR", "")
    summary["cards_override"] = os.environ.get("MCPWN_CARDS_OVERRIDE_DIR", "")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
