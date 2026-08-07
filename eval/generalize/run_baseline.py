"""Stage-1 baseline: hardcoded planner + signal library only, NO llm_points.

Expected on delegate-mcp: 0 findings. recon mis-classifies read_vault /
list_vaults / grant_access as path_traversal (name/desc regex), the attacker
burns budget on traversal shapes, and the signal library has zero coverage of
the grant-scope flaw (see preflight_signals.py). Expected: findings=0.

Usage:
    python eval/generalize/run_baseline.py [--port N]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.generalize._fresh_server import fresh_delegate_server
from mcp_redteam.orchestrator.runner import scan


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=20005)
    args = parser.parse_args()

    out_dir = Path("runs/generalize_baseline")
    async with fresh_delegate_server(args.port) as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=False,
        )
    print(
        f"stop={result.stop_reason} traces={len(result.traces)} "
        f"findings={len(result.findings)}"
    )
    for f in result.findings:
        print(" ", f.vuln_class, f.target, f.confidence, "|", f.summary[:180])
        for c in f.poc_call_sequence:
            print("    poc:", c.kind, c.name, c.args)


if __name__ == "__main__":
    asyncio.run(main())
