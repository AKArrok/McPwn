"""Stage-2 run: LLM decision points (hypothesis gen / retrospective / evidence judge).

Expected on vault-mcp: >=1 finding, where the Stage-1 baseline (hardcoded
planner + signal library only) found 0. planner_mode stays "hardcoded" - the
LLM is NOT used for permutation (M3 lesson); it is used only at the three
decision points. See README.md for the three-stage protocol.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from mcp_redteam.orchestrator.runner import scan


async def main() -> None:
    result = await scan(
        sse_url="http://127.0.0.1:9205/sse",
        out_dir=Path("runs/unknown_shape_llm"),
        max_tokens=30000,
        wall_seconds=300,
        planner_mode="hardcoded",
        llm_points=True,
        llm_hyp_budget=-1,  # unknown-shape: LLM 假设需自由探索
    )
    print(
        f"findings={len(result.findings)} stop={result.stop_reason} "
        f"attacker_tokens={result.attacker_tokens} judge_tokens={result.judge_tokens}"
    )
    for f in result.findings:
        print(" ", f.vuln_class, f.target, f.confidence, "|", f.summary[:180])
        for c in f.poc_call_sequence:
            print("    poc:", c.kind, c.name, c.args)


if __name__ == "__main__":
    asyncio.run(main())
