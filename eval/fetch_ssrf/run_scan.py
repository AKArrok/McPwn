"""Real-world SSRF scan against the official mcp-server-fetch (positive).

Runs BOTH scan configurations on the real fetch target:
  1. standard scan  (hardcoded planner + signal library only)
  2. + llm_points   (three LLM decision points, stripped prompts/cards like the
                     unknown-shape experiments)

Expected: >=1 SSRF finding in each. The recon classifier already tags `fetch`
as SSRF (name matches the fetch/http/url regex), and the deterministic signal
``ssrf_internal_service`` fires when fetch returns the intranet banner —
so this validates the SSRF class end-to-end on a REAL server (the 
"SSRF 真靶验证" gap from HANDOFF_NEXT), not on a self-built fixture.

Usage:
    python eval/fetch_ssrf/run_scan.py [--std-only] [--seed N]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Same stripped (类级框架) prompt/card overrides as the generalize experiment:
# no target-specific answer strings, keeps the class-level framework.
_ABLATION = ROOT / "eval" / "unknown_shape" / "ablation"
_PROMPTS = _ABLATION / "prompts"
_CARDS = ROOT / "eval" / "generalize" / "cards"
os.environ["MCPWN_AGENTS_OVERRIDE_DIR"] = str(_PROMPTS)
os.environ["MCPWN_CARDS_OVERRIDE_DIR"] = str(_CARDS)

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.fetch_ssrf._fresh import fresh_fetch_target
from mcp_redteam.orchestrator.runner import scan


async def one(
    out_dir: Path, llm_points: bool, seed: int | None
) -> tuple[int, list[tuple[str, str, float]], str]:
    async with fresh_fetch_target() as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=llm_points,
            seed=seed,
        )
    detail = [(f.vuln_class.value, f.target, round(f.confidence, 2)) for f in result.findings]
    return len(result.findings), detail, result.stop_reason


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--std-only", action="store_true", help="skip the llm_points run")
    parser.add_argument("--llm-only", action="store_true", help="skip the standard run")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if not args.llm_only:
        findings, detail, stop = await one(Path("runs/fetch_ssrf_std"), llm_points=False, seed=args.seed)
        print(f"[std]      findings={findings} stop={stop} {detail}")
    if not args.std_only:
        findings2, detail2, stop2 = await one(Path("runs/fetch_ssrf_llm"), llm_points=True, seed=args.seed)
        print(f"[llm+std]  findings={findings2} stop={stop2} {detail2}")


if __name__ == "__main__":
    asyncio.run(main())
