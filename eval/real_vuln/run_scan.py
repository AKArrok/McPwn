"""Scan the VULNERABLE filesystem server (positive target, official 0.6.2).

Criterion: >=1 finding (path_traversal via allowlist escape, detected through
the evidence judge on a zero-deterministic-signal trace). Runs both standard
and llm_points configurations.

Usage:
    $env:MCPWN_FS_INDEX_OLD = "<server-filesystem@0.6.2 dist/index.js>"
    python eval/real_vuln/run_scan.py [--std-only] [--llm-only] [--n N]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_ABLATION = ROOT / "eval" / "unknown_shape" / "ablation"
os.environ["MCPWN_AGENTS_OVERRIDE_DIR"] = str(_ABLATION / "prompts")
os.environ["MCPWN_CARDS_OVERRIDE_DIR"] = str(ROOT / "eval" / "generalize" / "cards")

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.real_vuln._fresh import fresh_fs_vuln_target
from mcp_redteam.orchestrator.runner import scan


async def one(out_dir: Path, llm: bool, seed: int | None) -> tuple[int, list, str]:
    async with fresh_fs_vuln_target() as sse_url:
        result = await scan(
            sse_url=sse_url, out_dir=out_dir, max_tokens=30000, wall_seconds=300,
            planner_mode="hardcoded", llm_points=llm, seed=seed,
            llm_hyp_budget=-1,  # recon is correct here (path_traversal) but
            # hypotheses must not be starved either; -1 keeps legacy behaviour
        )
    detail = [(f.vuln_class.value, f.target, round(f.confidence, 2)) for f in result.findings]
    return len(result.findings), detail, result.stop_reason


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--std-only", action="store_true")
    parser.add_argument("--llm-only", action="store_true")
    parser.add_argument("--n", type=int, default=1)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if not args.llm_only:
        for i in range(args.n):
            f, d, stop = await one(ROOT / f"runs/realvuln_fs_std_{i}", llm=False, seed=args.seed)
            ok = f >= 1
            print(f"std run{i}: findings={f} stop={stop} expect>=1 {'PASS' if ok else 'FAIL'} "
                  f"[{', '.join(f'{c}@{t} {cf}' for c, t, cf in d)}]")
    if not args.std_only:
        for i in range(args.n):
            f, d, stop = await one(ROOT / f"runs/realvuln_fs_llm_{i}", llm=True, seed=args.seed)
            ok = f >= 1
            print(f"llm run{i}: findings={f} stop={stop} expect>=1 {'PASS' if ok else 'FAIL'} "
                  f"[{', '.join(f'{c}@{t} {cf}' for c, t, cf in d)}]")


if __name__ == "__main__":
    asyncio.run(main())
