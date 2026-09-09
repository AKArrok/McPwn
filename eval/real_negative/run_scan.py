"""Negative (FPR) scans on two real-world FIXED servers.

Targets (official, latest, all CVE fixes applied):
  - git (mcp-server-git 2026.7.10): repo_path validated against --repository
  - filesystem (@modelcontextprotocol/server-filesystem 2026.7.10): allowlist
    enforced (sibling-dir and `..` escapes denied - verified)

Criterion (FPR control): every scan must produce 0 findings - a real
unpatched-looking-but-fixed server must not false-positive under the standard
planner nor under llm_points (which also exercises the evidence judge on
zero-signal traces: it must stay honest and not invent findings).

Usage:
    $env:MCPWN_GIT_VENV = "<venv with mcp-server-git>"
    $env:MCPWN_FS_INDEX = "<path to server-filesystem dist/index.js>"
    python eval/real_negative/run_scan.py [--llm-only] [--std-only]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Same stripped (类级框架) overrides as the other experiments.
_ABLATION = ROOT / "eval" / "unknown_shape" / "ablation"
os.environ["MCPWN_AGENTS_OVERRIDE_DIR"] = str(_ABLATION / "prompts")
os.environ["MCPWN_CARDS_OVERRIDE_DIR"] = str(ROOT / "eval" / "generalize" / "cards")

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.real_negative._fresh import fresh_fs_target, fresh_git_target
from mcp_redteam.orchestrator.runner import scan


async def one(
    fresh, out_dir: Path, llm: bool, seed: int | None
) -> tuple[int, list[tuple[str, str, float]], str]:
    async with fresh() as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=llm,
            seed=seed,
            llm_hyp_budget=-1,  # hypothesis leads must not be starved on negatives
        )
    detail = [(f.vuln_class.value, f.target, round(f.confidence, 2)) for f in result.findings]
    return len(result.findings), detail, result.stop_reason


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--std-only", action="store_true")
    parser.add_argument("--llm-only", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    targets = [("git", fresh_git_target), ("filesystem", fresh_fs_target)]
    for name, fresh in targets:
        print(f"== {name} (negative) ==")
        if not args.llm_only:
            f, d, stop = await one(fresh, ROOT / "runs" / f"realneg_{name}_std", llm=False, seed=args.seed)
            ok = f == 0
            print(f"  std: findings={f} stop={stop} expect=0 {'PASS' if ok else 'FAIL'} [{', '.join(f'{c}@{t} {cf}' for c, t, cf in d)}]")
        if not args.std_only:
            f, d, stop = await one(fresh, ROOT / "runs" / f"realneg_{name}_llm", llm=True, seed=args.seed)
            ok = f == 0
            print(f"  llm: findings={f} stop={stop} expect=0 {'PASS' if ok else 'FAIL'} [{', '.join(f'{c}@{t} {cf}' for c, t, cf in d)}]")


if __name__ == "__main__":
    asyncio.run(main())
