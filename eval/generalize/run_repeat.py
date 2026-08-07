"""Stage-2/3: LLM three decision points on delegate-mcp, N identical runs.

Generalization protocol (README.md): same protocol as vault-mcp Stage 3, but
on a NEW vuln shape (delegate grant-scope leak, CWE-639) and with the
answer-stripped (类级框架) prompts + auth_bypass card from the Stage-4 ablation
(MCPWN_AGENTS_OVERRIDE_DIR / MCPWN_CARDS_OVERRIDE_DIR). The stripped files
contain no vault-mcp answer patterns ("子串匹配 / 空 owner / CWE-639"), so a
PASS here shows the class-level discovery ability transfers across shapes.

判据 (locked before running): every run must find >=1 finding (read a secret
from admin_vault as a user who was never granted it), same budget, fresh
server per run, N=3, miss once = fail.

Usage:
    python eval/generalize/run_repeat.py [N] [--seed N] [--port-base N]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Stripped (类级框架) prompt/card override - MUST be set before importing
# mcp_redteam (both registries read env at import time). Prompts come from the
# Stage-4 ablation (no vault-mcp answer patterns); the auth_bypass card is the
# ablation stripped card + one CLASS-LEVEL playbook step ("verify grant scope
# after a successful delegation") - still no target-specific answer.
_ABLATION = ROOT / "eval" / "unknown_shape" / "ablation"
_PROMPTS = _ABLATION / "prompts"
_CARDS = ROOT / "eval" / "generalize" / "cards"
for _p in (_PROMPTS / "hypothesis_system.md", _PROMPTS / "retrospective_system.md",
           _PROMPTS / "evidence_judge_system.md", _CARDS / "auth_bypass.md"):
    if not _p.exists():
        raise FileNotFoundError(f"stripped override file missing: {_p}")
os.environ["MCPWN_AGENTS_OVERRIDE_DIR"] = str(_PROMPTS)
os.environ["MCPWN_CARDS_OVERRIDE_DIR"] = str(_CARDS)

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from eval.generalize._fresh_server import fresh_delegate_server
from mcp_redteam.orchestrator.runner import scan


async def one(
    port: int, seed: int | None, out_dir: Path
) -> tuple[int, list[tuple[str, str, float]], str]:
    """One Stage-2 run against a fresh delegate server; returns
    (findings, detail, stop_reason)."""
    async with fresh_delegate_server(port) as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=True,
            seed=seed,
        )
    detail = [
        (f.vuln_class.value, f.target, round(f.confidence, 2))
        for f in result.findings
    ]
    return len(result.findings), detail, result.stop_reason


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "n", nargs="?", type=int, default=3,
        help="number of identical runs (default 3)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="LLM sampling seed (provider-dependent; None = not seeded)",
    )
    parser.add_argument(
        "--port-base", type=int, default=20105,
        help="first port for fresh servers (default 20105)",
    )
    args = parser.parse_args()

    n = args.n
    if n < 1:
        parser.error("n must be >= 1")
    print(f"override prompts: {_PROMPTS}")
    print(f"override cards:   {_CARDS}")
    results: list[tuple[int, list[tuple[str, str, float]], str]] = []
    for i in range(n):
        port = args.port_base + i
        out_dir = Path(f"runs/generalize_repeat_{i}")
        findings, detail, stop = await one(port, args.seed, out_dir)
        results.append((findings, detail, stop))
        print(f"run {i}: findings={findings} seed={args.seed} port={port} "
              f"stop={stop} {detail}")
    hits = [r for r in results if r[0] >= 1]
    verdict = "PASS (strict-better)" if len(hits) == n else "FAIL (missed a run)"
    print(f"\n{len(hits)}/{n} runs found >=1 finding -> {verdict}")


if __name__ == "__main__":
    asyncio.run(main())
