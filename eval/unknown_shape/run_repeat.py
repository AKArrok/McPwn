"""Stage-3 repeat: N identical Stage-2 runs with the strict-better gate.

Protocol (README): same budget + fresh server per run + N>=3; the llm version
must find >=1 finding in EVERY run (miss once = fail).

Rigor fixes (2026-08-06):
- Each run spawns its own freshly-started vault server (in-memory store starts
  empty) so no run inherits vaults created by a previous run.
- seed is a real, recorded parameter: pass --seed N to forward it to the LLM
  API (provider-dependent; DeepSeek does not support `seed`, so leave unset -
  drift between runs is measured by attack_messages_sha1 in scan_result.json).

Usage:
    python eval/unknown_shape/run_repeat.py [N] [--seed N] [--port-base N]
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

from eval.unknown_shape._fresh_server import fresh_vault_server
from mcp_redteam.orchestrator.runner import scan


async def one(
    port: int, seed: int | None, out_dir: Path
) -> tuple[int, list[tuple[str, str, float]]]:
    """One Stage-2 run against a fresh vault server; returns (findings, detail)."""
    async with fresh_vault_server(port) as sse_url:
        result = await scan(
            sse_url=sse_url,
            out_dir=out_dir,
            max_tokens=30000,
            wall_seconds=300,
            planner_mode="hardcoded",
            llm_points=True,
            seed=seed,
            llm_hyp_budget=-1,  # unknown-shape: recon 全错类, LLM 假设需自由探索
        )
    detail = [
        (f.vuln_class.value, f.target, round(f.confidence, 2))
        for f in result.findings
    ]
    return len(result.findings), detail


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
        "--port-base", type=int, default=19205,
        help="first port for fresh servers (default 19205)",
    )
    args = parser.parse_args()

    n = args.n
    if n < 1:
        parser.error("n must be >= 1")
    results: list[tuple[int, list[tuple[str, str, float]]]] = []
    for i in range(n):
        port = args.port_base + i
        out_dir = Path(f"runs/unknown_shape_repeat_{i}")
        findings, detail = await one(port, args.seed, out_dir)
        results.append((findings, detail))
        print(f"run {i}: findings={findings} seed={args.seed} port={port} {detail}")
    hits = [r for r in results if r[0] >= 1]
    verdict = "PASS (strict-better)" if len(hits) == n else "FAIL (missed a run)"
    print(f"\n{len(hits)}/{n} runs found >=1 finding -> {verdict}")


if __name__ == "__main__":
    asyncio.run(main())
