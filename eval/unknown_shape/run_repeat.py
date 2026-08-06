"""Stage-3 repeat: N identical Stage-2 runs with the strict-better gate.

Protocol (README): same seed, same budget, N>=3 runs; the llm version must
find >=1 finding in EVERY run (miss once = fail). This is the falsifiable
criterion M3 lacked ("not worse" -> "strictly better").
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

URL = "http://127.0.0.1:9205/sse"


async def one(out_dir: Path, seed_note: str) -> tuple[int, list[tuple[str, str, float]]]:
    result = await scan(
        sse_url=URL,
        out_dir=out_dir,
        max_tokens=30000,
        wall_seconds=300,
        planner_mode="hardcoded",
        llm_points=True,
    )
    detail = [(f.vuln_class.value, f.target, round(f.confidence, 2)) for f in result.findings]
    return len(result.findings), detail


async def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    results: list[tuple[int, list[tuple[str, str, float]]]] = []
    for i in range(n):
        findings, detail = await one(Path(f"runs/unknown_shape_repeat_{i}"), str(i))
        results.append((findings, detail))
        print(f"run {i}: findings={findings} {detail}")
    hits = [r for r in results if r[0] >= 1]
    verdict = "PASS (strict-better)" if len(hits) == n else "FAIL (missed a run)"
    print(f"\n{len(hits)}/{n} runs found >=1 finding -> {verdict}")


if __name__ == "__main__":
    asyncio.run(main())
