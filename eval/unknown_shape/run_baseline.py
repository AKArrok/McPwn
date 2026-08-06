"""Reproduce the Stage-1 baseline: current agent must MISS the vault flaw.

Expected output: findings=0 (the unknown-shape vuln is invisible to recon
classes and the signal library). See README.md for the three-stage protocol.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from mcp_redteam.orchestrator.runner import scan


async def main() -> None:
    result = await scan(
        sse_url="http://127.0.0.1:9205/sse",
        out_dir=Path("runs/unknown_shape_baseline"),
        max_tokens=30000,
        wall_seconds=240,
        planner_mode="hardcoded",
    )
    print(f"findings={len(result.findings)} stop={result.stop_reason}")
    for f in result.findings:
        print(" ", f.vuln_class, f.target, f.confidence)


if __name__ == "__main__":
    asyncio.run(main())
