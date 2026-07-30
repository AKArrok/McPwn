"""Run driver — M0 stub exposing only `load_challenge_spec`.

M1 adds `run_one` for AGENTIC mode (challenge 02 smoke). PAIR mode arrives in M2.
"""

from __future__ import annotations

import asyncio
import csv
import json
import time
import uuid
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml

from mcp_redteam.contracts import (
    Attempt,
    ChallengeSpec,
    RunResult,
    StopReason,
)
from mcp_redteam.models.chat import make_client
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock


def _load_yaml() -> dict:
    text = files("mcp_redteam.config").joinpath("challenges.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "challenges" not in data:
        raise RuntimeError("config/challenges.yaml malformed: expected top-level 'challenges'")
    return data


def load_challenge_spec(challenge_id: str) -> ChallengeSpec:
    data = _load_yaml()
    defaults = data.get("defaults", {})
    for entry in data["challenges"]:
        if entry["id"] == challenge_id:
            merged = {**defaults, **entry}
            return ChallengeSpec.model_validate(merged)
    raise KeyError(f"challenge {challenge_id!r} not found in challenges.yaml")


def load_all_specs() -> list[ChallengeSpec]:
    data = _load_yaml()
    defaults = data.get("defaults", {})
    return [
        ChallengeSpec.model_validate({**defaults, **entry}) for entry in data["challenges"]
    ]


@dataclass
class RunPaths:
    root: Path

    @property
    def summary_csv(self) -> Path:
        return self.root / "summary.csv"

    @property
    def attempts_jsonl(self) -> Path:
        return self.root / "attempts.jsonl"

    @property
    def audit_dir(self) -> Path:
        return self.root / "audit"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.audit_dir.mkdir(parents=True, exist_ok=True)


def _new_run_id(prefix: str = "run") -> str:
    return f"{prefix}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _stop_reason_from_verdict(verdict, inner_stop: str) -> StopReason:
    if verdict.success:
        return "success"
    if verdict.short_circuit:
        return "short_circuit_only"
    if inner_stop == "budget_tokens":
        return "budget_tokens"
    if inner_stop == "budget_time":
        return "budget_time"
    if inner_stop == "budget_turns":
        return "budget_turns"
    return "error"


async def run_one(
    spec: ChallengeSpec,
    run_dir: Path,
    repeats: int = 1,
) -> list[RunResult]:
    """Run one challenge N times. AGENTIC only in M1; PAIR raises NotImplementedError."""
    paths = RunPaths(run_dir)
    paths.ensure()
    results: list[RunResult] = []

    if spec.category == "pair":
        raise NotImplementedError("pair mode arrives in M2; M1 only covers agentic")

    from mcp_redteam.attackers.agentic_runner import run_agentic_one

    attacker = make_client("attacker")
    run_id = _new_run_id(prefix=f"ch{spec.id}")

    for repeat_idx in range(repeats):
        budget = TokenBudget(max_tokens_total=spec.max_tokens_total)
        clock = WallClock(wall_seconds=spec.wall_seconds)
        wall_start = time.perf_counter()

        outcome = await run_agentic_one(spec, attacker, budget, clock)
        wall_seconds = time.perf_counter() - wall_start

        stop_reason = _stop_reason_from_verdict(outcome.attempt.verdict, outcome.stop_reason)
        result = RunResult(
            run_id=f"{run_id}-r{repeat_idx}",
            challenge_id=spec.id,
            attacker_model=attacker[1].model,
            victim_model=None,
            mode="agentic",
            success=outcome.attempt.verdict.success,
            short_circuit=outcome.attempt.verdict.short_circuit,
            turns_used=outcome.inner_steps,
            total_tokens=budget.counted_tokens + budget.judge_tokens,
            attacker_tokens=budget.attacker_tokens,
            victim_tokens=budget.victim_tokens,
            judge_tokens=budget.judge_tokens,
            wall_seconds=wall_seconds,
            attempts=[outcome.attempt],
            stop_reason=stop_reason,
        )
        results.append(result)

        # Append attempts.jsonl
        with paths.attempts_jsonl.open("a", encoding="utf-8") as f:
            f.write(outcome.attempt.model_dump_json() + "\n")

    _write_summary(paths.summary_csv, results)
    return results


def _write_summary(path: Path, results: list[RunResult]) -> None:
    fields = [
        "run_id",
        "challenge_id",
        "attacker_model",
        "victim_model",
        "mode",
        "success",
        "short_circuit",
        "turns_used",
        "total_tokens",
        "attacker_tokens",
        "victim_tokens",
        "judge_tokens",
        "wall_seconds",
        "stop_reason",
    ]
    write_header = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if write_header:
            w.writeheader()
        for r in results:
            row = r.model_dump()
            w.writerow({k: row.get(k) for k in fields})
