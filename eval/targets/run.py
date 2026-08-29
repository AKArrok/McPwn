"""Unified eval target runner - one entry point for every registered target.

Reads ``eval/targets/manifest.yaml`` and executes prove / baseline / llm
phases per target with the manifest's expectation as the PASS/FAIL criterion.
New targets are manifest entries (see manifest.yaml), not new scripts.

Usage:
    python eval/targets/run.py                        # prove all (no LLM, ~1min)
    python eval/targets/run.py --mode llm --n 1       # strict-better LLM rounds
    python eval/targets/run.py --target fetch --mode full
    python eval/targets/run.py --list                 # show registered targets

Expectation grammar (baseline_expect / llm_expect):
    0     exactly zero findings
    >=1   one or more findings
    info  record only, never affects the verdict (model-variance cases)
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.ERROR)

from eval.targets.spawners import get_spawner
from mcp_redteam.orchestrator.runner import scan
from mcp_redteam.report.benchmark import ManifestVerdict, expect_ok, write_benchmark

MANIFEST = Path(__file__).resolve().parent / "manifest.yaml"


@dataclass
class Target:
    name: str
    label: str
    spawn: str
    sse_url: str | None
    prove: bool
    prove_script: Path | None
    baseline_expect: str
    llm_expect: str
    llm_hyp_budget: int | None
    env: list[str]
    # Declarative connection (no spawner): stdio command + optional transport
    # override ("sse" / "streamable_http" for HTTP entries).
    command: str | None = None
    transport: str = "auto"

    @classmethod
    def from_manifest(cls, entry: dict) -> Target:
        return cls(
            name=entry["name"],
            label=entry.get("label", entry["name"]),
            spawn=entry.get("spawn", "sse"),
            sse_url=entry.get("sse_url"),
            prove=bool(entry.get("prove", False)),
            prove_script=(
                ROOT / entry["prove_script"]
                if entry.get("prove_script")
                else ROOT / "eval" / entry["name"] / "prove.py"
            ),
            baseline_expect=str(entry.get("baseline_expect", "info")),
            llm_expect=str(entry.get("llm_expect", "info")),
            llm_hyp_budget=entry.get("llm_hyp_budget"),  # None -> default pool
            env=list(entry.get("env", [])),
            command=entry.get("command"),
            transport=str(entry.get("transport", "auto")),
        )

    def spec(self):
        """Connection spec for this target (spawner URL or declarative)."""
        from mcp_redteam.contracts import TargetSpec

        if self.command:
            return TargetSpec.parse(transport=self.transport, command=self.command)
        if self.sse_url:
            return TargetSpec.parse(self.sse_url, transport=self.transport)
        return None  # spawner-provided URL

    def check_env(self) -> list[str]:
        import os

        return [k for k in self.env if k not in os.environ]


def load_manifest() -> list[Target]:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    return [Target.from_manifest(e) for e in data["targets"]]


@dataclass
class Result:
    ok: bool = True
    rows: list[str] = field(default_factory=list)

    def row(self, text: str) -> None:
        self.rows.append(text)
        print(text)


def _fmt(detail: list[tuple[str, str, float]]) -> str:
    return ", ".join(f"{c}@{t} {conf}" for c, t, conf in detail) or "(none)"


def _expect_ok(expect: str, findings: int) -> bool:
    # Single source of truth for the grammar: report/benchmark.py
    return expect_ok(expect, findings)


def _run_prove(target: Target, out: Result) -> None:
    if not target.prove:
        out.row(f"  [{target.name}] prove: skipped (prove=false)")
        return
    script = target.prove_script
    if not script.exists():
        out.ok = False
        out.row(f"  [{target.name}] prove: FAIL (script missing: {script})")
        return
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=180,
        cwd=ROOT, check=False,
    )
    ok = proc.returncode == 0
    out.ok &= ok
    tail = (proc.stdout or "").strip().splitlines()[-1:] or [proc.stderr.strip().splitlines()[-1]]
    out.row(f"  [{target.name}] prove: {'PASS' if ok else 'FAIL'} | {tail[0][:100]}")


async def _run_scan(
    target: Target, llm: bool, out: Result, n: int, seed: int | None
) -> None:
    expect = target.llm_expect if llm else target.baseline_expect
    for i in range(n):
        out_dir = ROOT / "runs" / f"manifest_{target.name}_{'llm' if llm else 'std'}_{i}"
        if target.command or target.sse_url:
            spec = target.spec()
            assert spec is not None
            result = await scan(
                sse_url=spec, out_dir=out_dir, max_tokens=30000,
                wall_seconds=300, planner_mode="hardcoded",
                llm_points=llm, seed=seed,
                llm_hyp_budget=target.llm_hyp_budget,
            )
        else:
            async with get_spawner(target.spawn, target.sse_url) as sse_url:
                result = await scan(
                    sse_url=sse_url, out_dir=out_dir, max_tokens=30000,
                    wall_seconds=300, planner_mode="hardcoded",
                    llm_points=llm, seed=seed,
                    llm_hyp_budget=target.llm_hyp_budget,
                )
        f = len(result.findings)
        write_benchmark(
            result, out_dir,
            entry=ManifestVerdict(
                name=target.name, label=target.label,
                baseline_expect=target.baseline_expect,
                llm_expect=target.llm_expect,
            ),
            max_tokens=30000, wall_seconds=300,
            mode="llm" if llm else "std",
        )
        detail = _fmt([(x.vuln_class.value, x.target, x.confidence) for x in result.findings])
        if expect == "info":
            out.row(f"  [{target.name}] {'llm' if llm else 'std'} run{i}: findings={f} "
                    f"stop={result.stop_reason} (info) [{detail}]")
        else:
            ok = _expect_ok(expect, f)
            out.ok &= ok
            out.row(f"  [{target.name}] {'llm' if llm else 'std'} run{i}: findings={f} "
                    f"stop={result.stop_reason} expect={expect} "
                    f"{'PASS' if ok else 'FAIL'} [{detail}]")


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="all", help="target name or 'all'")
    parser.add_argument("--mode", choices=["prove", "baseline", "llm", "full"], default="prove")
    parser.add_argument("--n", type=int, default=1)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--list", action="store_true", help="list registered targets and exit")
    args = parser.parse_args()

    targets = load_manifest()
    if args.list:
        for t in targets:
            missing = t.check_env()
            flag = f" (missing env: {', '.join(missing)})" if missing else ""
            print(f"{t.name:16s} {t.label}{flag}")
        return

    selected = [t for t in targets if args.target in ("all", t.name)]
    if not selected:
        parser.error(f"unknown target {args.target!r}; see --list")
    if args.mode in ("baseline", "llm", "full"):
        print(f"[manifest] mode={args.mode} n={args.n} — LLM budget will be consumed")

    out = Result()
    for t in selected:
        missing = t.check_env()
        if missing:
            out.ok = False
            print(f"== {t.name} == SKIPPED (missing env: {', '.join(missing)})")
            continue
        print(f"== {t.name}: {t.label} ==")
        if args.mode in ("prove", "full"):
            _run_prove(t, out)
        if args.mode in ("baseline", "full"):
            await _run_scan(t, False, out, args.n, args.seed)
        if args.mode in ("llm", "full"):
            await _run_scan(t, True, out, args.n, args.seed)

    print(f"\n[manifest] verdict: {'ALL PASS' if out.ok else 'FAIL'}")
    sys.exit(0 if out.ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
