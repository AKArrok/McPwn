"""Aggregated regression runner for the three eval targets.

Prevents future changes from silently breaking the "strict-better" claims
each experiment rests on:

    target    baseline (hardcoded)     llm_points (strict-better)
    vault     findings == 0            every run >= 1 finding
    delegate  findings == 0            every run >= 1 finding
    fetch     >= 1 SSRF finding        informational only (model token
                                       variance; reliable criterion is the
                                       deterministic baseline signal path)

Modes (default: prove):
    prove     deterministic exploit chain against a fresh server (no LLM, ~30s)
    baseline  1 hardcoded-planner scan per target (LLM budget)
    llm       N llm_points runs per target, miss once = FAIL (default N=1)
    full      prove + baseline + llm

Usage:
    python eval/regression.py                          # prove all
    python eval/regression.py --mode llm --n 3         # strict-better N=3
    python eval/regression.py --target fetch --mode full

NOTE: llm/baseline modes burn real LLM budget (deepseek attacker + doubao
judge). CI keeps the hermetic signal-precondition freeze in
tests/test_regression_shapes.py; run this locally (or in a dedicated runner).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

import logging

logging.basicConfig(level=logging.ERROR)  # keep regression output clean

# target-specific fresh-server spawners
from eval.fetch_ssrf._fresh import fresh_fetch_target
from eval.generalize._fresh_server import fresh_delegate_server
from eval.unknown_shape._fresh_server import fresh_vault_server
from mcp_redteam.orchestrator.runner import scan

TARGETS = ["vault", "delegate", "fetch"]

# fetch needs the project-local venv (official mcp-server-fetch + mcp<2)
FETCH_VENV = ROOT / "eval" / "fetch_ssrf" / ".venv" / "Scripts" / "python.exe"


@dataclass
class Result:
    ok: bool = True
    rows: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def row(self, text: str) -> None:
        self.rows.append(text)
        print(text)


def _fmt(detail: list[tuple[str, str, float]]) -> str:
    return ", ".join(f"{c}@{t} {conf}" for c, t, conf in detail) or "(none)"


# ── prove (deterministic exploit, no LLM) ────────────────────────────────────


async def prove_vault(out: Result) -> None:
    async with fresh_vault_server(19205) as url:
        from mcp_redteam.targets.mcp_client import McpSession

        me, name, secret = "u1", "pv", "s3cr3t-p"
        async with McpSession(url) as s:
            r = await s.call_tool("create_vault", {"owner": me, "name": name, "secret": secret})
            assert "created" in r.result_text, r.result_text
            leaked = await s.call_tool("read_vault", {"owner": "", "name": name})
            assert leaked.result_text == secret, leaked.result_text
    out.row("  vault prove: PASS (empty-owner read own secret)")


async def prove_delegate(out: Result) -> None:
    async with fresh_delegate_server(20105) as url:
        from mcp_redteam.targets.mcp_client import McpSession

        me, me2, name = "u1", "u2", "dv"
        async with McpSession(url) as s:
            r = await s.call_tool("create_vault", {"owner": me, "name": name, "secret": "x"})
            assert "created" in r.result_text, r.result_text
            denied = await s.call_tool("read_vault", {"owner": me2, "name": "admin_vault"})
            assert "cannot read" in denied.result_text, denied.result_text
            g = await s.call_tool("grant_access", {"owner": me, "name": name, "delegate": me2})
            assert "granted" in g.result_text, g.result_text
            leaked = await s.call_tool("read_vault", {"owner": me2, "name": "admin_vault"})
            assert leaked.result_text == "TOP-SECRET-ADMIN-VAULT-2026", leaked.result_text
    out.row("  delegate prove: PASS (grant-scope leaked admin_vault)")


async def prove_fetch(out: Result) -> None:
    if not FETCH_VENV.exists():
        out.ok = False
        out.row("  fetch prove: SKIP (venv missing - run setup, see eval/fetch_ssrf/README.md)")
        return
    async with fresh_fetch_target() as url:
        from mcp_redteam.targets.mcp_client import McpSession

        async with McpSession(url) as s:
            r = await s.call_tool("fetch", {"url": "http://127.0.0.1:9211/"})
            assert "TOP-SECRET-INTRANET-2026" in r.result_text, r.result_text
    out.row("  fetch prove: PASS (intranet secret returned by fetch)")


# ── scans (LLM budget) ───────────────────────────────────────────────────────


async def run_vault(out: Result, llm: bool, n: int) -> None:
    for i in range(n):
        out_dir = ROOT / "runs" / f"regression_vault_{'llm' if llm else 'base'}_{i}"
        async with fresh_vault_server(19205 + i) as url:
            res = await scan(sse_url=url, out_dir=out_dir, max_tokens=30000,
                             wall_seconds=300, planner_mode="hardcoded",
                             llm_points=llm, llm_hyp_budget=-1)
        f = len(res.findings)
        detail = _fmt([(x.vuln_class.value, x.target, x.confidence) for x in res.findings])
        expect = "0" if not llm else ">=1"
        ok = (f == 0) if not llm else (f >= 1)
        out.ok &= ok
        out.row(f"  vault {('llm' if llm else 'baseline')} run{i}: findings={f} "
                f"stop={res.stop_reason} expect={expect} {'PASS' if ok else 'FAIL'} [{detail}]")


async def run_delegate(out: Result, llm: bool, n: int) -> None:
    for i in range(n):
        out_dir = ROOT / "runs" / f"regression_delegate_{'llm' if llm else 'base'}_{i}"
        async with fresh_delegate_server(20105 + i) as url:
            res = await scan(sse_url=url, out_dir=out_dir, max_tokens=30000,
                             wall_seconds=300, planner_mode="hardcoded",
                             llm_points=llm, llm_hyp_budget=-1)
        f = len(res.findings)
        detail = _fmt([(x.vuln_class.value, x.target, x.confidence) for x in res.findings])
        expect = "0" if not llm else ">=1"
        ok = (f == 0) if not llm else (f >= 1)
        out.ok &= ok
        out.row(f"  delegate {('llm' if llm else 'baseline')} run{i}: findings={f} "
                f"stop={res.stop_reason} expect={expect} {'PASS' if ok else 'FAIL'} [{detail}]")


async def run_fetch(out: Result, llm: bool, n: int) -> None:
    if not FETCH_VENV.exists():
        out.ok = False
        out.row("  fetch scan: SKIP (venv missing)")
        return
    for i in range(n):
        out_dir = ROOT / "runs" / f"regression_fetch_{'llm' if llm else 'base'}_{i}"
        async with fresh_fetch_target() as url:
            res = await scan(sse_url=url, out_dir=out_dir, max_tokens=30000,
                             wall_seconds=300, planner_mode="hardcoded",
                             llm_points=llm)  # default llm_hyp_budget pool (40%)
        f = len(res.findings)
        detail = _fmt([(x.vuln_class.value, x.target, x.confidence) for x in res.findings])
        if llm:
            # Informational only (not part of the verdict): the llm round is
            # subject to model token variance - a wrong LLM hypothesis can
            # spend 15k+ in 3 calls (deepseek reasoning), so the recon SSRF
            # chain may not finish inside the leftover budget. The RELIABLE
            # fetch criterion is the baseline run (deterministic signal path).
            out.row(f"  fetch llm run{i}: findings={f} stop={res.stop_reason} "
                    f"(informational) [{detail}]")
        else:
            ok = f >= 1  # deterministic SSRF detection via ssrf_internal_service
            out.ok &= ok
            out.row(f"  fetch baseline run{i}: findings={f} stop={res.stop_reason} "
                    f"expect>=1 {'PASS' if ok else 'FAIL'} [{detail}]")


# ── orchestration ────────────────────────────────────────────────────────────


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS + ["all"], default="all")
    parser.add_argument("--mode", choices=["prove", "baseline", "llm", "full"], default="prove")
    parser.add_argument("--n", type=int, default=1, help="llm/baseline runs per target (default 1)")
    args = parser.parse_args()

    targets = TARGETS if args.target == "all" else [args.target]
    prove = args.mode in ("prove", "full")
    baseline = args.mode in ("baseline", "full")
    llm = args.mode in ("llm", "full")

    if args.mode in ("baseline", "llm", "full"):
        print(f"[regression] mode={args.mode} n={args.n} — LLM budget will be consumed")

    out = Result()
    for t in targets:
        print(f"== {t} ==")
        if prove:
            await {"vault": prove_vault, "delegate": prove_delegate, "fetch": prove_fetch}[t](out)
        if baseline:
            await {"vault": run_vault, "delegate": run_delegate, "fetch": run_fetch}[t](out, False, args.n)
        if llm:
            await {"vault": run_vault, "delegate": run_delegate, "fetch": run_fetch}[t](out, True, args.n)

    verdict = "ALL PASS" if out.ok else "FAIL"
    print(f"\n[regression] verdict: {verdict}")
    sys.exit(0 if out.ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
