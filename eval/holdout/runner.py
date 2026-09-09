"""Frozen paired holdout evaluator.

This is deliberately an evaluation layer, not a second scanner.  It reuses
registered targets and the normal scan pipeline, then asks a stronger causal
question than "did a string appear?":

1. did the vulnerable version yield an expected finding;
2. did the fixed version stay clean for the same vulnerability family; and
3. did replaying the exact vulnerable PoC on the fixed version produce a
   blocking response without reproducing the evidence signal?

The protocol manifest is SHA-256 locked and N>=5 is mandatory.  DVMCP is not
listed here because it is a seen regression fixture, not an independent holdout.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from eval.targets.run import Target
from eval.targets.run import load_manifest as load_target_manifest
from eval.targets.spawners import get_spawner
from mcp_redteam.contracts import Finding, McpCall, ScanResult, TargetSpec
from mcp_redteam.orchestrator.runner import scan
from mcp_redteam.signals.detectors import run_all_signals
from mcp_redteam.targets.mcp_client import McpSession

MANIFEST = Path(__file__).with_name("manifest.yaml")
LOCK = Path(__file__).with_name("lock.json")
DEFAULT_MANIFEST = MANIFEST
DEFAULT_LOCK = LOCK


class HoldoutProtocolError(ValueError):
    """The frozen protocol is invalid or was changed without re-signing."""


@dataclass(frozen=True)
class ControlReplay:
    finding_id: str
    calls_replayed: int
    exploit_evidence_grounded: bool = False
    control_blocked: bool = False
    control_signal_ids: list[str] | None = None
    same_signal_reproduced: bool = False
    passed: bool = False
    denied_pattern: str | None = None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_protocol(
    manifest_path: Path = MANIFEST,
    lock_path: Path = LOCK,
) -> dict[str, Any]:
    """Load the protocol only when its bytes match the committed lock."""
    if not manifest_path.exists() or not lock_path.exists():
        raise HoldoutProtocolError("holdout manifest/lock missing")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    actual = _sha256(manifest_path)
    if lock.get("sha256") != actual:
        raise HoldoutProtocolError(
            f"holdout manifest lock mismatch: expected {lock.get('sha256')}, got {actual}"
        )
    protocol = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if protocol.get("protocol_version") != 1:
        raise HoldoutProtocolError("unsupported holdout protocol_version")
    validate_repeats(protocol, int(protocol.get("minimum_repeats", 0)))
    pairs = protocol.get("pairs") or []
    if not pairs or not any(p.get("split") == "holdout" for p in pairs):
        raise HoldoutProtocolError("protocol must contain at least one holdout pair")
    for pair in pairs:
        required = {
            "pair_id", "split", "vulnerable_target", "fixed_target",
            "expected_vuln_classes", "control_block_patterns",
            "control_forbidden_signal_prefixes",
        }
        missing = sorted(required - set(pair))
        if missing:
            raise HoldoutProtocolError(
                f"pair {pair.get('pair_id', '<unknown>')} missing: {', '.join(missing)}"
            )
        if not pair["control_block_patterns"]:
            raise HoldoutProtocolError(f"pair {pair['pair_id']} has no control block patterns")
    return protocol


def validate_repeats(protocol: dict[str, Any], n: int) -> int:
    minimum = max(5, int(protocol.get("minimum_repeats", 5)))
    if n < minimum:
        raise HoldoutProtocolError(
            f"holdout requires at least {minimum} repeated runs; got {n}"
        )
    return n


def _signal_matches(pair: dict[str, Any], signal_id: str) -> bool:
    expected = set(pair.get("expected_signal_ids") or [])
    prefixes = tuple(pair.get("control_forbidden_signal_prefixes") or [])
    return signal_id in expected or signal_id.startswith(prefixes)


def exploit_evidence_grounded(finding: Finding) -> bool:
    if not finding.poc_call_sequence:
        return False
    relevant = [signal for signal in finding.signals if signal.severity in {"high", "critical"}]
    if not relevant:
        return False
    for signal in relevant:
        if signal.signal_id == "llm_evidence_verdict":
            if (
                signal.source_call_index is not None
                and signal.matched_text
                and 0 <= signal.source_call_index < len(finding.poc_call_sequence)
                and signal.matched_text
                in finding.poc_call_sequence[signal.source_call_index].result_text
            ):
                return True
        elif signal.source_call_index is not None:
            return True
    return False


def finding_matches_pair(finding: Finding, pair: dict[str, Any]) -> bool:
    classes = set(pair.get("expected_vuln_classes") or [])
    if finding.vuln_class.value not in classes:
        return False
    ids = {signal.signal_id for signal in finding.signals}
    if ids & set(pair.get("expected_signal_ids") or []):
        return exploit_evidence_grounded(finding)
    return bool(
        pair.get("allow_llm_evidence")
        and "llm_evidence_verdict" in ids
        and exploit_evidence_grounded(finding)
    )


def _eligible_finding(pair: dict[str, Any], finding: Finding) -> bool:
    return finding_matches_pair(finding, pair)


def _fixed_has_same_family_finding(pair: dict[str, Any], finding: Finding) -> bool:
    if finding.vuln_class.value in set(pair.get("expected_vuln_classes") or []):
        return True
    return any(_signal_matches(pair, signal.signal_id) for signal in finding.signals)


def evaluate_pair_run(
    pair: dict[str, Any],
    vulnerable_result: ScanResult | Any,
    fixed_result: ScanResult | Any,
    controls: list[ControlReplay],
) -> dict[str, Any]:
    eligible = [f for f in vulnerable_result.findings if _eligible_finding(pair, f)]
    positive_ids = {f.finding_id for f in eligible}
    fixed_same_family = [
        f for f in fixed_result.findings if _fixed_has_same_family_finding(pair, f)
    ]
    replay_passed = any(c.passed and c.finding_id in positive_ids for c in controls)
    replayed_ids = {c.finding_id for c in controls}
    reasons: list[str] = []
    if not eligible:
        reasons.append("no matching vulnerable-version finding")
    if fixed_same_family:
        reasons.append("fixed version reproduced the same vulnerability family")
    if positive_ids and not (positive_ids & replayed_ids):
        reasons.append("missing control replay for matching vulnerable finding")
    elif positive_ids and not replay_passed:
        reasons.append("control replay did not prove fixed-version blocking")
    verdict = {
        "positive_detected": bool(eligible),
        "fixed_clean": not fixed_same_family,
        "control_replay_passed": replay_passed,
        "positive_finding_ids": sorted(positive_ids),
        "fixed_same_family_finding_ids": sorted(f.finding_id for f in fixed_same_family),
        "reasons": reasons,
    }
    verdict["status"] = (
        "PASS" if all(verdict[k] for k in (
            "positive_detected", "fixed_clean", "control_replay_passed"
        )) else "FAIL"
    )
    return verdict


async def replay_finding_on_control(
    finding: Finding,
    session: Any,
    pair: dict[str, Any],
    sandbox_root: str | None = None,
) -> ControlReplay:
    """Replay the exact positive PoC and demand explicit fixed-version blocking."""
    replayed: list[McpCall] = []
    for call in finding.poc_call_sequence:
        if call.kind == "call_tool" and call.name:
            replayed.append(await session.call_tool(call.name, call.args or {}))
        elif call.kind == "read_resource" and call.name:
            replayed.append(await session.read_resource(call.name))

    def is_blocked_response(call: McpCall) -> bool:
        text = call.result_text.lower()
        return any(
            pattern.lower() in text
            for pattern in pair.get("control_block_patterns") or []
        )

    signals = run_all_signals(
        [call for call in replayed if not is_blocked_response(call)],
        "",
        sandbox_root=sandbox_root,
    )
    control_signal_ids = sorted({signal.signal_id for signal in signals})
    same_signal = any(_signal_matches(pair, signal_id) for signal_id in control_signal_ids)
    haystack = "\n".join(call.result_text.lower() for call in replayed)
    denied_pattern = next(
        (
            pattern
            for pattern in pair.get("control_block_patterns") or []
            if pattern.lower() in haystack
        ),
        None,
    )
    blocked = denied_pattern is not None
    grounded = exploit_evidence_grounded(finding)
    passed = bool(replayed) and grounded and blocked and not same_signal
    return ControlReplay(
        finding_id=finding.finding_id,
        calls_replayed=len(replayed),
        exploit_evidence_grounded=grounded,
        control_blocked=blocked,
        control_signal_ids=control_signal_ids,
        same_signal_reproduced=same_signal,
        passed=passed,
        denied_pattern=denied_pattern,
    )


@asynccontextmanager
async def _target_context(target: Target) -> AsyncIterator[TargetSpec]:
    direct = target.spec()
    if direct is not None:
        yield direct
        return
    async with get_spawner(target.spawn, target.sse_url) as url:
        yield TargetSpec.parse(url)


def _target_lookup() -> dict[str, Target]:
    return {target.name: target for target in load_target_manifest()}


def _missing_env(pair: dict[str, Any], targets: dict[str, Target]) -> list[str]:
    missing: set[str] = set()
    for name in (pair["vulnerable_target"], pair["fixed_target"]):
        target = targets.get(name)
        if target is None:
            raise HoldoutProtocolError(f"unknown target {name!r} in pair {pair['pair_id']}")
        missing.update(target.check_env())
    return sorted(missing)


async def _scan_target(
    target: Target,
    spec: TargetSpec,
    out_dir: Path,
    llm: bool,
    seed: int | None,
) -> ScanResult:
    return await scan(
        sse_url=spec,
        out_dir=out_dir,
        max_tokens=30000,
        wall_seconds=300,
        planner_mode="hardcoded",
        llm_points=llm,
        seed=seed,
        llm_hyp_budget=target.llm_hyp_budget,
        sandbox_root=target.sandbox_root,
    )


async def _run_pair_once(
    pair: dict[str, Any],
    targets: dict[str, Target],
    out_dir: Path,
    index: int,
    seed: int | None,
) -> dict[str, Any]:
    vulnerable = targets[pair["vulnerable_target"]]
    fixed = targets[pair["fixed_target"]]
    llm = pair.get("scan_mode") == "llm"
    run_dir = out_dir / pair["pair_id"] / f"run_{index}"

    async with _target_context(vulnerable) as vulnerable_spec:
        vulnerable_result = await _scan_target(
            vulnerable, vulnerable_spec, run_dir / "vulnerable", llm, seed
        )

    controls: list[ControlReplay] = []
    async with _target_context(fixed) as fixed_spec:
        fixed_result = await _scan_target(fixed, fixed_spec, run_dir / "fixed", llm, seed)
        async with McpSession(fixed_spec) as session:
            for finding in vulnerable_result.findings:
                if _eligible_finding(pair, finding):
                    controls.append(await replay_finding_on_control(
                        finding, session, pair, fixed.sandbox_root
                    ))

    verdict = evaluate_pair_run(pair, vulnerable_result, fixed_result, controls)
    verdict.update({
        "index": index,
        "seed": seed,
        "vulnerable_stop_reason": vulnerable_result.stop_reason.value,
        "fixed_stop_reason": fixed_result.stop_reason.value,
        "controls": [asdict(control) for control in controls],
    })
    return verdict


def _wilson_interval(passed: int, total: int) -> tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    z = 1.959963984540054
    phat = passed / total
    denom = 1 + z * z / total
    center = (phat + z * z / (2 * total)) / denom
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * total)) / total) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def _write_report(summary: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        "# Frozen Paired Holdout Report",
        "",
        f"- protocol sha256: `{summary['protocol_sha256']}`",
        f"- repeats per pair: **{summary['repeats']}**",
        f"- overall verdict: **{summary['status']}**",
        "",
        "| pair | split | pass | rate | Wilson 95% CI | verdict |",
        "|---|---|---:|---:|---:|---|",
    ]
    for row in summary["pairs"]:
        lines.append(
            f"| {row['pair_id']} | {row['split']} | {row['passed']}/{row['total']} | "
            f"{row['rate']:.3f} | [{row['ci95'][0]:.3f}, {row['ci95'][1]:.3f}] | "
            f"{row['status']} |"
        )
    lines.extend([
        "",
        (
            "PASS requires every run to satisfy all three gates: vulnerable detection, "
            "fixed-version cleanliness, and exact-PoC control replay blocked without "
            "reproducing the evidence family."
        ),
    ])
    path = out_dir / "eval_report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


async def run_protocol(
    out_dir: Path,
    n: int,
    split: str = "holdout",
    pair_id: str | None = None,
    seed: int | None = None,
) -> Path:
    protocol = load_protocol()
    validate_repeats(protocol, n)
    targets = _target_lookup()
    pairs = [
        pair for pair in protocol["pairs"]
        if (split == "all" or pair["split"] == split)
        and (pair_id is None or pair["pair_id"] == pair_id)
    ]
    if not pairs:
        raise HoldoutProtocolError("no pairs selected")

    rows: list[dict[str, Any]] = []
    for pair in pairs:
        missing = _missing_env(pair, targets)
        if missing:
            raise HoldoutProtocolError(
                f"pair {pair['pair_id']} missing environment: {', '.join(missing)}"
            )
        runs = [
            await _run_pair_once(
                pair, targets, out_dir, i, None if seed is None else seed + i
            )
            for i in range(n)
        ]
        passed = sum(run["status"] == "PASS" for run in runs)
        low, high = _wilson_interval(passed, n)
        rows.append({
            "pair_id": pair["pair_id"],
            "split": pair["split"],
            "passed": passed,
            "total": n,
            "rate": passed / n,
            "ci95": [low, high],
            "status": "PASS" if passed == n else "FAIL",
            "runs": runs,
        })

    summary = {
        "protocol_version": protocol["protocol_version"],
        "protocol_sha256": _sha256(MANIFEST),
        "repeats": n,
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
        "pairs": rows,
    }
    return _write_report(summary, out_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "runs" / "holdout")
    parser.add_argument("--n", type=int, default=5)
    parser.add_argument("--split", choices=["validation", "holdout", "all"], default="holdout")
    parser.add_argument("--pair", default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--check", action="store_true", help="verify lock/targets/env only")
    args = parser.parse_args()

    protocol = load_protocol()
    validate_repeats(protocol, args.n)
    if args.check:
        targets = _target_lookup()
        selected = [
            pair for pair in protocol["pairs"]
            if (args.split == "all" or pair["split"] == args.split)
            and (args.pair is None or pair["pair_id"] == args.pair)
        ]
        if not selected:
            raise HoldoutProtocolError("no pairs selected")
        for pair in selected:
            missing = _missing_env(pair, targets)
            state = "ready" if not missing else f"missing: {', '.join(missing)}"
            print(f"{pair['pair_id']}: {state}")
        return

    report = asyncio.run(run_protocol(args.out, args.n, args.split, args.pair, args.seed))
    summary = json.loads((args.out / "summary.json").read_text(encoding="utf-8"))
    print(f"wrote {report}")
    raise SystemExit(0 if summary["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
