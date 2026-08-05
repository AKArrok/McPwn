"""Deterministic half of the M3 acceptance judge (HANDOFF_JUDGE).

Pure data-in/data-out functions: A/B eval summaries, planner decision
stats, the 9010 chain gate, and the five locked M3 criteria. No LLM calls
and no imports from ``mcp_redteam.judge.m3`` (the conservative aggregation
and the LLM ruling live there).
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

import yaml

from mcp_redteam.contracts import M3JudgeReport, ScanResult

_log = logging.getLogger(__name__)

# Locked M3 criterion keys (HANDOFF_JUDGE); order is the report order.
CRITERION_KEYS = (
    "recall_llm_ge_hardcoded",
    "fpr_llm_le_hardcoded",
    "avg_findings_llm_ge_hardcoded",
    "planner_non_fallback_ge_0_8",
    "chain_9010_real",
)

_CHAIN_PORT = 9010
_CHAIN_CLASS = "chain_composition"


def load_expected() -> dict:
    """Load ``eval/dvmcp/expected.yaml`` (raw yaml dict, runner.py schema)."""
    path = Path(__file__).with_name("expected.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_scan_result(scan_path: Path) -> ScanResult | None:
    """Parse one ``scan_result.json``; None on any failure.

    The runner writes ``model_dump_json`` which includes the derived
    ``total_tokens`` @computed_field; ``extra="forbid"`` rejects it on
    re-validation (see tests/test_scan_metadata.py), so pop it first.
    """
    try:
        data = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    data.pop("total_tokens", None)
    try:
        return ScanResult.model_validate(data)
    except (OSError, ValueError):
        return None


def _iter_port_dirs(eval_dir: Path) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for path in eval_dir.glob("port_*"):
        if not path.is_dir():
            continue
        try:
            port = int(path.name.split("_", 1)[1])
        except (IndexError, ValueError):
            continue
        found.append((port, path))
    return sorted(found, key=lambda item: item[0])


def collect_eval_summary(eval_dir: Path, expected_by_port: dict[int, dict]) -> dict:
    """Summarise one DVMCP eval output dir.

    Returns ``{"ports": {port: {...}}}`` where each port entry carries
    ``tools_seen`` / ``resources_seen`` / ``n_findings`` /
    ``finding_signal_ids`` / ``hit`` / ``expected_signals`` plus a
    ``traces`` list (trimmed AttackTrace dicts) that :func:`chain_gate`
    needs. Hit logic mirrors eval/dvmcp/runner.py: a port hits when any
    finding's signal_ids intersect the port's expected_signals; every
    non-matching finding is a false positive.
    """
    ports: dict[int, dict] = {}
    for port, port_dir in _iter_port_dirs(eval_dir):
        result = _load_scan_result(port_dir / "scan_result.json")
        if result is None:
            _log.warning("m3 judge: skipping unreadable scan at %s", port_dir)
            continue
        expected_sigs = list(
            expected_by_port.get(port, {}).get("expected_signals") or []
        )
        expected_set = set(expected_sigs)
        finding_signal_ids = [[s.signal_id for s in f.signals] for f in result.findings]
        hit = any(
            expected_set and (set(sig_ids) & expected_set)
            for sig_ids in finding_signal_ids
        )
        traces = [
            {
                "vuln_class": t.vuln_class.value,
                "target": t.target,
                "attack_calls": [c.model_dump() for c in t.attack_calls],
                "final_llm_output": t.final_llm_output,
                "judge_verdict": t.judge_verdict.model_dump() if t.judge_verdict else None,
            }
            for t in result.traces
        ]
        ports[port] = {
            "tools_seen": list(result.tools_seen),
            "resources_seen": list(result.resources_seen),
            "n_findings": len(result.findings),
            "finding_signal_ids": finding_signal_ids,
            "hit": hit,
            "expected_signals": expected_sigs,
            "traces": traces,
        }
    return {"ports": ports}


def compute_metrics(summary: dict, port_subset: list[int]) -> dict:
    """Compute M3 numeric metrics over ``port_subset`` only.

    recall = hit_ports / n_ports; fpr = fp_count / total_findings (0.0
    when there are no findings); avg_findings = total_findings / n_ports.
    A finding is a false positive when its signal_ids do not intersect the
    port's expected_signals (runner.py semantics).
    """
    ports = summary.get("ports", {})
    n_ports = 0
    hit_ports = 0
    total_findings = 0
    fp_count = 0
    for port in port_subset:
        info = ports.get(port)
        if info is None:
            continue
        n_ports += 1
        if info.get("hit"):
            hit_ports += 1
        expected = set(info.get("expected_signals") or [])
        for sig_ids in info.get("finding_signal_ids") or []:
            total_findings += 1
            if not (expected and (set(sig_ids) & expected)):
                fp_count += 1
    return {
        "n_ports": n_ports,
        "recall": hit_ports / n_ports if n_ports else 0.0,
        "fpr": fp_count / total_findings if total_findings else 0.0,
        "avg_findings": total_findings / n_ports if n_ports else 0.0,
        "total_findings": total_findings,
        "hit_ports": hit_ports,
    }


def load_planner_decisions(llm_dir: Path) -> list[dict] | None:
    """Read ``<llm_dir>/planner_decisions.json``; None when missing/unparseable/empty.

    Schema: ``{"decisions": [{"port", "index", "vuln_class", "target",
    "source": "llm"|"fallback", "planned", "executed", "skip_reason"}]}``.
    """
    path = llm_dir / "planner_decisions.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        return None
    entries = [d for d in decisions if isinstance(d, dict)]
    return entries or None


def planner_stats(decisions: list[dict], llm_summary: dict) -> dict:
    """Stats over planner decisions.

    non_fallback_rate = (source == "llm" count) / total, None when
    total == 0. Hallucination: an LLM decision whose target is not in that
    port's tools_seen + resources_seen and whose target has no comma
    (chain anchors contain commas and are exempt). hallucination_rate =
    hallucinated_count / total, None when total == 0. degenerate_single_class
    = total >= 5 and >= 80% of decisions share one vuln_class.
    """
    total = len(decisions)
    llm_decisions = [d for d in decisions if d.get("source") == "llm"]
    non_fallback_count = len(llm_decisions)
    non_fallback_rate = non_fallback_count / total if total else None

    ports = llm_summary.get("ports", {})
    hallucinated_count = 0
    for d in llm_decisions:
        target = str(d.get("target") or "")
        if "," in target:
            continue
        info = ports.get(d.get("port")) or {}
        seen = set(info.get("tools_seen") or []) | set(info.get("resources_seen") or [])
        if target not in seen:
            hallucinated_count += 1
    hallucination_rate = hallucinated_count / total if total else None

    degenerate_single_class = False
    if total >= 5:
        counts = Counter(d.get("vuln_class") for d in decisions)
        if counts and counts.most_common(1)[0][1] / total >= 0.8:
            degenerate_single_class = True

    return {
        "total": total,
        "non_fallback_count": non_fallback_count,
        "non_fallback_rate": non_fallback_rate,
        "hallucination_rate": hallucination_rate,
        "hallucinated_count": hallucinated_count,
        "degenerate_single_class": degenerate_single_class,
    }


def _args_string(call: dict) -> str:
    """Deterministic string form of a call's args ('' when args is None)."""
    args = call.get("args")
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    return json.dumps(args, ensure_ascii=False, sort_keys=True)


def _has_prior_arg_link(calls: list[dict]) -> bool:
    """A later call's args contain a >=6-char substring of an earlier result.

    Checking 6-char windows is equivalent to asking for any >=6-char common
    substring (any longer match contains a 6-char window).
    """
    for i in range(len(calls)):
        text = str(calls[i].get("result_text") or "")
        for j in range(i + 1, len(calls)):
            target = _args_string(calls[j])
            if not target:
                continue
            for k in range(max(0, len(text) - 5)):
                if text[k : k + 6] in target:
                    return True
    return False


def _parse_anchors(target: str) -> list[str]:
    """Parse comma-separated kind:name anchor tokens from a chain target.

    A ``kind:`` prefix (e.g. ``resource:``) is stripped; a bare URI like
    ``internal://credentials`` is kept whole (its first colon starts the
    scheme, not a kind prefix).
    """
    anchors = []
    for token in target.split(","):
        token = token.strip()
        if not token:
            continue
        _, sep, tail = token.partition(":")
        if sep and tail and not tail.startswith("//"):
            token = tail
        anchors.append(token)
    return anchors


def _calls_two_anchors(target: str, calls: list[dict]) -> bool:
    """>=2 distinct parsed anchors from ``target`` are called by the trace."""
    called: set[str] = set()
    for anchor in _parse_anchors(target):
        for call in calls:
            name = str(call.get("name") or "")
            args = _args_string(call)
            if anchor and (anchor in name or anchor in args):
                called.add(anchor)
                break
    return len(called) >= 2


def chain_gate(llm_summary: dict, decisions: list[dict] | None) -> dict | None:
    """Gate the 9010 chain criterion; None when port 9010 is absent.

    chain_trace_present: any 9010 trace with vuln_class chain_composition
    and attack_calls. chain_planned_unexecuted: a 9010 chain_composition
    planner decision planned but not executed. prior_link: within the chain
    trace, a later call's args contain a >=6-char substring of an earlier
    call's result_text, or >=2 distinct anchor targets parsed from the
    trace's own comma-separated kind:name target string are actually called.
    """
    ports = llm_summary.get("ports", {})
    if _CHAIN_PORT not in ports:
        return None
    traces = ports[_CHAIN_PORT].get("traces") or []
    chain_trace = next(
        (
            t
            for t in traces
            if t.get("vuln_class") == _CHAIN_CLASS and t.get("attack_calls")
        ),
        None,
    )
    chain_trace_present = chain_trace is not None
    chain_attack_calls = len(chain_trace.get("attack_calls") or []) if chain_trace else 0
    chain_planned_unexecuted = any(
        d.get("port") == _CHAIN_PORT
        and d.get("vuln_class") == _CHAIN_CLASS
        and d.get("planned") is True
        and d.get("executed") is not True
        for d in decisions or []
    )
    prior_link = False
    if chain_trace is not None:
        calls = chain_trace.get("attack_calls") or []
        prior_link = _has_prior_arg_link(calls) or _calls_two_anchors(
            chain_trace.get("target") or "", calls
        )
    if chain_trace is None:
        excerpt = {"absent": True}
    else:
        excerpt = {
            "vuln_class": _CHAIN_CLASS,
            "target": chain_trace.get("target") or "",
            "attack_calls": [
                {
                    "kind": c.get("kind"),
                    "name": c.get("name"),
                    "args": c.get("args"),
                    "result_text": (c.get("result_text") or "")[:400],
                }
                for c in chain_trace.get("attack_calls") or []
            ],
            "final_llm_output": (chain_trace.get("final_llm_output") or "")[:500],
            "judge_verdict": chain_trace.get("judge_verdict"),
        }
    return {
        "chain_trace_present": chain_trace_present,
        "chain_attack_calls": chain_attack_calls,
        "chain_planned_unexecuted": chain_planned_unexecuted,
        "prior_link": prior_link,
        "excerpt": excerpt,
    }


def compute_criteria(
    metrics_hc: dict, metrics_llm: dict, ps: dict, cg: dict | None
) -> dict[str, str]:
    """Return the five locked M3 criteria (pass/fail/inconclusive).

    Conservative aggregation across criteria is NOT done here; that lives in
    mcp_redteam/judge/m3.py.
    """
    recall = "pass" if metrics_llm["recall"] >= metrics_hc["recall"] else "fail"
    fpr = "pass" if metrics_llm["fpr"] <= metrics_hc["fpr"] else "fail"
    avg = (
        "pass"
        if metrics_llm["avg_findings"] >= metrics_hc["avg_findings"] - 0.2
        else "fail"
    )
    if ps is None or ps.get("non_fallback_rate") is None:
        planner = "inconclusive"
    else:
        planner = "pass" if ps["non_fallback_rate"] >= 0.8 else "fail"
    if cg is None:
        chain = "inconclusive"
    elif not cg["chain_trace_present"]:
        chain = "inconclusive" if cg["chain_planned_unexecuted"] else "fail"
    else:
        chain = "pass" if cg["prior_link"] else "fail"
    values = {
        "recall_llm_ge_hardcoded": recall,
        "fpr_llm_le_hardcoded": fpr,
        "avg_findings_llm_ge_hardcoded": avg,
        "planner_non_fallback_ge_0_8": planner,
        "chain_9010_real": chain,
    }
    return {key: values[key] for key in CRITERION_KEYS}

_EMPTY_PLANNER_STATS = {
    "total": 0,
    "non_fallback_count": 0,
    "non_fallback_rate": None,
    "hallucination_rate": None,
    "hallucinated_count": 0,
    "degenerate_single_class": False,
}


def _planner_excerpt(decisions: list[dict] | None) -> str:
    """Compact planner-decision excerpt for the judge LLM (data, not prose)."""
    if not decisions:
        return "NO planner_decisions.json found; planner decision quality not assessed."
    return json.dumps(decisions[:200], ensure_ascii=False)[:4000]


def run_judge_m3(
    baseline_dir: Path,
    llm_dir: Path,
    out_dir: Path,
    judge_fn=None,
    judge_model: str = "",
) -> M3JudgeReport:
    """Run the full M3 acceptance pipeline for one hardcoded-vs-LLM A/B pair.

    Deterministic code computes the five criteria; ``judge_fn`` (the M3 LLM
    judge, built by the CLI) rules on ``chain_9010_real`` only. When
    ``judge_fn`` is None or returns None the report is assembled
    deterministically with verdict forced to "inconclusive" (HANDOFF_JUDGE
    decision 6: judge failure must not pretend pass/fail). Writes
    judge_report.json + judge_report.md under ``out_dir``.
    """
    from mcp_redteam.judge.m3 import M3JudgeInput

    expected = load_expected()
    expected_by_port = {e["port"]: e for e in expected["expected"]}
    hc = collect_eval_summary(baseline_dir, expected_by_port)
    llm = collect_eval_summary(llm_dir, expected_by_port)
    ports = sorted(set(hc["ports"]) & set(llm["ports"]))
    if not ports:
        raise ValueError(
            f"baseline and llm eval dirs share no port_* dirs: {baseline_dir} vs {llm_dir}"
        )
    metrics_hc = compute_metrics(hc, ports)
    metrics_llm = compute_metrics(llm, ports)
    decisions = load_planner_decisions(llm_dir)
    ps = planner_stats(decisions, llm) if decisions else _EMPTY_PLANNER_STATS
    cg = chain_gate(llm, decisions)
    criteria = compute_criteria(metrics_hc, metrics_llm, ps, cg)

    metrics: dict[str, float | int | None] = {
        "recall_hardcoded": metrics_hc["recall"],
        "recall_llm": metrics_llm["recall"],
        "fpr_hardcoded": metrics_hc["fpr"],
        "fpr_llm": metrics_llm["fpr"],
        "avg_findings_hardcoded": metrics_hc["avg_findings"],
        "avg_findings_llm": metrics_llm["avg_findings"],
        "planner_non_fallback_rate": ps["non_fallback_rate"],
        "planner_total_decisions": ps["total"],
        "hallucination_rate": ps["hallucination_rate"],
        "degenerate_single_class": int(ps["degenerate_single_class"]),
        "n_ports_compared": len(ports),
        "chain_trace_present": int(cg["chain_trace_present"]) if cg else 0,
        "chain_prior_link": int(cg["prior_link"]) if cg else 0,
    }
    evidence_refs = [
        str(baseline_dir / f"port_{p}" / "scan_result.json") for p in ports
    ] + [str(llm_dir / f"port_{p}" / "scan_result.json") for p in ports]
    if decisions is not None:
        evidence_refs.append(str(llm_dir / "planner_decisions.json"))

    inp = M3JudgeInput(
        hardcoded_summary=hc,
        llm_summary=llm,
        criteria=criteria,
        metrics=metrics,
        chain_excerpt=(cg["excerpt"] if cg else {"absent": True}),
        planner_excerpt=_planner_excerpt(decisions),
        planner_fallback_rate=(
            1.0 - ps["non_fallback_rate"] if ps["non_fallback_rate"] is not None else None
        ),
        evidence_refs=evidence_refs,
    )
    report = judge_fn(inp) if judge_fn is not None else None
    if report is None:
        report = M3JudgeReport(
            verdict="inconclusive",
            criteria=criteria,
            metrics=metrics,
            planner_fallback_rate=inp.planner_fallback_rate,
            evidence_refs=evidence_refs,
            reason=(
                "judge LLM unavailable; deterministic criteria recorded but no "
                "LLM ruling on chain_9010_real (verdict forced to inconclusive)"
            ),
            judge_model=judge_model,
            judge_tokens=0,
        )
    return report
