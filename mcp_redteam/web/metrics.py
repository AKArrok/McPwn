"""Pandas aggregation layer for the data platform (``/api/metrics``).

Inspect-AI-style analysis path: flattened per-run metrics -> DataFrame ->
group/sum by dimension (Langfuse's dimension rollups, MLflow's run-grouped
aggregations). SUMS ONLY: no verdict re-computation and no pass-rate math
anywhere in this module - verdict numbers stay verbatim in holdout summary
artifacts, which is a hard boundary of the web layer.

``tokens_per_finding`` is computed on RAW attacker tokens (uniform across
historical artifacts); cache-effective totals are reported separately in
``tokens_effective`` (zero for artifacts predating the field).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pandas as pd

from mcp_redteam.contracts import GroupMetric, MetricsBundle, RunMetrics

_FALLBACK_LABEL = "(未记录)"


def _to_row(label: str, g: pd.Series) -> GroupMetric:
    findings = int(g["findings"])
    attacker = int(g["attacker_tokens"])
    return GroupMetric(
        label=label,
        runs=int(g["runs"]),
        findings=findings,
        traces=int(g["traces"]),
        attacker_tokens=attacker,
        judge_tokens=int(g["judge_tokens"]),
        tokens_effective=int(g["tokens_effective"]),
        tokens_per_finding=round(attacker / findings, 1) if findings else 0.0,
        evidence_finding=int(g["evidence_finding"]),
        hallucinated=int(g["hallucinated"]),
    )


def _scalar_rows(df: pd.DataFrame, dim: str, *, desc: bool = True) -> list[GroupMetric]:
    if df.empty:
        return []
    g = df.groupby(dim).agg(
        runs=("run_id", "count"),
        findings=("findings", "sum"),
        traces=("traces", "sum"),
        attacker_tokens=("attacker_tokens", "sum"),
        judge_tokens=("judge_tokens", "sum"),
        tokens_effective=("tokens_effective", "sum"),
        evidence_finding=("evidence_finding", "sum"),
        hallucinated=("hallucinated", "sum"),
    )
    g = g.sort_values(["findings", "attacker_tokens"], ascending=(not desc, not desc))
    return [_to_row(str(label), g.loc[label]) for label in g.index]


def _vuln_class_rows(metrics: list[RunMetrics]) -> list[GroupMetric]:
    """Coverage matrix per VulnClass: probes, findings, evidence hits, runs."""
    traces: dict[str, int] = {}
    findings: dict[str, int] = {}
    evidence: dict[str, int] = {}
    runs: dict[str, int] = {}
    for m in metrics:
        touched = set(m.traces_by_vuln_class) | set(m.findings_by_vuln_class)
        for vc in touched:
            runs[vc] = runs.get(vc, 0) + 1
        for vc, n in m.traces_by_vuln_class.items():
            traces[vc] = traces.get(vc, 0) + n
        for vc, n in m.findings_by_vuln_class.items():
            findings[vc] = findings.get(vc, 0) + n
        for vc, n in m.evidence_finding_by_vuln_class.items():
            evidence[vc] = evidence.get(vc, 0) + n
    labels = sorted(
        set(traces) | set(findings) | set(evidence),
        key=lambda vc: (-(traces.get(vc, 0) + evidence.get(vc, 0)), vc),
    )
    return [
        GroupMetric(
            label=vc,
            runs=runs.get(vc, 0),
            traces=traces.get(vc, 0),
            findings=findings.get(vc, 0),
            evidence_finding=evidence.get(vc, 0),
        )
        for vc in labels
    ]


def build_metrics_bundle(metrics: list[RunMetrics], skipped: int) -> MetricsBundle:
    """Aggregate per-run metrics into every dimension rollup at once."""
    rows = [m.model_dump() for m in metrics]
    if rows:
        df = pd.DataFrame(rows)
        df["date"] = [str(x)[:10] for x in df["started_at"]]
        # Contract field names -> aggregate column names.
        df["tokens_effective"] = df["attacker_tokens_effective"].fillna(0).astype(int)
        df["findings"] = df["findings_count"]
        df["traces"] = df["trace_count"]
        # Empty labels get an explicit fallback so group keys stay readable.
        for col in ("attacker_model", "evidence_judge_model", "stop_reason"):
            df[col] = df[col].replace("", _FALLBACK_LABEL)
    else:
        df = pd.DataFrame(
            columns=[
                "run_id",
                "experiment",
                "attacker_model",
                "evidence_judge_model",
                "stop_reason",
                "date",
                "findings",
                "traces",
                "attacker_tokens",
                "judge_tokens",
                "tokens_effective",
                "evidence_finding",
                "hallucinated",
            ]
        )

    def _group(dim: str, *, desc: bool = True) -> list[GroupMetric]:
        if df.empty:
            return []
        return _scalar_rows(df, dim, desc=desc)

    dates = sorted({str(m.started_at)[:10] for m in metrics if m.started_at})
    summary = GroupMetric(
        label="全部运行",
        runs=len(metrics),
        findings=int(df["findings"].sum()) if not df.empty else 0,
        traces=int(df["traces"].sum()) if not df.empty else 0,
        attacker_tokens=int(df["attacker_tokens"].sum()) if not df.empty else 0,
        judge_tokens=int(df["judge_tokens"].sum()) if not df.empty else 0,
        tokens_effective=int(df["tokens_effective"].sum()) if not df.empty else 0,
        tokens_per_finding=(
            round(int(df["attacker_tokens"].sum()) / int(df["findings"].sum()), 1)
            if not df.empty and int(df["findings"].sum())
            else 0.0
        ),
        evidence_finding=int(df["evidence_finding"].sum()) if not df.empty else 0,
        hallucinated=int(df["hallucinated"].sum()) if not df.empty else 0,
    )
    return MetricsBundle(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        run_count=len(metrics),
        skipped=skipped,
        date_min=dates[0] if dates else "",
        date_max=dates[-1] if dates else "",
        summary=summary,
        by_experiment=_group("experiment"),
        by_model=_group("attacker_model"),
        by_judge=_group("evidence_judge_model"),
        by_date=sorted(_group("date"), key=lambda r: r.label),
        by_stop_reason=_group("stop_reason"),
        by_vuln_class=_vuln_class_rows(metrics),
    )


def bundle_to_dict(bundle: MetricsBundle) -> dict[str, Any]:
    """JSON-ready payload for the API and the static snapshot data.js."""
    return bundle.model_dump()
