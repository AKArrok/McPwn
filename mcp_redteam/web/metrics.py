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

from mcp_redteam.contracts import (
    GroupMetric,
    MetricsBundle,
    Recommendation,
    RunMetrics,
)

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


# Recommendation thresholds. Each rule fires only above an explicit bar so
# a healthy repo produces zero noise; every suggestion cites its numbers.
BUDGET_TRUNCATED_SHARE = 0.40
LOW_YIELD_RATE = 0.30
LOW_YIELD_MIN_PROBES = 20
JUDGE_SHARE_HIGH = 0.10
SLOW_EXPERIMENT_FACTOR = 2.0
SLOW_EXPERIMENT_MIN_RUNS = 5


def _recommendations(
    metrics: list[RunMetrics],
    summary: GroupMetric,
    by_stop_reason: list[GroupMetric],
    by_vuln_class: list[GroupMetric],
    by_experiment: list[GroupMetric],
) -> list[Recommendation]:
    """Data-grounded optimization directions (analysis → action pointers).

    The web layer stops at directions: it cites the numbers, names the
    validated remedy when one exists (e.g. the trace-cap experiments), and
    never applies anything or touches verdict semantics.
    """
    out: list[Recommendation] = []
    if summary.runs == 0:
        return out
    # 1. Budget-truncated runs dominate and cost more per finding.
    truncated = {g.label: g for g in by_stop_reason}.get("budget_tokens")
    completed = {g.label: g for g in by_stop_reason}.get("completed")
    if truncated and truncated.runs / summary.runs >= BUDGET_TRUNCATED_SHARE:
        pct = round(truncated.runs / summary.runs * 100)
        if completed and completed.tokens_per_finding:
            delta = round(
                (truncated.tokens_per_finding / completed.tokens_per_finding - 1) * 100
            )
            cost = f"，截断态 tok/finding {truncated.tokens_per_finding:,.0f} 比完成态 {completed.tokens_per_finding:,.0f} 贵 {delta}%"
        else:
            cost = ""
        out.append(
            Recommendation(
                label="预算截断占比过高",
                evidence=f"budget_tokens {truncated.runs}/{summary.runs} runs（{pct}%）{cost}",
                action="参照 trace_budget_dvmcp_v5/v9 已验证配置（trace cap 40% + 上下文压缩，"
                "tok/finding 12,301→9,080，-26% 且 findings 不降）；评估是否适用于当前预算计划",
                priority="high",
            )
        )
    # 2. Low-yield vuln classes with heavy probing.
    for g in by_vuln_class:
        if g.traces < LOW_YIELD_MIN_PROBES:
            continue
        rate = g.findings / g.traces if g.traces else 0.0
        if rate < LOW_YIELD_RATE:
            out.append(
                Recommendation(
                    label=f"{g.label} 产出率偏低",
                    evidence=f"{g.traces} 次探查仅 {g.findings} 发现（产出率 {round(rate * 100)}%），"
                    f"证据判定命中 {g.evidence_finding}",
                    action="评审该类的信号覆盖与策略卡执行步骤；若属已知边界（如 indirect_injection "
                    "的 L2 gap），记入对应实验线而非改判据",
                    priority="medium",
                )
            )
    # 3. Judge token share.
    if summary.attacker_tokens and summary.judge_tokens / summary.attacker_tokens > JUDGE_SHARE_HIGH:
        pct = round(summary.judge_tokens / summary.attacker_tokens * 100)
        out.append(
            Recommendation(
                label="judge 开销占比偏高",
                evidence=f"judge {summary.judge_tokens:,} tok = 攻击侧的 {pct}%（judge_tokens 为 "
                "prompt+completion 总口径）",
                action="评审 judge 侧 prompt 构成（evidence judge system 模板 + trace 序列化）；"
                "调整后必须用真实重跑验证 verdict 一致",
                priority="low",
            )
        )
    # 4. Hallucination markers need human review.
    if summary.hallucinated > 0:
        out.append(
            Recommendation(
                label="存在幻觉标记",
                evidence=f"{summary.hallucinated} 条 trace 的 attacker 声称外传/读取但证据未落地"
                "（grounding 闸门已拦截，未计入 findings）",
                action="人工复核对应 trace 的 final_llm_output；若集中在同一实验，评估其提示词",
                priority="high",
            )
        )
    # 5. Error-terminated runs.
    errored = {g.label: g for g in by_stop_reason}.get("error")
    if errored and errored.runs > 0:
        out.append(
            Recommendation(
                label="存在 error 终止的运行",
                evidence=f"{errored.runs} 个 run 以 error 停止、0 findings",
                action="检查 runs/ 对应目录内的日志与部分产物（连接失败/SDK 异常各占多少）",
                priority="medium",
            )
        )
    # 6. Experiment lines far below global efficiency.
    if summary.tokens_per_finding:
        for g in by_experiment:
            if (
                g.runs >= SLOW_EXPERIMENT_MIN_RUNS
                and g.findings > 0
                and g.tokens_per_finding > summary.tokens_per_finding * SLOW_EXPERIMENT_FACTOR
            ):
                out.append(
                    Recommendation(
                        label=f"实验线 {g.label} 单位产出偏低",
                        evidence=f"{g.runs} runs / {g.findings} findings，tok/finding "
                        f"{g.tokens_per_finding:,.0f} = 全局（{summary.tokens_per_finding:,.0f}）的 "
                        f"{round(g.tokens_per_finding / summary.tokens_per_finding)} 倍",
                        action="对照全局最优实验（by_experiment 按 tok/finding 排序头部）拆解差距来源；"
                        "实验线结论归实验线，不回灌主链路默认值",
                        priority="low",
                    )
                )
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda r: (order[r.priority], r.label))[:8]


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
        recommendations=_recommendations(
            metrics, summary, _group("stop_reason"), _vuln_class_rows(metrics), _group("experiment")
        ),
    )


def bundle_to_dict(bundle: MetricsBundle) -> dict[str, Any]:
    """JSON-ready payload for the API and the static snapshot data.js."""
    return bundle.model_dump()
