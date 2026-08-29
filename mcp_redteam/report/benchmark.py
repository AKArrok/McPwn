"""Per-target benchmark report: ScanResult -> <out_dir>/benchmark.md.

One document per scanned target (user decision 2026-08-29). The report is a
self-contained scorecard for that run: vuln-class coverage across the fixed
8-class taxonomy, signal/finding stats, budget & efficiency numbers, and —
when the target maps to a ``eval/targets/manifest.yaml`` entry — the
manifest expectation verdict (PASS/FAIL/INFO, same grammar as the manifest
runner).

Expectation grammar lives here (``expect_ok``) so eval runners and this
report can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_redteam.contracts import (
    FINDING_CONFIDENCE_THRESHOLD,
    SEVERITY_ORDER,
    ScanResult,
    VulnClass,
)


@dataclass(frozen=True)
class ManifestVerdict:
    """What the manifest says this target SHOULD do (decoupled from eval)."""

    name: str
    label: str = ""
    baseline_expect: str = "info"  # "0" | ">=1" | "info"
    llm_expect: str = "info"
    prove: bool = False
    prove_script: str = ""

    def expect_for(self, mode: str) -> str:
        return self.llm_expect if mode == "llm" else self.baseline_expect


def expect_ok(expect: str, findings: int) -> bool:
    """Manifest expectation grammar: 0 | >=1 | info (never fails)."""
    if expect == "info":
        return True
    if expect == "0":
        return findings == 0
    if expect == ">=1":
        return findings >= 1
    raise ValueError(f"unknown expectation {expect!r}")


def _fmt_ratio(used: float, limit: int | None) -> str:
    if not limit:
        return f"{used:,.0f}"
    return f"{used:,.0f} / {limit:,} ({used / limit:.0%})"


def build_benchmark(
    result: ScanResult,
    *,
    entry: ManifestVerdict | None = None,
    max_tokens: int | None = None,
    wall_seconds: int | None = None,
    mode: str = "std",
) -> str:
    """Render the per-target benchmark markdown for one ScanResult."""
    findings = result.findings
    lines: list[str] = []
    lines.append(f"# Benchmark — {result.sse_url}")
    lines.append("")
    lines.append(f"- **run_id**: `{result.run_id}`")
    lines.append(f"- **transport**: `{result.transport}`")
    lines.append(f"- **mode**: {mode}")
    lines.append(f"- **started**: {result.started_at}")
    lines.append(f"- **attacker model**: {result.attacker_model or 'n/a'}")
    if result.git_sha:
        lines.append(f"- **git_sha**: `{result.git_sha}`")
    if result.seed is not None:
        lines.append(f"- **seed**: {result.seed}")
    lines.append("")

    # ── verdict (manifest expectation) ──────────────────────────────────────
    if entry is not None:
        expect = entry.expect_for(mode)
        ok = expect_ok(expect, len(findings))
        verdict = "INFO (仅记录)" if expect == "info" else ("✅ PASS" if ok else "❌ FAIL")
        lines.append("## 判定")
        lines.append("")
        lines.append("| 字段 | 值 |")
        lines.append("|---|---|")
        lines.append(f"| 靶场 | {entry.name}{' — ' + entry.label if entry.label else ''} |")
        lines.append(f"| 期望 ({mode}) | `{expect}` |")
        lines.append(f"| 实际 findings | {len(findings)} |")
        lines.append(f"| 判定 | {verdict} |")
        if entry.prove and entry.prove_script:
            lines.append(f"| prove 脚本 | `{entry.prove_script}` |")
        lines.append("")

    # ── results overview ────────────────────────────────────────────────────
    top_sev = max(
        (f.severity for f in findings),
        key=SEVERITY_ORDER.index,
        default=None,
    )
    all_signals = [s for f in findings for s in f.signals]
    by_sev = {sev: 0 for sev in SEVERITY_ORDER}
    for s in all_signals:
        by_sev[s.severity] += 1
    n_traces = len(result.traces)
    hallucinated = sum(1 for t in result.traces if t.suspected_hallucination)

    lines.append("## 结果概览")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| findings | {len(findings)} |")
    lines.append(f"| 最高严重级 | {top_sev or '—'} |")
    lines.append("| 信号命中 (L1) | "
                 + ", ".join(f"{sev}×{n}" for sev, n in by_sev.items() if n)
                 + f" (共 {len(all_signals)}) |")
    lines.append(f"| 执行 trace 数 | {n_traces} |")
    if hallucinated:
        lines.append(f"| 疑似幻觉 trace | {hallucinated} (诊断项, 非发现) |")
    lines.append(f"| stop_reason | `{result.stop_reason}` |")
    lines.append("")

    # ── vuln-class coverage (fixed 8-class taxonomy) ────────────────────────
    lines.append("## 漏洞类覆盖")
    lines.append("")
    lines.append("| 漏洞类 | trace | finding | 最高置信度 |")
    lines.append("|---|---|---|---|")
    for cls in VulnClass:
        traces = [t for t in result.traces if t.vuln_class is cls]
        cls_findings = [f for f in findings if f.vuln_class is cls]
        conf = max((f.confidence for f in cls_findings), default=0.0)
        lines.append(
            f"| {cls.value} | {len(traces)} | {len(cls_findings)} | "
            f"{conf:.2f}{'' if conf else ' —'} |"
        )
    lines.append("")

    # ── budget & efficiency ─────────────────────────────────────────────────
    lines.append("## 预算与效率")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| attacker tokens | {_fmt_ratio(result.attacker_tokens, max_tokens)}"
                 + (f" (上限 {max_tokens:,}) |" if max_tokens else " |"))
    lines.append(f"| judge tokens (独立计数) | {result.judge_tokens:,} |")
    lines.append(f"| wall time | {_fmt_ratio(result.wall_seconds, wall_seconds)}"
                 + (f" (上限 {wall_seconds}s) |" if wall_seconds else " |"))
    lines.append(f"| tokens / trace | {result.attacker_tokens / n_traces:,.0f} |"
                 if n_traces else "| tokens / trace | — |")
    lines.append(f"| tokens / finding | {result.attacker_tokens / len(findings):,.0f} |"
                 if findings else "| tokens / finding | — |")
    lines.append("")

    # ── findings summary (id + class + title) ───────────────────────────────
    if findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| finding | 类 | 严重级 | 置信度 | 标题 |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(findings, key=lambda x: (-x.confidence)):
            lines.append(
                f"| `{f.finding_id}` | {f.vuln_class.value} | {f.severity} | "
                f"{f.confidence:.2f} | {f.title} |"
            )
        lines.append("")
        lines.append(f"> 置信度闸门: {FINDING_CONFIDENCE_THRESHOLD} (HANDOFF §5);"
                     "详细证据见 findings.md / traces/。")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_benchmark(
    result: ScanResult,
    out_dir: Path,
    *,
    entry: ManifestVerdict | None = None,
    max_tokens: int | None = None,
    wall_seconds: int | None = None,
    mode: str = "std",
) -> Path:
    """Write <out_dir>/benchmark.md. Return the path."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "benchmark.md"
    path.write_text(
        build_benchmark(
            result,
            entry=entry,
            max_tokens=max_tokens,
            wall_seconds=wall_seconds,
            mode=mode,
        ),
        encoding="utf-8",
    )
    return path
