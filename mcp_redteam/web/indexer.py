"""Read-only indexer over runs/ artifacts for the eval platform.

Scans ``<runs_dir>/**/scan_result.json`` into compact :class:`RunSummary`
entries behind an mtime+size-keyed cache (only new/changed files are
re-parsed) and mirrors protocol-locked holdout ``summary.json`` files into
:class:`HoldoutSummaryView` projections. Strictly read-only: detail views
re-read the artifact on demand so the API always serves what is on disk.

Artifacts are historical data: a parse failure (truncated JSON, legacy
shape) skips the file and bumps :attr:`RunIndex.skipped` instead of
raising - a viewer must never 500 because one directory holds junk.
Summary projections tolerate old artifacts by design; the strict scan
contracts live in ``contracts.py`` and are enforced at write time.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from mcp_redteam.contracts import (
    FindingSummary,
    HoldoutPairView,
    HoldoutRunView,
    HoldoutSummaryView,
    RunMetrics,
    RunSummary,
)

_log = logging.getLogger(__name__)

SCAN_RESULT_NAME = "scan_result.json"
SUMMARY_NAME = "summary.json"


def _metrics_from_raw(raw: dict[str, Any], summary: RunSummary) -> RunMetrics:
    """Project one parsed scan_result.json into per-run process metrics.

    Counters only (Langfuse-style rollups): token sums, judge behaviour
    counts, per-class coverage. No verdict re-computation of any kind.
    """
    traces = [t for t in (raw.get("traces") or []) if isinstance(t, dict)]
    findings = [f for f in (raw.get("findings") or []) if isinstance(f, dict)]
    traces_by_class: dict[str, int] = {}
    for t in traces:
        vc = str(t.get("vuln_class", ""))
        if vc:
            traces_by_class[vc] = traces_by_class.get(vc, 0) + 1
    findings_by_class: dict[str, int] = {}
    findings_by_sev: dict[str, int] = {}
    for f in findings:
        vc = str(f.get("vuln_class", ""))
        if vc:
            findings_by_class[vc] = findings_by_class.get(vc, 0) + 1
        sev = str(f.get("severity", ""))
        if sev:
            findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1
    l2_total = l2_steered = ev_total = ev_finding = hallucinated = 0
    ev_conf_sum = 0.0
    tokens_in = tokens_out = 0
    ev_finding_by_class: dict[str, int] = {}
    for t in traces:
        tokens_in += int(t.get("tokens_in") or 0)
        tokens_out += int(t.get("tokens_out") or 0)
        if t.get("suspected_hallucination"):
            hallucinated += 1
        jv = t.get("judge_verdict")
        if isinstance(jv, dict):
            l2_total += 1
            if jv.get("steered"):
                l2_steered += 1
        lv = t.get("llm_evidence_verdict")
        if isinstance(lv, dict):
            ev_total += 1
            if lv.get("is_finding"):
                ev_finding += 1
                ev_conf_sum += float(lv.get("confidence") or 0.0)
                vc = str(lv.get("vuln_class") or t.get("vuln_class") or "")
                if vc:
                    ev_finding_by_class[vc] = ev_finding_by_class.get(vc, 0) + 1
    return RunMetrics(
        run_id=summary.run_id,
        scan_dir=summary.scan_dir,
        experiment=summary.experiment,
        started_at=summary.started_at,
        attacker_model=summary.attacker_model,
        evidence_judge_model=summary.evidence_judge_model,
        stop_reason=summary.stop_reason,
        wall_seconds=summary.wall_seconds,
        attacker_tokens=summary.attacker_tokens,
        judge_tokens=summary.judge_tokens,
        attacker_tokens_effective=int(raw.get("attacker_tokens_effective") or 0),
        trace_count=summary.trace_count,
        findings_count=summary.findings_count,
        static_hits_count=summary.static_hits_count,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        traces_by_vuln_class=traces_by_class,
        findings_by_vuln_class=findings_by_class,
        findings_by_severity=findings_by_sev,
        evidence_finding_by_vuln_class=ev_finding_by_class,
        l2_total=l2_total,
        l2_steered=l2_steered,
        evidence_total=ev_total,
        evidence_finding=ev_finding,
        evidence_conf_sum=ev_conf_sum,
        hallucinated=hallucinated,
    )


def _summary_from_raw(
    raw: dict[str, Any], scan_dir: str
) -> tuple[RunSummary, list[FindingSummary], RunMetrics]:
    """Project one parsed scan_result.json into summary + findings + metrics.

    Raises on structurally unusable files (no run_id / not a dict); every
    other missing field degrades to its default so historical artifacts
    still index.
    """
    run_id = str(raw["run_id"])
    summary = RunSummary(
        run_id=run_id,
        scan_dir=scan_dir,
        experiment=scan_dir.split("/", 1)[0],
        target=str(raw.get("sse_url", "")),
        transport=str(raw.get("transport", "")),
        started_at=str(raw.get("started_at", "")),
        wall_seconds=float(raw.get("wall_seconds") or 0.0),
        attacker_tokens=int(raw.get("attacker_tokens") or 0),
        judge_tokens=int(raw.get("judge_tokens") or 0),
        total_tokens=int(raw.get("total_tokens") or 0),
        stop_reason=str(raw.get("stop_reason", "")),
        findings_count=len(raw.get("findings") or []),
        trace_count=len(raw.get("traces") or []),
        static_hits_count=len(raw.get("static_hits") or []),
        attacker_model=str(raw.get("attacker_model", "")),
        evidence_judge_model=str(raw.get("evidence_judge_model", "")),
        git_sha=str(raw.get("git_sha", "")),
    )
    findings: list[FindingSummary] = []
    for f in raw.get("findings") or []:
        if not isinstance(f, dict):
            continue
        findings.append(
            FindingSummary(
                finding_id=str(f.get("finding_id", "")),
                run_id=run_id,
                scan_dir=scan_dir,
                vuln_class=str(f.get("vuln_class", "")),
                severity=str(f.get("severity", "")),
                confidence=float(f.get("confidence") or 0.0),
                title=str(f.get("title", "")),
                target=str(f.get("target", "")),
            )
        )
    metrics = _metrics_from_raw(raw, summary)
    return summary, findings, metrics


class RunIndex:
    """In-memory mtime cache of RunSummary + FindingSummary projections.

    ``refresh()`` stats every scan_result.json under the runs root and
    re-parses only files whose mtime or size changed. Guarded by a lock so
    concurrent endpoint calls cannot interleave cache rebuilds.
    """

    def __init__(self, runs_dir: Path) -> None:
        self.runs_dir = Path(runs_dir)
        self._lock = threading.Lock()
        # scan_dir -> (mtime, size, RunSummary, [FindingSummary, ...], RunMetrics)
        self._cache: dict[
            str, tuple[float, int, RunSummary, list[FindingSummary], RunMetrics]
        ] = {}
        self.skipped = 0
        self.parses = 0

    def refresh(self) -> None:
        """Re-stat the runs root and re-parse changed artifacts."""
        with self._lock:
            self.skipped = 0
            seen: set[str] = set()
            if not self.runs_dir.is_dir():
                self._cache.clear()
                return
            for path in self.runs_dir.rglob(SCAN_RESULT_NAME):
                scan_dir = path.parent.relative_to(self.runs_dir).as_posix()
                seen.add(scan_dir)
                try:
                    st = path.stat()
                except OSError:
                    continue
                cached = self._cache.get(scan_dir)
                if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
                    continue
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                    summary, findings, metrics = _summary_from_raw(raw, scan_dir)
                except (OSError, ValueError, KeyError, TypeError):
                    # 历史产物容错：截断 JSON / 缺 run_id / 字段类型漂移都跳过。
                    self.skipped += 1
                    self._cache.pop(scan_dir, None)
                    _log.warning("eval platform: skipping unparseable %s", path)
                    continue
                self.parses += 1
                self._cache[scan_dir] = (
                    st.st_mtime,
                    st.st_size,
                    summary,
                    findings,
                    metrics,
                )
            for gone in set(self._cache) - seen:
                del self._cache[gone]

    def summaries(self) -> list[RunSummary]:
        """All cached run summaries, newest first."""
        items = [c[2] for c in self._cache.values()]
        return sorted(items, key=lambda s: (s.started_at, s.run_id), reverse=True)

    def findings(self) -> list[FindingSummary]:
        """All cached finding projections, newest run first."""
        items = [f for c in self._cache.values() for f in c[3]]
        return sorted(items, key=lambda f: (f.run_id, f.finding_id), reverse=True)

    def metrics(self) -> list[RunMetrics]:
        """All cached per-run metrics, newest first."""
        return sorted(
            (c[4] for c in self._cache.values()),
            key=lambda m: (m.started_at, m.run_id),
            reverse=True,
        )

    def _resolve(self, run_id: str) -> RunSummary | None:
        matches = [c[2] for c in self._cache.values() if c[2].run_id == run_id]
        if not matches:
            return None
        return max(matches, key=lambda s: s.started_at)

    def detail(self, run_id: str) -> dict[str, Any] | None:
        """Full artifact bundle for one run, re-read fresh from disk."""
        summary = self._resolve(run_id)
        if summary is None:
            return None
        scan_path = self.runs_dir / Path(summary.scan_dir) / SCAN_RESULT_NAME
        try:
            scan_result = json.loads(scan_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            scan_result = None
        findings_artifact = None
        findings_path = scan_path.parent / "findings.json"
        if findings_path.exists():
            try:
                findings_artifact = json.loads(findings_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                findings_artifact = None
        artifact_dir = scan_path.parent
        poc_files = sorted(p.name for p in artifact_dir.glob("poc/*.py"))
        return {
            "summary": summary.model_dump(),
            "scan_result": scan_result,
            "findings_artifact": findings_artifact,
            "poc_files": poc_files,
            "has_benchmark": (artifact_dir / "benchmark.md").exists(),
        }

    def compare(self, run_ids: list[str]) -> list[dict[str, Any]]:
        """Side-by-side projection for the requested run ids (order kept)."""
        columns: list[dict[str, Any]] = []
        for run_id in run_ids:
            summary = self._resolve(run_id)
            if summary is None:
                columns.append({"run_id": run_id, "missing": True})
                continue
            run_findings = [
                f.model_dump()
                for f in self.findings()
                if f.run_id == run_id
            ]
            columns.append(
                {"summary": summary.model_dump(), "findings": run_findings}
            )
        return columns

    def holdout(self) -> list[HoldoutSummaryView]:
        """Mirror every protocol-locked holdout summary.json, newest first.

        Only files carrying ``protocol_version`` are holdout summaries;
        other experiments write same-named files with different shapes.
        """
        views: list[HoldoutSummaryView] = []
        if not self.runs_dir.is_dir():
            return views
        for path in self.runs_dir.rglob(SUMMARY_NAME):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(raw, dict) or "protocol_version" not in raw:
                    continue
                views.append(_holdout_view_from_raw(
                    raw, path.parent.relative_to(self.runs_dir).as_posix()
                ))
            except (OSError, ValueError, KeyError, TypeError):
                _log.warning("eval platform: skipping unparseable %s", path)
                continue
        return sorted(views, key=lambda v: v.source)


def _holdout_view_from_raw(raw: dict[str, Any], source: str) -> HoldoutSummaryView:
    """Copy a holdout summary.json verbatim into its view projection."""
    pairs = []
    for p in raw.get("pairs") or []:
        if not isinstance(p, dict):
            continue
        runs = [
            HoldoutRunView(
                index=int(r.get("index") or 0),
                status=str(r.get("status", "")),
                positive_detected=bool(r.get("positive_detected")),
                fixed_clean=bool(r.get("fixed_clean")),
                control_replay_passed=bool(r.get("control_replay_passed")),
                reasons=[str(x) for x in (r.get("reasons") or [])],
            )
            for r in (p.get("runs") or [])
            if isinstance(r, dict)
        ]
        pairs.append(
            HoldoutPairView(
                pair_id=str(p.get("pair_id", "")),
                split=str(p.get("split", "")),
                passed=int(p.get("passed") or 0),
                total=int(p.get("total") or 0),
                rate=float(p.get("rate") or 0.0),
                ci95=[float(x) for x in (p.get("ci95") or [])],
                status=str(p.get("status", "")),
                runs=runs,
            )
        )
    return HoldoutSummaryView(
        source=source,
        protocol_version=int(raw.get("protocol_version") or 1),
        protocol_sha256=str(raw.get("protocol_sha256", "")),
        repeats=int(raw.get("repeats") or 0),
        status=str(raw.get("status", "")),
        pairs=pairs,
    )
