"""Unit tests for the deterministic M3 acceptance judge (eval/dvmcp/m3_judge.py).

Covers load_expected, collect_eval_summary, compute_metrics (subset + FP
counting), load_planner_decisions, planner_stats, chain_gate, and the five
locked compute_criteria branches. Uses tests/fixtures/m3_builder.py for
scenario fixtures and hand-built dicts for fine-grained unit cases.
"""
from __future__ import annotations

import json

import pytest

from eval.dvmcp.m3_judge import (
    chain_gate,
    collect_eval_summary,
    compute_criteria,
    compute_metrics,
    load_expected,
    load_planner_decisions,
    planner_stats,
)
from tests.fixtures.m3_builder import build_m3_fixture, expected_by_port

_PORTS = [9001, 9006, 9010]

_CRITERIA_KEYS = {
    "recall_llm_ge_hardcoded",
    "fpr_llm_le_hardcoded",
    "chain_9010_real",
    "avg_findings_llm_ge_hardcoded",
    "planner_non_fallback_ge_0_8",
}


def _metrics(**overrides: object) -> dict:
    data = {
        "n_ports": 3,
        "recall": 1.0,
        "fpr": 0.0,
        "avg_findings": 1.0,
        "total_findings": 3,
        "hit_ports": 3,
    }
    data.update(overrides)
    return data


def _ps(rate: float | None = 1.0) -> dict:
    return {
        "total": 3,
        "non_fallback_count": 3,
        "non_fallback_rate": rate,
        "hallucination_rate": 0.0,
        "hallucinated_count": 0,
        "degenerate_single_class": False,
    }


# ── load_expected ───────────────────────────────────────────────────────────


def test_load_expected_reads_yaml():
    data = load_expected()
    expected = {e["port"]: e for e in data["expected"]}
    assert {9001, 9006, 9010} <= set(expected)
    assert "leaks_api_key_shape" in expected[9001]["expected_signals"]
    assert "chain_composition" == expected[9010]["primary_class"]


# ── collect_eval_summary ────────────────────────────────────────────────────


def test_collect_eval_summary_fields(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    summary = collect_eval_summary(root / "llm", expected_by_port())
    ports = summary["ports"]
    assert set(ports) == {9001, 9006, 9010}
    p = ports[9001]
    assert p["tools_seen"] == ["get_user_info"]
    assert p["resources_seen"] == ["internal://credentials"]
    assert p["n_findings"] == 1
    assert p["finding_signal_ids"] == [["leaks_api_key_shape"]]
    assert p["hit"] is True
    assert p["expected_signals"] == ["leaks_api_key_shape"]
    assert ports[9010]["traces"][0]["vuln_class"] == "chain_composition"
    assert ports[9010]["traces"][0]["attack_calls"][0]["name"] == "internal://credentials"


def test_collect_eval_summary_skips_missing_scan(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    (root / "llm" / "port_9999").mkdir(parents=True, exist_ok=True)
    summary = collect_eval_summary(root / "llm", expected_by_port())
    assert 9999 not in summary["ports"]


# ── compute_metrics ─────────────────────────────────────────────────────────


def test_compute_metrics_subset_only(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    hc = collect_eval_summary(root / "baseline", expected_by_port())
    m = compute_metrics(hc, [9001, 9006])
    assert m == {
        "n_ports": 2,
        "recall": 1.0,
        "fpr": 0.0,
        "avg_findings": 1.0,
        "total_findings": 2,
        "hit_ports": 2,
    }


def test_compute_metrics_fp_counting(tmp_path):
    root = build_m3_fixture(tmp_path, "llm_worse_recall")
    llm = collect_eval_summary(root / "llm", expected_by_port())
    m = compute_metrics(llm, _PORTS)
    assert m["n_ports"] == 3
    assert m["hit_ports"] == 2
    assert m["total_findings"] == 3
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(1 / 3)
    assert m["avg_findings"] == 1.0


def test_compute_metrics_empty_subset():
    assert compute_metrics({"ports": {}}, [])["n_ports"] == 0
    assert compute_metrics({"ports": {}}, [])["recall"] == 0.0
    assert compute_metrics({"ports": {}}, [])["fpr"] == 0.0
    assert compute_metrics({"ports": {}}, [])["avg_findings"] == 0.0


# ── load_planner_decisions ──────────────────────────────────────────────────


def test_load_planner_decisions_missing_unparseable_empty(tmp_path):
    root = build_m3_fixture(tmp_path, "no_planner_decisions")
    llm = root / "llm"
    assert load_planner_decisions(llm) is None
    (llm / "planner_decisions.json").write_text("not json", encoding="utf-8")
    assert load_planner_decisions(llm) is None
    (llm / "planner_decisions.json").write_text(
        json.dumps({"decisions": []}), encoding="utf-8"
    )
    assert load_planner_decisions(llm) is None
    (llm / "planner_decisions.json").write_text(
        json.dumps({"decisions": [{"port": 9001}]}), encoding="utf-8"
    )
    assert load_planner_decisions(llm) == [{"port": 9001}]


def test_load_planner_decisions_valid(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    decisions = load_planner_decisions(root / "llm")
    assert decisions is not None
    assert len(decisions) == 3
    assert all(d["source"] == "llm" for d in decisions)


# ── planner_stats ───────────────────────────────────────────────────────────


def test_planner_stats_all_llm_no_hallucination(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    summary = collect_eval_summary(root / "llm", expected_by_port())
    decisions = load_planner_decisions(root / "llm")
    stats = planner_stats(decisions or [], summary)
    assert stats["total"] == 3
    assert stats["non_fallback_count"] == 3
    assert stats["non_fallback_rate"] == 1.0
    assert stats["hallucinated_count"] == 0
    assert stats["hallucination_rate"] == 0.0
    assert stats["degenerate_single_class"] is False


def test_planner_stats_empty_rates_none():
    stats = planner_stats([], {"ports": {}})
    assert stats["total"] == 0
    assert stats["non_fallback_count"] == 0
    assert stats["non_fallback_rate"] is None
    assert stats["hallucinated_count"] == 0
    assert stats["hallucination_rate"] is None
    assert stats["degenerate_single_class"] is False


def test_planner_stats_hallucination_and_degenerate(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    summary = collect_eval_summary(root / "llm", expected_by_port())
    decisions = [
        {
            "port": 9001,
            "vuln_class": "direct_prompt_injection",
            "target": "nonexistent://uri",
            "source": "llm",
            "planned": True,
            "executed": True,
            "skip_reason": None,
        }
        for _ in range(5)
    ]
    stats = planner_stats(decisions, summary)
    assert stats["total"] == 5
    assert stats["non_fallback_rate"] == 1.0
    assert stats["hallucinated_count"] == 5
    assert stats["hallucination_rate"] == 1.0
    assert stats["degenerate_single_class"] is True


def test_planner_stats_comma_target_exempt_from_hallucination():
    summary = {"ports": {9010: {"tools_seen": [], "resources_seen": []}}}
    decisions = [
        {
            "port": 9010,
            "vuln_class": "chain_composition",
            "target": "resource:a,tool:b",
            "source": "llm",
            "planned": True,
            "executed": True,
            "skip_reason": None,
        }
    ]
    stats = planner_stats(decisions, summary)
    assert stats["hallucinated_count"] == 0
    assert stats["hallucination_rate"] == 0.0


# ── compute_criteria (fine-grained branches) ────────────────────────────────


def test_compute_criteria_returns_locked_keys():
    criteria = compute_criteria(_metrics(), _metrics(), _ps(), None)
    assert set(criteria) == _CRITERIA_KEYS


def test_compute_criteria_recall_equal_higher_lower():
    hc = _metrics(recall=0.8)
    key = "recall_llm_ge_hardcoded"
    assert compute_criteria(hc, _metrics(recall=0.8), _ps(), None)[key] == "pass"
    assert compute_criteria(hc, _metrics(recall=0.9), _ps(), None)[key] == "pass"
    assert compute_criteria(hc, _metrics(recall=0.7), _ps(), None)[key] == "fail"


def test_compute_criteria_fpr_zero_nonzero():
    hc = _metrics(fpr=0.0)
    assert compute_criteria(hc, _metrics(fpr=0.0), _ps(), None)["fpr_llm_le_hardcoded"] == "pass"
    assert compute_criteria(hc, _metrics(fpr=0.1), _ps(), None)["fpr_llm_le_hardcoded"] == "fail"
    key = "fpr_llm_le_hardcoded"
    assert (
        compute_criteria(_metrics(fpr=0.2), _metrics(fpr=0.2), _ps(), None)[key]
        == "pass"
    )


def test_compute_criteria_avg_findings_boundary():
    hc = _metrics(avg_findings=1.0)
    key = "avg_findings_llm_ge_hardcoded"
    # exactly hardcoded - 0.2 -> pass (boundary is inclusive)
    assert compute_criteria(hc, _metrics(avg_findings=0.8), _ps(), None)[key] == "pass"
    assert compute_criteria(hc, _metrics(avg_findings=1.2), _ps(), None)[key] == "pass"
    # just below -> fail
    assert compute_criteria(hc, _metrics(avg_findings=0.7999), _ps(), None)[key] == "fail"


def test_compute_criteria_planner_fallback_boundary():
    hc = _metrics()
    key = "planner_non_fallback_ge_0_8"
    assert compute_criteria(hc, _metrics(), _ps(rate=0.8), None)[key] == "pass"
    assert compute_criteria(hc, _metrics(), _ps(rate=0.79), None)[key] == "fail"
    assert compute_criteria(hc, _metrics(), _ps(rate=None), None)[key] == "inconclusive"
    assert compute_criteria(hc, _metrics(), None, None)[key] == "inconclusive"


def test_compute_criteria_chain_no_9010_inconclusive():
    cg = chain_gate({"ports": {9001: {"traces": []}}}, None)
    assert cg is None
    assert compute_criteria(_metrics(), _metrics(), _ps(), cg)["chain_9010_real"] == "inconclusive"


# ── chain_gate (scenario fixtures) ──────────────────────────────────────────


def test_chain_gate_all_pass_prior_link(tmp_path):
    root = build_m3_fixture(tmp_path, "all_pass")
    expected = expected_by_port()
    hc = collect_eval_summary(root / "baseline", expected)
    llm = collect_eval_summary(root / "llm", expected)
    decisions = load_planner_decisions(root / "llm")
    cg = chain_gate(llm, decisions)
    assert cg is not None
    assert cg["chain_trace_present"] is True
    assert cg["chain_attack_calls"] == 2
    assert cg["chain_planned_unexecuted"] is False
    assert cg["prior_link"] is True
    excerpt = cg["excerpt"]
    assert "absent" not in excerpt
    assert excerpt["vuln_class"] == "chain_composition"
    assert excerpt["target"] == "resource:internal://credentials,tool:get_user_info"
    assert [c["name"] for c in excerpt["attack_calls"]] == [
        "internal://credentials",
        "get_user_info",
    ]
    assert excerpt["judge_verdict"]["steered"] is True
    criteria = compute_criteria(
        compute_metrics(hc, _PORTS), compute_metrics(llm, _PORTS), _ps(), cg
    )
    assert criteria == {
        "recall_llm_ge_hardcoded": "pass",
        "fpr_llm_le_hardcoded": "pass",
        "avg_findings_llm_ge_hardcoded": "pass",
        "planner_non_fallback_ge_0_8": "pass",
        "chain_9010_real": "pass",
    }


def test_chain_gate_no_chain_no_planned_fail(tmp_path):
    root = build_m3_fixture(tmp_path, "no_chain")
    expected = expected_by_port()
    hc = collect_eval_summary(root / "baseline", expected)
    llm = collect_eval_summary(root / "llm", expected)
    decisions = load_planner_decisions(root / "llm")
    cg = chain_gate(llm, decisions)
    assert cg is not None
    assert cg["chain_trace_present"] is False
    assert cg["chain_planned_unexecuted"] is False
    assert cg["excerpt"] == {"absent": True}
    criteria = compute_criteria(
        compute_metrics(hc, _PORTS), compute_metrics(llm, _PORTS), _ps(), cg
    )
    assert criteria["chain_9010_real"] == "fail"


def test_chain_gate_planned_unexecuted_inconclusive(tmp_path):
    root = build_m3_fixture(tmp_path, "planned_unexecuted")
    expected = expected_by_port()
    hc = collect_eval_summary(root / "baseline", expected)
    llm = collect_eval_summary(root / "llm", expected)
    decisions = load_planner_decisions(root / "llm")
    cg = chain_gate(llm, decisions)
    assert cg is not None
    assert cg["chain_trace_present"] is False
    assert cg["chain_planned_unexecuted"] is True
    criteria = compute_criteria(
        compute_metrics(hc, _PORTS), compute_metrics(llm, _PORTS), _ps(), cg
    )
    assert criteria["chain_9010_real"] == "inconclusive"


def test_chain_gate_chain_without_prior_link_fail():
    trace = {
        "vuln_class": "chain_composition",
        "target": "resource:internal://credentials",
        "attack_calls": [
            {
                "kind": "read_resource",
                "name": "internal://credentials",
                "args": None,
                "result_text": "response alpha bravo charlie",
                "elapsed_ms": 1,
            },
            {
                "kind": "call_tool",
                "name": "get_user_info",
                "args": {"username": "fresh-payload-xyz"},
                "result_text": "ok",
                "elapsed_ms": 1,
            },
        ],
        "final_llm_output": "no link",
        "judge_verdict": None,
    }
    cg = chain_gate({"ports": {9010: {"traces": [trace]}}}, None)
    assert cg is not None
    assert cg["chain_trace_present"] is True
    assert cg["prior_link"] is False
    criteria = compute_criteria(_metrics(), _metrics(), _ps(), cg)
    assert criteria["chain_9010_real"] == "fail"


def test_chain_gate_chain_trace_without_attack_calls_not_present():
    trace = {
        "vuln_class": "chain_composition",
        "target": "resource:a,tool:b",
        "attack_calls": [],
        "final_llm_output": "",
        "judge_verdict": None,
    }
    cg = chain_gate({"ports": {9010: {"traces": [trace]}}}, None)
    assert cg["chain_trace_present"] is False
    assert cg["chain_attack_calls"] == 0
    assert cg["excerpt"] == {"absent": True}


def test_chain_gate_excerpt_truncation():
    trace = {
        "vuln_class": "chain_composition",
        "target": "resource:a,tool:b",
        "attack_calls": [
            {
                "kind": "read_resource",
                "name": "a",
                "args": None,
                "result_text": "x" * 500,
                "elapsed_ms": 1,
            },
            {
                "kind": "call_tool",
                "name": "b",
                "args": {"k": "y" * 50},
                "result_text": "ok",
                "elapsed_ms": 1,
            },
        ],
        "final_llm_output": "z" * 600,
        "judge_verdict": None,
    }
    cg = chain_gate({"ports": {9010: {"traces": [trace]}}}, None)
    assert cg["excerpt"]["attack_calls"][0]["result_text"] == "x" * 400
    assert len(cg["excerpt"]["final_llm_output"]) == 500


def test_chain_gate_returns_none_without_9010():
    assert chain_gate({"ports": {9001: {"traces": []}}}, None) is None


# ── end-to-end criteria via scenarios ───────────────────────────────────────


def test_llm_worse_recall_criteria(tmp_path):
    root = build_m3_fixture(tmp_path, "llm_worse_recall")
    expected = expected_by_port()
    hc = collect_eval_summary(root / "baseline", expected)
    llm = collect_eval_summary(root / "llm", expected)
    decisions = load_planner_decisions(root / "llm")
    ps = planner_stats(decisions or [], llm)
    cg = chain_gate(llm, decisions)
    criteria = compute_criteria(
        compute_metrics(hc, _PORTS), compute_metrics(llm, _PORTS), ps, cg
    )
    assert criteria["recall_llm_ge_hardcoded"] == "fail"
    assert criteria["fpr_llm_le_hardcoded"] == "fail"
    assert criteria["avg_findings_llm_ge_hardcoded"] == "pass"
    assert criteria["planner_non_fallback_ge_0_8"] == "pass"
    assert criteria["chain_9010_real"] == "pass"


def test_no_planner_decisions_criterion_inconclusive(tmp_path):
    root = build_m3_fixture(tmp_path, "no_planner_decisions")
    expected = expected_by_port()
    hc = collect_eval_summary(root / "baseline", expected)
    llm = collect_eval_summary(root / "llm", expected)
    decisions = load_planner_decisions(root / "llm")
    assert decisions is None
    cg = chain_gate(llm, decisions)
    criteria = compute_criteria(
        compute_metrics(hc, _PORTS), compute_metrics(llm, _PORTS), None, cg
    )
    assert criteria["planner_non_fallback_ge_0_8"] == "inconclusive"
    assert criteria["chain_9010_real"] == "pass"
