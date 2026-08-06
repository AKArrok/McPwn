"""Synthetic M3 A/B eval fixture builder (self-contained, no network/LLM).

Builds a pair of DVMCP eval output dirs under ``root`` - ``baseline``
(hardcoded planner) and ``llm`` (LLM planner) - each with
``port_*/scan_result.json`` + ``eval_report.md``, plus
``llm/planner_decisions.json`` when the scenario needs it.

The fixture hardcodes these expected_signals into the findings it writes:
port 9001 -> ["leaks_api_key_shape"], 9006 -> ["stored_injection_roundtrip"],
9010 -> ["llm_judged_injection"]. Use :func:`expected_by_port` in tests so
hit accounting matches what the fixture writes.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_redteam.contracts import (
    AttackTrace,
    EvidenceSignal,
    Finding,
    JudgeVerdict,
    McpCall,
    ScanResult,
    VulnClass,
)

_PORTS = [9001, 9006, 9010]

_EXPECTED_SIGNALS = {
    9001: ["leaks_api_key_shape"],
    9006: ["stored_injection_roundtrip"],
    9010: ["llm_judged_injection"],
}


def expected_by_port() -> dict[int, dict]:
    """``expected_by_port`` matching the fixture's hardcoded signals."""
    return {
        port: {"expected_signals": list(signals)}
        for port, signals in _EXPECTED_SIGNALS.items()
    }


def _call(kind: str, name: str | None, args: dict | None, result_text: str) -> McpCall:
    return McpCall(kind=kind, name=name, args=args, result_text=result_text, elapsed_ms=1)


def _finding(vuln_class: VulnClass, target: str, signal_ids: list[str]) -> Finding:
    signals = [
        EvidenceSignal(signal_id=sid, severity="high", matched_text=sid, source_call_index=i)
        for i, sid in enumerate(signal_ids)
    ]
    return Finding(
        finding_id=Finding.compute_id(vuln_class, target, signal_ids[0]),
        vuln_class=vuln_class,
        target=target,
        severity="high",
        confidence=0.9,
        title=f"{vuln_class.value} on {target}",
        summary=f"signals: {', '.join(signal_ids)}",
        signals=signals,
    )


def _scan_result(
    port: int,
    tools: list[str],
    resources: list[str],
    findings: list[Finding],
    traces: list[AttackTrace],
) -> ScanResult:
    return ScanResult(
        run_id=f"scan-{port}",
        sse_url=f"http://127.0.0.1:{port}/sse",
        started_at="2026-08-05T00:00:00Z",
        wall_seconds=1.0,
        tools_seen=tools,
        resources_seen=resources,
        findings=findings,
        traces=traces,
        stop_reason="completed",
    )


def _chain_trace() -> AttackTrace:
    """9010 chain trace with a real prior link (args reuse a result substring)."""
    return AttackTrace(
        vuln_class=VulnClass.CHAIN_COMPOSITION,
        target="resource:internal://credentials,tool:get_user_info",
        strategy_card_slug="chain_composition",
        attack_calls=[
            _call(
                "read_resource",
                "internal://credentials",
                None,
                "CREDENTIALS secret-key-abc123 leaked",
            ),
            _call(
                "call_tool",
                "get_user_info",
                {"username": "secret-key-abc123"},
                "User found: admin",
            ),
        ],
        final_llm_output="Chained read_resource then get_user_info with leaked key.",
        judge_verdict=JudgeVerdict(steered=True, evidence_call_index=1, reason="prior result used"),
    )


def _indirect_trace() -> AttackTrace:
    """Non-chain 9010 trace (used by the no_chain / planned_unexecuted scenarios)."""
    return AttackTrace(
        vuln_class=VulnClass.INDIRECT_INJECTION,
        target="notes://x",
        strategy_card_slug="indirect_injection",
        attack_calls=[
            _call("call_tool", "process_document", {"content": "hello"}, "processed"),
            _call("read_resource", "notes://x", None, "latest note: hello"),
        ],
        final_llm_output="Probed stored injection roundtrip.",
    )


def _planner_decisions() -> list[dict]:
    return [
        {
            "port": 9001,
            "index": 0,
            "vuln_class": "direct_prompt_injection",
            "target": "internal://credentials",
            "source": "llm",
            "planned": True,
            "executed": True,
            "skip_reason": None,
        },
        {
            "port": 9006,
            "index": 0,
            "vuln_class": "indirect_injection",
            "target": "notes://x",
            "source": "llm",
            "planned": True,
            "executed": True,
            "skip_reason": None,
        },
        {
            "port": 9010,
            "index": 0,
            "vuln_class": "chain_composition",
            "target": "resource:internal://credentials,tool:get_user_info",
            "source": "llm",
            "planned": True,
            "executed": True,
            "skip_reason": None,
        },
    ]


def _planner_decisions_no_chain() -> list[dict]:
    return [
        d
        for d in _planner_decisions()
        if not (d["port"] == 9010 and d["vuln_class"] == "chain_composition")
    ]


def _planner_decisions_planned_unexecuted() -> list[dict]:
    decisions = _planner_decisions()
    for d in decisions:
        if d["port"] == 9010 and d["vuln_class"] == "chain_composition":
            d["executed"] = False
    return decisions


def _hit_9001() -> list[Finding]:
    return [
        _finding(
            VulnClass.DIRECT_PROMPT_INJECTION, "internal://credentials", ["leaks_api_key_shape"]
        )
    ]


def _hit_9006() -> list[Finding]:
    return [_finding(VulnClass.INDIRECT_INJECTION, "notes://x", ["stored_injection_roundtrip"])]


def _hit_9010_chain() -> list[Finding]:
    return [
        _finding(
            VulnClass.CHAIN_COMPOSITION, "internal://credentials", ["llm_judged_injection"]
        )
    ]


def _hit_9010_no_chain() -> list[Finding]:
    return [_finding(VulnClass.INDIRECT_INJECTION, "notes://x", ["llm_judged_injection"])]


def _miss_9001() -> list[Finding]:
    """9001 finding that does NOT hit: signal outside the fixture's expected set."""
    return [
        _finding(
            VulnClass.DIRECT_PROMPT_INJECTION, "internal://credentials", ["leaks_etc_passwd"]
        )
    ]


def _baseline_specs() -> dict:
    return {
        9001: (["get_user_info"], ["internal://credentials"], _hit_9001(), []),
        9006: (["process_document"], ["notes://x"], _hit_9006(), []),
        9010: (
            ["get_user_info"],
            ["internal://credentials"],
            [
                _finding(
                    VulnClass.CHAIN_COMPOSITION, "internal://credentials", ["llm_judged_injection"]
                )
            ],
            [],
        ),
    }


def _llm_specs(scenario: str) -> dict:
    if scenario == "all_pass":
        return {
            9001: (["get_user_info"], ["internal://credentials"], _hit_9001(), []),
            9006: (["process_document"], ["notes://x"], _hit_9006(), []),
            9010: (
                ["get_user_info"],
                ["internal://credentials"],
                _hit_9010_chain(),
                [_chain_trace()],
            ),
        }
    if scenario == "llm_worse_recall":
        return {
            9001: (["get_user_info"], ["internal://credentials"], _miss_9001(), []),
            9006: (["process_document"], ["notes://x"], _hit_9006(), []),
            9010: (
                ["get_user_info"],
                ["internal://credentials"],
                _hit_9010_chain(),
                [_chain_trace()],
            ),
        }
    if scenario in ("no_chain", "planned_unexecuted"):
        return {
            9001: (["get_user_info"], ["internal://credentials"], _hit_9001(), []),
            9006: (["process_document"], ["notes://x"], _hit_9006(), []),
            9010: (
                ["get_user_info"],
                ["internal://credentials"],
                _hit_9010_no_chain(),
                [_indirect_trace()],
            ),
        }
    if scenario == "no_planner_decisions":
        return {
            9001: (["get_user_info"], ["internal://credentials"], _hit_9001(), []),
            9006: (["process_document"], ["notes://x"], _hit_9006(), []),
            9010: (
                ["get_user_info"],
                ["internal://credentials"],
                _hit_9010_chain(),
                [_chain_trace()],
            ),
        }
    raise ValueError(f"unknown m3 fixture scenario: {scenario}")


def _write_eval_dir(eval_dir: Path, port_specs: dict) -> None:
    for port, (tools, resources, findings, traces) in port_specs.items():
        port_dir = eval_dir / f"port_{port}"
        port_dir.mkdir(parents=True, exist_ok=True)
        result = _scan_result(port, tools, resources, findings, traces)
        (port_dir / "scan_result.json").write_text(
            result.model_dump_json(indent=2), encoding="utf-8"
        )
    (eval_dir / "eval_report.md").write_text(
        "# DVMCP Regression Report\n\nSynthetic fixture (see port_*/scan_result.json).\n",
        encoding="utf-8",
    )


def build_m3_fixture(root: Path, scenario: str) -> Path:
    """Build a synthetic M3 A/B pair under ``root`` and return ``root``.

    Scenarios: all_pass, llm_worse_recall, no_chain, planned_unexecuted,
    no_planner_decisions.
    """
    baseline = root / "baseline"
    llm = root / "llm"
    _write_eval_dir(baseline, _baseline_specs())
    _write_eval_dir(llm, _llm_specs(scenario))
    if scenario == "no_planner_decisions":
        return root
    if scenario == "no_chain":
        decisions = _planner_decisions_no_chain()
    elif scenario == "planned_unexecuted":
        decisions = _planner_decisions_planned_unexecuted()
    else:
        decisions = _planner_decisions()
    (llm / "planner_decisions.json").write_text(
        json.dumps({"decisions": decisions}, indent=2), encoding="utf-8"
    )
    return root
