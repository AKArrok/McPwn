from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_redteam.contracts import EvidenceSignal, Finding, McpCall, VulnClass


def _call(result: str = "wrote outside sandbox") -> McpCall:
    return McpCall(
        kind="call_tool",
        name="write_file",
        args={"path": "/root/mcpwn-marker", "content": "marker"},
        result_text=result,
        elapsed_ms=1,
    )


def _finding(signal_id: str = "sandbox_escape_write") -> Finding:
    return Finding(
        finding_id="F-holdout01",
        vuln_class=VulnClass.PATH_TRAVERSAL,
        hypothesis_class=VulnClass.PATH_TRAVERSAL,
        evidence_class=VulnClass.PATH_TRAVERSAL,
        target="write_file",
        severity="high",
        confidence=0.75,
        title="sandbox escape",
        summary="paired holdout fixture",
        signals=[
            EvidenceSignal(
                signal_id=signal_id,
                severity="high",
                matched_text="sha256:test",
                source_call_index=0,
            )
        ],
        poc_call_sequence=[_call()],
    )


def _pair() -> dict:
    return {
        "pair_id": "sandbox-escape",
        "expected_vuln_classes": ["path_traversal"],
        "expected_signal_ids": ["sandbox_escape_write", "sandbox_escape_read"],
        "allow_llm_evidence": False,
        "control_forbidden_signal_prefixes": ["sandbox_escape"],
        "control_block_patterns": ["access denied", "outside allowed"],
    }


def test_repository_holdout_manifest_matches_frozen_lock():
    from eval.holdout.runner import load_protocol

    protocol = load_protocol()
    assert protocol["minimum_repeats"] == 5
    assert any(pair["split"] == "holdout" for pair in protocol["pairs"])


def test_holdout_lock_rejects_manifest_tampering(tmp_path: Path):
    from eval.holdout.runner import HoldoutProtocolError, load_protocol

    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("protocol_version: 1\nminimum_repeats: 4\npairs: []\n", encoding="utf-8")
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")

    with pytest.raises(HoldoutProtocolError, match="lock mismatch"):
        load_protocol(manifest, lock)


@pytest.mark.parametrize("n", [0, 1, 3, 4])
def test_holdout_rejects_fewer_than_five_repeats(n: int):
    from eval.holdout.runner import HoldoutProtocolError, validate_repeats

    with pytest.raises(HoldoutProtocolError, match="at least 5"):
        validate_repeats({"minimum_repeats": 5}, n)


def test_pair_run_requires_positive_fixed_clean_and_control_replay():
    from eval.holdout.runner import ControlReplay, evaluate_pair_run

    finding = _finding()
    positive = SimpleNamespace(findings=[finding])
    fixed = SimpleNamespace(findings=[])
    control = ControlReplay(
        finding_id=finding.finding_id,
        calls_replayed=1,
        exploit_evidence_grounded=True,
        control_blocked=True,
        control_signal_ids=[],
        same_signal_reproduced=False,
        passed=True,
    )

    verdict = evaluate_pair_run(_pair(), positive, fixed, [control])
    assert verdict["status"] == "PASS"
    assert verdict["positive_detected"] is True
    assert verdict["fixed_clean"] is True
    assert verdict["control_replay_passed"] is True


def test_pair_run_fails_when_fixed_version_reproduces_finding():
    from eval.holdout.runner import ControlReplay, evaluate_pair_run

    finding = _finding()
    control = ControlReplay(
        finding_id=finding.finding_id,
        calls_replayed=1,
        exploit_evidence_grounded=True,
        control_blocked=False,
        control_signal_ids=["sandbox_escape_write"],
        same_signal_reproduced=True,
        passed=False,
    )
    verdict = evaluate_pair_run(
        _pair(),
        SimpleNamespace(findings=[finding]),
        SimpleNamespace(findings=[_finding()]),
        [control],
    )
    assert verdict["status"] == "FAIL"
    assert verdict["fixed_clean"] is False
    assert verdict["control_replay_passed"] is False


@pytest.mark.asyncio
async def test_control_replay_requires_block_and_no_same_signal():
    from eval.holdout.runner import replay_finding_on_control

    class DenyingSession:
        async def call_tool(self, name: str, args: dict) -> McpCall:
            return McpCall(
                kind="call_tool",
                name=name,
                args=args,
                result_text="Access denied: path is outside allowed directories",
                elapsed_ms=1,
            )

    replay = await replay_finding_on_control(
        _finding(), DenyingSession(), _pair(), sandbox_root="/tmp/sandbox"
    )
    assert replay.calls_replayed == 1
    assert replay.control_blocked is True
    assert replay.same_signal_reproduced is False
    assert replay.passed is True
