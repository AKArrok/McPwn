"""Lock the reproducibility-metadata contract added to ScanResult (B1/B2/B3).

These tests are static (no LLM, no DVMCP): they pin field names, types, and
defaults so a future refactor cannot silently drop the reproducibility anchor
that B introduced (HANDOFF B: point-in-time reproducible scans).
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from mcp_redteam.contracts import ScanResult
from mcp_redteam.orchestrator import runner as runner_mod
from tests.fixtures.stub_attacker import fake_make_client


def test_scan_result_reproducibility_fields_default_to_safe():
    """All five new fields exist with the right types and safe defaults.

    Defaults must be safe: empty string / empty dict / 0.0, so a ScanResult
    built without these arguments (e.g. in unit tests) still validates.
    """
    r = ScanResult(
        run_id="r",
        sse_url="http://x/sse",
        started_at="2026-01-01T00:00:00Z",
        wall_seconds=1.0,
        stop_reason="completed",
    )
    assert r.git_sha == ""
    assert r.config_snapshot == {}
    assert r.attacker_model == ""
    assert r.attacker_temperature == 0.0
    assert r.attack_messages_sha1 == ""


def test_scan_result_reproducibility_fields_round_trip():
    """Filled fields survive model_dump_json / model_validate_json round trip."""
    r = ScanResult(
        run_id="r",
        sse_url="http://x/sse",
        started_at="2026-01-01T00:00:00Z",
        wall_seconds=1.0,
        stop_reason="completed",
        git_sha="abc123",
        config_snapshot={"attacker": {"model": "m", "temperature": 0.5}},
        attacker_model="m",
        attacker_temperature=0.5,
        attack_messages_sha1="0" * 40,
    )
    # ``total_tokens`` is a @computed_field derived from attacker_tokens +
    # judge_tokens; it is dumped for human readers but is otherwise redundant.
    # Excluding it lets round-trip work under ``extra="forbid"`` without
    # weakening the schema (total_tokens is a derived view, not a source of
    # truth - we can recompute it from attacker_tokens + judge_tokens).
    r2 = ScanResult.model_validate_json(
        r.model_dump_json(exclude={"total_tokens"})
    )
    assert r2.git_sha == "abc123"
    assert r2.config_snapshot["attacker"]["model"] == "m"
    assert r2.attacker_model == "m"
    assert r2.attacker_temperature == 0.5
    assert r2.attack_messages_sha1 == "0" * 40


def test_scan_result_still_rejects_extra_fields():
    """extra=forbid still holds: reproducibility fields are not a backdoor."""
    with pytest.raises(ValidationError):
        ScanResult(
            run_id="r",
            sse_url="x",
            started_at="t",
            wall_seconds=1.0,
            stop_reason="completed",
            unknown_field="oops",
        )


def test_attack_messages_sha1_format_locked():
    """attack_messages_sha1 is a 40-char hex string (sha1 length).

    Pinning the length keeps a downstream comparison script that does
    ``if old_sha1 != new_sha1: alert_drift`` from breaking on a refactor.
    """
    r = ScanResult(
        run_id="r",
        sse_url="x",
        started_at="t",
        wall_seconds=1.0,
        stop_reason="completed",
        attack_messages_sha1="0" * 40,
    )
    assert len(r.attack_messages_sha1) == 40
    int(r.attack_messages_sha1, 16)  # must be valid hex


def test_scan_result_seed_and_evidence_judge_model_defaults():
    """Stage-3 rigor fields default safe: seed None, evidence_judge_model ''.

    scan(seed=...) must be recorded on ScanResult (no fake 'same seed'
    claims), and evidence_judge_model must default empty so a scan that never
    ran evidence judgment doesn't pretend a judge model was used.
    """
    r = ScanResult(
        run_id="r",
        sse_url="x",
        started_at="t",
        wall_seconds=1.0,
        stop_reason="completed",
    )
    assert r.seed is None
    assert r.evidence_judge_model == ""


def test_scan_result_seed_and_evidence_judge_model_round_trip():
    """Filled rigor fields survive model_dump_json / model_validate_json."""
    r = ScanResult(
        run_id="r",
        sse_url="x",
        started_at="t",
        wall_seconds=1.0,
        stop_reason="completed",
        seed=42,
        evidence_judge_model="doubao-seed-2.0-lite",
    )
    r2 = ScanResult.model_validate_json(
        r.model_dump_json(exclude={"total_tokens"})
    )
    assert r2.seed == 42
    assert r2.evidence_judge_model == "doubao-seed-2.0-lite"


def test_scan_connection_error_is_persisted_without_static_hit_crash(monkeypatch, tmp_path):
    """A failed MCP connection still produces a valid, inspectable ScanResult."""

    class _FailingSession:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            raise OSError("connection refused")

        async def __aexit__(self, *_args):
            return False

    monkeypatch.setattr(runner_mod, "McpSession", _FailingSession)
    monkeypatch.setattr(runner_mod, "make_client", fake_make_client)
    monkeypatch.setattr(runner_mod, "_make_judge_fn_or_none", lambda: None)

    result = asyncio.run(runner_mod.scan("http://127.0.0.1:1/sse", out_dir=tmp_path))

    assert result.stop_reason == "error"
    assert result.static_hits == []
    assert (tmp_path / "scan_result.json").is_file()
