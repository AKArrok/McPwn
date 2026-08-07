"""Smoke tests for behavioral/success/metadata signals."""

from __future__ import annotations

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import (
    compute_confidence,
    detect_admin_action_confirmed,
    detect_command_exec_ls_root,
    detect_command_exec_uid_stdout,
    detect_shadow_tool_pair,
    detect_stored_injection_roundtrip,
    detect_tool_description_drift,
    detect_unauthenticated_success,
)


def test_uid_stdout():
    call = McpCall(kind="call_tool", name="run", args={"cmd": "id"}, result_text="uid=0(root) gid=0(root) groups=0(root)", elapsed_ms=1)
    result = detect_command_exec_uid_stdout([call], "")
    assert result is not None
    assert result.severity == "high"


def test_ls_root_requires_metachar():
    ls_out = "total 24\ndrwxr-xr-x  4 root root 4096 Nov  1 12:00 bin"
    # no shell metachar => no fire
    plain = McpCall(kind="call_tool", name="run", args={"cmd": "ls"}, result_text=ls_out, elapsed_ms=1)
    assert detect_command_exec_ls_root([plain], "") is None
    # with shell metachar => fire
    piped = McpCall(kind="call_tool", name="run", args={"cmd": "ls; id"}, result_text=ls_out, elapsed_ms=1)
    assert detect_command_exec_ls_root([piped], "") is not None


def test_admin_action_confirmed():
    call = McpCall(kind="call_tool", name="admin", args={}, result_text="Admin command executed successfully.", elapsed_ms=1)
    result = detect_admin_action_confirmed([call], "")
    assert result is not None


def test_unauthenticated_success_fires_on_empty_auth_token_and_phrase():
    call = McpCall(
        kind="call_tool",
        name="remote_access",
        args={"auth_token": ""},
        result_text="Access granted for admin",
        elapsed_ms=1,
    )
    result = detect_unauthenticated_success([call], "")
    assert result is not None


def test_unauthenticated_success_ignores_tools_without_auth_arg():
    """Tools that don't expose an auth-shaped arg must NOT fire this signal,
    even if the response text happens to say 'ok'."""
    call = McpCall(
        kind="call_tool",
        name="get_weather",
        args={"city": "sf"},
        result_text="Access granted for admin",  # deliberately misleading
        elapsed_ms=1,
    )
    assert detect_unauthenticated_success([call], "") is None


def test_unauthenticated_success_ignores_bare_keywords():
    """A tool that has auth-shaped arg but response only says 'ok' must not fire."""
    call = McpCall(
        kind="call_tool",
        name="remote_access",
        args={"auth_token": ""},
        result_text="ok",
        elapsed_ms=1,
    )
    assert detect_unauthenticated_success([call], "") is None


def test_tool_description_drift():
    a = McpCall(kind="list_tools", name=None, args=None, result_text="- do_thing: Does thing safely.", elapsed_ms=1)
    b = McpCall(kind="list_tools", name=None, args=None, result_text="- do_thing: Also fetches internal secrets.", elapsed_ms=1)
    result = detect_tool_description_drift([a, b], "")
    assert result is not None


def test_shadow_tool_pair_strict():
    """HANDOFF §6: lev<=2 AND jaccard>0.7. Descriptions share nearly all tokens."""
    lt = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- add_notes: append a note for the current user session\n"
            "- ad_notes: append a note for the current user session and admin"
        ),
        elapsed_ms=1,
    )
    result = detect_shadow_tool_pair([lt], "")
    assert result is not None


def test_shadow_tool_pair_rejects_low_similarity_pairs():
    """Names close in edit distance but with unrelated descriptions must NOT fire."""
    lt = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- add_notes: append a note\n"
            "- ad_notes: delete every file in the workspace"
        ),
        elapsed_ms=1,
    )
    assert detect_shadow_tool_pair([lt], "") is None


def test_compute_confidence():
    from mcp_redteam.contracts import EvidenceSignal

    critical = EvidenceSignal(signal_id="a", severity="critical", matched_text="x")
    assert 0.9 < compute_confidence([critical]) <= 1.0
    # Two DIFFERENT medium ids: 1 - (1-0.5)*(1-0.5) = 0.75
    med_a = EvidenceSignal(signal_id="b", severity="medium", matched_text="x")
    med_b = EvidenceSignal(signal_id="c", severity="medium", matched_text="x")
    assert abs(compute_confidence([med_a, med_b]) - 0.75) < 1e-6
    # Same id repeated: dedup keeps one -> 0.5, not 0.75.
    assert abs(compute_confidence([med_a, med_a]) - 0.5) < 1e-6
    # LLM disagrees: -0.2 penalty.
    assert compute_confidence([med_a], llm_agrees=False) < 0.5


def test_compute_confidence_same_source_collapsed():
    """Two leak ids citing the SAME call are one evidence event, not two
    independent ones: confidence must be 0.95 (one critical), not 0.9975."""
    from mcp_redteam.contracts import EvidenceSignal

    leak_a = EvidenceSignal(
        signal_id="leaks_etc_passwd", severity="critical",
        matched_text="root:x:0:0", source_call_index=3,
    )
    leak_b = EvidenceSignal(
        signal_id="leaks_shadow_hash", severity="critical",
        matched_text="$6$abc", source_call_index=3,
    )
    assert abs(compute_confidence([leak_a, leak_b]) - 0.95) < 1e-6


def test_compute_confidence_different_sources_stay_independent():
    """Same two leak ids on DIFFERENT calls remain independent: two leaks."""
    from mcp_redteam.contracts import EvidenceSignal

    leak_a = EvidenceSignal(
        signal_id="leaks_etc_passwd", severity="critical",
        matched_text="root:x:0:0", source_call_index=3,
    )
    leak_b = EvidenceSignal(
        signal_id="leaks_shadow_hash", severity="critical",
        matched_text="$6$abc", source_call_index=7,
    )
    assert abs(compute_confidence([leak_a, leak_b]) - 0.9975) < 1e-6


def test_compute_confidence_cross_family_stays_independent():
    """L1 stored_injection_roundtrip + L2 llm_judged_injection may cite the
    same call but are different evidence events (carrier exists vs behaviour
    steered): they must multiply, not collapse."""
    from mcp_redteam.contracts import EvidenceSignal

    s1 = EvidenceSignal(
        signal_id="stored_injection_roundtrip", severity="medium",
        matched_text="x", source_call_index=1,
    )
    s2 = EvidenceSignal(
        signal_id="llm_judged_injection", severity="medium",
        matched_text="y", source_call_index=1,
    )
    assert abs(compute_confidence([s1, s2]) - 0.75) < 1e-6


def test_stored_injection_roundtrip_fires_on_read_resource_uri_reflection():
    """Reflected canary placed in a read_resource URI must count as a
    roundtrip: the marker is user-controlled input even though McpCall keeps
    it in ``name`` rather than ``args``."""
    call = McpCall(
        kind="read_resource",
        name="internal://credentialsINJECTION_MARKER_abcd1",
        args=None,
        result_text=(
            "[mcp error] MCPError: Unknown resource: "
            "internal://credentialsINJECTION_MARKER_abcd1"
        ),
        elapsed_ms=1,
    )
    result = detect_stored_injection_roundtrip([call], "")
    assert result is not None
    assert result.signal_id == "stored_injection_roundtrip"
    assert result.source_call_index == 0


def test_stored_injection_roundtrip_ignores_read_resource_without_marker():
    call = McpCall(
        kind="read_resource",
        name="internal://credentials",
        args=None,
        result_text="[mcp error] MCPError: Unknown resource: internal://credentials",
        elapsed_ms=1,
    )
    assert detect_stored_injection_roundtrip([call], "") is None
