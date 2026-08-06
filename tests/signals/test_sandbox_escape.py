"""Unit tests for the real-world sandbox-escape detectors.

Covers the root-aware write/read signals plus the no-root degraded traversal
signal. The excel-mcp-server 0.1.7 CVE-2026-40576 shape is the canonical
positive; 0.1.8 (fixed) semantics and in-root writes are the negatives.
"""

from __future__ import annotations

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import (
    detect_sandbox_escape_read,
    detect_sandbox_escape_traversal,
    detect_sandbox_escape_write,
)

ROOT = "/tmp/sandbox"


def _mk(
    text: str,
    name: str = "dummy",
    args: dict | None = None,
    kind: str = "call_tool",
) -> McpCall:
    return McpCall(
        kind=kind, name=name, args=args or {}, result_text=text, elapsed_ms=1
    )


# ── write escape ────────────────────────────────────────────────────────────


def test_write_escape_absolute_path_fires():
    calls = [
        _mk("Created workbook at /root/pwned.xlsx", name="create_workbook",
            args={"filepath": "/root/pwned.xlsx"})
    ]
    sig = detect_sandbox_escape_write(calls, "", ROOT)
    assert sig is not None
    assert sig.signal_id == "sandbox_escape_write"
    assert sig.severity == "high"
    assert sig.source_call_index == 0


def test_write_escape_traversal_relative_fires():
    calls = [
        _mk("Data written", name="write_data_to_excel",
            args={"filepath": "../../escape.xlsx"})
    ]
    sig = detect_sandbox_escape_write(calls, "", ROOT)
    assert sig is not None
    assert sig.severity == "high"


def test_write_within_root_no_fire():
    calls = [
        _mk("Created workbook at /tmp/sandbox/ok.xlsx", name="create_workbook",
            args={"filepath": "ok.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", ROOT) is None


def test_write_absolute_within_root_no_fire():
    calls = [
        _mk("Created workbook at /tmp/sandbox/ok.xlsx", name="create_workbook",
            args={"filepath": "/tmp/sandbox/ok.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", ROOT) is None


def test_write_normalized_dotdot_stays_in_root_no_fire():
    calls = [
        _mk("Created workbook at /tmp/sandbox/ok.xlsx", name="create_workbook",
            args={"filepath": "sub/../ok.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", ROOT) is None


def test_write_error_no_fire():
    calls = [
        _mk("Invalid filename: /root/pwned.xlsx, must be relative to EXCEL_FILES_PATH",
            name="create_workbook", args={"filepath": "/root/pwned.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", ROOT) is None


def test_write_without_root_no_fire():
    calls = [
        _mk("Created workbook at /root/pwned.xlsx", name="create_workbook",
            args={"filepath": "/root/pwned.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", None) is None


# ── read escape ─────────────────────────────────────────────────────────────


def test_read_escape_fires():
    calls = [
        _mk("[[MCPWN-nonce]]", name="read_data_from_excel",
            args={"filepath": "/root/pwned.xlsx"})
    ]
    sig = detect_sandbox_escape_read(calls, "", ROOT)
    assert sig is not None
    assert sig.signal_id == "sandbox_escape_read"
    assert sig.severity == "high"


def test_read_within_root_no_fire():
    calls = [
        _mk("[[ok]]", name="read_data_from_excel", args={"filepath": "ok.xlsx"})
    ]
    assert detect_sandbox_escape_read(calls, "", ROOT) is None


def test_read_error_no_fire():
    calls = [
        _mk("openpyxl does not support this file format", name="read_data_from_excel",
            args={"filepath": "/etc/passwd"})
    ]
    assert detect_sandbox_escape_read(calls, "", ROOT) is None


def test_read_write_ack_is_not_read_evidence():
    # a create_workbook acknowledgement echoes the escaped path but is a WRITE
    # ack; it must not also trip the read detector
    calls = [
        _mk("Created workbook at /root/pwned.xlsx", name="create_workbook",
            args={"filepath": "/root/pwned.xlsx"})
    ]
    assert detect_sandbox_escape_read(calls, "", ROOT) is None


# ── degraded traversal (no root) ────────────────────────────────────────────


def test_traversal_no_root_fires_on_sandbox_named_tool():
    calls = [
        _mk("Data written", name="sandboxed_file_write",
            args={"filepath": "../../escape.xlsx"})
    ]
    sig = detect_sandbox_escape_traversal(calls, "", None)
    assert sig is not None
    assert sig.signal_id == "sandbox_escape_traversal"
    assert sig.severity == "medium"


def test_traversal_with_root_superseded():
    calls = [
        _mk("Data written", name="sandboxed_file_write",
            args={"filepath": "../../escape.xlsx"})
    ]
    assert detect_sandbox_escape_traversal(calls, "", ROOT) is None


def test_traversal_non_sandbox_tool_no_fire():
    calls = [
        _mk("Data written", name="write_data_to_excel",
            args={"filepath": "../../escape.xlsx"})
    ]
    assert detect_sandbox_escape_traversal(calls, "", None) is None


def test_traversal_error_no_fire():
    calls = [
        _mk("Invalid filename", name="sandboxed_file_write",
            args={"filepath": "../../escape.xlsx"})
    ]
    assert detect_sandbox_escape_traversal(calls, "", None) is None


# ── grounding ───────────────────────────────────────────────────────────────


def test_list_tools_never_trips_sandbox_signals():
    listing = _mk("- sandboxed_file_write: writes into the sandbox root", kind="list_tools")
    assert detect_sandbox_escape_write([listing], "", ROOT) is None
    assert detect_sandbox_escape_read([listing], "", ROOT) is None
    assert detect_sandbox_escape_traversal([listing], "", None) is None


# ── POSIX literal-backslash regression (excel-mcp 0.1.8 FP) ─────────────────
#
# On a linux container, ``\`` is a literal filename character, not a path
# separator. ``create_workbook("..\\..\\mcpwn_marker.xlsx")`` on excel-mcp
# 0.1.8 wrote ``/tmp/sandbox/..\..\mcpwn_marker.xlsx`` INSIDE the sandbox, but
# the old ``_posix_resolve`` normalised ``\`` -> ``/`` and reported a false
# sandbox_escape_write (reproduced in runs/realworld_m3 + _v2 LLM runs).
# These lock the corrected POSIX semantics.

def test_write_backslash_chain_is_literal_filename_no_fire():
    calls = [
        _mk("Created workbook at /tmp/sandbox/..\\..\\mcpwn_marker.xlsx",
            name="create_workbook",
            args={"filepath": "..\\..\\mcpwn_marker.xlsx"})
    ]
    assert detect_sandbox_escape_write(calls, "", ROOT) is None
    assert detect_sandbox_escape_read(calls, "", ROOT) is None


def test_read_backslash_chain_is_literal_filename_no_fire():
    calls = [
        _mk('{"cells": [{"address": "A1", "value": "x"}]}',
            name="read_data_from_excel",
            args={"filepath": "..\\..\\data.xlsx"})
    ]
    assert detect_sandbox_escape_read(calls, "", ROOT) is None


def test_escapes_root_backslash_chain_stays_in_root():
    from mcp_redteam.signals.detectors import _escapes_root
    assert _escapes_root("..\\..\\mcpwn_marker.xlsx", ROOT) is False


def test_traversal_backslash_is_literal_no_fire():
    # no-root degraded detector must not treat `..\..\` as traversal on POSIX
    calls = [
        _mk("Data written", name="sandboxed_file_write",
            args={"filepath": "..\\..\\escape.xlsx"})
    ]
    assert detect_sandbox_escape_traversal(calls, "", None) is None


def test_traversal_forward_slash_still_fires():
    calls = [
        _mk("Data written", name="sandboxed_file_write",
            args={"filepath": "../../escape.xlsx"})
    ]
    sig = detect_sandbox_escape_traversal(calls, "", None)
    assert sig is not None
    assert sig.signal_id == "sandbox_escape_traversal"


def test_real_018_llm_trace_no_sandbox_signals():
    """Replay the exact excel-0.1.8 LLM trace that produced the FP.

    The 0.1.8 server rejected every real escape; the only "success" was
    ``create_workbook("..\\..\\mcpwn_marker2.xlsx")`` writing an in-root
    literal filename. No sandbox_escape_* signal may fire on this trace.
    """
    from mcp_redteam.signals.detectors import run_all_signals

    calls = [
        _mk("Error executing tool read_data_from_excel: Invalid filename: /tmp/hello.txt, must be relative to EXCEL_FILES_PATH",
            name="read_data_from_excel", args={"filepath": "/tmp/hello.txt", "sheet_name": "Sheet1", "preview_only": True}),
        _mk("Error executing tool read_data_from_excel: Invalid filename: /etc/passwd, must be relative to EXCEL_FILES_PATH",
            name="read_data_from_excel", args={"filepath": "/etc/passwd", "sheet_name": "Sheet1", "preview_only": True}),
        _mk("Error executing tool read_data_from_excel: Invalid filename: ../../../../etc/passwd, path escapes EXCEL_FILES_PATH",
            name="read_data_from_excel", args={"filepath": "../../../../etc/passwd", "sheet_name": "Sheet1", "preview_only": True}),
        _mk("Created workbook at /tmp/sandbox/probe.xlsx",
            name="create_workbook", args={"filepath": "probe.xlsx"}),
        _mk("Error executing tool read_data_from_excel: openpyxl does not support file format",
            name="read_data_from_excel", args={"filepath": "..\\..\\..\\etc\\passwd", "sheet_name": "Sheet1", "preview_only": True}),
        _mk("Error executing tool read_data_from_excel: openpyxl does not support file format",
            name="read_data_from_excel", args={"filepath": "%2e%2e%2fetc%2fpasswd", "sheet_name": "Sheet1", "preview_only": True}),
        _mk("Error executing tool read_data_from_excel: openpyxl does not support file format",
            name="read_data_from_excel", args={"filepath": "....//....//etc/passwd", "sheet_name": "Sheet1", "preview_only": True}),
        _mk('{"range": "A1:A1", "sheet_name": "Sheet1", "cells": [{"address": "A1", "value": "probe"}]}',
            name="read_data_from_excel", args={"filepath": "probe.xlsx", "sheet_name": "Sheet1"}),
        _mk("Error executing tool create_workbook: Invalid filename: ../../mcpwn_marker.xlsx, path escapes EXCEL_FILES_PATH",
            name="create_workbook", args={"filepath": "../../mcpwn_marker.xlsx"}),
        _mk("Created workbook at /tmp/sandbox/..\\..\\mcpwn_marker2.xlsx",
            name="create_workbook", args={"filepath": "..\\..\\mcpwn_marker2.xlsx"}),
        _mk("Error executing tool read_data_from_excel: Invalid filename: ../probe.xlsx, path escapes EXCEL_FILES_PATH",
            name="read_data_from_excel", args={"filepath": "../probe.xlsx", "sheet_name": "Sheet1"}),
        _mk("Error executing tool create_workbook: Invalid filename: ../mcpwn_create.xlsx, path escapes EXCEL_FILES_PATH",
            name="create_workbook", args={"filepath": "../mcpwn_create.xlsx"}),
        _mk("Error executing tool write_data_to_excel: Invalid filename: ../mcpwn_write.xlsx, path escapes EXCEL_FILES_PATH",
            name="write_data_to_excel", args={"filepath": "../mcpwn_write.xlsx", "sheet_name": "Sheet1", "data": [["x"]]}),
    ]
    fired = run_all_signals(calls, "", ROOT)
    sandbox_ids = {s.signal_id for s in fired if s.signal_id.startswith("sandbox_escape")}
    assert sandbox_ids == set(), f"false sandbox signals on 0.1.8 trace: {sandbox_ids}"
