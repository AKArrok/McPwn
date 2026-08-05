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