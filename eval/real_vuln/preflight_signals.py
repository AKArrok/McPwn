"""Preflight: confirm the filesystem 0.6.2 exploit trace's signal verdict.

The allowlist-escape reads return a plain secret with no leak shape, so the
deterministic signal library is expected to stay SILENT here - detection goes
through the evidence judge (path_traversal card + LLM judge on a zero-signal
trace). This freeze asserts that premise (mirrors the unknown-shape preflights).

Usage: python eval/real_vuln/preflight_signals.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import run_all_signals

SECRET = "FS-SECRET-OUTSIDE-2026"

CALLS = [
    McpCall(
        kind="call_tool", name="read_file",
        args={"path": "C:/tmp/mcpwn-fs2/secret.txt"},
        result_text=SECRET,
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool", name="read_file",
        args={"path": "C:/tmp/mcpwn-fs/../mcpwn-fs2/secret.txt"},
        result_text=SECRET,
        elapsed_ms=1,
    ),
]


def main() -> None:
    signals = run_all_signals(CALLS, "attacker final")
    if signals:
        print(f"FAIL: expected 0 deterministic signals, got "
              f"{[(s.signal_id, s.severity) for s in signals]}")
        sys.exit(1)
    print("PASS: 0 deterministic signals (detection = evidence judge path)")


if __name__ == "__main__":
    main()
