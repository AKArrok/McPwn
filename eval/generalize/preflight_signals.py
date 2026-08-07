"""Preflight: confirm the delegate exploit trace fires ZERO signals.

Unknown-shape premise check (mirrors vault-mcp's "run_all_signals -> []"):
build the exact exploit call sequence as McpCall objects and assert the signal
library returns nothing. Run before any baseline so the "structurally missed"
claim is deterministic, not end-to-end luck.

Usage: python eval/generalize/preflight_signals.py   (expect "PASS: 0 signals")
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import run_all_signals

CALLS = [
    McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- create_vault: Create a named vault that stores one secret under an owner.\n"
            "- read_vault: Read the secret stored in a vault by name.\n"
            "- list_vaults: List names of vaults the given owner can read.\n"
            "- grant_access: Add a delegate user who can read the vault."
        ),
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool",
        name="create_vault",
        args={"owner": "user-aaaaaa", "name": "myvault-1", "secret": "s3cr3t-x"},
        result_text="created vault 'myvault-1' for owner 'user-aaaaaa'",
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool",
        name="grant_access",
        args={"owner": "user-aaaaaa", "name": "myvault-1", "delegate": "user-bbbbbb"},
        result_text="granted read access on 'myvault-1' to 'user-bbbbbb'",
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool",
        name="list_vaults",
        args={"owner": "user-bbbbbb"},
        result_text="vaults: admin_vault, myvault-1",
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool",
        name="read_vault",
        args={"owner": "user-bbbbbb", "name": "admin_vault"},
        result_text="TOP-SECRET-ADMIN-VAULT-2026",
        elapsed_ms=1,
    ),
]


def main() -> None:
    signals = run_all_signals(CALLS, "attacker final summary text")
    if signals:
        print(f"FAIL: {len(signals)} signal(s) fired on exploit trace:")
        for s in signals:
            print(f"  - {s.signal_id} ({s.severity}): {s.matched_text[:80]!r}")
        sys.exit(1)
    print("PASS: 0 signals fired on the exploit trace (unknown-shape premise holds)")


if __name__ == "__main__":
    main()
