"""Preflight: confirm the real fetch SSRF trace fires the ssrf_internal_service
signal (or, if it doesn't, that we know before burning LLM budget).

Standard-scan path relies on the deterministic signal: args point at
127.0.0.1 (INTERNAL arg gate) and the response carries an internal banner
(Welcome to nginx!) → ssrf_internal_service (high). Assert it fires here.

Usage: python eval/fetch_ssrf/preflight_signals.py   (expect PASS: signal fired)
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
        result_text="- fetch: Give the model the ability to make web requests.",
        elapsed_ms=1,
    ),
    McpCall(
        kind="call_tool",
        name="fetch",
        args={"url": "http://127.0.0.1:9211/"},
        result_text=(
            "Content type text/plain cannot be simplified to markdown, but here is the "
            "raw content:\nContents of http://127.0.0.1:9211/:\n"
            "Welcome to nginx!\ninternal secrets: TOP-SECRET-INTRANET-2026\n"
        ),
        elapsed_ms=1,
    ),
]


def main() -> None:
    signals = run_all_signals(CALLS, "attacker final summary")
    hits = [s for s in signals if s.signal_id == "ssrf_internal_service"]
    if not hits:
        print(f"FAIL: no ssrf_internal_service on exploit trace; got: "
              f"{[(s.signal_id, s.severity) for s in signals]}")
        sys.exit(1)
    print(f"PASS: ssrf_internal_service fired ({hits[0].severity}) "
          f"idx={hits[0].source_call_index} text={hits[0].matched_text[:60]!r}")


if __name__ == "__main__":
    main()
