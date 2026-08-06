"""Pure helpers shared by ``runner.scan`` and the LangGraph twin.

Extracted from ``runner.py`` so ``mcp_redteam/langgraph/nodes.py`` can reuse
the ScanResult metadata helpers without importing the runner module (which
would create a nodes ↔ runner circular-import trap).

All functions are deterministic/self-contained: no session, client or
budget state, so both orchestration paths assemble identical metadata.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from typing import Any

from mcp_redteam.contracts import AttackTrace, ScanStopReason
from mcp_redteam.models.chat import load_registry
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock


def safe_git_sha() -> str:
    """Best-effort current HEAD; empty string outside a git repo or on error.

    Used as a reproducibility anchor in ``ScanResult.git_sha`` so a months-old
    ``scan_result.json`` can be tied back to the code that produced it.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def config_snapshot() -> dict[str, Any]:
    """Snapshot of the parsed models.yaml registry. Empty dict on any error."""
    try:
        return load_registry()
    except Exception:
        return {}


def messages_sha1(traces: list[AttackTrace]) -> str:
    """SHA-1 of every attacker_message across traces, ordered and serialised.

    Behavioural-drift detection: if the same scan against the same target
    produces a different ``attack_messages_sha1`` between runs, the attacker
    LLM took a different decision path even if the findings look identical.
    """
    h = hashlib.sha1()
    for trace in traces:
        for msg in trace.attacker_messages:
            h.update(json.dumps(msg, sort_keys=True, default=str).encode("utf-8"))
            h.update(b"\n")
    return h.hexdigest()


def stop_reason(budget: TokenBudget, clock: WallClock, error: str | None) -> ScanStopReason:
    if error:
        return "error"
    if budget.exceeded():
        return "budget_tokens"
    if clock.exceeded():
        return "budget_time"
    return "completed"


def iso_now() -> str:
    """Current UTC timestamp in the ScanResult.started_at format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
