"""Best-effort JSON parsing for judge LLM outputs.

parse_json_object extracts a JSON object from raw LLM text (code fences,
trailing prose). parse_judge_json maps it to a JudgeVerdict; M3's
parse_m3_report reuses parse_json_object. Any failure returns None so
callers treat judge silence as not-steered / inconclusive, never a crash.
"""

from __future__ import annotations

import json
import logging
import re

from mcp_redteam.contracts import JudgeVerdict

_log = logging.getLogger(__name__)

_FENCE = "```"


def parse_json_object(content: str) -> dict | None:
    """Return the first JSON object in content, or None if none parse."""
    s = (content or "").strip()
    if s.startswith(_FENCE):
        s = s.strip("`")
        nl = s.find("\n")
        if nl != -1:
            first = s[:nl].strip()
            if first and not first.startswith("{"):
                s = s[nl + 1 :]
        s = s.strip()
        if s.endswith(_FENCE):
            s = s[: -len(_FENCE)].strip()
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", s, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                obj = None
        else:
            obj = None
    return obj if isinstance(obj, dict) else None


def parse_judge_json(content: str) -> JudgeVerdict | None:
    """Parse the L2 judge JSON; None on any failure (treated as not-steered)."""
    obj = parse_json_object(content)
    if obj is None:
        _log.warning("judge returned unparseable JSON: %r", (content or "")[:200])
        return None
    steered = bool(obj.get("steered", False))
    idx = obj.get("evidence_call_index")
    if not (isinstance(idx, int) or idx is None):
        idx = None
    return JudgeVerdict(
        steered=steered,
        evidence_call_index=idx,
        reason=str(obj.get("reason", ""))[:200],
    )
