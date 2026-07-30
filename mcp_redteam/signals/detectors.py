"""Signal detector functions.

Contract:
    detect_<signal_id>(mcp_calls, final_output) -> EvidenceSignal | None

Each detector that can point to a specific call MUST set
``source_call_index``; that lets ``verifier._minimal_poc`` trim the reported
PoC to the tail of noise-free calls. Detectors that only match against
the aggregate final LLM output may leave ``source_call_index=None``.

``source_call_index`` orient (contracts.py): index into the combined list
``recon_calls + attack_calls`` passed by the verifier. Detectors here MUST
preserve that convention.

HANDOFF paragraph 6: M0-M2 mandatory set = 12 signals.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Callable

from mcp_redteam.contracts import (
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    EvidenceSignal,
    McpCall,
    Severity,
)

_log = logging.getLogger(__name__)

# Detectors that scan the *contents* returned from the server for sensitive
# payloads must ignore ``list_tools`` / ``list_resources`` output, since those
# only carry tool metadata (name + description). A description that documents
# an example ("password: hunter2") would otherwise trip leak detectors and
# poison findings.md.
_CONTENT_KINDS: frozenset[str] = frozenset({"call_tool", "read_resource"})

# Fingerprint / redact matched_text for critical/high signals so findings.md
# and PoC replay scripts do not exfiltrate raw secrets to disk.
_REDACT_SEVERITIES = {"critical", "high"}
_MATCHED_TEXT_MAX = 200


# ── helpers ──────────────────────────────────────────────────────────────────


def _first_output_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _has_shell_metachar(call: McpCall) -> bool:
    if not call.args:
        return False
    args_str = json.dumps(call.args)
    return bool(re.search(r"[;&|`$()]", args_str))


def _redact(matched: str, severity: Severity) -> str:
    """Fingerprint critical/high matched text so raw secrets never touch disk.

    Keep a short prefix + length + SHA-1[:10] so the finding is auditable
    without leaking full ``/etc/passwd`` lines, SSH private keys, or plaintext
    passwords into ``findings.md`` / PoC scripts. Medium/low/info signals are
    passed through (truncated by EvidenceSignal's max_length).
    """
    if severity not in _REDACT_SEVERITIES:
        return matched[:_MATCHED_TEXT_MAX]
    import hashlib

    digest = hashlib.sha1(matched.encode("utf-8", "surrogatepass")).hexdigest()[:10]
    head = matched[:8].replace("\n", " ")
    return f"<redacted head={head!r} len={len(matched)} sha1={digest}>"


def _signal(
    signal_id: str,
    severity: Severity,
    matched_text: str,
    source_call_index: int | None = None,
) -> EvidenceSignal:
    return EvidenceSignal(
        signal_id=signal_id,
        severity=severity,
        matched_text=_redact(matched_text, severity),
        source_call_index=source_call_index,
    )


def _scan_calls(
    mcp_calls: list[McpCall],
    final_output: str,
    pattern: re.Pattern[str],
    *,
    kinds: frozenset[str] | None = None,
) -> tuple[re.Match[str] | None, int | None]:
    """Scan matching-kind calls (in order) then ``final_output``.

    Returns ``(first_match, source_call_index)``. ``source_call_index=None``
    means the match came from ``final_output`` only. ``kinds`` restricts the
    scan to specific ``McpCall.kind`` values; leak detectors pass
    ``_CONTENT_KINDS`` so tool/resource descriptions never trip them.
    """
    for i, call in enumerate(mcp_calls):
        if kinds is not None and call.kind not in kinds:
            continue
        m = pattern.search(call.result_text)
        if m:
            return m, i
    m = pattern.search(final_output)
    if m:
        return m, None
    return None, None
# ── A. sensitive-data leaks ──────────────────────────────────────────────────


_ETC_PASSWD_RE = re.compile(r"^(?:root:x:0:0|daemon:x:1:1)", re.MULTILINE)
_SHADOW_HASH_RE = re.compile(r"(?<!\w)\$[156y]\$")
_SSH_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----")
_API_KEY_RE = re.compile(
    r"(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})"
)
_HARDCODED_PW_RE = re.compile(
    r'(?:password|passwd|secret)\s*[:=]\s*(\S{8,})', re.IGNORECASE
)


def detect_leaks_etc_passwd(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _ETC_PASSWD_RE, kinds=_CONTENT_KINDS)
    if m:
        return _signal("leaks_etc_passwd", "critical", m.group(), idx)
    return None


def detect_leaks_shadow_hash(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _SHADOW_HASH_RE, kinds=_CONTENT_KINDS)
    if m:
        return _signal("leaks_shadow_hash", "critical", m.group(), idx)
    return None


def detect_leaks_ssh_private_key(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _SSH_KEY_RE, kinds=_CONTENT_KINDS)
    if m:
        return _signal("leaks_ssh_private_key", "critical", m.group(), idx)
    return None


def detect_leaks_api_key_shape(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _API_KEY_RE, kinds=_CONTENT_KINDS)
    if m:
        return _signal("leaks_api_key_shape", "high", m.group(), idx)
    return None


def detect_leaks_hardcoded_password(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    # We reject values starting with `$` (shadow-hash prefix) to avoid double-counting.
    for i, call in enumerate(mcp_calls):
        if call.kind not in _CONTENT_KINDS:
            continue
        m = _HARDCODED_PW_RE.search(call.result_text)
        if m and not m.group(1).startswith("$"):
            return _signal("leaks_hardcoded_password", "high", m.group(), i)
    m = _HARDCODED_PW_RE.search(final_output)
    if m and not m.group(1).startswith("$"):
        return _signal("leaks_hardcoded_password", "high", m.group(), None)
    return None


# ── B. behavioral success indicators ─────────────────────────────────────────


_UID_RE = re.compile(r"uid=\d+.*gid=\d+")
_LS_ROOT_RE = re.compile(r"total \d+\s+[drwx-]{9}")
_ADMIN_RE = re.compile(
    r"(?:admin\s+(?:command|action|access)\s+(?:executed|granted|confirmed)"
    r"|successfully\s+(?:authenticated|authorized)\s+admin"
    r"|admin\s+privilege\w*\s+(?:granted|enabled|set))",
    re.IGNORECASE,
)


def detect_command_exec_uid_stdout(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _UID_RE)
    if m:
        return _signal("command_exec_uid_stdout", "high", m.group(), idx)
    return None


def detect_command_exec_ls_root(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    # Fire only when a same-call args have shell metachars AND the same or
    # subsequent call output looks like ls -l.
    for i, call in enumerate(mcp_calls):
        m = _LS_ROOT_RE.search(call.result_text)
        if not m:
            continue
        # metachar in this call or any earlier attack call in same trace
        for j in range(i, -1, -1):
            if mcp_calls[j].kind == "call_tool" and _has_shell_metachar(mcp_calls[j]):
                return _signal("command_exec_ls_root", "medium", m.group(), i)
    return None


def detect_admin_action_confirmed(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    m, idx = _scan_calls(mcp_calls, final_output, _ADMIN_RE)
    if m:
        return _signal("admin_action_confirmed", "high", m.group(), idx)
    return None


# HANDOFF §6: "unauthenticated tool_call whose auth_token is empty/fake and
# whose response still indicates success". Signal fires only when the tool
# call *carries an auth-shaped argument* (i.e. the tool has an auth concept)
# AND that argument is empty / obviously fake AND the response reads as a
# success. Naked keyword hits like "ok" are too weak; require phrase-level
# matches so we do not flood findings.md.
_AUTH_ARG_KEYS: tuple[str, ...] = (
    "auth_token", "authToken", "token", "api_key", "apiKey", "session_token",
)
_AUTH_SUCCESS_PHRASES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"access\s+granted",
        r"authenticated\s+as",
        r"authorized\s+as",
        r"login\s+successful",
        r"welcome[, ]+\s*(?:admin|root|user)",
        r"admin\s+access\s+(?:granted|enabled)",
        r"authentication\s+successful",
    )
)


def _looks_like_fake_auth(value: object) -> bool:
    """Return True when a value is present but empty / obviously fake."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return True
    if len(stripped) < 6:
        return True
    return stripped.lower() in {"fake", "test", "dummy", "guest", "none", "null"}


def detect_unauthenticated_success(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool" or not call.args:
            continue
        # The tool must have an auth-shaped parameter for this signal to apply.
        present_key = next(
            (k for k in _AUTH_ARG_KEYS if k in call.args), None
        )
        if present_key is None:
            continue
        if not _looks_like_fake_auth(call.args.get(present_key)):
            continue
        for phrase in _AUTH_SUCCESS_PHRASES:
            m = phrase.search(call.result_text)
            if m:
                return _signal(
                    "unauthenticated_success",
                    "high",
                    f"{present_key}={call.args.get(present_key)!r} => {m.group()}",
                    source_call_index=i,
                )
    return None


# ── C. metadata anomalies ────────────────────────────────────────────────────


def _parse_list_tools_lookup(text: str) -> dict[str, str]:
    """Parse `- name: description` lines into a dict."""
    lookup: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("- "):
            continue
        content = s[2:]
        colon_pos = content.find(":")
        if colon_pos == -1:
            continue
        lookup[content[:colon_pos].strip()] = content[colon_pos + 1:].strip()
    return lookup


def detect_tool_description_drift(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Fires when two `list_tools` snapshots disagree on any tool's description.

    NOTE: verifier must feed us `recon_calls + attack_calls`; a single scan-time
    list_tools alone will never fire this.
    """
    snapshots: list[tuple[int, dict[str, str]]] = []
    for i, call in enumerate(mcp_calls):
        if call.kind == "list_tools":
            snapshots.append((i, _parse_list_tools_lookup(call.result_text)))
    if len(snapshots) < 2:
        return None

    # Compare each snapshot against its predecessor so that a description that
    # changes and then reverts (base == last but middle differs) still fires.
    prev_idx, prev = snapshots[0]
    for later_idx, later in snapshots[1:]:
        for name, desc in prev.items():
            if name in later and later[name] != desc:
                matched = f"{name}: {desc[:60]!r} -> {later[name][:60]!r}"
                return _signal(
                    "tool_description_drift", "medium", matched, later_idx
                )
        prev_idx, prev = later_idx, later
    return None


def _lev(a: str, b: str) -> int:
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i
    for j in range(m + 1):
        dp[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[n][m]


def _desc_similarity(a: str, b: str) -> float:
    """Cheap token-set Jaccard for descriptions (>0.7 threshold in HANDOFF §6)."""
    ta = {t.lower() for t in re.findall(r"[a-zA-Z_]+", a)}
    tb = {t.lower() for t in re.findall(r"[a-zA-Z_]+", b)}
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def detect_shadow_tool_pair(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """HANDOFF §6: two tools whose names differ by Levenshtein <= 2 AND whose
    descriptions share Jaccard similarity > 0.7. Uses the last ``list_tools``
    snapshot in the trace.

    Keep this strict on purpose: medium-severity false positives compound with
    other signals via ``1 - prod(1 - w_i)`` and pollute findings.md. If we
    later want the looser namespace-shadow branch, that requires a HANDOFF
    amendment first.
    """
    lookup: dict[str, str] = {}
    src_idx: int | None = None
    for i in range(len(mcp_calls) - 1, -1, -1):
        if mcp_calls[i].kind == "list_tools":
            lookup = _parse_list_tools_lookup(mcp_calls[i].result_text)
            src_idx = i
            break
    if len(lookup) < 2:
        return None

    names = list(lookup.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            lev = _lev(a, b)
            if lev > 2:
                continue
            sim = _desc_similarity(lookup[a], lookup[b])
            if sim > 0.7:
                return _signal(
                    "shadow_tool_pair",
                    "medium",
                    f"{a} <-> {b} (lev={lev}, jaccard={sim:.2f})",
                    src_idx,
                )
    return None


# ── D. LLM twin verdict ──────────────────────────────────────────────────────


def detect_llm_judged_injection(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Placeholder until M2/M3 wire a small judge LLM. NOT registered in
    ``DETECTORS`` so ``run_all_signals`` does not waste a call slot on a stub.
    """
    return None


# ── registry ─────────────────────────────────────────────────────────────────

SIGNAL_META: dict[str, Severity] = {
    "leaks_etc_passwd": "critical",
    "leaks_shadow_hash": "critical",
    "leaks_ssh_private_key": "critical",
    "leaks_api_key_shape": "high",
    "leaks_hardcoded_password": "high",
    "command_exec_uid_stdout": "high",
    "command_exec_ls_root": "medium",
    "admin_action_confirmed": "high",
    "unauthenticated_success": "high",
    "tool_description_drift": "medium",
    "shadow_tool_pair": "medium",
}


DETECTORS: dict[str, Callable[[list[McpCall], str], EvidenceSignal | None]] = {
    "leaks_etc_passwd": detect_leaks_etc_passwd,
    "leaks_shadow_hash": detect_leaks_shadow_hash,
    "leaks_ssh_private_key": detect_leaks_ssh_private_key,
    "leaks_api_key_shape": detect_leaks_api_key_shape,
    "leaks_hardcoded_password": detect_leaks_hardcoded_password,
    "command_exec_uid_stdout": detect_command_exec_uid_stdout,
    "command_exec_ls_root": detect_command_exec_ls_root,
    "admin_action_confirmed": detect_admin_action_confirmed,
    "unauthenticated_success": detect_unauthenticated_success,
    "tool_description_drift": detect_tool_description_drift,
    "shadow_tool_pair": detect_shadow_tool_pair,
}


# ── public API ───────────────────────────────────────────────────────────────

def run_all_signals(
    mcp_calls: list[McpCall], final_output: str
) -> list[EvidenceSignal]:
    """Run every registered detector; return fired signals.

    A detector raising is logged and skipped so one buggy check doesn't nuke
    the scan. LLM twin verdict (``llm_judged_injection``) is deliberately not
    registered until it has a real implementation.
    """
    results: list[EvidenceSignal] = []
    for signal_id, detector in DETECTORS.items():
        try:
            fired = detector(mcp_calls, final_output)
        except Exception:  # noqa: BLE001
            _log.exception("detector %s crashed; skipping", signal_id)
            continue
        if fired is not None:
            results.append(fired)
    return results


def _dedup_signals(signals: list[EvidenceSignal]) -> list[EvidenceSignal]:
    """Keep the highest-severity signal per ``signal_id``.

    Callers that aggregate signals across multiple traces or across calls to
    ``run_all_signals`` must not double-count the same id; the
    ``1 - prod(1 - w_i)`` combiner assumes independent evidence.
    """
    best: dict[str, EvidenceSignal] = {}
    for s in signals:
        cur = best.get(s.signal_id)
        if cur is None:
            best[s.signal_id] = s
            continue
        if SEVERITY_ORDER.index(s.severity) > SEVERITY_ORDER.index(cur.severity):
            best[s.signal_id] = s
    return list(best.values())


def compute_confidence(
    signals: list[EvidenceSignal], llm_agrees: bool | None = None
) -> float:
    """Confidence = 1 - prod(1 - w_i) after per-id dedup; LLM twin +/- nudge."""
    if not signals:
        return 0.0
    prod = 1.0
    for s in _dedup_signals(signals):
        prod *= 1.0 - SEVERITY_WEIGHT.get(s.severity, 0.3)
    confidence = 1.0 - prod
    if llm_agrees is True:
        confidence += 0.1
    elif llm_agrees is False:
        confidence -= 0.2
    return max(0.0, min(1.0, confidence))


def compute_finding_severity(signals: list[EvidenceSignal]) -> Severity:
    """Return the highest severity present, defaulting to ``'info'``."""
    max_idx = 0
    for s in signals:
        try:
            idx = SEVERITY_ORDER.index(s.severity)
        except ValueError:
            continue
        if idx > max_idx:
            max_idx = idx
    return SEVERITY_ORDER[max_idx]  # type: ignore[return-value]
