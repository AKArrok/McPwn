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


_SHADOW_PAIR_ARG_KEY = "__mcpwn_probe_pair__"


def _find_shadow_pair(lookup: dict[str, str]) -> tuple[str, str] | None:
    """Return (a, b) whose names differ by lev<=2 AND descriptions jaccard>0.7.

    Same predicate as `detect_shadow_tool_pair`; exposed for the executor so it
    can decide which two tools to compare-probe.
    """
    names = list(lookup.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            if _lev(a, b) > 2:
                continue
            if _desc_similarity(lookup[a], lookup[b]) > 0.7:
                return a, b
    return None


def _same_args(a: dict | None, b: dict | None) -> bool:
    if not a and not b:
        return True
    if a is None or b is None:
        return False
    # Drop the compare-probe marker so it does not force spurious matches.
    aa = {k: v for k, v in a.items() if k != _SHADOW_PAIR_ARG_KEY}
    bb = {k: v for k, v in b.items() if k != _SHADOW_PAIR_ARG_KEY}
    return aa == bb


def _normalize_response(text: str) -> str:
    """Best-effort semantic fingerprint used for divergence/flip comparisons.

    - Strip runs of whitespace.
    - Zero out obvious volatile fields (timestamps, uuids, dates, numbers).
    """
    s = text or ""
    s = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TS>", s)
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>", s)
    # Digit runs, allowing an immediately trailing single unit letter (F, C,
    # ms, %) or punctuation. This is a semantic fingerprint, not a security
    # boundary; a fluctuating "71F" -> "72F" should not fire rug_pull.
    s = re.sub(r"\d+(?:\.\d+)?[a-zA-Z%]{0,3}", "<NUM>", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def detect_shadow_tool_behavior_divergence(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Fires when two similarly-named tools return *different* content for the
    same input.

    A metadata shadow pair only proves "these two tools *could* be a rug"; if
    we can also show they *behave* differently on identical args, that is an
    independent piece of evidence and shifts confidence past the 0.6 gate
    without weakening the signal model.

    Executor is expected to seed matching probe pairs by tagging each with
    ``args[_SHADOW_PAIR_ARG_KEY]`` so we can pair them cheaply. We fall back to
    "same non-marker args" matching for hand-written traces.
    """
    # Group tool calls by their marker (if any); otherwise by a canonical
    # (name-independent) args tuple built by sorting items.
    marked: dict[str, list[tuple[int, McpCall]]] = {}
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool" or not call.args:
            continue
        marker = call.args.get(_SHADOW_PAIR_ARG_KEY)
        if not isinstance(marker, str):
            continue
        marked.setdefault(marker, []).append((i, call))

    def _try_report(a_idx: int, a: McpCall, b_idx: int, b: McpCall) -> EvidenceSignal | None:
        if not a.name or not b.name or a.name == b.name:
            return None
        na = _normalize_response(a.result_text)
        nb = _normalize_response(b.result_text)
        if na == nb:
            return None
        return _signal(
            "shadow_tool_behavior_divergence",
            "medium",
            f"{a.name} vs {b.name} diverged on same args",
            source_call_index=max(a_idx, b_idx),
        )

    for group in marked.values():
        if len(group) < 2:
            continue
        (a_idx, a), (b_idx, b) = group[0], group[1]
        sig = _try_report(a_idx, a, b_idx, b)
        if sig is not None:
            return sig

    # Fallback: pair any two call_tool entries with different names but
    # identical non-marker args, in call order.
    seen: list[tuple[int, McpCall]] = []
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool":
            continue
        for prev_i, prev in seen:
            if prev.name == call.name:
                continue
            if _same_args(prev.args, call.args):
                sig = _try_report(prev_i, prev, i, call)
                if sig is not None:
                    return sig
        seen.append((i, call))
    return None


_RUG_PULL_MARKER = "__mcpwn_rug_probe__"


def detect_rug_pull_response_flip(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Fires when repeat calls to the same tool with the same args (excluding
    the rug-pull probe marker) produce materially different responses after N
    invocations. Executor seeds four consecutive probes tagged with
    ``args[_RUG_PULL_MARKER]`` so we can attribute the sequence.

    Rationale: DVMCP challenge 4 mutates ``get_weather`` after the 4th call.
    Description drift is one indicator; response-body flip is an independent
    behavioral one. Ignore volatile fields (timestamps, uuids, numbers) so a
    'sunny 71F at 12:03' vs 'sunny 71F at 12:04' does not spuriously fire.
    """
    groups: dict[str, list[tuple[int, McpCall]]] = {}
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool" or not call.args:
            continue
        marker = call.args.get(_RUG_PULL_MARKER)
        if not isinstance(marker, str):
            continue
        groups.setdefault(marker, []).append((i, call))

    for group in groups.values():
        if len(group) < 2:
            continue
        # Take fingerprint of the FIRST call and compare each subsequent one.
        first_idx, first = group[0]
        first_norm = _normalize_response(first.result_text)
        for later_idx, later in group[1:]:
            if _normalize_response(later.result_text) != first_norm:
                return _signal(
                    "rug_pull_response_flip",
                    "medium",
                    f"{first.name} response changed between call#1 and call#{group.index((later_idx, later)) + 1}",
                    source_call_index=later_idx,
                )
    return None


_SUSPICIOUS_ERROR_PATTERNS: list[re.Pattern[str]] = [
    # Sales/upsell pitches in an error string are a classic rug-pull tell:
    # the service behaves normally until a threshold, then "upgrades" you
    # into paying or leaks something else.
    re.compile(r"\b(premium|pro plan|paid tier|subscription required)\b", re.IGNORECASE),
    re.compile(r"\b(upgrade to|subscribe to|payment required)\b", re.IGNORECASE),
    # Admin / credential language in tool output is never benign.
    re.compile(r"\b(admin access|credentials leaked|internal credentials)\b", re.IGNORECASE),
]


def detect_suspicious_error_pitch(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Fires when a call_tool response looks like an error but ALSO contains
    upsell/admin/credential language.

    Independent complement to ``rug_pull_response_flip``: a benign rate-limit
    says "try again later"; a malicious one advertises paid tiers or leaks
    admin content. Firing both pushes confidence across the 0.6 gate for
    single-tool rug-pull targets like DVMCP 9004.
    """
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool":
            continue
        text = call.result_text or ""
        # Must look error-ish first so we don't flag benign prose.
        if not re.search(r"\b(error|failed|denied|limit|exceeded)\b", text, re.IGNORECASE):
            continue
        for pat in _SUSPICIOUS_ERROR_PATTERNS:
            m = pat.search(text)
            if m:
                return _signal(
                    "suspicious_error_pitch",
                    "medium",
                    m.group(),
                    source_call_index=i,
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


# ── E. injection-surface roundtrip ───────────────────────────────────────────
#
# Prompt injection at L0/L1 (see PROMPT_INJECTION_GAP.md): agent-first has no
# resident victim LLM, so we do not observe an LLM being steered. Instead we
# prove the *surface* exists at the server IO layer by canary roundtrip: the
# attacker writes an INJECTION_MARKER via one tool call, and if any later
# call_tool / read_resource result contains the same marker verbatim, the
# server persisted user input without sanitization. This is the L0/L1
# analogue of "SQL payload made it into the query"; L2 impact on a downstream
# consumer LLM is a follow-on inference, not a test judgement.

_INJECTION_MARKER_RE = re.compile(r"INJECTION_MARKER_[A-Za-z0-9]{4,}")


def _extract_markers_from_args(args: dict | None) -> set[str]:
    if not args:
        return set()
    markers: set[str] = set()

    def _walk(v: object) -> None:
        if isinstance(v, str):
            markers.update(_INJECTION_MARKER_RE.findall(v))
        elif isinstance(v, dict):
            for x in v.values():
                _walk(x)
        elif isinstance(v, list):
            for x in v:
                _walk(x)

    _walk(args)
    return markers


def detect_stored_injection_roundtrip(
    mcp_calls: list[McpCall], final_output: str
) -> EvidenceSignal | None:
    """Fires when an ``INJECTION_MARKER_*`` placed in a ``call_tool`` arg
    comes back verbatim in a subsequent ``call_tool`` / ``read_resource``
    result, or is reflected in that same call's own result.

    Evidence: the server persisted or reflected user input without stripping
    the canary. Proves the stored / reflected injection surface exists at the
    server IO layer. Does **not** prove a downstream LLM would be steered
    (that is L2; see ``PROMPT_INJECTION_GAP.md``). Strategy cards
    ``direct_prompt_injection`` and ``indirect_injection`` mandate the marker
    format so this detector stays low-noise.
    """
    written: dict[str, int] = {}
    for i, call in enumerate(mcp_calls):
        if call.kind != "call_tool":
            continue
        for marker in _extract_markers_from_args(call.args):
            written.setdefault(marker, i)
    if not written:
        return None
    for i, call in enumerate(mcp_calls):
        if call.kind not in _CONTENT_KINDS:
            continue
        for marker, wrote_at in written.items():
            if i < wrote_at:
                continue
            if marker not in call.result_text:
                continue
            if i == wrote_at:
                return _signal(
                    "stored_injection_roundtrip",
                    "medium",
                    f"marker={marker!r} reflected_at_idx={i}",
                    i,
                )
            return _signal(
                "stored_injection_roundtrip",
                "medium",
                f"marker={marker!r} wrote_at_idx={wrote_at} read_at_idx={i}",
                i,
            )
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
    "shadow_tool_behavior_divergence": "medium",
    "rug_pull_response_flip": "medium",
    "suspicious_error_pitch": "medium",
    "stored_injection_roundtrip": "medium",
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
    "shadow_tool_behavior_divergence": detect_shadow_tool_behavior_divergence,
    "rug_pull_response_flip": detect_rug_pull_response_flip,
    "suspicious_error_pitch": detect_suspicious_error_pitch,
    "stored_injection_roundtrip": detect_stored_injection_roundtrip,
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
