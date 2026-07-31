"""Smoke tests for the sensitive-data-leak signals."""

from __future__ import annotations

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import (
    detect_leaks_api_key_shape,
    detect_leaks_etc_passwd,
    detect_leaks_hardcoded_password,
    detect_leaks_shadow_hash,
    detect_leaks_ssh_private_key,
)


def _mkcall(text: str) -> McpCall:
    return McpCall(
        kind="call_tool",
        name="dummy",
        args={},
        result_text=text,
        elapsed_ms=1,
    )


def test_leaks_etc_passwd_fires_on_root_line():
    call = _mkcall("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    result = detect_leaks_etc_passwd([call], "")
    assert result is not None
    assert result.severity == "critical"
    # critical matches are redacted: the raw hit must NOT be echoed, but the
    # fingerprint must carry the short head and length for traceability.
    assert "root:x:0:0" not in result.matched_text
    assert result.matched_text.startswith("<redacted head=")


def test_leaks_etc_passwd_no_false_positive():
    call = _mkcall("hello world, no sensitive stuff")
    assert detect_leaks_etc_passwd([call], "") is None


def test_leaks_api_key_fires_on_sk_prefix():
    call = _mkcall("Your API key is sk-abcdef0123456789abcdef and expires never.")
    result = detect_leaks_api_key_shape([call], "")
    assert result is not None
    assert result.severity == "high"


def test_leaks_ssh_private_key():
    call = _mkcall("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...\n-----END OPENSSH PRIVATE KEY-----")
    result = detect_leaks_ssh_private_key([call], "")
    assert result is not None
    assert result.severity == "critical"


def test_leaks_shadow_hash():
    call = _mkcall("root:$6$abcd1234$hashhashhashhashhash:19000:0:99999:7:::")
    result = detect_leaks_shadow_hash([call], "")
    assert result is not None


def test_leaks_hardcoded_password():
    call = _mkcall("username: alice\npassword: hunter2secret\n")
    result = detect_leaks_hardcoded_password([call], "")
    assert result is not None


def test_leaks_ignore_list_tools_descriptions():
    """Regression: leak detectors must not scan tool metadata. A tool whose
    description happens to include example secrets would otherwise trip
    high/critical signals and poison findings.md."""
    lt = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- fetch: e.g. api key sk-abcdefghijklmnopqrstuvwxyz1234\n"
            "- login: expects password: hunter2secret in args"
        ),
        elapsed_ms=1,
    )
    assert detect_leaks_api_key_shape([lt], "") is None
    assert detect_leaks_hardcoded_password([lt], "") is None
