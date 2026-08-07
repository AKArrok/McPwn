"""SSRF signal detectors: args-gate (target in call args) + response-evidence gate.

External reference: mcpwn MCP-004 SSRF check + the
auditing-mcp-servers-for-tool-poisoning skill SSRF_TARGETS list.
"""

from __future__ import annotations

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import (
    detect_ssrf_cloud_metadata,
    detect_ssrf_internal_service,
)


def _mk(text: str, name: str = "fetch_url", args: dict | None = None) -> McpCall:
    return McpCall(
        kind="call_tool",
        name=name,
        args=args or {},
        result_text=text,
        elapsed_ms=1,
    )


# ── ssrf_cloud_metadata ──────────────────────────────────────────────────────

def test_metadata_directory_listing_fires():
    call = _mk(
        "ami-id\nami-launch-index\ninstance-id\nlocal-ipv4\npublic-keys\n",
        args={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    sig = detect_ssrf_cloud_metadata([call], "")
    assert sig is not None
    assert sig.signal_id == "ssrf_cloud_metadata"
    assert sig.severity == "high"


def test_metadata_single_key_value_fires():
    call = _mk(
        "i-0abc123def4567890",
        args={"url": "http://169.254.169.254/latest/meta-data/instance-id"},
    )
    assert detect_ssrf_cloud_metadata([call], "") is not None


def test_metadata_aliyun_endpoint_fires():
    call = _mk(
        "instance-id: i-2ze39oexample\nregion-id: cn-shanghai",
        args={"url": "http://100.100.100.200/latest/meta-data/"},
    )
    assert detect_ssrf_cloud_metadata([call], "") is not None


def test_metadata_gate_requires_target_in_args():
    # Key-name tokens in the response alone (no metadata endpoint in args) must NOT fire.
    call = _mk("instance-id: i-0abc123def4567890a", args={"url": "http://example.com/"})
    assert detect_ssrf_cloud_metadata([call], "") is None


def test_metadata_error_response_does_not_fire():
    call = _mk("Error: could not reach host", args={"url": "http://169.254.169.254/latest/meta-data/"})
    assert detect_ssrf_cloud_metadata([call], "") is None


# ── ssrf_internal_service ────────────────────────────────────────────────────

def test_loopback_ssh_banner_fires():
    call = _mk(
        "SSH-2.0-OpenSSH_9.6p1 Debian-3",
        args={"url": "http://127.0.0.1:22/"},
    )
    sig = detect_ssrf_internal_service([call], "")
    assert sig is not None
    assert sig.signal_id == "ssrf_internal_service"
    assert sig.severity == "high"


def test_localhost_redis_error_fires():
    call = _mk(
        "ERR unknown command 'GET'",
        args={"endpoint": "http://localhost:6379/"},
    )
    assert detect_ssrf_internal_service([call], "") is not None


def test_private_range_probe_fires_on_banner():
    call = _mk(
        "Welcome to nginx!",
        args={"url": "http://10.0.0.5/"},
    )
    assert detect_ssrf_internal_service([call], "") is not None


def test_hex_encoded_loopback_fires_on_banner():
    """Regression (real fetch target): attacker used 0x7f000001 (hex-encoded
    127.0.0.1) per the ssrf card and hit a real IIS banner, but the arg gate
    did not recognize hex-encoded IPv4 -> missed. Now must fire."""
    call = _mk(
        "<p>IIS Windows</p>",
        args={"url": "http://0x7f000001/"},
    )
    sig = detect_ssrf_internal_service([call], "")
    assert sig is not None
    assert sig.signal_id == "ssrf_internal_service"


def test_ipv6_loopback_fires_on_banner():
    call = _mk(
        "Welcome to nginx!",
        args={"url": "http://[::1]:80/"},
    )
    assert detect_ssrf_internal_service([call], "") is not None


def test_internal_gate_requires_target_in_args():
    call = _mk("Welcome to nginx!", args={"url": "http://example.com/"})
    assert detect_ssrf_internal_service([call], "") is None


def test_internal_error_response_does_not_fire():
    call = _mk("Error: 403 Forbidden", args={"url": "http://127.0.0.1:22/"})
    assert detect_ssrf_internal_service([call], "") is None


# ── cross-trigger: file:// scheme is handled by leaks_* detectors ────────────

def test_file_scheme_does_not_fire_ssrf_but_leaks_does():
    from mcp_redteam.signals.detectors import detect_leaks_etc_passwd

    call = _mk(
        "root:x:0:0:root:/root:/bin/bash",
        args={"url": "file:///etc/passwd"},
    )
    assert detect_ssrf_cloud_metadata([call], "") is None
    assert detect_ssrf_internal_service([call], "") is None
    assert detect_leaks_etc_passwd([call], "") is not None
