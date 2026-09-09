"""Property-based contract tests (hypothesis).

The contracts are the project's single authority - these properties hold
for ANY input, not just curated examples:

- TargetSpec.parse: http(s) enforcement, /sse dispatch invariant, round-trip
- Finding.compute_id: determinism + injectivity-by-construction inputs
- expect_ok: total function over the documented grammar
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_redteam.contracts import Finding, TargetSpec, Transport
from mcp_redteam.report.benchmark import expect_ok

HOSTS = st.sampled_from(["127.0.0.1", "localhost", "example.com", "10.0.0.7"])
PORTS = st.integers(min_value=1, max_value=65535)


@st.composite
def http_urls(draw) -> str:
    host = draw(HOSTS)
    port = draw(PORTS)
    path = draw(st.sampled_from(["/sse", "/mcp", "/", "/messages", "/sse/x"]))
    return f"http://{host}:{port}{path}"


@given(http_urls())
@settings(max_examples=60, deadline=None)
def test_parse_always_yields_valid_transport_and_roundtrip(url: str):
    """parse never crashes on a well-formed http URL; spec survives a JSON
    round-trip; the transport is always one of the three enum members."""
    spec = TargetSpec.parse(url)
    assert spec.transport in (Transport.SSE, Transport.STREAMABLE_HTTP)
    assert spec.url == url
    revived = TargetSpec.model_validate_json(spec.model_dump_json())
    assert revived == spec


@given(http_urls())
@settings(max_examples=60, deadline=None)
def test_parse_sse_dispatch_invariant(url: str):
    """path (sans trailing slash) ending in /sse <=> transport == SSE."""
    spec = TargetSpec.parse(url)
    path = url.split("/", 3)[-1].rstrip("/")
    is_sse_path = path == "sse"
    assert (spec.transport is Transport.SSE) == is_sse_path


@given(
    host=HOSTS,
    port=PORTS,
    path=st.sampled_from(["/sse", "/mcp", "/"]),
)
def test_parse_display_survives_json(host: str, port: int, path: str):
    spec = TargetSpec.parse(f"http://{host}:{port}{path}")
    data = json.loads(spec.model_dump_json())
    # display is a @property: derived, not serialized - always recomputable
    assert data["url"] == spec.url
    assert spec.display == spec.url


@given(
    vuln=st.sampled_from(
        [
            "direct_prompt_injection",
            "command_injection",
            "path_traversal",
            "auth_bypass",
            "tool_metadata_probe",
            "indirect_injection",
            "chain_composition",
            "ssrf",
        ]
    ),
    target=st.text(min_size=1, max_size=40, alphabet=st.characters(min_codepoint=32, max_codepoint=0x4E00)),
    signal=st.text(min_size=1, max_size=20, alphabet="abcdefgh0123456789_"),
)
def test_compute_id_deterministic_and_sensitive(vuln: str, target: str, signal: str):
    id1 = Finding.compute_id(vuln, target, signal)
    id2 = Finding.compute_id(vuln, target, signal)
    assert id1 == id2
    assert id1.startswith("F-")
    # flipping any single input char must (over these alphabets) change the id
    flipped = Finding.compute_id(vuln, target, signal + "x")
    assert flipped != id1


@given(findings=st.integers(min_value=0, max_value=10))
def test_expect_ok_total_over_grammar(findings: int):
    # documented grammar: 0 | >=1 | info - a total, monotone predicate
    assert expect_ok("info", findings) is True
    assert expect_ok(">=1", findings) == (findings >= 1)
    assert expect_ok("0", findings) == (findings == 0)
