"""Lock the invariant that `_minimal_poc` trims to the last signal-producing
call, so `findings.md`/`poc/*.py` stay noise-free.
"""

from __future__ import annotations

from mcp_redteam.agent.verifier import build_findings
from mcp_redteam.contracts import AttackTrace, McpCall, VulnClass


def _mkcall(text: str, name: str = "run", args: dict | None = None) -> McpCall:
    return McpCall(
        kind="call_tool",
        name=name,
        args=args or {},
        result_text=text,
        elapsed_ms=1,
    )


def test_minimal_poc_trims_noise_after_first_hit():
    """A trace with 3 attack calls where the 1st leaks etc/passwd should
    produce a 1-call PoC, not 3."""
    recon = [McpCall(kind="list_tools", name=None, args=None, result_text="- read_file: read", elapsed_ms=1)]
    attack = [
        _mkcall("root:x:0:0:root:/root:/bin/bash\n", name="read_file", args={"path": "/etc/passwd"}),
        _mkcall("permission denied", name="read_file", args={"path": "/etc/shadow"}),
        _mkcall("nope", name="read_file", args={"path": "/root/.ssh/id_rsa"}),
    ]
    trace = AttackTrace(
        vuln_class=VulnClass.PATH_TRAVERSAL,
        target="read_file",
        strategy_card_slug="path_traversal",
        recon_calls=recon,
        attack_calls=attack,
        final_llm_output="root:x:0:0:root:/root:/bin/bash",
    )

    findings, _ = build_findings([trace], trace_dir=None)
    assert findings, "expected at least one finding above threshold"
    poc = findings[0].poc_call_sequence
    assert len(poc) == 1
    assert poc[0].args == {"path": "/etc/passwd"}


def test_final_output_only_match_is_not_a_finding():
    """Grounding gate: a secret that appears ONLY in the attacker's
    final_llm_output (never in any real call_tool result) is hallucination
    and must NOT produce a finding. Regression for the 'fabricated token' bug.
    """
    attack = [
        _mkcall("recon result 1"),
        _mkcall("recon result 2"),
    ]
    trace = AttackTrace(
        vuln_class=VulnClass.DIRECT_PROMPT_INJECTION,
        target="notes://{user}",
        strategy_card_slug="direct_prompt_injection",
        recon_calls=[],
        attack_calls=attack,
        final_llm_output="sk-abcdefghijklmnopqrstuvwxyz12345",
    )
    findings, _ = build_findings([trace], trace_dir=None)
    assert not findings, "hallucinated final_output must not become a finding"


def test_etc_passwd_only_in_final_output_is_not_a_finding():
    """Grounding gate, critical-severity variant: the /etc/passwd header quoted
    by the model but absent from real results must not fire a leak signal."""
    trace = AttackTrace(
        vuln_class=VulnClass.PATH_TRAVERSAL,
        target="read_file",
        strategy_card_slug="path_traversal",
        recon_calls=[],
        attack_calls=[_mkcall("permission denied")],
        final_llm_output="root:x:0:0:root:/root:/bin/bash",
    )
    findings, _ = build_findings([trace], trace_dir=None)
    assert not findings


def test_ssrf_cloud_metadata_classifies_as_ssrf():
    """An SSRF probe that returns IMDS key names must produce an `ssrf` finding
    (evidence-driven class, not the hypothesis), with a 1-call PoC."""
    recon = [
        McpCall(kind="list_tools", name=None, args=None,
                result_text="- fetch_url: fetches a URL server-side", elapsed_ms=1)
    ]
    attack = [
        _mkcall(
            "ami-id\ninstance-id\nlocal-ipv4\n",
            name="fetch_url",
            args={"url": "http://169.254.169.254/latest/meta-data/"},
        ),
        _mkcall("Error: connection refused", name="fetch_url", args={"url": "http://127.0.0.1:22/"}),
    ]
    trace = AttackTrace(
        vuln_class=VulnClass.SSRF,
        target="fetch_url",
        strategy_card_slug="ssrf",
        recon_calls=recon,
        attack_calls=attack,
        final_llm_output="IMDS metadata keys returned by fetch_url",
    )
    findings, _ = build_findings([trace], trace_dir=None)
    assert findings, "expected at least one finding above threshold"
    assert findings[0].vuln_class == VulnClass.SSRF
    poc = findings[0].poc_call_sequence
    assert len(poc) == 1
    assert poc[0].args == {"url": "http://169.254.169.254/latest/meta-data/"}
