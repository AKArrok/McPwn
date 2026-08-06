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


def test_evidence_judge_creates_finding_on_zero_signal_trace():
    """Stage-2: a grounded LLM evidence verdict turns a 0-signal trace into a
    finding (unknown-shape vuln the signal library cannot see). Also asserts
    the premise: the exploit calls themselves fire no detector."""
    from mcp_redteam.agent.verifier import verify_trace
    from mcp_redteam.contracts import LlmEvidenceVerdict

    recon = [
        McpCall(kind="list_tools", name=None, args=None,
                result_text="- read_vault: read secret by name", elapsed_ms=1)
    ]
    attack = [
        _mkcall("created vault 'admin_vault' for owner 'admin'",
                name="create_vault",
                args={"owner": "admin", "name": "admin_vault", "secret": "s3cr3t-abc123"}),
        _mkcall("s3cr3t-abc123", name="read_vault",
                args={"owner": "", "name": "admin_vault"}),
    ]
    trace = AttackTrace(
        vuln_class=VulnClass.AUTH_BYPASS,
        target="read_vault",
        strategy_card_slug="auth_bypass",
        recon_calls=recon,
        attack_calls=attack,
        final_llm_output="empty owner read the admin secret",
    )
    sigs, _ = verify_trace(trace, None)
    assert not sigs, f"premise broken: signal library fired {[s.signal_id for s in sigs]}"

    def fake_judge(t):
        # evidence_call_index is into recon_calls + attack_calls (=2 here:
        # [0] list_tools, [1] create_vault, [2] read_vault).
        return LlmEvidenceVerdict(
            is_finding=True,
            vuln_class=VulnClass.AUTH_BYPASS,
            evidence_call_index=2,
            evidence_text="s3cr3t-abc123",
            confidence=0.9,
            reason="read_vault(owner='') returned admin's secret",
        )

    findings, _ = build_findings([trace], trace_dir=None, evidence_judge_fn=fake_judge)
    assert findings, "grounded LLM verdict must create a finding"
    assert findings[0].vuln_class == VulnClass.AUTH_BYPASS
    assert findings[0].signals[0].signal_id == "llm_evidence_verdict"
    assert findings[0].confidence >= 0.6
    poc = findings[0].poc_call_sequence
    assert poc and poc[-1].args == {"owner": "", "name": "admin_vault"}
    assert trace.llm_evidence_verdict is not None


def test_evidence_judge_ungrounded_verdict_is_ignored():
    """A verdict citing text not present in any real call result must NOT
    create a finding (anti-hallucination gate)."""
    from mcp_redteam.contracts import LlmEvidenceVerdict

    attack = [
        _mkcall("created vault ok", name="create_vault",
                args={"owner": "admin", "name": "x", "secret": "a"}),
        _mkcall("error: cannot read", name="read_vault", args={"owner": "", "name": "x"}),
    ]
    trace = AttackTrace(
        vuln_class=VulnClass.AUTH_BYPASS,
        target="read_vault",
        strategy_card_slug="auth_bypass",
        recon_calls=[],
        attack_calls=attack,
        final_llm_output="I saw the admin secret",
    )

    def lying_judge(t):
        return LlmEvidenceVerdict(
            is_finding=True,
            vuln_class=VulnClass.AUTH_BYPASS,
            evidence_call_index=1,
            evidence_text="super-secret-not-in-any-result",
            confidence=0.95,
            reason="hallucinated",
        )

    findings, _ = build_findings([trace], trace_dir=None, evidence_judge_fn=lying_judge)
    assert not findings, "ungrounded verdict must not become a finding"
