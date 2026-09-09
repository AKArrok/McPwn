"""Test recon classifier heuristics."""

from __future__ import annotations

import asyncio

from mcp_redteam.agent.recon import (
    _classify_resource,
    _classify_tool,
    _parse_list_resources_text,
    _parse_list_tools_text,
    recon,
)
from mcp_redteam.contracts import McpCall, VulnClass


def test_classify_tool_shell_hit():
    hits = _classify_tool("execute_command", "run a shell command")
    classes = {h[0] for h in hits}
    assert VulnClass.COMMAND_INJECTION in classes


def test_classify_tool_file_hit():
    hits = _classify_tool("read_file", "read a file from disk")
    classes = {h[0] for h in hits}
    assert VulnClass.PATH_TRAVERSAL in classes


def test_classify_tool_ssrf_hit():
    hits = _classify_tool("fetch_url", "fetches a URL server-side")
    classes = {h[0] for h in hits}
    assert VulnClass.SSRF in classes


def test_classify_resource_template():
    hits = _classify_resource("notes://{user_id}")
    classes = {h[0] for h in hits}
    assert VulnClass.DIRECT_PROMPT_INJECTION in classes


def test_parse_list_tools():
    text = "- do_a: description a\n- do_b: description b"
    pairs = _parse_list_tools_text(text)
    assert pairs == [("do_a", "description a"), ("do_b", "description b")]


def test_parse_list_resources():
    text = "- notes://{user_id} (Notes): user notes\n- internal://credentials (): secrets"
    uris = _parse_list_resources_text(text)
    assert "notes://{user_id}" in uris
    assert "internal://credentials" in uris


# ── chain_composition heuristic (M2.5: 9010 unblocked) ──────────────────────

class _StubTool:
    def __init__(self, name, description=""):
        self.name = name
        self.description = description


class _StubResource:
    def __init__(self, uri):
        self.uri = uri


class _StubMcp:
    """Minimal McpSession stand-in for the recon() async contract."""

    def __init__(self, tools, resources):
        self._tools = tools
        self._resources = resources

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def list_tools(self):
        return McpCall(
            kind="list_tools",
            result_text="\n".join(f"- {t.name}: {t.description}" for t in self._tools),
            elapsed_ms=1,
        )

    async def list_resources(self):
        return McpCall(
            kind="list_resources",
            result_text="\n".join(f"- {r.uri} (n): d" for r in self._resources),
            elapsed_ms=1,
        )

    async def raw_list_tools(self):
        return list(self._tools)

    async def raw_list_resources(self):
        return list(self._resources)


def _run_recon(tools, resources):
    async def go():
        async with _StubMcp(tools, resources) as s:
            return await recon(s)
    return asyncio.run(go())


def test_chain_composition_emitted_for_multi_class_server():
    """Server exposing tools from >= 2 distinct vuln classes must yield
    one chain_composition candidate. Target is comma-joined kind:name tokens."""
    tools = [
        _StubTool("execute_command", "run shell"),
        _StubTool("read_file", "read file"),
        _StubTool("verify_token", "verify auth token"),
    ]
    _, candidates, _, _, _ = _run_recon(tools, [])
    chain = [c for c in candidates if c.vuln_class == VulnClass.CHAIN_COMPOSITION]
    assert len(chain) == 1, f"expected 1 chain candidate, got {len(chain)}"
    assert chain[0].score == 0.7
    assert "tool:" in chain[0].target
    assert "," in chain[0].target  # multi-token
    assert chain[0].target_kind == "chain"


def test_chain_composition_absent_for_single_class_server():
    """All-tools-same-class server must NOT emit a chain candidate (chain
    is by definition >= 2 vuln classes; one-class is not chain)."""
    tools = [
        _StubTool("read_file", "read file"),
        _StubTool("read_config", "read config file"),
    ]
    _, candidates, _, _, _ = _run_recon(tools, [])
    chain = [c for c in candidates if c.vuln_class == VulnClass.CHAIN_COMPOSITION]
    assert chain == [], f"single-class server should not chain; got {chain}"


def test_chain_composition_caps_target_list_at_four():
    """Chain target list caps at 4 anchors to keep the strategy card / LLM
    context bounded. With 6 tools across 3 classes, chain target should
    have at most 4 tokens."""
    tools = [
        _StubTool("execute_command", "run shell"),
        _StubTool("read_file", "read file"),
        _StubTool("verify_token", "verify token"),
        _StubTool("grant_role", "grant admin role"),
        _StubTool("read_config", "read config"),
        _StubTool("process_doc", "process document"),
    ]
    _, candidates, _, _, _ = _run_recon(tools, [])
    chain = [c for c in candidates if c.vuln_class == VulnClass.CHAIN_COMPOSITION]
    assert len(chain) == 1
    tokens = chain[0].target.split(",")
    assert len(tokens) <= 4, f"expected cap of 4 anchors, got {len(tokens)}: {tokens}"


def test_chain_composition_includes_resources():
    """Resources that map to direct_prompt_injection should also appear in
    the chain target list (e.g. injection resource + exec tool = chain)."""
    tools = [_StubTool("execute_command", "run shell")]
    resources = [_StubResource("internal://secrets")]
    _, candidates, _, _, _ = _run_recon(tools, resources)
    chain = [c for c in candidates if c.vuln_class == VulnClass.CHAIN_COMPOSITION]
    assert len(chain) == 1
    assert "resource:internal://secrets" in chain[0].target
