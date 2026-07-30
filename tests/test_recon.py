"""Test recon classifier heuristics."""

from __future__ import annotations

from mcp_redteam.agent.recon import (
    _classify_resource,
    _classify_tool,
    _parse_list_resources_text,
    _parse_list_tools_text,
)
from mcp_redteam.contracts import VulnClass


def test_classify_tool_shell_hit():
    hits = _classify_tool("execute_command", "run a shell command")
    classes = {h[0] for h in hits}
    assert VulnClass.COMMAND_INJECTION in classes


def test_classify_tool_file_hit():
    hits = _classify_tool("read_file", "read a file from disk")
    classes = {h[0] for h in hits}
    assert VulnClass.PATH_TRAVERSAL in classes


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
