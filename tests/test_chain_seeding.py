"""Executor chain-composition seeding tests.

The M3 judge requires 9010 chain evidence where a later call's args reuse a
prior call's result. `_seed_chain_probe` makes that deterministic: it leaks
via one anchor tool then feeds a real snippet into another anchor tool
before the LLM loop, mirroring `_seed_metadata_probes`.
"""
from __future__ import annotations

import json
import types

import pytest

from mcp_redteam.agent.executor import _chain_probe_args, _chain_snippet, _seed_chain_probe
from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import McpCall, VulnClass
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock


def _candidate() -> Candidate:
    return Candidate(
        vuln_class=VulnClass.CHAIN_COMPOSITION,
        target="tool:get_config,tool:process_user_input",
        target_kind="chain",
        score=0.7,
        reason="chain",
    )


def _raw_tools() -> list[types.SimpleNamespace]:
    return [
        types.SimpleNamespace(
            name="get_config",
            inputSchema={"properties": {"config_name": {"type": "string"}}, "required": ["config_name"]},
        ),
        types.SimpleNamespace(
            name="process_user_input",
            inputSchema={"properties": {"input_text": {"type": "string"}}, "required": ["input_text"]},
        ),
    ]


_PASSWD_LEAK = (
    "Configuration '/etc/passwd':\n"
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
)


class _LeakySession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, args: dict):
        self.calls.append((name, args))
        if name == "get_config" and args.get("config_name") == "/etc/passwd":
            return McpCall(kind="call_tool", name=name, args=args, result_text=_PASSWD_LEAK, elapsed_ms=1)
        return McpCall(
            kind="call_tool", name=name, args=args,
            result_text="PROCESSED: " + json.dumps(args), elapsed_ms=1,
        )


@pytest.mark.asyncio
async def test_seed_chain_probe_builds_real_composition():
    session = _LeakySession()
    attack_calls: list[McpCall] = []
    note = await _seed_chain_probe(
        session=session,
        candidate=_candidate(),
        recon_calls=[],
        attack_calls=attack_calls,
        budget=TokenBudget(max_tokens_total=100000),
        clock=WallClock(wall_seconds=1000),
        raw_tools=_raw_tools(),
    )
    assert note, "seeding should return a composition note"
    assert "两步组合证据" in note
    assert len(attack_calls) == 2
    assert attack_calls[0].name == "get_config"
    assert attack_calls[1].name == "process_user_input"
    # later args reuse a real substring of the earlier result
    first = attack_calls[0].result_text
    args_str = json.dumps(attack_calls[1].args, ensure_ascii=False)
    assert any(first[k : k + 6] in args_str for k in range(max(0, len(first) - 5)))
    assert "root:x:0:0" in args_str
    # clean snippet without the prefix
    assert attack_calls[1].args["input_text"].startswith("root:x:0:0")


@pytest.mark.asyncio
async def test_seed_chain_probe_no_leak_returns_empty_note():
    class _DrySession:
        async def call_tool(self, name: str, args: dict):
            return McpCall(
                kind="call_tool", name=name, args=args,
                result_text="[mcp error] boom", elapsed_ms=0,
            )

    attack_calls: list[McpCall] = []
    note = await _seed_chain_probe(
        session=_DrySession(),
        candidate=_candidate(),
        recon_calls=[],
        attack_calls=attack_calls,
        budget=TokenBudget(max_tokens_total=100000),
        clock=WallClock(wall_seconds=1000),
        raw_tools=_raw_tools(),
    )
    assert note == ""


def test_seed_chain_probe_requires_two_tool_anchors():
    import asyncio

    c = Candidate(
        vuln_class=VulnClass.CHAIN_COMPOSITION,
        target="resource:internal://credentials,tool:get_config",
        target_kind="chain",
        score=0.7,
        reason="chain",
    )
    out = asyncio.run(
        _seed_chain_probe(
            session=_LeakySession(),
            candidate=c,
            recon_calls=[],
            attack_calls=[],
            budget=TokenBudget(max_tokens_total=100000),
            clock=WallClock(wall_seconds=1000),
            raw_tools=_raw_tools(),
        )
    )
    assert out == ""


def test_chain_snippet_handles_space_and_newline_separators():
    assert _chain_snippet("Configuration '/etc/passwd': root:x:0:0:root") == "root:x:0:0:root"
    assert _chain_snippet("Configuration '/etc/passwd':\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x") == "root:x:0:0:root:/root:/bin/bash\ndaemon:x"
    assert _chain_snippet("[mcp error] nope") == ""


def test_chain_probe_args_sets_first_string_prop():
    schema = {
        "properties": {"config_name": {"type": "string"}},
        "required": ["config_name"],
    }
    assert _chain_probe_args(schema, "/etc/passwd") == {"config_name": "/etc/passwd"}