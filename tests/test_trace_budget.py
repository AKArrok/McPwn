"""Per-trace token cap + executor context compaction.

Regression background: one 9010 llm-points trace burned the whole 40k budget
with 50 calls and 0 findings, and half the DVMCP ports stop at budget_tokens
with later candidates unexecuted. The trace cap (runner-resolved fraction of
the scan budget) bounds what ONE trace may spend so a wrong lead rotates to
the next candidate. Compaction trims old tool results from the attacker LLM's
message history - the dominant prompt-token sink - while every evidence
consumer (signals, evidence judge, L2 judge, PoC replay) keeps reading the
full text from attack_calls.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Self
from unittest.mock import patch

from mcp_redteam.agent.executor import (
    _KEEP_RECENT_TURNS,
    _TOOL_DIGEST_CHARS,
    _compact_tool_results,
    execute_one,
)
from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import McpCall, VulnClass
from mcp_redteam.models.chat import ModelSpec
from mcp_redteam.orchestrator.budget import TokenBudget, WallClock
from mcp_redteam.orchestrator.runner import (
    _TRACE_CAP_FRACTION,
    _resolve_trace_token_cap,
)
from tests.fixtures.stub_attacker import (
    FakeChatCompletions,
    _msg,
    _resp,
    _tc,
)

# ── _resolve_trace_token_cap (mirrors the llm_hyp_budget knob semantics) ─────


def test_resolve_trace_cap_default_is_fraction():
    assert _resolve_trace_token_cap(30000, None) == int(30000 * _TRACE_CAP_FRACTION)


def test_resolve_trace_cap_minus_one_disables():
    assert _resolve_trace_token_cap(30000, -1) is None


def test_resolve_trace_cap_explicit_override():
    assert _resolve_trace_token_cap(30000, 5000) == 5000


# ── _compact_tool_results: structure-preserving history trim ─────────────────


def _mk_history(n_tool_turns: int, result_chars: int = 5000) -> list[dict]:
    """System + user + n assistant-with-tool_calls turns, each with one tool
    result of ``result_chars`` chars."""
    messages: list[dict] = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "attack this"},
    ]
    for i in range(n_tool_turns):
        messages.append({
            "role": "assistant", "content": "",
            "tool_calls": [{"id": f"c{i}", "type": "function",
                            "function": {"name": "probe", "arguments": "{}"}}],
        })
        messages.append({"role": "tool", "tool_call_id": f"c{i}",
                         "content": "A" * result_chars})
    return messages


def test_compact_noop_when_few_turns():
    messages = _mk_history(_KEEP_RECENT_TURNS)
    assert _compact_tool_results(messages) == 0
    # nothing truncated
    assert all(len(m.get("content") or "") == 5000
               for m in messages if m.get("role") == "tool")


def test_compact_truncates_only_old_turns():
    messages = _mk_history(_KEEP_RECENT_TURNS + 2)  # 4 turns -> 2 old, 2 recent
    n = _compact_tool_results(messages)
    tool_msgs = [m for m in messages if m.get("role") == "tool"]
    assert n == 2
    # old turns truncated to digest + marker
    for m in tool_msgs[:-_KEEP_RECENT_TURNS]:
        assert len(m["content"]) < _TOOL_DIGEST_CHARS + 200
        assert "truncated" in m["content"]
    # recent turns keep the full result
    for m in tool_msgs[-_KEEP_RECENT_TURNS:]:
        assert m["content"] == "A" * 5000
    # system / user / assistant entries untouched
    assert messages[0]["content"] == "system prompt"
    assert messages[1]["content"] == "attack this"
    assert all(m.get("tool_calls") for m in messages if m.get("role") == "assistant")


def test_compact_idempotent():
    messages = _mk_history(5)
    first = _compact_tool_results(messages)
    second = _compact_tool_results(messages)
    assert first > 0 and second == 0


def test_compact_preserves_message_count_and_pairing():
    messages = _mk_history(6)
    before = [(m.get("role"), m.get("tool_call_id")) for m in messages]
    _compact_tool_results(messages)
    after = [(m.get("role"), m.get("tool_call_id")) for m in messages]
    assert before == after  # shortened in place, never removed


# ── offline fixtures for the executor-level cap test ─────────────────────────


class _LongResultSession:
    """Minimal McpSession stand-in: one tool, every call returns a long result."""

    def __init__(self, result_chars: int = 5000) -> None:
        self._result = "A" * result_chars
        self.call_log: list[str] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def list_tools(self) -> McpCall:
        return McpCall(kind="list_tools", name=None, args=None,
                       result_text="- probe: probe tool", elapsed_ms=1)

    async def list_resources(self) -> McpCall:
        return McpCall(kind="list_resources", name=None, args=None,
                       result_text="", elapsed_ms=1)

    async def raw_list_tools(self) -> list:
        return [SimpleNamespace(
            name="probe", description="probe tool",
            inputSchema={"type": "object", "properties": {"q": {"type": "string"}},
                         "required": ["q"]},
        )]

    async def raw_list_resources(self) -> list:
        return []

    async def call_tool(self, name: str, args=None) -> McpCall:
        self.call_log.append(name)
        return McpCall(kind="call_tool", name=name, args=dict(args or {}),
                       result_text=self._result, elapsed_ms=1)

    async def read_resource(self, uri: str) -> McpCall:
        return McpCall(kind="read_resource", name=uri, args=None,
                       result_text=self._result, elapsed_ms=1)


def _tool_call_attacker(n_responses: int, in_tok: int = 500, out_tok: int = 100):
    """Stub attacker that always emits one tool_call - never converges on its
    own, so only the caps can stop the loop."""
    seq = [
        _resp(_msg(None, tool_calls=[_tc(f"c{i}", "probe", {"q": str(i)})]),
              in_tok=in_tok, out_tok=out_tok)
        for i in range(n_responses)
    ]
    client = SimpleNamespace(chat=SimpleNamespace(completions=FakeChatCompletions(seq)))
    spec = ModelSpec(role="attacker", provider="fake", base_url="", model="cap-replay",
                     temperature=0.0, timeout=60.0, key_env="")
    return client, spec


def _mk_candidate() -> Candidate:
    return Candidate(vuln_class=VulnClass.SSRF, target="probe",
                     target_kind="tool", score=0.85, reason="r")


def test_execute_one_stops_on_trace_cap():
    session = _LongResultSession()
    attacker = _tool_call_attacker(n_responses=50)
    budget = TokenBudget(max_tokens_total=30000)
    clock = WallClock(wall_seconds=600)
    recon_calls = [McpCall(kind="list_tools", name=None, args=None,
                           result_text="- probe: probe tool", elapsed_ms=1)]

    # per-turn usage = 500 in + 100 out = 600; cap 2400 -> 4 LLM calls
    # (600, 1200, 1800, 2400), then the loop-top cap check breaks. The 4th
    # loop iteration's compaction saw 3 turns, so the first tool result is
    # already a digest when the trace stops.
    trace = asyncio.run(execute_one(
        session=session, candidate=_mk_candidate(), attacker=attacker,
        budget=budget, clock=clock, sse_url="http://t/sse",
        recon_calls=recon_calls, max_inner_steps=12, trace_token_cap=2400,
    ))

    fake = attacker[0].chat.completions
    assert len(fake.calls) == 4, (
        f"expected cap to stop the loop after 4 LLM calls, got {len(fake.calls)}"
    )
    assert trace.tokens_in == 2000 and trace.tokens_out == 400
    assert "token cap 2400" in trace.final_llm_output
    assert len(session.call_log) == 4

    # Compaction ran: the first tool result is a digest in the message
    # history...
    tool_msgs = [m for m in trace.attacker_messages if m.get("role") == "tool"]
    assert len(tool_msgs) == 4
    assert "truncated" in tool_msgs[0]["content"]
    # ...but attack_calls keep the FULL result text (evidence untouched).
    assert all(len(c.result_text) == 5000 for c in trace.attack_calls)


def test_execute_one_uncapped_by_default():
    session = _LongResultSession()
    attacker = _tool_call_attacker(n_responses=50)
    budget = TokenBudget(max_tokens_total=30000)
    clock = WallClock(wall_seconds=600)
    recon_calls = [McpCall(kind="list_tools", name=None, args=None,
                           result_text="- probe: probe tool", elapsed_ms=1)]

    trace = asyncio.run(execute_one(
        session=session, candidate=_mk_candidate(), attacker=attacker,
        budget=budget, clock=clock, sse_url="http://t/sse",
        recon_calls=recon_calls, max_inner_steps=5,  # only max_inner_steps stops it
    ))

    assert len(attacker[0].chat.completions.calls) == 5
    assert trace.tokens_in == 5 * 500


# ── runner wiring: scan() resolves and forwards the cap to both paths ────────


def test_scan_passes_resolved_cap_to_executor(tmp_path):
    from mcp_redteam.orchestrator import runner as runner_mod
    from tests.fixtures.mock_mcp import FakeMcpSession
    from tests.fixtures.stub_attacker import fake_make_client

    captured: list = []
    real = runner_mod.execute_one

    async def _spy(**kwargs):
        captured.append(kwargs.get("trace_token_cap"))
        return await real(**kwargs)

    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession), \
         patch.object(runner_mod, "execute_one", _spy):
        asyncio.run(runner_mod.scan(
            sse_url="http://127.0.0.1:9001/sse",
            out_dir=tmp_path,
            max_tokens=10_000,
            wall_seconds=60,
            max_candidates=5,
        ))

    assert captured, "scan never called execute_one"
    assert all(c == 4000 for c in captured), captured  # 40% of 10k


def test_scan_disabled_cap_forwarded_as_none(tmp_path):
    from mcp_redteam.orchestrator import runner as runner_mod
    from tests.fixtures.mock_mcp import FakeMcpSession
    from tests.fixtures.stub_attacker import fake_make_client

    captured: list = []
    real = runner_mod.execute_one

    async def _spy(**kwargs):
        captured.append(kwargs.get("trace_token_cap"))
        return await real(**kwargs)

    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession), \
         patch.object(runner_mod, "execute_one", _spy):
        asyncio.run(runner_mod.scan(
            sse_url="http://127.0.0.1:9001/sse",
            out_dir=tmp_path,
            max_tokens=10_000,
            wall_seconds=60,
            max_candidates=5,
            trace_token_cap=-1,
        ))

    assert captured and all(c is None for c in captured), captured


def test_graph_path_passes_resolved_cap(tmp_path):
    """The LangGraph twin must forward the same resolved cap (parity)."""
    from mcp_redteam.langgraph import nodes as nodes_mod
    from mcp_redteam.orchestrator import runner as runner_mod
    from tests.fixtures.mock_mcp import FakeMcpSession
    from tests.fixtures.stub_attacker import fake_make_client

    captured: list = []
    real = nodes_mod.execute_one

    async def _spy(**kwargs):
        captured.append(kwargs.get("trace_token_cap"))
        return await real(**kwargs)

    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession), \
         patch.object(nodes_mod, "execute_one", _spy):
        asyncio.run(runner_mod.scan(
            sse_url="http://127.0.0.1:9001/sse",
            out_dir=tmp_path,
            max_tokens=10_000,
            wall_seconds=60,
            max_candidates=5,
            graph=True,
        ))

    assert captured, "graph scan never called execute_one"
    assert all(c == 4000 for c in captured), captured
