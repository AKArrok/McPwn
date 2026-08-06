"""L2 judge prompt externalization tests (HANDOFF rule 3).

- judge_system.md / judge_user.md render without error.
- user message includes vuln_class, target, call indices.
- make_judge_fn sends the rendered system prompt (not an inline string).
- verifier no longer carries an inline _JUDGE_SYSTEM constant.
"""
from __future__ import annotations

import types

from mcp_redteam.agent.verifier import (
    _JUDGE_SYSTEM_TMPL,
    _JUDGE_USER_TMPL,
    make_judge_fn,
)
from mcp_redteam.contracts import AttackTrace, McpCall, VulnClass
from mcp_redteam.judge.parse import parse_judge_json


def _trace() -> AttackTrace:
    return AttackTrace(
        vuln_class=VulnClass.INDIRECT_INJECTION,
        target="notes://x",
        strategy_card_slug="indirect_injection",
        recon_calls=[],
        attack_calls=[
            McpCall(
                kind="call_tool", name="add_note", args={"content": "x"},
                result_text="ok", elapsed_ms=1,
            ),
            McpCall(
                kind="read_resource", name=None, args=None,
                result_text="hello INJECTION_MARKER_abc1", elapsed_ms=1,
            ),
        ],
        attacker_messages=[
            {"role": "assistant", "content": "probe", "tool_calls": [{"function": {"name": "add_note"}}]},
            {"role": "assistant", "content": "done"},
        ],
    )


def test_system_template_renders():
    s = _JUDGE_SYSTEM_TMPL.render()
    assert "JSON only" in s
    assert "steered" in s
    assert "evidence_call_index" in s


def test_user_template_renders_with_trace_fields():
    t = _trace()
    msg = _JUDGE_USER_TMPL.render(
        vuln_class=t.vuln_class.value,
        target=t.target,
        calls="[0] call_tool | 'add_note' | ok\n[1] read_resource | None | hello INJECTION_MARKER_abc1",
        actions="  assistant tool_calls=['add_note'] | 'probe'",
    )
    assert "indirect_injection" in msg
    assert "notes://x" in msg
    assert "[1]" in msg


class _FakeCompletions:
    def __init__(self) -> None:
        self.captured: dict = {}

    def create(self, **kwargs):
        self.captured = kwargs

        class _Msg:
            content = '{"steered": false, "evidence_call_index": null, "reason": "r"}'

        class _Choice:
            message = _Msg()

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]
                self.usage = None

        return _Resp()


class _FakeClient:
    def __init__(self) -> None:
        self.chat = types.SimpleNamespace(completions=_FakeCompletions())


def test_make_judge_fn_sends_external_templates():
    client = _FakeClient()
    spec = types.SimpleNamespace(model="m", temperature=0.0, seed=None)
    fn = make_judge_fn(client, spec)
    verdict = fn(_trace(), None)
    msgs = client.chat.completions.captured["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"] == _JUDGE_SYSTEM_TMPL.render()
    assert "notes://x" in msgs[1]["content"]
    assert "indirect_injection" in msgs[1]["content"]
    assert verdict is not None and verdict.steered is False


def test_parse_judge_json_handles_code_fence():
    v = parse_judge_json(
        "```json\n{\"steered\": true, \"evidence_call_index\": 2, \"reason\": \"r\"}\n```"
    )
    assert v is not None
    assert v.steered is True
    assert v.evidence_call_index == 2


def test_no_inline_system_prompt_constant_remains():
    from mcp_redteam.agent import verifier

    assert not hasattr(verifier, "_JUDGE_SYSTEM"), "inline _JUDGE_SYSTEM must be externalized"
