"""Stub attacker LLM: replays a fixed sequence of tool_call / final responses.

Lets the test reproduce the runs/m0_smoke decision path without a real LLM
or a network call to the ARK API. When the LLM rate limit (429 Safe Experience
Mode) blocks the real run, this stub keeps the agent loop end-to-end runnable
inside CI.

The recorded decision sequence below is hand-extracted from the
``runs/m0_smoke/scan_result.json`` ``attacker_messages`` arrays: one
initial-turn tool_call response + one convergence final-text response per
trace. Order is fixed because planner() sorts candidates by heuristic score
(direct_prompt_injection 0.7 > tool_metadata_probe 0.4), so trace 1 fires
before trace 2.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any


def _tc(call_id: str, name: str, args: dict[str, Any]) -> SimpleNamespace:
    """Construct a fake ToolCall object matching the openai SDK shape."""
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def _msg(content: str | None, tool_calls: list[SimpleNamespace] | None = None) -> SimpleNamespace:
    return SimpleNamespace(content=content, tool_calls=tool_calls or [])


def _choice(message: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(message=message, index=0, finish_reason="stop")


def _resp(
    message: SimpleNamespace,
    in_tok: int = 100,
    out_tok: int = 50,
) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[_choice(message)],
        usage=SimpleNamespace(
            prompt_tokens=in_tok,
            completion_tokens=out_tok,
            total_tokens=in_tok + out_tok,
        ),
        model="m0-replay",
        id="fake-1",
    )


# Recorded decision sequence from runs/m0_smoke scan_result.json.
# The agent loop calls .create() exactly 4 times against the 9001 baseline;
# each call pops the next entry.
M0_SMOKE_SEQUENCE: list[SimpleNamespace] = [
    # trace 1 (direct_prompt_injection) - initial turn
    _resp(_msg(
        content=(
            "I will start by reading the target resource directly and "
            "simultaneously attempting a reflected injection probe with a "
            "marker string in the URI."
        ),
        tool_calls=[
            _tc("t1c1", "read_resource", {"uri": "internal://credentials"}),
            _tc("t1c2", "read_resource", {"uri": "internal://credentialsINJECTION_MARKER_8347"}),
        ],
    )),
    # trace 1 - convergence turn (after interim high/critical signal)
    _resp(_msg(
        content=(
            "Probed the sensitive-namespace resource `internal://credentials` "
            "via `read_resource` - the first call returned unredacted system "
            "credentials confirming a direct leak on a sensitive resource."
        ),
        tool_calls=[],
    )),
    # trace 2 (tool_metadata_probe) - initial turn (after metadata probe seed)
    _resp(_msg(
        content=(
            "I will build on the scanner work by probing `get_user_info` "
            "with a different username and reading a potentially interesting "
            "resource URI in parallel."
        ),
        tool_calls=[
            _tc("t2c1", "get_user_info", {"username": "admin"}),
            _tc("t2c2", "read_resource", {"uri": "internal://credentials"}),
        ],
    )),
    # trace 2 - convergence turn
    _resp(_msg(
        content=(
            "Probed `get_user_info(admin)` and `read_resource("
            "internal://credentials)`; the read_resource call returned system "
            "credentials confirming an exposed sensitive resource."
        ),
        tool_calls=[],
    )),
]


class FakeChatCompletions:
    """Stub for ``openai.OpenAI.chat.completions`` that replays a sequence.

    Returns the next pre-recorded response each time ``.create()`` is called.
    Loops the last response so a runaway agent does not IndexError - the
    last response is always a final-text one, so the loop converges naturally.
    """

    def __init__(self, sequence: list[SimpleNamespace] | None = None) -> None:
        self._seq = list(sequence if sequence is not None else M0_SMOKE_SEQUENCE)
        self._i = 0
        self.calls: list[dict[str, Any]] = []

    def create(
        self,
        *,
        model: str,
        messages: list,
        temperature: float = 0.0,
        tools: list | None = None,
        tool_choice: str = "auto",
        **kwargs: Any,
    ) -> SimpleNamespace:
        self.calls.append({
            "model": model,
            "temperature": temperature,
            "messages_len": len(messages),
            "tool_choice": tool_choice,
        })
        if self._i < len(self._seq):
            resp = self._seq[self._i]
            self._i += 1
        else:
            resp = self._seq[-1]
        return resp


# ── fake_make_client: stand-in for the real make_client inside tests ─────────

def fake_make_client(role: str, temperature: float | None = None):
    """Stand-in for ``mcp_redteam.models.chat.make_client``.

    Returns a (fake_client, fake_spec) tuple for the ``attacker`` role so the
    orchestrator can build a real ``OpenAI``-shaped object. Raises for
    ``judge`` so ``_make_judge_fn_or_none`` returns None and the scan proceeds
    without L2 coverage.
    """
    from mcp_redteam.models.chat import ModelSpec

    if role == "attacker":
        spec = ModelSpec(
            role="attacker",
            provider="fake",
            base_url="",
            model="m0-replay",
            temperature=temperature if temperature is not None else 0.0,
            timeout=60.0,
            key_env="",
        )
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=FakeChatCompletions())
        )
        return client, spec
    if role == "judge":
        raise RuntimeError("no judge configured in test")
    raise ValueError(f"unknown role: {role!r}")