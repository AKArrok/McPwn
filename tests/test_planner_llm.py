"""M3 LLM planner tests (HANDOFF_M3 section 2/3 + test plan).

Covers plan_llm parsing/fallback semantics (valid, fenced, missing,
unparseable, 429, hallucinated extra, complete coverage, chain ordering),
the planner prompt externalization (HANDOFF rule 3), PlannerDecision
serialization, and the runner wiring that fills per-candidate decisions
during an llm-mode scan.
"""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_redteam.agent.planner import _PLANNER_SYSTEM_TMPL, PlannedCandidate, plan_llm
from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import AttackTrace, PlannerDecision, VulnClass


def _candidates() -> list[Candidate]:
    return [
        Candidate(
            vuln_class=VulnClass.PATH_TRAVERSAL,
            target="get_config",
            target_kind="tool",
            score=0.8,
            reason="config read",
        ),
        Candidate(
            vuln_class=VulnClass.INDIRECT_INJECTION,
            target="process_user_input",
            target_kind="tool",
            score=0.6,
            reason="processes user text",
        ),
        Candidate(
            vuln_class=VulnClass.CHAIN_COMPOSITION,
            target="tool:get_config,tool:process_user_input",
            target_kind="chain",
            score=0.7,
            reason="chain top anchors",
        ),
    ]


class _Completions:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.captured: dict = {}

    def create(self, **kwargs):
        self.captured = kwargs
        text = self.responses.pop(0) if self.responses else '{"plan": []}'

        class _Msg:
            content = text

        class _Choice:
            message = _Msg()

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]
                self.usage = None

        return _Resp()


class _Client:
    def __init__(self, responses: list[str]) -> None:
        self.chat = types.SimpleNamespace(completions=_Completions(responses))

    def _captured(self) -> dict:
        return self.chat.completions.captured


def _spec() -> types.SimpleNamespace:
    return types.SimpleNamespace(model="deepseek-v4-flash", temperature=0.7)


def _plan_payload(entries: list[dict]) -> str:
    return json.dumps({"plan": entries})


def _valid_entries() -> list[dict]:
    return [
        {"vuln_class": "chain_composition", "target": "tool:get_config,tool:process_user_input", "reason": "compose"},
        {"vuln_class": "path_traversal", "target": "get_config", "reason": "leak"},
        {"vuln_class": "indirect_injection", "target": "process_user_input", "reason": "stored"},
    ]


def test_plan_llm_valid_full_permutation():
    client = _Client([_plan_payload(_valid_entries())])
    planned = plan_llm(_candidates(), ["get_config", "process_user_input"], [], client, _spec())
    assert [p.source for p in planned] == ["llm"] * 3
    assert [p.candidate.vuln_class for p in planned] == [
        VulnClass.CHAIN_COMPOSITION,
        VulnClass.PATH_TRAVERSAL,
        VulnClass.INDIRECT_INJECTION,
    ]
    assert {p.candidate.target for p in planned} == {
        "tool:get_config,tool:process_user_input", "get_config", "process_user_input",
    }
    msgs = client._captured()["messages"]
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"] == _PLANNER_SYSTEM_TMPL.render()
    assert "get_config" in msgs[1]["content"]
    assert "chain_composition" in msgs[1]["content"]


def test_plan_llm_code_fenced_json():
    fenced = "```json\n" + _plan_payload(_valid_entries()) + "\n```"
    client = _Client([fenced])
    planned = plan_llm(_candidates(), [], [], client, _spec())
    assert len(planned) == 3
    assert all(p.source == "llm" for p in planned)


def test_plan_llm_missing_candidate_falls_back():
    entries = _valid_entries()[:-1]  # omit indirect_injection
    client = _Client([_plan_payload(entries)])
    planned = plan_llm(_candidates(), [], [], client, _spec())
    assert all(p.source == "fallback" for p in planned)
    # fallback is full score-desc: path(0.8), chain(0.7), indirect(0.6)
    assert [p.candidate.vuln_class for p in planned] == [
        VulnClass.PATH_TRAVERSAL,
        VulnClass.CHAIN_COMPOSITION,
        VulnClass.INDIRECT_INJECTION,
    ]


def test_plan_llm_unparseable_json_falls_back():
    client = _Client(["this is not json"])
    planned = plan_llm(_candidates(), [], [], client, _spec())
    assert all(p.source == "fallback" for p in planned)


def test_plan_llm_llm_exception_falls_back(monkeypatch):
    monkeypatch.setattr("mcp_redteam.models.chat.time.sleep", lambda _: None)
    monkeypatch.setattr("mcp_redteam.models.chat._rate_limit_wait", lambda: None)
    from openai import RateLimitError

    def _boom(*args, **kwargs):
        raise RateLimitError(
            "rate limited", response=types.SimpleNamespace(status_code=429), body=None,
        )

    client = types.SimpleNamespace(
        chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=_boom)),
    )
    planned = plan_llm(_candidates(), [], [], client, _spec())
    assert all(p.source == "fallback" for p in planned)


def test_plan_llm_hallucinated_extra_dropped_but_plan_kept():
    entries = _valid_entries() + [
        {"vuln_class": "auth_bypass", "target": "made_up_tool", "reason": "invented"},
    ]
    client = _Client([_plan_payload(entries)])
    planned = plan_llm(_candidates(), [], [], client, _spec())
    # complete recon coverage kept, invented entry dropped, still llm
    assert len(planned) == 3
    assert all(p.source == "llm" for p in planned)
    assert all(p.candidate.target != "made_up_tool" for p in planned)


def test_plan_llm_empty_candidates():
    assert plan_llm([], [], [], _Client(["{}"]), _spec()) == []


def test_plan_llm_chain_can_be_ordered_first():
    entries = [
        {"vuln_class": "chain_composition", "target": "tool:get_config,tool:process_user_input", "reason": "first"},
        {"vuln_class": "path_traversal", "target": "get_config", "reason": "r"},
        {"vuln_class": "indirect_injection", "target": "process_user_input", "reason": "r"},
    ]
    client = _Client([_plan_payload(entries)])
    planned = plan_llm(_candidates(), [], [], client, _spec())
    assert planned[0].candidate.vuln_class == VulnClass.CHAIN_COMPOSITION
    assert planned[0].source == "llm"


def test_planner_system_prompt_externalized():
    from mcp_redteam.agent import planner

    rendered = _PLANNER_SYSTEM_TMPL.render()
    assert "chain_composition" in rendered
    assert "plan" in rendered
    # no inline long prompt constant remains in planner.py
    src = planner.__file__
    assert "_PLANNER_SYSTEM" not in Path(src).read_text(encoding="utf-8").replace(
        "_PLANNER_SYSTEM_TMPL", "",
    )


def test_planner_decision_contract_roundtrip():
    d = PlannerDecision(
        port=9010, index=0, vuln_class="chain_composition",
        target="tool:a,tool:b", source="llm", planned=True, executed=True,
    )
    dumped = json.loads(d.model_dump_json())
    assert dumped == {
        "port": 9010,
        "index": 0,
        "vuln_class": "chain_composition",
        "target": "tool:a,tool:b",
        "source": "llm",
        "planned": True,
        "executed": True,
        "skip_reason": None,
    }


def test_planner_decision_rejects_extra_field():
    with pytest.raises(ValidationError):
        PlannerDecision(port=1, index=0, vuln_class="a", target="t", source="llm", bogus=1)


def test_write_planner_decisions(tmp_path):
    from eval.dvmcp.runner import write_planner_decisions

    decisions = [
        PlannerDecision(port=9010, index=0, vuln_class="chain_composition", target="t", source="llm"),
        PlannerDecision(port=9010, index=1, vuln_class="path_traversal", target="x", source="llm", executed=True),
    ]
    path = write_planner_decisions(decisions, tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"decisions": [
        {"port": 9010, "index": 0, "vuln_class": "chain_composition", "target": "t", "source": "llm", "planned": True, "executed": False, "skip_reason": None},
        {"port": 9010, "index": 1, "vuln_class": "path_traversal", "target": "x", "source": "llm", "planned": True, "executed": True, "skip_reason": None},
    ]}


# ── scan() wiring: llm mode fills per-candidate decisions ──────────────────


def _trace_for(candidate: Candidate) -> AttackTrace:
    return AttackTrace(
        vuln_class=candidate.vuln_class,
        target=candidate.target,
        strategy_card_slug=candidate.vuln_class.value,
    )


class _FakeSession:
    """Minimal McpSession stand-in (scan never uses it once recon is patched)."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_scan_llm_mode_fills_decisions(tmp_path, monkeypatch):
    from mcp_redteam.orchestrator import runner as runner_mod

    cands = _candidates()
    tools = ["get_config", "process_user_input"]

    async def _fake_recon(session):
        return [], cands, tools, [], []

    planned = [
        PlannedCandidate(cands[2], "llm"),  # chain first
        PlannedCandidate(cands[0], "llm"),
        PlannedCandidate(cands[1], "llm"),
    ]

    async def _fake_execute_one(**kwargs):
        return _trace_for(kwargs["candidate"])

    monkeypatch.setattr(runner_mod, "McpSession", _FakeSession)
    monkeypatch.setattr(runner_mod, "recon", _fake_recon)
    monkeypatch.setattr(runner_mod, "plan_llm", lambda *a, **k: planned)
    monkeypatch.setattr(runner_mod, "execute_one", _fake_execute_one)
    monkeypatch.setattr(
        runner_mod, "make_client",
        lambda role, temperature=None, seed=None: (types.SimpleNamespace(), types.SimpleNamespace(model="fake", temperature=0.7)),
    )
    monkeypatch.setattr(runner_mod, "_make_judge_fn_or_none", lambda: None)

    decisions: list[PlannerDecision] = []
    result = await runner_mod.scan(
        sse_url="http://127.0.0.1:9010/sse",
        out_dir=tmp_path,
        planner_mode="llm",
        decisions=decisions,
    )
    assert result.stop_reason == "completed"
    assert [d.port for d in decisions] == [9010, 9010, 9010]
    assert [d.index for d in decisions] == [0, 1, 2]
    assert [d.source for d in decisions] == ["llm", "llm", "llm"]
    assert all(d.executed for d in decisions)
    assert [d.vuln_class for d in decisions] == [
        "chain_composition", "path_traversal", "indirect_injection",
    ]


@pytest.mark.asyncio
async def test_scan_llm_mode_budget_skip_records_unexecuted(tmp_path, monkeypatch):
    from mcp_redteam.orchestrator import runner as runner_mod

    cands = _candidates()

    async def _fake_recon(session):
        return [], cands, [], [], []

    planned = [PlannedCandidate(c, "llm") for c in cands]

    async def _fake_execute_one(**kwargs):
        return _trace_for(kwargs["candidate"])

    monkeypatch.setattr(runner_mod, "McpSession", _FakeSession)
    monkeypatch.setattr(runner_mod, "recon", _fake_recon)
    monkeypatch.setattr(runner_mod, "plan_llm", lambda *a, **k: planned)
    monkeypatch.setattr(runner_mod, "execute_one", _fake_execute_one)
    monkeypatch.setattr(
        runner_mod, "make_client",
        lambda role, temperature=None, seed=None: (types.SimpleNamespace(), types.SimpleNamespace(model="fake", temperature=0.7)),
    )
    monkeypatch.setattr(runner_mod, "_make_judge_fn_or_none", lambda: None)

    decisions: list[PlannerDecision] = []
    # zero token budget => nothing executes, every candidate recorded planned-unexecuted
    await runner_mod.scan(
        sse_url="http://127.0.0.1:9010/sse",
        out_dir=tmp_path,
        max_tokens=0,
        planner_mode="llm",
        decisions=decisions,
    )
    assert len(decisions) == 3
    assert all(not d.executed for d in decisions)
    assert all(d.skip_reason == "budget" for d in decisions)


@pytest.mark.asyncio
async def test_scan_hardcoded_mode_fills_fallback_decisions(tmp_path, monkeypatch):
    from mcp_redteam.orchestrator import runner as runner_mod

    cands = _candidates()

    async def _fake_recon(session):
        return [], cands, [], [], []

    async def _fake_execute_one(**kwargs):
        return _trace_for(kwargs["candidate"])

    monkeypatch.setattr(runner_mod, "McpSession", _FakeSession)
    monkeypatch.setattr(runner_mod, "recon", _fake_recon)
    monkeypatch.setattr(runner_mod, "execute_one", _fake_execute_one)
    monkeypatch.setattr(
        runner_mod, "make_client",
        lambda role, temperature=None, seed=None: (types.SimpleNamespace(), types.SimpleNamespace(model="fake", temperature=0.7)),
    )
    monkeypatch.setattr(runner_mod, "_make_judge_fn_or_none", lambda: None)

    decisions: list[PlannerDecision] = []
    result = await runner_mod.scan(
        sse_url="http://127.0.0.1:9010/sse",
        out_dir=tmp_path,
        planner_mode="hardcoded",
        decisions=decisions,
    )
    assert result.stop_reason == "completed"
    # hardcoded order is score-desc and every entry is fallback source
    assert [d.vuln_class for d in decisions] == [
        "path_traversal", "chain_composition", "indirect_injection",
    ]
    assert all(d.source == "fallback" for d in decisions)
    assert all(d.executed for d in decisions)