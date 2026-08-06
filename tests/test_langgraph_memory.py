"""Commit-2 (B stage) tests: prior_evidence cross-candidate memory.

The graph path injects hit summaries into later candidates' prompts; the
runner path does not - that divergence is the point of B (target 9006/9010
chain_composition). These tests pin the injection mechanics, the
chain-promotion reorder, and the llm_points hypothesis/retrospective nodes
without needing a real LLM (stub attacker + FakeMcpSession, same fixture
family as test_regression_baseline.py).
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from unittest.mock import patch

from mcp_redteam.agent.planner import PlannedCandidate
from mcp_redteam.agent.recon import Candidate
from mcp_redteam.contracts import VulnClass
from mcp_redteam.langgraph import nodes as graph_nodes
from mcp_redteam.orchestrator import runner as runner_mod
from tests.fixtures.mock_mcp import FakeMcpSession
from tests.fixtures.stub_attacker import fake_make_client

BASELINE_PATH = pathlib.Path(__file__).parent / "baselines" / "m0_9001.json"
PRIOR_PREFIX = "Prior evidence from earlier candidates in this scan:"


def _load_baseline() -> dict:
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _scan_graph(tmp_path: pathlib.Path, **kwargs):
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        return asyncio.run(runner_mod.scan(out_dir=tmp_path, graph=True, **kwargs))


def _scan_runner(tmp_path: pathlib.Path, **kwargs):
    with patch.object(runner_mod, "make_client", side_effect=fake_make_client), \
         patch.object(runner_mod, "McpSession", FakeMcpSession):
        return asyncio.run(runner_mod.scan(out_dir=tmp_path, **kwargs))


def _has_prior_message(trace) -> bool:
    return any(
        m.get("role") == "user"
        and isinstance(m.get("content"), str)
        and PRIOR_PREFIX in m["content"]
        for m in trace.attacker_messages
    )


def test_graph_injects_prior_evidence_into_later_traces(tmp_path) -> None:
    """Graph path appends a prior-evidence user message after the first hit;
    the runner path never does (that is the B-stage divergence)."""
    baseline = _load_baseline()
    kwargs = {
        "sse_url": baseline["sse_url"], "max_tokens": 10_000,
        "wall_seconds": 60, "max_candidates": 5,
    }
    old = _scan_runner(tmp_path / "runner", **kwargs)
    new = _scan_graph(tmp_path / "graph", **kwargs)

    assert len(new.traces) > 1, "fixture should produce multiple candidates"
    assert not any(_has_prior_message(t) for t in old.traces)
    # first trace has nothing to inject; later ones carry the memory
    assert not _has_prior_message(new.traces[0])
    assert any(_has_prior_message(t) for t in new.traces[1:])
    # findings still match: memory changes prompts, not the signal library
    assert [f.model_dump(exclude={"trace_ref"}) for f in new.findings] == [
        f.model_dump(exclude={"trace_ref"}) for f in old.findings
    ]


def _candidate(vuln_class: VulnClass, target: str) -> Candidate:
    return Candidate(
        vuln_class=vuln_class,
        target=target,
        target_kind="tool",
        score=0.5,
        reason="test",
    )


def test_promote_chains_moves_chain_after_strong_hit() -> None:
    plan = [
        PlannedCandidate(_candidate(VulnClass.PATH_TRAVERSAL, "a"), "fallback"),
        PlannedCandidate(_candidate(VulnClass.CHAIN_COMPOSITION, "chain1"), "fallback"),
        PlannedCandidate(_candidate(VulnClass.COMMAND_INJECTION, "b"), "fallback"),
        PlannedCandidate(_candidate(VulnClass.CHAIN_COMPOSITION, "chain2"), "fallback"),
    ]
    reordered = graph_nodes.promote_chains(plan, executed_count=1, strong_hit=True)
    assert reordered is not None
    assert [p.candidate.target for p in reordered] == ["a", "chain1", "chain2", "b"]
    # no-op cases: no strong hit / plan exhausted / no chains left
    assert graph_nodes.promote_chains(plan, 1, False) is None
    assert graph_nodes.promote_chains(plan, 4, True) is None
    assert graph_nodes.promote_chains([plan[0], plan[2]], 1, True) is None


def test_llm_points_hypothesis_node_appends_candidates(tmp_path) -> None:
    """hypothesis_node adds LLM hypotheses to candidates before planning."""
    baseline = _load_baseline()
    extra = _candidate(VulnClass.PATH_TRAVERSAL, "llm-extra")
    with patch.object(graph_nodes, "generate_hypotheses", return_value=[extra]):
        new = _scan_graph(
            tmp_path,
            sse_url=baseline["sse_url"], max_tokens=10_000,
            wall_seconds=60, max_candidates=10, llm_points=True,
        )
    assert any(t.target == "llm-extra" for t in new.traces)


def test_llm_points_retrospective_second_wave(tmp_path) -> None:
    """Zero-hit first wave + llm_points triggers the retrospective node once.

    ``verify_trace`` is patched only inside ``langgraph.nodes`` (the record +
    gate decision); ``verifier.build_findings`` still uses the real signal
    library, so findings stay grounded while we exercise the node scheduling.
    """
    baseline = _load_baseline()
    followup = _candidate(VulnClass.PATH_TRAVERSAL, "retro-followup")
    with patch.object(graph_nodes, "generate_hypotheses", return_value=[]), \
         patch.object(graph_nodes, "verify_trace", return_value=([], 0.0)), \
         patch.object(graph_nodes, "retrospective_hypotheses", return_value=[followup]):
        new = _scan_graph(
            tmp_path,
            sse_url=baseline["sse_url"], max_tokens=10_000,
            wall_seconds=60, max_candidates=10, llm_points=True,
        )
    followup_traces = [t for t in new.traces if t.target == "retro-followup"]
    # Exactly one follow-up trace: the second wave runs once (retro_fired).
    assert len(followup_traces) == 1


def test_llm_points_off_never_fires_retrospective(tmp_path) -> None:
    """Without llm_points the retrospective route is unreachable, even if the
    first wave found nothing."""
    baseline = _load_baseline()
    followup = _candidate(VulnClass.PATH_TRAVERSAL, "retro-followup")
    with patch.object(graph_nodes, "generate_hypotheses", return_value=[]), \
         patch.object(graph_nodes, "verify_trace", return_value=([], 0.0)), \
         patch.object(graph_nodes, "retrospective_hypotheses", return_value=[followup]):
        new = _scan_graph(
            tmp_path,
            sse_url=baseline["sse_url"], max_tokens=10_000,
            wall_seconds=60, max_candidates=10, llm_points=False,
        )
    assert not any(t.target == "retro-followup" for t in new.traces)
