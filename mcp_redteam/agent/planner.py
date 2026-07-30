"""Planner: sort recon candidates by heuristic score.

M2 交付形态: hard-coded heuristic (candidate.score).
M4 消融: 换成 LLM 决策 (读 recon 结果 -> 出 next-action list).
"""

from __future__ import annotations

from mcp_redteam.agent.recon import Candidate


def plan(candidates: list[Candidate], max_candidates: int = 20) -> list[Candidate]:
    """Sort by score desc, cap length. Stable within same score."""
    ordered = sorted(candidates, key=lambda c: c.score, reverse=True)
    return ordered[:max_candidates]
