"""Three-gate budget: turns / tokens / wall-time (HANDOFF Q8).

`judge_tokens` is kept independent — Judge should never starve attacker of tokens.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

TokenSource = Literal["attacker", "judge"]


@dataclass
class TokenBudget:
    max_tokens_total: int
    attacker_tokens: int = 0
    judge_tokens: int = 0
    # Optional pool bounding how much attacker budget LLM-hypothesis candidates
    # (origin="llm_hypothesis") may consume in total. None = unbounded (legacy
    # behaviour). When the pool is exhausted, remaining LLM-hypothesis
    # candidates are skipped so (possibly correct) recon candidates behind them
    # still get executed. Never limits recon candidates or the judge.
    llm_hyp_remaining: int | None = None

    def add(self, source: TokenSource, tokens_in: int, tokens_out: int) -> None:
        n = int(tokens_in) + int(tokens_out)
        if source == "attacker":
            self.attacker_tokens += n
        elif source == "judge":
            self.judge_tokens += n

    def charge_llm_hyp(self, tokens_in: int, tokens_out: int) -> bool:
        """Charge attacker tokens against the LLM-hypothesis pool.

        Returns True while the pool still has budget left (caller may keep
        going), False once the pool is exhausted (caller must stop). No-op
        (always True) when no pool is configured.
        """
        if self.llm_hyp_remaining is None:
            return True
        n = int(tokens_in) + int(tokens_out)
        if n <= 0:
            return self.llm_hyp_remaining > 0
        self.llm_hyp_remaining = max(0, self.llm_hyp_remaining - n)
        return self.llm_hyp_remaining > 0

    @property
    def counted_tokens(self) -> int:
        """Attacker only. Judge is out-of-band."""
        return self.attacker_tokens

    def exceeded(self) -> bool:
        return self.counted_tokens >= self.max_tokens_total


@dataclass
class WallClock:
    wall_seconds: float
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def exceeded(self) -> bool:
        return self.elapsed >= self.wall_seconds
