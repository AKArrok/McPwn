"""Three-gate budget: turns / tokens / wall-time (HANDOFF Q8).

`judge_tokens` is kept independent — Judge should never starve attacker of tokens.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

TokenSource = Literal["attacker", "judge"]

# DeepSeek bills cache-hit input at ~1/10 of cache-miss input (automatic
# prefix caching: the re-sent system prompt + strategy card + tool schemas
# are identical across calls within a scan). Effective cost weights the
# reported cache-hit portion accordingly; providers that don't report cache
# fields (ARK/doubao, OpenAI non-prompt-caching) keep effective == raw.
_CACHE_HIT_PRICE_RATIO = 0.1


@dataclass
class TokenBudget:
    max_tokens_total: int
    attacker_tokens: int = 0
    judge_tokens: int = 0
    # Observational cost-accounting fields (never gate anything): raw
    # attacker tokens split by DeepSeek prefix-cache reporting, and the
    # cache-discounted effective spend. 0 with no cache reporting.
    attacker_cache_hit_tokens: int = 0
    attacker_tokens_effective: int = 0
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
            self.attacker_tokens_effective += n
        elif source == "judge":
            self.judge_tokens += n

    def add_usage(self, source: TokenSource, usage: Any) -> None:
        """Charge one LLM response's usage, keeping cache-effective accounting.

        Reads ``prompt_tokens`` / ``completion_tokens`` and, when the provider
        reports them (DeepSeek), ``prompt_cache_hit_tokens``. Raw counters use
        the API-reported totals so budget semantics stay comparable across
        providers; ``attacker_tokens_effective`` discounts the cache-hit input
        share at ~1/10 price. Callers should prefer this over ``add`` whenever
        they hold the usage object.
        """
        pin = getattr(usage, "prompt_tokens", 0) or 0
        pout = getattr(usage, "completion_tokens", 0) or 0
        hit = getattr(usage, "prompt_cache_hit_tokens", None)
        self.add(source, pin, pout)
        if source != "attacker":
            return
        if hit:
            self.attacker_cache_hit_tokens += int(hit)
            effective_in = (int(pin) - int(hit)) + int(hit) * _CACHE_HIT_PRICE_RATIO
            self.attacker_tokens_effective += int(round(effective_in)) - int(pin)

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
