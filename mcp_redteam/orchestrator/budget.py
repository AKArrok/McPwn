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

    def add(self, source: TokenSource, tokens_in: int, tokens_out: int) -> None:
        n = int(tokens_in) + int(tokens_out)
        if source == "attacker":
            self.attacker_tokens += n
        elif source == "judge":
            self.judge_tokens += n

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
