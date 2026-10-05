"""Cache-effective token metering (DeepSeek prefix-cache accounting).

DeepSeek reports ``prompt_cache_hit_tokens`` on usage; cache-hit input is
billed at ~1/10. ``TokenBudget.add_usage`` keeps raw counters API-reported
(budget gates and cross-provider comparability) and additionally maintains
``attacker_tokens_effective`` with the hit share discounted. Providers that
don't report cache fields keep effective == raw.
"""

from __future__ import annotations

from types import SimpleNamespace

from mcp_redteam.orchestrator.budget import TokenBudget


def test_add_usage_without_cache_fields_effective_equals_raw():
    b = TokenBudget(max_tokens_total=30000)
    usage = SimpleNamespace(prompt_tokens=1000, completion_tokens=200)
    b.add_usage("attacker", usage)
    assert b.attacker_tokens == 1200
    assert b.attacker_cache_hit_tokens == 0
    assert b.attacker_tokens_effective == 1200


def test_add_usage_with_cache_hits_discounts_effective():
    b = TokenBudget(max_tokens_total=30000)
    # 1000 prompt of which 800 cache-hit, 200 completion.
    # raw = 1200; effective = (1000-800) + 800*0.1 + 200 = 480.
    usage = SimpleNamespace(
        prompt_tokens=1000,
        completion_tokens=200,
        prompt_cache_hit_tokens=800,
        prompt_cache_miss_tokens=200,
    )
    b.add_usage("attacker", usage)
    assert b.attacker_tokens == 1200  # raw stays API-reported
    assert b.attacker_cache_hit_tokens == 800
    assert b.attacker_tokens_effective == 480


def test_add_usage_accumulates_across_responses():
    b = TokenBudget(max_tokens_total=30000)
    b.add_usage("attacker", SimpleNamespace(
        prompt_tokens=1000, completion_tokens=0, prompt_cache_hit_tokens=600))
    b.add_usage("attacker", SimpleNamespace(
        prompt_tokens=500, completion_tokens=100, prompt_cache_hit_tokens=0))
    assert b.attacker_tokens == 1600
    assert b.attacker_cache_hit_tokens == 600
    # resp1: (1000-600)+60 = 460; resp2: 600. total effective = 1060.
    assert b.attacker_tokens_effective == 1060


def test_add_usage_judge_ignores_cache_accounting():
    b = TokenBudget(max_tokens_total=30000)
    b.add_usage("judge", SimpleNamespace(
        prompt_tokens=1000, completion_tokens=0, prompt_cache_hit_tokens=900))
    assert b.judge_tokens == 1000
    assert b.attacker_cache_hit_tokens == 0
    assert b.attacker_tokens_effective == 0  # attacker counters untouched


def test_add_still_works_and_keeps_effective_in_sync():
    b = TokenBudget(max_tokens_total=30000)
    b.add("attacker", 100, 50)
    assert b.attacker_tokens == 150
    assert b.attacker_tokens_effective == 150
    assert b.attacker_cache_hit_tokens == 0


def test_cache_fields_do_not_change_gates():
    b = TokenBudget(max_tokens_total=1200)
    b.add_usage("attacker", SimpleNamespace(
        prompt_tokens=1000, completion_tokens=100, prompt_cache_hit_tokens=900))
    # raw 1100 < 1200: budget NOT exceeded even though effective is far lower;
    # effective accounting is observational and must not gate anything.
    assert b.exceeded() is False
    b.add("attacker", 100, 0)
    assert b.exceeded() is True
