# Test Status Report

**Last verified**: 2026-08-07 (commit HEAD = `cf69940`, branch `codex/b-c-ci`; attacker=deepseek-v4-flash, judge=doubao-seed-2.0-lite)

## Summary

| Tool | Scope | Result |
|------|-------|--------|
| pytest | `tests/` | **274 passed** in 127.9s (数量已由 `scripts/check_docs.py` 与 CI 守护,不在此写死) |
| ruff | `mcp_redteam/` + `eval/` | **0 errors** |
| ruff | `tests/` | 见下方 Notes(历史遗留,已出当前作用域) |
| `mcpwn lint-cards` | `vulns/cards/*.md` | **8/8 ok** |
| `scripts/check_docs.py` | 文档-代码一致性 | **全部一致 ✓**(L1 事实锚点 + L2 结构校验) |

## Environment

- Python 3.13.13 (miniconda `base`)
- pytest, pytest-asyncio;openai / pydantic / mcp SDK
- mcpwn 0.1.0 (dev install)

## Reproduce

```bash
python -m pytest tests -q --no-header
python -m ruff check mcp_redteam eval
python -m mcp_redteam.cli lint-cards
python scripts/check_docs.py
```

## Notes

- **测试数量不在此写死**:按 `scripts/check_docs.py` 第 0 层原则("从代码可
  导出的量,文档里不应有字面量"),pytest 数量以 `pytest --collect-only` 实时
  值为准,README 已改为"数量见 CI badge"。本文件只记录**验证时点快照**。
- 历史遗留:早期 `tests/` 有 6 个 ruff errors(user-authored fixtures),已随
  `eval/clean_baseline` 的 ruff 清理出当前作用域;当前 `ruff check mcp_redteam eval` 0 errors。
- 文档数字漂移由 `scripts/check_docs.py` 守护:任何文档里写死的
  `N passed` / `N 条注册信号` / `N 张策略卡` 若与代码不符,CI 直接 FAIL。

## Eval 状态快照 (2026-08-07, informational)

| 回归 | 结果 | 来源 |
|------|-------|------|
| DVMCP 全港 | recall 8/10 (runner) / 9/10 (graph), FPR 0, replay 5/5 | `runs/` 各 eval_report.md |
| realworld (excel-mcp CVE-2026-40576) | 0.1.7 exploited / 0.1.8 blocked 双 PASS | `mcpwn eval realworld prove` |
| unknown_shape (vault-mcp) | baseline 0 findings → llm 3/3 PASS + 消融 D 3/3 | `eval/unknown_shape/README.md` |
| generalize (delegate-mcp) | 3/3 PASS (strict-better, 第 4 轮) | `eval/generalize/README.md` |
| fetch_ssrf (真实 server) | scan 1 finding (`ssrf/fetch` 0.75) | `eval/fetch_ssrf/README.md` |
| clean_baseline | 3 变体 0 findings (FPR 0) | `eval/clean_baseline/` |
| real_vuln / real_negative | filesystem CVE 正向 / 修复版负向试点 | `eval/real_vuln/` + `eval/real_negative/` |
| 三靶机回归网 | `eval/regression.py` prove ALL PASS + 前提冻结 5 tests | `tests/test_regression_shapes.py` |

> 完整回归命令:`python eval/regression.py --mode full --n 3`(消耗真实 LLM 预算,本地跑)。
