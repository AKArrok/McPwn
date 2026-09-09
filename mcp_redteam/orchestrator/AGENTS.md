# orchestrator/ — top-level scan driver + shared budget + DVMCP reset hook

- 输入: 目标 `str | TargetSpec` (URL / stdio command / 现成 spec;`sse_url` 为兼容保留的参数名) + budget/wall/candidate 限额 (defaults 见 `runner.scan()`).
- 输出: `ScanResult` + `<out_dir>/{findings.md, poc/, traces/, scan_result.json}` (合作 `report/`).
- 状态:
  * `TokenBudget` (per-scan, judge tokens 独立计数, HANDOFF Q8).
  * `WallClock` (per-scan).
- 变换: `scan()` = recon -> plan -> for candidate: execute_one -> verify -> emit findings.
- 边界:
  * 串行, 不并发候选 (HANDOFF Q9).
  * `reset_hook.reset_dvmcp(execute=False)` 是默认 dry-run; `--yes` 才动 docker.
  * budget 超限立刻停 (返回 `stop_reason=budget_*`), 已收集的 traces 与 findings 依然写盘.
