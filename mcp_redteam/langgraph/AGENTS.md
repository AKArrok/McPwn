# langgraph/ — LangGraph 编排层（`scan(..., graph=True)` 路径）

> 设计决策见 `HANDOFF_LANGGRAPH.md`（已实施 A+B 阶段）；旧 `runner.scan`
> 保留为默认路径与 parity 锚点。

- 输入: 与 `runner.scan` 完全相同的 scan 参数（target: `str | TargetSpec`,参数名 sse_url 兼容保留 / out_dir / 预算 /
  候选限制 / planner_mode / decisions / llm_points / seed），经
  `scan(..., graph=True)` 分支到 `orchestrator/runner._scan_graph`。
- 输出: 与 runner 同契约的 `ScanResult` + `<out_dir>/scan_result.json`；
  仅 graph 路径额外提供跨 trace 记忆（`prior_evidence` 注入）。
- 状态: `McPwnState` 只含可序列化数据，累积字段（`traces` / `prior_evidence`）
  用 `Annotated[list, operator.add]` reducer；`session` / attacker client /
  `TokenBudget` / `WallClock` 经 `GraphDeps` 闭包注入，绝不进 state。
- 变换: recon → hypothesis(仅 llm_points) → plan → execute 循环边
  （`signal_gate` 三路 execute / retrospective / verify）→ verify → report；
  节点失败经 MemorySaver `get_state` 恢复 partial traces（`stop_reason=error`）。
- 边界:
  * 不替代旧 `runner.scan`；finding 集合等价由 `tests/test_langgraph_parity.py`
    守护（`attack_messages_sha1` 因记忆注入预期不同）。
  * 内层 LLM 循环（`executor.execute_one`）是黑盒，不进 graph。
  * `signal_gate` 从不提前收敛；命中 high/critical 只把剩余
    chain_composition 候选提到最前（`promote_chains`），不跳过任何候选。
  * 复盘（retrospective）仅 `llm_points=True` 且第一波 0 命中且剩余预算
    ≥8k margin 时触发一次（`retro_fired`）；follow-up 波次不写 M3 decisions。
  * 记忆注入走 user message（`execute_one(prior_evidence=...)`），不碰
    `attackers/agents/*.md` 提示词。
