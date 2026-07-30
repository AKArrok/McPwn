# attackers/ — attacker prompt scaffolding

- 输入: `Candidate(vuln_class, target, ...)` + `StrategyCard.text` (由 `vulns/registry.py` 提供) + recon 结果.
- 输出: 一个渲染好的 attacker system prompt (jinja2), 通过 `agent/executor.py` 喂给 LLM.
- 状态: 无. 仅提供 prompt 模板 + tool schema builder.
- 变换:
  * `agents/attacker_system.md` — 通用 MCP 红队 agent 人格 + 决策框架 + 变量插值点.
  * `victims/agents/tool_schema_builder.py` — MCP 工具 -> OpenAI tools schema.
- 边界:
  * 提示词只能落 `agents/*.md`, `.py` 不得内联 3 行以上的 prompt 字符串.
  * 不做策略选择 (由 `agent/planner.py` 负责).
  * 不做信号判定 (由 `signals/` 负责).

旧版按 challenge 分的策略卡已归档到 `attic/benchmark-v0/strategies/`.
