# agent/ — agent loop (recon → planner → executor → verifier)

- 输入: 传输中立的端点 display 字符串 (由 `TargetSpec.display` 提供;SSE / streamable HTTP / stdio 统一为只读字符串,本层不感知传输)
- 输出: `ScanResult` (含 findings + traces)
- 状态: TokenBudget + WallClock 跨所有 trace 共享; 每个 trace 独立计时.
- 变换:
  1. recon -> `list[McpCall]` + `list[Candidate]`
  2. planner -> sorted `list[Candidate]`
  3. executor × N -> `list[AttackTrace]` (每候选一个, 遇 budget 停)
  4. verifier -> `list[Finding]` (confidence >= 0.6)
- 边界: 不直接调用 MCP server (委托给 mcp_client); 不直接调用 LLM (委托给 models/chat).
  executor 内嵌标准 openai function-calling 循环.

从 `cli.py` 的 `scan` 命令进入; 由 `agent/__init__.py` 暴露统一入口.
