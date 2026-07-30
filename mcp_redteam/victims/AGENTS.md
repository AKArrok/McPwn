# victims/ — 受害者 LLM(pair 模式专用)

**输入**:attacker 的自然语言 prompt、通过 `tool_schema_builder` 生成的 openai tools schema、
`agents/system_prompt.md` 渲染后的 system。

**输出**:victim 最终 `reply` + 本 turn 触发的 `mcp_calls`(经 `mcp_client` 记录)。

**状态**:内部循环上限 `victim_inner_steps=5`(HANDOFF Q8);
超限视为 `stop_reason=budget_turns` 内部子情况。

**变换**:attacker_prompt -> LLM(with tools) -> [call_tool ...] -> LLM final -> reply。

**边界**:
- **严禁 sanitize / rewrite tool description**(HANDOFF §4:description 原样透传)。
- 通用 `read_resource(uri: str)` 必须暴露(HANDOFF §5)。
- AuditLog 独立目录,不与 attempts.jsonl 混淆。
