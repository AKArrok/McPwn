# victims/ — 受害者 LLM(pair 模式专用)
#
# DEPRECATED (v2, 2026-07-30)
#
# Agent-first 重构后 scan 路径只调用 make_client("attacker"),无 victim LLM
# 参与。victim 相关配置 (models.yaml 中 deepseek 条目) 仅作为配置文件参考
# 保留,不参与实际执行。victim_tokens 字段在 contracts.py 中保留但不被充值,
# 恒为 0。tool_schema_builder.py 实际被 attacker 的 agent/executor.py 使用。
#
# 若后续需要 L2 (prompt injection 下游影响面) 验证,本契约可能复活。
# 在此之前所有引用本文件的代码路径应视为死代码。
# 不要在 scan 或 eval 命令中引用 make_client("victim")。
#
# 以下为 v0 原文,保留供参考:
#
# 输入:attacker 的自然语言 prompt、通过 tool_schema_builder 生成的 openai
#   tools schema、agents/system_prompt.md 渲染后的 system。
# 输出:victim 最终 reply + 本 turn 触发的 mcp_calls。
# 状态:内部循环上限 victim_inner_steps=5;超限视为 stop_reason=budget_turns。
# 变换:attacker_prompt -> LLM(with tools) -> [call_tool ...] -> LLM final -> reply。
# 边界:
#   - 严禁 sanitize / rewrite tool description(HANDOFF §4)
#   - 通用 read_resource(uri: str) 必须暴露(HANDOFF §5)
#   - AuditLog 独立目录,不与 attempts.jsonl 混淆
