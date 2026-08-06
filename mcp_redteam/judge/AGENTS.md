# judge/ — L2 证据复核 + M3 验收 judge

**输入**: L2 = AttackTrace (indirect/chain 且 attack_calls 非空);
M3 = M3JudgeInput (两套 eval 摘要 + 代码算好的判据 + 9010 chain trace 摘要 + planner decisions 摘要)。

**输出**: L2 = JudgeVerdict (由 agent/verifier.py 写回 trace.judge_verdict);
M3 = M3JudgeReport + 人类可读 judge_report.md。

**状态**: 无持久状态。judge token 独立计数 (budget.add("judge", ...) 或报告内 judge_tokens),
不挤 attacker 预算。

**变换**: agents/*.md + jinja2 渲染 → LLM (role=judge, temp 0.0) →
parse.py 容错 JSON 解析 → 结构化判定 (L2: steered / evidence_call_index / reason;
M3: verdict / criteria / metrics)。

**边界**:
- 判据数值计算一律在 eval/dvmcp/m3_judge.py (确定性代码), 本模块不做数字推断、不重算指标。
- judge 失败 / JSON 不可解析 → None → 按 not-steered / inconclusive 处理, 绝不 crash。
- prompt 只能落 agents/*.md, .py 不内联超 3 行 prompt 字符串 (HANDOFF 硬性规则 3)。
- 不定义本地版 contracts 类型, 全部从 mcp_redteam/contracts.py 导入。
