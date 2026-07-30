# McPwn 顶层规约(唯一权威)

设计细节见 `HANDOFF.md`。本文件仅规定**跨模块通用约束**,子目录 `AGENTS.md`
按"输入 / 输出 / 状态 / 变换 / 边界"五字段补齐本地规约。

## 硬性规则

1. **胶水优先**。参考成熟项目(mcp SDK、openai、typer、pydantic)的现成用法,
   能不自造轮子就不造。禁止无必要抽象。
2. **契约集中**。所有跨模块数据结构在 `mcp_redteam/contracts.py`,pydantic v2。
   任何模块不得在本地重定义 `McpCall / EvidenceSignal / AttackTrace / Finding / ScanResult / VulnClass`。
3. **提示词外置**。所有 LLM 提示词落 `**/agents/*.md`,`jinja2` 变量插值;
   `.py` 中不得内联长字符串提示词。
4. **判据禁参考 DVMCP 源码答案**。信号库 (`signals/registry.yaml`) 是通用启发,
   不针对具体 challenge;策略卡 (`vulns/cards/*.md`) 中不得出现已知靶场明文答案 (启动 lint 强制)。
5. **判据置信度**。Finding 由 `1 - prod(1 - w_i)` 的加权信号命中给出;
   `confidence >= 0.6` 才进 `findings.md`,否则只留在 traces 里。
6. **预算三闸门**。turns / tokens / wall-time 任一超限即 `stop_reason=budget_*`;
   judge tokens 独立计数,不占 attacker+victim 预算。
7. **不装 PyRIT**。仅在 `adapters/base.py` 复刻 Protocol 签名。
8. **合规声明常置**。见 `README.md` 顶部与 `attackers/agents/attacker_system.md` 首段。
9. **状态变更命令**默认 dry-run,`--yes` 才真的动 docker/文件系统。
10. **子目录 `AGENTS.md` 必须五字段全填**:输入 / 输出 / 状态 / 变换 / 边界。

## 目录一览

参见 `HANDOFF.md` §4。
