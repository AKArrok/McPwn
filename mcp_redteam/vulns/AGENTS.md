# vulns/ — vuln-class strategy cards

- 输入: `VulnClass` slug (8 类, 见 HANDOFF paragraph 4).
- 输出: `StrategyCard(slug, text, templates)`, `text` 已通过四段 lint.
- 状态: 无. 卡片是打包资源,启动一次性加载.
- 变换: `load_card()` 读 `cards/<slug>.md` -> 断言四段 -> 扫描 forbidden strings -> 抽 templates 列表.
- 边界: 卡片正文原样喂给 attacker LLM; templates 是 UI hint, 不做变量替换 (占位符 `{{...}}` 由 LLM 或 executor 自行替换).

启动时 `lint_all_cards()` 会加载全部 8 张卡,`cli.py` 的 `scan` 命令前会调一次.

## Prompt-injection 类卡片的判据取向 (v2)

`direct_prompt_injection` 与 `indirect_injection` 两张卡在 v2 已改为
**L0/L1 判据** (见 `PROMPT_INJECTION_GAP.md`):

- Playbook 不再依赖 LLM 行为观察, 而是通过 `INJECTION_MARKER_*` canary 串
  探测 server 侧回显/存储/工具描述污染
- 对应 detector: `stored_injection_roundtrip` (L0 反射 + L1 写-读往返) +
  `tool_description_drift` (L1 工具描述污染)
- `llm_judged_injection` (L2) 保留占位, 不在这两张卡的必路径上

编辑这两张卡时保持 marker 命名 (`INJECTION_MARKER_*`) 与 detector 正则
`INJECTION_MARKER_[A-Za-z0-9]{4,}` 一致, 否则 detector 命中率为零。
