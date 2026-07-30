# vulns/ — vuln-class strategy cards

- 输入: `VulnClass` slug (7 类, 见 HANDOFF paragraph 4).
- 输出: `StrategyCard(slug, text, templates)`, `text` 已通过四段 lint.
- 状态: 无. 卡片是打包资源,启动一次性加载.
- 变换: `load_card()` 读 `cards/<slug>.md` -> 断言四段 -> 扫描 forbidden strings -> 抽 templates 列表.
- 边界: 卡片正文原样喂给 attacker LLM; templates 是 UI hint, 不做变量替换 (占位符 `{{...}}` 由 LLM 或 executor 自行替换).

启动时 `lint_all_cards()` 会加载全部 7 张卡,`cli.py` 的 `scan` 命令前会调一次.
