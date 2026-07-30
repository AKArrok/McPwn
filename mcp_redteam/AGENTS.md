# mcp_redteam/ — 包总规约(v1 agent-first)

**输入**:CLI 参数(`scan <sse-url>` 或 `eval dvmcp run/reset`)、`config/models.yaml`、
`.env` 中的 API key、`vulns/cards/*.md` 策略卡。

**输出**:`<out_dir>/{findings.md, scan_result.json, traces/*.json, poc/*.py}`。
DVMCP 回归还追加 `eval_report.md`。

**状态**:Docker 容器 `dvmcp` 的 `/tmp/dvmcp_challenge*` 目录(challenge 3/4/6/8/10),
由 `orchestrator/reset_hook.py` 负责回收。scan 本身无持久状态,一切靠
`ScanResult.traces` 落盘可重放。

**变换**:CLI (`scan`) → `orchestrator/runner.scan` → `agent.recon` →
`agent.planner` → `agent.executor`(attacker LLM + `targets/mcp_client`) →
`agent.verifier`(signals + LLM twin) → `report.findings`。

**边界**:
- 不改 DVMCP 靶子源码。
- 不接外网靶标,仅评估 `127.0.0.1:9001-9010`。
- 不在 `.py` 内联长提示词,全部走 `**/agents/*.md`。
- 不定义本地版 `McpCall/EvidenceSignal/AttackTrace/Finding/ScanResult/VulnClass`,
  全部从 `contracts.py` 导入。
- `findings.md` / PoC 脚本禁止落原文敏感串;critical/high 信号的 `matched_text`
  在 `signals/detectors._redact` 层已经指纹化。
