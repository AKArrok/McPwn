# MCP 攻击技能调研 + 提示词优化落地 (2026-08-06)

> 用户需求:「找下有没有打 MCP 的 skill,可以优化提示词」。
> 结论:**已找到并落地** —— 新增第 8 个漏洞类 `ssrf`,并把外部技能里的
> tool-poisoning 隐藏指令启发写进策略卡与 attacker 系统提示词。

## 1. 调研到的「打 MCP」技能/工具 (按相关性排序)

| 来源 | 类型 | 覆盖的攻击面 | 可借鉴点 |
|---|---|---|---|
| `mukul975/anthropic-cybersecurity-skills`@`auditing-mcp-servers-for-tool-poisoning` | Claude Code skill (Apache-2.0) | tool poisoning / shadowing / rug pull / toxic flow / SSRF / 未鉴权暴露 | tool description 隐藏指令 red flags;SSRF_TARGETS 列表;静态+运行时扫描思路 |
| `ressl/mcpwn` (GitHub, AGPL-3.0) | MCP server 安全扫描器 (mcpwn scan) | MCP-001..010: tool poisoning / prompt injection / 数据外泄 / SSRF / 权限过大 / schema 宽松 / 传输不安全 / 资源穿越 / 工具链 / rug pull | 每个攻击面的**主动探测判据**:IMDS 端点、内网段、协议走私 (file:// gopher://)、Unicode/注释/base64 隐藏指令、工具调用形状 JSON 输出 |
| `invariantlabs-ai/mcp-scan` | 静态+运行时扫描器 | tool poisoning / shadowing / rug pull (哈希 pin) / toxic flow | description 哈希 pin 防 rug pull;raw description 逐条 inspect |
| `mcp-hub-corp/mcp` | MCP server (SKILL.md 扫描) | 61 规则: 指令覆盖 / 凭据泄露 / tool poisoning / shadow tools / SSRF | 17 个 analyzer 的分类清单 |
| `Mindgard/ai-ide-skills`@`mcp-config-poisoning` | skill | IDE 自动加载不可信 MCP 配置 / tool 批准控制 | 配置级投毒面 |
| `adudley78/mcp-audit` / `glatinone/mcpscan` / npm `skillaudit` | 供应链扫描 | 配置投毒 / schema 投毒 (MCP_SCHEMA_POISON) / 危险权限 | schema 宽松度=注入面 的启发 |
| PyPI `mcp-security-audit` | CLI/MCP server | 22 条 prompt 注入检测模式;live injection tests;工具风险分类 | 向 string 参数工具发注入 payload 的主动探测法 |

## 2. 落地改动 (本次 commit)

### 2.1 新增第 8 个漏洞类 `ssrf` (完整接线)
- `contracts.py`: `VulnClass.SSRF = "ssrf"` (8 类).
- `signals/detectors.py`: 新增 `detect_ssrf_cloud_metadata` (high) +
  `detect_ssrf_internal_service` (high),均**双闸门**:args 指向元数据端点/回环/内网
  **且** 响应含云元数据键名 (`ami-id`/`instance-id`/`local-ipv4`/`security-credentials`,
  或 `ami-xxxx`/`i-xxxx` 值形状) 或内部服务 banner (SSH/Redis/Mongo/nginx/IIS).
  只回显 URL 字符串不触发 (URL echo 不含键名/banner 形状)。
- `agent/verifier.py`: `_SIGNAL_TO_CLASS` 两条映射 + `_REMEDIATION["ssrf"]`.
- `agent/recon.py`: `_TOOL_PATTERNS` 新增 URL 代发工具正则
  (`fetch|http|url|webhook|callback|request|scrape|proxy` → SSRF, score 0.85).
- `vulns/cards/ssrf.md`: 新策略卡 (When to use / Objective / Playbook / Templates),
  templates 含 AWS/GCP/Aliyun IMDS 端点、回环端口、内网段、`file://`、十六进制/IPv6 绕过。
- docs: `HANDOFF.md` §2/§4 + `vulns/AGENTS.md` 7→8 类。
- tests: `tests/signals/test_ssrf.py` (含反例/闸门测试)、signal-meta fixtures、
  `test_recon.py` ssrf 分类、verifier ssrf finding 冒烟。**196 passed / ruff clean /
  lint-cards 8/8。**

### 2.2 提示词启发增强 (来自 mcpwn MCP-001/002 + skill §2)
- `tool_metadata_probe.md`: 新增**隐藏指令扫描**步 (零宽 Unicode / HTML 注释指令块 /
  base64 载荷 / "ignore previous"/"do not tell the user"/"system override"/"call <tool>"
  短语) → tool poisoning 候选.
- `direct_prompt_injection.md`: Poisoning 变体矩阵补 base64 / 注释包裹 / 社交工程短语 /
  调工具指令.
- `indirect_injection.md`: 新增传播证据 (读回内容含工具调用形状 JSON 或系统级指令).
- `attacker_system.md`: 合规声明类列表加 SSRF;新增规则 8 (工具描述是不可信输入) 与
  规则 9 (schema 宽松度 = 注入面).

## 3. 关键设计取舍 (为何这样判据)
- **SSRF 判据双闸门** (args 目标 + 响应指纹): 单看 args 会把「server 回显 URL」当证据
  (FPR); 单看响应指纹会被非 SSRF 场景误报。IMDS 目录响应是裸键名换行, 所以响应正则
  匹配**裸 token**, 不要求 `key:` 形状。
- `file://` 协议走私**不新增** ssrf 信号: 读回文件内容会交叉触发 `leaks_*` (已接线),
  由 verifier 按工具名归到 ssrf 或 path_traversal。避免信号重复。
- 未做 MCP-003 数据外泄 (DNS/HTTP 回调): agent-first 观测不到外部回连, 无法 ground。

## 4. 下一步建议
1. 做一个带 `fetch_url` + 内网服务的**未知形状靶机** (如 vault 变体), 验证 ssrf 类
   在 LLM agent 下真能提能 (严格更优判据, 不是 ≥)。
2. 可选: 把 mcp-scan 的 description 哈希 pin 思路做成 `list_tools` 两次 diff 的
   deterministic seed (rug pull 已覆盖, tool poisoning 可加 L0 检测).
3. 调研原文: skill 见 `https://github.com/mukul975/anthropic-cybersecurity-skills` 下
   `auditing-mcp-servers-for-tool-poisoning`;mcpwn README 见 `https://github.com/ressl/mcpwn`.
