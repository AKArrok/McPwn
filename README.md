# McPwn

> **合规声明 (P4)**:本项目仅用于评估**本机 Docker 容器**上的隔离靶机:Damn Vulnerable MCP Server
> (`dvmcp`, 127.0.0.1:9001-9010)与真实世界靶机(`excel-mcp-server` 0.1.7/0.1.8, 127.0.0.1:9203/9204,
> 由 `targets/realworld/deploy.ps1` 管理)等。**禁止**将本项目及其攻击 payload
> 用于任何生产系统、公网服务或未经授权的目标。所有攻击均在隔离容器内进行,
> 由本机 `reset_hook` / `deploy.ps1 -Clean` 负责状态回收。若你不在本地运行这些容器,请立即停止使用。

<p align="center">
  <strong>一个通用 MCP 红队 agent——给一个陌生 MCP server 的 SSE 端点,
  自主完成侦察 → 假设 → 攻击 → 验证 → 报告的完整闭环。</strong><br/>
  产出人类可读的 <code>findings.md</code> 与可重放的 PoC 脚本。
</p>

<p align="center">
  <a href="https://github.com/AKArrok/McPwn/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/AKArrok/McPwn/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.13-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <a href="docs/"><img alt="Docs" src="https://img.shields.io/badge/docs-docs%2F-blueviolet"></a>
</p>

<p align="center">
  <b>不针对任何具体 challenge</b> · 同一套信号库 + 策略卡,跑任何 MCP server 都有效 ·
  <b>证据只信真实调用返回</b> · 防 LLM 幻觉假阳
</p>

---

## 目录

- [为什么是 McPwn](#为什么是-mcpwn)
- [特性](#特性)
- [快速开始](#快速开始)
- [Demo](#demo)
- [评估结果](#评估结果)
- [系统架构](#系统架构)
- [命令行参考](#命令行参考)
- [文档](#文档)
- [项目结构](#项目结构)
- [开发](#开发)
- [已知边界](#已知边界)
- [License](#license)

---

## 为什么是 McPwn

MCP (Model Context Protocol) 正在成为 LLM 应用的"USB-C 接口"——但每个 MCP server
都是一个新的攻击面:工具参数可能被执行、文件路径可能被穿越、用户输入可能被
下游 LLM 消费。**McPwn 把"人工审一个陌生 MCP server"变成一条自动流水线**:

```text
mcpwn scan <sse-url>
  → list_tools + list_resources          # 侦察:建攻击面地图
  → 按 8 类漏洞分类打标                   # 假设:工具/资源形状 → 候选
  → LLM 按策略卡出 payload 探测           # 攻击:function-calling 循环
  → 信号库 + 置信度判 Finding             # 验证:证据只来自真实返回
  → findings.md + poc/*.py                # 报告:人类可读 + 可重放
```

DVMCP、excel-mcp-server、vault-mcp 等靶机**只是验证 agent 有效性的 fixture,
不是评测目标**——agent 的通用性体现在:同一套漏洞信号库与策略卡,跑任何
MCP server 都有效。

## 特性

| 特性 | 说明 |
|---|---|
| **通用漏洞信号库** | 20 条注册信号,按严重级分级 (critical/high/medium),纯正则启发,不针对任何具体 challenge |
| **八类漏洞策略卡** | `direct_prompt_injection` / `command_injection` / `path_traversal` / `auth_bypass` / `tool_metadata_probe` / `indirect_injection` / `chain_composition` / `ssrf`,每类一份四段式策略卡 |
| **agent-first 架构** | 无需常驻 victim LLM;prompt injection 类以 L0/L1 (攻击面存在性) 为判据,不依赖下游 LLM 是否被带偏 |
| **Grounding 闸门** | 证据只来自真实 `McpCall.result_text`,attacker LLM 的总结文本永不作为证据来源,从根上防幻觉假阳 |
| **三层预算闸门** | turns / tokens / wall-time 任一超限即停;judge 的 LLM token 独立计数,不挤占攻击预算 |
| **可复现扫描** | `ScanResult` 记录 git_sha / config_snapshot / model / seed / attack_messages_sha1,数月后仍可还原"是哪份代码+哪个模型产出该结论" |
| **LangGraph 双路径** | 默认手写循环 + `--graph` 显式状态机 (跨 trace 记忆 / checkpoint / 复盘),finding 集合等价由 parity 测试守护 |
| **真实世界靶机** | excel-mcp-server CVE-2026-40576 正向/负向双版本对照回归 |

## 快速开始

### 环境要求

- Python >= 3.13 (建议 conda 环境)
- 一个 OpenAI 兼容的 LLM 端点 (attacker) + 一个可选的 judge 端点
- 跑 DVMCP / 真实靶机回归需要 Docker

### 安装

```bash
cp .env.example .env        # 填入 API key
pip install -e ".[dev]"
```

模型配置在 `mcp_redteam/config/models.yaml` (逻辑名 → OpenAI 兼容端点),API key
从环境变量读取。当前默认:

| role | provider | model | key_env |
|---|---|---|---|
| attacker | DeepSeek 官方 API | `deepseek-v4-flash` | `DEEPSEEK_API_KEY` |
| judge | 火山 Ark (Coding/Agent Plan) | `doubao-seed-2.0-lite` | `ARK_API_KEY` |

### 冒烟测试

```bash
mcpwn ping-models --roles attacker,judge   # 自测各 role 端点连通性
mcpwn lint-cards                           # 校验策略卡格式与禁词
```

### 单目标扫描

```bash
mcpwn scan http://127.0.0.1:9001/sse --out runs/m0_smoke
```

## Demo

对 DVMCP 9001 (直接 prompt injection) 的一次真实扫描:

```text
$ mcpwn scan http://127.0.0.1:9001/sse --out runs/demo_9001

┌──────────────┬─────────────────────────────┐
│ run_id       │ 20260807T123456-abc123       │
│ sse_url      │ http://127.0.0.1:9001/sse   │
│ stop_reason  │ completed                   │
│ tools_seen   │ 2                           │
│ resources_seen│ 1                          │
│ traces       │ 1                           │
│ findings     │ 1                           │
│ total_tokens │ 8,412                       │
│ wall_seconds │ 23.4                        │
└──────────────┴─────────────────────────────┘
wrote runs/demo_9001/findings.md
```

```text
runs/demo_9001/
  findings.md             # 人类可读报告:1 条 Finding (direct_prompt_injection, 0.97)
  poc/F-xxx.py            # 可重放 PoC:read_resource("internal://credentials")
  traces/trace_*.json     # 完整 AttackTrace (attacker 每一步决策 + 真实返回)
  scan_result.json        # ScanResult + 可复现元数据 (git_sha/model/seed/...)
```

> 完整真实链路示例见 [`docs/agent_chain.md`](docs/agent_chain.md) §5 (DVMCP 9001 逐轮拆解)。

## 评估结果

McPwn 用多类 fixture 回归验证 agent 有效性,产出独立指标 (不做 pass@k 主表):

| 评估 | 靶机 | 结果 |
|---|---|---|
| **DVMCP 全港** | 10 个漏洞端口 (9001-9010) | recall **8/10** (runner) / **9/10** (graph), FPR **0.00**, replay **5/5** |
| **真实世界** | excel-mcp-server CVE-2026-40576 | 0.1.7 **exploited** / 0.1.8 **blocked** 双 PASS (docker 双核对) |
| **未知形状** | vault-mcp (CWE-639 子串鉴权) | baseline 0 findings → LLM 版 **3/3 PASS** + 提示词消融 **D 3/3** |
| **泛化验证** | delegate-mcp (CWE-639 授权作用域) | **3/3 PASS** (strict-better, 换形状仍成立) |
| **SSRF 真靶** | 官方 mcp-server-fetch | scan **1 finding** (`ssrf/fetch` 0.75, 真实内网服务命中) |
| **干净基线** | 无漏洞 server 变体 | 3 变体 **0 findings** (FPR 可信度) |

> 判据设计:提能实验一律"**严格更优**" (baseline=0、每 run ≥1、N=3 miss 即 fail),
> 拒绝"不劣于"自欺——M3 的负面结果教训见 [`docs/experiment_methodology.md`](docs/experiment_methodology.md)。

## 系统架构

```
  +-----------+     recon      +-------------------+
  |  User CLI | -------------> |  agent.recon      |
  |  mcpwn    |                |  list_tools/res + |
  |  scan URL |                |  classify shapes  |
  +-----------+                +---------+---------+
                                          |
                              tool/res list + candidate vuln classes
                                          |
                                          v
                              +-----------+-----------+
                              |    agent.planner      |
                              |  select next          |
                              |  (vuln_class, target) |
                              +-----------+-----------+
                                          |
                                          v
                              +-----------+-----------+   MCP/SSE   +---------+
                              |    agent.executor     |-----------> |   MCP   |
                              |  attacker LLM +       | <---------- | server  |
                              |  vuln class card      |             +---------+
                              +-----------+-----------+             +---------+
                                          |
                                          v
                              +-----------+-----------+
                              |    agent.verifier     |
                              |  signals + LLM twin   |
                              +-----------+-----------+
                                          |
                                   Finding | no-finding
                                          |
                                          v
                              +-----------+-----------+
                              |   report.findings     |
                              |  findings.md + poc/*  |
                              +-----------------------+
```

**一次 `scan` 的产物** (写入 `--out` 目录):

```text
<out_dir>/
  findings.md             # 人类可读报告,只含 confidence >= 0.6 的 Finding
  poc/<finding_id>.py     # 每个 Finding 一个可重放 PoC
  traces/trace_*.json     # 每个 candidate 的 AttackTrace 全量落盘
  scan_result.json        # 完整 ScanResult + 可复现元数据
```

关键设计点:

- **verifier 只判"是否可疑 + 属于哪一类"**,不判成功/失败;最终是否是真漏洞由人类阅读 `findings.md` 决定。
- **Finding 置信度**由信号加权合成:`confidence = 1 - prod(1 - w_i)`
  (critical=0.95 / high=0.75 / medium=0.5 / low=0.3),LLM 二审同意 +0.1、反对 -0.2;
  `confidence >= 0.6` 才进 `findings.md`,否则只留在 `traces` 里。计权前先去重:
  同 `signal_id` 取最高严重度;同一调用返回文本命中的多条泄露类信号
  (`leaks_*` / `sandbox_escape_*` / `ssrf_*`) 视为同一证据事件只计最高权重,
  防同一份泄露被反复计权导致置信度虚高。
- **L2 judge 窄覆盖**:judge LLM 只在 `indirect_injection` / `chain_composition`
  两类 trace 上二审,且单条 medium 信号不过 0.6 阈值,必须与确定性 L1 信号
  同 trace 共现才成 finding——把 judge 幻觉的爆炸半径封顶;judge 引用的
  `evidence_call_index` 越界时降级为 not-steered,不产出信号。

## 命令行参考

### `mcpwn scan <sse-url>`

对单个 MCP server 执行完整扫描。

| 选项 | 默认 | 说明 |
|---|---|---|
| `--out`, `-o` | `runs/scan_latest` | 产物输出目录 |
| `--max-tokens` | 30000 | attacker token 预算 |
| `--wall-seconds` | 240 | 墙钟时间预算 (秒) |
| `--max-candidates` | 20 | 最多探测的 (vuln_class, target) 候选数 |
| `--max-inner-steps` | 12 | 每个候选的 attacker 工具调用轮数上限 |
| `--attacker-temperature` | models.yaml | 覆盖 attacker 温度;用 0 得到可复现扫描 |
| `--headers` | — | SSE 请求头,如 `x-user-id=mcpwn,x-chat-id=scan1` (真实世界 MCP server 常用) |
| `--sandbox-root` | — | 声明的沙箱根 (部署元数据),启用 sandbox-escape 判据 |
| `--graph` | false | 以显式 LangGraph 状态机跑流水线 (与默认手写循环等价) |
| `--llm-points` | false | 启用三 LLM 决策点:假设生成 / 零发现复盘 / grounded 证据判定 (unknown-shape 覆盖) |

### `mcpwn ping-models [--roles ...]`

逐个 role 发一次 `pong` 冒烟请求,默认 `attacker`。

### `mcpwn lint-cards`

加载并校验全部策略卡 (四段标题齐全、无已知靶场明文答案)。

### `mcpwn eval dvmcp ...` / `mcpwn eval realworld ...`

回归评估子命令,见 [`docs/eval_guide.md`](docs/eval_guide.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/pipeline.md`](docs/pipeline.md) | 代码端到端链路 (runner + graph 双视图) |
| [`docs/agent_chain.md`](docs/agent_chain.md) | agent 思维与行动链路 (双路径) |
| [`docs/mcp_attack_surface.md`](docs/mcp_attack_surface.md) | 打 MCP 的攻击思路与入手面 |
| [`docs/anti_hallucination.md`](docs/anti_hallucination.md) | 防幻觉机制全集 (Grounding 闸门 / 指纹化 / claim mismatch) |
| [`docs/eval_guide.md`](docs/eval_guide.md) | 评估体系导航 (6 个 eval 怎么跑) |
| [`docs/reproducibility.md`](docs/reproducibility.md) | 可复现性设计 (seed / attack_messages_sha1) |
| [`docs/experiment_methodology.md`](docs/experiment_methodology.md) | 可证伪实验方法论 (strict-better 判据) |
| [`docs/pwn_results.md`](docs/pwn_results.md) | 各靶机攻击成果与结果记录 |

设计规约 (项目内部):`HANDOFF.md` (唯一权威) / `AGENTS.md` (顶层规约) /
`PROGRESS.md` (状态快照)。

## 项目结构

```
mcp_redteam/
  contracts.py            数据契约 (VulnClass/McpCall/EvidenceSignal/AttackTrace/
                          Finding/JudgeVerdict/LlmEvidenceVerdict/ScanResult/...)
  cli.py                  mcpwn 命令入口
  signals/detectors.py    20 条注册信号 + L2 占位
  vulns/cards/*.md        8 张策略卡 + registry.py (加载与 lint)
  agent/
    recon.py              侦察:list tools/resources + 形状分类打标
    planner.py            候选排序 (hardcoded;LLM 版已证 ROI 负,保留供对比)
    llm_points.py         三 LLM 决策点 (假设生成/复盘/证据判定)
    executor.py           openai function-calling 循环 + 主动探测
    verifier.py           信号汇总 + 置信度 + L2 judge + 证据判定
  orchestrator/           runner.py (scan 驱动) / budget.py (三闸门) / reset_hook.py
  langgraph/              LangGraph 状态机 (graph=True 路径)
  targets/mcp_client.py   MCP SDK 薄封装
  models/chat.py          OpenAI-compat 工厂 + retry-with-backoff + 限流
  judge/                  L2 judge (prompt 外置 + JSON 解析)
  report/findings.py      ScanResult -> findings.md + poc/*.py
eval/
  dvmcp/                  DVMCP fixture + expected.yaml + runner + m3_judge
  realworld/              excel-mcp CVE 回归 (prove.py 双版本对照)
  unknown_shape/          vault-mcp 三阶段实验 + 提示词消融
  generalize/             delegate-mcp 跨形状验证
  fetch_ssrf/             官方 mcp-server-fetch SSRF 真靶
  clean_baseline/         无漏洞 server 的 FPR baseline
  regression.py           三靶机聚合回归 (prove/baseline/llm/full)
tests/                    单元/回归测试 (pytest, 数量见 CI badge)
docs/                     8 篇文档 (见上表)
scripts/                  check_docs.py (文档 vs 代码 vs pyproject 一致性校验,CI 挂载)
```

## 开发

```bash
pytest                       # 全部测试 (数量见 CI badge)
ruff check mcp_redteam eval  # lint (0 errors)
mcpwn lint-cards             # 策略卡校验
python scripts/check_docs.py # 文档 vs 代码 vs pyproject 一致性校验
python eval/regression.py    # 三靶机聚合回归 (默认 prove, 无 LLM ~30s)
```

### 贡献

- 新增漏洞类/信号/策略卡:见 `mcp_redteam/vulns/AGENTS.md` 与 `mcp_redteam/signals/AGENTS.md`
- 文档里写死数字前,先在 `scripts/check_docs.py` 加规则——不靠人记得同步
- 所有攻击测试必须在隔离容器内进行 (见顶部合规声明)

## 已知边界

- **prompt injection 类覆盖 L0/L1 (攻击面存在性),不覆盖 L2 (下游 LLM 真被带偏)**;
  L2 需要 victim/judge LLM,是可选增强,见 `PROMPT_INJECTION_GAP.md`。
- **LLM planner (M3) 已实测与 hardcoded 等价甚至更差**,结论记录在案,不再作为提能方向;
  提能实验一律走"严格更优 + 可证伪"判据 (见 `docs/experiment_methodology.md`)。
- 未知形状发现依赖 `--llm-points` 三决策点,默认扫描不启用 (不影响既有判据口径)。

## License

[MIT](LICENSE) © 2026 McPwn contributors
