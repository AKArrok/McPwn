# McPwn → Next Session Handoff（当前）

> 顶层规约 = `HANDOFF.md`（唯一权威，设计细节）；状态快照 = `PROGRESS.md`。
> **历史里程碑 handoff 已归档**到 `attic/handoffs/`：`HANDOFF_M3.md` /
> `HANDOFF_M3_PLANNER.md` / `HANDOFF_M3_PLANNER_DONE.md` / `HANDOFF_JUDGE.md` /
> `HANDOFF_TARGETS.md` / `HANDOFF_MCP_SKILLS_RESEARCH.md`。
> 本文件是"下一 session 开工前要知道的"，只讲当前状态。

最后更新: 2026-08-06（HEAD `d88f2f5`，分支 codex/b-c-ci）

---

## TL;DR

McPwn 是 MCP 红队 agent：给一个陌生 MCP server 的 SSE 端点，自主完成
recon → hypothesis → attack → verify → report，产出 `findings.md` + 可重放 PoC。
DVMCP / excel-mcp / vault-mcp 都是 fixture，不是评测目标。

**当前主线 = 未知形状靶机三阶段实验（LLM 提能验证），已 3/3 PASS（严格更优）。**

三条已收口的历史线：
- **M2**：DVMCP 8/10 recall + FPR 0 + replay 5/5（v4 跨 model 确认）。
- **M3（结论为负，别再碰）**：LLM planner == hardcoded（recall/fpr 全等、
  avg_findings 更低），五判据全是"不劣于"→ **等价也 pass = 自欺**。教训：
  提能实验判据必须"严格更优"且可证伪。
- **SSRF 第 8 类**（skills 调研落地，commit `6eb315f`）：contracts + 2 信号 +
  recon + 卡 + 测试。**未在真靶上验证过**（没有 fetch_url 靶机）。

---

## 当前主线：未知形状实验（vault-mcp，CWE-639）

完整协议与结果见 `eval/unknown_shape/README.md`（协议权威）。要点：

### 靶机
`eval/unknown_shape/vault_server.py`（SSE 127.0.0.1:9205，内存态）：4 工具
`create_vault / read_vault / list_vaults / grant_access`。漏洞 = `_can_read`
用**子串匹配**判归属（`"" in "admin"` 为 True）→ `read_vault(owner="")` 读到
他人 secret。**不在固定 vuln class 集里、信号库零命中、recon 误判成
path_traversal**——这就是"未知形状"。

### 判据（锁死，别放松）
1. baseline = 0 findings（结构性漏，已实测）
2. llm 版每 run ≥1 finding（读到非本人 secret）
3. 同 budget 同 seed N=3，**miss 一次即 fail**（严格更优，不是"不劣于"）

### 三个 LLM 决策点（LLM 只在这三个点上线，**不做排列**）
| 点 | 时机 | 职责 | 预算 |
|---|---|---|---|
| 假设生成 | recon 后，2 次独立采样 union | 提 recon 正则漏的逻辑型假设（owner 子串绕过），score 0.99 排最前 | attacker |
| 复盘 | 第一波 0 命中且剩余预算 ≥8k | 看失败 trace 找被带偏原因，提下一步 | attacker |
| 证据判定 | 信号库 0 命中的 trace | 判真实调用是否有证据；**grounding 闸门** | judge（带外） |

**grounding 闸门（防自欺的核心）**：`evidence_text` 必须是
`evidence_call_index` 指向的真实调用 `result_text` 里的**逐字子串**；
绝不引用 attacker 总结文本。run 0（无漏洞 trace）时证据判定诚实返回
is_finding=false——不会为凑 finding 编造。

### 结果史（诚实记录）
- Stage 2：findings=2（read_vault + grant_access）
- Stage 3 第一轮 **2/3 FAIL**：假设生成单采样没提出假设 → attacker 被
  path_traversal 误判带偏、烧穿预算 → 复盘被 `budget.exceeded` 闸门关掉（接线 bug）
- 修复（不改判据）：假设生成 **2 采样 union**（降方差，仍 attacker 预算）；
  复盘闸门改 **剩余预算 ≥8k margin**；加原始输出 INFO 日志
- Stage 3 第二轮 **3/3 PASS**：每 run 2 findings

### 诚实边界
单靶机 N=3 样本量小；换一种逻辑漏洞形状（非子串鉴权 / delegate 语义 / SSRF）
是否仍成立**未验证**——这是下一步的第一优先。

---

## 关键设计决策（不要再讨论）

1. **信号 + 证据 = 真相，假设 = hint**：hit 判定 = `signal ∩ expected`，跟
   vuln_class 解耦。expected_signals 冻结于 HANDOFF §6，改必须 commit 带 reason。
2. **Grounding 闸门**：`_scan_calls` 只扫真实 `McpCall.result_text`，绝不扫
   `final_output`（防 LLM 幻觉）。证据判定同规则：evidence 必须是真实调用返回
   的逐字子串。
3. **窄 L2 judge**：indirect/chain only；judge token 独立计数不挤 attacker。
4. **metadata / chain 确定性播种**：executor `_seed_metadata_probes` /
   `_seed_chain_probe` 在 LLM 循环前跑，429 / paused 不影响。
5. **LLM 三决策点 ≠ planner**：假设生成 / 复盘 / 证据判定是**新增面**；
   排列（M3）已证 ROI 负，别再加 LLM 排序。
6. **判据可证伪**："严格更优"（≥1 / miss=fail），不是"不劣于"。

---

## 当前状态（数字）

- pytest **209 passed** / ruff clean / `lint-cards` 8/8（8 张卡）
- 8 个 vuln class；**20 条注册信号** + `llm_evidence_verdict` 合成信号（证据判定）
- 新增测试：`tests/test_llm_points.py`（解析/校验/grounding 纯函数）、
  `tests/test_verifier_minimal_poc.py`（证据判定正/反例）、
  `tests/signals/test_ssrf.py`（SSRF 闸门正/反例）
- 模型：attacker=`deepseek-v4-flash`（DeepSeek 官方），
  judge=`doubao-seed-2.0-lite`（ARK）。ARK 托管的 glm-5-2 / deepseek-v4-pro 被
  set inference limit pause，不再使用。
- 预算口径：假设生成 / 复盘记 attacker；证据判定记 judge（带外，与 L2 judge 同口径）。

## Commit 链（codex/b-c-ci，最近 8 个）

```code
d88f2f5  feat(stage2): unknown-shape 实验 - LLM 只在假设生成/复盘/证据判定三个点
6eb315f  feat(ssrf): 第 8 类 SSRF + tool-poisoning 提示词启发（skills 调研）
777cb8f  feat(eval): unknown-shape 靶机 vault-mcp + Stage-1 baseline（agent 漏）
99450ac  feat(eval): realworld --planner 校验 + decisions 审计
8d28505  fix(signals): POSIX 反斜杠是字面文件名不是分隔符
4aa65d4  docs(m3): 验收 verdict=pass + 根因复盘 + 判据修复记录
508205e  fix(m3 judge): hallucination 排除 meta-probe; chain_gate prior_link
dcabff1  docs: M3 planner 实现 handoff
```

---

## 目录地图（核心文件）

```code
HANDOFF.md            项目设计文档（唯一权威，读这个）
HANDOFF_NEXT.md       本文件，当前跨 session 上下文
PROGRESS.md           长期状态快照（数字 + commit 链）
attic/handoffs/       历史里程碑 handoff（M3 / JUDGE / TARGETS / SKILLS 调研）

mcp_redteam/
  contracts.py        VulnClass(8) / McpCall / EvidenceSignal / AttackTrace
                      (+llm_evidence_verdict) / Finding / LlmHypothesis /
                      LlmEvidenceVerdict / ScanResult / PlannerDecision
  cli.py              scan / ping-models / lint-cards / eval dvmcp
  signals/detectors.py  20 条注册信号 + llm_judged_injection 占位
  vulns/cards/*.md    8 张策略卡（含 ssrf.md）
  agent/
    recon.py          name/desc 正则分类（AUTH 0.95 / CMD 0.9 / SSRF 0.85 /
                      PATH 0.8 / INDIRECT 0.6 / meta 0.4）
    planner.py        plan() 硬编排序 + plan_llm()（M3，已证 ROI 负，别再用）
    llm_points.py     ★ 三决策点：generate_hypotheses / retrospective_hypotheses /
                      evidence_verdict + 纯解析/grounding 函数
    executor.py       openai function-calling 循环 + _seed_metadata_probes +
                      _seed_chain_probe
    verifier.py       signals + confidence + L2 judge + evidence_judge_fn
                      （0 信号 trace 上 grounded 证据判定 → llm_evidence_verdict）
  orchestrator/runner.py  scan() 顶级驱动；llm_points=True 开启三决策点
  attackers/agents/   attacker_system / planner_system / hypothesis_system /
                      retrospective_system / evidence_judge_system（全外置）
  models/chat.py      OpenAI-compat + chat_create_with_retry + rate limit
  targets/mcp_client.py  MCP SDK 薄封装

eval/
  unknown_shape/      ★ vault-mcp 三阶段实验（README 是协议权威）
  dvmcp/              DVMCP fixture + m3_judge.py
  realworld/          excel-mcp CVE 回归（prove.py 双版本对照）
  clean_baseline/     cross-server FPR baseline（9102 有 shutdown bug）

tests/
  test_llm_points.py / test_verifier_minimal_poc.py / signals/test_ssrf.py ...
```

---

## 已知坑

1. **clean_baseline 9102 shutdown bug（未修）**：FastMCP SSE 断开时子进程没优雅
   清理，报 `RemoteProtocolError`，trace stop_reason=error。修法：`sse.connect_sse`
   外层 try/except 或 finally 里 `server.shutdown()`。跟当前主线无关。
2. **vault server 是内存态**：重复跑实验会看到之前 prove.py / 之前 run 建的 vault
   （"同 seed"口径是共享该状态）。要干净环境就重启 `vault_server.py`。
3. **证据判定只在 0 信号 trace 跑**，且仅 `llm_points=True` 时启用（默认关，
   不影响 DVMCP / realworld 既有口径）。
4. **假设生成 / 复盘是 LLM 调用**：单次可能失败或空返回（已用 2 采样降方差，
   不保证 100%）。这是模型随机性，不是 bug。

---

## 下一步（按优先级）

1. **泛化验证**：换一种逻辑漏洞形状（非子串鉴权缺陷 / delegate 语义 / 带
   fetch_url 的 SSRF 靶机）重跑三阶段，验证三个决策点不是只对 vault 有效。
2. **接进回归**：把 vault-mcp + 三决策点做成 `eval` 里可跑的 fixture，防止以后
   改动破坏 "strict-better" 能力。
3. 可选：修 clean_baseline 9102 shutdown bug（跨 server FPR 的强证明还缺）。
4. 可选：SSRF 类需要一个真实 fetch_url 靶机才能验证（skills 调研的遗留）。
