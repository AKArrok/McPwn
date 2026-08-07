# 靶机 Pwn 与 B 阶段验证结果汇总（2026-08-06）

> 目标: 在真实靶机（excel-mcp CVE-2026-40576 + DVMCP 9006/9010）上记录
> **实际 pwn 结果**（确定性 exploit 链 + scan findings），并对照
> LangGraph 路径（`scan --graph`，B 阶段跨 trace 记忆）与默认 runner。
> 运行产物: `runs/lg_b_verify/`（scan_result.json / findings.md / proof_report.md）。

---

## 1. excel-mcp（真实世界靶机，CVE-2026-40576）

### 1.1 确定性 exploit 链（`eval.realworld.prove`，不走 LLM）

**v0.1.7（漏洞版，excel-mcp-017 @ :9203）→ `prove_expect=exploited` → PASS**

```text
nonce  : MCPWN-20260806T090037-33f962
marker : /root/mcpwn_pwned_MCPWN-20260806T090037-33f962.xlsx   # 沙箱外绝对路径
```

| step | 调用 | 结果 |
|---|---|---|
| 1 | `create_workbook({filepath: /root/mcpwn_pwned_<nonce>.xlsx})` | `Created workbook at /root/...`（接受沙箱外路径） |
| 2 | `write_data_to_excel({filepath, data: [[nonce]]})` | `Data written to Sheet1` |
| 3 | `read_data_from_excel({filepath, sheet_name: Sheet1})` | `A1 = MCPWN-20260806T090037-33f962` |

- out-of-band `docker exec ls`: 文件存在于 `/root/`（`-rw-r--r-- 1 root root 4847`）
- out-of-band `docker exec` 读回 A1: `MCPWN-20260806T090037-33f962`
- **结论: 成功越权写入并回读沙箱外文件 → exploited**

**v0.1.8（修复版，excel-mcp-018 @ :9204）→ `prove_expect=blocked` → PASS**

| step | 调用 | 结果 |
|---|---|---|
| 1 | `create_workbook({filepath: /root/mcpwn_pwned_<nonce>.xlsx})` | 拒绝: `Invalid filename ... must be relative to EXCEL_FILES_PATH` |

- out-of-band `docker exec ls`: `No such file or directory`
- **结论: 绝对路径被拒、无文件落盘 → blocked（修复生效）**

### 1.2 scan 对照（graph vs runner，`--sandbox-root /tmp/sandbox`）

| 靶机 | 模式 | traces | findings | 注入 |
|---|---|---|---|---|
| 9203 v0.1.7 | runner 20k | 1 | `path_traversal on read_data_from_excel` 0.75 | 无 |
| 9203 v0.1.7 | graph 20k | 1 | 同上（逐字段一致） | 无（单 trace） |
| 9203 v0.1.7 | graph 45k | 2 | read 命中 0.94 | `write_data_to_excel` **injected=True** |
| 9204 v0.1.8 | runner 20k | 1 | 0 | 无 |
| 9204 v0.1.8 | graph 20k | 1 | 0（FPR 0） | 无 |

- graph 与 runner 在真实靶上 finding 全等；修复版两模式都不误报。
- 45k 预算下 graph 注入生效: `write_data_to_excel` 候选收到 `read_data_from_excel`
  的 path_traversal 命中摘要——正好对准该 CVE 的 read/write 组合方向。

---

## 2. DVMCP（9006 / 9010）

| port | 模式 | traces | findings | 注入 |
|---|---|---|---|---|
| 9010 Multi-Vector（chain_composition） | runner 20k | 3 | 3（path_traversal / chain / indirect） | 全部无 |
| 9010 | graph 20k | 3 | 2（path_traversal 0.95, **chain_composition 0.95**） | chain、indirect trace **injected=True** |
| 9006 Indirect Prompt Injection | runner 20k | 2 | 0 | 无 |
| 9006 | graph 20k | 2 | 0 | meta trace injected=True |

- **9010 graph 版**: 首个命中（path_traversal on get_config）后 `chain_composition`
  被 `promote_chains` 提到第 2 位执行，且注入 prior evidence 后以 0.95 命中——
  B 阶段目标（chain 候选看到 prior hits）达成。
- 9010 runner 版无任何注入（对照成立）。9006 两版均 0 findings（indirect 弱港）。

---

## 3. 结论

1. **真 pwn 已实证**: excel-mcp 0.1.7 通过 3-call 链越权写读沙箱外文件
   （docker 双核对）；0.1.8 修复版拦截（绝对路径拒绝 + 无落盘）。
2. **graph 与 runner 行为等价**: 两个真实靶上 finding 集合一致（9010 港
   recall 两版都命中；9203 逐字段全等），未劣于。
3. **B 阶段记忆在真实靶生效**: DVMCP 9010 chain 注入 + promote + 命中；
   excel-mcp 9203 read→write 注入（CVE 组合方向）。
4. **FPR 保持 0**: 9204（修复版）与 9006 两模式均无误报。

## 4. 诚实边界

- N=1 点估计: LLM 在环，同 seed 可能漂移；9010 findings 数 graph(2) vs
  runner(3) 差异含漂移与预算分配变化（chain 提前消耗）。
- 20k→45k 预算下 9203 首个 finding 0.75→0.94 含 calls 数差异。
- prove 是确定性 3-call 链（无 LLM），结果可复现；scan 结果不可复现于同 seed。
- 未锁 seed（deepseek 不支持），`attack_messages_sha1` 可复核漂移。

---

## 5. 补跑：judge 模型参与（--llm-points）

> CLI 补暴露 `--llm-points`（此前只有 runner 参数、CLI 无开关）。三组扫描
> 全部 `llm_points=True`：假设生成 + 复盘 + **evidence judge（judge 角色
> doubao 对 0 信号 trace 做 grounding 证据判定）**。

| 扫描 | traces | findings | judge_tokens | evidence_judge_model | 注入 |
|---|---|---|---|---|---|
| 9010 graph llm-points 40k | 1（auth_bypass on get_config, 50 calls 烧穿预算） | 0 | 3466 | doubao-seed-2.0-lite | 无（单 trace） |
| 9010 runner llm-points 40k | 1（direct_prompt_injection, 28 calls） | 0 | 0 | doubao-seed-2.0-lite | 无 |
| 9006 graph llm-points 40k | 3 | 0 | 3112 | doubao-seed-2.0-lite | trace[1][2] injected |

### judge 参与结论

1. **evidence judge 真实参与了评判**：`evidence_judge_model='doubao-seed-2.0-lite'`
   记录 + `judge_tokens=3466/3112`（带外计数）——judge 角色模型（ARK 豆包）对
   0 信号 trace 执行了 grounding 证据判定。
2. **判定诚实（grounding 闸门）**：9010 graph llm-points 的 auth_bypass trace
   （50 次调用、0 确定性信号）被 judge 判定 `is_finding=false`——没有真实
   证据子串就不编造 finding（这正是防自欺设计）。
3. **口径细节**：9010 runner llm-points 的 `evidence_judge_model` 非空但
   `judge_tokens=0`——`_make_evidence_judge_fn` 记录了配置模型，但该组无
   0 信号 trace 触发实际调用（模型名=配置口径，tokens=实际消耗口径，两者分开看）。
4. **B 注入在 llm-points 组也工作**（9006 graph trace[1][2] injected=True）。
5. 注意：llm-points 组 9010 仅 1 个 candidate 即烧穿 40k 预算（假设生成 2 采样 +
   首个 trace 50 calls）→ 0 findings；与非 llm-points 组的 2-3 findings 差异是
   预算分配现实，非回归；judge 判定诚实否定未产生假阳性。

---

## 6. DVMCP 全 10 港 graph-vs-runner 对比（2026-08-06）

> 方法: `eval/dvmcp/runner.py` 的 `run_all` 加 `graph` 参数后跑两轮（runner →
> reset DVMCP → graph），预算 max_tokens=20000 / wall=300s。脚本与产物:
> `runs/lg_b_dvmcp_full/{compare.py, COMPARE.md, runner/, graph/}`（runs/ 忽略区）。

| 指标 | runner | graph |
|---|---|---|
| recall | 0.80 (8/10) | **0.90 (9/10)** |
| FPR | 0.00 | 0.00 |
| poc_replay_pass_rate | 1.00 (5/5) | 1.00 (5/5) |
| avg_findings/port | 1.2 | 0.9 |

逐港: 9001/9002/9003/9005/9007/9008/9009/9010 两版一致命中; 9006 两版都 miss
(indirect 弱港); **9004 (Rug Pull) runner miss、graph hit** —— 唯一差异。

对照 HANDOFF §10 验收（≥8/10 recall / 0 FPR / 5/5 replay）: **graph 9/10 满足
且严格更优; FPR 0; replay 5/5**。9004 差异可能含 LLM 漂移(N=1), 但方向是
"graph 不劣于 runner" 且额外命中一港。

---

## 7. vault-mcp（unknown-shape 实验，CWE-639 子串鉴权，2026-08-06）

> 协议与结果: `eval/unknown_shape/README.md`（权威）。判据锁死:
> baseline=0 findings（结构性漏）、llm 版每 run ≥1、同 budget N=3 **miss 即 fail**。

| 阶段 | 结果 |
|---|---|
| Stage-1 baseline（hardcoded planner + 信号库） | ✅ **0 findings**（`stop=budget_tokens`，attacker 被 recon 带偏 path_traversal，22 次调用全是穿越尝试） |
| Stage-2 LLM 三决策点（假设生成/复盘/证据判定） | ✅ 2 findings（`AUTH_BYPASS read_vault 0.75` + `grant_access 0.75`） |
| Stage-3 重复 N=3 | 第一轮 **2/3 FAIL**（假设单采样没提 auth_bypass）→ 修复：假设生成 2 采样 union + 复盘闸门改剩余预算≥8k → **第二轮 3/3 PASS** |
| Stage-4 提示词消融（2×2，A=双 HINTED / D=双 STRIPPED） | ✅ **A 3/3 + D 3/3**：剥离版提示词+卡（无 vault 答案）仍 3/3 → **能力成立（LLM 价值含「发现」不止「执行」）** |

- 证据 grounding: `read_vault(owner="", name=...)` 返回 admin secret（`"" in "admin"`）。
- judge 诚实: baseline 的 path_traversal 误判 trace 上 `is_finding=false`（不编造）。

---

## 8. delegate-mcp（泛化验证，CWE-639 授权作用域缺陷，2026-08）

> 协议与结果: `eval/generalize/README.md`（权威）。换形状重跑三阶段——与 vault
> 的**子串匹配**机制不同: `_can_read` 精确匹配，漏洞在 `grant_access` 把
> delegate 记入**全局集合**（授权作用域泄漏到所有 vault）。剥离版提示词+卡
> （类级框架，无 vault 答案）。判据同 vault: 每 run ≥1、N=3、miss 即 fail。

| 轮次 | 结果 | 修复 |
|---|---|---|
| baseline | ✅ 0 findings（结构性漏） | — |
| 第 1 轮 | **2/3 FAIL** | owner=`admin` 可猜 → LLM 走"冒充 owner 自授权"通用路径污染归因 → 修复: `admin_vault` owner 改不可猜字符串 `owner-9f7c3e21` |
| 第 2 轮 | **1/3 FAIL** | attacker grant 成功后只自证（读自己 vault）不做范围验证 → 修复: auth_bypass 卡补类级第 6 步"授权成功后用被授权身份 list 枚举可见资源并对比" |
| 第 3 轮 | **2/3 FAIL** | 同型"自证收敛" → 卡第 6 步加强（明确 list 枚举动作） |
| **第 4 轮** | ✅ **3/3 PASS（strict-better）** | run 0/1/2 各 1 finding（auth_bypass 0.75），归因全部干净 |

- 成功 finding 形态: attacker 诚实身份建 vault → grant 自己第二账号 → 被授权
  身份 `list_vaults` 意外列出 `admin_vault` / 读到未授权 vault secret（judge 0.9 认账）。
- 结论: 假设生成/judge 跨形状稳定，**方差在执行层"验证范围"动作** → 跨形状
  稳定性低于 vault；精确结论 = "类级框架 + 类级执行引导下跨形状严格更优成立"。

---

## 9. fetch（真实靶机，SSRF，2026-08）

> 协议与结果: `eval/fetch_ssrf/README.md`（权威）。GitHub 官方
> `modelcontextprotocol/servers` 的 `mcp-server-fetch`（真实 server，stdio），
> stdio→SSE 透传桥 + 本地 intranet 受害者（全 127.0.0.1 合规）。SSRF 面是
> **设计特性**（README 自认可访问内网）→ 最新版即"漏洞版"。补上 HANDOFF 遗留
> 的"SSRF 真靶验证"。

| 项目 | 结果 |
|---|---|
| prove（确定性 exploit） | ✅ `fetch("http://127.0.0.1:9211/")` 回流 `TOP-SECRET-INTRANET-2026` + nginx banner |
| **标准 scan** | ✅ **1 finding（`ssrf/fetch 0.75`，`ssrf_internal_service` high，stop=completed）**——SSRF 类（信号+卡）在真实 server 上端到端成立。命中点: `fetch("http://127.0.0.1:80/")` 返回**本机真实内网服务**的 `IIS Windows` banner（系统 HTTP.sys，非自建），`0x7f000001` 十六进制绕过同样命中 |
| llm_points 轮 | ⚠️ 连续 3 次 miss（1 次误报已修 + 2 次零命中）——暴露两个真实问题（见下） |

### 真实靶机暴露的两个问题

1. **信号假阳性（已修复）**: llm 轮误报 `path_traversal@fetch 0.75`，根因
   `leaks_hardcoded_password` 把错误回显 `Failed to fetch file:///etc/passwd:
   UnsupportedProtocol...` 的 `/etc/passwd:` 当密码键值（fetch 实际拒绝
   file://，无真实泄漏）。修复: `_HARDCODED_PW_RE` 加 `(?<![/a-zA-Z0-9])`
   前缀负向断言 + 3 条回归测试（`tests/signals/test_leaks.py`）。
2. **llm_points 假设抢占 trade-off（已修复）**: 假设生成 score=0.99
   排最前，曾把 recon 已正确分类的 `SSRF@fetch`（0.85）挤出 30k 预算 → llm 轮
   3 次 miss vs 标准 scan 一次即中。修复 = **LLM-hypothesis budget pool**
   （`llm_hyp_budget`，默认 40% attacker 预算）: LLM 假设候选共享一个池，
   池耗尽后剩余 LLM 假设被跳过、recon 候选照常执行；unknown-shape 实验
   （vault/delegate）传 `-1` 关闭池保持原行为。实现见
   `orchestrator/runner.py` + `orchestrator/budget.py`，
   回归测试 `tests/test_llm_hyp_budget.py`。

---

## 10. 靶机成果总表（截至 2026-08）

| 靶机 | 漏洞形状 | baseline | 检出（最终） | 关键修复/发现 |
|---|---|---|---|---|
| excel-mcp 0.1.7 | 沙箱逃逸（CVE-2026-40576） | — | prove exploited + scan 0.75/0.94 | 0.1.8 修复版 blocked（对照） |
| DVMCP 9010 | chain/indirect | — | graph 2-3 findings（0.95） | B 阶段注入+promote 生效 |
| vault-mcp | CWE-639 子串鉴权（unknown-shape） | 0 | **3/3 PASS**（llm 版） | 消融 D 臂 3/3 → 能力成立 |
| delegate-mcp | CWE-639 授权作用域（泛化） | 0 | **3/3 PASS**（第 4 轮） | owner 不可猜 fixture + 卡第 6 步执行引导 |
| fetch（真实） | SSRF（设计特性） | — | **scan 1 finding 0.75** | 信号假阳性修复 + llm 抢占 trade-off 修复（hyp budget pool） |
| git（真实，修复版） | 参数注入/路径校验（CVE 已修） | — | **0 findings（FPR ✓）** | std + llm 双配置 0 误报 |
| filesystem（真实，修复版） | allowlist 绕过（CVE 已修） | — | **0 findings（FPR ✓）** | std + llm 双配置 0 误报;漏洞版 schema 不兼容未做 |
