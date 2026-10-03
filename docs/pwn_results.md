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

> 口径: DVMCP 是已见过、已反复调参的 regression test set。本节数字证明
> 当前版本没有破坏这些已知案例,不能外推为陌生 MCP 的真实召回率。

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
> 这是 regression result,不是独立测试结果。

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
"graph 不劣于 runner" 且额外命中一港。不要把这里的 9/10 写成真实世界 90%
recall;它只说明 DVMCP 已知回归集没有退化。

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

## 8. delegate-mcp（跨形状开发验证，CWE-639 授权作用域缺陷，2026-08）

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
  由于前 3 轮失败后发生过调参,delegate 不能作为独立 holdout 使用。

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
| delegate-mcp | CWE-639 授权作用域（跨形状开发验证） | 0 | **3/3 PASS**（第 4 轮） | owner 不可猜 fixture + 卡第 6 步执行引导 |
| fetch（真实） | SSRF（设计特性） | — | **scan 1 finding 0.75** | 信号假阳性修复 + llm 抢占 trade-off 修复（hyp budget pool） |
| git（真实，修复版） | 参数注入/路径校验（CVE 已修） | — | **0 findings（FPR ✓）** | std + llm 双配置 0 误报 |
| filesystem（真实，修复版） | allowlist 绕过（CVE 已修） | — | **0 findings（FPR ✓）** | std + llm 双配置 0 误报;漏洞版验证见下 |
| filesystem 0.6.2（真实，漏洞版） | allowlist 绕过（CVE-2025-53109/53110） | — | **prove PASS + llm 2/3**（path_traversal 0.75/0.85） | sibling 前缀碰撞 + junction 越权,judge 认账 |

---

## 11. 机制改进（2026-08, 由真实靶机验证驱动）

1. **evidence judge 提前 + 判定喂回复盘**（`dd5f13f` 之前的 `d7b7d92`）:
   attacker 幻觉自认"打进去了"时, judge 立即揭穿（is_finding=false + reason）,
   复盘把判定喂回 attacker, 依据真实失败原因重试而非重复相同动作。
2. **metadata 弱信号不阻塞 judge**（`d7b7d92`）: shadow/rug/drift 等探测副作用
   不再让 0 信号 trace 跳过 judge（filesystem 0.6.2 回归暴露: 一个 shadow
   medium 信号曾藏掉真实 CVE finding）。
3. **attacker "先阅读后动手"**（`dd5f13f`）: 通读工具面判断最可能漏洞方向后
   再打（allowlist 沙箱 → 先查 junction/symlink/前缀碰撞）, 第一波从该方向
   开始; path_traversal 卡同步补链接面/前缀碰撞绕过条目。filesystem 0.6.2
   命中率 1/3 → 2/3, 命中 run 仅 6 calls（先 list 发现 junction → 沿 junction
   越权写, judge 0.85 认账）。
4. **桥通用化**（`8b3b605`）: stdio→SSE 透传桥支持任意 stdio 命令 +
   tolerant list_tools（旧版缺 inputSchema.type 时补 type, adapter-only）。
5. **SSRF 信号变体修复**（`ade6ca2`）: hex-encoded IP / IPv6 回环 / IIS banner。

---

## 12. harness 预算效率优化（trace cap + 上下文压缩 + 提示词瘦身, 2026-10）

> 背景: 40k llm-points 单 trace 烧穿 (§5) 与 6/10 港 `budget_tokens` 停止暴露
> 预算分配缺陷。目标: recall 不降、FPR=0 前提下 tok/finding -40%。
> 口径同 §6 (20k/300s, runner → reset → graph)。产物: `runs/trace_budget_dvmcp{,_v2}/`。

机制 (均落地并有单测 `tests/test_trace_budget.py`):
1. **per-trace token cap** (`trace_token_cap`, 默认 40% 预算, -1 关闭): 单 trace
   触顶即收敛轮转, 错误方向不吃光后续候选; 9010 50-call 烧穿类回归被结构性排除。
2. **executor 上下文压缩**: 最近 2 个工具轮保留全文, 更早 tool result 截 300 字符
   digest; 证据链读 `attack_calls` 全量不受影响。注: DVMCP 上不触发 (响应短),
   对文件系统/excel 等大输出靶才生效。
3. **提示词瘦身** (参考 `AI安全工程` 口诀风格): attacker_system 2020→1738 字节,
   8 卡 18.3k→14.0k 字节 (-23%), per-trace bundle -19%; auth_bypass 卡补回
   授权范围验证步骤 (§8 第 2 轮教训), ablation stripped 臂同步重生成 (预检 PASS)。

| 轮次 | runner recall | graph recall | FPR | runner tok/finding | graph tok/finding |
|---|---|---|---|---|---|
| 基线 (§6) | 8/10 | 9/10 | 0 | 11.2k | 17.1k |
| v1: cap+压缩 | **10/10** | 9/10 | 0 | 10.9k | 12.6k |
| v2: +提示词瘦身 | 8/10 | 9/10 | 0 | 12.5k | **10.8k** |

结论与诚实边界:
1. **单 trace 饥饿已消除**: cap 在两轮共触发 6+ 次 (9006/9007/9008/9009/9010 的
   metadata/auth trace 在 8-9k 处被截停轮转), budget 港位 6/10→5/10→5/10。
2. **tok/finding -40% 未达标** (聚合 -10~-25%): 根因是 DVMCP token 大头在每次
   LLM 调用的固定开销 (system+卡+schema), 压缩碰不到; 提示词瘦身省下的
   per-call 成本被 budget 港"更便宜→更多次调用"吃掉 (Jevons), 9002/9010 仍
   烧满 20k。固定口径下 graph 累计 -37% (17.1k→10.8k), runner 受 recall 分母
   波动反而 +11%。
3. **recall 在 9004/9006/9009 上掷硬币**: 三轮 N=1, temp=0.7, 单轮 recall
   8↔10 波动主因是 LLM 漂移不是机制变化; graph 路径三轮稳定 9/10, 两模式
   聚合 recall 17→19→17 / 20。recall 结论需 N=3 才能定稿。
4. **下一步**: (a) N=3 钉牢 recall 分布; (b) 40% 缺口的剩余部分在
   DeepSeek 前缀缓存计量 (重复 system+卡+schema 前缀命中计价 1/10, 零召回
   风险, 需把口径从原始 token 换成有效成本) 或砍调用次数, 需拍板。

### 12.1 N=3 重复 (2026-10, 代码=v2 口径)

> 钉 recall 分布: 3 独立样本 × (runner → reset → graph), 产物
> `runs/trace_budget_dvmcp_n3/r{0,1,2}/`。缓存有效成本计量
> (`attacker_tokens_effective`, DeepSeek 前缀缓存命中按 1/10 折算) 在本轮
> 之后落地, 本轮数字仍是原始 token 口径。

| mode | r0 | r1 | r2 | 聚合 recall | tok/finding (N=3) | replay |
|---|---|---|---|---|---|---|
| runner | 7/10 | 8/10 | 9/10 | **24/30 = 0.80** | 12.5k (449.9k/36) | 5/5 ×3 |
| graph | 8/10 | 8/10 | 8/10 | **24/30 = 0.80** | 12.1k (423.5k/35) | 5/5 ×3 |

FPR 全部 0.00。逐港命中 (x/3): 9001-9003/9005/9007/9008/9010 = 3/3 双模式;
**9004: runner 2/3, graph 3/3**; **9006: 双模式 0/3** (indirect 结构性弱港,
v1 runner 的命中确认为漂移); **9009: runner 1/3, graph 0/3** (graph 早期单轮
命中同为漂移, 轮转后 auth_bypass 面预算切片更紧)。

结论修订:
1. **recall 定稿**: 双模式聚合 0.80, 满足 HANDOFF ≥8/10 且 FPR=0; v1 的
   runner 10/10 是漂移不是机制增益。9006 (indirect) 是结构性缺口, 与 harness
   无关, 走卡/信号层单独立项。
2. **tok/finding 定稿**: graph 17.1k → 12.1k (**-29%**, N=3 分母可信);
   runner 11.2k → 12.5k (+11%, 但基线单轮 12 findings 属幸运样本, 现两模式
   收敛到同一水平 ~12k)。原始 token 口径的 -40% 目标到此为止:
   剩余缺口在重复前缀的计费而非调用量, 由缓存有效成本计量接棒
   (`attacker_tokens_effective` 已落地, 下轮回归开始产出)。
3. trace cap 三轮持续工作 (无单 trace 烧穿复发), 压缩在 DVMCP 不触发
   (预期, 短响应靶), 对大输出真实靶有效。

### 12.2 弱港归因修复 + 缓存有效成本 (2026-10, v4/v5)

> 自主目标: recall 0.80 → ≥0.90 @N=3, FPR=0。方法: 失败 trace 归因 → 类级
> 修复 → 单轮验证 (v4) → N=3 终验 (v5, 含缓存计量)。产物
> `runs/trace_budget_dvmcp_v4/` (单轮), `runs/trace_budget_dvmcp_v5/` (N=3)。

两处结构性归因 (N=3 旧轮 + 离线信号重放):
1. **9006 (indirect) 0/6 根因 = L2 judge 校准死锁**: `stored_injection_roundtrip`
   其实 6/6 全着 (L1 注入面每次都被证明), 但 confidence=0.5 需 L2 corroboration
   才过 0.6; judge 提示词却问「红队是否被欺骗」——agent-first 架构下恒否
   (v1 命中是侥幸)。修复: judge 重校准为「指令存在 + 指令点名的目标随后被
   回访 = 可注入」(判 server 侧能力, 不判 agent 服从); indirect 卡补
   「可操作性验证」步骤。
2. **9009 (auth_bypass) 缺口**: `remote_access` 工具名/描述都不匹配 auth-gated
   正则, 且第一遍短语表缺 "command executed"; 假 token 执行 `cat /etc/shadow`
   的确认响应不被认账。修复: `_AUTH_SUCCESS_PHRASES` +`command executed` /
   `executed on` (仅限带假凭据参数的第一遍, 低噪声); `_ADMIN_RE` +
   `permission 'x' applied/granted` (自授权确认; 特意锚定 "permission" 前缀,
   vault/delegate 的 "granted read access on..." 不匹配, 冻结协议不破,
   delegate 预检 PASS)。

| mode | r0/r1/r2 | 聚合 recall | tok/finding (raw) | tok/finding (effective) | cache hit 占比 |
|---|---|---|---|---|---|
| runner | 9/10, 10/10, 10/10 | **29/30 = 0.97** | 8.5k | **3.3k** | 69% |
| graph | 9/10 ×3 | **27/30 = 0.90** | 9.7k | **3.9k** | 67% |

FPR 全 0.00, replay 15/15。逐港: 9004/9009 修复后 3/3 双模式; **9006 runner
2/3** (graph 0/3 —— graph 路径的 attacker 不回访指令点名对象, 新判据诚实
判负, 是剩余的唯一结构性缺口)。

结论:
1. **recall 目标达成**: runner 0.97 / graph 0.90 (≥0.90 @N=3), 且逐港无
   0/3 港残留于 runner 路径。
2. **成本双口径定稿**: raw tok/finding runner 11.2k→8.5k (-24%), graph
   17.1k→9.7k (**-43%, 首次达 40% 线**); effective 口径 (DeepSeek 前缀缓存
   命中按 1/10 折算, 实测命中占 raw 的 67-69%) 双模式 **-71%/-77%**。
   「每次调用固定开销占大头」的早期归因被缓存命中占比直接证实。
3. 下一步候选: graph 路径 9006 (可操作性验证步骤在 graph 的 prior_evidence
   注入下不生效, 需看注入时机), 9006 之外无 0/3 港。

### 12.3 9006 双路径翻转 + 30/30 定稿 (2026-10, v6-v9)

> 承接 §12.2 残留缺口 (graph 路径 9006 0/3)。逐轮 trace 归因发现 9006 在
> 判定链上有四个独立断点, 全部为类级修复 (无靶场答案, lint 过, 负向靶全绿):
> ① judge 可靠性: judge 调用网络错误/JSON 不可解析被吞成 None, L2 通道静默
>   丢失 (v5 r1) → `make_judge_fn` 重试一次;
> ② judge 视野: 注入指令在 attacker args 里、回访对象在后续 args 里, 但 judge
>   用户消息只给 result_text → 补 args (截 200 字符);
> ③ judge 作者判据: 旧措辞「server 嵌入的指令」让 judge 正确地观察到「payload
>   是攻击者写的」而判负 (v6) → 重校准为「server 传输路径无隔离」——测试者
>   植入 payload 是 by design, 漏洞在回显/存储不过滤;
> ④ attacker 标记格式: 卡里 `INJECTION_MARKER_{{rand}}` 占位符无人渲染, LLM
>   自造后缀长度随机 (v7 出现 2 位后缀, 不匹配 detector 的 >=4 位正则) →
>   两张注入卡明确「`INJECTION_MARKER_` + >=6 位十六进制」。

| mode | 逐轮 recall | 聚合 | raw tok/finding | effective tok/finding | cache hit |
|---|---|---|---|---|---|
| runner | 10/10, 10/10, 10/10 | **30/30 = 1.00** | 9.5k | 3.6k | 69% |
| graph | 10/10, 10/10, 9/10 | **29/30 = 0.97** | 8.9k | 3.4k | 69% |

FPR 全 0.00。唯一 miss (graph r2 9006) 经 trace 归因是判据在正确工作:
marker 合规、roundtrip 命中 (L1), 但该轮 attacker 嵌入指令后未回访点名对象,
judge 按判据诚实判负 —— 温度 0.7 下的行为方差, 非缺陷。

全程 (v1-v9, 约 200 次 scan) FPR 恒为 0; 双模式 tok/finding 收敛到
8.9k-9.5k (raw) / 3.4k-3.6k (effective, DeepSeek 前缀缓存命中 69% 按 1/10
折算), 对照基线 raw -15%/-48%, effective -68%/-80%。

至此「预算效率 + recall」双目标闭环: judge/信号层的三处结构性死锁
(作者判据、单点失败、标记格式) 与两处短语缺口是本轮真正的方法论产出 ——
**归因驱动 (离线重放 + trace 逐 call 对账) 优于调参驱动**。
