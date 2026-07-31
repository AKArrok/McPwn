# McPwn → Next Session Handoff

> 读这个文件 + `HANDOFF.md` 就能接上。`PROGRESS.md` 是状态快照（数字 + commit 链），
> `HANDOFF.md` 是项目设计文档，这个文件是"你下一 session 开工前要知道的"。

最后更新: 2026-07-31 (commits 83b5146, 8f6bd67, 315df37)

---

## TL;DR

McPwn 是一个 MCP 红队 agent: 给一个陌生 MCP server 的 SSE 端点, 自主完成 recon →
hypothesis → attack → verify → report, 产出人类可读的 `findings.md` + 可重放 PoC。
DVMCP (Damn Vulnerable MCP Server) 是验证 agent 有效性的 fixture。

**M2 已过**, 真实 10 港跑出来 **recall 0.80 (8/10), FPR 0.00, PoC 重放 1.00**。
M3 (LLM 决策版 planner) 是下一里程碑。

---

## 关键设计决策（不要重新讨论）

### 1. 信号 + 证据 = 真相, 假设 = hint (刚改完)

**旧**: finding 的 `vuln_class` 由 recon 分类器猜的 hypothesis 决定 → recall 测的是
"分类器准不准", 是循环验证。

**新** (commit 83b5146): eval 改成 signal-based. Hit 判定 = `finding.signals ∩
expected_signals ≠ ∅`。finding 同时有:
- `vuln_class` (hypothesis, recon 猜的, 向后兼容)
- `evidence_class` (从 signal + 产生它的 call 推断的, 真正的证据)

`expected.yaml` 每港有 `expected_signals` 列表 (e.g. 9007: `[unauthenticated_success]`),
不再用 `also_accept` 做判据。

**含义**: M3 实现时 LLM planner 猜错 vuln_class 不影响 recall, 只要 signal 命中。
`evidence_class` 暴露 label 错位 (e.g. 9009: `hyp=command_injection, ev=auth_bypass`
因为 `unauthenticated_success` signal 明显是 auth 证据)。

### 2. Grounding 闸门 (防 LLM 幻觉)

`_scan_calls` 不扫 `final_output`, leak/行为 signal 只从 `call.result_text` 命中。
LLM 收敛轮不再要求"逐字引用可疑串" (诱导幻觉), 改为"一句话总结探了什么、证据落在哪条 call"。

每条 fired signal 必带非空 `source_call_index`。test
`test_hallucinated_secret_in_final_output_does_not_fire` 锁住这条不变式。

### 3. 窄 L2 judge (indirect/chain only)

`verifier` 对 `INDIRECT_INJECTION` / `CHAIN_COMPOSITION` trace 调 judge LLM (role="judge")。
judge 输入 = `attack_calls.result_text` (截断) + `final_llm_output` + 任务描述。
返回 `{steered, evidence_call_index, reason}`, steered=True 时 verifier 合成
`llm_judged_injection` (medium) 信号。

**L2 单独 (0.5) 不过 0.6 阈值**, 必须和确定性 L1 信号共现。judge token 走
`budget.add("judge", ...)`, 独立计数不挤 attacker。

`detect_llm_judged_injection` 保持纯函数占位, 不进 `DETECTORS`。

### 8. retry-with-backoff at chat layer (chat.py)
`chat_create_with_retry` 包装 `client.chat.completions.create`. 重试 5 次 (RateLimitError / APITimeoutError / APIConnectionError / InternalServerError), 退避 1/2/4/8/16s。4xx (BadRequestError 等代码 bug) 不重试。动机: M2 v3 重跑 (`runs/m2_dvmcp_full_v3/`) 命中 ARK `glm-5-2` set inference limit 触顶, executor 在 step 0 拿到 429 立刻 break, 整 trace 0 attack_calls → 0 findings → port miss (recall 8/10 → 6/10, 9008/9009)。retry 让短暂限流在同一 trace 内清掉, 不再把 port 拖到 0 finding。Wall-time budget 不在 retry helper 内查, 由 executor 每轮的 clock check 兜底; token budget 不受影响 (失败 attempt 不计费)。

### 4. metadata probing 主动探测 (executor)

`executor._seed_metadata_probes` 在 LLM 循环开始**之前**对 `TOOL_METADATA_PROBE` 候选主动调:
- shadow tool 对: 同 args 调两个近名 tool 各一次
- 单 tool: 同 args 调 4 次 (rug pull)
- refresh `list_tools` (drift)

探测塞进 `attack_calls`, 让行为类 signal 有数据可用。`_pick_probe_args` 从 tool schema
读第一个 required 参数, 给合理默认字符串, 避免 MCP SDK 拒绝 (SDK 不会传 schema 外的
参数, 所以 marker args 会被吞, 这就是为什么 `rug_pull_response_flip` 有
不依赖 marker 的 fallback 分组)。

### 5. auth detector 两遍 pass (9007/9009 关键)

`detect_unauthenticated_success`:
- **第一遍**: args 里有 auth-shaped key (`auth_token`/`token`/`api_key` 等),
  值是空/伪造, 响应含 success phrase
- **第二遍**: tool 名字匹配 `_AUTH_GATED_NAMES` (`remote_access`/`verify_token`/`admin`
  等), **整个 trace 里没有成功的 `authenticate` 调用** (`prior_auth_ok=False`),
  响应含 success phrase (含 "appears to be valid" / "command executed" / "executed on")

第二遍覆盖"伪造非空 token 被接受"和"optional auth 参数被省略但 tool 仍执行"两个场景。

### 6. verifier 过滤 (FPR 的关键)

`TOOL_METADATA_PROBE` trace 只接受 metadata 类 signal (drift/shadow/rug_pull/
suspicious_error/stored_injection), 滤掉 leak/行为类。原因: 主动探测会调到有漏洞的
tool (e.g. 9001 `get_user_info`, 9003 `file_manager`), leak signal 会命中但证据属于
该 tool 自己的 vuln_class, 不属于 metadata probing。

### 7. Hard-coded tool gating 在 vuln_class 决策上是不可信的

`recon.AUTH_BYPASS` score 从 0.75 提到 0.95, 高于 `COMMAND_INJECTION` 的 0.9。
让 `remote_access`/`verify_token` 优先走 auth_bypass 策略卡。但这是启发式兜底,
M3 的 LLM planner 应该比这更聪明。

---

## 当前状态

### 数字 (M2, 真实 10 港, `runs/m2_dvmcp_full_v2/`)

| 指标 | 值 | 要求 |
|---|---|---|
| recall | 0.80 (8/10) | >= 0.7 |
| FPR | 0.00 | < 0.3 |
| poc_replay_pass_rate | 1.00 (5/5) | 有就行 |
| pytest | 50 passed | |
| ruff | 0 errors | |
| lint-cards | 7/7 ok | |

### 10 港逐港明细

| port | hit? | findings | conf | signals | evidence_class |
|---|---|---|---|---|---|
| 9001 | YES | 1 | 0.97 | leaks_api_key_shape, leaks_hardcoded_password, stored_injection_roundtrip | chain_composition |
| 9002 | YES | 1 | 0.75 | command_exec_uid_stdout | command_injection |
| 9003 | YES | 1 | 0.95 | leaks_etc_passwd | path_traversal |
| 9004 | YES | 1 | 0.75 | rug_pull_response_flip, suspicious_error_pitch | tool_metadata_probe |
| 9005 | YES | 1 | 0.75 | shadow_tool_pair, shadow_tool_behavior_divergence | tool_metadata_probe |
| 9006 | no | 0 | - | L1 stored_injection_roundtrip 命中 (0.5), L2 judge 被调 (1083 tok) 但没追加信号 | - |
| 9007 | YES | 2 | 0.75 | unauthenticated_success (authenticate + verify_token 各一条) | auth_bypass |
| 9008 | YES | 1 | 0.99 | leaks_etc_passwd, command_exec_uid_stdout | command_injection |
| 9009 | YES | 3 | 0.75-0.94 | unauthenticated_success, admin_action_confirmed | auth_bypass |
| 9010 | no | 0 | - | L2 judge 被调 (1581 tok), 无 L1 锚定 | - |

9006 和 9010 是 HANDOFF §8 标的 bonus, 不阻塞 M2。

### Commit 链 (`main` 分支, 7 个 commit)

```
8e322f7  Initial McPwn v1 (agent-first) after supplemental review
59abf9c  fix: metadata probe signals + verifier filtering for 5/5 recall, 0% FPR
7cf39bc  feat: poc_replay_pass_rate + eval findings.md + ruff clean (0 errors)
6f7be23  fix: auth_bypass detection for 9007/9009 -> M2 recall 8/10
897df81  feat: hallucination suppression (grounding gate + L2 judge) + M2 verified
342aef4  docs: add PROGRESS.md to prevent context drift across sessions
83b5146  feat: signal-based eval + evidence_class (honest vulnerability discovery)
8f6bd67  fix: replace DVMCP-shaped _AUTH_GATED_NAMES with description+name heuristic
315df37  fix: retry-with-backoff for LLM transient errors
```

工作树干净 (`git status` 无改动)。

---

## 目录地图 (核心文件)

```
HANDOFF.md                      项目设计文档 (读这个)
PROGRESS.md                     状态快照 (数字 + commit 链)
AGENTS.md                       顶层规约 (5 字段硬性规则)
CODE_REVIEW.md                  上一轮 code review (含已修复的 P0-P3)
README.md                       快速开始

mcp_redteam/
  contracts.py                  数据契约 (VulnClass/McpCall/EvidenceSignal/AttackTrace/
                                Finding/ScanResult). Finding 有 hypothesis_class +
                                evidence_class 两个字段.
  cli.py                        mcpwn scan <url> / ping-models / lint-cards / eval dvmcp

  signals/detectors.py          15 条 signal detector (14 注册 + llm_judged_injection 占位).
                                _scan_calls 不扫 final_output (grounding 闸门).
  vulns/cards/*.md              7 张策略卡 (通用红队启发, 无 challenge 明文答案).
  vulns/registry.py             load_card + lint (禁 secret 明文 + 禁 challenge 名).

  agent/
    recon.py                    list tools/resources + classify by name/description regex.
                                AUTH_BYPASS score=0.95, COMMAND_INJECTION=0.9.
    planner.py                  按 score 排序遍历. **M3 改这里**.
    executor.py                 openai function-calling 循环 + _seed_metadata_probes 主动探测.
                                收敛轮 tool_choice="none" + 强制 break.
    verifier.py                 signals + confidence + L2 judge (indirect/chain only) +
                                evidence_class 推断. Finding 过滤 (tool_metadata_probe 只能接
                                metadata signal).

  orchestrator/
    runner.py                   scan() 顶级驱动.
    budget.py                   三闸门 (turns/tokens/wall). judge token 独立.

  targets/mcp_client.py         MCP SDK 薄封装 (raw_list_tools/resources).
  models/chat.py                OpenAI-compat 工厂.
  adapters/base.py              PyRIT Protocol 镜像 (不装 PyRIT).

  report/findings.py            ScanResult → findings.md + poc/*.py.
                                evidence_class 仅在 ≠ vuln_class 时显示.

eval/dvmcp/
  expected.yaml                 10 港预期 (primary_class + expected_signals + evidence_hint).
  runner.py                     全港扫描 + signal-based recall/FPR/replay 指标.

tests/                          50 passed.
```

---

## M3 任务: LLM 决策版 planner

HANDOFF §3 画的图里 planner 是 "select next (vuln_class, target)" 决策核心。
M2 用硬编 score 排序遍历, M3 换成 LLM 决策。

### M3 开工前要决定的 4 点

1. **LLM planner 输入**: 喂什么给 LLM?
   - 选项 A: 只喂 recon 结果 (tool 列表 + description + 已有 candidate 列表),
     让 LLM 选 next (vuln_class, target)
   - 选项 B: 加上"上一步执行结果" (上一步 signal 命中 / 失败), 让 LLM 可以链式决策
   - 选项 C: 让 LLM 自由生成新的 candidate (不限于 pre-computed 列表), 类似 MCTS

2. **LLM planner 输出**: LLM 返回什么?
   - 选项 A: `next(vuln_class, target, reason)` - 单步决策
   - 选项 B: 多步计划 `[(v1, t1), (v2, t2), ...]` - 减少 LLM 调用次数
   - 选项 C: 自由文本指令, executor 解析 - 灵活但脆

3. **怎么对比 LLM vs 硬编**:
   - 跑 10 港, 同样的 15000 token / 120s wall budget
   - 对比 recall / FPR / avg_findings_per_port / poc_replay_pass_rate
   - 还要看 trace json diff: LLM planner 选了哪些 candidate, 跳过了哪些

4. **Token 成本**: 每个 candidate 决策都要调一次 LLM. 10 港 × 多候选 × 决策 LLM
   = token 涨一个量级. 要不要给 LLM planner 单独 budget 闸门? 还是算在 attacker 里?

### M3 的失败模式预设

- **LLM 太保守**: 选 hypothesis 时倾向选"安全"的那几个, 跳过 rug_pull / shadow 之类
  需要主动调多次的类别 → recall 掉到 6/10 以下
- **LLM 太激进**: 一次生成很多 candidate, 每个都跑 → token 超 budget, wall 超时
- **LLM 幻觉 candidate**: 选了 recon 没列出的 (vuln_class, target) → executor 找不到
  对应 tool, 跑空, 浪费 token
- **LLM planner 在 chain 上表现好**: 9006/9010 可能因为链式决策有突破, 这是 M3
  的真正价值所在

### M3 完成后产出

`runs/m3_llm_decision/scan_results.json` + `eval_report.md`, 与 M2 的
`runs/m2_dvmcp_full_v2/eval_report.md` 对比。如果 LLM planner 持平或更好, 可以替换
硬编 planner; 如果更差, M3 报告说明 LLM 决策的边界条件, 保留硬编作为 fallback。

---

## 已知坑和注意事项

### 不要重跑 M1/M2 scan 数据

`runs/m2_dvmcp_full_v2/` 里的 10 港 trace 是真跑的, 是 M2 验收的数字来源。改 agent
代码后**不要**直接重跑覆盖这个目录, 否则分不清是"代码变了"还是"LLM 随机性"导致
数字变化。要重跑就写到新目录 `runs/m2_dvmcp_full_v3/` 之类。

### grounding 闸门是 P0 防线, 不能删

`_scan_calls` 不扫 `final_output` 是防幻觉的核心, 不能因为"某某 case 没 fire"就
加回 final_output 兜底。如果 LLM 编的 secret 真的被当 finding, 这就是 P0 漏洞。
测试 `test_hallucinated_secret_in_final_output_does_not_fire` 是回归门, 删它等于
拆了防幻觉。

### judge verdict 不落盘, debug 时看不到

verifier 调 judge 后, judge 返回的 `{steered, evidence_call_index, reason}` 不写进
`AttackTrace` 也不写进 `scan_result.json`。M2 验收时 9006 L2 judge 调了 1083 token
但没追加信号, 我们看不到 judge 说了什么。要 debug, 需要在 verifier 里把 judge
verdict 落盘到 trace.attack_calls 之外的 debug 字段, 或写到 `runs/.../judge_log.json`。

### 9006 的 L1 命中了但 L2 没追加信号

`stored_injection_roundtrip` 在 9006 上 fire (marker `INJECTION_MARKER_8x7k2` 被
`process_document` 回显), 但 L2 judge (1083 tok) 没追加 `llm_judged_injection`。
单条 medium 0.5 < 0.6 → 不成 finding。
**M2 阶段接受这个 miss (9006 是 bonus)**, 但如果 M3 想拿下 9006, 需要:
- 看 judge 实际返回什么 (需要落盘)
- 或加一条 L1 辅助 signal (e.g. 文档回显含 `SYSTEM` / `IGNORE` 等强指示词)

### 9010 的 chain 缺 planner 能力

当前 planner 是单候选遍历, 9010 需要"先用 A 拿到信息, 再用 B 攻击"。M3 的 LLM
planner 如果支持链式决策有可能拿下。M2 阶段放弃 9010。

### MCP SDK 会丢 schema 外的参数

`executor._seed_metadata_probes` 塞的 `__mcpwn_rug_probe__` 之类的 marker arg
会被 MCP SDK 丢弃 (SDK 只传 schema declare 的参数). 所以 `rug_pull_response_flip`
有 fallback 路径 (按 `(name, args)` 归组, 不依赖 marker). 写新的探测逻辑时
记得这点: marker args 不可靠, 用 schema 内的参数构造探测.

### signal_id 的命名约定

`leaks_*` 是泄露类, `command_exec_*` 是行为类 (shell exec), `admin_*` / `unauthenticated_*`
是 auth 类, `tool_description_drift` / `shadow_*` / `rug_pull_*` / `suspicious_error_*` /
`stored_injection_roundtrip` 是 metadata 类, `llm_judged_injection` 是 L2 类。
`expected.yaml` 用 signal_id 列表而不是 class 名做 hit 判定, 所以新增 signal 时
记得在 expected.yaml 加对应 signal_id.

---

## 开工第一步

```bash
# 读这三个文件, 15 分钟
cat HANDOFF.md
cat PROGRESS.md
cat HANDOFF_NEXT.md

# 跑测试和 lint 确认环境 OK
cd McPwn
python -m pytest tests -q
python -m ruff check mcp_redteam eval tests
python -m mcp_redteam.cli lint-cards
```

然后我们一起定 M3 的 4 个设计点, 不要直接动代码。