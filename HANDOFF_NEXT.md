# McPwn → Next Session Handoff

> 读这个文件 + `HANDOFF.md` + `PROGRESS.md` 就能接上。`PROGRESS.md` 是状态
> 快照 (数字 + commit 链), `HANDOFF.md` 是项目设计文档, 本文件是
> "下一 session 开工前要知道的"。

最后更新: 2026-08-05 (commits 8f6bd67, 315df37, e5bf87d, 41704e1, 97887db, 9d2b5cd)

---

## TL;DR

McPwn 是 MCP 红队 agent: 给一个陌生 MCP server 的 SSE 端点, 自主完成
recon → hypothesis → attack → verify → report, 产出 `findings.md` +
可重放 PoC。DVMCP (Damn Vulnerable MCP Server) 是 fixture, 不是评测目标。

**M2 v4 验证通过 (8/10, FPR=0, replay=5/5), auth-gated fix 跨 model 复用
确认。** attacker 临时从被 ARK paused 的 `glm-5-2-260617` 切到
`deepseek-v4-pro-260425` (账号下唯一可用的 active LLM)。**M2 v3 6/10
跟 v4 8/10 的差异是 ARK set inference limit, 不是代码回归**——加了
chat-layer rate limit (commit 41704e1) 防止再撞墙。

**下一里程碑是 M3 (LLM 决策版 planner)**, HANDOFF §3 标的。但 M3 战略
问题没定: "换决策方式 (LLM 选 next candidate)" 还是 "加新能力 (LLM
提议新 signal)"。

---

## 关键设计决策 (不要再讨论)

### 1. 信号 + 证据 = 真相, 假设 = hint
Hit 判定: `finding.signal_ids ∩ expected_signals ≠ ∅`, 跟
`vuln_class` 解耦。`expected.yaml` 每港有 `expected_signals` 列表
(不是 `also_accept`)。HANDOFF §6 的 12 条信号规格**先于** detector
实现冻结 (HANDOFF 阶段), `expected.yaml` 之后写。

### 2. Grounding 闸门 (防 LLM 幻觉)
`_scan_calls` 不扫 `final_output`, leak/行为 signal 只从真实
`McpCall.result_text` 命中。每条 fired signal 必带非空
`source_call_index`。`test_hallucinated_secret_in_final_output_does_not_fire`
是回归门。

### 3. 窄 L2 judge (indirect/chain only)
`verifier` 对 `INDIRECT_INJECTION` / `CHAIN_COMPOSITION` trace 调
judge LLM (role="judge")。judge 输入 = 真实 `attack_calls.result_text` +
`final_llm_output` + 任务描述。`llm_judged_injection` (medium) 单条
不过 0.6 阈值, 必须与确定性 L1 (`stored_injection_roundtrip` /
`tool_description_drift`) 同 trace 共现才成 finding。judge token 走
`budget.add("judge", ...)`, 独立计数不挤 attacker。

### 4. metadata probing 主动探测 (executor)
`executor._seed_metadata_probes` 在 LLM 循环开始**之前**对
`TOOL_METADATA_PROBE` 候选主动调: shadow tool 对同 args 各一次 /
单 tool 4 次 rug pull / refresh `list_tools`。**这层探测不需要 LLM**,
所以 429 / paused 也不影响 (M2 v3 / v4 9004/9005 的 hit 都是这条路径
贡献的)。MCP SDK 会吞 schema 外的 marker args, 所以
`rug_pull_response_flip` 有不依赖 marker 的 fallback 分组。

### 5. auth detector 两遍 pass (9007/9009 关键)
`detect_unauthenticated_success` 第二遍不再 hardcode
`(remote_access|admin|manage|verify_token|authenticate|grant_role)` —
那是 DVMCP-shaped 的, 真实 MCP server 的 `check_permission` /
`require_auth` / `is_authorized` 不会 fire。新逻辑 (8f6bd67):
- `_AUTH_DESC_RE` (主): tool description 含 auth/permission/token/
  role/admin/credential 等关键词
- `_AUTH_NAME_RE` (兜底): tool name 含 `auth\w*` / `verify_?token` /
  `credential\w*` / `permission\w*` / `grant_?role` / `admin\w*`
- `_is_auth_gated_tool()` helper 合并两路

`prior_auth_ok` **故意不动** (还是 hardcode `"authenticate"`), 注释
解释: "session 概念, 改宽会抑制后续真漏洞报出" (a forged
`verify_token` 自身是 vuln, 1st pass 已 fire, 但不构成 session,
不应阻止后续 auth-gated tool call 的 report)。

### 6. verifier 过滤 (FPR 的关键)
`TOOL_METADATA_PROBE` trace 只接受 metadata 类 signal
(drift/shadow/rug_pull/suspicious_error/stored_injection), 滤掉
leak/行为类。原因: 主动探测会调到有漏洞的 tool (e.g. 9001
`get_user_info`, 9003 `file_manager`), leak signal 会命中但证据属于
该 tool 自己的 vuln_class, 不属于 metadata probing。

### 7. Hard-coded tool gating 在 vuln_class 决策上是不可信的
`recon.AUTH_BYPASS` score 从 0.75 提到 0.95, 高于
`COMMAND_INJECTION` 的 0.9。让 `remote_access` / `verify_token` 优先
走 auth_bypass 策略卡。M3 的 LLM planner 应该比这更聪明。

### 8. retry-with-backoff (chat layer)
`chat_create_with_retry` 包装 `client.chat.completions.create`:
- 重试 5 次 (RateLimitError / APITimeoutError / APIConnectionError /
  InternalServerError)
- 退避 1, 2, 4, 8, 16s
- 4xx (BadRequestError 等代码 bug) 不重试
- 耗尽后最后一个异常原样 raise (executor 现有 except Exception
  仍能 fire)

动机: M2 v3 / v4 第一次都 429, executor 一 break 就 0 attack_calls。
retry 配合 rate limit 一起, retry 兜 transient, rate limit 兜
sustained。

### 9. chat-layer rate limit (新增, 41704e1)
`_MIN_INTERVAL_SEC` (默认 2.0s, `MCPWN_LLM_MIN_INTERVAL_SEC` env
覆盖) + `_last_call_monotonic` + `threading.Lock`。
`_rate_limit_wait()` 在 `chat_create_with_retry` 每次 attempt 之前
强制 sleep 到距上次 ≥ N 秒。thread-safe 让 sync client 也能被 async
executor 串行化。

ARK `glm-5-2` 的 "set inference limit" 是**平台硬墙**, retry
(抖动的) 救不了, rate limit (sustained) 也救不了——只能换 model
或解锁。**两个机制是配合关系, 不是替代关系**。

### 10. eval 信号判据 = signal ∩ expected, 不是 class
`eval/dvmcp/runner.py` 第 99 行起的 hit 判定:
`{s.signal_id for s in f.signals} & expected_sigs`。`primary_class`
只作人类阅读用。`expected_signals` 是 ground truth, HANDOFF §6 阶段
冻结, 不是 detector 反推。改 `expected.yaml` 必须 commit message 带
reason, 否则视为自评污染。

---

## 当前状态 (数字)

### M2 v4 (commit 9d2b5cd, deepseek-v4-pro)

| 指标 | v2 baseline (glm-5-2) | v4 (deepseek-v4-pro) | 一致? |
|---|---|---|---|
| recall | 0.80 (8/10) | 0.80 (8/10) | ✓ |
| FPR | 0.00 | 0.00 | ✓ |
| avg_findings_per_port | 1.0 | 1.0 | ✓ |
| poc_replay | 1.00 (5/5) | 1.00 (5/5) | ✓ |

Per-port 9 hit 港 (9001-9005, 9007-9009), 2 miss (9006 indirect,
9010 chain — HANDOFF §8 标的 bonus, 不阻塞 M2)。

**结论**: 8f6bd67 的 auth-gated fix **model-agnostic**。在两个不同
LLM 上保持 8/10 recall + 0.00 FPR + 1.00 poc_replay。

### clean_baseline v2 (9d2b5cd)

| variant | attack_calls | stop_reason | 评估 |
|---|---|---|---|
| 9101 noop | 17 | completed | **PASS** |
| 9102 summarize | 11 | error (peer closed) | **INCONCLUSIVE** |
| 9103 file_list | 32 | budget_tokens | **PROBABLE PASS** |

总 FPR=0.00 但 verdict = **PARTIAL**。9102 的 RemoteProtocolError 是
`eval/clean_baseline/servers/` FastMCP 子进程 graceful shutdown bug,
不是 agent/detector 问题。**修这个**才能拿强 cross-server FPR 证明
(见 "M3 / 后续" 节)。

### 全量验证

- 72/72 pytest pass (含 5 条新 `test_chat_retry.py` rate limit + 1 条
  `tests/test_clean_baseline_servers.py` variant registry)
- ruff check mcp_redteam eval: 0 errors
- ruff check tests: 6 pre-existing errors in user-authored files
  (`tests/fixtures/mock_mcp.py`, `tests/test_regression_baseline.py`,
  `tests/test_scan_metadata.py`) — out of scope, do not touch

---

## Commit 链 (main → codex/b-c-ci, 13 个)

```code
9d2b5cd  docs: record M2 v4 8/10 PASS + clean_baseline v2 PARTIAL results
97887db  chore: swap attacker model glm-5-2-260617 -> deepseek-v4-pro-260425
41704e1  fix: chat-layer rate limit + async subprocess.wait
e5bf87d  feat: cross-server FPR baseline (eval/clean_baseline/)
d1417bf  feat(B+C+CI): scan reproducibility + offline regression baseline + GitHub Actions   <-- user
315df37  fix: retry-with-backoff for LLM transient errors
8f6bd67  fix: replace DVMCP-shaped _AUTH_GATED_NAMES with description+name heuristic
1808e51  docs: add HANDOFF_NEXT.md for new-session review
83b5146  feat: signal-based eval + evidence_class (honest vulnerability discovery)
342aef4  docs: add PROGRESS.md to prevent context drift across sessions
897df81  feat: hallucination suppression (grounding gate + L2 judge) + M2 verified
6f7be23  fix: auth_bypass detection for 9007/9009 -> M2 recall 8/10
7cf39bc  feat: poc_replay_pass_rate + eval findings.md + ruff clean (0 errors)
```

工作树干净 (`git status` 无未提交改动)。

---

## 目录地图 (核心文件)

```
HANDOFF.md                      项目设计文档 (读这个)
PROGRESS.md                     状态快照 (数字 + commit 链)
HANDOFF_NEXT.md                 本文件, 跨 session 上下文

mcp_redteam/
  contracts.py                  VulnClass / McpCall / EvidenceSignal / AttackTrace /
                                Finding / ScanResult (含 finding.hypothesis_class
                                + evidence_class 双字段)
  cli.py                        mcpwn scan <url> / ping-models / lint-cards /
                                eval dvmcp. 顶部 load_dotenv().

  signals/detectors.py          15 条 signal detector (14 注册 + llm_judged_injection
                                占位). _scan_calls 不扫 final_output (grounding 闸门).
                                _AUTH_DESC_RE / _AUTH_NAME_RE 描述 + 名称启发 (8f6bd67).
                                commit 41704e1 之前.
  vulns/cards/*.md              7 张策略卡 (通用红队启发, 无 challenge 明文答案).
  vulns/registry.py             load_card + lint (禁 secret 明文 + 禁 challenge 名).

  agent/
    recon.py                    list tools/resources + classify by name/description
                                regex. AUTH_BYPASS score=0.95, COMMAND_INJECTION=0.9.
    planner.py                  按 score 排序遍历. **M3 改这里**.
    executor.py                 openai function-calling 循环 + _seed_metadata_probes.
                                chat_create_with_retry 包装 (commit 41704e1).
    verifier.py                 signals + confidence + L2 judge (indirect/chain only) +
                                evidence_class 推断 + TOOL_METADATA_PROBE 过滤.

  orchestrator/
    runner.py                   scan() 顶级驱动. SeriaPortBudget + WallClock 跨 trace 共享.
    budget.py                   三闸门 (turns / tokens / wall). judge token 独立.

  targets/mcp_client.py         MCP SDK 薄封装 (raw_list_tools/resources).
  models/chat.py                OpenAI-compat 工厂 + chat_create_with_retry +
                                _rate_limit_wait (MCPWN_LLM_MIN_INTERVAL_SEC env).
  config/models.yaml            attacker=deepseek-v4-pro-260425 (临时, 见 commit 97887db).
                                judge=deepseek-v4-flash.

  adapters/base.py              PyRIT Protocol 镜像 (不装 PyRIT).
  attackers/agents/
    attacker_system.md          通用红队 agent 人格 (jinja2).

  report/findings.py            ScanResult → findings.md + poc/*.py.
                                evidence_class 仅在 ≠ vuln_class 时显示.

eval/dvmcp/
  expected.yaml                 10 港预期 (port + name + primary_class +
                                expected_signals + evidence_hint).
  runner.py                     全港扫描 + signal-based recall/FPR/replay 指标.
  AGENTS.md                     5 字段本地契约 (5-field, signal-based, FPR 局限).

eval/clean_baseline/            (本 session 新增, e5bf87d)
  AGENTS.md                     5 字段, 标清楚是测 cross-server FPR (不是
                                cross-vuln-class).
  servers/__init__.py           3 个 FastMCP variant (mcp 2.0 MCPServer):
                                noop (空 desc) / summarize (prompt-like desc) /
                                file_list (路径形 arg, server 端 hard cap).
  servers/__main__.py           薄 entry point (python -m).
  runner.py                     启 server 子进程 + poll 端口 + scan + 收.
                                asyncio.create_subprocess_exec.
                                load_dotenv 跟 cli.py 对齐.

tests/
  test_chat_retry.py            5 条: 重试成功 / 4 transient 类 / BadRequest 不重试 /
                                耗尽 raise / backoff 序列 (41704e1 + rate limit mock).
  test_clean_baseline_servers.py 5 条: 3 variant registry + public file 严格性 +
                                build_app rejects unknown.
  test_behavioral.py            34 条 (uid / ls / admin_action / unauthenticated).
  test_leaks.py                 leak detectors.
  test_metadata_behavior_signals.py  metadata signals.
  test_drift_uses_combined_calls.py  drift detector contract.
  test_ground_truth_credentials.py   ground truth credentials.
  test_signal_meta_matches_detectors.py  meta <-> detectors <-> fire 三者一致.
  test_recon.py, test_vulns_registry.py, test_verifier_minimal_poc.py,
  test_l2_judge.py              misc.
  fixtures/mock_mcp.py          (user) 71/72 + 5+5 = 132 tests
  test_regression_baseline.py   (user) 共存
  test_scan_metadata.py         (user)
```

---

## M3 任务: LLM 决策版 planner (战略问题没定)

HANDOFF §3 把 planner 画成 "select next (vuln_class, target)" 决策核心。
M2 用硬编 score 排序遍历, M3 换成 LLM 决策。

### 战略问题 (开工前要决定)

**M3 目标是什么?**
- (a) "LLM 选 next candidate 持平或更好" — 战术, 几乎一定等价于硬编。
  7 类信号 × ~15 DVMCP tool 的组合空间里, 硬编 score 排序已饱和。
  LLM planner 学的就是 score 排序的近似。**劝别做, ROI 负。**
- (b) "LLM 提议新 signal" — 能力, 需要重新设计 verifier (新 signal
  入库 + 单独 0.6 阈值). 战略价值高, 工程量大。
- (c) "LLM 跨 trace 推理" — 能力, 把 trace 历史喂给 LLM, 让 LLM 在多步
  证据上做因果推理 (对 9010 chain 拿下有意义). 战略价值高, 工程量中。

**(a) 劝不做。(b)(c) 是真工作, 但工程量完全不一样。**

### 战术问题 (无论选哪个战略都要决定)

1. LLM planner 输入: 喂啥? (recon 结果 / 上一步执行结果 / LLM 自由
   生成 candidate)
2. LLM planner 输出: 单步 `(vuln_class, target, reason)` / 多步
   计划 / 自由文本指令
3. 怎么对比 LLM vs 硬编: 同样 30000 token / 240s wall budget, 报
   recall / FPR / avg_findings / poc_replay, 加 trace diff
4. Token 成本: 每决策一次 LLM 调用, 10 港 × 多候选 = 涨一量级.
   要不要给 LLM planner 单独 budget 闸门, 还是算在 attacker 里?

### 失败模式预设

- LLM 太保守: 倾向选"安全"那几类, 跳过 rug_pull/shadow → recall 掉
- LLM 太激进: 一次生成很多 candidate, 每个都跑 → budget 超时
- LLM 幻觉 candidate: 选了 recon 没列出的 → executor 找不到, 跑空
- **最可能**: LLM planner 与硬编 planner **完全等价**。如果等价,
  M3 ROI 负, 别做

### 完成后产出

`runs/m3_llm_decision/scan_results.json` + `eval_report.md`, 跟
`runs/m2_dvmcp_full_v4/eval_report.md` 对比。

---

## 已知坑和注意事项

### 9102 server graceful shutdown bug (clean_baseline)
`eval/clean_baseline/servers/__init__.py` FastMCP `MCPServer.run_sse_async`
在 SSE 客户端断开时, 子进程没正确清理, 报 `RemoteProtocolError: peer
closed connection without sending complete message body`。`runs/clean_baseline_v2/`
summarize variant 跑 11 calls 后挂, 整 trace stop_reason=error, 0 findings
可能是"agent 还没动手就崩"而不是"agent 探了没找到"。

**修法** (未做, 跟 v4 数字验证无关): 在 `sse.connect_sse` 之外包一层
try/except, 捕获 `RemoteProtocolError` 优雅退出。或者显式调用
`server.shutdown()` 在 finally 块。

### model.yaml 是临时切
`mcp_redteam/config/models.yaml` 现在 attacker.model =
`deepseek-v4-pro-260425` (commit 97887db)。ARK `glm-5-2-260617` 被
"set inference limit" 锁了, 需在 ARK 控制台 Model Activation 页手动
关 Safe Experience Mode 才解锁。**glm-5-2 解锁后**:
1. 把 model 切回 `glm-5-2-260617`
2. 跑 `runs/m2_dvmcp_full_v5/` 验证 v2 → v5 在两个 model 间一致
3. commit, 删 commit 97887db 的"临时" 注释

### judge LLM 是 deepseek-v4-flash (未切过, 一直 OK)
`config/models.yaml` judge role 用 `deepseek-v4-flash`, 一直没换过。
attacker 切到 deepseek-v4-pro 之后, judge 跟 attacker 走同一 ARK key
但不同 endpoint, 都活。

### evaluator LLM rate limit
即使有 rate limit (commit 41704e1), 长期跑 (e.g. M3 LLM planner)
仍可能撞墙, 因为 rate limit 只防 sustained, 不防 absolute cap。
**对策**: LLM planner 自身也要有 budget, 写明在 M3 任务里。

### MCP SDK 会丢 schema 外的参数
`executor._seed_metadata_probes` 塞的 `__mcpwn_rug_probe__` 等 marker
arg 会被 MCP SDK 丢弃 (SDK 只传 schema declare 的参数). 所以
`rug_pull_response_flip` 有不依赖 marker 的 fallback 分组 (按
`(name, args)` 归组). 写新探测逻辑时记得: **marker args 不可靠,
用 schema 内的参数构造探测**。

### signal_id 命名约定
`leaks_*` 泄露类, `command_exec_*` 行为类 (shell exec), `admin_*` /
`unauthenticated_*` auth 类, `tool_description_drift` / `shadow_*` /
`rug_pull_*` / `suspicious_error_*` / `stored_injection_roundtrip`
metadata 类, `llm_judged_injection` L2 类。`expected.yaml` 用
signal_id 列表, 新增 signal 时**必须**在 `expected.yaml` 加对应
signal_id (否则 DVMCP recall 会掉)。

### 9006 / 9010 仍是 bonus
HANDOFF §8 标这两个是 bonus: 9006 (indirect) 需要 L2 judge 调参, 9010
(chain) 需要 multi-step planner — 都在 M3 范畴。**M3 不一定拿下**,
但 M3 至少要解释为什么不拿 + 怎么拿。

### M2 v3 6/10 (vs v2 8/10) 不是代码回归
- v3 miss 的 9008/9009 是 ARK glm-5-2 在 2026-07-31 触 set inference
  limit, executor 在 step 0 拿到 429 立刻 break, 0 attack_calls
- v4 用 deepseek-v4-pro 重跑, 8/10 跟 v2 一致
- 这说明 v3 的 6/10 是 LLM availability 问题, 不是 auth-gated fix
  的回归。**别把 v3 数字当 evidence**。

### 9001 ground truth 里 marker 出现
DVMCP 9001 `notes://` 资源读出来含 canary `INJECTION_MARKER_8x7k2`。
`stored_injection_roundtrip` signal 在 9001 fire 是预期。读 9001
trace 时不要把它当 false positive。

### expected.yaml 改之前先冻结
`expected_signals` 顺序: HANDOFF §6 冻结 12 条信号规格 →
`signals/detectors.py` 实现 → `expected.yaml` 标注。改 expected.yaml
必须有可追溯理由 (git commit message 必带 reason), 否则视为自评污染。
**别做"看了 detector 之后写 expected" 的循环**。

---

## 开工第一步

```bash
# 1. 读这三个文件, 15 分钟
cat HANDOFF.md
cat PROGRESS.md
cat HANDOFF_NEXT.md     # 本文件

# 2. 跑测试和 lint 确认环境 OK
cd McPwn
python -m pytest tests -q
python -m ruff check mcp_redteam eval
python -m mcp_redteam.cli lint-cards

# 3. 检查 DVMCP 状态 (应该在跑)
docker ps | grep dvmcp

# 4. 确认 attacker model (现在 deepseek-v4-pro, 看 models.yaml)
cat mcp_redteam/config/models.yaml

# 5. 决定 M3 战略 (a/b/c) 之后开工
#    - 选 (a): 劝别做
#    - 选 (b): 设计 LLM signal proposer, 改 verifier
#    - 选 (c): 设计 multi-step trace-aware planner, 改 executor
#    战略定了再碰代码
```

不要直接动代码。先答 M3 战略问题。
