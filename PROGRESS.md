# McPwn 进度记录

> 每次开工前读这个文件 + HANDOFF.md。如果代码和这里说的不一致，以代码为准。
> 最后更新: 2026-08-05 (commit 8f6bd67 + 315df37 + e5bf87d + 新 rate limit + 模型切 deepseek-v4-pro; M2 v4 验证 8/10 PASS)

## 当前里程碑

**M2 已通过**。真实 10 港跑出来的数字：

| 指标 | 值 | HANDOFF §10 要求 |
|---|---|---|
| recall | 0.80 (8/10) | >= 0.7 |
| FPR | 0.00 | < 0.3 |
| poc_replay_pass_rate | 1.00 (5/5) | 有就行 |
| pytest | 50 passed | |
| ruff | 0 errors | |
| lint-cards | 7/7 ok | |

M2 数据产物: `runs/m2_dvmcp_full_v2/eval_report.md` + 每港 `scan_result.json` + `findings.md` + `poc/*.py`。

## Commit 链

```
8e322f7  Initial McPwn v1 (agent-first) after supplemental review
59abf9c  fix: metadata probe signals + verifier filtering for 5/5 recall, 0% FPR
7cf39bc  feat: poc_replay_pass_rate + eval findings.md + ruff clean
6f7be23  fix: auth_bypass detection for 9007/9009 -> M2 recall 8/10
897df81  feat: hallucination suppression (grounding gate + L2 judge) + M2 verified
8f6bd67  fix: replace DVMCP-shaped _AUTH_GATED_NAMES with description+name heuristic
315df37  fix: retry-with-backoff for LLM transient errors
```

工作树干净 (`git status` 无未提交改动)。

## 10 港逐港命中情况

| port | expected | hit? | findings | confidence | signals |
|---|---|---|---|---|---|
| 9001 | direct_prompt_injection | YES | 1 | 0.97 | leaks_api_key_shape, leaks_hardcoded_password, stored_injection_roundtrip |
| 9002 | command_injection | YES | 1 | 0.75 | command_exec_uid_stdout |
| 9003 | path_traversal | YES | 1 | 0.95 | leaks_etc_passwd |
| 9004 | tool_metadata_probe | YES | 1 | 0.75 | rug_pull_response_flip, suspicious_error_pitch |
| 9005 | tool_metadata_probe | YES | 1 | 0.75 | shadow_tool_pair, shadow_tool_behavior_divergence |
| 9006 | indirect_injection | no | 0 | - | L1 stored_injection_roundtrip 命中(0.5), L2 judge 被调(1083 tok)但没追加信号 |
| 9007 | auth_bypass | YES | 2 | 0.75 | unauthenticated_success (authenticate + verify_token 各一条) |
| 9008 | command_injection | YES | 1 | 0.99 | leaks_etc_passwd, command_exec_uid_stdout |
| 9009 | auth_bypass | YES | 3 | 0.75-0.94 | unauthenticated_success, admin_action_confirmed |
| 9010 | chain_composition | no | 0 | - | L2 judge 被调(1581 tok), 无 L1 锚定 |

9006 和 9010 是 HANDOFF §8 标的 bonus, 不阻塞 M2。

## 已落地的架构决策 (按重要性排序)

### 1. Grounding 闸门 (detectors.py)
`_scan_calls` 删掉了 `final_output` 兜底分支。leak/行为 signal 只从 `call_tool`/`read_resource` 的 `result_text` 命中, 不扫 LLM 自己写的 final answer。防止 LLM 在收敛轮编造 secret 产生假阳性。每条 fired signal 必带非空 `source_call_index`。

### 2. 窄 L2 Judge (verifier.py)
verifier 对 `INDIRECT_INJECTION` 和 `CHAIN_COMPOSITION` trace 调 judge LLM (role="judge")。judge 输入 = 真实 `attack_calls.result_text` (截断) + `final_llm_output` + 任务描述。输出 `{steered, evidence_call_index, reason}`。命中时 verifier 合成 `llm_judged_injection` (medium) 信号。**L2 单独 (0.5) 不过 0.6 阈值**, 必须和确定性 L1 信号 (如 `stored_injection_roundtrip`) 同 trace 共现才成 finding。judge token 走 `budget.add("judge", ...)`, 独立计数。`detect_llm_judged_injection` 保持纯函数占位, 不进 `DETECTORS`。

### 3. verifier 过滤 (verifier.py)
`TOOL_METADATA_PROBE` trace 只接受 metadata 类 signal (`tool_description_drift` / `shadow_tool_pair` / `shadow_tool_behavior_divergence` / `rug_pull_response_flip` / `suspicious_error_pitch` / `stored_injection_roundtrip`), 滤掉 leak/行为类。原因: executor 主动探测会调到有漏洞的 tool, leak signal 会命中但证据属于该 tool 自己的 vuln_class, 不属于 metadata probing。

### 4. auth detector 第二遍 pass (detectors.py)
`detect_unauthenticated_success` 原版只检查空/伪造 token。新增第二遍: 如果 tool 名字匹配 `_AUTH_GATED_NAMES` (`remote_access`/`verify_token`/`admin`/`manage` 等) 且整个 trace 里没有成功的 `authenticate` 调用 (`prior_auth_ok=False`), 且响应含 success phrase (含 `"appears to be valid"`, `"command executed"`, `"executed on"` 等), 就 fire。这覆盖了"伪造非空 token 被接受"和"optional auth 参数被省略但 tool 仍执行"两个场景。

### 5. recon score 调整 (recon.py)
`AUTH_BYPASS` 启发式 score 从 0.75 提到 0.95, 高于 `COMMAND_INJECTION` 的 0.9。这让 `remote_access`/`verify_token` 类 tool 优先走 auth_bypass 策略卡而不是 command_injection。

### 6. executor 主动探测 (executor.py)
`_seed_metadata_probes` 在 LLM 循环开始前, 对 `TOOL_METADATA_PROBE` 候选主动调:
- shadow tool 对: 同 args 调两个近名 tool 各一次
- 单 tool: 同 args 调 4 次 (rug pull 检测)
- refresh `list_tools` (drift 检测)

探测结果塞进 `attack_calls`, 让行为类 signal 有数据可用。

### 7. 收敛轮提示词改写 (executor.py + attacker_system.md)
收敛轮不再要求 LLM "逐字引用可疑串" (诱导幻觉), 改为"一句话总结探了什么、证据落在哪条 call"。

### 8. LLM 调用 retry-with-backoff (chat.py + executor.py)
`chat_create_with_retry` 包装 `client.chat.completions.create`, 重试 5 次 (RateLimitError / APITimeoutError / APIConnectionError / InternalServerError), 退避 1/2/4/8/16s。BadRequestError 等 4xx 代码 bug 不重试。背景: M2 v3 重跑 (runs/m2_dvmcp_full_v3/) 发现 9008/9009 在 step 0 拿到 429 (ARK glm-5-2 触发 set inference limit) 后 executor 立刻 break, 整 trace 0 attack_calls → 0 findings → port miss。retry 让短暂限流在同一 trace 内清掉, 而不是把 port 拖到 0 finding。Wall-time budget 不在 retry helper 内查, 由 executor 每轮的 clock check 兜底; token budget 不受影响 (失败 attempt 不计费)。

## 信号库 (15 条, 14 条注册 + 1 条占位)

| signal_id | severity | 类别 | 说明 |
|---|---|---|---|
| leaks_etc_passwd | critical | A-leak | `/etc/passwd` 起始行 |
| leaks_shadow_hash | critical | A-leak | `$6$` 等 hash |
| leaks_ssh_private_key | critical | A-leak | PEM 私钥头 |
| leaks_api_key_shape | high | A-leak | sk-/AKIA/AIza 格式 |
| leaks_hardcoded_password | high | A-leak | password:=xxx (>=8 字符) |
| command_exec_uid_stdout | high | B-behavior | uid=N gid=N |
| command_exec_ls_root | medium | B-behavior | ls 输出 + shell metachar |
| admin_action_confirmed | high | B-behavior | admin action executed/granted |
| unauthenticated_success | high | B-behavior | 空/伪造 token + success (含 prior_auth_ok 第二遍) |
| tool_description_drift | medium | C-metadata | 两次 list_tools 描述不一致 |
| shadow_tool_pair | medium | C-metadata | lev<=2 AND jaccard>0.7 |
| shadow_tool_behavior_divergence | medium | C-metadata | 同名 shadow tool 返回体差异 |
| rug_pull_response_flip | medium | C-metadata | 同 tool 同 args 多次调用后响应突变 |
| suspicious_error_pitch | medium | C-metadata | error 响应含 upsell/admin 语言 |
| stored_injection_roundtrip | medium | C-metadata | canary marker 在 tool result 里回显 |
| llm_judged_injection | medium | D-llm | **占位**, verifier 合成, 不进 DETECTORS |

confidence 公式: `1 - prod(1 - w_i)` (去重后), critical=0.95, high=0.75, medium=0.5。阈值 >= 0.6 才进 findings.md。

## 未完成 / 下一步

### M2 v4 验证 (PASS)
M2 v4 (`runs/m2_dvmcp_full_v4/`, 8/10) 验证完成。attacker 临时从 paused 的 `glm-5-2-260617` 切到 `deepseek-v4-pro-260425` (账号下唯一 active 非-paused LLM; 1s/次)。加 chat-layer rate limit (2s/call, env `MCPWN_LLM_MIN_INTERVAL_SEC` 可调) 防再撞墙。跑完 10 分 7 秒。

**结论: auth-gated fix (8f6bd67) 是 model-agnostic**, 在 glm-5-2 跟 deepseek-v4-pro 两个不同 model 上保持 8/10 recall / 0.00 FPR / 1.00 poc_replay。9006 (indirect) 跟 9010 (chain) 仍 miss, 是 HANDOFF 标的 bonus, 没拆。

### #4 cross-server FPR baseline (v2 PARTIAL)
`runs/clean_baseline_v2/` 跑了, 总 FPR=0.00 但有 1 个 variant server 挂 (summarize), 实际是 1 PASS + 1 INCONCLUSIVE + 1 PROBABLE PASS。

| variant | attack_calls | stop_reason | 评估 |
|---|---|---|---|
| 9101 noop | 17 | completed | PASS (description-regex 不被空 desc 骗) |
| 9102 summarize | 11 | error (peer closed) | INCONCLUSIVE (server 中途断) |
| 9103 file_list | 32 | budget_tokens | PROBABLE PASS (32 次都没触发 path-traversal) |

9102 那个 RemoteProtocolError 是 server 端 bug: FastMCP 2.0 `MCPServer.run_sse_async` 在 SSE 客户端异常断时没正确清理, 子进程挂了。要 strong cross-server FPR 数字, 修 server 的 graceful shutdown, 然后 `clean_baseline_v3` 重跑。

### M3 (LLM 决策版 planner)
把 `agent/planner.py` 的 `plan()` 从硬编 score 排序改成 LLM 决策。输入 recon 结果 (tool 列表 + resource 列表 + 描述), 输出 next-action (vuln_class, target)。和硬编版 M2 对比 recall / FPR / avg_findings_per_port。不改 recon -> executor -> verifier -> report 闭环。

### 9006 (indirect_injection) L2 judge 调参
L1 `stored_injection_roundtrip` 已命中 (marker `INJECTION_MARKER_8x7k2` 被 `process_document` 回显), 但 L2 judge (1083 tok) 没追加 `llm_judged_injection` 信号。单条 medium 0.5 < 0.6。需要: (a) 看 judge 实际返回了什么 (当前 judge verdict 不落盘), (b) 调 judge prompt 或放宽判定标准, (c) 或加一条 L1 辅助信号。

### 9010 (chain_composition) chain planner
当前 planner 是单候选遍历, 没有"前一步结果喂给下一步"的机制。需要 multi-step chain planner (M3 范畴)。

### poc_replay_pass_rate 已实装
`eval/dvmcp/runner.py._replay_poc` 重连 MCP, 重放 `poc_call_sequence`, 重跑 signals, 看 signal_id 是否重现。M2 实跑 5/5 = 1.00。

### 其他待清理项
- `eval dvmcp run` 不支持 `--max-candidates` / `--max-inner-steps` 透传 (CODE_REVIEW 未提但实际跑时默认 20/12 够用)
- judge verdict 不落盘到 trace (debug 时看不到 judge 说了什么)
- `connect_timeout` 参数在 `McpSession` 里定义了但没用上 (CODE_REVIEW P3)

## 目录结构 (v1, agent-first)

```
mcp_redteam/
  contracts.py          数据契约 (VulnClass/McpCall/EvidenceSignal/AttackTrace/Finding/ScanResult)
  cli.py                mcpwn scan <url> / ping-models / lint-cards / eval dvmcp
  signals/
    detectors.py        15 条 signal detector (14 注册 + 1 占位)
  vulns/
    cards/*.md          7 张策略卡
    registry.py         load_card + lint
  agent/
    recon.py            list tools/resources + classify + candidate
    planner.py          按 score 排序 (M3 换 LLM)
    executor.py         openai function-calling 循环 + 主动探测
    verifier.py         signals + confidence + L2 judge + finding 过滤
  orchestrator/
    runner.py           scan() 顶级驱动
    budget.py           三闸门 (turns/tokens/wall)
    reset_hook.py       DVMCP 状态清理 (find -mindepth 1 -delete)
  targets/
    mcp_client.py       MCP SDK 薄封装 (raw_list_tools/resources)
  models/
    chat.py             OpenAI-compat 工厂
  victims/
    agents/tool_schema_builder.py  MCP tools -> openai tools schema
  adapters/
    base.py             PyRIT Protocol 镜像 (不装 PyRIT)
  attackers/agents/
    attacker_system.md  通用红队 agent 人格 (jinja2)
  report/
    findings.py         ScanResult -> findings.md + poc/*.py
eval/dvmcp/
  expected.yaml         10 港预期 vuln class
  runner.py             全港扫描 + recall/FPR/replay 指标
```