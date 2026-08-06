# McPwn -> Next Session: M3 LLM Planner 已实现（待真实 eval 验收）

> 读这个文件 + `HANDOFF_M3.md` + `HANDOFF_M3_PLANNER.md`（契约权威）+ `HANDOFF_JUDGE.md`。
> 本文件回答：M3 planner 实现了什么、真实 eval 验收结果、第一次 fail 的根因与修复。
> 来源：会话因 Codex remote-compaction 崩溃中断，改动以 checkpoint commit `4fbb69b` 落盘，本文档事后补写。

最后更新: 2026-08-06（分支 codex/b-c-ci；M3 验收 verdict=pass，judge 产物 runs/m3_final/judge/）

---

## TL;DR

M3 唯一缺口（LLM planner + `planner_decisions.json` 产出 + 9010 chain 真实证据）**已全部实现**：

1. `agent/planner.py` 硬编排序之上新增 `plan_llm()`，真实调用 attacker LLM 出完整有序计划，失败整条降级为 fallback。
2. `agent/executor.py` 新增 `_seed_chain_probe()`，对 `chain_composition` 候选做确定性两步组合（泄漏原语 -> 消费方复用返回片段），产出真实组合证据。
3. `orchestrator/runner.py::scan` 串联：llm 模式调 `plan_llm`，全程记录 `PlannerDecision`（含 planned-but-unexecuted）。
4. `eval/dvmcp/runner.py` llm 模式写出 `<llm_dir>/planner_decisions.json`。
5. CLI `mcpwn eval dvmcp run` 新增 `--planner {hardcoded,llm}`。
6. 契约 `PlannerDecision` 入 `contracts.py`（pydantic extra=forbid，字段与 HANDOFF_M3 section 2 逐字一致）。
7. prompt 外置 `mcp_redteam/attackers/agents/planner_system.md`（jinja2），`chain_composition.md` 卡片改写为两步组合打法。

**验证（本地实跑）**：`pytest tests/test_planner_llm.py tests/test_chain_seeding.py tests/test_m3_judge.py tests/test_m3_criteria.py tests/test_judge_m3_cli.py` -> **67 passed**；`ruff check` 改动文件 -> **0**。

**M3 已通过**：当前代码重跑全量 baseline+llm A/B（同代码同预算 45k/港）后 `judge-m3` verdict=`pass`，五判据全过（见 §4）。产物在 `runs/m3_final/`。

---

## 1. 现状（事实，以代码为准）

| 项 | 状态 | 位置 |
|---|---|---|
| `PlannerDecision` 契约 | 已完成，`extra=forbid`，字段逐字对齐 HANDOFF_M3 | `mcp_redteam/contracts.py` |
| LLM planner `plan_llm` | 已完成（完整覆盖校验 + 幻觉丢弃 + 整条 fallback） | `mcp_redteam/agent/planner.py::plan_llm` |
| 硬编 `plan()` fallback | 保留，`_fallback_plan` 不截断以覆盖完整计划 | `mcp_redteam/agent/planner.py` |
| planner system prompt 外置 | jinja2 Template 加载 | `mcp_redteam/attackers/agents/planner_system.md` |
| chain 确定性播种 | `_seed_chain_probe` 两步组合（leak -> consume） | `mcp_redteam/agent/executor.py` |
| chain 卡片重写 | 两步组合打法，强调 later args 复用 prior result | `mcp_redteam/vulns/cards/chain_composition.md` |
| `scan()` 串联 planner + decisions | llm 模式调 `plan_llm`，记录每个 executed/skipped decision | `mcp_redteam/orchestrator/runner.py::scan` |
| `planner_decisions.json` 写出 | llm 模式写 llm 输出目录根 | `eval/dvmcp/runner.py::write_planner_decisions` |
| CLI `--planner` | `hardcoded`（默认）/`llm` | `mcp_redteam/cli.py::dvmcp_run` |
| recon 正则微调 | `config(?:uration)?` 归入 path_traversal 文件读取面 | `mcp_redteam/agent/recon.py` |
| 测试 | 12 planner_llm + 5 chain_seeding，全过 | `tests/test_planner_llm.py` / `tests/test_chain_seeding.py` |

---

## 2. 实现要点（给接手者）

### 2.1 `plan_llm` 的容错与 fallback 语义（锁死，别改）

- LLM 必须返回 `{"plan": [{"vuln_class","target","reason"}, ...]}`，且是输入候选的**一个排列**（每个候选恰好一次，无发明项）。
- 校验通过 -> 每项 `source="llm"`。
- 以下任一成立 -> **整条计划**降级为 `_fallback_plan`，每项 `source="fallback"`（单条计划要么全 llm 要么全 fallback，不混合）：
  - LLM 调用抛异常（429/超时已由 `chat_create_with_retry` 重试过）；
  - 返回非 JSON / 非 `{"plan": list}`；
  - 计划漏掉任一候选（`len(used) != len(candidates)`）；
  - 计划含发明/重复项 -> 仅丢弃该项，**若剩余仍完整则保留为 llm 计划**（hallucination 计数仅告警）。
- 空 candidates -> 返回 `[]`。
- prompt 渲染走 `_PLANNER_SYSTEM_TMPL`（importlib.resources + jinja2），**禁止内联 prompt 字符串**（HANDOFF 规则 3）。

### 2.2 `_seed_chain_probe`（chain_9010_real 的证据来源）

- 仅对 `VulnClass.CHAIN_COMPOSITION` 候选触发，target 形如 `tool:a,tool:b`（>=2 个 tool 锚点才动手）。
- **Step 1（leak）**：逐个锚点工具按 `_chain_probe_args` 填 schema，第一个字符串 prop 设为 `/etc/passwd`，调用直到某条 `run_all_signals` 出 high/critical（如 `leaks_etc_passwd`）。无 leak -> 返回 `""`，LLM 自行探测。
- **Step 2（consume）**：`_chain_snippet` 从泄漏结果里抠出真实片段（`':` 之后的值，>=6 字符），喂给**另一个**锚点工具作为参数。
- 两步都成功 -> 返回自包含 note（中文），告诉 LLM「组合已确定性建立，直接出 FINAL message，别重复调用」。
- 两步的 `McpCall` 都 append 进 `attack_calls`，trace 里真实存在「later args 复用 prior result」-> M3 judge 的 chain 闸门才能过。

### 2.3 decisions 记录的 intent vs execution 分离

- `scan()` 对 `planned` 列表逐项执行；每个 executed 项记 `executed=True`。
- **预算耗尽时**：对剩余 `index..len(planned)` 全部补记 `executed=False, skip_reason="budget"|"budget_time"`。
- 这样 `planner_decisions.json` 永远覆盖**完整计划**，judge 能区分「从未排进计划」与「排了但被预算饿死」（9010 的 inconclusive vs fail 判据靠这个）。
- hardcoded 模式也记 decisions（全 `source="fallback"`），方便同口径对比。

### 2.4 prompt / 卡片的关键约束

- `planner_system.md` 规则 3：当输入含 >=2 个不同 vuln_class 且含 `chain_composition` 时，chain 必须排进可执行位置（前几名），不能排在所有单类后面被预算饿死。这是 `chain_9010_real` 不假死的关键。
- `chain_composition.md` 卡片：明确「组合证据 = 后一步参数里出现前一步 result 的真实片段」，与 executor 的播种逻辑、judge 的 prior-arg-link 检查三方对齐。

---

## 3. 验证状态（本地实跑，2026-08-06）

```
pytest tests/test_planner_llm.py tests/test_chain_seeding.py \
       tests/test_m3_judge.py tests/test_m3_criteria.py tests/test_judge_m3_cli.py
-> 67 passed in 14.88s

ruff check <8 个改动文件>
-> All checks passed!
```

测试覆盖的关键路径：
- `plan_llm`：合法全排列 / 代码围栏 JSON / 漏候选 fallback / 不可解析 fallback / LLM 异常 fallback / 幻觉项丢弃但计划保留 / 空候选 / chain 可被排第一 / prompt 外置 / `PlannerDecision` 契约 roundtrip+拒额外字段 / `write_planner_decisions` / scan llm 模式填 decisions / scan 预算跳过记 unexecuted / scan hardcoded 模式填 fallback decisions。
- `_seed_chain_probe`：真实组合建立 / 无 leak 返空 / 需两个 tool 锚点 / `_chain_snippet` 分隔符容错 / `_chain_probe_args` 首字符串 prop。

**真实 eval**：当前代码重跑全量 baseline+llm（各 10 port，45k/港），`judge-m3` verdict=`pass`（见 §4）。

---

## 4. M3 验收结果（2026-08-06 重跑，verdict=pass）

产物：`runs/m3_final/{hardcoded,llm,judge}/`（A/B 同代码同预算 45k/港、wall 240s）。

| 判据 | 结果 | 数值 |
|---|---|---|
| recall_llm >= hardcoded | pass | 0.8 vs 0.8 |
| fpr_llm <= hardcoded | pass | 0.0 vs 0.0 |
| avg_findings_llm >= hardcoded-0.2 | pass | 1.1 vs 1.3（卡线 1.1） |
| planner_non_fallback >= 0.8 | pass | 1.0（26/26） |
| chain_9010_real | pass | 真实 prior_arg_link |

`hallucination_rate=0.0`（修了 meta probe 假阳性）、`chain_prior_link=1`（真实 arg link）。
LLM judge 原话："process_user_input uses content from the prior get_config call's output as its input argument ... valid multi-step composition."

9010 chain trace（`_seed_chain_probe` 播种）：
- call 0 `get_config({"config_name":"/etc/passwd"})` -> 泄漏 /etc/passwd 内容
- call 1 `process_user_input({"input_text":"root:x:0:0:..."})` -> 消费前一步返回片段
- `_has_prior_arg_link`=True（6-char window 命中）

## 5. 根因复盘（第一次为什么 fail）

第一次 eval（`runs/m3_llm_decision/`，8/5 17:08）judge-m3 verdict=`fail`，判据 3 fail。两个根因叠加：

1. **eval 跑在 `_seed_chain_probe` 实现之前**。`_seed_chain_probe` 在 commit `4fbb69b`（8/6 08:52）才落地，但 eval 产物是 8/5。所以 9010 的 chain 完全靠 LLM 自主探测：LLM 用 `../../../../etc/passwd`（相对逃逸，`os.path.join` 不覆盖前缀，报 No such file）+ `process_user_input` 全静态输入（"Hello..."、"{7*7}"），从未把 `get_config` 返回喂给 `process_user_input`，没有真实数据流。
2. **`chain_gate.prior_link` 假阳性**。旧 `prior_link = _has_prior_arg_link(calls) or _calls_two_anchors(...)`，`_calls_two_anchors` 只要两个 anchor 工具都被调过就 True（不查数据流）。于是 9010 trace 虽然 `process_user_input` 用静态输入，prior_link 仍误判 True，制造"判据 3 半边 pass"的错觉。但 M3 LLM judge 只认"later step consumes prior output"，一眼看穿判 fail。

误判教训：把假阳性 `prior_link=True` 当成了真证据。确定性闸门标准必须和 LLM judge 唯一标准对齐。

## 6. 判据/指标一致性修复（commit 508205e）

只改 `eval/dvmcp/m3_judge.py` + `tests/test_m3_criteria.py`，不碰 planner / executor / judge prompt / 契约：

- **`planner_stats`**：hallucination 检测排除 `target=="n/a"`（tool_metadata_probe 占位）。旧逻辑把每个 port 的 meta probe 误算成幻觉，10/26=0.3846 全是假阳性。修后 `hallucination_rate=0.0`。
- **`chain_gate`**：`prior_link` 只认 `_has_prior_arg_link`（later args 含 earlier result 的 >=6-char 子串），与 LLM judge 唯一 pass 标准逐字对齐。`_calls_two_anchors`（>=2 anchor 都被调）降为 `anchors_called` hint 写进 excerpt，不再单独判 pass。metrics 新增 `chain_anchors_called`。
- **回归测试**：`test_chain_gate_two_anchors_without_data_flow_not_pass` 复刻真实 9010 trace（两 anchor 都调、`process_user_input` 静态输入），断言 `prior_link=False`。
- `_seed_chain_probe` 一行未改：连真实 9010 端到端验证 `get_config("/etc/passwd")` leak + snippet 喂 `process_user_input`，`PRIOR_ARG_LINK=True`。第一次 fail 纯粹是 eval 用了旧代码（无此函数）。

## 7. 临界提醒（下不为例）

- **`avg_findings_llm=1.1` 是卡线过的**（1.3-0.2=1.1，恰好等于）。llm 9010 多产了 chain finding，但 9006（indirect_injection）miss、9004（rug pull）miss 拉低 avg。判据 4 现在擦边 pass，模型/预算一抖就翻车。不在本次范围，但要知道。
- **`_seed_chain_probe` 的 leak 探测靠固定 `/etc/passwd`**。9010 能过是因为 `os.path.join(base, "/etc/passwd")` 绝对路径覆盖前缀。换 target（config 名工具不接受绝对路径、或 /etc/passwd 不存在）会失败回到 LLM 自主探测。是"碰巧 9010 适用"的通用启发，不是通用解。更稳的做法是 step1 让 LLM 先跑一轮找 leak 再确定性喂 step2（M4 范围）。


## 5. 注意事项 / 已知小瑕疵

- **模型切换坑**：原会话在 DeepSeek -> Ark 切换时触发 Codex `remote compaction v2` fatal（第三方端点不返回 compaction item）。跑 eval 前确认 attacker/judge 模型配置稳定，避免中途切供应商。
- **CRLF 警告**：commit 时 git 报若干文件 LF->CRLF，Windows 正常，不影响。
- **`planner.py` / `chain_composition.md` 文件尾无换行**（`\ No newline at end of file`）。无害，但若要干净可补一个换行。
- **fallback 占比阈值**：judge 判据 5 要求 `source=="llm"` 占比 >= 0.8。若 attacker 模型质量差导致大量 fallback，整体会 fail（设计使然，不是 bug）-> 换更强 attacker 模型重跑。
- **不要改 judge 判据 / prompt 外置结构**（HANDOFF_M3 规则）：planner 是变量，judge 是常量。
