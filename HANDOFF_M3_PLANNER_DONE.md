# McPwn -> Next Session: M3 LLM Planner 已实现（待真实 eval 验收）

> 读这个文件 + `HANDOFF_M3.md` + `HANDOFF_M3_PLANNER.md`（契约权威）+ `HANDOFF_JUDGE.md`。
> 本文件回答：M3 planner 缺口实现了什么、验证到什么程度、下一步要跑什么才能拿到 M3 pass。
> 来源：会话因 Codex remote-compaction 崩溃中断，改动以 checkpoint commit `4fbb69b` 落盘，本文档事后补写。

最后更新: 2026-08-06（分支 codex/b-c-ci，checkpoint `4fbb69b` 未推送）

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

**唯一未做**：没在真实 DVMCP 端口上跑 `--planner llm` 全量 eval 并 `judge-m3` 拿最终 verdict。这是下一步。

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

**未实跑**：真实 DVMCP 端口上的 `--planner llm` 全量 eval 与 `judge-m3`。单元/契约层全绿，但端到端 verdict 未取。

---

## 4. 下一步（接手就做这个）

1. **跑 LLM 版 eval**（替换模型为实际配置的 attacker，这里示例 deepseek-v4-flash）：
   ```bash
   mcpwn eval dvmcp run --ports <...> --out runs/m3_llm_v1 --planner llm
   ```
2. **跑硬编 baseline**（同口径，`--planner hardcoded`，作为对比基线）：
   ```bash
   mcpwn eval dvmcp run --ports <...> --out runs/m3_baseline_v1 --planner hardcoded
   ```
3. **M3 验收 judge**（读 `--llm` 目录的 `planner_decisions.json` + chain trace）：
   ```bash
   mcpwn eval dvmcp judge-m3 --baseline runs/m3_baseline_v1 --llm runs/m3_llm_v1 \
       --out runs/m3_judge_v1
   ```
4. 看 `runs/m3_judge_v1/` 的 `M3JudgeReport`：
   - 五判据全 pass -> 整体 pass，M3 收工。
   - 若 `chain_9010_real` 仍 inconclusive/fail：检查 9010 上 planner 是否把 chain 排进计划且预算没饿死它（看 `planner_decisions.json` 里 9010 的 chain 项 `executed`/`skip_reason`），以及 `_seed_chain_probe` 是否真建立了两步（看 9010 trace 的 attack_calls）。

---

## 5. 注意事项 / 已知小瑕疵

- **模型切换坑**：原会话在 DeepSeek -> Ark 切换时触发 Codex `remote compaction v2` fatal（第三方端点不返回 compaction item）。跑 eval 前确认 attacker/judge 模型配置稳定，避免中途切供应商。
- **CRLF 警告**：commit 时 git 报若干文件 LF->CRLF，Windows 正常，不影响。
- **`planner.py` / `chain_composition.md` 文件尾无换行**（`\ No newline at end of file`）。无害，但若要干净可补一个换行。
- **fallback 占比阈值**：judge 判据 5 要求 `source=="llm"` 占比 >= 0.8。若 attacker 模型质量差导致大量 fallback，整体会 fail（设计使然，不是 bug）-> 换更强 attacker 模型重跑。
- **不要改 judge 判据 / prompt 外置结构**（HANDOFF_M3 规则）：planner 是变量，judge 是常量。
