# McPwn → Next Session: M3 唯一交接（LLM planner 实现）

> 读这个文件开始；细节权威是 `HANDOFF_M3_PLANNER.md` + `HANDOFF_JUDGE.md`。
> judge 已完成，M3 唯一缺口是 LLM planner + `planner_decisions.json` 产出。
> 新会话只做 planner，不要改 judge 判据或 prompt 外置结构。

最后更新: 2026-08-05（HANDOFF_M3_PLANNER.md 已 commit，当前分支 codex/b-c-ci）

---

## TL;DR

M3 成功由已完成的 judge 验收：`mcpwn eval dvmcp judge-m3`。要拿 `pass`，planner 必须：
1. 真实调用 LLM 决策，非 fallback 占比 >= 80%。
2. 9010 的完整计划里**包含且实际执行** `chain_composition`，chain trace 有真实组合证据。
3. LLM 版 recall/FPR/avg_findings 不低于同模型 hardcoded baseline。

唯一缺口 = 把 `agent/planner.py` 的硬编排序升级为 LLM 决策，并让 `eval/dvmcp` 的 LLM 模式写出 `<llm_dir>/planner_decisions.json`。

---

## 现状（事实）

| 项 | 状态 |
|---|---|
| L2 judge prompt 外置 + M3 acceptance judge | 已完成（`mcp_redteam/judge/`、`eval/dvmcp/m3_judge.py`、`mcpwn eval dvmcp judge-m3`） |
| `M3JudgeReport` contract | 已完成（`mcp_redteam/contracts.py`） |
| 五条判据 + 9010 意图分离 + fallback 统计 | 已完成，锁死 |
| `planner_decisions.json` 契约 | 已定义，**planner 必须产出** |
| `agent/planner.py::plan` | 仍是硬编 score 降序 |
| `orchestrator/runner.py::scan` | 仍无条件调硬编 `plan(...)` |
| `eval/dvmcp/runner.py` | 无 `--planner`，无 planner_decisions 写入 |
| 模型 | attacker=deepseek-v4-flash，judge=doubao-seed-2.0-lite |

---

## 成功判据（不要改）

- `recall_llm_ge_hardcoded`
- `fpr_llm_le_hardcoded`
- `avg_findings_llm_ge_hardcoded`
- `planner_non_fallback_ge_0_8`
- `chain_9010_real`

整体聚合：任一 fail → fail；否则任一 inconclusive → inconclusive；否则 pass。

9010 关键规则：
- 完整计划里没有 `chain_composition` → `fail`。
- 计划里有 chain 但没执行 → `inconclusive`。
- 执行了 chain 且 later args 复用 prior result、或调用 >=2 个声明 anchor、或 >=2 条不同 tag 信号 → LLM judge 裁 `pass`（最终由 judge 确认）。

---

## 实施步骤

### 1. `agent/planner.py` 增加 LLM 模式

- 保留现有硬编 `plan()` 作为 fallback 与 hardcoded baseline。
- 新增 `plan_llm(candidates, tools_seen, resources_seen, client, model_spec, sse_url=None) -> list[PlannedCandidate]`。
- LLM 输入：recon 产出的完整候选集（vuln_class / target / kind / reason / score）+ tools/resource 摘要。
- LLM 输出：**包含全部候选的完整有序计划**，不允许漏项；每项输出 `vuln_class`、`target`、`reason`。
- 输出非法 JSON / 缺项 / LLM 429 / 超时 → 返回硬编 `plan()` 结果并标记整条计划 `source="fallback"`。
- 新增 prompt 模板 `mcp_redteam/attackers/agents/planner_system.md`（jinja2），不得内联。
- prompt 明确要求：对同时存在多类候选的 server，评估是否应把 `chain_composition` 排进可执行位置；不能只排"安全"类。

### 2. 新增 `PlannerDecision` 契约

放 `mcp_redteam/contracts.py`（pydantic，extra=forbid）：

```python
class PlannerDecision(BaseModel):
    port: int
    index: int
    vuln_class: str
    target: str
    source: Literal["llm", "fallback"]
    planned: bool = True
    executed: bool = False
    skip_reason: str | None = None
```

`eval/dvmcp/m3_judge.py::load_planner_decisions` 已按此字段消费，不要改 schema。

### 3. `orchestrator/runner.py::scan` 支持 planner 注入

- 增加参数 `planner_mode: Literal["hardcoded", "llm"] = "hardcoded"`（或传入 `planner_fn`，任选，但 CLI 要暴露 hardcoded/llm）。
- hardcoded：现状不变。
- llm：recon 后调用 `plan_llm` 得到完整 ordered plan；按序执行，每条 trace 记录对应 decision；因 budget 未执行的候选保留 `planned=true, executed=false, skip_reason="budget"`。
- scan 返回的 `ScanResult` 不需要新增字段；`planner_decisions` 由 eval runner 组装写出。

### 4. `eval/dvmcp/runner.py` 增加 `--planner`

- `run_all(..., planner_mode="hardcoded"|"llm")` 透传给 `scan()`。
- llm 模式跑完全部 port 后，在输出目录根写 `<out>/planner_decisions.json`：
  `{"decisions": [ ... ]}`，包含所有 port 所有候选的完整计划序列（含未执行项）。
- CLI：`mcpwn eval dvmcp run --planner llm --out runs/m3_llm_decision/llm`；hardcoded 是默认值。
- 完整序列必须覆盖该 port 的全部 recon candidates，不能只记执行过的。

### 5. 9010 预算保证

- A/B 两版使用**同一预算**：建议默认 `max_tokens=45000`、`wall_seconds=240`，避免 30k 在 individuals 上烧光后 chain 永远不执行。
- planner prompt 要求把 chain 排进可执行位置；runner 必须实际执行到它（`attack_calls > 0`）。
- 如果 LLM 没把 chain 排进计划但 recon 存在 chain candidate → 判定会 fail，这不是可接受的实现结果。

---

## 验收流程

```bash
# 1. 硬编 baseline（同模型同预算）
mcpwn eval dvmcp run --out runs/m3_llm_decision/hardcoded --max-tokens 45000

# 2. LLM planner
mcpwn eval dvmcp run --planner llm --out runs/m3_llm_decision/llm --max-tokens 45000

# 3. judge 验收
mcpwn eval dvmcp judge-m3 --baseline runs/m3_llm_decision/hardcoded \
  --llm runs/m3_llm_decision/llm --out runs/m3_llm_decision/judge

# 4. 唯一通过标准
cat runs/m3_llm_decision/judge/judge_report.json  # verdict == "pass"
```

若 `inconclusive`，按 judge_report 指出的判据修；常见卡点：
- 缺 `planner_decisions.json` → 判据 5 inconclusive。
- 计划里没 chain → 判据 3 fail。
- 计划里有 chain 没执行 → 判据 3 inconclusive（预算没保证）。
- 某 port 没跑完 / LLM 失败太多 → fallback 率 fail。

---

## 测试计划

- Unit：`plan_llm` 合法/非法/缺项 JSON、429 fallback、source 标记、完整计划不漏候选、chain 排序能力。
- Contract：用 `tests/fixtures/m3_builder.py` 的 `all_pass` / `no_chain` / `planned_unexecuted` / `no_planner_decisions` 场景反向验证 `judge-m3` 输出。
- Integration：9001 + 9010 先冒烟，再全 10 port A/B。
- Regression：全套 pytest、`ruff check mcp_redteam eval`、`lint-cards`；保持 153 条现有测试全过。

---

## 已知坑

- **不要改 judge 判据/契约**：`M3JudgeReport`、五条 key、`planner_decisions.json` 字段都是锁定输入。
- **不要实现跨 trace prior-findings 传递**：HANDOFF_M3_PLANNER 已明确不在范围；chain 组合证据解释为 chain trace 内部前序步骤产出。
- **不要拿 `runs/m2_dvmcp_full_v4` 当 hardcoded baseline**：那是 deepseek-v4-pro，不是当前 flash。
- **提示词必须外置**：planner prompt 放 `attackers/agents/planner_system.md`，禁止内联长字符串。
- **提交规范**：M3 planner 单独 commit，不裹挟 judge/realworld/其他未提交改动；跑通后更新 `PROGRESS.md`。
