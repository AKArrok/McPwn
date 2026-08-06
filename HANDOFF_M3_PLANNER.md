# McPwn → Next Session: M3 Planner 专项交接（judge 已完成，planner 是唯一缺口）

> 读这个文件 + `HANDOFF_JUDGE.md` + `HANDOFF.md` + `PROGRESS.md` 就能接上。
> 本文件回答两件事：
> 1. judge 扩展做完了什么（已完成，可直接用）。
> 2. M3 LLM planner 要实现什么、必须产出什么，judge 才会给 pass（唯一缺口）。

最后更新: 2026-08-05 (commits 721ee9a + ed96348, 分支 codex/b-c-ci 已推送)

---

## TL;DR

- **judge 两层验收模型已完成**：L2 证据复核（prompt 外置到 `mcp_redteam/judge/agents/`）+ M3 acceptance judge
  （`mcpwn eval dvmcp judge-m3`）。pytest 153 passed, ruff 0, lint-cards 7/7，真实 runs 目录冒烟通过。
- **唯一缺口 = M3 LLM planner**：把 `agent/planner.py` 的硬编排序换成 LLM 决策，并让
  `eval/dvmcp/runner.py` 在跑 LLM 版时写出 `planner_decisions.json`。
- 没有这份产物之前，judge 判据 5（非 fallback 率）和判据 3（9010 chain）恒为 `inconclusive`，
  整体不可能 pass——这是设计使然（无证据不假装 pass），不是 bug。
- **本文件定义的 `planner_decisions.json 契约` 是硬性要求**，planner 实现必须逐字段满足，否则 judge 无法判定。

---

## 1. judge 已完成（事实，以代码为准）

| 事实 | 位置 |
|---|---|
| L2 judge prompt 全量外置 (system + user)，不再有内联长字符串 | `mcp_redteam/judge/agents/{judge_system,judge_user}.md`，verifier 用 jinja2 渲染 |
| 容错 JSON 解析 (code fence + 正则兜底) | `mcp_redteam/judge/parse.py` (`parse_json_object` / `parse_judge_json`) |
| M3 报告契约 | `mcp_redteam/contracts.py` 的 `M3JudgeReport` (verdict / criteria / metrics / planner_fallback_rate / evidence_refs / reason / judge_model / judge_tokens) |
| M3 judge LLM 模块 (只裁 `chain_9010_real` + reason) | `mcp_redteam/judge/m3.py` (`make_m3_judge_fn` / `parse_m3_report` / `assemble_report` / `write_m3_report`) |
| M3 judge prompt | `mcp_redteam/judge/agents/judge_m3_system.md` |
| 确定性半边 (摘要/指标/planner 统计/9010 闸门/五判据) | `eval/dvmcp/m3_judge.py` (`collect_eval_summary` / `compute_metrics` / `load_planner_decisions` / `planner_stats` / `chain_gate` / `compute_criteria` / `run_judge_m3`) |
| CLI | `mcp_redteam/cli.py`: `mcpwn eval dvmcp judge-m3 --baseline <dir> --llm <dir> --out <dir> [--judge-model <model>]`，exit 恒 0 |
| 测试 | `tests/test_judge_prompt_external.py` / `tests/test_m3_judge.py` (18) / `tests/test_m3_criteria.py` (27) / `tests/test_judge_m3_cli.py` / `tests/fixtures/m3_builder.py` (5 场景) |

### 1.1 已实测
- 冒烟：`mcpwn eval dvmcp judge-m3 --baseline runs/m2_dvmcp_full_v4 --llm runs/m2_5_v1` →
  整体 `inconclusive`（无 planner_decisions + 无 chain trace，预期），LLM judge (doubao-seed-2.0-lite)
  对 9010 给出真实裁决 "no chain trace, insufficient evidence"，judge_tokens 1352。报告见 `runs/m3_judge_smoke/`。
- 确定性半边对真实 `runs/m2_dvmcp_full_v4` 重算 recall=0.8 / fpr=0.0，与已知数字一致。

## 2. judge 怎么判 M3 通过（planner 的靶子）

五条判据 key（锁定，别改）：
- `recall_llm_ge_hardcoded`: llm 版 recall >= 硬编版 recall（同 port 交集、同分母）
- `fpr_llm_le_hardcoded`: llm 版 fpr <= 硬编版 fpr（期望两边 0）
- `avg_findings_llm_ge_hardcoded`: llm 版 avg_findings >= 硬编版 - 0.2
- `planner_non_fallback_ge_0_8`: planner 决策里 `source=="llm"` 占比 >= 0.8，否则 fail；无 `planner_decisions.json` → inconclusive
- `chain_9010_real`: 见 2.1（代码给闸门，LLM judge 只裁这一条）

整体聚合（保守，锁死）：任一 fail → fail；否则任一 inconclusive → inconclusive；否则 pass。

### 2.1 chain_9010_real 的意图 vs 执行分离（grill 已锁）

- **LLM planner 的完整计划序列里没有 `chain_composition`** → 判据 3 = `fail`（主动放弃 9010 是决策失败，不是运气）。
- **计划里有 chain 但预算没执行** → `inconclusive`（数据不足，不冤枉 planner）。
- **执行了 chain 且有组合证据**（later args 复用 prior result，或调用 >=2 个声明 anchor，或 >=2 条不同 tag 信号）→ 代码给 `pass` 前置，
  LLM judge 读 trace 摘要确认真组合 → 最终 `pass`；LLM 否认 → `fail`。
- **没有 9010 数据**（llm 目录缺 port_9010）→ `inconclusive`。

### 2.2 对 planner 的行为要求（直接推导）

1. 必须真实调用 LLM 做决策，且非 fallback 占比 >= 80%（判据 5）。
2. 9010 上必须**把 chain_composition 排进计划并实际执行**，且要让 chain trace 出现真实组合（判据 3）。
3. recall/fpr/avg_findings 不低于硬编版（判据 1/2/4）——注意硬编版是 `agent/planner.py` 现在的行为，
   LLM 版如果只是等价重排，判据 1/2/4 会 pass 但 9010 不执行 → 整体还是 inconclusive/fail，ROI 为负，别做等价实现。

## 3. planner 必须产出的契约：`planner_decisions.json`（硬性要求）

位置：**llm 版 eval 输出目录的根目录**（`<llm_dir>/planner_decisions.json`，与 `port_*/` 平级）。
judge 只从 `--llm` 目录读它；硬编 baseline 目录不需要。

Schema（示例）：
```json
{
  "decisions": [
    {
      "port": 9010,
      "index": 0,
      "vuln_class": "command_injection",
      "target": "run_cmd",
      "source": "llm",
      "planned": true,
      "executed": true,
      "skip_reason": null
    }
  ]
}
```

字段语义（judge 的 `eval/dvmcp/m3_judge.py` 就是这么消费的）：

| 字段 | 语义 | judge 用途 |
|---|---|---|
| `port` | 该决策属于哪个 DVMCP 港 | 幻觉检测、chain 意图分离都按 port 定位 |
| `index` | 在**完整计划序列**里的顺序（从 0 起） | 计划序列完整性 |
| `vuln_class` / `target` | 决策选的 (vuln_class, target) | 幻觉检测：target 不在该 port 的 tools_seen+resources_seen 且不含逗号 → 计为 hallucinated（chain anchor 含逗号，豁免） |
| `source` | `"llm"` = LLM planner 决策；`"fallback"` = LLM 调用失败(429/非法 JSON)回落到硬编排序 | 判据 5：`llm` 占比 >= 0.8 |
| `planned` | 该项是否在计划序列里（含从未执行的） | 判据 3 意图分离：计划里有 chain 但没执行 → inconclusive |
| `executed` | 该项是否真的跑了（attack_calls > 0） | 判据 3：chain 执行 |
| `skip_reason` | `"budget"` / `"error"` / `null`（没执行时填原因） | 报告审计 |

**必须满足的完整性规则**：
- 每个 port 的计划序列 = 该 port 全部候选的**有序列表**（planned=true 全覆盖），不是只记执行过的；否则“计划里有没有 chain”无法判断。
- `executed=false` 的项必须保留在列表里并填 `skip_reason`。
- `source` 逐条记录：LLM 决策记 `llm`，fallback 记 `fallback`——fallback 定义与 `models/chat.py::chat_create_with_retry` 耗尽/非法 JSON 一致。

## 4. M3 planner 实现指引（改造点 + 失败模式）

### 4.1 现状代码事实
- `mcp_redteam/agent/planner.py::plan(candidates, max_candidates)` 现在是硬编 score 降序截断。
- `mcp_redteam/agent/recon.py` 在 recon 出 >=2 个不同 vuln class 时**必生成** `CHAIN_COMPOSITION` 候选
  （score 0.7，target = 前 4 个 anchor 的 `kind:name` 逗号串）。但 9010 在 m2_5_v1 撞 budget_tokens 时
  chain 排在 individuals（0.95/0.9/0.85/0.8）后面，**根本没轮到执行**。
- `mcp_redteam/orchestrator/runner.py::scan` 直接调 `plan(...)`，无 planner 模式参数；
  `eval/dvmcp/runner.py::run_all` 每港独立 `scan()`（每港独立 budget）。

### 4.2 改造点（建议，可自行细化但必须产出 §3 契约）
1. `agent/planner.py` 增加 LLM 决策模式：输入 recon 结果（tool 列表 + 描述 + candidate 集），输出完整有序计划序列 + 每条 `source`。
   - 复用 `models/chat.py::make_client("attacker")` + `chat_create_with_retry`；LLM 输出非法/失败 → fallback 到硬编排序并记 `source="fallback"`。
   - 决策要能覆盖“把 chain 排进计划”这个动作（9010 是硬闸门，见 §2.1）。
2. `eval/dvmcp/runner.py` 增加 `--planner llm|hardcoded`（或等价开关），llm 模式跑完后在输出目录根写 `planner_decisions.json`（§3）。
3. 9010 预算：chain 要在 budget 内执行——要么 planner 把 chain 排高，要么 eval runner 对 9010 单独给足 budget；
   两者选一即可，但必须保证 chain 真的跑了（`attack_calls > 0`）。

### 4.3 失败模式（HANDOFF_NEXT 预设，planner 验收时对照）
- 太保守：只选“安全”类，跳过 chain/rug_pull/shadow → 9010 判据 fail。
- 太激进：一次生成一堆 candidate 每个都跑 → budget 超时，chain 又没跑到 → inconclusive。
- 幻觉 candidate：选了 recon 没列出的 → hallucination_rate 升高（只记录，不进判据，但会污染决策质量）。
- **最可能：与硬编 planner 完全等价** → 判据 1/2/4 pass 但 9010 不执行 → 整体 fail/inconclusive，ROI 负。
  judge 的意义就是把这个“等价假 M3”拦下来。

### 4.4 公平性
- hardcoded baseline 和 llm 版**必须同一 attacker 模型、同一批次、同一 budget** 跑（现在 models.yaml attacker=deepseek-v4-flash）。
- 不要拿 `runs/m2_dvmcp_full_v4`（deepseek-v4-pro）当 hardcoded baseline。

## 5. 验收流程（M3 planner 完成后照此跑）

1. 同一模型同一批次跑两遍：
   - 硬编版：`mcpwn eval dvmcp run --out runs/m3_llm_decision/hardcoded`（默认 planner=hardcoded）
   - LLM 版：`mcpwn eval dvmcp run --planner llm --out runs/m3_llm_decision/llm`（runner 写 `planner_decisions.json`）
2. 判：`mcpwn eval dvmcp judge-m3 --baseline runs/m3_llm_decision/hardcoded --llm runs/m3_llm_decision/llm --out runs/m3_llm_decision/judge`
3. 读 `runs/m3_llm_decision/judge/judge_report.md`（人可读）+ `judge_report.json`（机器可复核）。
4. **M3 只有 verdict=pass 才算通过**；inconclusive/fail 都是未完成，报告里会写明哪条判据卡住。
   - 常见卡点：`planner_non_fallback_ge_0_8=inconclusive`（没写 planner_decisions.json）、`chain_9010_real=fail`（计划里没 chain）。

## 6. 测试计划（planner + judge 契约）

- 单测：planner LLM 决策输出解析（合法/非法 JSON/code fence）、fallback 语义（429→fallback 且 source 记对）、
  计划序列完整（含未执行项）、幻觉检测与 §3 规则一致。
- 集成：用 `tests/fixtures/m3_builder.py` 的 `all_pass` 场景反推——真实 planner 跑出来的 `planner_decisions.json` + 9010 chain trace
  必须让 `judge-m3` 输出 `pass`；把 builder 的 `no_chain` / `planned_unexecuted` / `no_planner_decisions` 场景当负例回归。
- 回归：pytest 全套、`ruff check mcp_redteam eval`、`lint-cards`。

## 7. 已知坑 / 注意

- **`planner_decisions.json` 是 judge 的命脉**：漏写 → 判据 5 inconclusive；计划序列不完整（只记执行过的）→ 判据 3 的意图分离失效。
- 9006 不是 M3 判据（HANDOFF_JUDGE 决策 8）：它要的是 L1 假阳修复或 L2 judge 调参，和 planner 无关，报告里只记录状态。
- judge 与 attacker 同模型风险：现在 judge role=doubao-seed-2.0-lite，与 attacker 不同；若以后换同模型，报告仍会记录 judge_model 供审计。
- 跨 trace 喂 prior findings 的机制**不在本次范围**（grill 已锁）：`chain 使用 prior findings` 解释为 chain 尝试内部前序步骤的产出，
  不要为此改 executor 的跨 candidate 状态传递。
- 提交规范：M3 planner 单独 commit，别裹挟 judge/realworld 改动；跑完按 §5 出报告后更新 PROGRESS.md。
