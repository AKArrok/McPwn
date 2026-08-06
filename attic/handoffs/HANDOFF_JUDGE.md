# McPwn → Next Session: Judge 专项交接

> 读这个文件 + `HANDOFF.md` + `PROGRESS.md` + `HANDOFF_NEXT.md` 就能接上。
> 本文只讲 judge。M3 planner 的设计见最终 M3 计划; 本文件是它拆出来的独立任务,
> 新会话可以**先实现 judge, 不依赖 M3 planner 完成**。

最后更新: 2026-08-05 (commit HEAD 在 codex/b-c-ci, 见 `git log`)

---

## TL;DR

judge 现在只是**窄 L2 evidence verifier**: 对 `INDIRECT_INJECTION` / `CHAIN_COMPOSITION`
trace 判 `steered / evidence_call_index / reason`, 合成一条 medium signal, 并落盘到
`AttackTrace.judge_verdict`。M3 需要把它扩展成**两层验收模型**:

1. **保留 L2 evidence judge**: 判 "这条 trace 是否真的被 tool result 里的指令操纵"。
2. **新增 M3 acceptance judge**: 输入 hardcoded 版 + LLM 版两个 eval 结果, 自动输出
   `M3JudgeReport`, 判 M3 是否通过, 而不是让人类只靠 A/B 表拍板。

另外发现一个必须修的违规: `_JUDGE_SYSTEM` 是 `verifier.py` 里的**内联长字符串 prompt**,
违反 HANDOFF 硬性规则 3 (提示词必须落 `**/agents/*.md`, 用 jinja2)。任何 judge 扩展
第一步就是把它外置。

---

## 现状 (代码事实, 以代码为准)

| 事实 | 位置 |
|---|---|
| `JudgeVerdict` pydantic, `steered: bool`, `evidence_call_index: int\|None`, `reason: str` | `mcp_redteam/contracts.py` |
| `AttackTrace.judge_verdict: JudgeVerdict \| None` | `mcp_redteam/contracts.py` |
| L2 prompt `_JUDGE_SYSTEM` 内联 | `mcp_redteam/agent/verifier.py` |
| judge 只在 `_L2_CLASSES` (`INDIRECT_INJECTION` / `CHAIN_COMPOSITION`) 且 `attack_calls` 非空时调用 | `verifier.py` |
| judge 输出 medium signal `llm_judged_injection`; 单条 0.5 不过 0.6, 必须与 L1 共现 | `verifier.py` |
| judge token 走 `budget.add("judge", ...)`, 独立于 attacker | `verifier.py` |
| judge 失败/JSON 不可解析 -> `None`, 视为 not-steered, 不 crash | `verifier.py` |
| 现有 L2 tests: `tests/test_l2_judge.py` (9 条) | 已覆盖 steered / not-steered / unparseable / non-L2 / verdict 落盘 |
| `eval dvmcp run` 目前无 `--planner`, 无 judge 子命令 | `mcp_redteam/cli.py` |

---

## 目标

把 judge 变成 **M3 验收模型**: 能读 hardcoded 与 LLM planner 两套 `runs/m3_llm_decision/`
产物, 按五条判据输出 `pass / fail / inconclusive`, 并生成人类可读报告。judge 不做数字
计算, 数字由确定性代码算; judge 只审 evidence、planner 决策质量和 9010 chain 真实性。

### M3 五条判据 (锁定, 不要改)

1. `recall_llm >= recall_hardcoded`
2. `fpr_llm <= fpr_hardcoded` (期望两边 0)
3. 9010: chain candidate 被实际执行 (`attack_calls > 0`) 且 chain trace 使用了 prior findings
4. `avg_findings_llm >= avg_findings_hardcoded - 0.2`
5. planner 非 fallback 决策占比 >= 80% (否则 A/B 实际是 hardcoded vs hardcoded)

其中 1/2/4/5 由代码计算并喂给 judge; 第 3 条由 judge 看 9010 trace + L2 verdict 判定。

---

## 关键设计决策 (不要再讨论)

1. **确定性 + LLM 混合验收**: 代码算五条里的数值判据, LLM judge 审证据并给最终 verdict。
   不允许让 judge 自己从 raw 数字推断 A/B 结论, 避免 LLM 算数漂移。
2. **新增 `M3JudgeReport`**, 放 `contracts.py`:
   ```python
   class M3JudgeReport(BaseModel):
       verdict: Literal["pass", "fail", "inconclusive"]
       criteria: dict[str, Literal["pass", "fail", "inconclusive"]]
       planner_fallback_rate: float | None
       evidence_refs: list[str]  # trace/finding/report paths judged
       reason: str
   ```
3. **新增 `M3JudgeInput`** (internal dataclass/pydantic, 不落盘也行): baseline 摘要、
   llm 摘要、代码算好的 criteria、9010 chain trace 摘要、planner decisions。
4. **prompt 外置**: 新建两个 jinja2 模板:
   - `mcp_redteam/attackers/agents/judge_system.md` — 替换 `_JUDGE_SYSTEM` (L2)。
   - `mcp_redteam/attackers/agents/judge_m3_system.md` — M3 acceptance。
   `.py` 不得保留 3 行以上 prompt 字符串。
5. **CLI**: `mcpwn eval dvmcp judge-m3 --baseline <dir> --llm <dir> --out <dir>`。
   输入是两个 eval 输出目录, 每个内含 `port_*/scan_result.json` + `eval_report.md`。
   输出 `<out>/judge_report.json` + `<out>/judge_report.md`。
6. **judge budget**: M3 judge 调用也走 `budget.add("judge", ...)` 独立计数; 单港/单次
   judge 失败返回 `None`, 报告标 `inconclusive`, 不 crash。
7. **9010 判定**: judge 必须有 9010 chain trace 的真实证据才给 pass; 没有 trace 时该
   判据为 `inconclusive`, 整个 report 不能因 9010 缺失而假装 fail/pass。
8. **9006 不在范围**: 9006 是 L1 假阳 + L2 不追加 signal 的 detector/judge 调参问题,
   M3 judge 只记录其状态, 不把它当成验收判据。

---

## 数据流

```
eval/dvmcp 跑两遍 (hardcoded, llm)
        |
        v
judge-m3 读两个目录
        |
        v
代码算五条判据里的数字 (recall/FPR/avg_findings/fallback_rate)
        |
        v
构造 M3JudgeInput (含 9010 trace + L2 verdicts + planner decisions)
        |
        v
LLM judge (judge_m3_system.md, temp 0.0) -> M3JudgeReport
        |
        v
写 judge_report.json + judge_report.md
```

如果 `runs/m3_llm_decision/` 还没跑出来, 新会话先用 `tests/fixtures/` 下的合成
ScanResult 或现有 `runs/m2_dvmcp_full_v4` + `runs/clean_baseline_v5` 构造最小 A/B
样例测 judge 管道; judge 实现不阻塞 M3 planner。

---

## 实施步骤 (按顺序)

1. **外置 L2 prompt**: 新建 `judge_system.md`, 删除 `_JUDGE_SYSTEM` 内联, 用 jinja2
   `Template` 渲染; 跑 `tests/test_l2_judge.py` 确认 9 条全过。
2. **contracts**: 新增 `M3JudgeReport`; 如需 `M3JudgeInput` 做 internal 模型。
3. **新建 `mcp_redteam/judge/m3.py`**: `build_m3_input(...)`, `make_m3_judge_fn(...)`,
   `parse_m3_report(...)`, `write_m3_report(...)`。
4. **eval runner**: 新增 `collect_eval_summary(dir) -> dict` 和五条判据计算函数
   (`compute_criteria(hardcoded, llm) -> dict[str, Literal[...]]`)。
5. **CLI**: `eval dvmcp judge-m3` 子命令。
6. **测试**: 见下。
7. **用真实 A/B 产物跑通** (M3 planner 完成后, 或先用合成 fixture)。
8. **更新 PROGRESS.md + commit + push**。

---

## 测试计划

- Unit:
  - `judge_system.md` 渲染不变量 (`vuln_class`, `target`, calls index)。
  - `_parse_judge_json` 已有覆盖, 迁移后保持。
  - `compute_criteria`: recall 相等/更高/更低、FPR 0/非 0、fallback 0.8 边界、
    avg_findings -0.2 边界。
  - `parse_m3_report`: 合法 JSON / 非法 JSON / code fence / 空 reason。
  - M3 judge 失败 -> `None` -> report `inconclusive`。
- Integration:
  - 用 `tests/fixtures/` 合成 A/B 数据跑 `judge-m3`, 验证 JSON + MD 输出。
  - 等 M3 planner 跑完后用真实 `runs/m3_llm_decision/{hardcoded,llm}` 复跑。
- Regression: 全套 pytest, `ruff check mcp_redteam eval`, `lint-cards`。

---

## 已知坑 / 注意

- **`_JUDGE_SYSTEM` 内联违规**是第一个必须修的; 新 judge prompt 绝不能再内联。
- **judge 与 attacker 同模型风险**: 当前 attacker 和 judge 都是 `deepseek-v4-flash`。
  M3 acceptance 由同一模型验收自己的 planner, 可能有自我认可 bias。至少要在
  `judge_report.md` 里记录 judge model, 后续有第二个模型时优先换 judge role。
- **L2 不能单独制造 finding**: `llm_judged_injection` 是 medium 0.5, 单条 < 0.6。
  M3 judge 是报告不是 finding, 不要把它接进 `build_findings` 的置信度。
- **9010 没跑到就不能 pass**: judge 必须把 "chain trace 不存在" 标 `inconclusive`,
  不能因为 A/B 指标好看就给 9010 pass。
- **fallback 率**: planner 429 或非法 JSON 都会 fallback。如果 fallback >= 20%,
  M3 judge 应判第 5 条 fail, 避免 "hardcoded vs hardcoded" 被包装成 LLM 验证。
- **9006 不是 M3**: 它需要的是 L1 假阳修复（`stored_injection_roundtrip` severity 或
  corroboration detector）或 L2 judge 调参, 和 planner 无关。
- **数据目录**: 输入必须是两个**独立** eval 输出目录, 不要混用 `runs/m2_dvmcp_full_v4`
  当 hardcoded baseline（模型是 deepseek-v4-pro, 不是当前 flash）。
