# McPwn 实验方法论:可证伪的提能验证

> 本文讲 McPwn 做"给 agent 加能力"类实验时用的**判据设计方法**。
> 核心问题:**怎么证明"加了 X 之后 agent 变强了"是真的,而不是自欺?**
>
> 背景:2026-07 的 M3 实验(LLM planner 替代 hardcoded)用"不劣于"判据
> 得出了 PASS,事后发现**等价也算 PASS 是自欺**,推翻了结论。从那以后,
> McPwn 的提能实验一律改用**严格更优 + 可证伪**的判据,并把这个教训写成
> 正式决策。本文记录这套方法论。

---

## 1. 起点:M3 的负面结果(为什么"不劣于"会自欺)

**实验**:M3 用 LLM 决策版 planner 替代 hardcoded score 排序,目标是证明
"LLM 规划比硬编码更强"。

**判据**(五条,全部是"不劣于"):

```text
recall_llm >= recall_hardcoded
fpr_llm     <= fpr_hardcoded
avg_findings_llm >= avg_findings_hardcoded
planner 非 fallback 率 >= 0.8
9010 chain 闸门
```

**结果**:LLM planner 与 hardcoded **recall/fpr 全等、avg_findings 更低**。
按判据,五条"不劣于"全部成立 → **verdict = PASS**。

**为什么这是自欺**:

1. "不劣于"= 等价也 PASS。等价意味着 LLM planner **没有带来任何提升**,
   但报告会写 PASS,读者会以为"LLM 提能有效";
2. LLM planner 还**更贵**(多一次 LLM 调用)更慢,等价 = 纯成本;
3. 判据本身不可证伪:无论 LLM 多差,只要不太差,都能 PASS。

**最终处理**:M3 结论记录为**负**(commit `4aa65d4` + `HANDOFF_NEXT.md`
"结论为负,别再碰"),教训写死:

> **提能实验判据必须"严格更优"且可证伪;等价也 pass = 自欺。**

---

## 2. 替代方案:严格更优(strict-better)判据

M3 之后的所有提能实验(unknown-shape 三阶段、泛化验证、提示词消融)改用:

| 要素 | 设计 | 为什么 |
|---|---|---|
| baseline 必须漏 | baseline = 0 findings(结构性漏报) | 没有对照的"发现"无法归因 |
| 加能力后必须 ≥1 | 每 run ≥1 finding | 有就是有,没有就是没有 |
| N 次重复 | 同 budget、每 run 全新 server、N=3 | 单次成功可能是运气 |
| **miss 即 fail** | 3 次里 1 次 miss = 整个实验 FAIL | 严格更优,不是"不劣于" |
| 判据跑前锁死 | 协议文档先写判据再跑 | 事后改判据 = 作弊 |

**"miss 即 fail" 的分量**:N=3 全过的概率,在能力真实成立时是 1,
在能力靠运气时是 (p)^3——p<1 时迅速归零。这个判据**可证伪**:
只要有一次 miss,结论就是"不成立",没有模糊地带。

---

## 3. 三阶段实验协议(unknown-shape 模板)

vault-mcp 实验定型的协议,后来 generalize / fetch_ssrf 复用:

| 阶段 | 内容 | 判据 | 回答的问题 |
|---|---|---|---|
| 1 baseline | 当前 agent(无 LLM 决策点)扫靶机 | **0 findings** | 确定性前提:现有能力确实漏 |
| 2 LLM 增量 | 加三决策点(假设生成/复盘/证据判定) | ≥1 finding | 增量是否有效 |
| 3 重复 | 同 budget、每 run 全新 server、N=3 | 每 run ≥1,**miss 即 fail** | 是否稳定(不是运气) |
| 4 消融(可选) | 剥掉提示词答案模式重跑 | D 臂 3/3 | 是"能力"还是"提示词背答案" |

**关键点**:

- **阶段 1 的 0 findings 是前提,不是结果**——如果 baseline 已经能找到,
  实验不成立,先修别的;
- **阶段 3 的每 run 全新 server** 排除靶机状态污染(vault 内存态,
  重复跑会看到上次的 vault);
- **阶段 4 消融**回答"LLM 的价值是发现还是执行提示词里的答案":
  把 hint(子串匹配 / 空 owner / CWE-639)从提示词和策略卡里剥掉,
  2×2 四臂(HINTED/STRIPPED × 卡/提示词),D 臂(全剥离)3/3 = 能力成立。
  防泄漏靠 manifest 双向预检(残留 grep + 逐行 diff,防剥过头)。

---

## 4. 诚实记录的配套机制

判据严格,还不够——结果必须**可审计**。McPwn 的配套:

### 4.1 预注册(protocols locked before runs)

- `eval/unknown_shape/README.md`、`eval/generalize/README.md`、
  `eval/fetch_ssrf/README.md`、`ABLATION_PLAN.md` 都是**跑前写死判据**;
- 修复过程不改判据,只改实现(如 delegate 第 1-3 轮 FAIL 后改 owner
  不可猜、改策略卡第 6 步——判据"每 run ≥1、N=3"原样保留)。

### 4.2 负面结果也落盘

- M3 负结论、Stage-3 第一轮 2/3 FAIL、delegate 三轮 FAIL 全部写进
  `README.md` / `PROGRESS.md` / `HANDOFF_NEXT.md`;
- 失败记录带根因(如"复盘被 budget.exceeded 闸门自己关掉,接线 bug"),
  修复后重跑。

### 4.3 可复现性锚点

- 同 budget、记录 seed、`attack_messages_sha1` 度量 LLM 行为漂移
  (DeepSeek 不支持 seed 时的诚实替代,见 `docs/reproducibility.md`);
- 每 run 全新 server 排除靶机状态。

### 4.4 确定性兜底

LLM 在环的结果再严格也有随机性,所以关键实验配**确定性 prove**:

- excel-mcp:`prove.py` 3-call 链 + docker exec 核对(不走 LLM);
- fetch:`prove.py` 直接调 `fetch("http://127.0.0.1:9211/")` 断言回流;
- 这些是"就算 scan 随机漂移,漏洞确实存在"的确定性证据。

---

## 5. 方法论速查(给下一个实验)

```text
要证明"加了 X 更强":
1. baseline 必须漏(0 findings)          → 否则实验不成立
2. 判据:每 run ≥1, N=3, miss 即 fail   → 可证伪,拒绝"不劣于"
3. 判据跑前锁死写文档                    → 事后改判据 = 作弊
4. 每 run 全新 server / reset 靶机状态  → 排除污染
5. 提示词消融(D 臂)                      → 区分"能力" vs "提示词背答案"
6. 负面结果照实记录                      → 可审计,不粉饰
7. 确定性 prove 兜底                    → LLM 随机性之外的地基
```

---

## 6. 相关文档与记录

- `HANDOFF_NEXT.md` — M3 负结论、严格更优判据的权威表述
- `eval/unknown_shape/README.md` — 三阶段协议 + Stage-3 第一轮 2/3 FAIL 的修复史
- `eval/unknown_shape/ABLATION_PLAN.md` — 消融协议(泄漏清单、2×2 四臂、防泄漏预检)
- `eval/generalize/README.md` — 跨形状验证 + 三轮 FAIL 的修复过程
- `eval/dvmcp/m3_judge.py` — M3 五判据的代码实现(留作反面教材对照)
- `docs/pwn_results.md` — 各实验的最终结果与诚实边界
