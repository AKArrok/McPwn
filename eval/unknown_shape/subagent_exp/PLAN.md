# Subagent 消融实验：attacker 主循环加 `dispatch_probe` 有没有用？

> 状态：**预注册**。判据在跑主实验（N=3×2）之前锁死；只允许用 ≤2 次 smoke
> 校准预算常数（两臂共享同一常数，校准后不得再动）。
> 日期：2026-10-02。分支：codex/b-c-ci。

## 1. 要回答的问题

当前 attacker 是**单 agent 循环**：每个 candidate 一条 trace，主 agent 在同一个
上下文里完成"定方向 + 穷举探测 + 解读返回"（`agent/executor.py::execute_one`，
最多 12 步）。本次实验验证一个架构假设：

> 给主 agent 加一个 **in-loop 委派工具** `dispatch_probe(task)`（Claude Code
> Task-tool 模式）：主 agent 保持战略视角，把穷举式变体探测委派给**全新上下文**
> 的 subagent（6 步上限），其真实 MCP 调用并入 trace 证据、token 计入同一份
> attacker 预算——在**同等总预算**下，这样做能否提高 finding 率？

### 机制上的正反论点（跑之前写下，防事后叙事）

- **正方（context 卫生）**：主 agent 上下文不被原始 tool 输出塞满；穷举变体
  在干净上下文里做，不锚定在已失败的尝试上。
- **反方（协调开销）**：写 task、读摘要都花 token；subagent 缺全局上下文可能
  重复探测；vault 只有 4 个工具、trace 上下文远没到卫生瓶颈——开销可能白付。

## 2. 实验台与两臂

- 靶机：vault-mcp（`eval/unknown_shape/`），每 run 全新 server
  （`fresh_vault_server`），生产提示词（HINTED），`llm_points=True`，
  `planner_mode=hardcoded`，`llm_hyp_budget=-1`。attacker=deepseek-v4-flash
  （temp 0.7，不支持 seed，漂移用 `attack_messages_sha1` 记录），
  evidence judge=doubao-seed-2.0-lite（带外）。
- **BASE 臂**：生产代码原样（`MCPWN_ATTACKER_SUBAGENT` 未设置）。
- **SUB 臂**：`MCPWN_ATTACKER_SUBAGENT=1`——`execute_one` 的主 agent 额外获得
  `dispatch_probe(task)` 工具 + 委派指引 addendum（`attacker_system.md` 零改动，
  addendum 追加在渲染后的 system prompt 末尾）；subagent 系统提示词
  `subagent_probe_system.md`；每 trace 最多 3 次委派，subagent 最多 6 步。
- **预算**：主实验用**两个预算点** `16000` 与 `20000`（校准记录见 §5：20k 时
  BASE 余量过大，16k 处于"假设生成 4-8k + trace0 完成 12-18k"的跨越区）。
  两臂同预算；subagent token 计入同一 `TokenBudget`（attacker 源），llm-hypothesis
  candidate 内的委派同样进 llm_hyp 池。
- **Judge 降级**（实验配置一部分）：ARK judge（doubao）CodingPlan 订阅失效
  （smoke0 实测 400 InvalidSubscription），设 `MCPWN_JUDGE=attacker` 把 evidence
  judge 降级到 attacker 同款模型（deepseek-v4-flash）——即 Stage-2/3 的历史
  配置。两臂同 judge，内部效度不受影响；与 doubao-judge 的历史 3/3 不可直接
  比对，已如实记录。

## 3. 判据（跑之前锁死）

- **主判据**（同 Stage-3 协议）：每 run ≥1 finding（读到非本人 secret），
  报告 X/3。
- **次级指标**：attacker/judge tokens、wall_seconds、traces、attack_calls 数、
  trace 累计 tokens-to-first-finding（按 finding 的 (vuln_class, target) 匹配
  trace 序号，累加至该 trace 含自身；不含 trace 之前的假设生成 token——两臂
  期望对称）、SUB 臂委派采纳数（每 run dispatch 次数，从 trace 的
  `attacker_messages` 里数 `[subagent done` 工具消息）。
- **N=3 每臂每预算点**（2 预算点 × 2 臂 × 3 = 12 runs）。**扩样规则（预注册）**：
  若某预算点两臂命中数恰好相差 1（如 2/3 vs 3/3），该预算点两臂各扩到 N=5，
  以 N=5 为准；其余情况 N=3 收口。这是**方向性小实验**，不是确证性结论；
  结论强度限定见 §6。

## 4. 判定表（跑之前锁死）

| 观察结果 | 诚实结论 |
|---|---|
| SUB 3/3 且 BASE ≤2/3 | 委派在临界预算下有正贡献（方向性）；值得扩 N 复核 |
| 两臂同 X/3 | 本实验规模下**无证据**表明有用/有害；看次级效率指标与委派采纳率定后续 |
| BASE 3/3 且 SUB ≤2/3 | 委派开销在紧预算下是净负担（方向性负结果，同样值得记录） |
| 两臂都 0/3 | 预算线校准失败，实验无效；修正预算后重跑，烧掉的 runs 作废如实记录 |

## 5. Smoke 校准记录（跑完如实填写）

- **smoke0 @20k, flag-off**（2026-10-02）：attacker 行为与历史生产 run 一致
  （`read_vault(owner="")` 在 trace0 call[2] 命中 secret）→ **flag-off 路径生产
  零影响验证通过**。但 0 findings：ARK judge 返回 400 InvalidSubscription
  （CodingPlan 订阅失效），evidence judge 一次未跑、信号库对 vault 结构性零命中
  → 暴露基础设施问题而非临界信号。处置：加 `MCPWN_JUDGE=attacker` 降级开关
  （`models/chat.py::load_spec`），本次实验 judge=deepseek-v4-flash。
  该 smoke 因 judge 失效**不用于预算校准**。
- **smoke1 @20k, judge=attacker**（2026-10-02）：BASE 2 findings，trace 累计
  tokens-to-first-finding=11,970（hyp+trace0 完成约 16k）→ 20k 余量过大、
  不构成临界区；锁定主实验预算点 = **{16000, 20000}**（16k 恰在 hyp 4-8k +
  trace0 完成 12-18k 的跨越区内），两臂共享，主实验前不再调整。

## 6. 机制与边界

1. **生产零影响**：flag 关闭时 `execute_one` 不渲染 addendum、工具列表不含
   dispatch_probe、不进入 subagent 分支（冒烟验证）。
2. **证据纪律**：dispatch 本身不是 MCP call，不进 `attack_calls`（grounding：
   证据只能来自真实 tool 返回）；subagent 的真实 MCP 调用进 `attack_calls`，
   对信号库/证据判定与主 agent 的调用完全同权。
3. **预算纪律**：subagent token 计入同一 TokenBudget；total-budget 对比自动成立。
4. **诚实边界**：只测 vault 一种形状、单模型（deepseek-v4-flash）、N=3 小样本、
   temp 0.7 方差大；委派采纳率不强制（SUB 臂 agent 可能少用甚至不用
   dispatch_probe——采纳率本身作为指标记录，零采纳≈两臂等价）。
5. 交付物：`eval/unknown_shape/subagent_exp/`（PLAN + run_one + run_all +
   判定汇总），`runs/subagent_exp/`（每 run scan_result.json + summary.json）。

## 7. 结果与结论（2026-10-02，跑完回填）

### 7.1 主判据（每 run ≥1 finding）

| 预算 | BASE | SUB（委派可选） | FORCE（强制委派，探索性诊断） |
|---|---|---|---|
| 20000 | **5/5** | **5/5** | 3/3 |
| 16000 | **4/5** | **3/5** | 2/3 |

- N=3 首轮 b20k 出现 2/3 vs 3/3，触发预注册扩样规则；扩到 N=5 后 b20k 两臂
  全饱和（5/5 vs 5/5），首轮差距确认为温度噪声。
- b16k 4/5 vs 3/5：差 1，但见 §7.2 —— 两臂行为并不构成"有/无委派"的对比。

### 7.2 关键观察：自发采纳率 = 0

**10 条 SUB run 里 `dispatch_probe` 被调用 0 次**（addendum 已渲染进 system
prompt、工具已在 tools 列表，逐条核验过）。即 SUB 与 BASE 的实际行为差异只剩
"system prompt 里多一段静态文本 + tools 里多一个未被调用的工具"。b16k 的 1 条
差距不能归因于委派机制本身。

机制解释（有数据支撑的方向）：addendum 文本随 system prompt **每次 LLM 调用
重发**。b20k 全程烧满预算的两臂相比，SUB 的 run 总 token 中位数 22.6k vs BASE
21.1k（+~7%），trace 累计 tokens-to-first-finding 中位数 17.5k vs 12.8k——
同样行为、同样的 20k 帽子，SUB 每轮更贵、能做的探测更少。这是**静态提示词税**，
不是委派的开销（委派从未发生）。

### 7.3 FORCE 诊断：机制能跑通，但无收益、紧预算下是负担

- 采纳率 100%（每 run 恰 1 次委派），且出现**纯 orchestrator 形态**：主 agent
  自己 0 次直接 MCP 调用，subagent 包办全部 14-24 条探测调用；findings 正常
  产出 —— 证明 subagent 调用并入 `attack_calls` 后，信号库/证据判定/finding
  管道完全同权，证据纪律未被破坏。
- b20k 3/3（预算宽松，伤害不可见）；b16k 2/3，miss 形态：subagent 6 步耗在
  `list_vaults` 枚举上，被全局预算闸门截断（summary 首行 `[subagent stopped:
  budget/clock]`），没来得及试 `read_vault(owner="")`。**紧预算下强制委派 =
  用协调开销换了一个更慢、更容易被预算掐死的探测者。**

### 7.4 结论（对应 §4 判定表）

1. **本实验规模下，"加 subagent"对 finding 率无正贡献，也无实害**（20k 两臂
   同为 5/5）；16k 的 1 条差距方向为负，但归因是静态提示词税 + 噪声，不是委派。
2. **真正的发现是采纳率为 0**：deepseek-v4-flash 在 4 工具、假设直指目标的
   靶形上**从不自发委派**。"加 subagent 有没有用"在这个设置下的诚实答案：
   **没用，因为没人用它**——收益上限被采纳率锁死。
3. 强制使用时机制正确、证据管道无恙，但单靶单洞的 vault 上没有可见收益。
4. **下一步若继续验证**（按价值排序）：
   - 换靶形：穷举面大、上下文会塞满的多工具靶（如 server-everything /
     DVMCP 组合洞），让"context 卫生"论点真正上桌；
   - 换委派位置：把 subagent 用在 **hypothesis 侦察**（现有假设点只看 schema
     文本，不给活的 server——能试调的侦察 subagent 可能压低 Stage-3 round-1
     那种假设采样方差），这比 in-loop 委派更对症；
   - 并行 fan-out 的 wall-time 收益（本实验串行，未测）。
5. 成本：~28 runs，attacker ~600k tokens + judge ~45k（deepseek-v4-flash，
   flash 价可忽略）；judge 因 ARK 订阅失效降级为 attacker 同款（MCPWN_JUDGE=
   attacker），与历史 doubao-judge 的 3/3 不可直接跨实验比对。
6. **配置变更记录（实验结束后）**：judge 角色已迁至阿里云百炼
   `qwen3.8-27b`（DashScope compatible-mode，`DASHSCOPE_API_KEY`，
   key 复制自 CISP 项目；ARK doubao/CodingPlan 订阅失效弃用，
   `run_one.py` 的 `MCPWN_JUDGE=attacker` 临时降级已拆除）。本次实验全部
   runs 的 evidence judge 仍是 deepseek-v4-flash；后续复跑或新实验的
   findings/ttff 口径与本次不同，跨实验对比须注明 judge 版本。
