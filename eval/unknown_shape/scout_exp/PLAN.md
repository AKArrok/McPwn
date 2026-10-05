# Scout 实验：结构化委派的 hypothesis 侦察 subagent 有没有用？

> 状态：**预注册**，判据在跑主实验（N=3×2）之前锁死；smoke 仅验证机制跑通。
> 日期：2026-10-02。前置：`../subagent_exp/PLAN.md`（in-loop 委派实验，
> 结论：deepseek-v4-flash 自发采纳率 0；burst 挖掘显示真实靶机存在委派理性形状）。

## 1. 要回答的问题

in-loop 委派（模型自己调 `dispatch_probe`）败在采纳率上。本实验换**结构化委派**：
由**框架**在 hypothesis 决策点派出一个**能活探测的侦察 subagent**
（`agent/llm_points.py::scout_hypotheses`，`MCPWN_HYP_SCOUT=1`）——采纳率 100%
by construction，价值验证不再依赖模型自觉。

> 假设：hypothesis 决策点现在只看 schema 文本就猜（Stage-3 round-1 miss 的
> 源头）；给侦察 subagent ≤3 轮 / ≤6 次真实探测，能把"从 schema 猜"变成
> "用事实锚定"，降低 miss 方差、提高到 finding 的效率。

**机制要点**（预注册）：
- scout 在 `generate_hypotheses` **之前**运行，产物经同一套
  `parse_hypotheses` 校验（target 必须真实存在、类名合法），reason 带
  `[llm-scout]` 标记与探测观察到的事实摘要，score 0.99 与 llm-hyp 同权重；
- scout 的探测调用**不进任何 trace**（grounding 纪律：证据只能来自真实攻击
  trace）；它喂给主 attacker 的是候选 reason 里的事实摘要；
- scout token 计入 attacker 预算（不走 llm_hyp 池——池约束的是候选 trace，
  scout 跑在任何候选之前）。

## 2. 实验台与两臂

- 靶机：vault-mcp，每 run 全新 server；`llm_points=True`（含复盘 + 证据判定），
  `planner_mode=hardcoded`，`llm_hyp_budget=-1`。
- attacker：deepseek-v4-flash（temp 0.7，seed=None）。
- judge：**qwen3.8-27b（DashScope）**——注意口径：与 subagent_exp 的
  deepseek-judge 不可跨实验直接比数；本实验两臂同 judge，内部效度成立。
- **BASE**：生产配置原样（2-sample 假设生成 + 复盘 + 证据判定）。
- **SCOUT**：`MCPWN_HYP_SCOUT=1`。
- **预算**：`max_tokens=16000`（subagent_exp 实测 BASE 4/5 的临界区，有 headroom）。

### §2.1 设计修订（两次冒烟后、主批次前，如实记录）

冒烟暴露两个机制问题并修复：
1. **scout 预算挤占**（smoke0：scout 花了 8.5k/16k，攻击波饿死成 0 call trace）
   → 加 `_SCOUT_TOKEN_CAP=5000` 硬帽（探测超帽即收敛出 JSON；最终 JSON 调用
   不受帽限、受全局预算限）。
2. **结论式 reason 反噬**（smoke0：主 attacker 读了 reason 里的"已证实"就
   直接 FINAL、0 真实调用 → grounding 闸门诚实拒绝）→ scout prompt 改为
   "reason 是给主攻击者的**复现任务书**，禁止结论性表述"。
3. **叠加→替换**（smoke2：scout 6.5k + 2-sample 生成 4k = 10.5k 固定开销，
   16k 下攻击波只剩 5.5k，叠加设计结构性饥饿）：SCOUT 臂改为**同决策点的
   两种实现对比**——scout 有产出时**跳过** 2-sample 生成（live-probing 实现
   vs schema 猜测实现）；scout 空手时才回退到生成。此修订在主批次前锁定。

## 3. 判据（跑之前锁死）

- **主判据**：每 run ≥1 finding，报 X/3。
- **次级**：ttff（trace 累计 tokens-to-first-finding）、attacker tokens、
  attack_calls、scout 归因（`scout_traces`：首条 user message 含 `[llm-scout]`
  的 trace 数；`scout_findings`：其中成为 finding trace 的数）——衡量
  "scout 提出的方向是否真的承载了 finding"。
- N=3 每臂；两臂命中差 1 → 各扩 N=5。

## 4. 判定表（跑之前锁死）

| 观察结果 | 诚实结论 |
|---|---|
| SCOUT 3/3 且 BASE ≤2/3，或 ttff 显著优 | 结构化委派在假设点有正贡献；扩样复核 |
| 两臂同 X/3 且 ttff 相近 | 无证据；看 scout_findings 归因判断 scout 是否只是重算已知答案 |
| SCOUT ≤ BASE | 侦察开销 ≥ 收益；方向性负结果，记录后考虑砍掉 scout 或换更便宜的探测 |
| 两臂都 0/3 | 环境/口径问题，实验无效，如实记录 |

## 5. 诚实边界

1. 只测 vault 单形状；scout 的价值假说（降假设方差）在此靶上正中要害，但
   泛化到多工具真实靶是下一个实验。
2. N=3（可扩 5），temp 0.7 方差大；方向性小实验。
3. scout 探测不进 trace，若 scout 一步就踩中漏洞，finding 仍需正式 trace 复现
   ——这是设计立场（证据纪律），不是缺陷，但会低估 scout 的"直达"价值。
4. SCOUT 臂 scout token 挤占同一 16k 预算；ttff 若变差需区分"侦察税"与"方向差"。

## 6. 结果与结论（2026-10-02，跑完回填）

### 6.1 零成本预研：burst 挖掘（`scripts/mine_enumeration_bursts.py` → `runs/analysis/burst_mining.json`）

249 个历史 scan，判据预注册（≥6 连发同工具 = burst；同工具同参数键 = 严格参数扫）：
非实验 scan 中 **48 个含 ≥1 burst**，68 条 burst 里 **63 条是严格参数扫**；最长
20 连发（ws_target `fs_read` @~9.6k token 位、lg_b_verify `get_config` @~24k
token 位——都在上下文深水区）；~20 条 post-evidence burst（证据到手还在扫）。
**结论：委派理性的形状在真实靶机存在但非普遍（约 1/3 scan），vault 恰好没有**
—— in-loop 实验的零采纳有靶形因素，不全是模型因素。

### 6.2 主实验（16k，qwen3.8-27b judge，N=3 → 预注册扩样 N=5）

| 臂 | N=3 | N=5（为准） | 备注 |
|---|---|---|---|
| BASE | 1/3 | **5/5** | 全部 [llm-hyp] 命中，ttff 11.9k-15.7k |
| SCOUT | 2/3 | **1/5** | 两条 N=3 命中实为 scout 空手后的生成回退 |

scout 日志（run_all 采集 child stderr）拆出了直接原因：**N=5 的 5 条 run 里
scout 全部撞 5k 帽后 JSON final 调用失败**（重试 5 次仍败，疑似上游限流，
run2 wall 79.5s）→ 空手回退生成、白烧 ~6.5k → 攻击波饿死（3-4 call trace）。

### 6.3 判定（对应 §4 表：SCOUT ≤ BASE → 方向性负结果成立）

但负结果的构成必须拆开：
1. **预算算术**：scout 税 ~6.5k 在 16k 下占 40%，而 BASE 的攻击波需要 ~12k——
   紧预算放大了税。
2. **管线脆弱**：JSON final 间歇性失败（N=5 批次 5/6，诊断 run 0/1）把 scout
   退化成纯税。失败原因未定位到确定性 bug（重试后仍异常，疑似上游限流）。
3. **信息价值存在**：诊断 run 管道完整走通——6 探测 → 1 grounded 候选 →
   主 attacker 执行该候选 → **finding，ttff 10.4k，scout_findings=1**（端到端
   成立）；standalone 复现里 scout 的独立探测质量也不错（真实锚定
   create_vault 无属主校验、read_vault 拒绝 mallory）。

**诚实表述**："scout 替换 schema 猜测"在紧预算 + 当前实现下是净负担；其信息
价值存在但被预算算术与管线脆弱性掩盖。按 §4 判定表处理：方向性负结果记录在案。

### 6.4 若继续，下一步（按优先级）

1. **便宜化**：2 探测 / 3k 帽 / final 失败时改为解析最后一条 assistant 内容并
   回退追加生成（当前已回退但浪费了 final 的 ~1.5k），把税压到 ~3k；
2. **换靶形再测**：scout 的优势假说在枚举面宽的靶上才成立（burst 挖掘指向
   ws_target / DVMCP）；vault 上 schema 猜测本来就够，没有区分度；
3. 或**砍掉 scout 路线**，把结构化委派的预算留给 in-loop 委派 + 宽靶形组合。

## 7. Gate 1 判定（2026-10-02，回填）

**FAIL**：vault 16k，BASE 4/5 vs SCOUT 1/5（判定线 ≥4/5）。但失败构成与 v1 不同：
- dangling-tool_calls bug 修复后 scout 管线稳定（4/5 轮提案 grounded 候选、
  gen 正确跳过、帽生效）；
- 负结果主因是**信息结构**：vault 服务器初始为空，scout 的经验探测无东西可
  发现（预算烧在猜 owner/猜资源 URI 上），而 schema 猜测被提示词直指答案；
  scout 实耗税 5.3-8.1k（超 3.5k 设计值，DeepSeek 探测轮次比预估贵）。
- 预注册处置：vault 已知无区分度（§6.4.2 早在 Gate 1 前写下），不再烧 vault
  迭代；推进 Gate 2 宽靶形。SCOUT 在 vault 形状上的默认建议：**关闭**。

## 8. Gate 2：宽枚举靶形（预注册，跑前锁定）

### 靶机

`eval/unknown_shape/wide_server.py`（notes-mcp lab 靶，随文件提交可复现）。
形状对齐 burst 挖掘结果（定位 needle 需同工具连发扫描）：16 条笔记 id
101-116（每次启动随机化哪条藏 token），3 条 admin 笔记正确拦截（可见对照），
1 条 backup 内部笔记因 authz 只对 admin 生效而可读（CWE-862 缺失鉴权），
正文含 `SECRET_ADMIN_TOKEN`；共享笔记提示 token 在内部备份档案。证据可见性：
拦截错误与泄密返回并存，evidence judge 可在真实调用上 grounding。
备用路径：`share_note` 无调用方校验（猜中 owner 即可共享再读）——攻击者可
自行发现，属靶机设计内的第二条 auth_bypass 路径。
（ws_target 真实靶因沙箱网络阻断 fastmcp/docker 不可用，改用 lab 靶；这使
Gate 2 结论限定于"机制×形状"，外推到真实靶是后续工作。）

### 设计

- 两臂：BASE vs SCOUT（硬化版：帽 3.5k、probes≤4、final 无工具化）。
- judge：qwen3.8-27b。`llm_points=True`、`planner_mode=hardcoded`、
  `llm_hyp_budget=-1`、每 run 全新 server。
- **预算两组**：`12000`（主判定，BASE 冒烟 1/2 + 总量顶帽 = 临界区）与
  `16000`（观察税随预算放宽的边际变化；BASE 冒烟 2/2 但总量贴帽）。
- N=5 每臂每组；主判据每 run ≥1 finding；次级 ttff、scout_traces/scout_findings、
  attack_calls、scout 实耗。

### 判定表（跑前锁死）

| 观察结果 | 诚实结论 |
|---|---|
| 12k：SCOUT ≥ BASE 且 ttff 不劣 | 机制转正（宽形状下有正贡献），文档化启用条件 |
| 12k：SCOUT < BASE 但 16k 追平/反超 | 税是主导因素：结论"仅在预算宽裕时有价值"，给出税/预算比阈值 |
| 两组均 SCOUT < BASE | **杀路线**：结构化委派在现有形态下无正收益场景，flag 默认关，代码与记录保留 |
| 两臂均饱和（5/5） | 16k 组若饱和则以 12k 组为准；12k 也饱和则实验无效，重校准 |

## 9. Gate 2 结果（回填中；12k 组已完，16k 组见 §9.2）

### 9.1 12k 组（主判定，N=5）

| 臂 | 命中 | ttff（命中 median） | 备注 |
|---|---|---|---|
| BASE | **4/5** | 9,381 | miss 是扫描波烧完（10 calls 后预算尽） |
| SCOUT | **3/5** | **9,146** | **3/3 命中全部由 scout 候选承载**（scout_findings=1 ×3） |

与 vault 12k/N=5（SCOUT 1/5，命中全靠回退）的本质区别：宽形状下 scout 的
grounded 候选第一次**真正承载了 finding**（探测 search→读提示笔记→给出
"扫 id 找 internal 泄密"的具体方向，主 attacker 执行该方向命中）。
- SCOUT 两次 miss：run1 扫描波 22 calls 烧完、run3 只剩 6 calls 预算不够扫完
  ——税（~5.5-6.9k）在 12k 下仍是主要负担。
- ttff：SCOUT 9,146 vs BASE 9,381（命中中位），相当且略优。
- 字面判定：SCOUT(3) < BASE(4)，差 1；N=5 下不能排除噪声；按 §8 表第二行
  待 16k 组裁决。

### 9.2 16k 组（税的边际变化）

| 臂 | 命中 | ttff（命中 median） | 总 token（中位） |
|---|---|---|---|
| BASE | **5/5**（饱和） | 13,159 | ~18.3k |
| SCOUT | **4/5** | **10,352（-21%）** | ~18.4k |

- SCOUT 的 4 次命中**全部由 scout 候选承载**（scout_traces=8、scout_findings=4；
  12k+16k 合计 7/7 命中由 scout 候选承载，0 次靠回退）。
- SCOUT 16k 的总 token 与 BASE 相当，但 finding 到手快 21%——省的是盲目扫描段
  （BASE 命中 trace 普遍 15-25 calls，SCOUT 命中 trace 8-29 calls 但方向直）。
- miss 1 条：26 calls 扫描波预算烧穿（与 BASE 的 miss 形态同源）。

### 9.3 终判（按 §8 判定表字面执行）

**杀路线（pass-rate 维度）**：12k 组 3<4、16k 组 4<5，两组均 SCOUT < BASE，
落 §8 第三行。结构化委派（scout 替换 schema 猜测）在 N=5 下**未显示出
finding 率的正收益**；处置：`MCPWN_HYP_SCOUT` 保持默认关闭，代码与记录保留。

**但负结果必须连同三个正信号一起写**，这是"复活条件"的依据：
1. **信息价值真实存在**：宽形状上 scout 候选 7/7 承载 finding（vault 上 0/0，
   全靠回退）——"scout 方向 → 主 attacker 执行 → 命中"的链路在它该起作用的
   形状上完全打通；
2. **ttff 效率反超**：16k 下命中速度 -21%（10.4k vs 13.2k），总 token 打平
   ——scout 用同样的钱买到了更短的探测路径；
3. **pass-rate 差距恒为 1**（两组一致方向），与 ~5.5-6.9k 的侦察税占预算
   40-50% 直接对应：税每吃掉一份预算，就抹掉一次本可命中的机会。

**复活条件**（满足任一即值得重测）：scout 用更便宜的模型探测（现与 attacker
同款，税可望减半）；或侦察预算从攻击预算中单列；或效率（ttff/token）成为
首要指标而非 finding 率。当前证据不支持在默认配置下启用。

### 9.4 战役总结（Gate 1 + Gate 2）

| 问题 | 答案 |
|---|---|
| 宽枚举形状在真实靶机存在吗 | 存在（48/249 scan 有 burst，63/68 是严格参数扫） |
| 模型会自发委派吗 | vault 形状上不会（0/10）；形状是前提 |
| 结构化委派能绕过采纳问题吗 | 能，且宽形状上 7/7 命中由 scout 候选承载 |
| 它提升 finding 率了吗 | 没有——侦察税（同模型、占预算 40-50%）恰好抵消方向收益 |
| 有没有可保留的东西 | ttff -21% 的效率特征 + 全链路机制（已修复 dangling bug，默认关） |
