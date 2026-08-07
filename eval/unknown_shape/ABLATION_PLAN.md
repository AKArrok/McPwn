# 提示词消融实验方案（vault-mcp 三决策点）

> 状态：**方案已评审，实施中**。实施后本文件即成为协议的一部分，判据在跑之前锁死。
> 评审决定（2026-08-06 会话）：① B/C 臂归因改三分法（见 §4）；② 主设计改**串行 gate**（先 A 后 D，见 §3）；③ 泄漏清单补全 evidence_judge 判据 3 的 `owner=""` / 非属主 owner；④ loader 加 fail-fast（prompts 缺失即崩，cards 缺失回退+warning）；⑤ 预检加双向 diff（防剥过头）。
> 对应问题：Stage-3 的 3/3 PASS 里，LLM 的价值到底是「发现」还是「执行」？

---

## 1. 要回答的问题

现有 3/3 PASS 有一个没排除的解释：**提示词里明写着答案**（"子串匹配 / 空 owner / CWE-639"）。
如果真是这样，3/3 只能证明「提示词给了模式时，LLM 能执行」，不能证明「LLM 能从通用能力里
发现新形状」。本消融把提示词里的答案模式剥掉，重跑同样的 strict-better 判据，看三个决策点
还能不能找回 vault 漏洞。

**一句话**：剥掉答案后 3/3 仍成立 → 能力成立；剥掉后挂 → 提示词承载答案，诚实结论改写为
「LLM 执行 > 发现」。

---

## 2. 提示词泄漏点清单（消融对象，先枚举）

LLM 实际能看到的提示词里，含 vault 答案模式的共 **4 处**：

| 文件 | 泄漏内容（行号来自当前 HEAD） | 剥离后保留什么 |
|---|---|---|
| `attackers/agents/hypothesis_system.md` | L19 示例"试 owner='' 或非属主名字"；L28"校验可能是子串、前缀、默认值、空值绕过 (CWE-639)" | 保留"访问控制逻辑缺陷归 auth_bypass"类目映射（这是分类学，不是答案）；保留"owner/user/role 语义但 schema 无约束"这类**类级推理提示**（不点破具体技巧） |
| `attackers/agents/retrospective_system.md` | L16 示例"下一步试 owner=''"；L25"有没有'空值 / 默认值 / 子串 / 前缀'这类服务端逻辑绕过没试过?" | 保留复盘视角：被错误归类带偏？参数语义没被正确利用？响应里有反常信息被忽略？（都是推理提示，不含技巧） |
| `attackers/agents/evidence_judge_system.md` | L13"例如本应被拒绝的越权读取却返回了 secret"（判据 1 的带例子表述）；L14"空 owner / 非属主 owner 读到了他人数据 (CWE-639)"；L18"如 `owner=""` 或"；L19 示例"空 token / 越界路径" | **必须保留 grounding 规则**（evidence 必须是真实调用 result_text 的逐字子串、必须指向真实 index）——这是防幻觉机制，不是漏洞提示；保留判据 1"应被拒却返回敏感内容"（不带例子）、判据 3"参数本身能说明越权"（不带例子） |
| `vulns/cards/auth_bypass.md` | L11"先用**空 token** 调一次"；L12"换...**空串**..."；Objective"以**空 / 伪造 / 弱结构**凭据触发" | 保留 Playbook 骨架（试弱凭据→观察通过/拒绝→追加敏感动作→`admin-console/root/internal` 系统参数、32-hex 随机串、已知用户名）——这些是通用鉴权绕过套路，不是 vault 的技巧；去掉所有"空"候选与 `{"auth_token": ""}` 模板 |

**明确不是泄漏源**：`attacker_system.md`（通用人格，L9 只有"绕过/注入方向"泛化指引）；
`read_vault` 工具描述（"Read the secret stored in a vault by name."，无提示）；
`README.md` / `HANDOFF_NEXT.md`（LLM 不读，只给人类）；`chain_composition.md` 里的"子串"
（指链式证据拼接，与本漏洞无关）。

剥离规格 = 去掉上表"泄漏内容"列的全部文字，其余原样保留。

---

## 3. 消融设计：2×2 四臂（判据锁死，与 Stage 3 同门槛）

- **X 轴** = 三决策点提示词（hypothesis / retrospective / evidence_judge）：`HINTED`（当前版）vs `STRIPPED`（剥离版，保留类级框架）
- **Y 轴** = `auth_bypass` 策略卡：`HINTED`（当前版）vs `STRIPPED`（去空值候选）

| 臂 | X（决策点提示词） | Y（策略卡） | 回答的问题 |
|---|---|---|---|
| **A**（对照） | HINTED | HINTED | 复现 3/3；同时验证新配置（证据判定改用 doubao judge、每 run 全新 server）下 3/3 是否保持——历史 3/3 的证据判定用的是 attacker 模型，所以 A 不是浪费，是必需基线 |
| **B** | STRIPPED | HINTED | 决策点提示词是不是答案载体？（假设生成若剥了提示就提不出 auth_bypass，卡再强也白搭） |
| **C** | HINTED | STRIPPED | 策略卡是不是答案载体？（候选提出来后，attacker 没有卡上的"空"套路还能不能执行出 owner=''） |
| **D** | STRIPPED | STRIPPED | **主问题**：全剥离后三决策点还能不能发现并确认这个漏洞 |

**判据（同 Stage 3，一字不改）**：每 run ≥1 finding（读到非本人 secret）；同 budget（30k attacker）、
每 run 全新 vault server；N=3；miss 一次即 fail。seed 照实记录（DeepSeek 不支持时留 None，
漂移用 `attack_messages_sha1` 度量）。

**主设计（串行 gate，预注册）**：先跑 A(3)，判定"实验有效"后才烧 D(3)。
- A 非 3/3 → 实验无效，先修配置/环境（doubao judge / fresh server 是首次组合），**不跑任何剥离臂**——D 白烧 ~100k token 的代价不值得并行省那 15 分钟；
- A 3/3 → 跑 D(3)：D 3/3 → 能力成立，结论可直接写，B/C 为可选项；
- D 挂 → 补跑 B(3) + C(3)，用判定表定位答案在 X 侧还是 Y 侧。

---

## 4. 判定表（跑之前锁死，禁止事后改）

| 观察结果 | 结论 | 对外的诚实表述 |
|---|---|---|
| A 非 3/3 | 实验无效 | 配置/模型/环境变了（证据判定模型已换 doubao），先修再谈消融 |
| D 3/3 | 能力成立 | "三决策点能在不给答案模式的前提下，从类级框架里发现子串鉴权缺陷（vault）" |
| D<3/3 且 B 3/3 | 答案（至少部分）在卡片侧 | **三分归因**：① 套路直接命中——卡上有答案参数（如 `auth_token=""` 恰好是洞），纯执行；② 套路迁移——卡只给"空串"套路，LLM 迁移到 owner 参数（卡上根本没有 owner 参数），**含弱发现成分**；③ 类级推导——无套路自己想到。只有 ① 才支持"执行>发现"，② ③ 都要写进结论 |
| D<3/3 且 C 3/3 | 答案在决策点提示侧 | 卡片不是关键，hypothesis/evidence 提示承载了答案。注意：C 臂 X 未剥、X 直接点名 owner=''，3/3 是**弱证据**（预期内），信息量低 |
| D<3/3 且 B、C 都<3/3 | 两侧都承载 | 全量提示才有效；LLM 目前"执行>发现"，需要改提示词教推理或换验证路径 |

> 注：N=3 是小样本。若 D 3/3，可选把 D 扩到 N=5 复核（防单次运气）；判定以 N=3 为准，N=5 是加分项。

---

## 5. 实现机制（不动生产提示词）

1. **加载器加 override 目录**：提示词/卡片加载改为"override 目录优先"。
   - env `MCPWN_AGENTS_OVERRIDE_DIR`：同名覆盖 `hypothesis_system.md` / `retrospective_system.md` / `evidence_judge_system.md`（llm_points.py 的 `files(...)` 加载点）
   - env `MCPWN_CARDS_OVERRIDE_DIR`：同名覆盖 `auth_bypass.md`（vulns/registry.load_card）
   - 在模块 import 时读一次 env（每 run 一个子进程，env 天然隔离），不改成运行时重读，避免动执行路径性能。
   - **fail-fast**：prompts override 文件缺失/不可读 → raise（静默回退会把 STRIPPED 臂悄悄跑成 HINTED，全实验作废）。cards override 缺失 → 回退生产 + loud warning（本消融只覆盖 `auth_bypass.md` 一张卡，其余 7 张卡回退生产是正确行为）；消融关键文件的存在性由预检断言（见 3）。
2. **剥离版文件**放 `eval/unknown_shape/ablation/prompts/*.md` 与 `ablation/cards/auth_bypass.md`（提交进仓库，可复现）。
3. **防泄漏预检（跑任何 run 之前，双向）**：
   - **残留检查**：对剥离文件 grep 禁止 token——`子串|前缀|空值|空 owner|空串|空 token|owner=''|CWE-639|非属主`，命中任一即 fail 并拒绝开跑；
   - **过头检查**：对每对 (HINTED, STRIPPED) 逐行 diff，断言 STRIPPED 中缺失的行 == `ablation/manifest.json` 预期的删除行（按子串匹配），且非删除行全部保留。防手滑把类级框架也删了——那会把 D 挂误归因为"能力不足"（假阴性）。
4. **`run_ablation.py`**：按臂 spawn 子进程（每 run 一个，内部 `fresh_vault_server` + `scan(seed=..., llm_points=True)`），收 `scan_result.json`，汇总成判定表。每个 run 记录：arm / seed / port / findings / confidence / 命中信号（`llm_evidence_verdict` 还是别的）/ stop_reason / attacker+judge tokens / `attack_messages_sha1` / git_sha。
5. 生产提示词零改动：git diff 里只有 ablation/ 新增 + loader 的 override 分支。

---

## 6. 成本与时间

| 方案 | runs | 约 token | 墙钟 |
|---|---|---|---|
| A+D（主设计） | 6 | ~210k（每 run 30k attacker + 5k judge） | ~30min |
| 全 2×2 | 12 | ~420k | ~60min |

DeepSeek-v4-flash 便宜；`_rate_limit_wait`（2s 间隔）已内置。跑之前确认 .env 里有 DEEPSEEK_API_KEY 与 ARK_API_KEY。

---

## 7. 诚实边界（写结论时同时写进 README）

1. **只证 vault 一种形状**。D 过只说明"子串鉴权"这一类可被发现；换非子串鉴权 / delegate 语义 / SSRF 形状是否成立是**下一个实验**（泛化验证），消融不替代它。
2. 样本量 N=3；D 过时用 N=5 复核降低运气解释。
3. 证据判定的 grounding 诚实性（run-0 负例：path_traversal 误判 trace 上 is_finding=false）不在本消融范围——那是防幻觉机制，已有单测锁定。
4. A 臂同时承担"新配置回归"职责：证据判定模型从 attacker 换成 doubao、server 从共享内存态换成每 run 全新，这两处改动本身就可能改变 3/3，必须先复现。
5. 消融只动 LLM 可见的提示词；人类文档里的答案描述不影响 agent 行为。
6. **D 3/3 的结论强度限定"类级框架提示下"**：剥离版 hypothesis 仍保留"工具带 owner/user/role 语义但 schema 无约束"（L29-30 原文）——攻击面被指到 owner 参数。D 3/3 的诚实表述是"在不给具体技巧（子串/空值/前缀）的前提下，LLM 能从类级框架发现子串鉴权缺陷"，不是"零引导冷启动发现"。
7. **B 臂三分归因 + judge 也是被测对象**：B 3/3 若来自"套路迁移"（卡给空串套路、LLM 迁移到 owner 参数），写结论时不能归为纯执行；且剥离版 evidence_judge 必须**不带例子**认出 `owner=""` 返回敏感数据是越权——judge 环节的泛化认账能力也是结果的一部分，B 3/3 时尤其要记得 judge 也参与了。

---

## 8. 交付物

1. `eval/unknown_shape/ablation/`（剥离版 prompts + cards + `manifest.json` + `run_ablation.py` + `run_one.py`）+ loader override 分支
2. `runs/unknown_shape_ablation/`（每 run scan_result.json + 汇总判定表）
3. 结论写回 `eval/unknown_shape/README.md`（"能力 vs 提示词"定论）与 `HANDOFF_NEXT.md`
4. 若 D 挂：结论为"当前 LLM 执行>发现"，下一步二选一：改提示词教推理（把"如何推理逻辑型缺陷"而非"答案"写进去）或直接跳到泛化验证（换形状，绕开 vault 提示词问题）
