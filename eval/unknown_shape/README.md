# Unknown-Shape Target: vault-mcp (CWE-639 access-control logic flaw)

实验目的：给"LLM 提能"一个**可证伪**的检验台。前提是当前 agent
（hardcoded planner + 固定信号库）**结构性漏掉**某个真实漏洞，而加了
LLM 决策点（假设生成 / 证据判定）后能**找到**。M3 的教训是不能用
"不劣于"判据自证——所以这个实验的判据是严格更优（baseline=0）。

## 靶机：vault-mcp

`vault_server.py`，FastMCP SSE on `http://127.0.0.1:9205/sse`，4 个工具：

- `create_vault(owner, name, secret)` — 建 vault
- `read_vault(owner, name)` — 读 secret
- `list_vaults(owner)` — 列出可读 vault
- `grant_access(owner, name, delegate)` — 授权

### 漏洞形状（为什么是 unknown-shape）

`_can_read` 用**子串匹配**而非精确匹配做归属校验：

```python
if requested_owner in owner or owner in requested_owner:  # BUG (CWE-639)
    return True
```

`"" in "admin"` 为 True → `read_vault(owner="", name="admin_vault")` 直接返回
admin 的 secret。这是服务端特定的访问控制逻辑错误：

- **不在 McPwn 的固定 vuln class 集里**（没有"访问控制逻辑"类）；
- **信号库零命中**（已实测：`run_all_signals` 对 exploit trace 返回 `[]`）；
- recon 会把它误判成 path_traversal（读工具 + 名字参数），把 attacker 带偏。

## 三阶段实验协议

| 阶段 | 内容 | 判据 | 状态 |
|---|---|---|---|
| 1 baseline | 当前 agent 扫 vault（hardcoded planner + 固定信号库） | 0 findings（结构性漏） | ✅ 0 findings |
| 2 LLM 增量 | LLM 三决策点：假设生成 / 复盘 / 证据判定 | ≥1 finding（读到他人 secret） | ✅ 2 findings |
| 3 重复 | 同 budget、记录 seed、每 run 全新 server N=3 | 每 run ≥1 finding，miss 即 fail（严格更优） | ✅ 3/3 PASS |
| 4 提示词消融 | 剥掉答案模式重跑判据（2×2 预注册，协议见 ABLATION_PLAN.md） | D(3) 3/3 = 能力成立 | ✅ A 3/3 + D 3/3 |

## Stage 1 结果（2026-08-06，hardcoded planner，30k tokens）

```
stop: budget_tokens  traces: 1  findings: 0
trace: path_traversal / read_vault  attack_calls: 22
```

Trace 实录：attacker 被 path_traversal 卡住，22 次调用全在试
`../../etc/passwd`、`%2e%2e%2f`、反斜杠、marker 名字，甚至建了一堆
穿越样式的 vault 再读回；**从未尝试 `owner=""` / 子串 owner**。
确定性前提（信号库零命中）与端到端 baseline 双重确认：当前 agent 漏。

## Stage 2 结果（2026-08-06，30k attacker budget）

LLM 只在三个点上线（**没有**做排列，M3 教训）。全部提示词外置
`mcp_redteam/attackers/agents/{hypothesis,retrospective,evidence_judge}_system.md`：

| 点 | 时机 | 职责 | 预算 |
|---|---|---|---|
| 假设生成 | recon 后（2 次独立采样 union） | 提出 recon 正则漏掉的逻辑型假设（owner 子串校验绕过），score 0.99 排最前 | attacker |
| 复盘 | 第一波 0 命中且剩余预算 ≥8k | 看失败 trace，指出被带偏原因，提下一步具体尝试 | attacker |
| 证据判定 | 信号库 0 命中的 trace | 判定真实调用是否有证据；**grounding 闸门**：evidence 必须是真实调用返回的逐字子串，绝不引用总结文本 | judge（带外） |

```
findings=2 stop=budget_tokens attacker_tokens=31658 judge_tokens=5128
- AUTH_BYPASS read_vault    0.75  read_vault(owner="") 返回 admin secret；非属主 alice 被拒
- AUTH_BYPASS grant_access  0.75  非属主成功 grant 读权限
```

证据判定在 baseline 的 path_traversal 误判 trace 上诚实返回 is_finding=false
（只有合法 owner='admin' 读取 + 失败的穿越尝试），证明它不会为凑 finding 编造。

## Stage 3 结果（同 seed 同 budget N=3）

**第一轮 2/3 FAIL**（run 0 漏）。根因：假设生成**单次采样**没提出 auth_bypass
假设 → attacker 被 recon 的 path_traversal 误判带偏、烧穿 30k 预算 → 复盘因
`budget.exceeded` 闸门被自己关掉（接线 bug）。证据判定本身 3/3 诚实。

修复（**不是改判据**，判据"每 run ≥1、miss 即 fail"原样保留）：
- 假设生成改 **2 次独立采样 union**（降单采样方差，仍是同一个决策点，token 记 attacker）
- 复盘闸门从"预算未超"改**剩余预算 ≥8k margin**（安全网不再被饿死）
- 加原始 LLM 输出 INFO 日志，实验可复盘可复现

**第二轮 3/3 PASS（严格更优）**：
```
run 0: findings=2 (read_vault, grant_access)
run 1: findings=2 (read_vault, list_vaults)
run 2: findings=2 (read_vault, list_vaults)
```

## 用法

```bash
# 1. 起靶机（本机 SSE）
python eval/unknown_shape/vault_server.py

# 2. 确定性 exploit 证明
python eval/unknown_shape/prove.py          # 期望 PASS

# 3. baseline 扫描复现
python eval/unknown_shape/run_baseline.py   # 期望 findings=0

# 4. Stage 2: LLM 三决策点
python eval/unknown_shape/run_llm.py        # 期望 findings>=1

# 5. Stage 3: 重复 N 次, 严格更优 (每 run 自动起全新 server, 无需手动起靶机)
python eval/unknown_shape/run_repeat.py 3   # 期望 3/3 PASS
#    可选: --seed N 透传 LLM seed (provider 支持时); --port-base 改起始端口 (默认 19205)
```

## 严谨性修复（2026-08-06，三坑）

第二段 3/3 PASS 之后，补了三处"实验可信度"修复，判据与结论不变：

1. **"同 seed"真实化**：`scan(seed=...)` 全链路透传（chat.py → ModelSpec →
   OpenAI-compatible `seed` 参数）并记录到 `ScanResult.seed`。DeepSeek 不支持
   `seed` 参数（models.yaml 默认不设），此时如实留 None，run 间漂移由
   `attack_messages_sha1` 度量；支持 seed 的 provider 可在 models.yaml 配置。
2. **状态隔离**：`run_repeat.py` 每 run 自动 spawn 一个全新 `vault_server.py`
   （`eval/unknown_shape/_fresh_server.py`，默认端口 19205+i），跑完即终止——
   不再让 run 0 建的 vault 泄漏到 run 1/2（旧版共享内存态是混淆变量）。
3. **证据判定模型**：证据判定默认用 `judge` 角色模型（doubao），judge 未配置时
   退回 attacker 模型并 loud warning；实际模型记录到 `ScanResult.evidence_judge_model`
   （token 无论哪种都记 judge，带外不占 attacker 预算）。
## Stage 4: 提示词消融（能力 vs 提示词，2026-08-06）

**要回答的问题**：Stage-3 的 3/3 PASS 里，LLM 的价值到底是「发现」还是「执行」？
提示词里明写着答案（"子串匹配 / 空 owner / CWE-639"）时，3/3 只能证明"提示词
给模式时 LLM 能执行"。消融把答案模式从 LLM 可见提示词里剥掉，重跑同样判据。
协议权威：`eval/unknown_shape/ABLATION_PLAN.md`（判据跑前锁死、预注册）。

**设计**：2×2 四臂。X 轴 = 三决策点提示词（hypothesis / retrospective /
evidence_judge），Y 轴 = `auth_bypass` 策略卡；HINTED = 生产版，STRIPPED = 剥离版
（去掉全部"子串匹配 / 空值 / 前缀 / owner='' / CWE-639 / 非属主"文字，保留类级
框架与 grounding 规则）。主设计**串行 gate**：A(3) 先跑验证新配置，过 gate 才烧
D(3)。防泄漏预检**双向锁死**：残留 grep + 逐行 diff vs manifest（防剥过头→假阴性）。

| 臂 | X | Y | 结果 | 作用 |
|---|---|---|---|---|
| A | HINTED | HINTED | **3/3 PASS** | 新配置回归（doubao judge + 每 run fresh server）——历史 3/3 跑在两处修复之前，A 是必需基线 |
| D | STRIPPED | STRIPPED | **3/3 PASS** | **主问题**：全剥离后三决策点仍能发现并确认漏洞 |

D 臂 6 个 finding 分布：read_vault×2 / grant_access×2 / list_vaults×1 /
create_vault×1（全是 auth_bypass 0.75）。

**结论（能力成立，限定表述）**：三决策点能在**不给具体答案模式**（子串匹配 /
空值绕过 / CWE-639 / owner=''）的前提下，从保留的**类级框架**（"owner 语义但
schema 无约束"）里发现子串鉴权缺陷并确认——LLM 的价值包含「发现」，不只是
「执行提示词里的答案」。B/C 臂按预注册规则不跑（D 3/3 时为可选项）。

**审计**：6 runs 全记录于 `runs/unknown_shape_ablation/summary.json`（arm / port /
findings / confidence / attacker+judge tokens / stop_reason / attack_messages_sha1 /
evidence_judge_model / override env / git_sha=ae6ff076）。judge 全程
doubao-seed-2.0-lite（带外计数）；seed=None（DeepSeek 不支持，漂移由 sha1 度量）。

**诚实边界**（ABLATION_PLAN.md §7）：
1. D 3/3 限定"类级框架提示下"——剥离版保留"owner/user/role 语义但 schema 无
   约束"类级推理提示，不是零引导冷启动发现。
2. 只证 vault 一种形状；换形状（非子串鉴权 / delegate / SSRF）是下一个实验。
3. N=3 小样本；D 3/3 可选扩 N=5 复核（加分项，未跑）。
4. judge 环节（剥离版 evidence_judge 须不带例子认出越权）也是被测对象，已通过。

**用法**：
```bash
python eval/unknown_shape/ablation/run_ablation.py --preflight-only  # 双向防泄漏预检
python eval/unknown_shape/ablation/run_ablation.py --arm A --n 3      # 单臂
python eval/unknown_shape/ablation/run_ablation.py --all              # 自动串行 gate: A→D→(B+C if D miss)
```

## 增量判定标准（已通过，2026-08-06）

与 M3 相反——**必须严格更优**：
- llm 版在 vault 上 ≥1 finding，且
- 证据必须是 `read_vault(owner="")`（或子串 owner）返回了非本人 secret，
- 同 budget 重复 N=3 次，miss 一次即 fail。

结果：**3/3 PASS**。这就是 M3 判据缺的那条"能证伪"的闸门。

诚实边界：单靶机 N=3 样本量小；换一种逻辑漏洞形状（非子串的鉴权缺陷、
delegate 语义）是否仍成立，是下一步该验的。
