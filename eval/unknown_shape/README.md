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
| 3 重复 | 同 seed 同 budget N=3 | 每 run ≥1 finding，miss 即 fail（严格更优） | ✅ 3/3 PASS |

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

# 5. Stage 3: 重复 N 次, 严格更优
python eval/unknown_shape/run_repeat.py 3   # 期望 3/3 PASS
```

## 增量判定标准（已通过，2026-08-06）

与 M3 相反——**必须严格更优**：
- llm 版在 vault 上 ≥1 finding，且
- 证据必须是 `read_vault(owner="")`（或子串 owner）返回了非本人 secret，
- 同 budget 重复 N=3 次，miss 一次即 fail。

结果：**3/3 PASS**。这就是 M3 判据缺的那条"能证伪"的闸门。

诚实边界：单靶机 N=3 样本量小；换一种逻辑漏洞形状（非子串的鉴权缺陷、
delegate 语义）是否仍成立，是下一步该验的。
