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

- **不在 McPwn 的 12 个 vuln class 里**（没有"访问控制逻辑"类）；
- **信号库零命中**（已实测：`run_all_signals` 对 exploit trace 返回 `[]`）；
- recon 会把它误判成 path_traversal（读工具 + 名字参数），把 attacker 带偏。

## 三阶段实验协议

| 阶段 | 内容 | 判据 |
|---|---|---|
| 1 baseline（本轮已跑） | 当前 agent 扫 vault | 0 findings（结构性漏） |
| 2 LLM 增量（item 3） | 加 LLM 证据判定 / 假设生成决策点 | ≥1 finding（读到他人 secret） |
| 3 重复 | 同 seed 同 budget N≥3 次 | llm 版至少多 1 个 finding，严格更优 |

## Stage 1 结果（2026-08-06，hardcoded planner，30k tokens）

```
stop: budget_tokens  traces: 1  findings: 0
trace: path_traversal / read_vault  attack_calls: 22
```

Trace 实录：attacker 被 path_traversal 卡住，22 次调用全在试
`../../etc/passwd`、`%2e%2e%2f`、反斜杠、marker 名字，甚至建了一堆
穿越样式的 vault 再读回；**从未尝试 `owner=""` / 子串 owner**。
确定性前提（信号库零命中）与端到端 baseline 双重确认：当前 agent 漏。

## 用法

```bash
# 1. 起靶机（本机 SSE）
python eval/unknown_shape/vault_server.py

# 2. 确定性 exploit 证明
python eval/unknown_shape/prove.py          # 期望 PASS

# 3. baseline 扫描复现
python eval/unknown_shape/run_baseline.py   # 期望 findings=0
```

## 给 item 3 的增量判定标准

LLM 增量实现后，判定标准与 M3 相反——**必须严格更优**：
- llm 版在 vault 上 ≥1 finding，且
- 证据必须是 `read_vault(owner="")`（或子串 owner）返回了非本人 secret，
- 同 budget 重复 N≥3 次，miss 一次即 fail。

这就是 M3 判据缺的那条"能证伪"的闸门。
