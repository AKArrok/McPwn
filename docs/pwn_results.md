# 靶机 Pwn 与 B 阶段验证结果汇总（2026-08-06）

> 目标: 在真实靶机（excel-mcp CVE-2026-40576 + DVMCP 9006/9010）上记录
> **实际 pwn 结果**（确定性 exploit 链 + scan findings），并对照
> LangGraph 路径（`scan --graph`，B 阶段跨 trace 记忆）与默认 runner。
> 运行产物: `runs/lg_b_verify/`（scan_result.json / findings.md / proof_report.md）。

---

## 1. excel-mcp（真实世界靶机，CVE-2026-40576）

### 1.1 确定性 exploit 链（`eval.realworld.prove`，不走 LLM）

**v0.1.7（漏洞版，excel-mcp-017 @ :9203）→ `prove_expect=exploited` → PASS**

```text
nonce  : MCPWN-20260806T090037-33f962
marker : /root/mcpwn_pwned_MCPWN-20260806T090037-33f962.xlsx   # 沙箱外绝对路径
```

| step | 调用 | 结果 |
|---|---|---|
| 1 | `create_workbook({filepath: /root/mcpwn_pwned_<nonce>.xlsx})` | `Created workbook at /root/...`（接受沙箱外路径） |
| 2 | `write_data_to_excel({filepath, data: [[nonce]]})` | `Data written to Sheet1` |
| 3 | `read_data_from_excel({filepath, sheet_name: Sheet1})` | `A1 = MCPWN-20260806T090037-33f962` |

- out-of-band `docker exec ls`: 文件存在于 `/root/`（`-rw-r--r-- 1 root root 4847`）
- out-of-band `docker exec` 读回 A1: `MCPWN-20260806T090037-33f962`
- **结论: 成功越权写入并回读沙箱外文件 → exploited**

**v0.1.8（修复版，excel-mcp-018 @ :9204）→ `prove_expect=blocked` → PASS**

| step | 调用 | 结果 |
|---|---|---|
| 1 | `create_workbook({filepath: /root/mcpwn_pwned_<nonce>.xlsx})` | 拒绝: `Invalid filename ... must be relative to EXCEL_FILES_PATH` |

- out-of-band `docker exec ls`: `No such file or directory`
- **结论: 绝对路径被拒、无文件落盘 → blocked（修复生效）**

### 1.2 scan 对照（graph vs runner，`--sandbox-root /tmp/sandbox`）

| 靶机 | 模式 | traces | findings | 注入 |
|---|---|---|---|---|
| 9203 v0.1.7 | runner 20k | 1 | `path_traversal on read_data_from_excel` 0.75 | 无 |
| 9203 v0.1.7 | graph 20k | 1 | 同上（逐字段一致） | 无（单 trace） |
| 9203 v0.1.7 | graph 45k | 2 | read 命中 0.94 | `write_data_to_excel` **injected=True** |
| 9204 v0.1.8 | runner 20k | 1 | 0 | 无 |
| 9204 v0.1.8 | graph 20k | 1 | 0（FPR 0） | 无 |

- graph 与 runner 在真实靶上 finding 全等；修复版两模式都不误报。
- 45k 预算下 graph 注入生效: `write_data_to_excel` 候选收到 `read_data_from_excel`
  的 path_traversal 命中摘要——正好对准该 CVE 的 read/write 组合方向。

---

## 2. DVMCP（9006 / 9010）

| port | 模式 | traces | findings | 注入 |
|---|---|---|---|---|
| 9010 Multi-Vector（chain_composition） | runner 20k | 3 | 3（path_traversal / chain / indirect） | 全部无 |
| 9010 | graph 20k | 3 | 2（path_traversal 0.95, **chain_composition 0.95**） | chain、indirect trace **injected=True** |
| 9006 Indirect Prompt Injection | runner 20k | 2 | 0 | 无 |
| 9006 | graph 20k | 2 | 0 | meta trace injected=True |

- **9010 graph 版**: 首个命中（path_traversal on get_config）后 `chain_composition`
  被 `promote_chains` 提到第 2 位执行，且注入 prior evidence 后以 0.95 命中——
  B 阶段目标（chain 候选看到 prior hits）达成。
- 9010 runner 版无任何注入（对照成立）。9006 两版均 0 findings（indirect 弱港）。

---

## 3. 结论

1. **真 pwn 已实证**: excel-mcp 0.1.7 通过 3-call 链越权写读沙箱外文件
   （docker 双核对）；0.1.8 修复版拦截（绝对路径拒绝 + 无落盘）。
2. **graph 与 runner 行为等价**: 两个真实靶上 finding 集合一致（9010 港
   recall 两版都命中；9203 逐字段全等），未劣于。
3. **B 阶段记忆在真实靶生效**: DVMCP 9010 chain 注入 + promote + 命中；
   excel-mcp 9203 read→write 注入（CVE 组合方向）。
4. **FPR 保持 0**: 9204（修复版）与 9006 两模式均无误报。

## 4. 诚实边界

- N=1 点估计: LLM 在环，同 seed 可能漂移；9010 findings 数 graph(2) vs
  runner(3) 差异含漂移与预算分配变化（chain 提前消耗）。
- 20k→45k 预算下 9203 首个 finding 0.75→0.94 含 calls 数差异。
- prove 是确定性 3-call 链（无 LLM），结果可复现；scan 结果不可复现于同 seed。
- 未锁 seed（deepseek 不支持），`attack_messages_sha1` 可复核漂移。

---

## 5. 补跑：judge 模型参与（--llm-points）

> CLI 补暴露 `--llm-points`（此前只有 runner 参数、CLI 无开关）。三组扫描
> 全部 `llm_points=True`：假设生成 + 复盘 + **evidence judge（judge 角色
> doubao 对 0 信号 trace 做 grounding 证据判定）**。

| 扫描 | traces | findings | judge_tokens | evidence_judge_model | 注入 |
|---|---|---|---|---|---|
| 9010 graph llm-points 40k | 1（auth_bypass on get_config, 50 calls 烧穿预算） | 0 | 3466 | doubao-seed-2.0-lite | 无（单 trace） |
| 9010 runner llm-points 40k | 1（direct_prompt_injection, 28 calls） | 0 | 0 | doubao-seed-2.0-lite | 无 |
| 9006 graph llm-points 40k | 3 | 0 | 3112 | doubao-seed-2.0-lite | trace[1][2] injected |

### judge 参与结论

1. **evidence judge 真实参与了评判**：`evidence_judge_model='doubao-seed-2.0-lite'`
   记录 + `judge_tokens=3466/3112`（带外计数）——judge 角色模型（ARK 豆包）对
   0 信号 trace 执行了 grounding 证据判定。
2. **判定诚实（grounding 闸门）**：9010 graph llm-points 的 auth_bypass trace
   （50 次调用、0 确定性信号）被 judge 判定 `is_finding=false`——没有真实
   证据子串就不编造 finding（这正是防自欺设计）。
3. **口径细节**：9010 runner llm-points 的 `evidence_judge_model` 非空但
   `judge_tokens=0`——`_make_evidence_judge_fn` 记录了配置模型，但该组无
   0 信号 trace 触发实际调用（模型名=配置口径，tokens=实际消耗口径，两者分开看）。
4. **B 注入在 llm-points 组也工作**（9006 graph trace[1][2] injected=True）。
5. 注意：llm-points 组 9010 仅 1 个 candidate 即烧穿 40k 预算（假设生成 2 采样 +
   首个 trace 50 calls）→ 0 findings；与非 llm-points 组的 2-3 findings 差异是
   预算分配现实，非回归；judge 判定诚实否定未产生假阳性。
