# Prompt Injection 覆盖缺口分析

- **日期**: 2026-07-30 (v2, L0/L1/L2 分层重写)
- **范围**: `agent-first` 重构后,`direct_prompt_injection` / `indirect_injection`
  两类漏洞在 McPwn 当前实现下的可验证性分析
- **结论**: agent-first 下 McPwn **能覆盖 L0/L1 (server 侧攻击面存在性)**,
  **不覆盖 L2 (下游 LLM 真被带偏)**。L0/L1 是主流做法(类比 SQL injection
  只需证明 payload 污染查询,不必等实际泄露);L2 需要接 victim/judge LLM,
  是可选增强,不是必需。原文档 v1 "prompt injection 打空" 的判断是错位的。

---

## 0. v1 → v2 差异

v1 的核心错误: 把 prompt injection 的验证等同于「下游 LLM 真被带偏」(L2),
因此宣称 agent-first 下这两类漏洞「大半打空」。这个前提站不住:

- 类比 SQL injection: 只需证明 payload 污染查询即可,不必等实际数据被拖走
- 类比 XSS: 只需证明 script 被存进 DOM,不必等浏览器真的执行它
- Prompt injection 同理: 只需证明 server 存在「原样接受/存储/回显」用户输入的
  攻击面,这就是 L0/L1。下游 LLM 是否被带偏是可推论、不需现场验证

v2 引入 L0/L1/L2 分层,重新审视两类漏洞的实测现状。**结果不是"打空"而是
"覆盖 L0/L1,L2 是可选增强"**。同时补齐 `stored_injection_roundtrip` 信号
落地 L1 判据。

---

## 1. 能力分层框架

Prompt injection 的验证按攻击面深度分三层,各层判据不同:

| 层级 | 攻击面 | 判据 | 需要 victim LLM 吗 |
|---|---|---|---|
| **L0 — 输入面** | server 接受未清洗的注入串 (长度/字符集/schema 校验缺失) | 含注入标记的输入被 server 接收并反映在响应中 | 不需要 |
| **L1 — 传播面** | 注入串被 server 存储/回显/污染 state,跨会话可读 | 写-读往返标记串仍在;或被广播进 tool description | 不需要 |
| **L2 — 下游影响面** | 消费方 LLM 被带偏,越权调用/泄露 | LLM 行为偏离原任务,执行了注入指令 | 需要 |

**McPwn 当前覆盖**: L0 ✅, L1 ✅ (新增 `stored_injection_roundtrip` 信号), L2 ❌
(`llm_judged_injection` 未接线,策略卡标注为进阶)。

---

## 2. agent-first 架构下 prompt injection 还能打什么

Agent-first 砍掉了常驻 victim LLM,但这不意味着 prompt injection 不可测。
以下攻击面**不需要 LLM 在场**:

**Reflected injection** (L0, 回显注入):
- 用户可控参数值被 server 原样放进 tool result 或 resource 响应
- 判据: 提交 `INJECTION_MARKER_xxx`, 看返回里是否出现该标记
- 对应真实漏洞: 任何 MCP client (Cursor, Claude Desktop) 读到含指令的 tool
  result 有非零概率被带偏。**不需要重现这个概率, 证明 server 存在回显面即可**。

**Stored injection** (L1, 存储型注入):
- 写入类 tool (`add_note`, `save_document`) 接受含注入标记的内容;另一路径
  读回时标记串未被清洗
- 判据: `stored_injection_roundtrip` 信号 — 写-读往返后标记串仍在
- 对应真实漏洞: 下游 LLM 读 notes 时被污染,跨会话影响

**Tool poisoning** (L1, 工具描述污染):
- `list_tools` 返回的 description 在攻击前后不一致,或本身含嵌入指令
- 判据: `tool_description_drift` 信号 (已存在)
- 对应真实漏洞: 任何 client 的 `list_tools` 返回含嵌入指令的 description,
  下游 LLM 决策时被影响

**McPwn 当前架构完全可测的是 L0+L1**。L2 (LLM 真被带偏) 需要额外组件。

---

## 3. `direct_prompt_injection` 的覆盖现状

| 子类型 | 覆盖层级 | 判据 | 对应 detector |
|---|---|---|---|
| Reflected | L0 ✅ | 标记串回显 | `stored_injection_roundtrip` (同 call 回显) |
| Stored | L1 ✅ | 写-读往返标记串未清洗 | `stored_injection_roundtrip` (跨 call) |
| Poisoning | L1 ✅ | tool description 不一致 | `tool_description_drift` |
| 带偏 LLM | L2 ❌ | 行为偏离原任务 | `llm_judged_injection` (未接线) |

**策略卡已更新**: Playbook 从 pair 模式话术改为三条 L0/L1 探测路径。
不再使用 `Ignore previous instructions` 话术 (原话术是写给 LLM 看的,
对 server 测回显/存储不必要),改用 `INJECTION_MARKER_*` 纯标记串。

---

## 4. `indirect_injection` 的覆盖现状

| 子类型 | 覆盖层级 | 判据 | 对应 detector |
|---|---|---|---|
| 污染载体存在性 | L1 ✅ | 用户可控文本写入后再读回,指令标记串未清洗 | `stored_injection_roundtrip` |
| 污染工具描述 | L1 ✅ | 写入后 `list_tools` 描述不一致 | `tool_description_drift` |
| 下游 LLM 被带偏 | L2 ❌ | 行为偏离原任务 | `llm_judged_injection` (未接线) |

**策略卡已更新**: Objective 从"让 LLM 改变行为"改为"验证 server 是否存在
污染载体",判据是 server 侧 IO 可观测行为。

---

## 5. 关于 `llm_judged_injection` 信号 (L2)

`llm_judged_injection` 是 L2 信号的唯一 candidate。它在 `detectors.py` 中占位
(返回 None),不注册在 `DETECTORS` 中,因此 `run_all_signals` 不跑它。

要接上它有两种方式,都不是当前 M2 必过项:

- **方案 A (judge LLM 二审)**: 在 verifier 中用 judge LLM 审 attacker 的
  `final_llm_output`,判定「attacker 是否偏离攻击任务执行了注入指令」。
  需要先改 attacker system prompt 把角色从"纯攻击"改为"良性任务 + 注入 payload",
  否则 judge 无法区分「被注入带偏」vs「任务内行为」。代价低,但覆盖有限。

- **方案 B (victim LLM 回归)**: 在 executor 外层加一层 victim LLM。
  attacker 生成 payload → victim (DeepSeek + MCP 工具) 执行 → 观察 victim 是否
  被带偏。代价高,覆盖完整,违背 agent-first 简化初衷。

`HANDOFF §8` 把 9006 / 9010 列为 bonus,不进 M2 必过。当前进度期望:
8/10 必过项 (缺 9006 indirect, 9010 chain) 即可出门。9001 direct 在 v2 下
以 L0/L1 判据通过,不再依赖 leak 信号近似。

---

## 6. 结论

1. **McPwn 能测 prompt injection 的 L0/L1,且这些层面对 server 审计有独立价值。**
   `stored_injection_roundtrip` 信号 + 策略卡更新 已补齐这一层。
2. **L2 的缺失是能力边界,不是 bug。** 需要 victim/judge LLM,是可选增强。
3. **`direct_prompt_injection` 策略卡的操作路数换成了三路径 (Reflected /
   Stored / Poisoning),不再依赖 LLM 行为。** 判据更精确、误报率更低。
4. **`indirect_injection` 策略卡的判据从"LLM 行为改变"换成了"server 侧
   污染载体存在性"。** 判据可观测、可复现,不依赖随机性。

对外叙事建议: 覆盖 7 类 (L0/L1 完整;prompt injection 类 L2 未覆盖,
作为 bonus feature 待接 judge LLM)。避免笼统的 "7 类通用" 表达。

---

## 7. 相关文件索引

- `mcp_redteam/vulns/cards/direct_prompt_injection.md` — v2 已更新,三路径 L0/L1
- `mcp_redteam/vulns/cards/indirect_injection.md` — v2 已更新,server 侧判据
- `mcp_redteam/signals/detectors.py` — 新增 `stored_injection_roundtrip` 信号 (E 节)
- `mcp_redteam/signals/AGENTS.md` — 已更新,反映新信号
- `tests/signals/test_signal_meta_matches_detectors.py` — 新增 fixture
- `mcp_redteam/agent/verifier.py` — 无改动 (L2 judge 保持占位)
- `mcp_redteam/victims/AGENTS.md` — v0 遗留契约, 待标 DEPRECATED (跟踪)
- `HANDOFF.md §6` — 信号列表: v1 12 条 → v2 12 (M0-M2 必需) + 3 (M2 扩展含
  `stored_injection_roundtrip`)
- `HANDOFF.md §8` — 9006/9010 维持 bonus (不阻塞 M2)
- `README.md:8` — 过时的「DeepSeek 作受害者 LLM」描述待更新
