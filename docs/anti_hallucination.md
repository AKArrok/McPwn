# McPwn 防幻觉机制(anti-hallucination)

> 本文系统性地讲 McPwn 如何**防止 LLM 幻觉污染漏洞报告**。LLM(attacker /
> judge)在环上的每一步都可能"编造":attacker 可能在收敛轮凭空声称读到
> secret,judge 可能给出没有证据支撑的裁定。McPwn 的立场是:**LLM 的输出
> 永远不是证据,证据只来自真实 MCP 调用返回,由确定性信号库判定**。
>
> 这不是一个单一开关,而是一组**相互独立的防线**,每层防一种具体的幻觉形态。

---

## 0. 一句话

> **Grounding 闸门**:证据只能来自真实 `McpCall.result_text`;LLM 的最终文本
> 永不作证据来源。其余所有机制都是这条不变式的具体化。

---

## 1. 幻觉形态清单(按严重度)

McPwn 里 LLM 幻觉可能出现的五个位置,每种都有对应防线:

| # | 幻觉形态 | 位置 | 对应防线 |
|---|---|---|---|
| 1 | attacker 在收敛文本里"引用"一个**实际未被任何调用返回**的敏感串 | attacker `final_llm_output` | Grounding 闸门(§2) |
| 2 | attacker 声称"我拿到了 / 泄露了 X"但没有信号支撑 | attacker `final_llm_output` | `suspected_hallucination` 标记(§3) |
| 3 | L2 judge 声称"被注入带偏",但**指认的调用下标越界或不存在** | judge `evidence_call_index` | judge index 校验(§4) |
| 4 | 证据判定 LLM 给出 finding,但 evidence 不是真实调用返回的**逐字子串** | evidence judge `evidence_text` | 证据判定 grounding(§5) |
| 5 | 报告泄露真实敏感串(被检测到的 secret 明文进入 findings.md / PoC) | `matched_text` | 指纹化 redaction(§6) |

> 前四种是"假阳性"幻觉(没漏洞说成有漏洞),第五种是"信息泄露"幻觉
> (把真 secret 写进报告)。两者都防。

---

## 2. Grounding 闸门(第一道,也是最根本的)

**位置**:`mcp_redteam/signals/detectors.py` 的 `_scan_calls`。

```python
# Only scan McpCall.result_text, NEVER final_output.
# Scanning final_output would let a hallucinated secret produce a false
# finding from text the server never returned.
```

规则:

- leak/行为类 detector 只从 `call_tool` / `read_resource` 的 `result_text` 里取证据;
- `list_tools` / `list_resources` 的 description 里出现示例串**不算命中**;
- attacker LLM 的 `final_output` **永不作证据来源**——函数签名里保留
  `final_output` 参数只是为了 detector 契约统一,实际不扫;
- 因此每条 fired 的 leak/行为信号**必带非空 `source_call_index`**,
  指向 `recon_calls + attack_calls` 合并列表里的真实调用。

**防什么**:模型在收敛轮"引用"了一段实际未被任何调用返回的敏感串(典型幻觉)。
收敛轮提示词也配合改过:不再要求 LLM "逐字引用可疑串"(诱导幻觉),
改为"一句话总结探了什么、证据落在哪条 call"。

**代价与边界**:确定性信号库漏检的"未知形状"漏洞(信号库不认识)不会被
grounding 闸门补上——这是 2026-08 引入「证据判定 LLM」(§5)的原因。

---

## 3. `suspected_hallucination` 标记(校准,不定罪)

**位置**:`mcp_redteam/agent/verifier.py` 的 `_detect_claim_mismatch`。

检测逻辑:

```python
_LEAK_CLAIM_RE:    # root:x:0:0 | $6$ | BEGIN ... PRIVATE KEY | sk-... | flag{
_SUCCESS_CLAIM_RE: # successfully | leaked | obtained | extracted | ...

def _detect_claim_mismatch(trace, signals) -> bool:
    if not final_llm_output: return False
    if not _LEAK_CLAIM_RE.search(final): return False   # 声称拿到了敏感物
    if not _SUCCESS_CLAIM_RE.search(final): return False # 且声称已成功
    return not any(content_signal in signals)            # 但没有任何信号支撑
```

**规则**:

- 只有"声称**已成功**拿到敏感物"(`leaked` / `extracted` / `successfully` ...)
  且**零信号支撑**时才标记;`"I will try to read /etc/passwd"` 是计划,不标记;
- 标记落在 trace 上(`suspected_hallucination`),**永不创建或抬升 Finding**;
- 用途:校准与调试——统计模型幻觉率、定位收敛轮提示词问题。

**防什么**:形态 #2。它是 grounding 闸门的**诊断伴侣**:闸门防止幻觉成为证据,
这个标记让幻觉本身可被观测。

---

## 4. L2 judge 的 index 校验(防 judge 编造证据位置)

**位置**:`mcp_redteam/agent/verifier.py` 的 `_maybe_add_l2_signal`。

L2 judge(indirect/chain 类 trace 的 LLM 二审)输出
`JudgeVerdict(steered, evidence_call_index, reason)`,其中
`evidence_call_index` 声称"注入指令出现在第 N 条调用里"。judge 可能编造
这个下标(模型算错 / 幻觉)。处理:

```python
if idx is None or not (0 <= idx < len(all_calls)):
    _log.warning("L2 judge cited out-of-range evidence_call_index=%r ...")
    return  # 直接丢弃该信号,不追加 llm_judged_injection
```

**规则**:

- `evidence_call_index` 越界或不是 int → 该 judge 信号**整体丢弃**;
- 即使 steered=True 且 index 合法,`llm_judged_injection` 也只是 medium
  (0.5),单条**不过 0.6 阈值**,必须与确定性 L1 信号(如
  `stored_injection_roundtrip` / `tool_description_drift`)同 trace 共现
  才可能成 finding;
- judge 失败 / 返回不可解析 JSON → 视作 not-steered,不 crash、不定罪。

**防什么**:形态 #3。把 judge 幻觉的爆炸半径封顶——judge 顶多抬置信度,
无单独定罪权。

---

## 5. 证据判定 LLM 的 grounding(unknown-shape 场景)

**位置**:`mcp_redteam/agent/verifier.py` 的 `build_findings` +
`agent/llm_points.py` 的 `evidence_verdict`。

2026-08 引入的 Stage-2 决策点:当确定性信号库对某个 trace **零命中**时,
允许证据判定 LLM(judge 角色,带外预算)裁定"这个 trace 是否其实有漏洞"。
这是 grounding 闸门唯一的结构性例外,所以 grounding 规则被**显式写进契约**:

```text
LlmEvidenceVerdict.evidence_text 必须是 evidence_call_index 指向的
真实调用 result_text 里的逐字子串;绝不引用 attacker 的总结文本。
```

实现上的双重校验(parse + grounding 纯函数,有单元测试):

1. `evidence_call_index` 必须指向真实调用(同 §4 越界校验);
2. `evidence_text` 必须是该调用 `result_text` 的**逐字子串**——解析层就
   做 `in` 校验,不满足直接判 `is_finding=false`;
3. 即使 grounded,verifier 把判定映射为 **high (0.75) 合成信号**
   `llm_evidence_verdict`,仍走标准置信度机制,`confidence >= 0.6` 才进 findings;
4. run 0(无漏洞 trace)时判定诚实返回 `is_finding=false`——实测在 vault-mcp
   baseline 的 path_traversal 误判 trace 上,judge 拒绝编造 finding。

**防什么**:形态 #4,同时守住"unknown-shape 提能"的诚实边界——LLM 可以在
信号库漏检时发言,但必须引用**真实存在的返回内容**,且单独权重不够定罪。

---

## 6. 指纹化 redaction(防敏感串外流)

**位置**:`mcp_redteam/signals/detectors.py` 的 `_redact`。

```python
def _redact(matched: str, severity: Severity) -> str:
    ...
    digest = sha1(matched)[:10]
    return f"<redacted head={head!r} len={len(matched)} sha1={digest}>"
```

**规则**:

- critical / high 信号的 `matched_text` 一律指纹化:只留头部几字符 + 长度 +
  sha1 摘要,原文不外流;
- 因此 `findings.md` 与 PoC 脚本里**不会出现** `/etc/passwd` 明文、
  API key、SSH 私钥等敏感串;
- 指纹可用来核对"同一条证据"(sha1 相同),但不能反推原文。

**防什么**:形态 #5——防的是**报告污染**而不是假阳性:扫描打穿了,但人类
可读报告与可重放 PoC 不该把真实 secret 复制出去。

---

## 7. 置信度机制(幻觉的最终过滤器)

以上防线都过了,信号进了 `EvidenceSignal` 列表,还有最后一层数字闸门:

```text
confidence = 1 - prod(1 - w_i)        # 去重后
w: critical=0.95, high=0.75, medium=0.5, low=0.3
LLM 二审同意 += 0.1;反对 -= 0.2;封顶 [0, 1]
FINDING_CONFIDENCE_THRESHOLD = 0.6   # 低于此值只留 traces,不进 findings.md
```

作用:

- 单条 medium(0.5)信号**永远过不了 0.6**——必须多条叠加或 L2 抬升;
- L2 / 证据判定 LLM 的贡献被严格限定(§4/§5),**无法单凭 LLM 意见造出 finding**;
- 确定性信号(正则命中真实返回)是 finding 的主体,LLM 只是边缘校正。

---

## 8. 防线总览

| 防线 | 位置 | 防的幻觉 | 机制类型 |
|---|---|---|---|
| Grounding 闸门 | `signals/detectors.py:_scan_calls` | 编造敏感串(形态 1) | 确定性,证据只来自真实返回 |
| `suspected_hallucination` | `agent/verifier.py:_detect_claim_mismatch` | 声称无据(形态 2) | 诊断标记,不定罪 |
| judge index 校验 | `agent/verifier.py:_maybe_add_l2_signal` | 编造证据下标(形态 3) | 确定性,越界即丢弃 |
| 证据判定 grounding | `agent/verifier.py` + `llm_points.py` | 编造 evidence(形态 4) | 逐字子串校验 + 权重限制 |
| 指纹化 redaction | `signals/detectors.py:_redact` | 敏感串外流(形态 5) | 报告层脱敏 |
| 置信度阈值 | `contracts.py` + `verifier.py` | 所有形态的最终过滤 | 数值闸门 >= 0.6 |

**设计原则总结**:

1. **LLM 是执行者,不是裁判**——定罪权在确定性信号 + 数值阈值;
2. **每层防线独立**——破坏任何一层,其他层仍挡住大部分幻觉;
3. **LLM 可以发言,但必须引用真实存在的返回内容**;
4. **防幻觉的代价是漏检未知形状**,由受控的 LLM 决策点(§5)在严格 grounding
   下补足,而不是放开闸门。

---

## 9. 相关文档与代码

- `mcp_redteam/signals/AGENTS.md` — 信号库本地规约(Grounding 不变式)
- `mcp_redteam/agent/verifier.py` — `_detect_claim_mismatch` / `_maybe_add_l2_signal` / `build_findings`
- `mcp_redteam/signals/detectors.py` — `_scan_calls` / `_redact`
- `mcp_redteam/contracts.py` — `LlmEvidenceVerdict` / `SEVERITY_WEIGHT` / `FINDING_CONFIDENCE_THRESHOLD`
- `docs/pwn_results.md` §5 — evidence judge 在真实靶上的诚实判定记录
- `tests/test_verifier_minimal_poc.py` — 证据判定正/反例测试
