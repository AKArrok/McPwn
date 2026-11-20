# jev_probe — 决策点 "System One 化" 小实验

背景: TypeSafe AI 的 Jev (System One Model) 宣称在决策类任务上比 LLM 快/便宜两个数量级。
本实验不接外部服务,用 DashScope qwen 的 `logprobs` 在**同一个 judge 模型**上复刻
"单 token 分类决策 + 概率" (poor-man's Jev),对比生产字符串 JSON 决策的成本与一致性。

## 决策点

`evidence_verdict` (`mcp_redteam/agent/llm_points.py`): 对零信号 trace 判
is_finding (+ vuln_class + 证据),是最 "System One 形状" 的 LLM 决策点。

## 数据

`runs/holdout/cache-tenant-collision/run_{0..4}/{fixed,vulnerable}/scan_result.json`
共 24 条带 `llm_evidence_verdict` 的实跑 trace (9 fixed / 15 vulnerable)。

## 四臂 (同一 judge 模型 qwen3.8-flash, temperature=0, 同一 trace 输入)

| 臂 | 说明 | 对应 |
|---|---|---|
| A | 生产 prompt,thinking 默认开 (现状) | `evidence_verdict` 原样 |
| A2 | 生产 prompt,`enable_thinking=false` | 公平字符串基线 |
| B | 极简字母 prompt,`max_tokens=1` + `top_logprobs` → P(Y)/P(N)/P(U) | poor-man's Jev |
| B2 | 仅 B 判 Y 的 trace:vuln_class 八选一字母题,2 种选项顺序 | Jev 顺序敏感性复测 |

## 读数

- 每 token 成本 (prompt/completion) 与墙钟时延 (本机网络,只看相对比)
- 一致性: A vs A2 vs B vs 当次实跑记录的 verdict
- 对 arm 标签的粗判别: fixed→N/U, vulnerable→Y;P(Y) 在两臂的分离度 (校准代理)
- B2: 同一问题两种选项顺序下,选中类概率漂移 (tsukumo 对 Jev 的核心批评)

## 运行

```bash
uv run python eval/jev_probe/run_probe.py   # 结果写 eval/jev_probe/results.json
```

注: 实验 prompt 内联在本脚本 (一次性探针);若转正需按仓库规约外置到 `**/agents/*.md`。

## 结果 (2026-10-06, N=25, 单 challenge)

| 臂 | prompt tok | completion tok | 时延 | vs A 一致 | vs 实跑记录一致 | arm 正确率 fixed / vuln |
|---|---|---|---|---|---|---|
| A 现状 (thinking ON) | 1215 | **1240** | **22.5s** | — | 24/25 | 8/11, 13/14 |
| A2 关思考 | 1179 | 122 | 2.7s | 24/25 | 23/25 | 9/11, 13/14 |
| B 单token logits | 734 | **1** | 1.8s | 21/25 | 20/25 | 10/11, 11/14 |

- **最大发现: 现状 judge 的 1240 completion tokens 几乎全是隐藏推理**。同 prompt
  关掉 thinking (A2) 与 A 24/25 一致,token 1/10、时延 1/8.5 —— 生产 judge 调用
  (evidence_verdict / M3) 加 `enable_thinking=false` 即得,无需换模型。
- B (logits 决策) 概率分离度好: P(finding) fixed 均值 0.136 vs vulnerable 0.793;
  但直接替换丢召回 (vulnerable 11/14 vs 13/14),极简 prompt 信息量不足是主要混淆。
  下一轮应测「全量生产 prompt + 单 token 解码」再判断。
- B2 顺序漂移 ≤0.11,12 条全选 auth_bypass (单一类,证据弱)。
- 局限: N=25、单 challenge、单 judge 模型;arm 标签是粗粒度真值。
