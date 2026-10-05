# McPwn 面试问答稿（第一人称，按话题组织）

> 用法：每题先给 30 秒版本（第一段），追问再展开（后段）。数字与口径与
> `docs/evidence_matrix.md` / `docs/pwn_results.md` 一致；不确定的数字不写。

## 0. 一分钟开场（项目介绍）

> McPwn 是我独立开发的 MCP 红队自动化 agent。MCP（Model Context Protocol）正在
> 成为 LLM 应用连接工具的事实标准，但每个 MCP server 都是一个新攻击面。给它一个
> 陌生 MCP server 的端点，它会自主完成侦察、假设、攻击、验证、报告的完整闭环，
> 产出人类可读的 findings.md、机器可读的 JSON/SARIF 和可重放的 PoC。技术上它是
> Python 3.13 + LangGraph + OpenAI 兼容多模型：手写的 bounded function-calling
> 循环为主路径，LangGraph 状态机为等价路径，用 parity 测试锁住两版行为一致。
> 评测上我在回归集上做到 N=3 定稿 recall 1.00/0.97、FPR 恒 0，并为此建了一套
> 冻结 holdout 协议来保证结论经得起质疑。

## 1. 为什么需要 grounding 闸门？（为什么不信 LLM）

**30 秒版**：红队 agent 最大的假阳来源是 attacker LLM 自己的"成功汇报"——它
会声称"我拿到了 /etc/passwd"，哪怕工具真实返回里什么都没有。所以 McPwn 的
规则是：一切证据必须是真实 MCP 调用返回（`McpCall.result_text`）的逐字子串，
LLM 的总结文本永远不会被扫描。结果就是约 200 次扫描 FPR 恒 0。

**追问展开**：
- 判定链有三层防幻觉：①信号库只扫真实返回（L1）；②L2 judge 只在
  indirect/chain 两类 trace 上二审，且单条 medium 信号不过 0.6 置信度阈值，
  必须与确定性 L1 信号同 trace 共现才成 finding——judge 幻觉的爆炸半径被
  共现规则封顶；③judge 引用的 `evidence_call_index` 越界时降级为不产信号
  （judge 会编造不存在的调用序号，若放行会污染 findings 和 PoC）。
- 还有两级去重：同一 `signal_id` 取最高严重度；同一份返回文本命中的多条
  泄露类信号视为同一证据事件只计最高权重，防止同一份泄露被 `1-∏(1-w_i)`
  反复相乘导致置信度虚高。
- attacker 声称拿到敏感物但信号库零命中时，trace 会打
  `suspected_hallucination` 标记——只进 traces 供校准，永不进 findings。

## 2. 为什么评测判据是"严格更优"？（strict-better 与 M3 负结果）

**30 秒版**：我最早把 planner 换成 LLM 决策（M3），定的判据是"不劣于硬编版"。
跑出来五个判据全部"等价也 pass"，我当时差点当成"持平即成功"写进报告——后来
意识到这是自欺：一个不产生信息的实验被我包装成了结论。此后所有提能实验一律
改成 strict-better（baseline=0、每 run ≥1、miss 一次即 fail），并且预注册。

**追问展开**：
- M3 的负结果原文留档在 `docs/experiment_methodology.md` 和 PROGRESS，没有删。
  我认为这是这个项目最有价值的产出之一：它证明了"判据设计错了，实验就只是在
  生成自我安慰的材料"。
- strict-better 的落地是冻结 holdout 协议：`manifest.yaml` 的 sha256 冻结在
  `lock.json`，改判据/加提示会让所有 run 中止，直到有意的 `freeze.py`——防止
  "看过失败结果后再调规则"这种过拟合。若真看过结果改了规则，该配对必须降级
  为 validation split，不再作独立测试集。
- 证据分层我也刻意讲清楚：DVMCP 是已见过的回归集（recall 1.00 只说明没退化），
  excel/filesystem 漏洞版/修复版配对是因果验证集，只有冻结 holdout 配对才
  支持泛化声明。简历上我写的是"DVMCP regression set"，不是"召回率 100%"。

## 3. agent 循环怎么设计的？

**30 秒版**：主循环是 bounded function-calling：recon 阶段 list_tools/resources
建攻击面地图并按启发式给 (vuln_class, target) 候选打分排序，然后每个候选加载
一张策略卡（四段式 md：When to use / Objective / Playbook / Templates，启动时
lint 禁止靶场答案泄题），喂给 attacker LLM 出 payload，最多 12 个内部步；信号
命中强证据即收敛进下一个候选。turns/tokens/wall-time 三层预算任一超限即停。

**追问展开**：
- 为什么策略卡是 md 外置而不是写进 prompt 代码：策略内容要独立评审、lint、
  打包校验（package-data glob 漏注册会在 CI 报错），改策略不碰代码。
- 为什么还有 LangGraph 路径：运行语义（状态、决策、执行）和编排（怎么串）
  解耦。graph 路径有跨 trace 记忆（prior_evidence 喂后续 trace）和 checkpoint
  能力，finding 集合与手写循环等价由 parity 测试守护——我不用 LangGraph 是
  因为"该用"，而是把等价性作为测试目标，编排收益（断点续跑、流式）留给长扫描
  场景。

## 4. token 成本怎么控制的？

**30 秒版**：三层预算闸门之外，我加了 per-trace token 子闸门（默认 40% 预算，
单 trace 触顶立即收敛轮转，错误方向不再吃光后续候选的预算）、上下文压缩
（最近 2 个工具轮保留全文、更早的结果截 300 字符 digest，而证据链读
attack_calls 全量不受影响）、提示词瘦身（bundle -19%）。

**追问展开**：
- 一个有意思的反直觉发现：提示词瘦身省下的 per-call 开销被"更便宜→更多次
  调用"吃掉了（Jevons 效应），DVMCP 上 raw token/finding 只降了 10-25%。
  真正的大头是 DeepSeek 前缀缓存——重复的 system+策略卡+schema 前缀命中
  计价 1/10，我把口径升级成有效成本（attacker_tokens_effective）：命中占
  raw 的 67-69%，effective tok/finding 3.4k-3.6k，对照基线 -68%/-80%。
- 这轮优化我坚持"recall 不降、FPR=0"两条红线，归因用离线信号重放 + trace
  逐 call 对账，而不是凭感觉调参。

## 5. CI/CD 怎么接的？

**30 秒版**：`mcpwn scan` 产出 JSON Schema 版本化的 findings.json + SARIF +
可重放 PoC；`mcpwn ci` 只读 artifact 做确定性 severity gate（不重跑 LLM，判定
与采样方差解耦）。仓库 CI 四条线：双平台 lint+test（380 测试、coverage gate
75%）、CodeQL、pip-audit（首跑抓到 pyjwt/urllib3 共 14 条 PYSEC，已升级清零）、
tag 触发 wheel 构建验证。还有一个我很得意的 `check_docs.py`：文档里写死的
数字（测试数/信号数/命令名）用白名单正则锚定到代码真实值，防止文档腐烂。

## 6. 如果给你更多时间，下一做什么？

- L2 判据从"攻击面存在性"推进到"下游 LLM 真被带偏"（victim 真实化），
  `PROMPT_INJECTION_GAP.md` 已把缺口写清。
- holdout 配对扩到 3-5 对、跨域形状（非 CWE-639/345 家族）。
- 多目标并发扫描 + 结果聚合视图（ui/ 控制台已有只读版）。
