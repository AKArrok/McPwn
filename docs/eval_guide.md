# McPwn 评估体系导航(eval guide)

> 本文回答:**这个项目到底有哪些评估/回归,各自验证什么、怎么跑、判据是什么、
> 当前状态如何**。McPwn 的定位是"通用 MCP 红队 agent",靶机(DVMCP / excel-mcp /
> vault-mcp / delegate-mcp / fetch)都只是验证 agent 有效性的 fixture——本文的
> 每个 eval 都在测 agent 的某一面。
>
> 顶层视角:`HANDOFF.md`(设计)与 `HANDOFF_NEXT.md`(当前主线);
> 本文是"评估目录"的导航。

---

## 1. 评估全景

| eval | 靶机 | 验证什么 | 关键指标 | 状态(2026-08) |
|---|---|---|---|---|
| `dvmcp` | DVMCP 10 港(9001-9010) | 8 类漏洞的**召回** | recall / FPR / replay | recall 0.80-0.90, FPR 0, replay 5/5 |
| `realworld` | excel-mcp CVE-2026-40576 | 真实漏洞**正向检出 + 修复版负向拦截** | prove exploited/blocked + scan findings | 0.1.7 exploited / 0.1.8 blocked, 双 PASS |
| `unknown_shape` | vault-mcp(CWE-639 子串鉴权) | LLM 三决策点能否补**结构性漏报** | baseline=0 → llm ≥1, N=3 miss=fail | 3/3 PASS + 消融 D 3/3 |
| `generalize` | delegate-mcp(CWE-639 授权作用域) | 三决策点能否**跨形状迁移** | 同上(严格更优) | 3/3 PASS(第 4 轮) |
| `fetch_ssrf` | 官方 mcp-server-fetch | SSRF 类在**真实 server** 上端到端 | ≥1 SSRF finding | scan 1 finding 0.75 |
| `clean_baseline` | 本地无漏洞 server 变体 | 信号库**不误报**(FPR 可信度) | 0 findings | 3 变体 0 findings |

> 一句话分工:DVMCP 测"广度"(8 类都会)、realworld 测"真实"(CVE)、
> unknown_shape/generalize 测"深度"(信号库漏时 LLM 能否补)、fetch_ssrf 测
> "SSRF 真靶"、clean_baseline 测"不胡说"。

---

## 2. DVMCP 回归(fixture:Damn Vulnerable MCP Server)

**验证什么**:agent 在 10 个不同漏洞端口上能自主发现多少。10 港对应 8 类
漏洞(chain / indirect 是 bonus),预期映射在 `eval/dvmcp/expected.yaml`。

**怎么跑**:

```bash
mcpwn eval dvmcp reset --yes   # 清理容器状态(默认 dry-run, --yes 才真的动)
mcpwn eval dvmcp run           # 遍历 9001-9010, 产 eval_report.md
```

**指标**(`eval/dvmcp/runner.py`):

| 指标 | 含义 | 当前 |
|---|---|---|
| recall | 预期 vuln class 被发现的端口占比 | 0.80(8/10, runner)/ 0.90(9/10, graph) |
| false_positive_rate | findings 中 vuln class 不在预期里的比例 | 0.00 |
| poc_replay_pass_rate | 随机抽 5 条 finding 重放 PoC,信号是否重现 | 1.00 |

**注意**:DVMCP 状态有污染(challenge 4 计数器等),每次跑前先 `reset`。

---

## 3. 真实世界回归(fixture:excel-mcp-server CVE-2026-40576)

**验证什么**:真实世界的 MCP 漏洞(沙箱逃逸:filepath 参数可写沙箱外任意路径)。
用 0.1.7(漏洞版)做正向、0.1.8(修复版)做负向对照——既是漏洞检出测试,
也是修复有效性测试。

**怎么跑**:

```bash
./targets/realworld/deploy.ps1 -Yes          # 拉起 0.1.7(:9203) / 0.1.8(:9204), 默认 dry-run
mcpwn eval realworld prove excel-0.1.7       # 确定性打穿证明:写 marker 到 /root/ + docker exec 核对
mcpwn eval realworld prove excel-0.1.8       # 对照:0.1.8 拒绝写入
mcpwn eval realworld run -o runs/eval_real_world   # 检测门:正向 recall + 负向 precision
mcpwn scan <sse-url> --sandbox-root /tmp/sandbox   # 单目标扫描, 带沙箱根部署元数据
```

**关键点**:`--sandbox-root` 是部署元数据(operator 提供),启用
`sandbox_escape_write/read` 信号;无 root 时降级为 `sandbox_escape_traversal`
(medium, 单发 0.5 不过 0.6,不可能凭空造 finding)。

**当前**:0.1.7 exploited PASS / 0.1.8 blocked PASS,正向检出
`sandbox_escape_write` (high),负向 0 findings。

---

## 4. 未知形状实验(fixture:vault-mcp,CWE-639 子串鉴权)

**验证什么**:固定信号库对"未知形状"漏洞结构性漏报(vault 的
`_can_read` 用子串匹配,`"" in "admin"` 为 True,不在任何信号模式里),
`--llm-points` 的三个 LLM 决策点能否补上。

**三阶段协议**(判据锁死,权威在 `eval/unknown_shape/README.md`):

| 阶段 | 内容 | 判据 | 结果 |
|---|---|---|---|
| 1 baseline | hardcoded planner + 固定信号库 | 0 findings(结构性漏) | ✅ 0 findings |
| 2 LLM 增量 | 三决策点 | ≥1 finding | ✅ 2 findings |
| 3 重复 | 同 budget、每 run 全新 server、N=3 | 每 run ≥1,**miss 即 fail** | ✅ 3/3 PASS |
| 4 消融 | 2×2 四臂,剥掉提示词答案 | D(3) 3/3 | ✅ A 3/3 + D 3/3 |

**怎么跑**:

```bash
python eval/unknown_shape/run_baseline.py   # Stage 1
python eval/unknown_shape/run_llm.py        # Stage 2
python eval/unknown_shape/run_repeat.py 3   # Stage 3
python eval/unknown_shape/ablation/run_ablation.py --all   # Stage 4
```

**三决策点**(`--llm-points`,LLM 只在三个固定位置上线,不做排列):

| 点 | 时机 | 预算 |
|---|---|---|
| 假设生成 | recon 后,2 次独立采样 union,score 0.99 排最前 | attacker |
| 复盘 | 第一波 0 命中且剩余预算 ≥8k,只触发一次 | attacker |
| 证据判定 | 信号库 0 命中的 trace,grounding 闸门(evidence 必须逐字子串) | judge(带外) |

**防自欺设计**:判据是"严格更优"(baseline=0、每 run ≥1、miss=fail),不是
"不劣于";证据判定有 grounding 闸门,run 0 时诚实返回 is_finding=false。

---

## 5. 泛化验证(fixture:delegate-mcp,CWE-639 授权作用域)

**验证什么**:vault-mcp 上的"类级发现能力"是**只对子串鉴权一种形状成立**,
还是能**跨形状迁移**。delegate 的机制完全不同:读接口精确匹配(绕参数无效),
漏洞在 `grant_access` 把 delegate 记入**全局集合**(授权副作用泄漏到所有 vault)。

**结果**(判据同 vault:每 run ≥1、N=3、miss=fail):

| 轮次 | 结果 | 修复 |
|---|---|---|
| baseline | ✅ 0 findings | — |
| 第 1 轮 | 2/3 FAIL | owner 可猜 → LLM 走"冒充 owner 自授权"通用路径 |
| 第 2 轮 | 1/3 FAIL | attacker 只自证不范围验证 → 卡补第 6 步 |
| 第 3 轮 | 2/3 FAIL | 同型"自证收敛" → 卡第 6 步加强 |
| **第 4 轮** | ✅ **3/3 PASS** | — |

**结论**:假设生成 / judge 跨形状稳定;方差在执行层"验证范围"动作。
精确表述:"类级框架 + 类级执行引导下跨形状严格更优成立"。

---

## 6. SSRF 真靶验证(fixture:官方 mcp-server-fetch)

**验证什么**:SSRF 类(信号 + 卡)在**真实 server** 上端到端成立——之前的
SSRF 检测从未在真靶上验证过。靶机是 GitHub 官方
`modelcontextprotocol/servers` 的 `mcp-server-fetch`(stdio → SSE 桥),
SSRF 面是其**设计特性**(README 自认可访问内网),本地 intranet 假服务当受害者。

**结果**:

- 标准 scan:**1 finding**(`ssrf/fetch 0.75`,`ssrf_internal_service` high,
  stop=completed)——命中点是 `fetch("http://127.0.0.1:80/")` 返回**本机真实
  内网服务**(IIS Windows banner,系统 HTTP.sys),十六进制绕过 `0x7f000001`
  同样命中;
- `prove.py` 确定性 exploit:`fetch("http://127.0.0.1:9211/")` 回流
  `TOP-SECRET-INTRANET-2026`。

**暴露的两个真实问题**(自建靶机暴露不了):

1. 信号假阳性(已修复):`leaks_hardcoded_password` 把错误回显
   `Failed to fetch file:///etc/passwd: UnsupportedProtocol...` 当密码键值
   → 加 `(?<![/a-zA-Z0-9])` 前缀负向断言 + 3 条回归测试;
2. llm_points 假设抢占 trade-off(已修复):假设生成 score=0.99 排最前,
   曾把 recon 已正确分类的 `SSRF@fetch`(0.85)挤出预算 → llm 轮 miss 而标准
   scan 一次即中。修复 = **LLM-hypothesis budget pool**(`llm_hyp_budget`,
   默认 40% attacker 预算):LLM 假设候选共享一个池,池耗尽后剩余 LLM 假设
   被跳过、recon 候选照常执行——vault/delegate 的 unknown-shape 发现不受
   影响(`-1` 关闭池,未知形状实验用)。实现见
   `orchestrator/runner.py` + `budget.py`,回归测试 `tests/test_llm_hyp_budget.py`。

---

## 7. 干净基线(fixture:本地无漏洞 server)

**验证什么**:信号库对**没有漏洞**的 server 不误报——这是 DVMCP FPR=0 可信的
前提。三个变体(noop / summarize / file_list)都是"名字很像有洞、实际干净"
的 server,recon 会被骗但信号库不该出 finding。

```bash
python -m eval.clean_baseline.runner   # 3 变体各跑一次 scan
```

**当前**:3 变体 0 findings(FPR=0.00),均有真实 LLM 攻击探测
(attacker_tokens 非零),无 error。

---

## 8. 怎么选跑哪个

| 你想验证 | 跑 |
|---|---|
| agent 广度(8 类都认识) | `mcpwn eval dvmcp run` |
| 真实 CVE 检出 + 修复对照 | `mcpwn eval realworld prove/run` |
| LLM 提能(未知形状) | `python eval/unknown_shape/run_*.py` |
| 能力是否跨形状 | `python eval/generalize/...`(协议见 README) |
| SSRF 真靶 | `eval/fetch_ssrf/`(见 README) |
| FPR 可信度 | `eval/clean_baseline/` |

> 所有 eval 都以 `runs/` 下产物为准(`eval_report.md` / `scan_result.json`);
> `runs/` 被 gitignore,产物是本地证据,commit 只进协议与代码。

---

## 9. 相关文档

- `docs/pwn_results.md` — 各靶机 pwn 结果的详细记录(含 graph-vs-runner 对比)
- `HANDOFF.md` §7 / §10 — DVMCP fixture 定位与里程碑验收
- `HANDOFF_NEXT.md` — 当前主线(unknown-shape)与下一步
- 各 eval 目录内 `README.md` — 协议权威(判据跑前锁死)
