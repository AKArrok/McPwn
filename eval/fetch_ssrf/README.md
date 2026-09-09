# 真实靶机验证:官方 mcp-server-fetch(SSRF)

> 目的:补上 `HANDOFF_NEXT.md` 遗留的 **"SSRF 类需要一个真实 fetch_url 靶机才能
> 验证"**。之前的 SSRF 检测(信号 + 卡)从未在真实 server 上端到端验证过——
> 本实验用 GitHub 官方 `modelcontextprotocol/servers` 仓库里的真实
> `mcp-server-fetch` 当靶机,验证 McPwn 的 SSRF 类能力(信号 + 卡 + 三决策点)
> 在真实 server 上是否成立。

## 合规声明

**只在本地自部署的开源副本上测试**:fetch 跑在 127.0.0.1,SSRF 受害者是本地
自建的 intranet 假服务(127.0.0.1,无真实敏感数据),全程不触碰任何未授权的
第三方系统或公网服务。这是教学/自动化红队研究的隔离环境(AGENTS.md 规约 8)。

## 靶机构成(全部 127.0.0.1 本地进程)

| 组件 | 说明 |
|---|---|
| `mcp-server-fetch`(官方,真实 server) | GitHub `modelcontextprotocol/servers/src/fetch`,pip 包 `mcp-server-fetch` 2026.7.10 + `mcp<2`(项目内 venv `eval/fetch_ssrf/.venv`)。**stdio** transport。SSRF 面是**设计特性**:README 自认 "can access local/internal IP addresses and may represent a security risk",无 private-IP 拦截——所以"只测漏洞版"= 最新版即是漏洞版(无 patch 可修,不是 CVE 型漏洞)。 |
| `bridge.py`(stdio→SSE 桥) | 官方 mcp SDK 组件(stdio_client + 低级 Server + SseServerTransport)拼的 ~60 行透传桥:工具 schema 逐字透传,不做任何加工。官方 server 只讲 stdio,桥把工具面原样抬到 SSE。注:McPwn 连接层现已原生支持 stdio(`mcpwn scan --command ...`),桥仅为保持既有跑法/对照保留。 |
| `intranet_server.py`(受害者) | 本地假内网服务,监听 8000/8080/9211,返回 nginx banner + `TOP-SECRET-INTRANET-2026`。模拟"只有 server 侧能访问的内网目标"。 |

## 判据(锁死)

- **positive(真实漏洞)**:标准 scan 检出 ≥1 条 SSRF finding(`ssrf_internal_service`
  high 信号,args 指向 127.0.0.1 + 响应含 nginx banner);`llm_points` 三决策点
  追加一轮,同样 ≥1。
- 确定性兜底:`prove.py` 直接调 `fetch("http://127.0.0.1:9211/")` 断言内网
  secret 回流。

## 结果

### 标准 scan(无 LLM 决策点)→ ✅ SSRF 检出
```
[std] findings=1 stop=completed [('ssrf', 'fetch', 0.75)]
```
attacker 按 ssrf 卡走完整探测链:良性确认(example.com)→ 回环端口
(22/6379/80)→ 云 metadata(169.254.169.254 等)→ 协议走私(file://)。
**命中点是 `fetch("http://127.0.0.1:80/")` 返回了本机真实内网服务
(`IIS Windows` banner,系统 HTTP.sys)——不是自建 intranet,是本机真实存在
的内网 HTTP 服务** → `ssrf_internal_service`(high)确定性信号。十六进制绕过
(`0x7f000001`)同样命中 IIS。**SSRF 类(信号+卡)在真实 server + 真实内网
目标上端到端成立**——补上 HANDOFF 遗留的"SSRF 真靶验证"。
(自建 intranet 服务 8000/8080/9211 供 `prove.py` 确定性复现用;scan 轮的
命中点恰好是系统真实服务,证据更强。)

### 真实靶机暴露的两个真实问题(自建靶机暴露不了)

1. **信号假阳性(已修复)**:llm 轮曾误报 `path_traversal@fetch 0.75`——
   根因是 `leaks_hardcoded_password` 正则把错误回显 `Failed to fetch
   file:///etc/passwd: UnsupportedProtocol...` 里的 `/etc/passwd:` 当成了
   密码键值对(fetch 实际拒绝 file://,无真实泄漏)。修复:
   `_HARDCODED_PW_RE` 加前缀负向断言 `(?<![/a-zA-Z0-9])`(路径/URL 片段不再
   触发;`root_passwd: x` 仍触发),新增 3 条回归测试(tests/signals/test_leaks.py)。
1b. **信号漏报(已修复)**:ssrf 卡模板教的十六进制 IP(`0x7f000001`)与 IPv6
   回环(`[::1]`)命中真实 IIS banner 时 `ssrf_internal_service` 不触发——
   `_INTERNAL_ARG_RE` 缺 hex/IPv6 变体、`_INTERNAL_BANNER_RE` 缺 `IIS` 变体
   (真实 HTTP.sys 默认页是 "IIS Windows" 而非 "Microsoft-IIS")。修复两个
   正则 + 2 条测试(tests/signals/test_ssrf.py)。
2. **llm_points 假设抢占 trade-off(已修复,2026-08)**:llm 轮曾连续 3 次
   **miss** SSRF(1 次误报 + 2 次 0 findings),标准 scan 却一次即中。机制:
   三决策点的假设生成给新假设 score=0.99 排最前,而 recon 已正确分类
   `SSRF@fetch`(0.85);LLM 假设(cmd_injection / indirect_injection /
   path_traversal)错误时把正确候选挤出 30k 预算。**修复 = LLM 假设预算池**
   (`scan(llm_hyp_budget=...)`,默认 `max_tokens*0.4`;`Candidate.origin` 标记
   假设来源,池尽截断/跳过,runner + langgraph 双路径;unknown-shape 实验
   显式传 -1 禁用)。**修复后 fetch llm 轮命中 SSRF 0.75**。详见 HANDOFF_NEXT 第 9 条。

### 确定性证明
`prove.py`:fetch("http://127.0.0.1:9211/") 返回 `TOP-SECRET-INTRANET-2026` +
nginx banner ✓;`preflight_signals.py`:`ssrf_internal_service` 命中 ✓。

### 审计
- runs/fetch_ssrf_std / runs/fetch_ssrf_llm(scan_result.json + traces)
- std: 1 finding(ssrf/fetch 0.75), stop=completed
- llm 轮: 3 runs(1 误报已修 + 2 零命中), 详见上
- 信号修复: 新增 3 条测试, tests/signals 16 passed

## 用法

```bash
# 0. 建靶机依赖(一次性)
python -m venv eval/fetch_ssrf/.venv
eval/fetch_ssrf/.venv/Scripts/pip install mcp-server-fetch "mcp<2"

# 1. 信号预检(确定性 SSRF 信号命中确认)
python eval/fetch_ssrf/preflight_signals.py     # 期望 PASS: ssrf_internal_service fired

# 2. 确定性 exploit 证明(fresh 自动起 intranet + 桥)
python eval/fetch_ssrf/prove.py                 # 期望 PASS(先手动起 fresh 或在 run_scan 内)

# 3. 真实靶机扫描(标准 scan + llm_points 双配置,自动 fresh)
python eval/fetch_ssrf/run_scan.py              # 期望两轮均 ≥1 SSRF finding
#    可选: --std-only 只跑标准 scan; --seed N
```

## 诚实边界

1. SSRF 形状在 McPwn 的 8 类 vuln 集内(recon 正则 + 信号 + 卡全覆盖),这是
   **已知类真靶验证**(与 unknown-shape 实验互补),不是新形状发现。
2. 桥是适配层:验证的是"官方 fetch 真实代码 + 真实抓取行为",transport 由桥
   提供,不影响漏洞本体(SSRF 发生在 fetch 进程内)。
3. 本地 intranet 服务是自建的,代表"内网目标"占位;真实生产环境的内网目标
   形态更多样(云 metadata 等),信号已覆盖(`ssrf_cloud_metadata`)但本实验只
   验证 `ssrf_internal_service` 路径。
4. 只测 127.0.0.1 本地目标,不触真实公网/云。
