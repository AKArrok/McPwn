# 真实修复版靶机验证:git + filesystem(negative / FPR)

> 目的:在**真实、已修复**的官方 MCP server 上验证 McPwn 的 FPR 控制——一个
> 看似有攻击面(路径/注入参数)但 CVE 已修复的真实 server,标准 scan 与
> llm_points 都**不应产生 finding**(0 findings 判据)。与 excel-mcp 0.1.8
> 修复版对照互补,补"真实 server 不误报"这一维。

## 合规声明

本地自部署开源副本(127.0.0.1):git 指向本地临时 demo 仓库,filesystem 的
allowlist 目录为本地临时目录;全部工具调用发生在本地,不触碰任何未授权系统。

## 靶机(官方,最新版,全部 CVE 已修复)

| 靶机 | 来源 | 版本 | 已修复的 CVE | 校验行为(实测) |
|---|---|---|---|---|
| git | `mcp-server-git`(pip) | 2026.7.10 | CVE-2025-68143/44/45、CVE-2026-27735 | `repo_path` 限 `--repository` 根;`git_checkout` 拒绝 `-` 开头分支名;`git_add` 拒绝绝对路径/`../` |
| filesystem | `@modelcontextprotocol/server-filesystem`(npm) | 2026.7.10 | CVE-2025-53109/53110 | allowlist 强制;sibling 目录(前缀碰撞)与 `..` 穿越均 `Access denied` |

## 判据(锁死)

- **FPR**:标准 scan 0 findings;llm_points 轮 0 findings(三决策点假设被拒、
  evidence judge 对 0 信号 trace 诚实否定、不编造)。

## 结果

**4/4 run 全部 0 findings PASS(FPR 控制验证成立)**:

```
== git (negative) ==
  std: findings=0 stop=budget_tokens expect=0 PASS
  llm: findings=0 stop=budget_time  expect=0 PASS
== filesystem (negative) ==
  std: findings=0 stop=budget_tokens expect=0 PASS
  llm: findings=0 stop=budget_tokens expect=0 PASS
```

- 标准 scan:attacker 按 path_traversal/ssrf 等卡探测,真实 server 的
  repo_path/allowlist 校验全部拒绝 → 0 确定性信号 → 0 findings。
- llm_points:三决策点假设(路径穿越/参数注入等)同样被拒;0 信号 trace 走
  evidence judge,**judge 诚实否定、不编造 finding**(与 vault baseline 的
  judge 行为一致)。
- 结论:**McPwn 在真实已修复 server 上 FPR = 0**,补上"真实 server 不误报"
  这一维(excel-mcp 0.1.8 之外的第二个/第三个 negative 真实靶机)。

## 一次性环境(部署)

```powershell
# git: 任意 venv, 需 mcp-server-git + "mcp<2" + starlette + uvicorn
python -m venv C:\tmp\git-venv
C:\tmp\git-venv\Scripts\pip install mcp-server-git "mcp<2" starlette uvicorn
$env:MCPWN_GIT_VENV = "C:\tmp\git-venv"

# filesystem: 本地 npm install(源码级, 需要 node; npm registry 可达时)
npm install @modelcontextprotocol/server-filesystem
$env:MCPWN_FS_INDEX = "<path>\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js"
```

两个 server 都是 stdio,经 `eval/fetch_ssrf/bridge.py`(stdio→SSE 透传桥,
mcp<2 venv 跑)暴露;`_fresh.py` 每 run 自动准备 demo repo / allowlist 目录并
spawn bridge。

## 用法

```powershell
$env:MCPWN_GIT_VENV = "C:\tmp\git-venv"
$env:MCPWN_FS_INDEX = "<server-filesystem dist\index.js>"
python eval/real_negative/run_scan.py            # 4 个 run (2 靶机 × std+llm)
python eval/real_negative/run_scan.py --std-only # 只标准 scan
```

## 诚实边界

1. **漏洞版未做 positive**:filesystem 0.6.2(CVE 修复前)的 inputSchema 缺顶层
   `type` 字段,mcp SDK 1.29 严格 pydantic 校验在 bridge 启动即失败;git 漏洞版
   需版本考古(pip 装 2025.x + mcp<2 兼容性)。两个 CVE 的"检出"验证未完成,
   留作后续。
2. 最新版是"修复后"的现实——负面试点验证的是**不误报**,不是"能检出"。
3. filesystem 依赖 npm 安装(CI 无网络);本机 npx 缓存路径写死进环境变量。
