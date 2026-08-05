# McPwn

> **合规声明(P4)**:本项目仅用于评估**本机 Docker 容器**上的隔离靶机:Damn Vulnerable MCP Server
> (`dvmcp`, 127.0.0.1:9001-9010)与真实世界靶机(`excel-mcp-server` 0.1.7/0.1.8, 127.0.0.1:9203/9204,
> 由 `targets/realworld/deploy.ps1` 管理)。**禁止**将本项目及其攻击 payload
> 用于任何生产系统、公网服务或未经授权的目标。所有攻击均在隔离容器内进行,
> 由本机 `reset_hook` / `deploy.ps1 -Clean` 负责状态回收。若你不在本地运行这些容器,请立即停止使用。

McPwn 是一个**通用 MCP 红队 agent**:给一个陌生 MCP server 的 SSE 端点,它
自主完成侦察 → 假设 → 攻击 → 验证 → 报告的闭环,产出人类可读的 findings 与
可重放的 PoC。DVMCP 只是**验证 agent 有效性的 fixture**(见 `HANDOFF.md` §0)。

设计文档见 `HANDOFF.md`,顶层规约见 `AGENTS.md`。

## 快速开始

```bash
cp .env.example .env             # 填入 ARK_API_KEY
pip install -e ".[dev]"
mcpwn ping-models                # 自测已配置的 attacker 端点 (agent-first, 无常驻 victim LLM)
mcpwn lint-cards                 # 启动前校验策略卡格式与禁词
mcpwn scan http://127.0.0.1:9001/sse --out runs/m0_smoke
```

> 当前 `attacker` 用 DeepSeek 官方 API(`deepseek-v4-flash`, `DEEPSEEK_API_KEY`),
> `judge`(L2, 仅 indirect/chain trace)用豆包(`doubao-seed-2.0-lite`, `ARK_API_KEY`, best-effort)。
> 配置见 `config/models.yaml`;L2 观察 LLM 真被带偏是 bonus,见 `PROMPT_INJECTION_GAP.md`。

`scan` 直接把 `findings.md` / `poc/*.py` / `traces/*.json` / `scan_result.json`
写到 `--out` 目录,无需额外 `report` 步骤。

DVMCP 全端口回归(HANDOFF §7):

```bash
mcpwn eval dvmcp reset --yes    # 默认 dry-run,加 --yes 才真清容器状态
mcpwn eval dvmcp run            # 遍历 9001-9010,产 eval_report.md
```

真实世界靶机回归(excel-mcp-server CVE-2026-40576):

```bash
./targets/realworld/deploy.ps1 -Yes      # 拉起 0.1.7(:9203) / 0.1.8(:9204), 默认 dry-run
mcpwn eval realworld prove excel-0.1.7   # 确定性打穿证明:写 marker 到沙箱外 /root/ 并 docker exec 核对
mcpwn eval realworld prove excel-0.1.8   # 对照:0.1.8 拒绝写入(修复有效)
mcpwn eval realworld run -o runs/eval_real_world  # 检测门:正向 recall + 负向 precision
mcpwn scan <sse-url> --sandbox-root /tmp/sandbox  # 单目标扫描, 带沙箱根部署元数据
```

Milestone 与验收标准见 `HANDOFF.md` §10。
