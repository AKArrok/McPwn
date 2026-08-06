# McPwn → 真实 MCP 靶机探索 Handoff

> 这个文件记录“从 DVMCP 走向真实世界 MCP 靶机”的探索、部署、验证和 McPwn 差距。
> 开工前先读 `HANDOFF.md` + `PROGRESS.md` + `HANDOFF_NEXT.md`, 然后读这个文件。

> **状态 (2026-08-05)**: §6.1 三信号 (sandbox_escape_write / sandbox_escape_read / sandbox_escape_traversal) + §6.2 eval/realworld harness (runner + prove + targets.yaml) + deploy.ps1 已实现, 全量 101 测试绿, ruff clean。prove = 0.1.7 exploited 双通道 + 0.1.8 blocked 对照。

最后更新: 2026-08-05

---

## 0. 结论一句话

**真实世界靶机 ≠ DVMCP**: DVMCP 的信号形状 (passwd / uid / API key) 在真实
带防护的 MCP server 上不一定出现。我们找到了一个**有公开 CVE、可手工打穿**
的正常用途 MCP server (`excel-mcp-server`), 但 McPwn 当前信号库**漏报**。
下一步不是继续换靶子, 而是补真实世界 detector。

---

## 1. 选型标准修正

### 第一次选错 (踩过的坑)

按“正常用途 + star 多”挑, 结果挑到带防护的:

| 靶机 | 为什么难打 |
|---|---|
| `MCP-Workspace-Server` | 自带 `ResponseSanitizer`, 敏感输出被压空 / 报 `response validation failed`; 默认还要 `x-user-id` header 才有 workspace/exec |
| `acuvity/mcp-server-filesystem` | 带 OPA/rego policy + SBOM + Minibridge, 直接挡 path traversal |

### 这次找对的方向

- 优先找**公开 CVE / GitHub Advisory** 的 MCP server
- 其次是正常用途但**没有硬防护层** (无 sanitizer / 无 policy / 无 auth)
- 再按部署条件筛: Docker 或 PyPI 能跑, SSE/streamable-http 能连
- 不要按 star 数当安全标准

---

## 2. 已部署靶机 (2026-08-05)

| 容器 | 镜像/来源 | 端口 | 用途 |
|---|---|---|---|
| `mcp-ws` | `mcp-filesystem` (自 build) | `9201` | MCP-Workspace-Server, 11 tools, 带 sanitizer |
| `mcp-fs` | `acuvity/mcp-server-filesystem:latest` | `9202` | 官方 filesystem 镜像, 带 rego policy |
| `excel-mcp` | python:3.12-slim + `pip install excel-mcp-server==0.1.7` | `9203` | **已知 CVE-2026-40576**, 25 tools, 无认证 SSE |

容器当前都在跑 (如果后续被停, 重新起):

```powershell
# MCP-Workspace-Server (build 时需要代理, 见 §5)
cd "D:\Users\ASUS\Desktop\学习资料\代码\McPwn\targets\MCP-Workspace-Server"
$env:HTTP_PROXY="http://host.docker.internal:7897"; $env:HTTPS_PROXY="http://host.docker.internal:7897"
docker build -t mcp-filesystem .
docker run -d --name mcp-ws -p 9201:18089 mcp-filesystem

# acuvity filesystem
docker run -d --name mcp-fs -p 9202:8000 acuvity/mcp-server-filesystem

# excel-mcp-server 0.1.7 (vulnerable)
docker run -d --name excel-mcp -p 9203:8017 -e EXCEL_FILES_PATH=/tmp/sandbox -e FASTMCP_HOST=0.0.0.0 -e FASTMCP_PORT=8017 python:3.12-slim sh -c "mkdir -p /tmp/sandbox && pip install --quiet excel-mcp-server==0.1.7 && excel-mcp-server sse"
```

---

## 3. 扫描结果

| 靶机 | McPwn 结果 | 备注 |
|---|---|---|
| WS-Server | v2/v3/v4 最终 1 finding | `command_injection on exec`, signal `command_exec_uid_stdout`; 但 `exec` 是该产品**自带功能**, 语义上算 false positive |
| acuvity filesystem | 0 findings | rego policy 挡住 path traversal |
| excel-mcp-server 0.1.7 | **0 findings** | **漏报真实 CVE** |

### excel-mcp 手工打穿证据

```python
call_tool("create_workbook", {"filepath": "/tmp/pwn.xlsx"})
call_tool("write_data_to_excel", {"filepath": "/tmp/pwn.xlsx", "sheet_name": "Sheet1", "data": [["SECRET", "VALUE"]]})
call_tool("read_data_from_excel", {"filepath": "/tmp/pwn.xlsx", "sheet_name": "Sheet1"})
```

结果: 在 `/tmp/pwn.xlsx` 写入并读回 `SECRET/VALUE`, 绕过 `EXCEL_FILES_PATH`
沙箱。这是 CVE-2026-40576 的两个核心原语 (绝对路径 + `../` 穿越)。

### McPwn 为什么漏报

- `excel-mcp` 读 `/etc/passwd` 会报 `openpyxl does not support ...` 格式错误,
  不会回显 `root:x:0:0`
- trace 里其实已经成功 `create_workbook("/tmp/out.xlsx")` (沙箱外写入), 但
  现有 14 条 signal 全是 DVMCP 形状 (passwd / hash / uid / api key / shadow pair),
  **没有 sandbox escape / 路径穿越 detector**
- 结论: 真实世界不是“换靶子”能解决的, 是信号库覆盖不足

---

## 4. 这轮顺手改的 McPwn 代码

这些改动已提交 (commit `e19d15b`), 内容:

- `mcp_redteam/targets/mcp_client.py`
  - `McpSession` 新增 `headers` 参数, 支持带 `x-user-id` / `x-chat-id` 的真实 MCP
  - `connect_timeout` 真正传给 `sse_client()`
  - `list_resources` / `raw_list_resources` 对不支持 `resources/list` 的 server 优雅降级 (acuvity 就报 Method not found)
- `mcp_redteam/orchestrator/runner.py`
  - `scan()` 新增 `sse_headers` 参数
- `mcp_redteam/cli.py`
  - `scan` 新增 `--headers "k=v,k2=v2"` 参数
- `mcp_redteam/config/models.yaml`
  - attacker: DeepSeek 官方 API `deepseek-v4-flash`, key 用 `DEEPSEEK_API_KEY`
  - judge: 已是 DeepSeek 官方 `deepseek-v4-flash`
  - 不再用 ARK (ARK 上的 glm-5-2 / deepseek-v4-pro 都触顶被 pause)

验证: `80 passed`, ruff clean。

---

## 5. 环境 / 部署注意

- Docker build 需要代理时: `HTTP_PROXY=http://host.docker.internal:7897`
  (本机 clash 在 7897, BuildKit 在 Docker Desktop VM 里必须用
  `host.docker.internal`, 不能用 `127.0.0.1`)
- ARK key 当前不可用: `glm-5-2` 和 `deepseek-v4-pro` (ARK 托管) 都被
  `SetLimitExceeded` pause。DeepSeek 官方 API 的 `deepseek-v4-flash` 可用,
  用户已经填好 `DEEPSEEK_API_KEY`
- `eval_real_world/` 和 `targets/` 是外部 clone / 部署目录, 建议不要加进
  git; 要加也只加 `HANDOFF_TARGETS.md` + 代码改动

---

## 6. 下一步建议

1. **加两条真实世界 detector** (优先)
   - `sandbox_escape_write`: `filepath` 含绝对路径或 `../`, 且返回
     `Created workbook at ...` / `Data written` / 成功写文件
   - `sandbox_escape_read`: `filepath` 含绝对路径或 `../`, 且成功返回
     文件内容 / cell 数据
   - `excel-mcp-server` 就是现成回归样本, 保证 fire
2. **建 `eval_real_world/` 回归 harness**
   - 把 `excel-mcp` 加进去, 类似 `eval/dvmcp` 但只测“真实 CVE 能不能发现”
   - 记录 target version, CVE 编号, expected_signal
3. **回测 DVMCP**
   - 新增 detector 后重跑 `mcpwn eval dvmcp run -o runs/m2_dvmcp_full_v5`,
     确认没破坏 8/10
4. **再补一个真实靶子**
   - 可选: `ADB MCP Server` command injection CVE, 或 `notion-mcp-server`
     path traversal issue, 扩一个第二回归样本

---

## 7. 现有文件 / 结果

- `runs/ws_target_v4/` — WS 用 DeepSeek flash 的 finding
- `runs/acuvity_fs_v2/` — acuvity 0 findings
- `runs/excel_mcp_v1/` — excel-mcp 0 findings (漏报, trace 里有 `/tmp/out.xlsx` 写入证据)
- `targets/excel-mcp-server/` — 最新 clone (0.1.8, 已修复), 部署用 PyPI 0.1.7
- `targets/MCP-Workspace-Server/`, `targets/mcp-server-sqlite-npx/` — 其它 clone

> sqlite-npx 是 stdio-only, 项目 McpSession 走 SSE, 没有直接用; 需要
> mcp-proxy 桥接才能当靶子, 当前优先级低。

---

## 8. M2.5 落地记录 (2026-08-05)

### 实现 (commit e19d15b)
- `mcp_redteam/signals/detectors.py`: 3 条新信号 `sandbox_escape_write` / `sandbox_escape_read`
  (high, root-aware, 词法 posix 路径解析) + `sandbox_escape_traversal` (medium, 无 root 降级);
  全部 detector 统一签名 `(mcp_calls, final_output, sandbox_root=None)`
- `--sandbox-root` 全链路 (scan -> verifier -> detectors), `ScanResult.sandbox_root` 可复现性字段
- `eval/realworld/`: `runner.py` (正向 recall 门 + 负向 precision 门), `prove.py` (确定性 3-call 链
  + in-band 读回 + out-of-band docker exec 核对), `targets.yaml`, `AGENTS.md`
- `targets/realworld/deploy.ps1`: 幂等 dry-run/`--yes`, 127.0.0.1 绑定, 容器内 pip 走代理
- `vulns/cards/path_traversal.md` + `attacker_system.md`: 沙箱逃逸 Playbook + `sandbox_root` 变量

### 验证结果
| 验证 | 结果 |
|---|---|
| pytest / ruff | 101 passed / clean |
| `mcpwn eval realworld prove excel-0.1.7` | PASS: marker 落 `/root/` (docker exec 4845B, nonce 一致) |
| `mcpwn eval realworld prove excel-0.1.8` | PASS: 写入被拒, 无文件落地 |
| `mcpwn eval realworld run -o runs/eval_real_world/v1` | 2/2: 0.1.7 `sandbox_escape_write` high 0.75; 0.1.8 0 findings |
| `mcpwn eval dvmcp run -o runs/m2_dvmcp_full_v5` | recall 8/10, FPR 0, replay 5/5 (无回归) |

### 能力边界 (演示确认)
- 读: 沙箱外任意 **xlsx 家族**文件可读走 (含其他目录/租户), 跨容器 root 权限;`/etc/passwd`/shadow/ssh/.env 等文本读不了 (openpyxl 拒收)
- 写: 任意路径写 xlsx (含覆盖已有文件)
- 边界: 无 docker 挂载时仅容器内;宿主不可达

### 使用
```powershell
./targets/realworld/deploy.ps1 -Yes            # 拉起 0.1.7(:9203)/0.1.8(:9204)
mcpwn eval realworld prove excel-0.1.7         # 打穿证明
mcpwn eval realworld prove excel-0.1.8         # 对照(修复有效)
mcpwn eval realworld run -o runs/eval_real_world  # 检测门
mcpwn scan <url> --sandbox-root /tmp/sandbox   # 单目标
```
