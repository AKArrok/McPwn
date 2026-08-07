# 真实漏洞版靶机:filesystem 0.6.2(allowlist 绕过,positive)

> 目的:**在真实官方 server 的漏洞版本上验证 McPwn 的检出能力**。之前的
> git/filesystem 是最新版(已修复,negative);这里用 `server-filesystem`
> **0.6.2(CVE-2025-53109/53110 修复前)**,验证 path_traversal 类的端到端检出。

## 合规声明

本地自部署开源旧版副本(127.0.0.1):allowlist 指向本地临时目录,被越权读取的
"secret" 是自建假数据;不触碰任何未授权系统。

## 靶机与漏洞

`@modelcontextprotocol/server-filesystem` **0.6.2**(npm,修复前),allowlist
用**前缀匹配**校验路径,CVE 修复前存在两类绕过(实测 `prove.py` 均成立):

| 绕过 | 机制 | 实测 |
|---|---|---|
| (a) sibling 前缀碰撞 | `<allowed>` 目录的兄弟 `<allowed>2` 也通过前缀匹配 → 读兄弟目录任意文件 | `read_file(<fs2>\secret.txt)` → `FS-SECRET-OUTSIDE-2026` ✓ |
| (b) `..` 穿越 | 未规范化路径,`<allowed>\..\<outside>\secret.txt` 放行 | ✓ |

修复版 2026.7.10 对两类都拒绝(`Access denied`,见 `eval/real_negative`)。

## 判据(锁死)

- **positive**:llm_points 轮 ≥1 finding(std 轮无 evidence judge 通道——judge
  只在 llm_points 下启用——因此 std 轮只验证"确定性信号不误报",不参与检出判据)。
- 检出路径:recon 把 `read_file` 等分类为 `path_traversal` → 卡引导穿越尝试 →
  **0 确定性信号**(secret 无泄漏形状,`preflight_signals.py` 冻结该前提)→
  evidence judge 对 0 信号 trace 认账(is_finding)——**judge 是这里的判定通道**。

## 结果

- **prove(确定性)**:PASS——(a) sibling 前缀碰撞、(b) 沙箱内 junction 指向外部,
  均越权读到 `FS-SECRET-OUTSIDE-2026`(CVE-2025-53110/53109 本体)。
- **标准 scan(3 次)**:0 findings(无 judge 通道,确定性信号全静默——预期,不判失败)。
- **llm_points 轮**:引导前 2/4 命中(`search_files 0.75` / `move_file 0.85`);
  **"先阅读后动手"引导后 2/3**(`create_directory 0.75` / `move_file 0.75`)。
  命中形态:attacker 先 `list_directory` 发现沙箱内 junction → `get_file_info`
  确认 → 沿 junction 越权读/写/列举(6 calls 即中),judge 认账("junction point
  inside the allowed directory that points outside returned content of the
  external directory")。
- **判定机制(2026-08 增强)**:evidence judge 提前到每 trace 后判定 + 判定喂回
  复盘(attacker 幻觉自认打进去 → judge 揭穿 is_finding=false + reason → 复盘
  修正方向重试)。命中率仍受 attacker 探索路径随机性限制(试 move_file/read_file
  穿越 vs 直接 list junction)与 DeepSeek token 方差(7 calls 可烧 34k,复盘 margin
  来不及触发)——如实记录,不宣称稳定检出。

## 一次性环境

```powershell
# 漏洞版 (0.6.2) 源码: npm 可访问时
npm install @modelcontextprotocol/server-filesystem@0.6.2
$env:MCPWN_FS_INDEX_OLD = "<path>\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js"
```

0.6.2 的 inputSchema 缺顶层 `type`,bridge 用 tolerant list_tools 补
(adapter-only,不改 server 行为)。stdio→SSE 桥与 venv 同 fetch 靶机。

## 用法

```powershell
$env:MCPWN_FS_INDEX_OLD = "<server-filesystem@0.6.2 dist/index.js>"
python eval/real_vuln/prove.py                  # 确定性绕过证明 (PASS)
python eval/real_vuln/preflight_signals.py      # 0 确定性信号前提
python eval/real_vuln/run_scan.py               # std + llm 双配置 (期望 ≥1)
```

## 诚实边界

1. 0.6.2 是 2025-07-01 之前的旧版;用的是官方发布的 npm 包,未改源码。
2. 检出依赖 judge 通道(0 确定性信号)——信号库对"纯 secret 文本的路径穿越"
   无直接检测,judge 认账能力是本次被测对象(与 vault 空 owner 同类)。
3. git 漏洞版(2025.x)仍未做:repo_path 校验缺失的检出验证,留作后续。
