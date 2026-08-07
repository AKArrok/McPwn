# AGENTS.md — eval/real_vuln(filesystem 0.6.2 漏洞版,positive 靶机)

- **输入**: SSE `http://127.0.0.1:9350/sse`(桥 + 官方 server-filesystem 0.6.2,
  allowlist = `%TEMP%\mcpwn-fs`);`MCPWN_FS_INDEX_OLD` 指向 0.6.2 dist/index.js。
  无 sandbox_root。
- **输出**: 标准 scan + llm_points 均 ≥1 finding(path_traversal,0 确定性信号
  → evidence judge 认账);`prove.py` 确定性证明两类 allowlist 绕过。
- **状态**: allowlist/兄弟目录由 `_fresh.py` 幂等准备,每 run 全新 bridge 子进程。
- **变换**: 官方 0.6.2 工具透传(桥 tolerant list_tools 只补 schema 顶层
  type,不改行为);漏洞本体 = 前缀匹配 allowlist 未规范化(sibling + `..`)。
- **边界**: 仅 127.0.0.1 本地;secret 为自建假数据;依赖本机 npm 安装的 0.6.2
  源码;只读绕过,不涉及写/删(写方向留作后续)。
