# AGENTS.md — eval/unknown_shape (vault-mcp 实验靶机)

- 输入: SSE 端点 `http://127.0.0.1:9205/sse`（本机进程）；无 sandbox_root。
- 输出: baseline 预期 0 findings；exploit 证据 = `read_vault(owner="")` 返回他人 secret。
- 状态: 内存 `_VAULTS`（name -> owner/secret/delegates），重启即清空。
- 变换: create_vault / read_vault / list_vaults / grant_access（故意含 CWE-639 子串匹配缺陷）。
- 边界: 仅 127.0.0.1:9205；无持久化；无 auth 工具；纯实验靶机，禁止部署到任何真实环境。
