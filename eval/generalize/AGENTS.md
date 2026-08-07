# AGENTS.md — eval/generalize (delegate-mcp 泛化验证靶机)

- **输入**: SSE 端点 `http://127.0.0.1:PORT/sse`(`run_*` 脚本每 run 自动 spawn
  全新 `delegate_server.py`,端口 20005/20105+i);无 sandbox_root。
- **输出**: baseline 预期 0 findings;exploit 证据 = 非 owner 用户通过"自己的
  vault 授权"意外读到 `admin_vault` 的 secret(`TOP-SECRET-ADMIN-VAULT-2026`)。
- **状态**: 内存 `_VAULTS`(含预置 `admin_vault`,owner=admin)+ **全局**
  `_DELEGATES` set(漏洞本体:授权作用域错误),进程重启即复位;每 run 全新
  server 隔离 run 间状态。
- **变换**: create_vault / read_vault / list_vaults / grant_access(故意含
  CWE-639 delegate 授权作用域缺陷:grant 校验用精确 owner 相等(正确),但
  delegate 记入全局集合,泄漏到所有 vault)。
- **边界**: 仅 127.0.0.1;无持久化;无 auth 工具;纯实验靶机,禁止部署到任何
  真实环境。与 vault-mcp 形状不同(子串匹配 vs 授权作用域),机制差异见
  `README.md`。
