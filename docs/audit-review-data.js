// Static, redacted handoff data for the existing artifact viewer.
// Do not add raw MCP responses, credentials, tokens, or container file contents here.
window.MCPWN_AUDIT_REVIEW = {
  "schema_version": 1,
  "kind": "mcpwn_audit_review",
  "run_id": "20260910T160013Z-a2f5835b",
  "status": "completed",
  "scope": "DVMCP 9001–9010; Excel MCP 0.1.7 on 9203 and 0.1.8 on 9204",
  "summary": {
    "confirmed_vulnerabilities": 19,
    "entries_including_fix_verification": 20,
    "severity": {
      "Critical": 6,
      "High": 6,
      "Medium": 6,
      "Low": 1,
      "Info": 1
    },
    "surfaces": {
      "DVMCP": { "confirmed": 16, "fix_verification": 0 },
      "Excel MCP": { "confirmed": 3, "fix_verification": 1 }
    }
  },
  "source": {
    "report": "full_audit_report_20260910T160013Z-a2f5835b.md",
    "trace": "full_audit_trace_20260910T160013Z-a2f5835b.json",
    "evidence_policy": "页面只展示脱敏报告摘要；不展示原始响应、凭据、session token 或容器文件内容。"
  },
  "targets": [
    { "surface": "DVMCP", "port": 9001, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9002, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9003, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9004, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9005, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9006, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9007, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9008, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9009, "version": "1.29.0" },
    { "surface": "DVMCP", "port": 9010, "version": "1.29.0" },
    { "surface": "Excel MCP", "port": 9203, "version": "0.1.7" },
    { "surface": "Excel MCP", "port": 9204, "version": "0.1.8" }
  ],
  "entries": [
    {
      "id": "DVMCP-01",
      "title": "未授权读取隐藏敏感资源",
      "surface": "DVMCP",
      "ports": [9001],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Resource access",
      "evidence": "resources/read internal://credentials 返回 SYSTEM CREDENTIALS",
      "reproduction": "resources/read internal://credentials"
    },
    {
      "id": "DVMCP-02",
      "title": "资源内容可注入提示词",
      "surface": "DVMCP",
      "ports": [9001],
      "versions": ["1.29.0"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Prompt injection sink",
      "evidence": "notes://{user_id} 原样反射 AUDIT_C1_IGNORE_PREVIOUS_INSTRUCTIONS",
      "reproduction": "resources/read notes://<attacker-payload>"
    },
    {
      "id": "DVMCP-03",
      "title": "安全命令白名单可被 shell 注入绕过",
      "surface": "DVMCP",
      "ports": [9002],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Command injection",
      "evidence": "execute_command('pwd && printf ...') 执行了第二条命令",
      "reproduction": "execute_command: pwd && printf DVMCP_C2_INJECTED"
    },
    {
      "id": "DVMCP-04",
      "title": "read_file 路径穿越读取容器文件",
      "surface": "DVMCP",
      "ports": [9002],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Path traversal",
      "evidence": "通过 /tmp/safe/../../etc/hostname 绕过前缀检查",
      "reproduction": "read_file: /tmp/safe/../../etc/hostname"
    },
    {
      "id": "DVMCP-05",
      "title": "文件管理器无路径授权边界",
      "surface": "DVMCP",
      "ports": [9003],
      "versions": ["1.29.0"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Unbounded file permissions",
      "evidence": "同一工具成功 read/write/delete /etc 或任意路径",
      "reproduction": "file_manager: read/write/delete /etc or arbitrary path"
    },
    {
      "id": "DVMCP-07",
      "title": "天气工具状态型 rug pull",
      "surface": "DVMCP",
      "ports": [9004],
      "versions": ["1.29.0"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Stateful rug pull",
      "evidence": "同一会话前三次返回天气，第四次变为付费升级提示",
      "reproduction": "get_weather ×4: normal output → upgrade prompt"
    },
    {
      "id": "DVMCP-08",
      "title": "相似工具名导致角色越权/工具混淆",
      "surface": "DVMCP",
      "ports": [9005],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Authorization confusion",
      "evidence": "get_user_role(bob)=user，而 get_user_roles(bob)=admin, superuser, system",
      "reproduction": "get_user_role(bob)=user vs get_user_roles(bob)=admin,..."
    },
    {
      "id": "DVMCP-09",
      "title": "间接提示注入：文档内容原样进入分析输出",
      "surface": "DVMCP",
      "ports": [9006],
      "versions": ["1.29.0"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Indirect prompt injection",
      "evidence": "process_document 返回包含完整攻击者文档内容",
      "reproduction": "process_document: attacker-controlled document text"
    },
    {
      "id": "DVMCP-10",
      "title": "认证接口直接泄露且可预测 session token",
      "surface": "DVMCP",
      "ports": [9007],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Predictable token",
      "evidence": "admin 登录响应返回 token，且与 MD5(admin:<当前秒>) 匹配",
      "reproduction": "authenticate(admin) → MD5(admin:<current timestamp>)"
    },
    {
      "id": "DVMCP-11",
      "title": "verify_token 只验证 MD5 格式不验证真实性",
      "surface": "DVMCP",
      "ports": [9007],
      "versions": ["1.29.0"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Token validation bypass",
      "evidence": "伪造的 32 个零仍返回 appears to be valid",
      "reproduction": "verify_token: 32 zeroes → appears valid"
    },
    {
      "id": "DVMCP-12",
      "title": "evaluate_expression 任意 Python 代码执行",
      "surface": "DVMCP",
      "ports": [9008],
      "versions": ["1.29.0"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Arbitrary code execution",
      "evidence": "eval 表达式成功调用 os.popen 并返回 DVMCP_C8_EVAL",
      "reproduction": "evaluate_expression: __import__('os').popen(...)"
    },
    {
      "id": "DVMCP-13",
      "title": "admin-console 仅检查 token 非空",
      "surface": "DVMCP",
      "ports": [9009],
      "versions": ["1.29.0"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Weak admin authentication",
      "evidence": "auth_token=not-a-token 即返回 admin command executed",
      "reproduction": "remote_access admin-console with auth_token=not-a-token"
    },
    {
      "id": "DVMCP-14",
      "title": "权限管理无认证/授权检查",
      "surface": "DVMCP",
      "ports": [9009],
      "versions": ["1.29.0"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Missing authorization",
      "evidence": "匿名 manage_permissions(grant) 返回 permission applied",
      "reproduction": "manage_permissions(grant) without authentication"
    },
    {
      "id": "DVMCP-15",
      "title": "get_config 允许绝对路径读取任意文件",
      "surface": "DVMCP",
      "ports": [9010],
      "versions": ["1.29.0"],
      "severity": "High",
      "status": "confirmed",
      "kind": "Arbitrary file read",
      "evidence": "绝对路径 /etc/hostname 被当作配置文件成功读取；部署环境没有创建 README 所述 system.conf",
      "reproduction": "get_config: /etc/hostname"
    },
    {
      "id": "DVMCP-16",
      "title": "process_user_input 原样反射不可信输入",
      "surface": "DVMCP",
      "ports": [9010],
      "versions": ["1.29.0"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Input reflection",
      "evidence": "返回模板包含 AUDIT_C10_UNTRUSTED_INPUT",
      "reproduction": "process_user_input: attacker payload appears in output"
    },
    {
      "id": "DVMCP-17",
      "title": "公开资源泄露运行时/容器信息",
      "surface": "DVMCP",
      "ports": [9010],
      "versions": ["1.29.0"],
      "severity": "Low",
      "status": "confirmed",
      "kind": "Information disclosure",
      "evidence": "system://info 返回 OS、Python、machine、node",
      "reproduction": "resources/read system://info"
    },
    {
      "id": "EXCEL-01",
      "title": "0.1.7 文件路径可逃逸 EXCEL_FILES_PATH",
      "surface": "Excel MCP",
      "ports": [9203],
      "versions": ["0.1.7"],
      "severity": "Critical",
      "status": "confirmed",
      "kind": "Sandbox escape",
      "evidence": "create/write/read ../audit_escape_<run>.xlsx 成功；文件落在 /tmp/sandbox 外",
      "reproduction": "create/write/read ../audit_escape_<run>.xlsx"
    },
    {
      "id": "EXCEL-03",
      "title": "write_data_to_excel 绕过公式安全校验",
      "surface": "Excel MCP",
      "ports": [9203, 9204],
      "versions": ["0.1.7", "0.1.8"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Formula validation bypass",
      "evidence": "WEBSERVICE 公式可通过通用写入接口持久化；该接口不调用公式校验",
      "reproduction": "write_data_to_excel: =WEBSERVICE(...)"
    },
    {
      "id": "EXCEL-04",
      "title": "公式危险函数黑名单可用小写绕过",
      "surface": "Excel MCP",
      "ports": [9203, 9204],
      "versions": ["0.1.7", "0.1.8"],
      "severity": "Medium",
      "status": "confirmed",
      "kind": "Case-sensitive denylist bypass",
      "evidence": "大写 WEBSERVICE 被拒绝，但 apply_formula 接受小写 hyperlink 并写入单元格",
      "reproduction": "apply_formula: =hyperlink(...)"
    },
    {
      "id": "EXCEL-02",
      "title": "0.1.8 已修复路径逃逸",
      "surface": "Excel MCP",
      "ports": [9204],
      "versions": ["0.1.8"],
      "severity": "Info",
      "status": "fix_verification",
      "kind": "Fix verification",
      "evidence": "同样的 ../ 路径被拒绝；这是修复验证，不是漏洞",
      "reproduction": "Excel 0.1.8 rejects the same ../ path"
    }
  ],
  "notes": [
    "EXCEL-02 是修复验证项，不计入 19 个确认漏洞。",
    "9005 未按字面上的同名 MCP 工具冲突计数；页面保留实际行为导致的权限混淆 finding。",
    "9010 以已部署 SSE 变体的真实工具行为为准，不采用旧 source 注释作为证据。",
    "9003 的资源 URI 穿越负向测试未计入漏洞。"
  ]
};
