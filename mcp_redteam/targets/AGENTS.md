# targets/ — MCP 客户端

**输入**:`base_url`(如 `http://127.0.0.1:9001/sse`)、工具/资源调用参数。

**输出**:`McpCall`(见 `contracts.py`)+ 结果文本;分 `mcp_calls`(攻击)与
`recon_calls`(侦察)两条流。

**状态**:一次会话内保持 SSE 连接;每次 `list_tools/list_resources/call_tool/read_resource`
产生一条 `McpCall` 记入 AuditLog。

**变换**:官方 `mcp` SDK 的高层 API -> pydantic 化 `McpCall`。

**边界**:
- 不解读工具语义,不 sanitize description(HANDOFF §4)。
- 不缓存 `list_tools` 结果(每 turn 可能被 rug pull 改)。
- 不对 `call_tool` 的返回做失败-重试(交给上层)。
