# targets/ — MCP 客户端

**输入**:`TargetSpec`(见 `contracts.py`;SSE / streamable HTTP 的 URL,或
stdio 启动命令 + env)+ 工具/资源调用参数。

**输出**:`McpCall`(见 `contracts.py`)+ 结果文本;分 `mcp_calls`(攻击)与
`recon_calls`(侦察)两条流。

**状态**:一次会话内保持一条传输连接(SSE / streamable HTTP / stdio 子进程);
每次 `list_tools/list_resources/call_tool/read_resource` 产生一条 `McpCall`
记入 AuditLog。

**变换**:官方 `mcp` SDK 的高层 API(`sse_client` / `streamable_http_client` /
`stdio_client`,兼容 1.x 与 2.0 命名)-> pydantic 化 `McpCall`。

**边界**:
- 不解读工具语义,不 sanitize description(HANDOFF §4)。
- 不缓存 `list_tools` 结果(每 turn 可能被 rug pull 改)。
- 不对 `call_tool` 的返回做失败-重试(交给上层)。
- `transport="auto"` 时非 `/sse` URL 先试 streamable HTTP、失败回退 SSE;
  显式声明的传输永不回退。stdio 子进程由本模块拉起并在退出时回收。
