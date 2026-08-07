# AGENTS.md — eval/fetch_ssrf(真实 fetch 靶机,SSRF 验证)

- **输入**: SSE 端点 `http://127.0.0.1:9210/sse`(桥暴露的官方 mcp-server-fetch);
  内网受害者服务 `127.0.0.1:{8000,8080,9211}`。`_fresh.py` 每 run 自动 spawn
  两者并清理。无 sandbox_root。
- **输出**: 标准 scan 预期 ≥1 条 `ssrf_internal_service` finding(high 0.75);
  `llm_points` 版同样 ≥1。`prove.py` 确定性断言 `fetch("http://127.0.0.1:9211/")`
  回流内网 secret。
- **状态**: 桥内 fetch 子进程 + intranet 服务均为每 run 全新进程(无跨 run 状态)。
- **变换**: 官方 `mcp-server-fetch` 单一 `fetch(url, max_length, start_index, raw)`
  工具,由 server 侧 httpx 抓取 URL 并带回内容(SSRF 面);`bridge.py` 仅透传
  schema/调用,不修改行为。
- **边界**: 仅 127.0.0.1 本地进程;内网受害者是自建假服务(无真实敏感数据);
  禁止将抓取目标指向任何未授权系统/公网(合规声明见 README)。
