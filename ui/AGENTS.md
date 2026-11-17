# ui/ — 本地控制台界面(测评中台前端)

- 输入：双形态。API 模式（`mcpwn ui`）从同源 `/api/*` 拉取 runs/ 产物的
  只读索引；无后端时（`serve.py` 静态托管或离线导入）使用明确标注的
  演示数据，用户选择的离线 findings.json 仅在浏览器本地读取。
- 输出：中文、键盘可用的扫描控制台：总览 / 目标 / 运行记录 / 发现项 /
  运行对比 / holdout 汇总 / 离线导入。
- 状态：当前页面、筛选、选中项与 API 数据缓存，只存在浏览器内存。
- 变换：不可信字段一律 textContent 渲染；本地 JSON 不上传；API 模式
  把后端投影（RunSummary/FindingSummary）映射为行数据后复用同一套渲染。
- 边界：不在浏览器运行 MCP/stdio，不持久化密钥，不将演示发现项冒充真实
  扫描结果（真实产物固定打“真实产物”标）；CSP 由服务端响应头下发
  （serve.py 为 connect-src 'none'，mcpwn ui 为 connect-src 'self'），
  index.html 不再内联 meta CSP；判定/置信度一律展示产物原文，前端不重算。
