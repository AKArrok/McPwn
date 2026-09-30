# McPwn 控制台界面预览

这是 D 盘独立工作树里的前端排版预览，使用明确标注的演示数据。当前 `origin/main` 没有 Web 后端，所以“新建扫描”只展示交互和预算摘要，不会发起真实扫描。离线导入只在浏览器内读取 JSON。

在本目录运行：

```powershell
python serve.py
```

打开 http://127.0.0.1:8765/ 。无前端依赖或构建步骤。

设计参考：GitHub Security 的组合筛选、Sentry 的事件详情主次结构、DefectDojo 的可下钻概览。实现保持本地单用户语境，演示数据与真实结果始终有清楚标记。

- https://docs.github.com/en/code-security/how-tos/manage-security-alerts/remediate-alerts-at-scale/filtering-alerts-in-security-overview
- https://docs.sentry.io/product/issues/issue-details/
- https://docs.defectdojo.com/metrics_reports/dashboards/introduction_dashboard/

验收：2026-09-30，Node 语法检查通过；Playwright 使用本机 Edge 完成 1440px、768px、390px 验收。导航、运行状态筛选、发现项搜索和详情、预算切换、离线 JSON 导入通过；恶意 HTML 字段按文字显示，无执行、无页面错误、无页面横向溢出。

此版本是界面预览，尚未接入扫描后端。没有真实扫描、重放或探测能力。后续接入时应从集中契约生成类型并使用受控后端 API。

## 可复跑验收

应用运行无需 npm。以下依赖仅用于浏览器测试。先在另一个终端启动上面的本机服务器，然后在 ui 目录执行：

```powershell
npm ci
npx playwright install chromium
npm run lint
npm test
```

若使用本机 Edge，可跳过浏览器下载，设置 `$env:PLAYWRIGHT_CHANNEL='msedge'` 后执行 `npm test`。可用 `PREVIEW_URL` 指向另一个本机预览端口；测试截图输出到忽略的 `test-results/` 目录。

Review 修复了筛选后详情仍显示旧记录、空结果仍展示旧证据、总览打开记录受旧筛选影响和浏览器历史导航的问题。测试还覆盖错误 JSON、空 findings、移动端键盘导航、恶意标签和离线导入无外部请求。

启动器始终只监听 127.0.0.1，可用 `python serve.py --port 8766` 换端口；它只提供静态文件，不执行扫描。响应包含 CSP、nosniff 和 no-referrer，禁止脚本发起网络连接和加载第三方资源。系统级浏览器扩展或安全软件可能影响测试；可把 `PREVIEW_URL` 设为 index.html 的 file URI 验收原始静态文件。

本机 Edge 的 HTTP 页面被 Kaspersky 注入第三方脚本，系统级注入不受页面 CSP 约束。需要隔离该干扰时，设置 `$env:PREVIEW_ISOLATE_HTTP='1'`：Playwright 通过自己的 HTTP 客户端读取**真实服务器响应**后交给浏览器，不替换任何页面数据，也不放宽外部请求断言。CI 默认直接测试 HTTP；本机已通过原始 file URI 和此 HTTP 隔离模式的完整验收。普通 Edge HTTP 会因安全软件外部请求而在最后一项断言失败，不能据此宣称该浏览器环境无外部请求。
