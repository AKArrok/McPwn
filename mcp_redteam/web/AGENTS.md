# web/ — 测评中台(本地只读 eval platform,`mcpwn ui`)

**输入**:`<runs_dir>/**/scan_result.json`、同目录 `findings.json` / `poc/*.py` /
`benchmark.md`,以及冻结协议的 holdout `summary.json`(以 `protocol_version`
键识别;其他实验的同名文件忽略)。全部为已落盘的产物,本模块不触发任何扫描。

**输出**:GET-only JSON API(`/api/platform` `/api/runs` `/api/findings`
`/api/runs/{run_id}` `/api/compare` `/api/holdout`)+ 静态托管 `ui/` 控制台。
响应模型 `RunSummary / FindingSummary / HoldoutSummaryView` 等定义在
`contracts.py`,不本地重定义。

**状态**:仅内存——`RunIndex` 的 mtime+size 缓存(每次请求重 stat,
变更文件重解析)与 run 详情的请求级缓存。**不写任何文件**;detail 接口
按请求实时重读磁盘,API 永远呈现盘上真实内容。

**变换**:文件 → `RunSummary`(容错投影:历史产物缺字段取默认值,结构不可用
则跳过并计入 `skipped`,绝不 500)→ API 过滤/对比投影;holdout summary
**逐字段镜像,不重算** pass rate / CI(聚合唯一权威在 `eval/holdout`,
期望判定语义唯一权威在 `benchmark.expect_ok`)。

**边界**:
- 只读:`runs_dir` 下零写入、零删除;不执行扫描、不调用 LLM、不联网。
- CLI 默认绑 `127.0.0.1`;响应头与 `ui/serve.py` 同源(CSP/nosniff/
  no-referrer),唯一差别 `connect-src 'self'` 以允许同源 API。
- 产物本身在落盘时已经 `security.redact_scan_result` 脱敏,本层原样转发,
  不做二次改写(改写属于 report 层职责)。
- `ui/` 目录不入 wheel:从源码检出运行,或 `--ui-dir` 显式指定。
- API key 仅从 env 读取(本模块完全不读 key)。
