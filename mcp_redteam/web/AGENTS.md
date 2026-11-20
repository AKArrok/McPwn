# web/ — 测评中台(本地只读 eval platform,`mcpwn ui`)

**输入**:`<runs_dir>/**/scan_result.json`、同目录 `findings.json` / `poc/*.py` /
`benchmark.md`,以及冻结协议的 holdout `summary.json`(以 `protocol_version`
键识别;其他实验的同名文件忽略)。全部为已落盘的产物,本模块不触发任何扫描。

**输出**:GET-only JSON API(`/api/platform` `/api/runs` `/api/findings`
`/api/runs/{run_id}` `/api/compare` `/api/holdout` `/api/metrics`)+ 静态托管
`ui/` 控制台;`export.py` 的 `mcpwn export-ui` 产出自包含静态快照站
(index.html + data.js,含 runs/findings/holdout/**metrics 聚合**投影,
内嵌 meta CSP `connect-src 'none'`)。响应模型
`RunSummary / FindingSummary / HoldoutSummaryView / RunMetrics /
GroupMetric / MetricsBundle` 等定义在 `contracts.py`,不本地重定义。

**状态**:API 服务仅内存——`RunIndex` 的 mtime+size 缓存(每次请求重 stat,
变更文件重解析)与 run 详情的请求级缓存。**唯一写盘路径是 `export-ui`**:
新建导出目录,已存在需 `--force`,失败清理半成品。API 的 detail 接口
按请求实时重读磁盘,永远呈现盘上真实内容。

**变换**:文件 → `RunSummary`(容错投影:历史产物缺字段取默认值,结构不可用
则跳过并计入 `skipped`,绝不 500)→ API 过滤/对比投影;同一次解析产出
`RunMetrics`(token 经济 / judge 行为计数 / 漏洞类覆盖),`web/metrics.py`
用 pandas 按维度聚合(experiment / 模型 / 日期 / stop_reason / vuln_class,
Langfuse/Inspect AI/MLflow 同款模式);holdout summary
**逐字段镜像,不重算** pass rate / CI(聚合唯一权威在 `eval/holdout`,
期望判定语义唯一权威在 `benchmark.expect_ok`)。

**边界**:
- 只读:`runs_dir` 下零写入、零删除;不执行扫描、不调用 LLM、不联网。
  例外仅 `export-ui`(见上,写新建目录)。
- CLI 默认绑 `127.0.0.1`;响应头与 `ui/serve.py` 同源(CSP/nosniff/
  no-referrer),唯一差别 `connect-src 'self'` 以允许同源 API。
- 产物本身在落盘时已经 `security.redact_scan_result` 脱敏,本层原样转发,
  不做二次改写(改写属于 report 层职责)。**快照导出只含摘要投影**
  (RunSummary/FindingSummary/HoldoutView/MetricsBundle),traces /
  attacker_messages / 完整 scan_result.json 永不出库;发布行为由使用者
  自行承担合规确认(目标授权 + 脱敏),CLI 输出附带该提醒。
- **数据中台红线**:`/api/metrics` 与洞察页只算**过程 / 成本 / 覆盖指标**
  (纯求和);通过率 / pass / fail 等判定数字一律只读 holdout summary,
  不在本层重算或另立口径。
- `ui/` 目录不入 wheel:从源码检出运行,或 `--ui-dir` 显式指定。
- API key 仅从 env 读取(本模块完全不读 key)。
