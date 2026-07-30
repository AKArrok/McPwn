# report/ — 报告

**输入**:内存中的 `ScanResult`(由 `orchestrator/runner.scan` 返回)。

**输出**:`<out_dir>/findings.md` + `<out_dir>/poc/{finding_id}.py`。
完整的 `scan_result.json` 与 `traces/*.json` 由 runner / verifier 写入,不由本模块负责。

**状态**:无(纯离线渲染)。

**变换**:`ScanResult.findings` → `_finding_section` 拼 markdown;
`Finding.poc_call_sequence` → `_poc_script` 输出可 `python -m` 运行的 asyncio 脚本。

**边界**:
- 不重算 verdict / confidence(以 `Finding.confidence` 为准)。
- 不生成图表:findings 是 per-run 的定性发现,不做聚合可视化。DVMCP 回归的
  聚合指标由 `eval/dvmcp/runner.py` 输出到 `eval_report.md`。
- 不落原文敏感串:`matched_text` 已在 `signals/detectors._redact` 阶段脱敏。
- PoC 脚本必须能独立 `python <finding_id>.py` 运行(顶部合规声明常置)。
