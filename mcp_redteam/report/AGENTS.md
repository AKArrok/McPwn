# report/ — 报告

**输入**:内存中的 `ScanResult`(由 `orchestrator/runner.scan` 返回)。

**输出**:`<out_dir>/findings.md` + `<out_dir>/findings.json` +
`<out_dir>/findings.sarif` + `<out_dir>/poc/{finding_id}.py`;
`benchmark.py` 另产出 `<out_dir>/benchmark.md`(per-target benchmark 报告)。
完整的 `scan_result.json` 与 `traces/*.json` 由 runner / verifier 写入,不由本模块负责。

**状态**:无(纯离线渲染)。

**变换**:`ScanResult.findings` → `_finding_section` 拼 markdown + `model_dump`
生成 schema_version=1 的 JSON artifact(结构由 `mcp_redteam/schemas/findings-v1.schema.json`
锁定);
`Finding.poc_call_sequence` → `_poc_script` 输出可 `python -m` 运行的 asyncio 脚本。

**边界**:
- 不重算 verdict / confidence(以 `Finding.confidence` 为准)。
- benchmark.md 是 per-target 的(每个靶场扫完一份);跨靶场聚合页不在此层。
  期望判定语法 (`0|>=1|info`) 唯一权威在 `benchmark.expect_ok`,
  `eval/targets/run.py` 复用之,不允许本地重写。
- 所有报告与 PoC 写入前都必须使用 `security.redact_scan_result`;目标 env/header
  值保存为可重放引用,URL query 和常见凭证形态做脱敏。`matched_text` 仍在
  `signals/detectors._redact` 阶段指纹化,但 server-returned 任意字段仍需人工审查。
- PoC 脚本必须能独立 `python <finding_id>.py` 运行(顶部合规声明常置)。
