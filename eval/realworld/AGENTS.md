# eval/realworld/ — 真实世界 MCP 靶机 harness (excel-mcp-server CVE-2026-40576)

- 输入: `targets.yaml` (excel-0.1.7 positive + excel-0.1.8 negative; 每 target
  含 sse_url / version / cve / sandbox_root / container / expected_signals /
  prove_expect / marker_path) + 两个已部署容器 excel-mcp-017(:9203) 与
  excel-mcp-018(:9204), 由 deploy.ps1 --yes 拉起.
- 输出: `runner.py` -> `out_dir/eval_report.md` (per-target PASS/FAIL 表 +
  PASS 数/总数 总结) + `out_dir/<name>/` 下 `findings.md` 等 scan 产物;
  `prove.py` -> `<out>/<name>/proof_report.md` (3-call 链 + in-band 断言 +
  docker exec out-of-band 核对 + 最终 PASS/FAIL).
- 状态: 无持久状态. runner 用 orchestrator 串行预算; prove 直连 MCP 不走
  LLM, 攻击 marker 留在靶机 /root/ 属攻击产物, 不自动清理.
- 变换:
  1. `run_all`: for target in targets: `scan(sse_url, out_dir/<name>,
     sandbox_root)` -> `write_findings`; positive 门 = 任一 finding 的
     signal_id ∩ expected_signals ≠ ∅; negative 门 = 无任何 finding 带
     `sandbox_escape*` 前缀信号; 异常记 ERROR 继续.
  2. `prove_target(name)`: nonce = `MCPWN-<UTC %Y%m%dT%H%M%S>-<6 hex>`;
     marker = marker_path.replace("<nonce>", nonce).
  3. exploited: create_workbook -> write_data_to_excel -> read_data_from_excel
     断言 + docker exec `ls -la` + openpyxl 读回 A1 == nonce.
  4. blocked: 只 create_workbook, 断言被拒 (must be relative / Invalid
     filename) + docker exec `ls -la` 必须找不到文件.
- 边界:
  * **docker exec 必须 list 形式 subprocess**, 禁止拼 shell 字符串.
  * docker CLI / 容器不在 -> prove FAIL 并提示"先跑 deploy.ps1 --yes",
    不自动拉起容器.
  * **本目录只允许这 5 个文件**, 不碰 cli.py / mcp_redteam/* / tests/*.
  * runner 依赖并行实现的 `scan(..., sandbox_root=...)` 签名与
    sandbox_escape_write/read/traversal 信号 id (见 HANDOFF_TARGETS §6).
  * LLM 在环: scan 是单次点估计, 同 seed 可能漂移; prove 是确定性
    3-call 链, 不走 LLM, 结果可复现.