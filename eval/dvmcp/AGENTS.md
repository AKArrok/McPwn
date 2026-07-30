# eval/dvmcp/ — DVMCP regression harness (fixture, not the target)

- 输入: `expected.yaml` (每个 port 的预期 vuln class) + 一个 DVMCP 容器 (9001-9010).
- 输出: `eval_report.md` + `port_<port>/{findings.md, scan_result.json, ...}`.
- 状态: 无. 每 port 独立跑 `mcpwn scan`.
- 变换: for port in ports: scan -> collect findings -> 命中 `primary_class ∪ also_accept` 记 hit.
- 边界:
  * `expected.yaml` 是 **regression baseline**, 不是评测判据. 判据仍是 signals 库.
  * 状态污染 (challenge 4 状态计数器等) 通过 `mcpwn eval dvmcp reset --yes` 处理.
  * `poc_replay_pass_rate` M0 记为 placeholder; M2 打开真正的重放路径.
