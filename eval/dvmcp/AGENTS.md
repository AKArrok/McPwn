# eval/dvmcp/ — DVMCP regression harness (fixture, not the target)

- 输入: `expected.yaml` (10 港, 每港含 `port` + `name` + `primary_class` +
  `also_accept` + `expected_signals` + `evidence_hint`) + 一组 DVMCP 容器
  (9001-9010, 串行启动, 状态独立).
- 输出: `eval_report.md` (recall / FPR / avg_findings_per_port /
  poc_replay_pass_rate) + `port_<port>/{findings.md, scan_result.json, traces/, poc/}`.
- 状态: 无. 每 port 独立跑 `mcpwn scan`, 串行 (orchestrator/AGENTS.md 已规定).
  scan 内部预算 (TokenBudget / WallClock) 跨所有 trace 共享, 见 agent/AGENTS.md.
- 变换:
  1. `for port in ports`: 调 `mcpwn scan http://127.0.0.1:<port>/sse` -> `ScanResult`
  2. 对每条 finding 取 `signal_id` 集合 vs `expected_signals` 集合: 交集非空
     -> 该 port 记 hit (一港只要有一个 finding 命中, 整港算 hit).
  3. 抽最多 5 个 finding (总数 <= 5 全部抽, 否则 random.sample), 重连 MCP,
     重放 `poc_call_sequence`, 跑 `run_all_signals` 检 `signal_id` 是否重现
     -> `poc_replay_pass_rate` (分子=重现 sample 数, 分母=抽样数).
  4. 写 `eval_report.md` (recall + FPR + per-port 表).
- 边界:
  * **hit 判定 = signal-based** (commit 83b5146 起, 取代 v0 的
    `primary_class ∪ also_accept`). `primary_class` 与 `also_accept` 仅作
    人类阅读与 cross-port 统计用, 不参与 recall 计算.
  * **`expected_signals` 是 ground truth 列表, 不是 detector 反推结果**.
    规格顺序固定: HANDOFF §6 冻结 12 条信号语义 -> `signals/detectors.py`
    实现 -> `expected.yaml` 标注每港期望哪些 signal fire. 改 expected.yaml
    必须有可追溯理由 (git commit message 必带 reason, 否则视作自评污染).
  * **`poc_call_sequence` 重放不重算 finding**, 只重放 calls + 跑
    `run_all_signals` 看 signal_id 是否重现. verifier / LLM judge 都不重跑.
  * **状态污染** (9004 状态计数器等) 通过 `mcpwn eval dvmcp reset --yes`
    处理 (`orchestrator/reset_hook.py`, 默认 dry-run).
  * **DVMCP 是已见过、已反复调参的 regression test set, 不是泛化测试集**.
    当前 FPR 在 10 港上测的是 "agent 在 DVMCP-shape 上不误报 DVMCP-shape
    的端口", 不是 "agent 在干净 MCP server 上不报警". 后者需要额外的
    negative sample set.
  * 8/10、9/10、FPR 0、replay 5/5 只能证明当前版本没有破坏这些已知案例,
    不能外推为陌生 MCP 80%-90% recall. 独立泛化结论只看冻结 holdout.
  * **N=1 跑 scan** 没有稳定性约束. LLM 在环, 同 seed 重跑结果可能漂移.
    当前 recall 是单次点估计, 没置信区间. N>=5 也只测同一目标上的 LLM
    运行方差,不是增加样本数.
