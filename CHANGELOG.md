# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [0.3.0] - 2026-10-05

### Added

- **预算/成本 harness 闭环** (trace cap / 上下文压缩 / 提示词瘦身 / 缓存计量):
  per-trace token 子闸门 (`trace_token_cap`, 默认 40% 预算, `-1` 关闭),
  executor 上下文压缩 (最近 2 工具轮全文, 更早结果截 digest, 证据链仍读
  `attack_calls` 全量), 提示词 bundle -19%, DeepSeek 前缀缓存有效成本计量
  (`attacker_tokens_effective`, 命中按 1/10 折算)。
- `ui/` 本地中文控制台预览 (只读 findings 查看器, `serve.py` + browser
  smoke + 独立 `ui-preview.yml` workflow);`docs/audit-review-data.js` 与
  `docs/artifact-viewer.html` 增强。

### Changed

- **judge 角色切换 Qwen**: `qwen3.8-27b` @ 阿里云百炼 DashScope OpenAI
  兼容端点 (`DASHSCOPE_API_KEY`);现役 config/README/eval 文档中 ARK/doubao
  残留清除 (历史记录保留)。
- README 评估数字刷新为 N=3 定稿口径:DVMCP 回归集 runner **30/30 (1.00)** /
  graph **29/30 (0.97)**,FPR 恒 0 (约 200 次 scan),replay 15/15;effective
  tok/finding 3.4k-3.6k (对照基线 -68%/-80%);新增英文 TL;DR。

### Fixed

- **9006 (indirect) 双路径翻转**: L2 judge 重校准为判「server 传输路径无隔离」
  (而非「攻击者是否服从」);judge 调用网络错误重试一次;judge 用户消息补
  args;两张注入卡明确 `INJECTION_MARKER_` + >=6 位 hex 标记格式 — recall
  0.80 → 1.00/0.97 @N=3。
- **9009 (auth_bypass) 检出缺口**: `_AUTH_SUCCESS_PHRASES` 补 `command
  executed`/`executed on` (仅假凭据第一遍, 低噪声);`_ADMIN_RE` 补
  `permission ... applied/granted` 自授权确认 (前缀锚定, 冻结协议不破)。

### Added (2026-08-31, redaction & release hardening)

- Persisted scan artifacts now pass through a shared redaction boundary:
  target env/header values become local replay references, URL query values and
  credential-shaped fields are redacted, and generated PoCs resolve references
  only from the operator's local environment.
- Added release metadata checks, locked uv-based CI installation, Dependabot,
  CodeQL, dependency auditing, and a tag-triggered wheel verification workflow.
- Added a local read-only findings.json viewer and operations/contributing/security
  documentation that state the supported CI boundary and the gaps before any
  hosted multi-tenant deployment.
- **Real-target config entrypoint**: `mcpwn init` now writes a reusable
  `mcpwn.yaml`, and `mcpwn scan --target-config mcpwn.yaml` compiles that
  file into the existing `TargetSpec` scan path. This makes scanning a
  non-fixture MCP server a first-class workflow instead of a long ad-hoc CLI
  command.
- **Machine-readable findings artifact**: every `write_findings` call now also
  emits `findings.json` (`schema_version=1`) with run metadata, counts,
  findings, and static hits for CI/platform integration.
- **CI gate command**: `mcpwn ci <out_dir|findings.json>` evaluates the
  persisted artifact without re-running the LLM scan. It fails on configurable
  severity thresholds, includes static hits by default, and uses distinct exit
  codes for risk found, malformed artifact, and inconclusive scans.
- **Repository CI exercises the artifact gate**: `.github/workflows/ci.yml`
  now runs `scripts/ci_artifact_smoke.py`, which checks the installed CLI
  returns 0 for a clean synthetic artifact and 1 for a high-severity artifact.
- **Versioned findings JSON Schema**: `mcp_redteam/schemas/findings-v1.schema.json`
  defines the external artifact contract, `mcpwn validate-artifact` validates
  it directly, and `mcpwn ci` rejects schema-invalid artifacts before applying
  severity gates.
- **Wheel packaging smoke**: `scripts/package_smoke.py` builds the wheel,
  verifies packaged config/schema/prompt/card resources, installs it into a
  temporary venv, and exercises the generated `mcpwn` entrypoint; CI runs it
  on both Linux and Windows.
- **Frozen holdout evaluation protocol** (`eval/holdout/`): the four-piece
  credibility work from review feedback — 漏洞版/修复版配对 + 冻结 holdout +
  N≥5 重复 + 对照证据验证.
  - `manifest.yaml` + `lock.json` (sha256) freeze: any edit to the manifest
    (hint, relaxed criterion, swapped expected signals) aborts every protocol
    run until a deliberate `freeze.py`; `minimum_repeats=5`
    (key targets 10), N<5 aborts on LLM rounds.
  - Paired-run verdict (`evaluate_pair_run`): positive detected (class +
    deterministic signal, or a grounding-gated `llm_evidence_verdict` for
    holdout pairs) AND fixed-version clean AND control replay passed
    (grounded + denied + no forbidden signal reproduced) — a detection
    without its negative control is not causal.
  - Control replay (`replay_finding_on_control`): replays a finding's PoC
    onto the FIXED server; denied calls are evidence of the fix and are not
    scanned for signal reproduction.
  - Evidence taxonomy clarified: DVMCP is a seen/tuned regression test set;
    excel/filesystem pairs are validation/causal controls; only frozen
    holdout pairs support external generalization claims; N≥5 measures
    repeated LLM variance on the same target, not sample size.
  - New frozen holdout pair **cache-mcp** (multi-tenant cache key collision,
    CWE-345 flavour): vulnerable version keys the store by bare key so tenant
    B reads tenant A's cached value; fixed version namespaces by `(owner, key)`
    with verbatim-identical tool descriptions. Deterministic prove PASS on
    both versions; baseline scan stays at 0 findings (unknown-shape premise);
    hermetic regression in `tests/test_holdout_pair.py`.
- New tests: `tests/test_holdout_protocol.py` (protocol contract, GPT-written)
  + `tests/test_holdout_pair.py` (unknown-shape premise freeze, replay edges,
  real fixed-server causal closed loop).

### Notes

- Judge role now runs Qwen `qwen3.8-27b` via DashScope (`DASHSCOPE_API_KEY`);
  the llm-round evidence channel is restored. Holdout `--mode llm --n 5` on
  the cache-mcp pair is still pending — numbers land in runs/ artifacts.

## [0.2.0] - 2026-08-30

Three-transport connection layer, per-target benchmarking, static
screening, supply-chain vetting, SARIF export, and a batch of
real-failure-driven robustness fixes.

### Added

- **Three MCP transports** (`mcp_redteam/targets/mcp_client.py`):
  `sse` / `streamable_http` / `stdio` behind one `TargetSpec` contract
  (`transport=auto` dispatch: `/sse` URLs stay on legacy SSE, other HTTP
  URLs try Streamable HTTP with SSE fallback; stdio via `--command`).
  Dual-compatible with mcp SDK 1.x and 2.0 API naming.
- **Per-target benchmark reports** (`mcpwn benchmark <target>` +
  `benchmark.md` auto-attached to every scan): manifest verdict
  (PASS/FAIL/INFO), vuln-class coverage across the fixed 8-class taxonomy,
  budget/efficiency incl. tokens-per-finding and **first-class overshoot
  rows**, evidence-judge independence flag.
- **Static screening layer** (`mcpwn static-scan`, zero-LLM): regex
  heuristics over tool/resource metadata (instruction override,
  concealment, exfiltration, cross-origin, credential/exec surfaces,
  sandbox escape, internal endpoints) - the cheap layer peers like
  mcp-scan lead with; rides recon so every scan gets it for free.
- **Supply-chain vetting** (`mcpwn vet-package`): package typosquat
  detection against a bundled list of well-known MCP servers +
  known-malicious registry (public disclosures only), plaintext-remote
  flag; integrated into every scan for stdio targets.
- **SARIF 2.1.0 export** (`findings.sarif` next to findings.md): findings
  + static hits in GitHub Code Scanning-compatible form.
- **Property-based contract tests** (hypothesis): `TargetSpec.parse`
  invariants and round-trip, `compute_id` determinism, `expect_ok`
  totality.
- **Coverage gate**: pytest-cov in CI, `fail_under = 75` (measured 78%).
- **pre-commit hooks** (ruff + hygiene) and **uv.lock**.

### Fixed

- `ScanResult.total_tokens` is now a validator-derived field:
  `scan_result.json` round-trips (previously a computed_field that broke
  re-loading under `extra="forbid"`) - offline aggregation possible.
- Connection errors now name the target/transport/fallback state and roll
  back partially entered contexts (previously leaked sockets on
  mid-initialize failure).
- A TCP-accepting-but-silent server hung 300 s before `initialize`:
  `sse_read_timeout` now wired to `read_timeout` across all transports
  (300s -> bounded).
- mcp floor raised to `>=2.0` (test fixtures use the 2.0 API); SDK 1.x
  vs 2.0 naming (McpError, streamable client, read_timeout types) handled
  in the client layer.
- Spawner port hygiene: bridge ports fall back to ephemeral when the
  historical default is occupied; semantic ports fail fast with a
  remediation hint instead of hanging.
- CLI rejects `target` + `--command` together instead of silently
  dropping the URL.
- CI chronic red since 2026-08-07 fixed (check_docs now skips
  gitignored local docs instead of FileNotFoundError) and matrix extended
  to windows-latest (UTF-8 forced; cp1252 subprocess crash fixed).

## [0.1.x] - 2026-08 (pre-history)

- Agent-first v1 pipeline: recon -> planner -> attacker loop -> verifier
  with signal-grounded findings (confidence >= 0.6 gate), 8-class MCP
  vulnerability taxonomy with one strategy card per class, three Stage-2
  LLM decision points (hypothesis generation / zero-finding retrospective /
  grounded evidence judgment).
- DVMCP regression harness + real-world targets (excel-mcp CVE-2026-40576
  exploit/block proof pairs), manifest-based unified eval runner,
  LangGraph parity path, M3 planner A/B judge.
- docs/agent_chain.md walkthrough, scripts/check_docs.py doc-code
  consistency guard.
