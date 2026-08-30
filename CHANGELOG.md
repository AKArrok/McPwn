# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

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
