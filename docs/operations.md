# Operating McPwn safely

McPwn is currently ready to land as a local or CI security-assessment CLI. It
is not a hosted security platform. This distinction is part of the product
contract, not a temporary disclaimer.

## Supported deployment levels

| Level | Status | Use |
|---|---|---|
| Local developer run | Supported | Disposable, authorized stdio or HTTP MCP targets. |
| CI runner | Supported with controls | Fixed target config, bounded budgets, SARIF/JSON artifacts, severity gate. |
| Scheduled internal assessment | Conditional | Add an allowlist, approval record, isolated runner, and artifact retention policy. |
| Public multi-tenant service | Not supported | Authentication, RBAC, secret management, job isolation, queueing, audit, and central observability do not exist. |

## Reproducible CI flow

Install from the lock file, then make the target configuration explicit:

```bash
uv sync --locked --extra dev
uv run mcpwn init --kind url --out mcpwn.yaml
uv run mcpwn scan --target-config mcpwn.yaml --out runs/ci-scan
uv run mcpwn validate-artifact runs/ci-scan
uv run mcpwn ci runs/ci-scan --fail-on high
```

For a reviewer-facing local view, open `docs/artifact-viewer.html` in a browser and
select the redacted `findings.json`. The viewer is intentionally static: it does
not connect to a target, call an API, or execute a generated PoC.

The command supports stdio, SSE, and Streamable HTTP targets. Every scan is
bounded by token, wall-clock, candidate, and inner-step limits. A budget stop
is `inconclusive`; it must not be reported as a clean scan.

## Secret boundary

`--env KEY=value` and `--headers name=value` are used in memory for the live
connection. Persisted `scan_result.json`, findings, SARIF, traces, and generated
PoCs do not retain those values:

- environment values become `${KEY}` references;
- header values become `${MCPWN_HEADER_NAME}` references;
- URL query values and common credential-shaped strings are redacted;
- replay resolves references from the local process environment and fails
  loudly if a required value is missing.

Keep `mcpwn.yaml`, `.env`, and raw target output outside commits. Review
server-returned content before publishing a trace: an unusual server can put a
secret in an arbitrary field that no pattern-based redactor can identify.

## Evidence needed for a release or résumé claim

Keep a redacted evidence bundle with the exact commit SHA, package version,
target fixture/version, transport, model/config, seed, budget, run count,
duration, token cost, and exit code. Include both positive and negative
controls. Do not turn the example output in `docs/demo_3min.md` into a claim of
current performance until the run has actually been collected.

For independent generalization claims, use a holdout that was not inspected
while tuning prompts, cards, or detectors. The checked-in protocol protects
against accidental manifest edits; it cannot make a publicly readable target
implementation blind by itself.

## Operational gaps before enterprise deployment

The following are deliberately outside the current CLI scope: user
authentication, RBAC, target approval workflow, centralized secret storage,
concurrent job isolation, durable job queue, tamper-evident audit log, remote
artifact retention, distributed tracing, and a production support process.
Build those only if the product requirement changes from a CI tool to a shared
service.
