# Three-minute engineering demo

This is the shortest reviewer path from a target configuration to a CI decision. It
is a command walkthrough, not a claimed recording or a captured transcript. The
exact finding count, model response, and elapsed time depend on the authorized
target and the configured LLM endpoint.

## What this demo proves

The path demonstrates that McPwn has an operational delivery loop:

- a real MCP target can be described once in `mcpwn.yaml`;
- `scan` produces grounded human-readable and machine-readable artifacts;
- the artifact can be checked against the submitted JSON Schema;
- a later CI step can gate on the persisted artifact without re-running the LLM scan.

It does not prove that a clean scan is secure, that every MCP vulnerability is
found, or that DVMCP scores generalize to unknown servers. Findings still require
human triage.

## Demo path

Run this only against a local, authorized MCP server. `mcpwn init` writes a template;
edit the generated command or URL before scanning.

```bash
mcpwn init --kind stdio --out mcpwn.yaml
# Edit mcpwn.yaml: command, cwd, env, and any sandbox_root metadata.

mcpwn scan --target-config mcpwn.yaml --out runs/demo
mcpwn validate-artifact runs/demo
mcpwn ci runs/demo --fail-on high
```

The same flow works for an SSE or streamable HTTP target by using the corresponding
target-config template and transport. `mcpwn ci` consumes `findings.json`; it does
not repeat the scan.

### Example transcript (illustrative)

```text
$ mcpwn init --kind stdio --out mcpwn.yaml
wrote mcpwn.yaml

$ mcpwn scan --target-config mcpwn.yaml --out runs/demo
... scan completes; artifact paths are printed ...
wrote runs/demo/findings.md
wrote runs/demo/findings.json

$ mcpwn validate-artifact runs/demo
valid runs/demo/findings.json (schema_version=1)

$ mcpwn ci runs/demo --fail-on high
... gate decision is derived from persisted findings.json ...
```

The ellipses are intentional: this document does not invent a target-specific
finding, score, timing, or terminal transcript.

## Expected output tree

```text
mcpwn.yaml
runs/demo/
  findings.md             # human-readable findings (confidence >= 0.6)
  findings.json           # schema_version=1 artifact for CI/platforms
  findings.sarif          # SARIF export for compatible code-scanning UIs
  poc/<finding_id>.py     # replayable PoC for each reported finding
  traces/trace_*.json     # grounded call/evidence traces
  scan_result.json        # run metadata and stop_reason
  benchmark.md            # benchmark context when a target manifest matches
```

The exact optional files depend on the target and scan path. A finding is a
grounded, confidence-gated report entry; it is not a proof that the target is
secure or insecure without review of the evidence and PoC.

## CI integration

The repository CI exercises the artifact gate and wheel packaging smoke without a
Docker target, network, or LLM key. A consuming project can use the same shape:

```yaml
jobs:
  mcpwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e ".[dev]"
      - run: mcpwn scan --target-config mcpwn.yaml --out runs/mcpwn_scan
      - run: mcpwn validate-artifact runs/mcpwn_scan
      - run: mcpwn ci runs/mcpwn_scan --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: runs/mcpwn_scan/findings.sarif
```

Use `--allow-inconclusive` only when the pipeline owner explicitly wants a
non-completed scan to be evaluated as an artifact rather than treated as an
inconclusive failure. The default gate keeps `budget_*` and `error` runs distinct.

## Interview explanation

> McPwn is a CI-integrable MCP red-team agent. It turns an authorized MCP server
> into grounded findings, replayable PoCs, a versioned machine-readable artifact,
> and a severity gate. The important engineering boundary is that the LLM scan is
> persisted once and the CI decision is deterministic over that artifact. A clean
> result is not a security certification; reported findings still need human
> triage.

For evaluation claims, point to the evidence matrix. DVMCP is a seen/tuned
regression set; paired vulnerable/fixed targets establish causal evidence; only a
frozen holdout can support an external generalization claim.

