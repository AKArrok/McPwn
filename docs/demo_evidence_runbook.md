# Real demo evidence runbook

This runbook describes how to collect a real McPwn demo artifact. It is an
operator procedure, not a prerecorded result. The operator must use only local,
authorized targets and must inspect/redact the captured material before sharing it.

## What the evidence contains

The demo has two separate evidence chains:

1. **Deterministic proof**: the existing excel-mcp vulnerable/fixed pair proves the
   recorded behavior without an attacker LLM.
2. **Live agent scan**: McPwn scans the vulnerable target, writes grounded
   artifacts, validates `findings.json`, and applies the CI severity gate.

The excel pair is a validation/causal case. It is not a frozen holdout and does not
support a general MCP recall claim. DVMCP numbers remain seen/tuned regression
evidence.

## Preconditions

- Docker Desktop is running and the operator is authorized to use the local fixture.
- Python 3.13 and the repository development dependencies are installed.
- The attacker model endpoint is configured according to
  `mcp_redteam/config/models.yaml`; required environment variable presence may be
  checked, but values must never be printed or committed.
- No API key, bearer token, cookie, or production URL is stored in
  `examples/demo_excel_017.yaml`.
- The operator has a screen recorder or terminal recorder ready. A recording is
  evidence only after the operator checks it for secrets and sensitive paths.

## Safe preflight

From the repository root, run the read-only check first:

```powershell
pwsh -File scripts/demo_evidence.ps1 -Check
```

The check may report that Docker or a model environment variable is unavailable;
it must not start, stop, remove, or scan anything. The deployment script's own
`-Check` mode is also read-only:

```powershell
pwsh -File targets/realworld/deploy.ps1 -Check
```

## Live collection

Every state-changing or attack action requires `-Yes` and an explicit action.

### One-command operator flow

After preflight, this is the preferred recording path. It creates one unique
bundle, runs every stage, and does not clean containers:

```powershell
pwsh -File scripts/demo_evidence.ps1 -RunAll -Yes
```

### Step-by-step operator flow

Use an explicit output directory and `-Resume` when the recording needs to show
each stage separately. Every command below writes to the same bundle:

```powershell
$run = 'runs/demo_evidence/20260909T120000'
pwsh -File scripts/demo_evidence.ps1 -Deploy -Yes -Out $run
```

This delegates to the existing `targets/realworld/deploy.ps1 -Yes`. It manages only
the documented local containers `excel-mcp-017` on port 9203 and `excel-mcp-018` on
port 9204.

### 1. Run deterministic proof

```powershell
pwsh -File scripts/demo_evidence.ps1 -Prove -Yes -Out $run -Resume
```

The output records the existing three-call exploit sequence for 0.1.7 and the
one-call rejection proof for 0.1.8.
The proof result is not an LLM recall measurement.

### 2. Run the live scan

```powershell
pwsh -File scripts/demo_evidence.ps1 -Scan -Yes -Out $run -Resume
```

The positive target uses the checked-in local config
`examples/demo_excel_017.yaml`. The fixed target is scanned separately at
`http://127.0.0.1:9204/sse` with the same declared sandbox root. The script records
both command exit codes and scan output paths; it does not reinterpret a scan as a
security certification.

### 3. Validate and gate the persisted artifact

```powershell
pwsh -File scripts/demo_evidence.ps1 -Validate -Yes -Out $run -Resume
pwsh -File scripts/demo_evidence.ps1 -Gate -Yes -Out $run -Resume
```

Both `findings.json` files must pass schema validation. The CI gate is evaluated for
both targets and has intentional exit semantics: `0` means no item reached the
configured threshold, `1` means a finding or static hit reached it, `2` means an
invalid/missing artifact, and `3` means an inconclusive scan by default. For a
vulnerable demo, a gate exit code `1` can be an expected policy result; it is not
automatically a script failure. The fixed target is expected to be reviewed as the
negative comparison, not silently ignored.

After the manifest is written, the runner exits non-zero for a failed deploy,
proof, scan, schema validation, CI error/inconclusive result, or a fixed-target
CI block. A vulnerable-target CI exit code `1` remains a recorded gate result,
not a runner crash.

Both flows still do not clean containers. Cleanup remains an explicit
operator action:

```powershell
pwsh -File targets/realworld/deploy.ps1 -Clean -Yes
```

## Output contract

The script writes to `runs/demo_evidence/<timestamp>/`:

```text
demo_manifest.json          # redacted metadata and command/exit-code ledger
logs/                        # command transcripts for manual review
prove/                       # deterministic proof reports
scan/excel-0.1.7/           # vulnerable-target scan artifacts
scan/excel-0.1.8/           # fixed-target scan artifacts
```

The manifest records only non-secret metadata: Git SHA, UTC timestamp, target
identifiers, redacted command strings, relative artifact paths, SHA-256 for each
`findings.json`, selected fields from `scan_result.json` (model name, temperature,
token counts, wall time, and stop reason), and validation/gate exit codes. It must
not copy environment values or raw credentials.

Run output is ignored by the repository's `runs/*` rule. Do not force-add raw logs,
PoCs, traces, or screenshots to Git. Share only a manually reviewed, redacted
bundle or a release attachment.

## Recording checklist

The final three-minute recording should show, in order:

1. Git SHA and the repository version;
2. read-only `-Check` output;
3. explicit `-Deploy -Yes` (or already-running local containers);
4. vulnerable/fixed deterministic proof;
5. live `mcpwn scan` and the output directory;
6. `findings.json`, one trace/PoC, and `findings.sarif` when produced;
7. `validate-artifact` output;
8. `mcpwn ci` output and the actual exit code;
9. the fixed-target comparison or its persisted proof report.

Before sharing, pause the recording and inspect every frame and every file for API
keys, Authorization headers, environment values, real secrets, host usernames,
private paths, or unrelated target data. A recording must never be used to claim a
finding count, timing, or successful LLM path that was not actually observed.

## Acceptance criteria

A demo evidence bundle is ready only when all of these are true:

- `python scripts/check_demo_assets.py` passes;
- the deterministic vulnerable/fixed proof was run and its reports are present;
- the live scan's `findings.json` passes `mcpwn validate-artifact`;
- the manifest contains Git SHA, target/version, artifact hashes, and real exit
  codes without secret values;
- the recording and bundle have been manually redacted;
- the README links this runbook but does not claim that a recording exists until it
  is actually attached.
