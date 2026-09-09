# Case study: excel-mcp sandbox escape

This case study uses the repository's recorded real-world fixture results. It is a
validation/causal case, not a frozen holdout and not a universal recall estimate.

## Background

The target is the repository's `excel-mcp-server` fixture associated with
CVE-2026-40576. The evaluation deploys a vulnerable `0.1.7` target and a fixed
`0.1.8` target as separate local services. The relevant question is not merely
whether a string looks suspicious; it is whether an absolute path can escape the
declared sandbox and whether the fixed version blocks that behavior.

## Vulnerability mechanism

The recorded deterministic proof uses a three-call sequence:

1. `create_workbook` receives an absolute path outside the sandbox;
2. `write_data_to_excel` writes a marker;
3. `read_data_from_excel` reads the marker back.

For `0.1.7`, the proof records the file outside the sandbox and reads the marker
back. For `0.1.8`, the absolute path is rejected as requiring a path relative to
`EXCEL_FILES_PATH`, and the file is not created. The proof is deterministic and
does not rely on the attacker LLM.

## McPwn workflow

The repository exercises both the deterministic proof and the scan path:

- the proof establishes the vulnerable/fixed behavior directly;
- `mcpwn scan` runs reconnaissance and bounded dynamic probing against the target;
- the verifier grounds a `path_traversal` finding in real MCP call returns;
- `findings.md`, `findings.json`, traces, and a replayable PoC preserve the result;
- the fixed target is scanned as a negative control rather than treated as an
  afterthought.

The recorded scan comparison also checks runner and graph paths. The repository
reports a finding on the vulnerable target and no finding on the fixed target in
the compared 20k configurations; the higher-budget graph run additionally records
the read/write composition. Those are repository results for this fixture, not
claims about all Excel MCP deployments.

## Why the paired control matters

A vulnerable-only result has several alternative explanations: a detector could
be matching a project-specific string, a PoC could be malformed, or the server
could already be permissive in both versions. The fixed `0.1.8` target supplies a
negative control: the same assessment context should see the path rejected and no
file written. The holdout protocol generalizes this idea into fixed-clean and
control-replay gates.

## What this case proves

- The repository has a deterministic, non-LLM proof for the recorded fixture
  behavior.
- McPwn can carry the behavior into a grounded finding and replayable artifact.
- A vulnerable/fixed pair provides stronger causal evidence than a vulnerable-only
  scan.
- The fixed version's blocked behavior is represented as a negative control in the
  evaluation material.

## What this case does not prove

- It does not prove general MCP recall, including on unknown server shapes.
- It does not turn the DVMCP regression figures into real-world percentages.
- It does not prove every version or deployment of `excel-mcp-server` has the same
  behavior.
- It does not make a clean scan a security certification; findings and PoCs still
  require human review.

