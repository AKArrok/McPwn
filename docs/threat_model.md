# Threat model and claim boundaries

## Intended use

McPwn is an authorized assessment tool for MCP servers that an operator owns or
has explicit permission to test. Its primary workflow is reconnaissance, bounded
dynamic probing, evidence grounding, replayable proof-of-concept generation, and
machine-readable CI reporting. The repository's fixtures are local evaluation
targets, not a permission to scan arbitrary services.

The compliance boundary is part of the product contract: do not use the tool or
its payloads against production systems, public services, or unauthorized targets.

## Supported target shapes

The scan path supports the target forms represented by `TargetSpec` and the CLI:

- SSE HTTP endpoints;
- streamable HTTP endpoints (with the documented `auto` selection/fallback);
- local stdio servers launched from a command;
- reusable `mcpwn.yaml` target configuration containing transport, endpoint or
  command, environment, headers, and optional sandbox metadata.

The scan can combine static pre-screening with dynamic calls and can emit Markdown,
JSON, SARIF, traces, and replayable PoCs. These are delivery shapes, not promises
of exhaustive protocol coverage.

## Out of scope

- testing systems without explicit authorization or operating outside the local
  isolation/compliance boundary;
- proving that an MCP server is secure because one scan is clean;
- exhaustive vulnerability discovery or a universal recall percentage;
- treating DVMCP regression numbers as unfamiliar-server recall;
- claiming L2 prompt-injection impact on a downstream victim LLM from L0/L1
  attack-surface evidence alone;
- replacing a human security review, remediation decision, or incident process.

The scanner's own unsafe defaults and tightening paths are recorded in
[`unsafe_defaults.md`](unsafe_defaults.md).

## Finding semantics

A finding is a confidence-gated report entry assembled from detector signals and,
for the limited supported paths, grounded evidence judgment. Evidence-bearing
signals must originate in actual `McpCall.result_text`; an attacker model's final
summary is not evidence by itself. Findings below the configured confidence
threshold remain in traces rather than being promoted to `findings.md`.

This is intentionally asymmetric: a finding is a reason for a human to inspect the
trace and replay the PoC, not an automatic legal or operational verdict. A clean
scan means only that this run produced no reportable finding under its target,
budget, model, and detector configuration.

## CI semantics

`mcpwn ci` reads an existing `findings.json`, validates the versioned schema, and
then applies the configured severity threshold. Static hits are included by
default. A high or critical finding can therefore be used as a blocking policy,
while lower severities can remain advisory according to project policy.

The gate also distinguishes incomplete scans (`budget_*` or `error`) from a
completed clean result. `--allow-inconclusive` is an explicit opt-in to evaluate an
incomplete artifact anyway; it should not be confused with a successful security
assessment. Schema validity and a passing gate are delivery checks, not proof that
the target is secure.

