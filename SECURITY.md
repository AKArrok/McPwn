# Security policy

## Scope

McPwn is an authorized security-assessment tool for local or explicitly
authorized MCP servers. The repository's fixtures are the supported regression
scope. Do not use the scanner or generated PoCs against production, public, or
third-party systems without written authorization.

The project does not currently claim to be a hosted, multi-tenant security
service. It has no central authentication, RBAC, secret manager, queue
isolation, or enterprise audit service.

## Reporting a vulnerability

Do not open a public issue containing credentials, private target details, or a
reproducible exploit against a real service. Use the repository's private
security contact or the hosting provider's private vulnerability-reporting
channel. Include the affected commit, a minimal local reproduction, impact,
and the smallest safe log excerpt.

Before sharing any McPwn artifact, inspect `scan_result.json`, `findings.json`,
`findings.sarif`, `traces/`, and `poc/`. The runtime redacts target environment
and header values before persistence, but human review is still required for
secrets returned by an unusual target or embedded in custom payloads.

## Safe reproduction

Use the checked-in fixtures or a disposable local server. Keep API keys in the
process environment, never in `mcpwn.yaml`, a command line copied into an
issue, or a committed run directory. See
[`docs/operations.md`](docs/operations.md) and
[`docs/threat_model.md`](docs/threat_model.md) for the current boundaries.
