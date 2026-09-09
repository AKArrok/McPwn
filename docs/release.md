# Release and compatibility checklist

## SemVer policy

McPwn follows Semantic Versioning as documented in `CHANGELOG.md` and the package
version in `pyproject.toml`:

- **MAJOR**: an incompatible change to the public CLI, Python contracts, or
  versioned artifact contract;
- **MINOR**: a backward-compatible capability or command addition;
- **PATCH**: a backward-compatible bug fix, documentation correction, or packaging
  repair.

The rule applies to the user-visible CLI and the machine-readable artifact, not
only to internal modules. If a change cannot be kept compatible, document the
migration in the changelog before release.

## Pre-release commands

Run these from a clean checkout with the development dependencies installed:

```bash
python scripts/check_docs.py
python -m ruff check mcp_redteam eval tests scripts
python scripts/ci_artifact_smoke.py
python scripts/package_smoke.py
python -m pytest -q
```

The repository CI also runs the test suite on Python 3.13 across Ubuntu and
Windows. The smoke scripts intentionally avoid requiring a Docker target, network,
or LLM credentials.

## Artifact compatibility policy

`findings.json` is an external integration surface. The current contract is
`schema_version=1`, validated by
[`mcp_redteam/schemas/findings-v1.schema.json`](../mcp_redteam/schemas/findings-v1.schema.json)
and `mcpwn validate-artifact`.

- Keep existing v1 required fields and enum meanings stable within the 0.x minor
  line unless the release notes call out the break explicitly.
- Treat a change to required fields, field types, severity meanings, or transport
  values as a schema compatibility decision, not as a private refactor.
- If an incompatible artifact contract is necessary, publish a new schema version,
  update the validator and CI documentation together, and state the migration
  path in the changelog.
- A schema-valid artifact is structurally consumable; it is not a claim that its
  findings are true or complete.

## Example release note

```text
## [0.2.1] - YYYY-MM-DD

### Fixed
- Corrected a packaging or documentation issue without changing the v1
  findings.json contract.

### Verified
- check_docs, ruff, ci_artifact_smoke, package_smoke, and pytest passed.

### Compatibility
- Existing `mcpwn ci` consumers continue to read `schema_version=1` artifacts.
```

Replace `YYYY-MM-DD` and the bullets with facts from the actual release run. Do
not copy a passing status into a release note before the commands have run.

