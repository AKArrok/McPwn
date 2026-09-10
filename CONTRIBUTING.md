# Contributing

## Development setup

The supported development environment is Python 3.13 with the checked-in
`uv.lock`:

```bash
uv sync --locked --extra dev
uv run pre-commit run --all-files
```

## Required checks

Run the same deterministic checks as CI before opening a pull request:

```bash
uv run ruff check mcp_redteam eval tests scripts
uv run python scripts/check_release.py
uv run python scripts/ci_artifact_smoke.py
uv run python scripts/package_smoke.py
uv run pytest -q --cov=mcp_redteam --cov-report=term-missing
uv run python scripts/check_docs.py
uv run python scripts/check_demo_assets.py
```

Live LLM, Docker, and real-target runs are separate evidence jobs. Never make
the hermetic PR suite depend on a secret or a public service.

## Design rules

- Cross-module data contracts belong in `mcp_redteam/contracts.py`.
- Long prompts belong in `**/agents/*.md`, not Python source.
- Findings require grounded evidence and `confidence >= 0.6`.
- State-changing fixture commands default to dry-run and require `--yes`.
- Do not tune a frozen holdout and then report it as an independent result.
- New persisted fields or changes to `findings.json` require an artifact
  compatibility note and tests.

Please keep pull requests narrow. Include the user-visible behavior change,
the test that proves it, and any documentation or compatibility impact.
