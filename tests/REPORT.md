# Test Status Report

**Last verified**: 2026-08-05 (commit HEAD = `77f5447`, ahead of origin by 5 commits; deepseek-v4-pro attacker model active)
**Verified by**: Claude session in Codex desktop

## Summary

| Tool | Scope | Result |
|------|-------|--------|
| pytest 9.1.1 | `tests/` | **72 passed** in 11.75s |
| ruff 0.16.0 | `mcp_redteam/` + `eval/` | **0 errors** |
| ruff 0.16.0 | `tests/` | 6 pre-existing errors (user-authored files, out of scope per HANDOFF_NEXT) |
| `mcpwn lint-cards` | `vulns/cards/*.md` | **7/7 ok** |

## Environment

- Python 3.13.13
- pytest 9.1.1, pytest-asyncio 1.4.0
- ruff 0.16.0
- jinja2 3.1.6, openai 2.44.0, pydantic 2.13.2, pydantic-settings 2.12.0
- mcpwn 0.1.0 (dev install at project root)

## Reproduce

```bash
python -m pytest tests -q --no-header
python -m ruff check mcp_redteam eval
python -m ruff check tests        # known: 6 pre-existing errors in user-authored files
python -m mcp_redteam.cli lint-cards
```

## Notes

- The 6 ruff errors in `tests/` are pre-existing in user-authored files
  (`tests/fixtures/mock_mcp.py`, `tests/test_regression_baseline.py`,
  `tests/test_scan_metadata.py`). Per HANDOFF_NEXT, they are out of scope
  and should not be touched without owner approval.
- `tests/` not under ruff auto-fix scope; tracked separately in PROGRESS.md.
- For canonical status, see PROGRESS.md.

## M2 v4 (DVMCP) status (informational)

| Metric | Value | Source |
|--------|-------|--------|
| recall | 0.80 (8/10) | `runs/m2_dvmcp_full_v4/eval_report.md` |
| FPR | 0.00 | same |
| poc_replay_pass_rate | 1.00 (5/5) | same |
| total wall time | 601.1s (10 min 1s) | sum of per-port wall_seconds in findings.md |
| attacker model | deepseek-v4-pro-260425 (ARK) | `mcp_redteam/config/models.yaml` |
| judge model | deepseek-v4-flash (deepseek.com) | same |

> Regenerate this file by running the four commands under *Reproduce*
> and pasting output into the *Summary* / *Environment* tables.
