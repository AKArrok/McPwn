# Evidence matrix

McPwn reports different evidence layers for different questions. The layers are
deliberately not interchangeable: a regression result is not a generalization
result, and a CI gate is not a security certification.

| Evidence layer | Artifact / command | What it proves | What it does not prove |
|---|---|---|---|
| DVMCP regression set | `mcpwn eval dvmcp run`; per-target `findings.md` and `eval_report.md` | The current version still handles the known, repeatedly tuned DVMCP cases and helps localize regressions. | Recall on unfamiliar MCP servers or real-world prevalence. The 8/10 and 9/10 figures must not be extrapolated. |
| Vulnerable/fixed pairs | `eval/holdout/manifest.yaml`; `python -m eval.holdout.runner --check`; pair summaries | A positive finding is checked against a corresponding fixed target and control replay, supporting causal attribution to the vulnerability difference. | Independent generalization. The validation pairs have been used for harness/debugging and are not frozen holdout evidence. |
| Frozen holdout | `eval/holdout/lock.json`; `python -m eval.holdout.runner --split holdout --n 5` | A target kept out of rule, strategy-card, and prompt tuning can support an external generalization claim when the locked protocol passes. | A guarantee for all unknown MCPs, especially if the holdout was inspected and then used for tuning. |
| N≥5 repeats | Holdout runner with `minimum_repeats: 5` and `--n 5` or higher | Stability of the LLM-driven decision on the same target under the same protocol. | More independent targets or a larger sample of the MCP ecosystem. Repeats measure run variance, not sample size. |
| Grounding gate | Real call evidence in traces; `findings.md` / `findings.json`; verifier and grounding tests | Reported evidence is tied to actual MCP call returns, not only to an attacker model's narrative. | That the interpretation is correct, that the target is safe, or that no unreported issue exists. Human triage remains required. |
| `findings.json` schema | `mcpwn validate-artifact <out_dir|findings.json>`; `mcp_redteam/schemas/findings-v1.schema.json` | Downstream tooling can rely on the versioned top-level fields, counts, findings, and static-hit structure. | The artifact's findings are true, complete, or independently validated. Schema validity is structural validity. |
| CI gate | `mcpwn ci <out_dir|findings.json> --fail-on high`; `scripts/ci_artifact_smoke.py` | A persisted artifact is evaluated with deterministic severity, schema, and inconclusive-run semantics; high/critical findings can block a pipeline. | A passing gate means the target is secure. It only means no artifact entry met the configured gate, subject to scan completeness and coverage. |
| Wheel smoke | `python scripts/package_smoke.py` | The built wheel contains required schemas, prompts, cards, config resources, and an installed `mcpwn` entrypoint can validate an artifact. | Runtime correctness of every target transport, LLM provider, or production deployment. |

The practical reading order is: regression for development feedback, paired
controls for causality, frozen holdout for generalization, and artifact/CI checks
for delivery reliability.

