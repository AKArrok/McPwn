# Positioning against adjacent approaches

McPwn is not a replacement for every security tool. Its position is the seam
between cheap metadata checks and repeatable, evidence-bearing dynamic assessment.

| Approach | Strength | Boundary | McPwn's position |
|---|---|---|---|
| Static MCP scanners | Fast, cheap pre-screening of tool/resource metadata and package signals. | They do not exercise target behavior, so a suspicious description is not a demonstrated impact. | McPwn keeps static pre-screening as the first layer, then can perform bounded dynamic probing. |
| Traditional DAST | Mature request/response testing and strong operational workflows for HTTP applications. | MCP tool semantics, resources, transports, and LLM-shaped attack paths need protocol-aware calls and evidence handling. | McPwn is MCP-aware at the target and evidence layers; it is not a general web DAST replacement. |
| Manual red team | Highest flexibility and context; useful for novel business logic and final triage. | Expensive to repeat and difficult to turn into a stable CI contract without disciplined artifacts. | McPwn automates reconnaissance and bounded hypotheses, while keeping traces and PoCs for human review. |
| LLM-only agent demos | Quickly show an agent taking actions against a target. | A narrative or self-reported success is not grounded evidence, a replay contract, or a deterministic CI input. | McPwn constrains evidence to real call returns and emits replayable PoCs plus machine-readable artifacts. |
| Benchmark scripts | Make a fixture or metric easy to run and compare. | They measure a test protocol; they are not, by themselves, a target-facing delivery workflow. | McPwn separates evaluation layers from the product scan path and adds artifact validation and severity gates. |

The concise product description is:

> static pre-screening + grounded dynamic probing + replayable PoC +
> machine-readable CI artifact.

That composition is the engineering claim. It does not turn fixture scores into a
universal recall claim, and it does not remove the need for human triage.

