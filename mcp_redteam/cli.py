"""mcpwn CLI - Typer app.

Primary command: `mcpwn scan <target>` runs a full agent-first scan and writes
findings.md + poc/*.py + traces/*.json + scan_result.json under --out.
<target> is an HTTP endpoint URL (SSE or streamable HTTP) or, with --command,
a stdio launch command.

Support commands: `ping-models`, `lint-cards`.
DVMCP-specific helpers live under `mcpwn eval dvmcp ...` (HANDOFF paragraph 2).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

app = typer.Typer(add_completion=False, no_args_is_help=True)
eval_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Regression eval sub-apps.")
dvmcp_app = typer.Typer(add_completion=False, no_args_is_help=True, help="DVMCP regression harness.")
app.add_typer(eval_app, name="eval")
eval_app.add_typer(dvmcp_app, name="dvmcp")

console = Console()


def _parse_headers(raw: str | None) -> dict[str, str]:
    """Parse `--headers` value like `x-user-id=mcpwn,x-chat-id=scan1`."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def _build_m3_judge_fn(judge_model: str | None):
    """Build the M3 judge callable + effective model name.

    Returns (None, "") when the judge role is unconfigured / unreachable so
    the CLI degrades to a deterministic inconclusive report instead of crashing.
    """
    try:
        from dataclasses import replace

        from mcp_redteam.judge.m3 import make_m3_judge_fn
        from mcp_redteam.models.chat import make_client

        client, spec = make_client("judge")
        if judge_model:
            spec = replace(spec, model=judge_model)
        return make_m3_judge_fn(client, spec), spec.model
    except Exception:
        return None, ""


def _match_manifest_entry(spec):
    """Best-effort match of a scan spec against eval/targets/manifest.yaml.

    Returns a ManifestVerdict when the URL/transport or stdio command equals a
    manifest entry's connection spec, else None (report renders self-eval
    only). Never raises - benchmark extras must not break a scan.
    """
    try:
        from eval.targets.run import load_manifest
        from mcp_redteam.report.benchmark import ManifestVerdict

        for t in load_manifest():
            tspec = t.spec()
            if tspec is None:
                continue
            same_http = tspec.url and tspec.url == spec.url and tspec.transport == spec.transport
            same_stdio = tspec.command and tspec.command == spec.command
            if same_http or same_stdio:
                return ManifestVerdict(
                    name=t.name,
                    label=t.label,
                    baseline_expect=t.baseline_expect,
                    llm_expect=t.llm_expect,
                    prove=t.prove,
                    prove_script=str(t.prove_script) if t.prove_script else "",
                )
    except Exception:
        logging.getLogger(__name__).debug(
            "manifest match skipped (no manifest / eval unavailable)", exc_info=True
        )
        return None
    return None


@app.command("init")
def init_cmd(
    out: Path = typer.Option(
        Path("mcpwn.yaml"),
        "--out",
        "-o",
        help="Where to write the target config template.",
    ),
    kind: str = typer.Option(
        "stdio",
        "--kind",
        help="Template kind: stdio or url.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing config file.",
    ),
) -> None:
    """Create a starter mcpwn.yaml for scanning a real MCP server."""
    from mcp_redteam.target_config import write_example_config

    if kind not in {"stdio", "url"}:
        console.print("[red]FAIL[/red] --kind must be 'stdio' or 'url'")
        raise typer.Exit(code=2)
    if out.exists() and not force:
        console.print(f"[red]FAIL[/red] {out} already exists; pass --force to overwrite")
        raise typer.Exit(code=2)
    write_example_config(out, kind=kind)  # type: ignore[arg-type]
    console.print(f"[green]wrote[/green] {out}")


@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(
        "",
        help="MCP target: HTTP endpoint URL (SSE or streamable HTTP). "
        "Optional when --command launches a stdio server.",
    ),
    command: str | None = typer.Option(
        None,
        "--command",
        help="stdio target launch command, e.g. 'uvx mcp-server-fetch' "
        "(implies transport=stdio; the child is spawned per scan).",
    ),
    transport: str = typer.Option(
        "auto",
        "--transport",
        help="auto (default: /sse URLs -> SSE, other URLs -> streamable "
        "HTTP with SSE fallback), sse, streamable-http, or stdio.",
    ),
    env: str | None = typer.Option(
        None,
        "--env",
        help="Comma-separated k=v env vars for a --command stdio child, "
        "e.g. EXCEL_FILES_PATH=/tmp/sandbox. WARNING: values are stored "
        "in PLAINTEXT in scan_result.json and the generated PoC scripts "
        "(needed for replay) - never pass secrets here.",
    ),
    target_config: Path | None = typer.Option(
        None,
        "--target-config",
        help="YAML target config generated by `mcpwn init`; use this instead "
        "of positional target/--command for repeatable real-server scans.",
    ),
    out: Path = typer.Option(
        Path("runs/scan_latest"),
        "--out",
        "-o",
        help="Output directory for findings.md / poc / traces / scan_result.json.",
    ),
    max_tokens: int = typer.Option(30000, help="Attacker token budget."),
    wall_seconds: int = typer.Option(240, help="Wall-clock budget in seconds."),
    max_candidates: int = typer.Option(20, help="Max (vuln_class, target) candidates to probe."),
    max_inner_steps: int = typer.Option(12, help="Max attacker tool-call rounds per candidate."),
    attacker_temperature: float | None = typer.Option(
        None,
        "--attacker-temperature",
        help="Override attacker LLM temperature (default from models.yaml). "
        "Use 0 for reproducible scan runs.",
    ),
    headers: str | None = typer.Option(
        None,
        "--headers",
        help="Comma-separated SSE headers, e.g. "
        "x-user-id=mcpwn,x-chat-id=scan1. Useful for real-world MCP "
        "servers that require per-user session headers.",
    ),
    sandbox_root: str | None = typer.Option(
        None,
        "--sandbox-root",
        help="Declared sandbox root (deployment metadata) used by "
        "sandbox-escape detectors, e.g. /tmp/sandbox for excel-mcp-server.",
    ),
    graph: bool = typer.Option(
        False,
        "--graph",
        help="Run the pipeline as an explicit LangGraph state machine "
        "(parity with the default hand-written loop).",
    ),
    llm_points: bool = typer.Option(
        False,
        "--llm-points",
        help="Enable the three Stage-2 LLM decision points: hypothesis "
        "generation, zero-finding retrospective, and grounded evidence "
        "judgment by the judge role model (unknown-shape coverage).",
    ),
) -> None:
    """Scan one MCP server. Produces findings.md + poc scripts + traces."""
    from mcp_redteam.contracts import TargetSpec
    from mcp_redteam.orchestrator.runner import scan
    from mcp_redteam.report.findings import write_findings
    from mcp_redteam.target_config import load_target_config

    config = None
    if target_config is not None:
        if command or target:
            console.print("[red]FAIL[/red] give either --target-config or target/--command, not both")
            raise typer.Exit(code=2)
        try:
            config = load_target_config(target_config)
        except Exception as exc:
            console.print(f"[red]FAIL[/red] invalid target config {target_config}: {exc}")
            raise typer.Exit(code=2) from exc
    if config is None and not command and not target:
        console.print("[red]FAIL[/red] mcpwn scan needs a target URL or --command")
        raise typer.Exit(code=2)
    if config is None and command and target:
        console.print("[red]FAIL[/red] give either a target URL or --command, not both")
        raise typer.Exit(code=2)
    spec = (
        config.target_spec()
        if config is not None
        else TargetSpec.parse(
            None if command else target,
            transport=transport.replace("-", "_"),
            command=command,
            env=_parse_headers(env),
            headers=_parse_headers(headers),
        )
    )
    effective_sandbox_root = sandbox_root or (config.sandbox_root if config else None)
    effective_llm_points = llm_points or bool(config.llm_points if config else False)
    result = asyncio.run(scan(
        sse_url=spec,
        out_dir=out,
        max_tokens=max_tokens,
        wall_seconds=wall_seconds,
        max_candidates=max_candidates,
        max_inner_steps=max_inner_steps,
        attacker_temperature=attacker_temperature,
        sse_headers=_parse_headers(headers) if config is None else None,
        sandbox_root=effective_sandbox_root,
        graph=graph,
        llm_points=effective_llm_points,
    ))
    md_path = write_findings(result, out)
    from mcp_redteam.report.benchmark import write_benchmark

    entry = _match_manifest_entry(spec)
    benchmark_path = write_benchmark(result, out, entry=entry, max_tokens=max_tokens,
                                     wall_seconds=wall_seconds,
                                     mode="llm" if effective_llm_points else "std")

    table = Table("field", "value")
    table.add_row("run_id", result.run_id)
    table.add_row("transport", result.transport)
    table.add_row("target", result.sse_url)
    table.add_row("stop_reason", result.stop_reason)
    table.add_row("tools_seen", str(len(result.tools_seen)))
    table.add_row("resources_seen", str(len(result.resources_seen)))
    table.add_row("traces", str(len(result.traces)))
    table.add_row("findings", f"[green]{len(result.findings)}[/green]" if result.findings else "0")
    table.add_row("total_tokens", str(result.total_tokens))
    table.add_row("wall_seconds", f"{result.wall_seconds:.1f}")
    console.print(table)
    console.print(f"[dim]wrote {md_path}[/dim]")
    console.print(f"[dim]wrote {out / 'findings.json'}[/dim]")
    console.print(f"[dim]wrote {benchmark_path}[/dim]")
    if not result.findings:
        raise typer.Exit(code=1)


@app.command("ci")
def ci_cmd(
    artifact: Path = typer.Argument(
        Path("runs/scan_latest"),
        help="Scan output directory or direct findings.json path.",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum severity that fails CI: info, low, medium, high, critical.",
    ),
    allow_inconclusive: bool = typer.Option(
        False,
        "--allow-inconclusive",
        help="Evaluate findings even when stop_reason is not completed.",
    ),
    ignore_static: bool = typer.Option(
        False,
        "--ignore-static",
        help="Do not include static_hits in the CI threshold gate.",
    ),
) -> None:
    """Evaluate an existing findings.json as a CI pass/fail gate."""
    from mcp_redteam.ci import evaluate_ci_artifact, load_findings_artifact

    try:
        data = load_findings_artifact(artifact)
    except Exception as exc:
        console.print(f"[red]FAIL[/red] invalid CI artifact: {exc}")
        raise typer.Exit(code=2) from exc

    verdict = evaluate_ci_artifact(
        data,
        fail_on=fail_on,
        include_static=not ignore_static,
        allow_inconclusive=allow_inconclusive,
    )

    style = {
        "pass": "green",
        "fail": "red",
        "inconclusive": "yellow",
        "invalid": "red",
    }.get(verdict.status, "white")
    table = Table("field", "value")
    table.add_row("status", f"[{style}]{verdict.status}[/{style}]")
    table.add_row("threshold", verdict.threshold)
    table.add_row("blocking_count", str(verdict.blocking_count))
    table.add_row("max_severity", verdict.max_severity or "-")
    table.add_row("stop_reason", verdict.stop_reason or "-")
    table.add_row("reason", verdict.reason)
    console.print(table)
    raise typer.Exit(code=verdict.exit_code)


@app.command("validate-artifact")
def validate_artifact_cmd(
    artifact: Path = typer.Argument(
        Path("runs/scan_latest"),
        help="Scan output directory or direct findings.json path.",
    ),
) -> None:
    """Validate findings.json against the checked-in JSON Schema."""
    from mcp_redteam.ci import load_findings_artifact, resolve_findings_json

    try:
        path = resolve_findings_json(artifact)
        load_findings_artifact(artifact)
    except Exception as exc:
        console.print(f"[red]FAIL[/red] invalid artifact: {exc}")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]valid[/green] {path}")


@app.command("static-scan")
def static_scan_cmd(
    target: str = typer.Argument(
        "", help="MCP target: HTTP endpoint URL. Optional when --command is given."
    ),
    command: str | None = typer.Option(
        None, "--command", help="stdio target launch command (implies stdio transport)."
    ),
    transport: str = typer.Option(
        "auto",
        "--transport",
        help="auto (default), sse, streamable-http, or stdio.",
    ),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Optional output file for the SARIF report."
    ),
) -> None:
    """Zero-LLM static screening: tool/resource metadata + supply-chain vet.

    The cheap first layer: regex heuristics over descriptions/arg schemas
    (injection phrasing, exfiltration semantics, credential surfaces, ...)
    plus package typosquat/known-malicious checks for stdio targets. No
    attack traffic, no tokens - safe against ANY server.
    """
    import asyncio

    from mcp_redteam.agent.static_scan import scan_surface_static
    from mcp_redteam.agent.supplychain import vet_target_spec
    from mcp_redteam.contracts import StaticHit, TargetSpec
    from mcp_redteam.targets.mcp_client import McpSession

    if not command and not target:
        console.print("[red]FAIL[/red] static-scan needs a target URL or --command")
        raise typer.Exit(code=2)
    spec = TargetSpec.parse(
        None if command else target,
        transport=transport.replace("-", "_"),
        command=command,
    )

    # Supplychain vetting is offline - report it even if the target is down.
    hits: list[StaticHit] = vet_target_spec(spec)

    async def _surface() -> list[StaticHit]:
        async with McpSession(spec) as s:
            tools = await s.raw_list_tools()
            resources = await s.raw_list_resources()
        return scan_surface_static(tools, resources)

    try:
        hits = hits + asyncio.run(_surface())
    except RuntimeError as exc:
        # McpSession already names target/transport; keep it friendly.
        console.print(f"[red]FAIL[/red] {exc}")
        for h in hits:
            console.print(f"[{h.severity}] {h.rule_id}: {h.summary}")
        raise typer.Exit(code=2) from exc

    table = Table("severity", "rule", "subject", "where", "summary")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for h in sorted(hits, key=lambda x: order.get(x.severity, 9)):
        table.add_row(h.severity, h.rule_id, h.subject, h.where, h.summary)
    if hits:
        console.print(table)
    console.print(f"[green]{len(hits)}[/green] static hit(s) on {spec.display}")
    if out:
        import json as _json

        from mcp_redteam.report.sarif import to_sarif

        pseudo = _StaticScanResult(target=spec.display, transport=spec.transport.value, hits=hits)
        out.write_text(
            _json.dumps(to_sarif(pseudo), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        console.print(f"[dim]wrote {out}[/dim]")
    if hits:
        raise typer.Exit(code=1)


class _StaticScanResult:
    """Minimal duck-type for to_sarif() on standalone static scans."""

    def __init__(self, target: str, transport: str, hits: list) -> None:
        self.run_id = "static-scan"
        self.sse_url = target
        self.transport = transport
        self.findings = []
        self.static_hits = hits


@app.command("vet-package")
def vet_package_cmd(
    name: str = typer.Argument(..., help="MCP server package name, e.g. mcp-server-fetch."),
) -> None:
    """Vet one package name: typosquat distance + known-malicious list."""
    from mcp_redteam.agent.supplychain import vet_package_name

    hits = vet_package_name(name)
    if not hits:
        console.print(f"[green]ok[/green] {name}: 无已知风险 (本地知识库范围内)")
        return
    for h in hits:
        console.print(f"[{h.severity}] {h.rule_id}: {h.summary} (match: {h.matched_text})")
    raise typer.Exit(code=1)


@app.command("benchmark")
def benchmark_cmd(
    name: str = typer.Argument(
        ...,
        help="Target name from eval/targets/manifest.yaml (vault/fetch/git/...).",
    ),
    mode: str = typer.Option(
        "std",
        "--mode",
        help="std (hardcoded planner, baseline_expect) or llm (llm_points on, llm_expect).",
    ),
    out: Path = typer.Option(
        Path("runs/benchmark"),
        "--out",
        "-o",
        help="Output root; writes <out>/<name>/{findings.md, benchmark.md, poc/, traces/}.",
    ),
    max_tokens: int = typer.Option(30000, help="Attacker token budget."),
    wall_seconds: int = typer.Option(300, help="Wall-clock budget in seconds."),
    seed: int | None = typer.Option(None, help="LLM sampling seed (provider-dependent)."),
) -> None:
    """Benchmark one manifest target: scan it, then emit benchmark.md.

    The report combines scan self-metrics (coverage / signals / budget) with
    the manifest expectation verdict for the chosen mode.
    """
    import asyncio

    from eval.targets.run import load_manifest
    from mcp_redteam.orchestrator.runner import scan
    from mcp_redteam.report.benchmark import write_benchmark
    from mcp_redteam.report.findings import write_findings

    if mode not in ("std", "llm"):
        console.print("[red]FAIL[/red] --mode must be std or llm")
        raise typer.Exit(code=2)
    matches = [t for t in load_manifest() if t.name == name]
    if not matches:
        console.print(f"[red]FAIL[/red] unknown target {name!r}; see: mcpwn eval targets --list")
        raise typer.Exit(code=2)
    t = matches[0]

    from mcp_redteam.report.benchmark import ManifestVerdict

    entry = ManifestVerdict(
        name=t.name,
        label=t.label,
        baseline_expect=t.baseline_expect,
        llm_expect=t.llm_expect,
        prove=t.prove,
        prove_script=str(t.prove_script) if t.prove_script else "",
    )
    out_dir = out / name
    llm_points = mode == "llm"

    async def _run() -> None:
        spec = t.spec()
        if spec is not None:
            result = await scan(
                sse_url=spec, out_dir=out_dir, max_tokens=max_tokens,
                wall_seconds=wall_seconds, llm_points=llm_points, seed=seed,
            )
        else:  # spawner-based target: borrow its lifecycle context
            from eval.targets.spawners import get_spawner

            async with get_spawner(t.spawn, t.sse_url) as sse_url:
                result = await scan(
                    sse_url=sse_url, out_dir=out_dir, max_tokens=max_tokens,
                    wall_seconds=wall_seconds, llm_points=llm_points, seed=seed,
                )
        write_findings(result, out_dir)
        path = write_benchmark(
            result, out_dir, entry=entry,
            max_tokens=max_tokens, wall_seconds=wall_seconds, mode=mode,
        )
        table = Table("field", "value")
        table.add_row("target", f"{t.name} ({t.label})")
        table.add_row("transport", result.transport)
        table.add_row("mode", mode)
        table.add_row("expect", entry.expect_for(mode))
        table.add_row("findings", str(len(result.findings)))
        table.add_row("total_tokens", str(result.total_tokens))
        table.add_row("wall_seconds", f"{result.wall_seconds:.1f}")
        console.print(table)
        console.print(f"[dim]wrote {path}[/dim]")

    asyncio.run(_run())


@app.command("ping-models")
def ping_models(
    roles: str = typer.Option("attacker", help="Comma-separated roles to smoke-test."),
) -> None:
    from mcp_redteam.models.chat import ping

    table = Table("role", "status", "reply")
    exit_code = 0
    for role in [r.strip() for r in roles.split(",") if r.strip()]:
        try:
            reply = ping(role, prompt="Reply with the single word: pong.")
            table.add_row(role, "[green]ok[/green]", reply[:80])
        except Exception as exc:
            table.add_row(role, "[red]FAIL[/red]", f"{type(exc).__name__}: {exc}")
            exit_code = 1
    console.print(table)
    raise typer.Exit(code=exit_code)


@app.command("lint-cards")
def lint_cards() -> None:
    """Load and lint all 8 vuln-class strategy cards."""
    from mcp_redteam.vulns.registry import VULN_SLUGS, lint_all_cards

    errors = lint_all_cards()
    if errors:
        for err in errors:
            console.print(f"[red]FAIL[/red] {err}")
        raise typer.Exit(code=1)
    console.print(f"[green]ok[/green] all {len(VULN_SLUGS)} cards passed lint")


# ─── eval dvmcp ─────────────────────────────────────────────────────────────


@dvmcp_app.command("reset")
def dvmcp_reset(
    yes: bool = typer.Option(False, "--yes", help="Actually run docker exec; default is dry-run."),
) -> None:
    """Reset DVMCP container-side state directories (challenges 3/4/6/8/10)."""
    from mcp_redteam.orchestrator.reset_hook import reset_dvmcp

    result = reset_dvmcp(execute=yes)
    console.print(result)


@dvmcp_app.command("run")
def dvmcp_run(
    out: Path = typer.Option(Path("runs/m2_dvmcp_full"), "--out", "-o"),
    ports: str = typer.Option(
        "9001,9002,9003,9004,9005,9006,9007,9008,9009,9010",
        help="Comma-separated ports to scan.",
    ),
    max_tokens: int = typer.Option(30000),
    wall_seconds: int = typer.Option(240),
    planner_mode: str = typer.Option(
        "hardcoded", "--planner",
        help="Planner mode: hardcoded (score order) or llm (LLM decision).",
    ),
) -> None:
    """Run `mcpwn scan` across DVMCP ports and produce eval_report.md."""
    from eval.dvmcp.runner import run_all

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    report_path = asyncio.run(run_all(
        ports=port_list,
        out_dir=out,
        max_tokens=max_tokens,
        wall_seconds=wall_seconds,
        planner_mode=planner_mode,
    ))
    console.print(f"[green]wrote[/green] {report_path}")


@dvmcp_app.command("judge-m3")
def dvmcp_judge_m3(
    baseline: Path = typer.Option(
        ..., "--baseline",
        help="Hardcoded-planner eval output dir (port_*/scan_result.json + eval_report.md).",
    ),
    llm: Path = typer.Option(
        ..., "--llm",
        help="LLM-planner eval output dir; should contain planner_decisions.json.",
    ),
    out: Path = typer.Option(
        Path("runs/m3_judge"), "--out", "-o",
        help="Output dir for judge_report.json + judge_report.md.",
    ),
    judge_model: str | None = typer.Option(
        None, "--judge-model",
        help="Override judge LLM model (default: models.yaml judge role).",
    ),
) -> None:
    """M3 acceptance: judge hardcoded vs LLM-planner A/B output dirs."""
    from eval.dvmcp.m3_judge import run_judge_m3
    from mcp_redteam.judge.m3 import write_m3_report

    judge_fn, model = _build_m3_judge_fn(judge_model)
    report = run_judge_m3(baseline, llm, out, judge_fn=judge_fn, judge_model=model)
    json_path, md_path = write_m3_report(report, out)

    table = Table("field", "value")
    table.add_row("verdict", report.verdict)
    table.add_row("judge_model", report.judge_model or "n/a")
    table.add_row("judge_tokens", str(report.judge_tokens))
    table.add_row("criteria", ", ".join(f"{k}={v}" for k, v in report.criteria.items()))
    table.add_row("evidence_refs", str(len(report.evidence_refs)))
    console.print(table)
    console.print(f"[dim]wrote {json_path}[/dim]")
    console.print(f"[dim]wrote {md_path}[/dim]")


# ─── eval realworld ─────────────────────────────────────────────────────────


realworld_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Real-world MCP target harness (excel-mcp CVE-2026-40576).",
)
eval_app.add_typer(realworld_app, name="realworld")


@realworld_app.command("run")
def realworld_run(
    out: Path = typer.Option(Path("runs/eval_real_world"), "--out", "-o"),
    max_tokens: int = typer.Option(30000),
    wall_seconds: int = typer.Option(240),
    planner_mode: str = typer.Option(
        "hardcoded", "--planner",
        help="Planner mode: hardcoded (score order) or llm (LLM decision).",
    ),
) -> None:
    """Scan all real-world targets; recall + precision gates -> eval_report.md."""
    from eval.realworld.runner import run_all

    report_path = asyncio.run(run_all(
        out_dir=out,
        max_tokens=max_tokens,
        wall_seconds=wall_seconds,
        planner_mode=planner_mode,
    ))
    console.print(f"[green]wrote[/green] {report_path}")


@realworld_app.command("prove")
def realworld_prove(
    target: str = typer.Argument(
        ...,
        help="Target name from eval/realworld/targets.yaml (excel-0.1.7 / excel-0.1.8).",
    ),
    out: Path = typer.Option(Path("runs/eval_real_world/prove"), "--out", "-o"),
) -> None:
    """Deterministic exploit proof: write marker outside sandbox, verify via docker exec."""
    from eval.realworld.prove import prove_target

    report_path = asyncio.run(prove_target(target, out / target))
    console.print(f"[green]wrote[/green] {report_path}")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
