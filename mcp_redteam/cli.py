"""mcpwn CLI - Typer app.

Primary command: `mcpwn scan <sse-url>` runs a full agent-first scan and writes
findings.md + poc/*.py + traces/*.json + scan_result.json under --out.

Support commands: `ping-models`, `lint-cards`.
DVMCP-specific helpers live under `mcpwn eval dvmcp ...` (HANDOFF paragraph 2).
"""

from __future__ import annotations

import asyncio
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


@app.command("scan")
def scan_cmd(
    sse_url: str = typer.Argument(..., help="MCP SSE endpoint, e.g. http://127.0.0.1:9001/sse"),
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
) -> None:
    """Scan one MCP server. Produces findings.md + poc scripts + traces."""
    from mcp_redteam.orchestrator.runner import scan
    from mcp_redteam.report.findings import write_findings

    result = asyncio.run(scan(
        sse_url=sse_url,
        out_dir=out,
        max_tokens=max_tokens,
        wall_seconds=wall_seconds,
        max_candidates=max_candidates,
        max_inner_steps=max_inner_steps,
        attacker_temperature=attacker_temperature,
    ))
    md_path = write_findings(result, out)

    table = Table("field", "value")
    table.add_row("run_id", result.run_id)
    table.add_row("sse_url", result.sse_url)
    table.add_row("stop_reason", result.stop_reason)
    table.add_row("tools_seen", str(len(result.tools_seen)))
    table.add_row("resources_seen", str(len(result.resources_seen)))
    table.add_row("traces", str(len(result.traces)))
    table.add_row("findings", f"[green]{len(result.findings)}[/green]" if result.findings else "0")
    table.add_row("total_tokens", str(result.total_tokens))
    table.add_row("wall_seconds", f"{result.wall_seconds:.1f}")
    console.print(table)
    console.print(f"[dim]wrote {md_path}[/dim]")
    if not result.findings:
        raise typer.Exit(code=1)


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
    """Load and lint all 7 vuln-class strategy cards."""
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
) -> None:
    """Run `mcpwn scan` across DVMCP ports and produce eval_report.md."""
    from eval.dvmcp.runner import run_all

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    report_path = asyncio.run(run_all(
        ports=port_list,
        out_dir=out,
        max_tokens=max_tokens,
        wall_seconds=wall_seconds,
    ))
    console.print(f"[green]wrote[/green] {report_path}")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
