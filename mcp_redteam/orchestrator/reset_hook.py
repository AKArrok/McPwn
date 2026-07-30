"""Reset DVMCP container-side state directories.

Only challenges 3/4/6/8/10 store state under `/tmp/dvmcp_challenge*` (HANDOFF §0).
`execute=False` (default) prints the plan; `execute=True` runs `docker exec`.

If the container-scoped clean fails, fall back to `docker restart dvmcp` (HANDOFF P3).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

CONTAINER = "dvmcp"
STATE_GLOBS = [
    "/tmp/dvmcp_challenge3",
    "/tmp/dvmcp_challenge4",
    "/tmp/dvmcp_challenge6",
    "/tmp/dvmcp_challenge8",
    "/tmp/dvmcp_challenge10",
]


@dataclass
class ResetResult:
    dry_run: bool
    commands: list[list[str]]
    stdout: str
    stderr: str
    fell_back: bool

    def __str__(self) -> str:
        mode = "DRY-RUN" if self.dry_run else "EXECUTED"
        fb = " (fell back to docker restart)" if self.fell_back else ""
        lines = [f"[reset] {mode}{fb}"]
        for cmd in self.commands:
            lines.append("  $ " + " ".join(cmd))
        if self.stdout:
            lines.append("[stdout]\n" + self.stdout.rstrip())
        if self.stderr:
            lines.append("[stderr]\n" + self.stderr.rstrip())
        return "\n".join(lines)


def _clean_cmd() -> list[str]:
    # Wipe *contents* of each state dir while keeping the directory itself, so
    # server code can re-create files on demand. ``find -mindepth 1 -delete``
    # is safer than ``rm -rf .*`` because it does not depend on shell glob
    # expansion of ``.*`` (which resolves to ``.``/``..`` on some ``sh``s and
    # would touch the parent). Missing paths are ignored via ``|| true``.
    inner = " ; ".join(
        f"find {p} -mindepth 1 -delete 2>/dev/null || true" for p in STATE_GLOBS
    )
    return ["docker", "exec", CONTAINER, "sh", "-c", inner]


def _restart_cmd() -> list[str]:
    return ["docker", "restart", CONTAINER]


def reset_dvmcp(execute: bool = False) -> ResetResult:
    clean = _clean_cmd()
    if not execute:
        return ResetResult(dry_run=True, commands=[clean], stdout="", stderr="", fell_back=False)

    proc = subprocess.run(clean, capture_output=True, text=True)
    if proc.returncode == 0:
        return ResetResult(
            dry_run=False,
            commands=[clean],
            stdout=proc.stdout,
            stderr=proc.stderr,
            fell_back=False,
        )

    # Fallback: full container restart. Slow but guaranteed to reset in-memory state too.
    restart = _restart_cmd()
    proc2 = subprocess.run(restart, capture_output=True, text=True)
    return ResetResult(
        dry_run=False,
        commands=[clean, restart],
        stdout=(proc.stdout + proc2.stdout),
        stderr=(proc.stderr + proc2.stderr),
        fell_back=True,
    )
