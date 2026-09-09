"""Build a wheel and smoke-test the installed ``mcpwn`` entrypoint.

This catches the class of engineering bugs that unit tests miss: package-data
not included in the wheel, console scripts not generated, or installed code
unable to locate checked-in schemas/prompts/cards.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp_redteam.report.findings import FINDINGS_JSON_SCHEMA_VERSION

REQUIRED_WHEEL_FILES = {
    "mcp_redteam/config/models.yaml",
    "mcp_redteam/schemas/findings-v1.schema.json",
    "mcp_redteam/vulns/cards/ssrf.md",
    "mcp_redteam/attackers/agents/attacker_system.md",
    "mcp_redteam/judge/agents/judge_system.md",
}


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    return completed


def _build_wheel(tmp: Path) -> Path:
    wheel_dir = tmp / "wheelhouse"
    wheel_dir.mkdir()
    completed = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
        ],
        cwd=ROOT,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"pip wheel failed with rc={completed.returncode}")
    wheels = sorted(wheel_dir.glob("mcpwn-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one mcpwn wheel, found {len(wheels)}")
    return wheels[0]


def _assert_wheel_contents(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
    missing = sorted(REQUIRED_WHEEL_FILES - names)
    if missing:
        raise RuntimeError(f"wheel is missing package data: {missing}")
    cards = [
        name for name in names
        if name.startswith("mcp_redteam/vulns/cards/") and name.endswith(".md")
    ]
    if len(cards) != 8:
        raise RuntimeError(f"expected 8 strategy cards in wheel, found {len(cards)}")


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _mcpwn_exe(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/mcpwn.exe" if sys.platform == "win32" else "bin/mcpwn")


def _artifact() -> dict:
    return {
        "schema_version": FINDINGS_JSON_SCHEMA_VERSION,
        "run_id": "package-smoke",
        "target": "stdio: synthetic",
        "transport": "stdio",
        "stop_reason": "completed",
        "counts": {
            "tools_seen": 0,
            "resources_seen": 0,
            "traces": 0,
            "findings": 0,
            "static_hits": 0,
        },
        "findings": [],
        "static_hits": [],
    }


def _install_and_smoke(wheel: Path, tmp: Path) -> None:
    venv_dir = tmp / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(venv_dir)
    python = _venv_python(venv_dir)
    completed = _run(
        [str(python), "-m", "pip", "install", "--no-deps", "--ignore-installed", str(wheel)]
    )
    if completed.returncode != 0:
        raise RuntimeError(f"wheel install failed with rc={completed.returncode}")

    out_dir = tmp / "artifact"
    out_dir.mkdir()
    (out_dir / "findings.json").write_text(
        json.dumps(_artifact(), ensure_ascii=False),
        encoding="utf-8",
    )
    mcpwn = _mcpwn_exe(venv_dir)
    completed = _run([str(mcpwn), "validate-artifact", str(out_dir)])
    if completed.returncode != 0:
        raise RuntimeError(f"installed mcpwn validate-artifact failed with rc={completed.returncode}")


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="mcpwn-package-smoke-") as raw_tmp:
            tmp = Path(raw_tmp)
            wheel = _build_wheel(tmp)
            _assert_wheel_contents(wheel)
            _install_and_smoke(wheel, tmp)
    except RuntimeError as exc:
        print(f"package smoke failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
