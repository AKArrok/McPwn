"""Check the release metadata contract without contacting external services."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _source_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    return completed.stdout.strip()


def collect_issues(*, require_tag: bool = False, require_clean: bool = False) -> list[str]:
    expected = _source_version()
    issues: list[str] = []

    sys.path.insert(0, str(ROOT))
    from mcp_redteam import __version__

    if __version__ != expected:
        issues.append(f"runtime version {__version__!r} != pyproject version {expected!r}")

    try:
        installed = version("mcpwn")
    except PackageNotFoundError:
        installed = None
    if installed is not None and installed != expected:
        issues.append(f"installed distribution version {installed!r} != {expected!r}")

    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'(?ms)^\[\[package\]\]\s*name = "mcpwn"\s*version = "([^"]+)"', lock)
    if not match:
        issues.append("uv.lock has no mcpwn package entry")
    elif match.group(1) != expected:
        issues.append(f"uv.lock version {match.group(1)!r} != {expected!r}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if re.search(rf"^## \[?{re.escape(expected)}\]?\b", changelog, re.MULTILINE) is None:
        issues.append(f"CHANGELOG.md has no {expected} release heading")

    sarif = (ROOT / "mcp_redteam" / "report" / "sarif.py").read_text(encoding="utf-8")
    if '"version": __version__' not in sarif:
        issues.append("SARIF exporter is not wired to the package version")

    if require_tag and f"v{expected}" not in _git("tag", "--points-at", "HEAD").splitlines():
        issues.append(f"HEAD is not tagged v{expected}")
    if require_clean and _git("status", "--porcelain"):
        issues.append("working tree is not clean")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-tag", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    issues = collect_issues(require_tag=args.require_tag, require_clean=args.require_clean)
    if issues:
        for issue in issues:
            print(f"[FAIL] {issue}")
        return 1
    print(f"release metadata OK ({_source_version()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
