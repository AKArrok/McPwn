"""McPwn package metadata."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path


def _discover_version() -> str:
    root = Path(__file__).resolve().parents[1]
    try:
        import tomllib

        data = tomllib.loads(
            (root / "pyproject.toml").read_text(encoding="utf-8")
        )
        return str(data["project"]["version"])
    except (FileNotFoundError, KeyError, TypeError, ValueError):
        # Installed wheels do not contain the repository pyproject; use their
        # distribution metadata after the source checkout path is unavailable.
        try:
            return package_version("mcpwn")
        except PackageNotFoundError:
            return "0+unknown"


__version__ = _discover_version()
