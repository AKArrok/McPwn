"""Release metadata must have one version across published surfaces."""

from __future__ import annotations

import re

from mcp_redteam import __version__


def test_source_version_matches_runtime_and_lock():
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    data = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8")
    )
    source = str(data["project"]["version"])
    lock = (root / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'(?ms)^\[\[package\]\]\s*name = "mcpwn"\s*version = "([^"]+)"', lock)

    assert __version__ == source
    assert match is not None
    assert match.group(1) == source


def test_sarif_uses_runtime_version_source():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    sarif = (root / "mcp_redteam" / "report" / "sarif.py").read_text(encoding="utf-8")

    assert "from mcp_redteam import __version__" in sarif
    assert '"version": __version__' in sarif
