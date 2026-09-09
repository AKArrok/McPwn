"""Read and write user-facing ``mcpwn.yaml`` target configs."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml

from mcp_redteam.contracts import TargetConfig

DEFAULT_CONFIG = Path("mcpwn.yaml")


def example_config(kind: Literal["url", "stdio"] = "stdio") -> str:
    if kind == "url":
        return (
            "name: local-http-mcp\n"
            "transport: auto\n"
            "url: http://127.0.0.1:9000/mcp\n"
            "headers:\n"
            "  x-user-id: mcpwn-test\n"
            "sandbox_root: null\n"
            "llm_points: false\n"
        )
    return (
        "name: local-stdio-mcp\n"
        "transport: stdio\n"
        "command: python path/to/server.py\n"
        "cwd: null\n"
        "env: {}\n"
        "sandbox_root: null\n"
        "llm_points: false\n"
    )


def load_target_config(path: Path = DEFAULT_CONFIG) -> TargetConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path} must contain a YAML mapping")
    return TargetConfig.model_validate(data)


def write_example_config(path: Path = DEFAULT_CONFIG, *, kind: Literal["url", "stdio"] = "stdio") -> Path:
    path.write_text(example_config(kind), encoding="utf-8")
    return path
