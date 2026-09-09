"""User-facing mcpwn.yaml target config contract."""

from __future__ import annotations

import pytest
import yaml

from mcp_redteam.contracts import TargetConfig, Transport
from mcp_redteam.target_config import example_config, load_target_config, write_example_config


def test_stdio_example_config_builds_target_spec(tmp_path):
    path = tmp_path / "mcpwn.yaml"
    write_example_config(path, kind="stdio")

    cfg = load_target_config(path)
    spec = cfg.target_spec()

    assert cfg.name == "local-stdio-mcp"
    assert spec.transport is Transport.STDIO
    assert spec.command == ["python", "path/to/server.py"]
    assert spec.display == "stdio: python path/to/server.py"


def test_url_config_builds_target_spec(tmp_path):
    path = tmp_path / "mcpwn.yaml"
    path.write_text(
        """name: local-http
transport: streamable-http
url: http://127.0.0.1:9000/mcp
headers:
  x-user-id: mcpwn-test
sandbox_root: /tmp/sandbox
llm_points: true
""",
        encoding="utf-8",
    )

    cfg = load_target_config(path)
    spec = cfg.target_spec()

    assert spec.transport is Transport.STREAMABLE_HTTP
    assert spec.headers == {"x-user-id": "mcpwn-test"}
    assert cfg.sandbox_root == "/tmp/sandbox"
    assert cfg.llm_points is True


def test_target_config_rejects_unknown_fields():
    with pytest.raises(ValueError):
        TargetConfig.model_validate({
            "name": "bad",
            "url": "http://127.0.0.1:9000/mcp",
            "unexpected": True,
        })


def test_target_config_rejects_url_and_command_conflict():
    cfg = TargetConfig.model_validate({
        "name": "bad",
        "url": "http://127.0.0.1:9000/mcp",
        "command": "uvx mcp-server-fetch",
    })
    with pytest.raises(ValueError, match="both"):
        cfg.target_spec()


def test_url_example_config_is_valid():
    cfg = TargetConfig.model_validate(yaml.safe_load(example_config("url")))
    assert cfg.target_spec().url == "http://127.0.0.1:9000/mcp"
