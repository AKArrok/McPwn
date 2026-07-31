"""OpenAI-compatible chat client factory.

Loads `config/models.yaml`, reads API key from `os.environ[key_env]`, and returns a
configured `openai.OpenAI` client bundled with a `ModelSpec` describing runtime knobs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from importlib.resources import files
from typing import Literal

import yaml
from openai import OpenAI

Role = Literal["attacker", "judge"]


@dataclass(frozen=True, slots=True)
class ModelSpec:
    role: Role
    provider: str
    base_url: str
    model: str
    temperature: float
    timeout: float
    key_env: str


def _load_registry() -> dict[str, dict]:
    text = files("mcp_redteam.config").joinpath("models.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError("config/models.yaml must be a mapping of role -> config")
    return data


def load_spec(role: Role) -> ModelSpec:
    reg = _load_registry()
    if role not in reg:
        raise KeyError(f"role {role!r} missing from config/models.yaml")
    cfg = reg[role]
    required = {"provider", "base_url", "model", "key_env"}
    missing = required - cfg.keys()
    if missing:
        raise KeyError(f"role {role!r} missing keys: {sorted(missing)}")
    return ModelSpec(
        role=role,
        provider=cfg["provider"],
        base_url=cfg["base_url"],
        model=cfg["model"],
        temperature=float(cfg.get("temperature", 0.7)),
        timeout=float(cfg.get("timeout", 60)),
        key_env=cfg["key_env"],
    )


def make_client(role: Role) -> tuple[OpenAI, ModelSpec]:
    spec = load_spec(role)
    key = os.environ.get(spec.key_env)
    if not key:
        raise RuntimeError(
            f"environment variable {spec.key_env} not set — copy .env.example to .env "
            f"and fill in the API key for role={role}"
        )
    client = OpenAI(base_url=spec.base_url, api_key=key, timeout=spec.timeout)
    return client, spec


def ping(role: Role, prompt: str = "ping") -> str:
    """One-shot smoke test: return short reply text or raise."""
    client, spec = make_client(role)
    resp = client.chat.completions.create(
        model=spec.model,
        temperature=spec.temperature,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=32,
    )
    return (resp.choices[0].message.content or "").strip()
