"""OpenAI-compatible chat client factory.

Loads `config/models.yaml`, reads API key from `os.environ[key_env]`, and returns a
configured `openai.OpenAI` client bundled with a `ModelSpec` describing runtime knobs.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import time
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
    # Optional LLM sampling seed (OpenAI-compatible `seed` param). None = the
    # provider default; only set it when the endpoint supports `seed` - some
    # providers (e.g. DeepSeek) reject unknown params with a 400.
    seed: int | None = None


def _load_registry() -> dict[str, dict]:
    text = files("mcp_redteam.config").joinpath("models.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError("config/models.yaml must be a mapping of role -> config")
    return data


def load_registry() -> dict[str, dict]:
    """Public read-only view of the parsed models.yaml registry.

    Used by the orchestrator to snapshot the active config into ``ScanResult``
    so a months-old run is reproducible without re-reading the live yaml.
    """
    return _load_registry()


def load_spec(role: Role) -> ModelSpec:
    reg = _load_registry()
    if role not in reg:
        raise KeyError(f"role {role!r} missing from config/models.yaml")
    cfg = reg[role]
    required = {"provider", "base_url", "model", "key_env"}
    missing = required - cfg.keys()
    if missing:
        raise KeyError(f"role {role!r} missing keys: {sorted(missing)}")
    raw_seed = cfg.get("seed")
    seed = int(raw_seed) if raw_seed is not None else None
    return ModelSpec(
        role=role,
        provider=cfg["provider"],
        base_url=cfg["base_url"],
        model=cfg["model"],
        temperature=float(cfg.get("temperature", 0.7)),
        timeout=float(cfg.get("timeout", 60)),
        key_env=cfg["key_env"],
        seed=seed,
    )


def make_client(
    role: Role,
    temperature: float | None = None,
    seed: int | None = None,
) -> tuple[OpenAI, ModelSpec]:
    spec = load_spec(role)
    if temperature is not None:
        spec = dataclasses.replace(spec, temperature=temperature)
    if seed is not None:
        spec = dataclasses.replace(spec, seed=seed)
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
    resp = chat_create_with_retry(
        client,
        model=spec.model,
        temperature=spec.temperature,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=32,
    )
    return (resp.choices[0].message.content or "").strip()


# ── retry-with-backoff ────────────────────────────────────────────────────────
# 429 RateLimitError from the upstream API (e.g. ARK ``glm-5-2`` hitting its
# set inference limit) used to bubble straight out of the executor and
# terminate the trace with 0 attack_calls. Wrap chat completions so a brief
# rate-limit clears within the same trace, instead of dropping the port to
# 0 findings on a transient control-plane blip. Wall-time budget is still
# enforced by the executor's clock check between iterations; this helper
# does not consult it.

from openai import (
    APIConnectionError,
    APITimeoutError,
    InternalServerError,
    RateLimitError,
)

_log = logging.getLogger(__name__)

# Transient errors that may succeed on retry. 4xx other than 429
# (BadRequest, AuthenticationError, PermissionDeniedError) are NOT
# retried - they are code bugs, not transient control-plane conditions.
_RETRY_EXCEPTIONS: tuple[type[BaseException], ...] = (
    RateLimitError,
    APITimeoutError,
    APIConnectionError,
    InternalServerError,
)
_MAX_RETRIES = 5
_BASE_BACKOFF = 1.0  # seconds; sequence is 1, 2, 4, 8, 16 (total ~31s)


import threading

_MIN_INTERVAL_SEC = float(os.environ.get("MCPWN_LLM_MIN_INTERVAL_SEC", "2.0"))
_rate_limit_lock = threading.Lock()
_last_call_monotonic: float = 0.0


def _rate_limit_wait() -> None:
    global _last_call_monotonic
    with _rate_limit_lock:
        now = time.monotonic()
        elapsed = now - _last_call_monotonic
        if elapsed < _MIN_INTERVAL_SEC:
            time.sleep(_MIN_INTERVAL_SEC - elapsed)
        _last_call_monotonic = time.monotonic()


def chat_create_with_retry(
    client: OpenAI,
    *,
    seed: int | None = None,
    **kwargs,
):
    """Call ``client.chat.completions.create(**kwargs)`` with exponential backoff.

    ``seed`` is forwarded to the API as the OpenAI-compatible ``seed`` param
    only when it is not None; None leaves the provider default untouched.

    Retries up to ``_MAX_RETRIES=5`` times on ``RateLimitError``,
    ``APITimeoutError``, ``APIConnectionError``, ``InternalServerError``.
    Backoff sequence: 1s, 2s, 4s, 8s, 16s. After exhaustion the last
    exception is re-raised unchanged so the caller's existing
    ``except Exception`` handling (which logs the executor error) still
    fires on persistent failures.

    Wall-time budget is NOT checked here; the executor's per-iteration
    clock check will break the inner loop if a retry sequence eats too
    much time. Token budget is unaffected: failed attempts are not
    charged by the upstream API.
    """
    if seed is not None:
        kwargs["seed"] = seed
    for attempt in range(_MAX_RETRIES + 1):
        _rate_limit_wait()
        try:
            return client.chat.completions.create(**kwargs)
        except _RETRY_EXCEPTIONS as exc:
            if attempt >= _MAX_RETRIES:
                _log.warning(
                    "chat_create_with_retry: exhausted %d retries, "
                    "last error: %s: %s",
                    _MAX_RETRIES + 1, type(exc).__name__, exc,
                )
                raise
            wait = _BASE_BACKOFF * (2 ** attempt)
            _log.info(
                "chat_create_with_retry: attempt %d/%d failed (%s: %s); "
                "retrying in %.1fs",
                attempt + 1, _MAX_RETRIES + 1, type(exc).__name__, exc, wait,
            )
            time.sleep(wait)
    raise RuntimeError("unreachable")  # for type checker
