"""Unit tests for ``chat_create_with_retry`` (mcp_redteam/models/chat.py).

The retry helper exists because trace v3 on 9009/9008 caught a
``RateLimitError: 429`` at executor step 0, which the prior
``except Exception: break`` swallowed, leaving 0 attack_calls and the
port dropping to 0 findings. These tests lock down the contract:

- transient errors (RateLimitError, APITimeoutError, APIConnectionError,
  InternalServerError) are retried with exponential backoff
- non-transient errors (BadRequestError) are NOT retried
- after the retry budget is exhausted, the last exception bubbles up so
  the caller's existing error handling still fires
- backoff sequence is 1, 2, 4, 8, 16 seconds (5 retries, ~31s max)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from openai import (
    APIConnectionError,
    APITimeoutError,
    BadRequestError,
    InternalServerError,
    RateLimitError,
)

from mcp_redteam.models.chat import _MAX_RETRIES, chat_create_with_retry


def _client_that_raises(exc: BaseException, n_times: int) -> MagicMock:
    """Build a mock OpenAI client whose chat.completions.create raises
    ``exc`` for the first ``n_times`` calls, then returns a sentinel."""
    client = MagicMock()
    sentinel = MagicMock(name="ok_response")
    call_log: list[int] = []

    def side_effect(**kwargs):
        call_log.append(1)
        if len(call_log) <= n_times:
            raise exc
        return sentinel

    client.chat.completions.create.side_effect = side_effect
    client._call_log = call_log
    client._sentinel = sentinel
    return client


def _make_rate_limit() -> RateLimitError:
    # openai 2.x exceptions accept (message, response=, body=) but most fields
    # are optional. Constructing with just a message is enough for type checking.
    return RateLimitError("rate limited", response=MagicMock(), body=None)


def _make_timeout() -> APITimeoutError:
    return APITimeoutError("timed out")


def _make_conn_error() -> APIConnectionError:
    return APIConnectionError(request=MagicMock())


def _make_500() -> InternalServerError:
    return InternalServerError("server error", response=MagicMock(), body=None)


def _make_bad_request() -> BadRequestError:
    return BadRequestError("bad request", response=MagicMock(), body=None)


def test_retries_then_succeeds_on_rate_limit(monkeypatch):
    """Rate limit on attempt 1, success on attempt 2 -> one retry, returns."""
    monkeypatch.setattr("mcp_redteam.models.chat.time.sleep", lambda _: None)
    client = _client_that_raises(_make_rate_limit(), 1)
    out = chat_create_with_retry(client, model="m", messages=[])
    assert out is client._sentinel  # the sentinel returned after retries
    assert len(client._call_log) == 2  # 1 fail + 1 success


def test_retries_each_transient_error_type(monkeypatch):
    """Each of the 4 transient exception classes triggers retry."""
    monkeypatch.setattr("mcp_redteam.models.chat.time.sleep", lambda _: None)
    for exc in [
        _make_rate_limit(),
        _make_timeout(),
        _make_conn_error(),
        _make_500(),
    ]:
        client = _client_that_raises(exc, 2)
        out = chat_create_with_retry(client, model="m", messages=[])
        assert out is not None
        assert len(client._call_log) == 3  # 2 fail + 1 success


def test_does_not_retry_bad_request(monkeypatch):
    """BadRequestError is a 4xx code bug, not a transient condition;
    must surface immediately so the caller sees the real error."""
    client = _client_that_raises(_make_bad_request(), 99)
    with pytest.raises(BadRequestError):
        chat_create_with_retry(client, model="m", messages=[])
    assert len(client._call_log) == 1  # no retry


def test_exhausts_retries_then_raises(monkeypatch):
    """Persistent RateLimitError -> _MAX_RETRIES retries, then last
    exception bubbles up unchanged so executor error logging still fires."""
    monkeypatch.setattr("mcp_redteam.models.chat.time.sleep", lambda _: None)
    client = _client_that_raises(_make_rate_limit(), _MAX_RETRIES + 5)
    with pytest.raises(RateLimitError):
        chat_create_with_retry(client, model="m", messages=[])
    # _MAX_RETRIES retries means _MAX_RETRIES+1 total attempts.
    assert len(client._call_log) == _MAX_RETRIES + 1


def test_backoff_sequence_is_exponential(monkeypatch):
    """Backoff sleeps follow 1, 2, 4, 8, 16 sequence.

    Disables _rate_limit_wait (sets _MIN_INTERVAL_SEC to 0) so only the
    retry-backoff component is exercised. The rate-limit component is
    covered by test_rate_limit_enforces_min_interval below.
    """
    from mcp_redteam.models import chat as chat_mod
    monkeypatch.setattr(chat_mod, "_MIN_INTERVAL_SEC", 0.0)
    sleeps: list[float] = []
    monkeypatch.setattr("mcp_redteam.models.chat.time.sleep", lambda s: sleeps.append(s))
    client = _client_that_raises(_make_rate_limit(), _MAX_RETRIES + 5)
    with pytest.raises(RateLimitError):
        chat_create_with_retry(client, model="m", messages=[])
    # _MAX_RETRIES=5 retries means _MAX_RETRIES sleeps (not after the final
    # failed attempt). Sequence: 1, 2, 4, 8, 16.
    assert sleeps == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_rate_limit_enforces_min_interval(monkeypatch):
    """_rate_limit_wait blocks until at least _MIN_INTERVAL_SEC has passed.

    We mock time.monotonic to return a controlled sequence and time.sleep
    to capture the wait durations. Two consecutive calls (with no
    intervening real time) must result in a sleep of _MIN_INTERVAL_SEC
    on the second call (the first sees elapsed=infinity since the
    module-level _last_call_monotonic starts at 0).
    """
    from mcp_redteam.models import chat as chat_mod
    # Reset the rate limit state so the test is hermetic.
    monkeypatch.setattr(chat_mod, "_last_call_monotonic", 0.0)
    times = [100.0, 100.0, 100.5, 100.5, 101.5, 101.5, 102.5, 102.5]
    monkeypatch.setattr(chat_mod.time, "monotonic", lambda: times.pop(0))
    sleeps: list[float] = []
    monkeypatch.setattr(chat_mod.time, "sleep", lambda s: sleeps.append(s))
    # First call: elapsed = 100.0 - 0.0 = 100.0 >= 2.0, no sleep.
    chat_mod._rate_limit_wait()
    assert sleeps == []
    # Second call (0.5s later): elapsed = 0.5 < 2.0, sleep 1.5s.
    chat_mod._rate_limit_wait()
    assert sleeps == [1.5]
    # Third call (1.0s after second): elapsed = 1.0 < 2.0, sleep 1.0s.
    chat_mod._rate_limit_wait()
    assert sleeps == [1.5, 1.0]
