"""Thin async wrapper over the official `mcp` SDK's client transports.

Design:
- Accepts a ``TargetSpec`` (or anything ``TargetSpec.parse`` accepts: a URL,
  or a stdio launch command) and dispatches to the matching SDK transport:
  ``sse_client`` / ``streamablehttp_client`` / ``stdio_client``. Reports and
  prompts only ever see ``TargetSpec.display`` - no downstream code branches.
- ``transport="auto"`` + a non-``/sse`` HTTP URL tries streamable HTTP first
  and falls back to legacy SSE on connect failure (targets that declare
  ``transport="sse"`` explicitly never fall back).
- Session is managed via async context (`async with McpSession(url) as s:`).
- Every high-level call (`list_tools`/`list_resources`/`call_tool`/`read_resource`) returns
  an `McpCall` record so the caller can decide whether to append to `mcp_calls`
  (attack) or `recon_calls` (recon).
- ``raw_list_tools`` / ``raw_list_resources`` return the structured SDK objects
  for consumers that need name+description+inputSchema without going through
  a text re-parse (recon classifier, tool schema builder, drift detector).
- No caching, no retries. The orchestrator owns those policies.
"""

from __future__ import annotations

import logging
import time
from types import TracebackType
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client

from mcp_redteam.contracts import McpCall, TargetSpec, Transport

try:  # mcp >= 2.0 renamed both the error type and the streamable client.
    from mcp import MCPError
    from mcp.client.streamable_http import streamable_http_client

    _SDK_V2 = True
except ImportError:  # mcp 1.x
    from mcp import McpError as MCPError  # type: ignore[attr-defined]
    from mcp.client.streamable_http import (
        streamablehttp_client as streamable_http_client,  # type: ignore[no-redef]
    )

    _SDK_V2 = False

from mcp.shared._httpx_utils import create_mcp_http_client

_log = logging.getLogger(__name__)


def _stdio_env(extra: dict[str, str] | None) -> dict[str, str] | None:
    """Merge user env over the SDK default environment.

    ``StdioServerParameters(env=...)`` replaces the child's whole environment;
    a partial override would lose PATH/HOME, so overlay on the SDK default.
    """
    if not extra:
        return None
    from mcp.client.stdio import get_default_environment

    env = dict(get_default_environment())
    env.update(extra)
    return env


def _flatten_content(content: Any) -> str:
    """Best-effort stringification of MCP content lists (text/blob/embedded)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            text = getattr(item, "text", None)
            if text is not None:
                parts.append(text)
                continue
            # ResourceContents variant
            for attr in ("text", "blob"):
                v = getattr(item, attr, None)
                if v is not None:
                    parts.append(str(v))
                    break
            else:
                parts.append(repr(item))
        return "\n".join(parts)
    return str(content)


class McpSession:
    """Async session against an MCP target over any supported transport.

    Usage:
        async with McpSession("http://127.0.0.1:9001/sse") as s:
            call = await s.read_resource("internal://credentials")
        async with McpSession("uvx mcp-server-fetch", transport="stdio") as s:
            call = await s.list_tools()
    """

    def __init__(
        self,
        target: str | TargetSpec,
        connect_timeout: float = 15.0,
        *,
        headers: dict[str, str] | None = None,
        transport: str | Transport = "auto",
        command: str | list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        read_timeout: float = 120.0,
    ) -> None:
        if isinstance(target, TargetSpec):
            self.spec = target
        else:
            self.spec = TargetSpec.parse(
                target,
                transport=transport,
                command=command,
                env=env,
                headers=headers,
                cwd=cwd,
            )
        # auto-resolved non-/sse URLs may fall back to legacy SSE if the
        # server does not speak streamable HTTP; explicit choices never do.
        self._allow_sse_fallback = (
            transport == "auto" and not command and self.spec.transport is Transport.STREAMABLE_HTTP
        )
        self.connect_timeout = connect_timeout
        # Bounded per-call read timeout: without it a single hung tool call
        # (e.g. upstream server stuck on a slow fetch) blocks the whole scan
        # forever and voids the orchestrator's wall-clock guarantee.
        self.read_timeout = read_timeout
        self.headers = headers
        self._session: ClientSession | None = None

    def _http_client_factory_kwargs(self) -> dict[str, Any]:
        """Per-request HTTP timeouts shared by every HTTP transport branch.

        ``sse_read_timeout`` governs waiting for the FIRST event on the SSE
        stream - i.e. a TCP-accepting-but-silent server. Without wiring it,
        that phase hangs for the SDK default (60*5 = 300s) and our
        ``read_timeout`` never even comes into play.
        """
        return {"sse_read_timeout": self.read_timeout}

    def _transport_ctx(self, spec: TargetSpec) -> Any:
        effective_headers = self.headers if self.headers else spec.headers
        if spec.transport is Transport.STDIO:
            return stdio_client(
                StdioServerParameters(
                    command=spec.command[0],
                    args=spec.command[1:],
                    env=_stdio_env(spec.env),
                    cwd=spec.cwd,
                ),
            )
        if spec.transport is Transport.STREAMABLE_HTTP:
            if _SDK_V2:
                # 2.0 drops headers/timeout kwargs; headers + timeouts go via
                # a custom httpx client.
                if effective_headers or self.read_timeout:
                    import httpx2

                    timeout = httpx2.Timeout(
                        self.connect_timeout, read=self.read_timeout or None
                    )
                    return streamable_http_client(
                        spec.url,  # type: ignore[arg-type]
                        http_client=create_mcp_http_client(
                            headers=effective_headers, timeout=timeout
                        ),
                    )
                return streamable_http_client(spec.url)  # type: ignore[arg-type]
            return streamable_http_client(
                spec.url,  # type: ignore[arg-type]
                headers=effective_headers,
                timeout=self.connect_timeout,
                **self._http_client_factory_kwargs(),
            )
        return sse_client(
            spec.url,  # type: ignore[arg-type]
            headers=effective_headers,
            timeout=self.connect_timeout,
            **self._http_client_factory_kwargs(),
        )

    def _connect_msg(self, exc: Exception, *, fell_back: bool) -> str:
        hint = " (streamable 与 legacy SSE 均尝试失败)" if fell_back else ""
        return (
            f"无法连接 MCP 目标 {self.spec.display} "
            f"[transport={self.spec.transport.value}]{hint}: "
            f"{type(exc).__name__}: {exc}"
        )

    async def __aenter__(self) -> McpSession:
        # The transport ctx and ClientSession are both async context managers;
        # we enter them manually so the session survives beyond a single
        # `async with`. Two attempts max: the spec's transport, then (auto +
        # non-/sse URL only) legacy SSE. Any failure rolls back partially
        # entered context managers and re-raises WITH the target identity -
        # a bare "ConnectError: All connection attempts failed" from httpx
        # is useless to someone scanning five targets in a loop.
        attempts: list[tuple[Any, TargetSpec]] = [(self._transport_ctx(self.spec), self.spec)]
        if self._allow_sse_fallback:
            fallback_spec = self.spec.model_copy(update={"transport": Transport.SSE})
            attempts.append(
                (
                    sse_client(
                        fallback_spec.url,
                        headers=self.headers if self.headers else self.spec.headers,
                        timeout=self.connect_timeout,
                        **self._http_client_factory_kwargs(),
                    ),
                    fallback_spec,
                )
            )

        last_exc: Exception | None = None
        for index, (ctx, attempt_spec) in enumerate(attempts):
            try:
                streams = await ctx.__aenter__()
            except Exception as exc:  # noqa: BLE001 - retried/final-raised below
                # transport never entered; nothing to roll back
                last_exc = exc
                continue
            # streamablehttp_client yields (read, write, get_session_id); the
            # others yield pairs - we only ever need the first two streams.
            read_stream, write_stream = streams[0], streams[1]
            session_kwargs: dict[str, Any] = {}
            if self.read_timeout:
                if _SDK_V2:  # 2.0 takes float seconds
                    session_kwargs["read_timeout_seconds"] = self.read_timeout
                else:  # 1.x takes timedelta
                    from datetime import timedelta

                    session_kwargs["read_timeout_seconds"] = timedelta(
                        seconds=self.read_timeout
                    )
            sess_ctx = ClientSession(read_stream, write_stream, **session_kwargs)
            try:
                session = await sess_ctx.__aenter__()
                await session.initialize()
            except Exception as exc:
                # Roll back whatever entered so a failed connect cannot leak
                # sockets/child processes behind our back. Cleanup failures
                # are logged but never mask the original connect error.
                for rollback in (sess_ctx, ctx):
                    try:
                        await rollback.__aexit__(type(exc), exc, None)
                    except Exception as cleanup_exc:  # noqa: BLE001
                        _log.debug(
                            "rollback after failed connect raised: %s", cleanup_exc
                        )
                raise RuntimeError(
                    self._connect_msg(exc, fell_back=index > 0)
                ) from exc
            self._transport_ctx_obj = ctx
            self._sess_ctx = sess_ctx
            self._session = session
            self.spec = attempt_spec
            return self
        assert last_exc is not None
        raise RuntimeError(
            self._connect_msg(last_exc, fell_back=len(attempts) > 1)
        ) from last_exc

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            if hasattr(self, "_sess_ctx"):
                await self._sess_ctx.__aexit__(exc_type, exc, tb)
        finally:
            if hasattr(self, "_transport_ctx_obj"):
                await self._transport_ctx_obj.__aexit__(exc_type, exc, tb)
        self._session = None

    def _ensure(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("McpSession used outside of `async with` block")
        return self._session

    async def list_tools(self) -> McpCall:
        s = self._ensure()
        t0 = time.perf_counter()
        result = await s.list_tools()
        elapsed = int((time.perf_counter() - t0) * 1000)
        rendered = "\n".join(
            f"- {tool.name}: {tool.description}" for tool in result.tools
        )
        return McpCall(
            kind="list_tools",
            name=None,
            args=None,
            result_text=rendered,
            elapsed_ms=elapsed,
        )

    async def raw_list_tools(self) -> list[Any]:
        """Return the SDK ``Tool`` objects (name/description/inputSchema) directly.

        Callers that need structured metadata (recon classifier, drift detector,
        OpenAI schema builder) should use this instead of parsing the text form
        emitted by :meth:`list_tools`.
        """
        s = self._ensure()
        result = await s.list_tools()
        return list(result.tools)

    async def raw_list_resources(self) -> list[Any]:
        """Return the SDK ``Resource`` objects directly.

        Some real-world MCP servers (e.g. acuvity/mcp-server-filesystem)
        do not implement ``resources/list`` and return MCPError -32601.
        Treat that as "no resources" rather than crashing recon.
        """
        s = self._ensure()
        try:
            result = await s.list_resources()
        except MCPError as exc:
            if exc.code == -32601 or "method not found" in (exc.message or "").lower():
                return []
            raise
        return list(result.resources)

    async def list_resources(self) -> McpCall:
        s = self._ensure()
        t0 = time.perf_counter()
        try:
            result = await s.list_resources()
        except MCPError as exc:
            if exc.code == -32601 or "method not found" in (exc.message or "").lower():
                return McpCall(
                    kind="list_resources",
                    name=None,
                    args=None,
                    result_text="",
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                )
            raise
        elapsed = int((time.perf_counter() - t0) * 1000)
        rendered = "\n".join(
            f"- {res.uri} ({getattr(res, 'name', '')}): {getattr(res, 'description', '') or ''}"
            for res in result.resources
        )
        return McpCall(
            kind="list_resources",
            name=None,
            args=None,
            result_text=rendered,
            elapsed_ms=elapsed,
        )

    async def call_tool(self, name: str, args: dict[str, Any] | None = None) -> McpCall:
        s = self._ensure()
        t0 = time.perf_counter()
        result = await s.call_tool(name, args or {})
        elapsed = int((time.perf_counter() - t0) * 1000)
        text = _flatten_content(getattr(result, "content", None))
        if getattr(result, "isError", False):
            text = f"[isError] {text}"
        return McpCall(
            kind="call_tool",
            name=name,
            args=args or {},
            result_text=text,
            elapsed_ms=elapsed,
        )

    async def read_resource(self, uri: str) -> McpCall:
        s = self._ensure()
        t0 = time.perf_counter()
        result = await s.read_resource(uri)
        elapsed = int((time.perf_counter() - t0) * 1000)
        text = _flatten_content(getattr(result, "contents", None))
        return McpCall(
            kind="read_resource",
            name=uri,
            args=None,
            result_text=text,
            elapsed_ms=elapsed,
        )
