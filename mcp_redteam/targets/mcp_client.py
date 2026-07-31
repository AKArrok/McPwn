"""Thin async wrapper over the official `mcp` SDK's SSE client.

Design:
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

import time
from types import TracebackType
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client

from mcp_redteam.contracts import McpCall


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
    """Async session against a DVMCP SSE endpoint.

    Usage:
        async with McpSession("http://127.0.0.1:9001/sse") as s:
            call = await s.read_resource("internal://credentials")
    """

    def __init__(self, sse_url: str, connect_timeout: float = 15.0) -> None:
        self.sse_url = sse_url
        self.connect_timeout = connect_timeout
        self._stack: list[Any] = []
        self._session: ClientSession | None = None

    async def __aenter__(self) -> McpSession:
        # sse_client and ClientSession are both async context managers; we enter them
        # manually so the session survives beyond a single `async with`.
        self._sse_ctx = sse_client(self.sse_url)
        streams = await self._sse_ctx.__aenter__()
        read_stream, write_stream = streams
        self._sess_ctx = ClientSession(read_stream, write_stream)
        self._session = await self._sess_ctx.__aenter__()
        await self._session.initialize()
        return self

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
            if hasattr(self, "_sse_ctx"):
                await self._sse_ctx.__aexit__(exc_type, exc, tb)
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
        """Return the SDK ``Resource`` objects directly."""
        s = self._ensure()
        result = await s.list_resources()
        return list(result.resources)

    async def list_resources(self) -> McpCall:
        s = self._ensure()
        t0 = time.perf_counter()
        result = await s.list_resources()
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
