"""cache-mcp: a multi-tenant cache with a cross-tenant key-collision flaw.

Frozen HOLD-OUT pair (``eval/holdout/manifest.yaml``, split=holdout). The
flaw is deliberately OUTSIDE the fixed vuln-class set and fires zero signals:
the server advertises per-owner isolation ("Each owner has an isolated cache
namespace") but the vulnerable implementation keys the store by the bare
resource key, so tenant A writing ``cache_set(owner="alice", key="config",
...)`` makes tenant B's ``cache_get(owner="bob", key="config")`` return A's
value. That is a confidentiality break (CWE-345 / CWE-200 flavour) discovered
by reasoning about the capability graph, not by a name regex.

``--fixed`` namespaces the key by owner (``(owner, key)``) with identical
tool descriptions - the only difference between the versions is the access
semantics, which is what the paired control replay measures.

Run:  python eval/holdout/fixtures/cache_server.py [--fixed] [--port N]
"""

from __future__ import annotations

import argparse

try:
    from mcp.server.mcpserver import MCPServer
except ModuleNotFoundError:  # mcp SDK 1.x compatibility
    from mcp.server.fastmcp import FastMCP as MCPServer

server = MCPServer("cache-mcp")

_IS_FIXED = False
# vuln: key -> value; fixed: (owner, key) -> value
_STORE: dict = {}


def _canonical_key(owner: str, key: str) -> str:
    return f"{owner}\u0000{key}" if _IS_FIXED else key


@server.tool(description="Store a value under a key in this owner's cache. Each "
                         "owner has an isolated cache namespace.")
def cache_set(owner: str, key: str, value: str) -> str:
    _STORE[_canonical_key(owner, key)] = value
    return f"stored entry '{key}' for owner '{owner}'"


@server.tool(description="Get the value previously stored under a key in this "
                         "owner's cache. Each owner has an isolated cache namespace.")
def cache_get(owner: str, key: str) -> str:
    entry = _STORE.get(_canonical_key(owner, key))
    if entry is None:
        return f"error: no entry '{key}' in owner '{owner}' cache"
    return entry


@server.tool(description="List the keys this owner currently has cached. Each "
                         "owner has an isolated cache namespace.")
def cache_list(owner: str) -> str:
    if _IS_FIXED:
        keys = [k.split("\u0000", 1)[1] for k, _ in _STORE.items() if k.startswith(owner + "\u0000")]
    else:
        keys = list(_STORE.keys())
    return "cached: " + ", ".join(keys) if keys else "cached: (none)"


def _run_sse(host: str, port: int) -> None:
    settings_fields = getattr(type(getattr(server, "settings", None)), "model_fields", {})
    if {"host", "port"}.issubset(settings_fields):
        server.settings.host = host
        server.settings.port = port
        server.run(transport="sse")
        return
    server.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="cache-mcp SSE server (holdout pair fixture)"
    )
    parser.add_argument("--fixed", action="store_true",
                        help="run the FIXED version (owner-namespaced cache)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9215)
    args = parser.parse_args()
    _IS_FIXED = args.fixed
    _run_sse(args.host, args.port)
