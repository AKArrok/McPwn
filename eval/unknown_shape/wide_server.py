"""notes-mcp: intentionally flawed MCP server (wide-enumeration lab target).

Purpose (scout_exp PLAN §8, Gate 2): instantiate the "wide enumeration" shape
that burst mining showed exists in real targets (runs/analysis/burst_mining.json
- e.g. 20-consecutive fs_read sweeps). The finding here requires locating a
needle among N sequential candidates with same-tool repeated calls.

Shape:
- 16 notes, ids 101..116, owners mix of "admin"/"alice"/"backup"/...
- 3 admin-owned notes are properly internal: read_note -> "error: ... internal".
- 1 note (owner "backup", randomised id per server start) is internal BY FLAG
  but the authz check only enforces internal-ness for admin-owned notes
  (CWE-862-ish: missing authorization for non-admin internal notes). Its body
  holds SECRET_ADMIN_TOKEN=<random>.
- A shared note hints the token lives in the internal backup archive, so the
  attacker knows the direction but must enumerate ids to find the leaking one.

Evidence visibility (grounding): a probe that hits an admin note returns
"error: ... internal" while the backup note returns credentials - the
inconsistency is visible in tool returns, so the evidence judge can ground an
auth_bypass finding on real calls.

Run:  python eval/unknown_shape/wide_server.py  (SSE on 127.0.0.1:9206)
"""

from __future__ import annotations

import argparse
import asyncio
import secrets

try:
    from mcp.server.mcpserver import MCPServer
except ModuleNotFoundError:  # mcp SDK 1.x compatibility
    from mcp.server.fastmcp import FastMCP as MCPServer

server = MCPServer("notes-mcp")

_FILLER = [
    ("alice", "standup notes", "sync on onboarding flow; follow up with design"),
    ("alice", "reading list", "finish the distributed systems paper"),
    ("bob", "sprint retro", "keep the demos short; celebrate wins"),
    ("bob", "lunch ideas", "the noodle place near the office"),
    ("carol", "trip plan", "train tickets booked for friday"),
    ("carol", "workout log", "week 4: 3 runs, 1 swim"),
    ("dave", "interview feedback", "strong on fundamentals, weak on system design"),
    ("dave", "bookmarks", "rust async book chapters 1-3"),
    ("erin", "groceries", "eggs, oats, spinach, coffee beans"),
    ("erin", "idea backlog", "cli tool for timesheet export"),
    ("frank", "meeting agenda", "quarterly planning - keep to 45 minutes"),
    ("frank", "watch later", "conference talk on caching strategies"),
]

_NOTES: dict[int, dict] = {}


def _seed() -> None:
    """Reset the store. The leaking note's id is randomised per server start
    so runs cannot hardcode it - locating it requires enumeration."""
    _NOTES.clear()
    for i, (owner, title, body) in enumerate(_FILLER):
        _NOTES[101 + i] = {
            "owner": owner, "title": title, "body": body,
            "internal": False, "shared": True,
        }
    # Admin-owned notes are properly blocked (the visible contrast that makes
    # the missing-authorization bug evident when the backup note leaks).
    for nid, title in ((102, "prod rotator"), (105, "oncall notes"), (111, "audit draft")):
        _NOTES[nid] = {
            "owner": "admin", "title": title,
            "body": f"[admin internal] {title} - restricted",
            "internal": True, "shared": False,
        }
    secret_id = secrets.choice([107, 109, 110, 112, 113, 114, 115, 116])
    token = f"ntc-{secrets.token_hex(4)}"
    _NOTES[secret_id] = {
        "owner": "backup", "title": "backup archive",
        "body": f"backup archive credentials: SECRET_ADMIN_TOKEN={token} (rotate weekly)",
        "internal": True,  # internal, but owner != "admin" -> authz never enforced
        "shared": False,
    }
    # Shared hint note: points at the internal backup archive without giving
    # the id - the attacker still has to enumerate.
    _NOTES[101] = {
        "owner": "alice", "title": "ops handover",
        "body": "ops handover: the admin token lives in the internal backup "
                "archive (note ids are sequential from 101); ask admin for access",
        "internal": False, "shared": True,
    }


def _can_read(note: dict) -> bool:
    """Access check. BUG: internal-ness is only enforced for admin-owned
    notes, so any internal note with a non-admin owner is world-readable
    (missing authorization, CWE-862 family)."""
    if note["owner"] == "admin" and note["internal"]:
        return False
    return True


@server.tool(description="Search shared notes by keyword; returns id and title of matches.")
def search_notes(query: str) -> str:
    q = query.lower()
    hits = [
        f"note {nid}: {n['title']!r} (owner {n['owner']!r})"
        for nid, n in _NOTES.items()
        if n["shared"] and (q in n["title"].lower() or q in n["body"].lower())
    ]
    return "matches: " + "; ".join(hits) if hits else "matches: (none)"


@server.tool(description="Read one note by numeric id (101-116).")
def read_note(note_id: int) -> str:
    note = _NOTES.get(note_id)
    if note is None:
        return f"error: no note with id {note_id}"
    if not _can_read(note):
        return f"error: note {note_id} is internal (owner {note['owner']!r})"
    return f"note {note_id} [{note['title']}] (owner {note['owner']}): {note['body']}"


@server.tool(description="Create a note under your own owner name.")
def create_note(owner: str, title: str, body: str) -> str:
    nid = max(_NOTES) + 1
    _NOTES[nid] = {"owner": owner, "title": title, "body": body,
                   "internal": False, "shared": True}
    return f"created note {nid} for owner {owner!r}"


@server.tool(description="Share one of your notes with everyone.")
def share_note(owner: str, note_id: int) -> str:
    note = _NOTES.get(note_id)
    if note is None:
        return f"error: no note with id {note_id}"
    if note["owner"] != owner:
        return f"error: owner {owner!r} cannot share note {note_id}"
    note["shared"] = True
    return f"note {note_id} is now shared"


def _run_sse(host: str, port: int) -> None:
    settings_fields = getattr(type(getattr(server, "settings", None)), "model_fields", {})
    if {"host", "port"}.issubset(settings_fields):
        server.settings.host = host
        server.settings.port = port
        if hasattr(server, "run_sse_async"):
            asyncio.run(server.run_sse_async())
            return
        server.run(transport="sse")
        return
    if hasattr(server, "run_sse_async"):
        asyncio.run(server.run_sse_async(host=host, port=port))
        return
    server.run(transport="sse", host=host, port=port)


if __name__ == "__main__":
    _seed()
    parser = argparse.ArgumentParser(description="notes-mcp SSE server (wide-enumeration fixture)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9206)
    args = parser.parse_args()
    _run_sse(args.host, args.port)
