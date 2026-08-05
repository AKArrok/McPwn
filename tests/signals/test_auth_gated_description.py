"""Regression tests for the description-based auth-gated tool detection.

v0 used an exact-name hardcode ``(remote_access|admin|manage|verify_token|
authenticate|grant_role)`` that was DVMCP-shaped. The detector now judges
auth-gated by tool description (primary) or name stem (fallback). These
tests lock down the new contract:

- description-flavored tool with a non-DVMCP name still fires
- non-auth tool (no description, no name stem) does not fire even with
  success phrase
- DVMCP 9007 / 9009 tool descriptions still fire (regression gate for
  the recall=8/10 result)
"""

from __future__ import annotations

from mcp_redteam.contracts import McpCall
from mcp_redteam.signals.detectors import detect_unauthenticated_success


def test_auth_gated_via_description_for_generic_tool_name():
    """A tool named ``check_permission`` (not in the old DVMCP hardcode)
    with an auth-flavored description must fire the second pass."""
    list_tools = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- check_permission: Verify if the user has admin permission "
            "to access this resource"
        ),
        elapsed_ms=1,
    )
    call = McpCall(
        kind="call_tool",
        name="check_permission",
        args={},
        result_text="Access granted",
        elapsed_ms=1,
    )
    sig = detect_unauthenticated_success([list_tools, call], "")
    assert sig is not None
    assert sig.signal_id == "unauthenticated_success"
    assert sig.source_call_index == 1


def test_auth_gated_via_description_for_require_auth_tool():
    """A tool named ``require_auth`` (not in the old hardcode) with a
    minimal description must fire via the name stem fallback."""
    list_tools = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text="- require_auth: Authenticate the user",
        elapsed_ms=1,
    )
    call = McpCall(
        kind="call_tool",
        name="require_auth",
        args={},
        result_text="Authentication successful",
        elapsed_ms=1,
    )
    sig = detect_unauthenticated_success([list_tools, call], "")
    assert sig is not None


def test_non_auth_tool_does_not_fire_even_with_success_phrase():
    """A tool with a benign description and a generic name (no auth stem)
    must not fire even if the response contains a success phrase. This
    is the negative-case gate for the new logic."""
    list_tools = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text="- add: Add two numbers and return the sum",
        elapsed_ms=1,
    )
    call = McpCall(
        kind="call_tool",
        name="add",
        args={"a": 1, "b": 2},
        result_text="3",
        elapsed_ms=1,
    )
    assert detect_unauthenticated_success([list_tools, call], "") is None


def test_dvmcp_9007_authenticate_description_still_fires():
    """Regression gate: DVMCP 9007 ``authenticate`` description must keep
    firing so M2 9007 (2 findings) does not regress."""
    list_tools = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- authenticate: Authenticate a user and return a session token\\n"
            "- verify_token: Verify if a session token is valid"
        ),
        elapsed_ms=1,
    )
    call = McpCall(
        kind="call_tool",
        name="verify_token",  # takes token arg, first pass fires
        args={"token": "forged_string_xx"},
        result_text="Token is valid",
        elapsed_ms=1,
    )
    sig = detect_unauthenticated_success([list_tools, call], "")
    assert sig is not None
    assert sig.signal_id == "unauthenticated_success"


def test_dvmcp_9009_remote_access_description_fires():
    """Regression gate: DVMCP 9009 ``remote_access`` description has
    ``authentication token`` in the arg block; second pass must fire."""
    list_tools = McpCall(
        kind="list_tools",
        name=None,
        args=None,
        result_text=(
            "- remote_access: Execute a command on a remote system\\n\\n"
            "            Args:\\n"
            "                system: The remote system to access\\n"
            "                command: The command to execute\\n"
            "                auth_token: Optional authentication token for "
            "privileged operations\\n"
        ),
        elapsed_ms=1,
    )
    call = McpCall(
        kind="call_tool",
        name="remote_access",
        args={"system": "db", "command": "id"},
        result_text="Command executed on db",
        elapsed_ms=1,
    )
    sig = detect_unauthenticated_success([list_tools, call], "")
    assert sig is not None
    assert sig.signal_id == "unauthenticated_success"
