"""Convert MCP tools + resources into OpenAI-compatible ``tools`` schema.

HANDOFF §5: victim(and agentic attacker) exposes native MCP tools plus a generic
`read_resource(uri)` tool. Tool descriptions are passed through **verbatim** — no
sanitization (HANDOFF §4/victims/AGENTS.md).
"""

from __future__ import annotations

from typing import Any

_READ_RESOURCE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "read_resource",
        "description": (
            "Read the raw text/blob content of an MCP resource by URI "
            "(e.g. 'internal://credentials', 'notes://<user_id>')."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "uri": {
                    "type": "string",
                    "description": "MCP resource URI to read.",
                }
            },
            "required": ["uri"],
        },
    },
}


def _fallback_schema(name: str, description: str) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description or f"MCP tool {name}",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": True},
        },
    }


def mcp_tool_to_openai(tool: Any) -> dict[str, Any]:
    """Map an MCP `Tool` (as returned by ClientSession.list_tools()) into openai tools format."""
    name = getattr(tool, "name", None) or "unknown_tool"
    description = getattr(tool, "description", "") or ""
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
    if not isinstance(schema, dict):
        return _fallback_schema(name, description)
    # Normalize: OpenAI wants `parameters` to be a JSON Schema object.
    if schema.get("type") != "object":
        schema = {"type": "object", "properties": schema.get("properties", {}), "required": schema.get("required", [])}
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": schema},
    }


def build_openai_tools(mcp_tools: list[Any]) -> list[dict[str, Any]]:
    tools = [mcp_tool_to_openai(t) for t in mcp_tools]
    tools.append(_READ_RESOURCE_SCHEMA)
    return tools
