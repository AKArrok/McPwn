"""Static (zero-LLM) screening of MCP tool/resource metadata.

The cheap first layer the agent pipeline runs BEFORE any attack traffic:
regex heuristics over tool/resource descriptions and argument schemas,
flagging the shapes that make a tool worth attacking (or avoiding).
Generic, public-knowledge patterns only - nothing tuned to any specific
challenge target (top-level rule 4).

Severity mapping follows the shared SEVERITY_ORDER vocabulary so static
hits can ride the same reporting/SARIF path as dynamic findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from mcp_redteam.contracts import StaticHit

_MAX_MATCH = 200


@dataclass(frozen=True)
class StaticRule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    summary: str
    # Which metadata fields to inspect: "name", "description", "args"
    targets: tuple[str, ...] = ("description",)


_RULES: tuple[StaticRule, ...] = (
    StaticRule(
        "static_instruction_override",
        "high",
        re.compile(
            r"ignore (all |any |the )?(previous|prior|earlier|above) (instructions|prompts)"
            r"|disregard (your|all|the) (instructions|rules)"
            r"|you must (obey|follow) only (this|these) instructions",
            re.IGNORECASE,
        ),
        "工具描述疑似注入指令覆盖语句 (instruction override)",
    ),
    StaticRule(
        "static_concealment",
        "high",
        re.compile(
            r"do not (tell|reveal|inform|mention) (the )?(user|human|owner)"
            r"|hide (this|these) (instructions|tool) from (the )?user"
            r"|keep (this|these) (instructions|behavior) (secret|hidden)",
            re.IGNORECASE,
        ),
        "工具描述要求对用户隐藏自身行为 (concealment)",
    ),
    StaticRule(
        "static_exfiltration",
        "high",
        re.compile(
            r"exfiltrat|send (the )?(data|results|contents) to (a |an |the )?(remote|external|attacker)"
            r"|(webhook|requestbin|pastebin|ngrok)\.[a-z]{2,}"
            r"|post (the )?(data|contents) to (a |the )?third[- ]party (url|endpoint|server)",
            re.IGNORECASE,
        ),
        "工具描述含向第三方/远程端点外传数据的语义 (exfiltration)",
    ),
    StaticRule(
        "static_cross_origin",
        "high",
        re.compile(
            r"(invoke|call|access) (tools?|functions?) (from|of|on) (another|a different|other) (mcp )?server"
            r"|other servers' tools|cross[- ]origin escalation",
            re.IGNORECASE,
        ),
        "工具描述涉及跨 server 调用其他工具 (cross-origin escalation 面)",
    ),
    StaticRule(
        "static_credential_return",
        "medium",
        re.compile(
            r"returns? (the )?(value of )?(api[_ ]?keys?|secrets?|tokens?|credentials|passwords)"
            r"|reads? (the )?\.(env|netrc|npmrc|aws/credentials)"
            r"|dump (all )?(environment variables|env vars)",
            re.IGNORECASE,
        ),
        "工具声称可读取并返回凭证/密钥/环境变量 (credential 面)",
    ),
    StaticRule(
        "static_arbitrary_exec",
        "medium",
        re.compile(
            r"(execute|run) (arbitrary|any|raw) (shell |system |os )?command"
            r"|(os\.system|subprocess\.(call|run)|child_process\.exec)\b"
            r"|\beval\(",
            re.IGNORECASE,
        ),
        "工具声称/实现任意命令执行 (command execution 面)",
    ),
    StaticRule(
        "static_sandbox_escape",
        "medium",
        re.compile(
            r"(\.\./){2,}"
            r"|absolute paths? (are |is )?(allowed|permitted|accepted)"
            r"|bypass(es|ing)? (the )?sandbox",
            re.IGNORECASE,
        ),
        "参数/描述含路径逃逸信号 (sandbox escape 面)",
        targets=("description", "args"),
    ),
    StaticRule(
        "static_internal_surface",
        "medium",
        re.compile(
            r"169\.254\.169\.254"
            r"|(internal|intranet|metadata|admin) (endpoint|service|api)"
            r"|localhost:\d+",
            re.IGNORECASE,
        ),
        "描述指向内网/元数据/管理端点 (SSRF 面)",
    ),
)

_ARG_RULES: tuple[StaticRule, ...] = tuple(
    r for r in _RULES if "args" in r.targets
)


def _hit(rule: StaticRule, subject: str, where: str, matched: str) -> StaticHit:
    excerpt = matched.strip().replace("\n", " ")[:_MAX_MATCH]
    return StaticHit(
        rule_id=rule.rule_id,
        severity=rule.severity,
        subject=subject,
        where=where,
        matched_text=excerpt,
        summary=rule.summary,
    )


def _scan_text(rule: StaticRule, subject: str, where: str, text: str) -> StaticHit | None:
    if not text:
        return None
    m = rule.pattern.search(text)
    if m:
        return _hit(rule, subject, where, m.group(0))
    return None


def _scan_args(rule: StaticRule, subject: str, schema: dict[str, Any]) -> list[StaticHit]:
    hits: list[StaticHit] = []
    props = (schema or {}).get("properties", {})
    if not isinstance(props, dict):
        return hits
    for arg_name, arg_schema in props.items():
        desc = ""
        if isinstance(arg_schema, dict):
            desc = str(arg_schema.get("description", "") or "")
        hit = _scan_text(rule, subject, f"arg:{arg_name}", desc)
        if hit:
            hits.append(hit)
    return hits


def scan_tool_static(tool: Any) -> list[StaticHit]:
    """Screen one SDK Tool object (name/description/inputSchema)."""
    name = getattr(tool, "name", "") or ""
    description = getattr(tool, "description", "") or ""
    schema = getattr(tool, "inputSchema", None)
    schema_dict = schema if isinstance(schema, dict) else {}
    hits: list[StaticHit] = []
    for rule in _RULES:
        hit = _scan_text(rule, name, "description", description)
        if hit:
            hits.append(hit)
        if "args" in rule.targets:
            hits.extend(_scan_args(rule, name, schema_dict))
    return hits


def scan_resource_static(resource: Any) -> list[StaticHit]:
    """Screen one SDK Resource object (uri/name/description)."""
    subject = str(getattr(resource, "uri", "") or getattr(resource, "name", "") or "")
    description = str(getattr(resource, "description", "") or "")
    hits: list[StaticHit] = []
    for rule in _RULES:
        hit = _scan_text(rule, subject, "description", description)
        if hit:
            hits.append(hit)
    return hits


def scan_surface_static(tools: list[Any], resources: list[Any]) -> list[StaticHit]:
    """Screen the full recon surface; deterministic order (rules x objects)."""
    hits: list[StaticHit] = []
    for tool in tools:
        hits.extend(scan_tool_static(tool))
    for resource in resources:
        hits.extend(scan_resource_static(resource))
    return hits
