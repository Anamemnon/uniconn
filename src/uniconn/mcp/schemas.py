# src/uniconn/mcp/schemas.py
"""Определения JSON Schema для инструментов и ресурсов встроенного MCP-сервера uniconn."""

from __future__ import annotations

from .models import (
    MCPResourceDefinition,
    MCPResourceTemplate,
    MCPSecurityPolicy,
    MCPToolDefinition,
)


def build_default_tools(policy: MCPSecurityPolicy) -> list[MCPToolDefinition]:
    """Сформировать список определений MCP-инструментов с JSON Schema."""
    write_note = (
        "Enabled in current policy."
        if policy.allow_write
        else "DISABLED by default security policy (requires --allow-write)."
    )
    sudo_note = (
        "Permitted by current policy."
        if policy.allow_sudo
        else "Disabled by default policy (requires --allow-sudo)."
    )
    return [
        MCPToolDefinition(
            name="uniconn_list_hosts",
            description=(
                "List registered hosts, groups, transport schemes, and active security "
                "guardrails in the uniconn MCP server registry."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "group": {
                        "type": "string",
                        "description": "Optional group name to filter registered hosts.",
                    }
                },
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_ping",
            description=(
                "Check connectivity and measure round-trip latency (RTT) concurrently across "
                "one or more registered hosts."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ],
                        "description": "Host alias or list of host aliases to ping.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Ping timeout in seconds (default: 5.0).",
                        "default": 5.0,
                    },
                },
                "required": ["targets"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_run",
            description=(
                "Execute a command on a target host through the resilient uniconn pipeline "
                "with automatic structured CLI output parsing (parse='auto') and zero-turn "
                f"self-healing diagnostics on failure. Sudo status: {sudo_note}"
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered host name/alias.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command string to execute on the target host.",
                    },
                    "parse": {
                        "oneOf": [{"type": "boolean"}, {"type": "string"}],
                        "description": (
                            "Enable semantic output parsing (true/'auto', false, or explicit "
                            "parser spec like 'df', 'ip_addr', 'jc:uname'). Default: true."
                        ),
                        "default": True,
                    },
                    "diagnose": {
                        "type": "boolean",
                        "description": (
                            "Automatically collect root-cause diagnostic context (category, vitals, "
                            "logs, port conflicts, suggested actions) when exit_code != 0. Default: true."
                        ),
                        "default": True,
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Execution timeout in seconds (default: 30.0).",
                        "default": 30.0,
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Optional working directory for command execution.",
                    },
                    "sudo": {
                        "type": "boolean",
                        "description": "Execute command with sudo privileges (requires --allow-sudo or HITL).",
                        "default": False,
                    },
                    "approval_id": {
                        "type": "string",
                        "description": (
                            "Single-use HITL approval token ID (e.g. 'appr_...') obtained after "
                            "human operator approval."
                        ),
                    },
                    "wait_for_approval": {
                        "type": "boolean",
                        "description": (
                            "Wait synchronously up to wait_timeout_seconds for operator approval "
                            "if action triggers HITL policy."
                        ),
                    },
                },
                "required": ["target", "command"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_gather_facts",
            description=(
                "Collect structured system facts from a target host (OS family, distribution, "
                "kernel, architecture, CPU cores, memory, disks, network interfaces, uptime)."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered host name/alias.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Fact collection timeout in seconds (default: 15.0).",
                        "default": 15.0,
                    },
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_diff_facts",
            description=(
                "Collect and compare system facts concurrently across multiple hosts or an "
                "inventory group to detect configuration and hardware drift."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of host aliases to compare (minimum 2).",
                    },
                    "group": {
                        "type": "string",
                        "description": "Inventory group name to compare all hosts within the group.",
                    },
                },
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_read_file",
            description=(
                "Safely read UTF-8 text content of a file on a target host with automatic "
                "size truncation and secret masking."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered host name/alias.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Remote file path to read.",
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": f"Maximum bytes to return (capped by policy at {policy.max_read_bytes}).",
                        "default": policy.max_read_bytes,
                    },
                },
                "required": ["target", "path"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_stat_path",
            description=(
                "Inspect metadata of a file or directory on a target host (existence, size, "
                "permissions, modification time)."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered host name/alias.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Remote file or directory path.",
                    },
                },
                "required": ["target", "path"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_checksum",
            description=(
                "Compute cryptographic digest (sha256, sha1, md5) of a file across one "
                "or more hosts concurrently to verify integrity."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ],
                        "description": "Host alias or list of host aliases.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Remote file path to hash.",
                    },
                    "algorithm": {
                        "type": "string",
                        "enum": ["sha256", "sha1", "md5"],
                        "description": "Hash digest algorithm (default: sha256).",
                        "default": "sha256",
                    },
                },
                "required": ["targets", "path"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_write_file",
            description=(
                "Write text content to a file on a target host (supports atomic replacement). "
                f"Write status: {write_note}"
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered host name/alias.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Remote destination file path.",
                    },
                    "content": {
                        "type": "string",
                        "description": "UTF-8 text content to write.",
                    },
                    "atomic": {
                        "type": "boolean",
                        "description": "Write atomically via temporary file rename (default: true).",
                        "default": True,
                    },
                    "approval_id": {
                        "type": "string",
                        "description": (
                            "Single-use HITL approval token ID (e.g. 'appr_...') obtained after "
                            "human operator approval."
                        ),
                    },
                    "wait_for_approval": {
                        "type": "boolean",
                        "description": (
                            "Wait synchronously up to wait_timeout_seconds for operator approval "
                            "if action triggers HITL policy."
                        ),
                    },
                },
                "required": ["target", "path", "content"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_propose_action",
            description=(
                "Evaluate risk tier (SAFE, MUTATING, DESTRUCTIVE, FORBIDDEN) and create a "
                "Human-in-the-Loop (HITL) approval request with unified diff preview before executing "
                "a command or file modification."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered target host name/alias.",
                    },
                    "tool_name": {
                        "type": "string",
                        "enum": ["uniconn_run", "uniconn_write_file"],
                        "description": "Tool to propose ('uniconn_run' or 'uniconn_write_file').",
                        "default": "uniconn_run",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command string when proposing 'uniconn_run'.",
                    },
                    "sudo": {
                        "type": "boolean",
                        "description": "Whether command requires sudo privileges.",
                        "default": False,
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Optional working directory for 'uniconn_run'.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Destination file path when proposing 'uniconn_write_file'.",
                    },
                    "content": {
                        "type": "string",
                        "description": "New UTF-8 file content when proposing 'uniconn_write_file'.",
                    },
                    "atomic": {
                        "type": "boolean",
                        "description": "Atomic write flag when proposing 'uniconn_write_file'.",
                        "default": True,
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Optional identifier of the AI agent proposing the action.",
                    },
                },
                "required": ["target"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_check_approval",
            description=(
                "Check the status of a specific Human-in-the-Loop approval request by approval_id, "
                "or list active approval requests."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "approval_id": {
                        "type": "string",
                        "description": "Optional approval_id (e.g. 'appr_...') to inspect.",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["PENDING", "APPROVED", "CONSUMED", "REJECTED", "EXPIRED"],
                        "description": "Optional status filter when listing approval requests.",
                    },
                },
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_wait_approval",
            description=(
                "Wait asynchronously for a human operator to approve or reject a pending "
                "approval_id up to timeout seconds."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "approval_id": {
                        "type": "string",
                        "description": "Approval request ID (e.g. 'appr_...') to wait for.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Maximum seconds to wait for operator decision (default: 30.0).",
                        "default": 30.0,
                    },
                },
                "required": ["approval_id"],
                "additionalProperties": False,
            },
        ),
    ]


def build_default_resources() -> list[MCPResourceDefinition]:
    """Сформировать список статических ресурсов MCP-сервера."""
    return [
        MCPResourceDefinition(
            uri="uniconn://inventory/hosts",
            name="uniconn Inventory & Security Policy",
            description="Registered hosts, groups, and active MCP security policy.",
        ),
        MCPResourceDefinition(
            uri="uniconn://approvals/pending",
            name="Pending HITL Approvals",
            description="Active Human-in-the-Loop approval requests awaiting operator decision.",
        ),
    ]


def build_default_resource_templates() -> list[MCPResourceTemplate]:
    """Сформировать список шаблонов ресурсов MCP-сервера."""
    return [
        MCPResourceTemplate(
            uri_template="uniconn://hosts/{host}/facts",
            name="Host System Facts",
            description="Live structured HostFacts JSON for a registered host.",
        )
    ]


__all__ = [
    "build_default_resource_templates",
    "build_default_resources",
    "build_default_tools",
]

