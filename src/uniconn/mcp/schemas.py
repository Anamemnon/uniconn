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
                "Human-in-the-Loop (HITL) approval request with unified diff or DAG plan preview "
                "before executing a command, file modification, or orchestration Flow."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Registered target host name/alias (or comma-separated aliases for flows).",
                    },
                    "targets": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ],
                        "description": "Target host alias or list of host aliases when proposing a Flow.",
                    },
                    "group": {
                        "type": "string",
                        "description": "Optional inventory group name when proposing a Flow.",
                    },
                    "tool_name": {
                        "type": "string",
                        "description": (
                            "Tool to propose ('uniconn_run', 'uniconn_write_file', "
                            "'uniconn_run_flow', or dynamic 'flow_<name>')."
                        ),
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
                    "flow_name": {
                        "type": "string",
                        "description": "Flow name when proposing 'uniconn_run_flow'.",
                    },
                    "vars": {
                        "type": "object",
                        "description": "Flow parameters dictionary when proposing a Flow.",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional task tag filter when proposing a Flow.",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["barrier", "independent"],
                        "description": "Optional rollout mode when proposing a Flow.",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Optional identifier of the AI agent proposing the action.",
                    },
                },
                "additionalProperties": True,
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
        MCPToolDefinition(
            name="uniconn_list_flows",
            description=(
                "List all registered declarative DAG orchestration Flows exported as MCP tools, "
                "including their waves, tasks, input parameter schemas, and risk assessments."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "include_checkpoints": {
                        "type": "boolean",
                        "description": "Include resumable flow checkpoints (default: true).",
                        "default": True,
                    }
                },
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_inspect_flow",
            description=(
                "Inspect a registered orchestration Flow in detail: returns its ASCII DAG execution plan, "
                "topological waves, task dependencies, JSON Schema of parameters, and HITL risk assessment."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "flow_name": {
                        "type": "string",
                        "description": (
                            "Registered Flow name or MCP tool name "
                            "(e.g. 'zero_downtime_deploy' or 'flow_zero_downtime_deploy')."
                        ),
                    },
                    "targets": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ],
                        "description": "Optional target hosts to preview in the execution plan.",
                    },
                    "group": {
                        "type": "string",
                        "description": "Optional host group to preview in the execution plan.",
                    },
                    "vars": {
                        "type": "object",
                        "description": "Optional parameter values to preview in the execution plan.",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional tag filter to preview active tasks in the DAG.",
                    },
                },
                "required": ["flow_name"],
                "additionalProperties": False,
            },
        ),
        MCPToolDefinition(
            name="uniconn_run_flow",
            description=(
                "Execute a registered declarative DAG orchestration Flow across one or more target hosts "
                "or an inventory group with two-phase HITL approval, automatic root-cause diagnostics on "
                "task failure, and resumable checkpointing."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "flow_name": {
                        "type": "string",
                        "description": "Registered Flow name or tool name to execute.",
                    },
                    "targets": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "array", "items": {"type": "string"}},
                        ],
                        "description": "Target host alias or list of host aliases.",
                    },
                    "group": {
                        "type": "string",
                        "description": "Optional inventory group name to target.",
                    },
                    "vars": {
                        "type": "object",
                        "description": (
                            "Dictionary of Flow parameters "
                            "(passed to FlowContext.vars and @task functions)."
                        ),
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of task tags to filter execution.",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["barrier", "independent"],
                        "description": "Optional override for fleet execution mode ('barrier' or 'independent').",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Run Flow in dry-run simulation mode without mutating hosts.",
                        "default": False,
                    },
                    "approval_id": {
                        "type": "string",
                        "description": "Single-use HITL approval token ID (e.g. 'appr_...').",
                    },
                    "wait_for_approval": {
                        "type": "boolean",
                        "description": "Wait synchronously for human operator approval if HITL is triggered.",
                    },
                    "resume_run_id": {
                        "type": "string",
                        "description": "Optional checkpoint run_id (e.g. 'run_...') to resume from.",
                    },
                },
                "required": ["flow_name"],
                "additionalProperties": True,
            },
        ),
        MCPToolDefinition(
            name="uniconn_resume_flow",
            description=(
                "Resume a previously failed Flow execution from its checkpoint run_id, skipping "
                "(host, task) nodes that already succeeded in earlier runs."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "run_id": {
                        "type": "string",
                        "description": "Checkpoint run_id (e.g. 'run_...') from a failed Flow execution.",
                    },
                    "vars": {
                        "type": "object",
                        "description": "Optional updated FlowContext.vars parameters for the resumed run.",
                    },
                    "approval_id": {
                        "type": "string",
                        "description": "Single-use HITL approval token ID (e.g. 'appr_...') if approval is required.",
                    },
                    "wait_for_approval": {
                        "type": "boolean",
                        "description": "Wait synchronously for human operator approval if HITL is triggered.",
                    },
                },
                "required": ["run_id"],
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
        MCPResourceDefinition(
            uri="uniconn://flows",
            name="Registered Orchestration Flows & Checkpoints",
            description="Registered DAG orchestration Flows exported as tools and resumable checkpoints.",
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

