# src/uniconn/mcp/_server_tools.py
"""Фасад миксинов MCP-инструментов (tools) и чтения ресурсов (resources) для MCPServer."""

from __future__ import annotations

import json
from typing import Any

from ._tools_files import MCPFileToolsMixin
from ._tools_governance import MCPGovernanceToolsMixin
from ._tools_hosts import MCPHostToolsMixin
from .models import ApprovalStatus


class MCPServerToolsMixin(MCPHostToolsMixin, MCPFileToolsMixin, MCPGovernanceToolsMixin):
    """Композитный миксин обработчиков MCP tools и resources для ``MCPServer``."""

    async def _read_resource(self, uri: str) -> dict[str, Any]:
        """Прочитать MCP-ресурс по URI."""
        data: dict[str, Any] | None = None
        if uri == "uniconn://inventory/hosts":
            data = await self._tool_list_hosts({})
        elif uri == "uniconn://approvals/pending":
            pending = await self.approval_manager.list_requests(status=ApprovalStatus.PENDING)
            data = {
                "pending_approvals": [r.to_public_dict() for r in pending],
                "count": len(pending),
            }
        elif uri == "uniconn://flows":
            data = await self._tool_list_flows({"include_checkpoints": True})
        elif uri == "uniconn://security/guardrails":
            data = {
                "guardrails": self.policy.guardrails.to_summary_dict(),
                "security_policy": self.policy.to_summary_dict(),
            }
        else:
            prefix = "uniconn://hosts/"
            suffix = "/facts"
            if uri.startswith(prefix) and uri.endswith(suffix):
                host_name = uri[len(prefix) : -len(suffix)].strip("/")
                if not host_name:
                    raise ValueError(f"Invalid host resource URI: {uri!r}")
                data = await self._tool_gather_facts({"target": host_name})

        if data is None:
            raise KeyError(f"Resource URI not found: {uri!r}")

        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data, ensure_ascii=False, indent=2),
                }
            ]
        }


__all__ = [
    "MCPFileToolsMixin",
    "MCPGovernanceToolsMixin",
    "MCPHostToolsMixin",
    "MCPServerToolsMixin",
]
