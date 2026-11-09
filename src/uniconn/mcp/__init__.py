# src/uniconn/mcp/__init__.py
"""Официальный встроенный сервер Model Context Protocol (MCP) для uniconn."""

from __future__ import annotations

from .models import (
    MCPHostEntry,
    MCPResourceDefinition,
    MCPResourceTemplate,
    MCPSecurityPolicy,
    MCPToolDefinition,
)
from .registry import MCPHostRegistry, mask_uri_secrets
from .server import SUPPORTED_PROTOCOL_VERSION, MCPServer

__all__ = [
    "SUPPORTED_PROTOCOL_VERSION",
    "MCPHostEntry",
    "MCPHostRegistry",
    "MCPResourceDefinition",
    "MCPResourceTemplate",
    "MCPSecurityPolicy",
    "MCPServer",
    "MCPToolDefinition",
    "mask_uri_secrets",
]
