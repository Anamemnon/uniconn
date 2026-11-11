# src/uniconn/mcp/__init__.py
"""Официальный встроенный сервер Model Context Protocol (MCP) для uniconn."""

from __future__ import annotations

from .hitl import (
    DEFAULT_APPROVAL_STORE_PATH,
    ActionRiskClassifier,
    ApprovalChannel,
    ApprovalManager,
    TerminalApprovalChannel,
    WebhookApprovalChannel,
    build_unified_diff,
)
from .models import (
    ActionRiskTier,
    ApprovalRequest,
    ApprovalStatus,
    HITLPolicy,
    MCPHostEntry,
    MCPResourceDefinition,
    MCPResourceTemplate,
    MCPSecurityPolicy,
    MCPToolDefinition,
    RiskAssessment,
)
from .registry import MCPHostRegistry, mask_uri_secrets
from .server import SUPPORTED_PROTOCOL_VERSION, MCPServer

__all__ = [
    "DEFAULT_APPROVAL_STORE_PATH",
    "SUPPORTED_PROTOCOL_VERSION",
    "ActionRiskClassifier",
    "ActionRiskTier",
    "ApprovalChannel",
    "ApprovalManager",
    "ApprovalRequest",
    "ApprovalStatus",
    "HITLPolicy",
    "MCPHostEntry",
    "MCPHostRegistry",
    "MCPResourceDefinition",
    "MCPResourceTemplate",
    "MCPSecurityPolicy",
    "MCPServer",
    "MCPToolDefinition",
    "RiskAssessment",
    "TerminalApprovalChannel",
    "WebhookApprovalChannel",
    "build_unified_diff",
    "mask_uri_secrets",
]

