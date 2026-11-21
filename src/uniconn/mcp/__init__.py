# src/uniconn/mcp/__init__.py
"""Официальный встроенный сервер Model Context Protocol (MCP) для uniconn."""

from __future__ import annotations

from .auth import (
    CallerIdentity,
    MCPAuthConfig,
    MCPAuthenticator,
    MCPAuthError,
    MCPHttpConfig,
    MTLSClientCertValidator,
    MTLSConfig,
    OAuth2JWTValidator,
    OAuth2OIDCConfig,
    caller_identity_context,
    get_current_caller,
)
from .flows import (
    FlowCheckpointRecord,
    FlowCheckpointStore,
    FlowRiskEvaluator,
    FlowSchemaGenerator,
    MCPFlowRegistry,
    normalize_flow_tool_name,
)
from .hitl import (
    DEFAULT_APPROVAL_STORE_PATH,
    ActionRiskClassifier,
    ApprovalChannel,
    ApprovalManager,
    TerminalApprovalChannel,
    WebhookApprovalChannel,
    build_unified_diff,
)
from .http_transport import build_mcp_http_app, serve_mcp_http
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
from .server import SUPPORTED_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, MCPServer
from .sessions import (
    MCPSession,
    MCPSessionError,
    MCPSessionForbiddenError,
    MCPSessionLimitError,
    MCPSessionManager,
    MCPSessionNotFoundError,
)

__all__ = [
    "DEFAULT_APPROVAL_STORE_PATH",
    "SUPPORTED_PROTOCOL_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ActionRiskClassifier",
    "ActionRiskTier",
    "ApprovalChannel",
    "ApprovalManager",
    "ApprovalRequest",
    "ApprovalStatus",
    "CallerIdentity",
    "FlowCheckpointRecord",
    "FlowCheckpointStore",
    "FlowRiskEvaluator",
    "FlowSchemaGenerator",
    "HITLPolicy",
    "MCPAuthConfig",
    "MCPAuthError",
    "MCPAuthenticator",
    "MCPFlowRegistry",
    "MCPHostEntry",
    "MCPHostRegistry",
    "MCPHttpConfig",
    "MCPResourceDefinition",
    "MCPResourceTemplate",
    "MCPSecurityPolicy",
    "MCPServer",
    "MCPSession",
    "MCPSessionError",
    "MCPSessionForbiddenError",
    "MCPSessionLimitError",
    "MCPSessionManager",
    "MCPSessionNotFoundError",
    "MCPToolDefinition",
    "MTLSClientCertValidator",
    "MTLSConfig",
    "OAuth2JWTValidator",
    "OAuth2OIDCConfig",
    "RiskAssessment",
    "TerminalApprovalChannel",
    "WebhookApprovalChannel",
    "build_mcp_http_app",
    "build_unified_diff",
    "caller_identity_context",
    "get_current_caller",
    "mask_uri_secrets",
    "normalize_flow_tool_name",
    "serve_mcp_http",
]

