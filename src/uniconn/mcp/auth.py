# src/uniconn/mcp/auth.py
"""Fail-closed аутентификация (OAuth 2.1/OIDC JWKS + mTLS X.509) и контекст субъекта для сетевого MCP."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any

from ._auth_models import (
    CallerIdentity,
    MCPAuthConfig,
    MCPAuthError,
    MCPHttpConfig,
    MTLSConfig,
    OAuth2OIDCConfig,
    _require_jwt_crypto,
    caller_identity_context,
    get_current_caller,
)
from ._auth_mtls import MTLSClientCertValidator
from ._auth_oauth2 import JsonFetcher, OAuth2JWTValidator


def _extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    """Извлечь Bearer-токен из заголовка ``Authorization`` (без учёта регистра имени заголовка)."""
    auth_hdr = next((v for k, v in headers.items() if k.lower() == "authorization"), None)
    if not auth_hdr:
        return None
    parts = auth_hdr.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise MCPAuthError("Authorization header must use Bearer scheme", status_code=401)
    return parts[1].strip()


class MCPAuthenticator:
    """Композитный fail-closed аутентификатор MCP-шлюза (``oauth2``, ``mtls``, ``either``, ``both``)."""

    def __init__(
        self,
        config: MCPAuthConfig,
        *,
        jwks_fetcher: JsonFetcher | None = None,
    ) -> None:
        """Инициализировать валидаторы OAuth 2.1 и/или mTLS согласно ``MCPAuthConfig``."""
        self.config = config
        self.oauth2_validator = (
            OAuth2JWTValidator(
                config.oauth2,
                default_role=config.default_role,
                default_tenant=config.default_tenant,
                require_tenant=config.require_tenant,
                fetcher=jwks_fetcher,
            )
            if config.oauth2 is not None
            else None
        )
        self.mtls_validator = (
            MTLSClientCertValidator(
                config.mtls,
                default_role=config.default_role,
                default_tenant=config.default_tenant,
                require_tenant=config.require_tenant,
            )
            if config.mtls is not None
            else None
        )

    async def authenticate(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> CallerIdentity:
        """Провалидировать входящий HTTP-запрос и вернуть криптографически подтверждённую ``CallerIdentity``."""
        mode = self.config.mode

        if mode == "oauth2":
            token = _extract_bearer_token(headers)
            if not token:
                raise MCPAuthError("Missing Bearer access token", status_code=401)
            if self.oauth2_validator is None:
                raise MCPAuthError("OAuth2 validator is not configured", status_code=401)
            return await self.oauth2_validator.validate_token(token)

        if mode == "mtls":
            if self.mtls_validator is None:
                raise MCPAuthError("mTLS validator is not configured", status_code=401)
            return self.mtls_validator.validate_scope(scope, headers)

        if mode == "either":
            token = _extract_bearer_token(headers)
            if token is not None:
                if self.oauth2_validator is None:
                    raise MCPAuthError("OAuth2 authentication is not enabled", status_code=401)
                return await self.oauth2_validator.validate_token(token)
            if self.mtls_validator is not None:
                return self.mtls_validator.validate_scope(scope, headers)
            raise MCPAuthError("Missing Bearer token or client mTLS certificate", status_code=401)

        # mode == "both": defense-in-depth (OAuth 2.1 + mTLS + RFC 8705 cnf.x5t#S256 binding)
        token = _extract_bearer_token(headers)
        if not token:
            raise MCPAuthError("Mode 'both' requires both Bearer token and mTLS certificate", status_code=401)
        if self.oauth2_validator is None or self.mtls_validator is None:
            raise MCPAuthError("Both OAuth2 and mTLS validators must be configured", status_code=401)

        cert_identity = self.mtls_validator.validate_scope(
            scope,
            headers,
            allow_missing_role=True,
            allow_missing_tenant=True,
        )
        jwt_identity = await self.oauth2_validator.validate_token(
            token,
            allow_missing_role=bool(cert_identity.role),
            allow_missing_tenant=bool(cert_identity.tenant_id),
        )

        # RFC 8705 Certificate-Bound Access Token check (cnf.x5t#S256)
        mtls_cfg = self.config.mtls
        if mtls_cfg is not None and mtls_cfg.verify_jwt_cert_thumbprint:
            cnf = jwt_identity.claims.get("cnf")
            cnf_thumb = cnf.get("x5t#S256") if isinstance(cnf, Mapping) else None
            if cnf_thumb is not None:
                if not isinstance(cnf_thumb, str) or not cert_identity.cert_thumbprint_sha256:
                    raise MCPAuthError("Invalid RFC 8705 cnf.x5t#S256 claim", status_code=401)
                if not hmac.compare_digest(cnf_thumb, cert_identity.cert_thumbprint_sha256):
                    raise MCPAuthError(
                        "JWT cnf.x5t#S256 thumbprint does not match client mTLS certificate",
                        status_code=401,
                    )
            elif mtls_cfg.require_jwt_cert_binding:
                raise MCPAuthError(
                    "JWT is missing required RFC 8705 cnf.x5t#S256 certificate binding claim",
                    status_code=401,
                )

        if (
            jwt_identity.tenant_id
            and cert_identity.tenant_id
            and jwt_identity.tenant_id != cert_identity.tenant_id
        ):
            raise MCPAuthError(
                "Tenant mismatch between JWT claim and mTLS client certificate",
                status_code=403,
                error_code="tenant_mismatch",
            )

        merged_tenant = jwt_identity.tenant_id or cert_identity.tenant_id
        if self.config.require_tenant and not merged_tenant:
            raise MCPAuthError("Neither JWT nor mTLS certificate provides a tenant_id", status_code=403)

        merged_role = jwt_identity.role or cert_identity.role
        if not merged_role:
            raise MCPAuthError("Neither JWT nor mTLS certificate provides an authorized role", status_code=403)

        return CallerIdentity(
            agent_id=jwt_identity.agent_id,
            role=merged_role,
            tenant_id=merged_tenant,
            auth_method="oauth2+mtls",
            scopes=jwt_identity.scopes,
            cert_thumbprint_sha256=cert_identity.cert_thumbprint_sha256,
            verified=True,
            claims=jwt_identity.claims,
        )


__all__ = [
    "CallerIdentity",
    "JsonFetcher",
    "MCPAuthConfig",
    "MCPAuthError",
    "MCPAuthenticator",
    "MCPHttpConfig",
    "MTLSClientCertValidator",
    "MTLSConfig",
    "OAuth2JWTValidator",
    "OAuth2OIDCConfig",
    "_require_jwt_crypto",
    "caller_identity_context",
    "get_current_caller",
]
