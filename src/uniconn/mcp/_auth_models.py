# src/uniconn/mcp/_auth_models.py
"""Модели конфигурации, исключения и контекст субъекта сетевой аутентификации MCP."""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import Iterator, Mapping, Sequence
from contextvars import ContextVar
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..exceptions import AuthenticationError, OptionalDependencyError

_ALLOWED_ASYMMETRIC_ALGS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)


def _require_jwt_crypto() -> tuple[Any, Any, Any]:
    """Лениво загрузить ``jwt``, ``x509`` и ``hashes`` из extra ``uniconn[mcp-http]``."""
    try:
        import jwt as pyjwt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise OptionalDependencyError(
            "Remote network MCP authentication requires optional dependencies "
            "(PyJWT and cryptography). Install with: pip install 'uniconn[mcp-http]'"
        ) from exc
    return pyjwt, x509, hashes


class MCPAuthError(AuthenticationError):
    """Ошибка сетевой аутентификации или авторизации MCP (HTTP 401/403)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 401,
        error_code: str = "invalid_token",
        required_scopes: Sequence[str] = (),
    ) -> None:
        """Инициализировать ошибку сетевой аутентификации с HTTP-статусом и кодом RFC 6750."""
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.required_scopes: tuple[str, ...] = tuple(str(s) for s in required_scopes if str(s).strip())


class CallerIdentity(BaseModel):
    """Криптографически подтверждённый субъект вызова MCP-инструмента."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    role: str
    tenant_id: str | None = None
    auth_method: Literal["oauth2", "mtls", "oauth2+mtls", "stdio"] = "stdio"
    scopes: tuple[str, ...] = ()
    session_id: str | None = None
    cert_thumbprint_sha256: str | None = None
    verified: bool = False
    claims: dict[str, Any] = Field(default_factory=dict, repr=False, exclude=True)

    def to_public_dict(self) -> dict[str, Any]:
        """Сериализовать идентичность без сырых токенов и чувствительных claims."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "auth_method": self.auth_method,
            "scopes": list(self.scopes),
            "session_id": self.session_id,
            "cert_thumbprint_sha256": self.cert_thumbprint_sha256,
            "verified": self.verified,
        }


_CURRENT_CALLER_IDENTITY: ContextVar[CallerIdentity | None] = ContextVar(
    "uniconn_mcp_caller_identity",
    default=None,
)


def get_current_caller() -> CallerIdentity | None:
    """Вернуть активную ``CallerIdentity`` текущего запроса из ``contextvars``."""
    return _CURRENT_CALLER_IDENTITY.get()


@contextlib.contextmanager
def caller_identity_context(identity: CallerIdentity | None) -> Iterator[CallerIdentity | None]:
    """Установить ``CallerIdentity`` в ``ContextVar`` на время обработки запроса."""
    token = _CURRENT_CALLER_IDENTITY.set(identity)
    try:
        yield identity
    finally:
        _CURRENT_CALLER_IDENTITY.reset(token)


class OAuth2OIDCConfig(BaseModel):
    """Конфигурация OAuth 2.1 / OIDC Resource Server (RFC 9728 + JWKS JWT validation)."""

    model_config = ConfigDict(frozen=True)

    issuer: str | None = None
    audience: str | tuple[str, ...] | None = None
    jwks_url: str | None = None
    static_jwks: dict[str, Any] | None = None
    static_public_key_pem: str | None = None
    algorithms: tuple[str, ...] = (
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "EdDSA",
    )
    role_claim: str = "role"
    role_mapping: dict[str, str] = Field(default_factory=dict)
    role_priority: tuple[str, ...] = (
        "admin",
        "platform_admin",
        "lead_sre",
        "senior_sre",
        "sre",
        "operator",
        "agent",
        "readonly",
        "auditor",
        "observer",
        "triage_bot",
    )
    tenant_claim: str = "tenant_id"
    agent_id_claim: str = "sub"
    scope_claim: str = "scope"
    required_scopes: tuple[str, ...] = ()
    jwks_cache_ttl_seconds: float = Field(default=300.0, gt=0.0)
    jwks_refresh_min_interval_seconds: float = Field(default=5.0, ge=0.0)
    leeway_seconds: float = Field(default=30.0, ge=0.0)
    resource_url: str | None = None
    authorization_servers: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    allow_private_network: bool = False
    http_timeout_seconds: float = Field(default=5.0, gt=0.1)
    verify_exp: bool = True
    verify_nbf: bool = True

    @field_validator("algorithms")
    @classmethod
    def _validate_algorithms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("OAuth2OIDCConfig.algorithms must not be empty")
        cleaned: list[str] = []
        for alg in value:
            norm = alg.strip()
            if norm.lower() == "none" or norm.upper().startswith("HS"):
                raise ValueError(
                    f"Algorithm {alg!r} is forbidden for OAuth2/OIDC JWT validation (asymmetric only)"
                )
            if norm not in _ALLOWED_ASYMMETRIC_ALGS:
                raise ValueError(f"Unsupported JWT algorithm {alg!r}")
            cleaned.append(norm)
        return tuple(cleaned)

    @model_validator(mode="after")
    def _validate_key_source(self) -> OAuth2OIDCConfig:
        if not any((self.issuer, self.jwks_url, self.static_jwks, self.static_public_key_pem)):
            raise ValueError(
                "OAuth2OIDCConfig requires at least one key source: "
                "issuer, jwks_url, static_jwks, or static_public_key_pem"
            )
        return self

    def effective_authorization_servers(self) -> list[str]:
        """Вернуть список доверенных Authorization Servers для RFC 9728 metadata."""
        if self.authorization_servers:
            return list(self.authorization_servers)
        if self.issuer:
            return [self.issuer]
        return []


class MTLSConfig(BaseModel):
    """Конфигурация клиентской mTLS-аутентификации (X.509 / SPIFFE / Trusted Proxy)."""

    model_config = ConfigDict(frozen=True)

    ca_cert_path: str | None = None
    ca_cert_pem: str | None = None
    require_client_cert: bool = True
    role_source: Literal["ou", "san_uri", "cn", "static_map", "spiffe_sa"] = "ou"
    role_mapping: dict[str, str] = Field(default_factory=dict)
    tenant_source: Literal["o", "ou", "spiffe_ns", "san_dns", "cn", "static_map"] = "spiffe_ns"
    tenant_mapping: dict[str, str] = Field(default_factory=dict)
    agent_id_source: Literal["cn", "san_uri", "san_email", "spiffe_sa"] = "cn"
    trusted_proxy_cidrs: tuple[str, ...] = ()
    client_cert_pem_headers: tuple[str, ...] = (
        "X-SSL-Client-Cert",
        "X-Client-Cert",
        "X-Forwarded-Client-Cert",
    )
    verify_proxy_cert_chain: bool = True
    verify_jwt_cert_thumbprint: bool = True
    require_jwt_cert_binding: bool = False

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def _validate_cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for raw in value:
            s = raw.strip()
            if not s:
                continue
            ipaddress.ip_network(s, strict=False)
            cleaned.append(s)
        return tuple(cleaned)


class MCPAuthConfig(BaseModel):
    """Сводная конфигурация аутентификации сетевого MCP-шлюза (fail-closed)."""

    model_config = ConfigDict(frozen=True)

    mode: Literal["oauth2", "mtls", "either", "both"] = "oauth2"
    oauth2: OAuth2OIDCConfig | None = None
    mtls: MTLSConfig | None = None
    require_tenant: bool = True
    default_role: str | None = None
    default_tenant: str | None = None

    @model_validator(mode="after")
    def _validate_mode_configs(self) -> MCPAuthConfig:
        if self.mode == "oauth2" and self.oauth2 is None:
            raise ValueError("MCPAuthConfig(mode='oauth2') requires 'oauth2' configuration")
        if self.mode == "mtls" and self.mtls is None:
            raise ValueError("MCPAuthConfig(mode='mtls') requires 'mtls' configuration")
        if self.mode == "both" and (self.oauth2 is None or self.mtls is None):
            raise ValueError("MCPAuthConfig(mode='both') requires both 'oauth2' and 'mtls' configurations")
        if self.mode == "either" and self.oauth2 is None and self.mtls is None:
            raise ValueError("MCPAuthConfig(mode='either') requires at least 'oauth2' or 'mtls'")
        return self


class MCPHttpConfig(BaseModel):
    """Параметры HTTP/SSE-шлюза MCP Streamable HTTP."""

    model_config = ConfigDict(frozen=True)

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    mcp_path: str = "/mcp"
    allowed_origins: tuple[str, ...] = ()
    allow_localhost_origins: bool = True
    allowed_hosts: tuple[str, ...] = ()
    session_ttl_seconds: float = Field(default=1800.0, gt=0.0)
    max_sessions_per_tenant: int = Field(default=100, ge=1)
    max_total_sessions: int = Field(default=10_000, ge=1)
    max_request_bytes: int = Field(default=2_097_152, ge=1024)
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
    tls_client_ca_path: str | None = None
    sse_keepalive_seconds: float = Field(default=15.0, gt=0.1)
    stateless_mode: bool = False
    enable_rfc9728_metadata: bool = True

    @field_validator("mcp_path")
    @classmethod
    def _normalize_path(cls, value: str) -> str:
        cleaned = value.strip() or "/mcp"
        if not cleaned.startswith("/"):
            cleaned = "/" + cleaned
        return cleaned.rstrip("/") or "/mcp"

    @model_validator(mode="after")
    def _validate_tls_pair(self) -> MCPHttpConfig:
        has_cert = bool(self.tls_cert_path and self.tls_cert_path.strip())
        has_key = bool(self.tls_key_path and self.tls_key_path.strip())
        if has_cert != has_key:
            raise ValueError(
                "MCPHttpConfig requires both 'tls_cert_path' and 'tls_key_path' when enabling TLS"
            )
        return self


def _extract_nested_claim(claims: Mapping[str, Any], path: str) -> Any:
    """Извлечь значение claim по имени или точечному пути (например, ``realm_access.roles``)."""
    if path in claims:
        return claims[path]
    cur: Any = claims
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _extract_scopes(claims: Mapping[str, Any], scope_claim: str) -> tuple[str, ...]:
    """Извлечь кортеж OAuth scopes из ``scope`` (строка) или ``scp`` (список)."""
    raw = _extract_nested_claim(claims, scope_claim)
    if raw is None and scope_claim != "scp":
        raw = claims.get("scp")
    if isinstance(raw, str):
        return tuple(tok for tok in raw.split() if tok)
    if isinstance(raw, Sequence) and not isinstance(raw, bytes | bytearray):
        return tuple(str(tok).strip() for tok in raw if str(tok).strip())
    return ()


def _resolve_role_value(
    raw_role: Any,
    *,
    role_mapping: Mapping[str, str],
    role_priority: Sequence[str],
    default_role: str | None,
) -> str | None:
    """Нормализовать значение роли (строка или список ролей) с учётом ``role_mapping``."""
    candidates: list[str] = []
    if isinstance(raw_role, str) and raw_role.strip():
        candidates.append(raw_role.strip())
    elif isinstance(raw_role, Sequence) and not isinstance(raw_role, bytes | bytearray):
        for item in raw_role:
            s = str(item).strip()
            if s:
                candidates.append(s)

    mapped: list[str] = []
    if role_mapping:
        for cand in candidates:
            if cand in role_mapping:
                mapped.append(role_mapping[cand].strip())
    else:
        mapped = list(candidates)

    if not mapped:
        return default_role.strip() if isinstance(default_role, str) and default_role.strip() else None
    if len(mapped) == 1:
        return mapped[0]

    priority_index = {r.lower(): idx for idx, r in enumerate(role_priority)}
    mapped.sort(key=lambda r: priority_index.get(r.lower(), len(priority_index)))
    return mapped[0]
