# src/uniconn/mcp/_auth_oauth2.py
"""Валидация OAuth 2.1 / OIDC Bearer JWT (Discovery, JWKS TTL-кэш, SSRF-защита)."""

from __future__ import annotations

import asyncio
import json
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..exceptions import ConfigurationError
from ..security.url_validation import open_ssrf_safe_url, validate_outbound_url
from ._auth_models import (
    CallerIdentity,
    MCPAuthError,
    OAuth2OIDCConfig,
    _extract_nested_claim,
    _extract_scopes,
    _require_jwt_crypto,
    _resolve_role_value,
)

JsonFetcher = Callable[[str, float], dict[str, Any]]


def _default_ssrf_json_fetch(url: str, timeout: float, *, allow_private_network: bool) -> dict[str, Any]:
    """Выполнить SSRF-безопасный HTTP GET JSON-документа (OIDC Discovery / JWKS)."""
    validate_outbound_url(url, allow_private_network=allow_private_network, resolve_dns=False)
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "uniconn-mcp-auth"},
        method="GET",
    )
    with open_ssrf_safe_url(
        req,
        timeout=timeout,
        allow_private_network=allow_private_network,
        allow_redirects=False,
    ) as resp:
        raw = resp.read(524_288)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise MCPAuthError(f"Expected JSON object from {url!r}", status_code=401)
    return parsed


class OAuth2JWTValidator:
    """Валидатор Bearer JWT по OAuth 2.1 / OIDC (Discovery, кэшируемый JWKS, static key)."""

    def __init__(
        self,
        config: OAuth2OIDCConfig,
        *,
        default_role: str | None = None,
        default_tenant: str | None = None,
        require_tenant: bool = True,
        fetcher: JsonFetcher | None = None,
    ) -> None:
        """Инициализировать валидатор JWT с TTL-кэшем JWKS и SSRF-защитой."""
        self.config = config
        self._default_role = default_role
        self._default_tenant = default_tenant
        self._require_tenant = require_tenant
        self._fetcher = fetcher
        self._lock = asyncio.Lock()
        self._discovered_jwks_url: str | None = config.jwks_url
        self._jwks_keys: list[dict[str, Any]] = []
        self._jwks_fetched_at: float = 0.0
        self._jwks_expires_at: float = 0.0

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        validate_outbound_url(
            url,
            allow_private_network=self.config.allow_private_network,
            resolve_dns=False,
        )
        if self._fetcher is not None:
            result = self._fetcher(url, self.config.http_timeout_seconds)
            if asyncio.iscoroutine(result):
                return await result
            return result
        return await asyncio.to_thread(
            _default_ssrf_json_fetch,
            url,
            self.config.http_timeout_seconds,
            allow_private_network=self.config.allow_private_network,
        )

    async def _resolve_jwks_url(self) -> str:
        if self._discovered_jwks_url:
            return self._discovered_jwks_url
        if not self.config.issuer:
            raise MCPAuthError("OIDC issuer or jwks_url is not configured", status_code=401)
        discovery_url = self.config.issuer.rstrip("/") + "/.well-known/openid-configuration"
        try:
            doc = await self._fetch_json(discovery_url)
        except ConfigurationError as exc:
            raise MCPAuthError(f"Blocked OIDC discovery URL: {exc}", status_code=401) from exc
        except Exception as exc:
            raise MCPAuthError(f"Failed to fetch OIDC discovery metadata: {exc}", status_code=401) from exc
        jwks_uri = doc.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.strip():
            raise MCPAuthError("OIDC discovery document missing 'jwks_uri'", status_code=401)
        try:
            validate_outbound_url(
                jwks_uri,
                allow_private_network=self.config.allow_private_network,
                resolve_dns=False,
            )
        except ConfigurationError as exc:
            raise MCPAuthError(f"Blocked JWKS URL from OIDC discovery: {exc}", status_code=401) from exc
        self._discovered_jwks_url = jwks_uri.strip()
        return self._discovered_jwks_url

    async def _load_jwks(self, *, force_refresh: bool = False) -> list[dict[str, Any]]:
        if self.config.static_jwks is not None:
            raw_keys = self.config.static_jwks.get("keys")
            return [dict(k) for k in raw_keys if isinstance(k, Mapping)] if isinstance(raw_keys, list) else []

        now = time.monotonic()
        if not force_refresh and self._jwks_keys and now < self._jwks_expires_at:
            return self._jwks_keys

        async with self._lock:
            now = time.monotonic()
            if not force_refresh and self._jwks_keys and now < self._jwks_expires_at:
                return self._jwks_keys
            if (
                force_refresh
                and self._jwks_keys
                and (now - self._jwks_fetched_at) < self.config.jwks_refresh_min_interval_seconds
            ):
                return self._jwks_keys

            jwks_url = await self._resolve_jwks_url()
            try:
                doc = await self._fetch_json(jwks_url)
            except ConfigurationError as exc:
                raise MCPAuthError(f"Blocked JWKS URL: {exc}", status_code=401) from exc
            except Exception as exc:
                raise MCPAuthError(f"Failed to fetch JWKS keys: {exc}", status_code=401) from exc

            raw_keys = doc.get("keys")
            if not isinstance(raw_keys, list) or not raw_keys:
                raise MCPAuthError("JWKS document contains no keys", status_code=401)
            self._jwks_keys = [dict(k) for k in raw_keys if isinstance(k, Mapping)]
            self._jwks_fetched_at = time.monotonic()
            self._jwks_expires_at = self._jwks_fetched_at + self.config.jwks_cache_ttl_seconds
            return self._jwks_keys

    async def _resolve_signing_key(self, pyjwt: Any, kid: str | None) -> Any:
        if self.config.static_public_key_pem:
            return self.config.static_public_key_pem

        keys = await self._load_jwks(force_refresh=False)
        matched = self._select_jwk(keys, kid)
        if matched is None and self.config.static_jwks is None:
            keys = await self._load_jwks(force_refresh=True)
            matched = self._select_jwk(keys, kid)

        if matched is None:
            raise MCPAuthError(f"No matching JWKS signing key found for kid={kid!r}", status_code=401)
        try:
            return pyjwt.PyJWK.from_dict(matched).key
        except Exception as exc:
            raise MCPAuthError(f"Invalid JWK key material: {exc}", status_code=401) from exc

    @staticmethod
    def _select_jwk(keys: Sequence[dict[str, Any]], kid: str | None) -> dict[str, Any] | None:
        sig_keys = [k for k in keys if k.get("use", "sig") == "sig"]
        if kid:
            for item in sig_keys:
                if item.get("kid") == kid:
                    return item
            return None
        if len(sig_keys) == 1:
            return sig_keys[0]
        return None

    async def validate_token(
        self,
        token: str,
        *,
        allow_missing_role: bool = False,
        allow_missing_tenant: bool = False,
    ) -> CallerIdentity:
        """Провалидировать Bearer JWT и вернуть верифицированную ``CallerIdentity``."""
        pyjwt, _, _ = _require_jwt_crypto()
        clean_token = token.strip()
        if not clean_token:
            raise MCPAuthError("Empty Bearer token", status_code=401)

        try:
            header = pyjwt.get_unverified_header(clean_token)
        except Exception as exc:
            raise MCPAuthError(f"Malformed JWT header: {exc}", status_code=401) from exc

        alg = str(header.get("alg") or "").strip()
        if not alg or alg.lower() == "none" or alg not in self.config.algorithms:
            raise MCPAuthError(f"Rejected JWT algorithm {alg!r}", status_code=401)

        kid = header.get("kid")
        key = await self._resolve_signing_key(pyjwt, str(kid) if kid is not None else None)

        audience = (
            list(self.config.audience)
            if isinstance(self.config.audience, tuple)
            else self.config.audience
        )
        required_claims = ["sub"]
        if self.config.verify_exp:
            required_claims.append("exp")

        try:
            claims = pyjwt.decode(
                clean_token,
                key=key,
                algorithms=list(self.config.algorithms),
                audience=audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway_seconds,
                options={
                    "verify_signature": True,
                    "verify_exp": self.config.verify_exp,
                    "verify_nbf": self.config.verify_nbf,
                    "verify_aud": bool(audience),
                    "verify_iss": bool(self.config.issuer),
                    "require": required_claims,
                },
            )
        except Exception as exc:
            raise MCPAuthError(f"JWT validation failed: {exc}", status_code=401) from exc

        if not isinstance(claims, dict):
            raise MCPAuthError("JWT payload must be a JSON object", status_code=401)

        scopes = _extract_scopes(claims, self.config.scope_claim)
        if self.config.required_scopes:
            missing = [s for s in self.config.required_scopes if s not in scopes]
            if missing:
                raise MCPAuthError(
                    f"Token missing required OAuth scope(s): {', '.join(missing)}",
                    status_code=403,
                    error_code="insufficient_scope",
                    required_scopes=self.config.required_scopes,
                )

        raw_agent = _extract_nested_claim(claims, self.config.agent_id_claim)
        if raw_agent is not None and (not isinstance(raw_agent, str | int) or isinstance(raw_agent, bool)):
            raise MCPAuthError(
                f"Token claim {self.config.agent_id_claim!r} must be a scalar string or integer",
                status_code=401,
            )
        agent_id = str(raw_agent).strip() if raw_agent is not None and str(raw_agent).strip() else ""
        if not agent_id:
            raise MCPAuthError(
                f"Token missing required subject claim {self.config.agent_id_claim!r}",
                status_code=401,
            )

        raw_role = _extract_nested_claim(claims, self.config.role_claim)
        role = _resolve_role_value(
            raw_role,
            role_mapping=self.config.role_mapping,
            role_priority=self.config.role_priority,
            default_role=self._default_role,
        )
        if not role:
            if allow_missing_role:
                role = ""
            else:
                raise MCPAuthError(
                    f"Token does not carry an authorized role in claim {self.config.role_claim!r}",
                    status_code=403,
                    error_code="insufficient_role",
                )

        raw_tenant = _extract_nested_claim(claims, self.config.tenant_claim)
        if raw_tenant is not None and (not isinstance(raw_tenant, str | int) or isinstance(raw_tenant, bool)):
            raise MCPAuthError(
                f"Token claim {self.config.tenant_claim!r} must be a scalar string or integer",
                status_code=401,
            )
        tenant_id = (
            str(raw_tenant).strip()
            if raw_tenant is not None and str(raw_tenant).strip()
            else self._default_tenant
        )
        if self._require_tenant and not tenant_id and not allow_missing_tenant:
            raise MCPAuthError(
                f"Token missing required tenant claim {self.config.tenant_claim!r}",
                status_code=403,
                error_code="missing_tenant",
            )

        return CallerIdentity(
            agent_id=agent_id,
            role=role,
            tenant_id=tenant_id,
            auth_method="oauth2",
            scopes=scopes,
            verified=True,
            claims=dict(claims),
        )
