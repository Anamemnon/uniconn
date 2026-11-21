# src/uniconn/mcp/_auth_mtls.py
"""Валидация клиентских X.509 mTLS-сертификатов (прямой TLS, SPIFFE, Trusted Proxy)."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from ._auth_models import (
    CallerIdentity,
    MCPAuthError,
    MTLSConfig,
    _require_jwt_crypto,
    _resolve_role_value,
)

_SPIFFE_RE = re.compile(r"^spiffe://([^/]+)(/.*)?$", re.IGNORECASE)
_SPIFFE_NS_SA_RE = re.compile(r"^/ns/([^/]+)/sa/([^/]+)(?:/.*)?$")
_XFCC_PAIR_RE = re.compile(r'([A-Za-z0-9_]+)=(?:"((?:[^"\\]|\\.)*)"|([^;,]+))')


def _compute_cert_thumbprint_s256(cert: Any, hashes_mod: Any) -> str:
    """Вычислить RFC 8705 base64url SHA-256 thumbprint сертификата (``x5t#S256``)."""
    digest = cert.fingerprint(hashes_mod.SHA256())
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_spiffe_uri(uri: str) -> tuple[str | None, str | None, str | None]:
    """Разобрать SPIFFE URI ``spiffe://<domain>/ns/<ns>/sa/<sa>`` в ``(domain, ns, sa)``."""
    m = _SPIFFE_RE.match(uri.strip())
    if not m:
        return None, None, None
    domain = m.group(1)
    path = m.group(2) or ""
    ns_m = _SPIFFE_NS_SA_RE.match(path)
    if ns_m:
        return domain, ns_m.group(1), ns_m.group(2)
    segments = [seg for seg in path.split("/") if seg]
    if len(segments) >= 2:
        return domain, segments[-2], segments[-1]
    if len(segments) == 1:
        return domain, None, segments[0]
    return domain, None, None


def _normalize_pem_from_header(raw_value: str) -> str | None:
    """Извлечь PEM-блок сертификата из сырого или URL-кодированного прокси-заголовка."""
    candidate = unquote(raw_value.strip())
    if "-----BEGIN CERTIFICATE-----" not in candidate:
        return None
    start = candidate.index("-----BEGIN CERTIFICATE-----")
    end_marker = "-----END CERTIFICATE-----"
    if end_marker not in candidate[start:]:
        return None
    end = candidate.index(end_marker, start) + len(end_marker)
    pem_block = candidate[start:end]
    if "\n" not in pem_block:
        body = (
            pem_block.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .strip()
        )
        body = re.sub(r"\s+", "\n", body)
        pem_block = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"
    return pem_block


def _split_first_xfcc_element(header_val: str) -> str:
    """Извлечь первый элемент XFCC до первой запятой вне двойных кавычек."""
    in_quotes = False
    escaped = False
    for idx, ch in enumerate(header_val):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if ch == "," and not in_quotes:
            return header_val[:idx]
    return header_val


def _parse_xfcc_header(header_val: str) -> dict[str, str]:
    """Разобрать первый элемент заголовка Envoy ``X-Forwarded-Client-Cert``."""
    first_elem = _split_first_xfcc_element(header_val)
    parsed: dict[str, str] = {}
    for match in _XFCC_PAIR_RE.finditer(first_elem):
        key = match.group(1).strip()
        val = match.group(2) if match.group(2) is not None else (match.group(3) or "")
        parsed[key] = val.replace('\\"', '"').strip()
    return parsed


class MTLSClientCertValidator:
    """Валидатор клиентских сертификатов X.509 (прямой TLS и доверенные прокси)."""

    def __init__(
        self,
        config: MTLSConfig,
        *,
        default_role: str | None = None,
        default_tenant: str | None = None,
        require_tenant: bool = True,
    ) -> None:
        """Инициализировать валидатор mTLS-сертификатов и загрузить доверенные CA."""
        self.config = config
        self._default_role = default_role
        self._default_tenant = default_tenant
        self._require_tenant = require_tenant
        self._trusted_networks = tuple(
            ipaddress.ip_network(cidr, strict=False) for cidr in config.trusted_proxy_cidrs
        )
        self._ca_certs: list[Any] = []
        self._ca_loaded = False

    def _ensure_ca_loaded(self, x509_mod: Any) -> list[Any]:
        if self._ca_loaded:
            return self._ca_certs
        pem_bytes: bytes | None = None
        if self.config.ca_cert_pem:
            pem_bytes = self.config.ca_cert_pem.encode("utf-8")
        elif self.config.ca_cert_path:
            pem_bytes = Path(self.config.ca_cert_path).expanduser().read_bytes()
        if pem_bytes:
            self._ca_certs = list(x509_mod.load_pem_x509_certificates(pem_bytes))
        self._ca_loaded = True
        return self._ca_certs

    def _is_trusted_proxy(self, client_ip: str | None) -> bool:
        if not self._trusted_networks or not client_ip:
            return False
        try:
            ip_obj = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            return False
        return any(ip_obj in net for net in self._trusted_networks)

    def _verify_cert_chain_and_validity(
        self,
        cert: Any,
        x509_mod: Any,
        *,
        from_proxy: bool,
    ) -> None:
        now = datetime.now(UTC)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=UTC)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=UTC)
        if now < not_before or now > not_after:
            raise MCPAuthError("Client X.509 certificate is expired or not yet valid", status_code=401)

        ca_certs = self._ensure_ca_loaded(x509_mod)
        must_verify_ca = bool(ca_certs) or (from_proxy and self.config.verify_proxy_cert_chain)
        if from_proxy and not self.config.verify_proxy_cert_chain:
            must_verify_ca = False

        if not must_verify_ca:
            return

        if not ca_certs:
            raise MCPAuthError(
                "Trusted proxy mTLS certificate verification requires a configured CA "
                "(ca_cert_path or ca_cert_pem) when verify_proxy_cert_chain=True",
                status_code=401,
            )

        from cryptography.x509.oid import ExtensionOID

        verified = False
        for ca in ca_certs:
            ca_nb = getattr(ca, "not_valid_before_utc", None) or ca.not_valid_before.replace(tzinfo=UTC)
            ca_na = getattr(ca, "not_valid_after_utc", None) or ca.not_valid_after.replace(tzinfo=UTC)
            if now < ca_nb or now > ca_na:
                continue
            try:
                bc_ext = ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                if not bc_ext.ca:
                    continue
            except Exception:
                pass
            try:
                cert.verify_directly_issued_by(ca)
                verified = True
                break
            except Exception:
                continue
        if not verified:
            raise MCPAuthError(
                "Client X.509 certificate failed CA signature verification",
                status_code=401,
            )

    def _extract_cert_from_scope(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, str],
        x509_mod: Any,
    ) -> tuple[Any, bool]:
        """Извлечь сертификат X.509 и признак ``from_proxy`` из ASGI scope или заголовков прокси."""
        # 1. Прямое извлечение из ASGI TLS extension / peer DER/PEM
        extensions = scope.get("extensions")
        if isinstance(extensions, Mapping):
            tls_ext = extensions.get("tls")
            if isinstance(tls_ext, Mapping):
                chain = tls_ext.get("client_cert_chain")
                if isinstance(chain, Sequence) and not isinstance(chain, str | bytes) and chain:
                    leaf = chain[0]
                    if isinstance(leaf, bytes):
                        try:
                            return x509_mod.load_pem_x509_certificate(leaf), False
                        except ValueError:
                            return x509_mod.load_der_x509_certificate(leaf), False
                    if isinstance(leaf, str):
                        return x509_mod.load_pem_x509_certificate(leaf.encode("utf-8")), False

        raw_der = scope.get("client_cert_der")
        if isinstance(raw_der, bytes) and raw_der:
            return x509_mod.load_der_x509_certificate(raw_der), False

        raw_pem = scope.get("client_cert_pem")
        if isinstance(raw_pem, str) and raw_pem.strip():
            return x509_mod.load_pem_x509_certificate(raw_pem.encode("utf-8")), False

        # 2. Извлечение из заголовков только если запрос пришёл от доверенного прокси
        client_tuple = scope.get("client")
        client_ip = str(client_tuple[0]) if isinstance(client_tuple, tuple | list) and client_tuple else None
        if not self._is_trusted_proxy(client_ip):
            return None, False

        lower_headers = {k.lower(): v for k, v in headers.items()}
        for hdr_name in self.config.client_cert_pem_headers:
            hdr_val = lower_headers.get(hdr_name.lower())
            if not hdr_val:
                continue
            if hdr_name.lower() == "x-forwarded-client-cert":
                xfcc = _parse_xfcc_header(hdr_val)
                cert_field = xfcc.get("Cert")
                if cert_field:
                    pem = _normalize_pem_from_header(cert_field)
                    if pem:
                        return x509_mod.load_pem_x509_certificate(pem.encode("utf-8")), True
            pem = _normalize_pem_from_header(hdr_val)
            if pem:
                return x509_mod.load_pem_x509_certificate(pem.encode("utf-8")), True
        return None, True

    def validate_scope(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, str],
        *,
        allow_missing_role: bool = False,
        allow_missing_tenant: bool = False,
    ) -> CallerIdentity:
        """Проверить клиентский X.509 сертификат из TLS/доверенного прокси и вернуть ``CallerIdentity``."""
        _, x509_mod, hashes_mod = _require_jwt_crypto()
        try:
            cert, from_proxy = self._extract_cert_from_scope(scope, headers, x509_mod)
        except Exception as exc:
            raise MCPAuthError(f"Invalid client X.509 certificate payload: {exc}", status_code=401) from exc

        if cert is None:
            raise MCPAuthError("Client mTLS certificate is required", status_code=401)

        self._verify_cert_chain_and_validity(cert, x509_mod, from_proxy=from_proxy)

        from cryptography.x509.oid import ExtensionOID, NameOID

        def _get_name_attr(oid: Any) -> str | None:
            attrs = cert.subject.get_attributes_for_oid(oid)
            if attrs:
                val = str(attrs[0].value).strip()
                return val or None
            return None

        cn = _get_name_attr(NameOID.COMMON_NAME)
        ou = _get_name_attr(NameOID.ORGANIZATIONAL_UNIT_NAME)
        org = _get_name_attr(NameOID.ORGANIZATION_NAME)

        san_uris: list[str] = []
        san_dns: list[str] = []
        san_emails: list[str] = []
        with contextlib.suppress(Exception):
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            san_uris = [str(u) for u in san_ext.get_values_for_type(x509_mod.UniformResourceIdentifier)]
            san_dns = [str(d) for d in san_ext.get_values_for_type(x509_mod.DNSName)]
            san_emails = [str(e) for e in san_ext.get_values_for_type(x509_mod.RFC822Name)]

        spiffe_uri = next((u for u in san_uris if u.lower().startswith("spiffe://")), None)
        _, spiffe_ns, spiffe_sa = _parse_spiffe_uri(spiffe_uri) if spiffe_uri else (None, None, None)

        agent_candidates = {
            "cn": cn,
            "san_uri": san_uris[0] if san_uris else None,
            "san_email": san_emails[0] if san_emails else None,
            "spiffe_sa": spiffe_sa,
        }
        agent_id = agent_candidates.get(self.config.agent_id_source) or cn or spiffe_sa or (
            san_uris[0] if san_uris else None
        )
        if not agent_id:
            raise MCPAuthError("Client X.509 certificate missing subject identifier", status_code=401)

        role_candidates = {
            "ou": ou,
            "san_uri": spiffe_uri or (san_uris[0] if san_uris else None),
            "cn": cn,
            "spiffe_sa": spiffe_sa,
            "static_map": cn or spiffe_uri or ou,
        }
        raw_role = role_candidates.get(self.config.role_source)
        role = _resolve_role_value(
            raw_role,
            role_mapping=self.config.role_mapping,
            role_priority=(),
            default_role=self._default_role,
        )
        if not role:
            if allow_missing_role:
                role = ""
            else:
                raise MCPAuthError(
                    f"Client X.509 certificate does not map to an authorized role (source={self.config.role_source})",
                    status_code=403,
                    error_code="insufficient_role",
                )

        tenant_candidates = {
            "o": org,
            "ou": ou,
            "spiffe_ns": spiffe_ns,
            "san_dns": san_dns[0] if san_dns else None,
            "cn": cn,
            "static_map": org or spiffe_ns or cn,
        }
        raw_tenant = tenant_candidates.get(self.config.tenant_source)
        if raw_tenant and self.config.tenant_mapping:
            tenant_id = self.config.tenant_mapping.get(raw_tenant)
        else:
            tenant_id = raw_tenant
        if not tenant_id:
            tenant_id = self._default_tenant
        if self._require_tenant and not tenant_id and not allow_missing_tenant:
            raise MCPAuthError(
                f"Client X.509 certificate missing tenant mapping (source={self.config.tenant_source})",
                status_code=403,
                error_code="missing_tenant",
            )

        thumbprint = _compute_cert_thumbprint_s256(cert, hashes_mod)
        return CallerIdentity(
            agent_id=agent_id,
            role=role,
            tenant_id=tenant_id,
            auth_method="mtls",
            scopes=(),
            cert_thumbprint_sha256=thumbprint,
            verified=True,
        )
