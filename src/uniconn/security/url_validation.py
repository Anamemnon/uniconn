# src/uniconn/security/url_validation.py
"""Единый валидатор исходящих HTTP/HTTPS URL с защитой от SSRF (OPA, Webhooks, Dashboard)."""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..exceptions import ConfigurationError

_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.internal",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

_LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


def _validate_ip_address(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private_network: bool,
    allow_metadata: bool,
    context_host: str,
) -> None:
    """Проверить IPv4/IPv6-адрес (включая IPv4-mapped IPv6) на принадлежность к запрещённым сетям."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        _validate_ip_address(
            ip_obj.ipv4_mapped,
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
            context_host=context_host,
        )

    if not allow_metadata and (ip_obj.is_link_local or ip_obj.is_unspecified):
        raise ConfigurationError(
            f"Outbound URL target {context_host!r} resolves to blocked link-local or unspecified IP {ip_obj}"
        )

    if not allow_private_network and (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    ):
        raise ConfigurationError(
            f"Outbound URL target {context_host!r} points to restricted loopback/private/reserved IP {ip_obj}"
        )


def validate_outbound_url(
    url: str,
    *,
    allow_private_network: bool = False,
    resolve_dns: bool = False,
    allow_metadata: bool = False,
) -> str:
    """Проверить исходящий URL (HTTP/HTTPS) на соответствие политике защиты от SSRF.

    Args:
        url: Целевой URL.
        allow_private_network: Разрешить loopback (``127.0.0.1``, ``localhost``) и RFC1918 адреса.
        resolve_dns: Разрешать ли DNS-имя через ``socket.getaddrinfo`` для защиты от DNS-rebinding.
        allow_metadata: Разрешить ли link-local / cloud metadata адреса (по умолчанию запрещены всегда).

    Returns:
        Нормализованный исходный URL (stripped).

    Raises:
        ConfigurationError: При недопустимой схеме, некорректном хосте/порте или запрещённом IP.

    """
    if not isinstance(url, str) or not url.strip():
        raise ConfigurationError("Outbound URL must be a non-empty string")
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ConfigurationError(f"Unsupported outbound URL scheme {parsed.scheme!r}: only http/https allowed")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ConfigurationError(f"Outbound URL {cleaned!r} must include a valid hostname")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError(f"Outbound URL {cleaned!r} has invalid port: {exc}") from exc

    if not allow_metadata and hostname in _METADATA_HOSTNAMES:
        raise ConfigurationError(f"Outbound URL to cloud metadata endpoint {hostname!r} is blocked")

    if not allow_private_network and (
        hostname in _LOCAL_HOSTNAMES or hostname.endswith((".localhost", ".local"))
    ):
        raise ConfigurationError(f"Outbound URL to local hostname {hostname!r} is blocked (SSRF guard)")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        _validate_ip_address(
            literal_ip,
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
            context_host=hostname,
        )
    elif resolve_dns:
        eff_port = port if port is not None else (443 if scheme == "https" else 80)
        try:
            addr_infos = socket.getaddrinfo(hostname, eff_port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            addr_infos = []
        for _fam, _kind, _proto, _canon, sockaddr in addr_infos:
            if not sockaddr:
                continue
            raw_ip = str(sockaddr[0]).split("%", 1)[0]
            try:
                resolved_ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            _validate_ip_address(
                resolved_ip,
                allow_private_network=allow_private_network,
                allow_metadata=allow_metadata,
                context_host=hostname,
            )

    return cleaned


class _SSRFValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Обработчик HTTP-редиректов, проверяющий каждый целевой URL перед переходом."""

    def __init__(self, *, allow_private_network: bool, allow_metadata: bool) -> None:
        self._allow_private_network = allow_private_network
        self._allow_metadata = allow_metadata

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        validate_outbound_url(
            newurl,
            allow_private_network=self._allow_private_network,
            resolve_dns=True,
            allow_metadata=self._allow_metadata,
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_ssrf_safe_opener(
    *,
    allow_private_network: bool = False,
    allow_metadata: bool = False,
) -> urllib.request.OpenerDirector:
    """Создать ``OpenerDirector`` для ``urllib.request``, проверяющий редиректы на SSRF."""
    return urllib.request.build_opener(
        _SSRFValidatingRedirectHandler(
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
        )
    )


__all__ = [
    "build_ssrf_safe_opener",
    "validate_outbound_url",
]
