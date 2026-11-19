# src/uniconn/security/url_validation.py
"""Единый валидатор исходящих HTTP/HTTPS URL с защитой от SSRF (OPA, Webhooks, Dashboard)."""

from __future__ import annotations

import ipaddress
import re
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

_METADATA_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)

_LOCAL_HOSTNAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*)$", re.IGNORECASE)


def _parse_nonstandard_ipv4(hostname: str) -> ipaddress.IPv4Address | None:
    """Распознать нестандартные формы IPv4 (десятичную, hex, octal, сокращённую 127.1)."""
    if ":" in hostname:
        return None
    parts = hostname.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    if not all(_NUMERIC_LABEL_RE.fullmatch(part) for part in parts):
        return None
    try:
        vals: list[int] = []
        for part in parts:
            if part.lower().startswith("0x"):
                vals.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                vals.append(int(part, 8))
            else:
                vals.append(int(part, 10))
        if len(vals) == 1:
            addr_int = vals[0]
        elif len(vals) == 2:
            if vals[0] > 0xFF or vals[1] > 0xFFFFFF:
                return None
            addr_int = (vals[0] << 24) | vals[1]
        elif len(vals) == 3:
            if vals[0] > 0xFF or vals[1] > 0xFF or vals[2] > 0xFFFF:
                return None
            addr_int = (vals[0] << 24) | (vals[1] << 16) | vals[2]
        else:
            if any(v > 0xFF for v in vals):
                return None
            addr_int = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]
        if 0 <= addr_int <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(addr_int)
    except ValueError:
        return None
    return None


def _is_metadata_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Проверить, относится ли IP к известным облачным metadata-диапазонам (AWS/GCP/Azure/Alibaba)."""
    return any(ip_obj in net for net in _METADATA_NETWORKS)


def _validate_ip_address(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private_network: bool,
    allow_metadata: bool,
    context_host: str,
) -> None:
    """Проверить IPv4/IPv6-адрес (включая IPv4-mapped IPv6) на принадлежность к запрещённым сетям."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        embedded_v4: list[ipaddress.IPv4Address] = []
        if ip_obj.ipv4_mapped is not None:
            embedded_v4.append(ip_obj.ipv4_mapped)
        if ip_obj.sixtofour is not None:
            embedded_v4.append(ip_obj.sixtofour)
        if ip_obj.teredo is not None:
            embedded_v4.extend(ip_obj.teredo)
        for v4 in embedded_v4:
            _validate_ip_address(
                v4,
                allow_private_network=allow_private_network,
                allow_metadata=allow_metadata,
                context_host=context_host,
            )

    if not allow_metadata and (ip_obj.is_link_local or ip_obj.is_unspecified or _is_metadata_ip(ip_obj)):
        raise ConfigurationError(
            f"Outbound URL target {context_host!r} resolves to blocked link-local/metadata or unspecified IP {ip_obj}"
        )

    if not allow_private_network and (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or not ip_obj.is_global
        or _is_metadata_ip(ip_obj)
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

    literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = _parse_nonstandard_ipv4(hostname)

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
        except socket.gaierror as exc:
            raise ConfigurationError(
                f"Failed to resolve outbound URL hostname {hostname!r}: {exc}"
            ) from exc
        if not addr_infos:
            raise ConfigurationError(f"Outbound URL hostname {hostname!r} resolved to no IP addresses")
        validated_any = False
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
            validated_any = True
        if not validated_any:
            raise ConfigurationError(f"Outbound URL hostname {hostname!r} resolved to no valid IP addresses")

    return cleaned


class _SSRFValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Обработчик HTTP-редиректов, проверяющий каждый целевой URL (или запрещающий редиректы)."""

    def __init__(
        self,
        *,
        allow_private_network: bool,
        allow_metadata: bool,
        allow_redirects: bool = True,
    ) -> None:
        self._allow_private_network = allow_private_network
        self._allow_metadata = allow_metadata
        self._allow_redirects = allow_redirects

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not self._allow_redirects:
            raise ConfigurationError(f"HTTP redirect ({code}) to {newurl!r} is blocked by SSRF policy")
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
    allow_redirects: bool = True,
) -> urllib.request.OpenerDirector:
    """Создать ``OpenerDirector`` для ``urllib.request``, проверяющий или запрещающий редиректы."""
    return urllib.request.build_opener(
        _SSRFValidatingRedirectHandler(
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
            allow_redirects=allow_redirects,
        )
    )


__all__ = [
    "build_ssrf_safe_opener",
    "validate_outbound_url",
]
