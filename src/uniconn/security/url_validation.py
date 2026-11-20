# src/uniconn/security/url_validation.py
"""Единый валидатор исходящих HTTP/HTTPS URL с защитой от SSRF (OPA, Webhooks, Dashboard)."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
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


def _resolve_and_validate(
    url: str,
    *,
    allow_private_network: bool = False,
    resolve_dns: bool = False,
    allow_metadata: bool = False,
) -> tuple[str, str, str | None]:
    """Провалидировать URL и при ``resolve_dns=True`` вернуть ``(cleaned_url, hostname, pinned_ip)``."""
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

    pinned_ip: str | None = None
    if literal_ip is not None:
        _validate_ip_address(
            literal_ip,
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
            context_host=hostname,
        )
        pinned_ip = str(literal_ip)
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
        validated_ips: list[str] = []
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
            validated_ips.append(str(resolved_ip))
        if not validated_ips:
            raise ConfigurationError(f"Outbound URL hostname {hostname!r} resolved to no valid IP addresses")
        pinned_ip = validated_ips[0]

    return cleaned, hostname, pinned_ip


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
    cleaned, _, _ = _resolve_and_validate(
        url,
        allow_private_network=allow_private_network,
        resolve_dns=resolve_dns,
        allow_metadata=allow_metadata,
    )
    return cleaned


def resolve_and_validate_outbound_url(
    url: str,
    *,
    allow_private_network: bool = False,
    allow_metadata: bool = False,
) -> tuple[str, str, str]:
    """Провалидировать URL с DNS-резолвом и вернуть ``(url, hostname, pinned_ip)`` для защиты от TOCTOU."""
    cleaned, hostname, pinned_ip = _resolve_and_validate(
        url,
        allow_private_network=allow_private_network,
        resolve_dns=True,
        allow_metadata=allow_metadata,
    )
    if not pinned_ip:
        raise ConfigurationError(f"Outbound URL hostname {hostname!r} resolved to no valid IP addresses")
    return cleaned, hostname, pinned_ip


def _open_pinned_socket(
    conn: http.client.HTTPConnection,
    pinned_ips: dict[str, str],
    scheme_label: str,
) -> socket.socket:
    """Открыть TCP-сокет строго к провалидированному IP-адресу из карты ``pinned_ips``."""
    norm_host = (conn.host or "").strip().strip("[]").lower().rstrip(".")
    target_ip = pinned_ips.get(norm_host)
    if target_ip is None:
        raise ConfigurationError(f"Refusing unpinned {scheme_label} connection to {conn.host!r}")
    source_addr: tuple[str, int] | None = getattr(conn, "source_address", None)
    return socket.create_connection((target_ip, conn.port), conn.timeout, source_addr)


def _make_pinned_http_connection_cls(pinned_ips: dict[str, str]) -> type[http.client.HTTPConnection]:
    """Создать класс ``HTTPConnection``, подключающийся строго к провалидированному IP-адресу."""

    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            self.sock = _open_pinned_socket(self, pinned_ips, "HTTP")
            tunnel_host = getattr(self, "_tunnel_host", None)
            if tunnel_host:
                tunnel_fn = getattr(self, "_tunnel", None)
                if callable(tunnel_fn):
                    tunnel_fn()

    return _PinnedHTTPConnection


def _make_pinned_https_connection_cls(pinned_ips: dict[str, str]) -> type[http.client.HTTPSConnection]:
    """Создать класс ``HTTPSConnection`` с привязкой TCP к провалидированному IP и TLS SNI по исходному имени."""

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            sock = _open_pinned_socket(self, pinned_ips, "HTTPS")
            tunnel_host: str | None = getattr(self, "_tunnel_host", None)
            if tunnel_host:
                self.sock = sock
                tunnel_fn = getattr(self, "_tunnel", None)
                if callable(tunnel_fn):
                    tunnel_fn()
                server_hostname = tunnel_host
            else:
                server_hostname = self.host
            ctx: ssl.SSLContext = getattr(self, "_context", None) or ssl.create_default_context()
            self.sock = ctx.wrap_socket(sock, server_hostname=server_hostname)

    return _PinnedHTTPSConnection


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    """HTTPHandler с привязкой TCP-сокета к провалидированным IP-адресам."""

    def __init__(self, pinned_ips: dict[str, str]) -> None:
        super().__init__()
        self._conn_cls = _make_pinned_http_connection_cls(pinned_ips)

    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(self._conn_cls, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler с привязкой TCP-сокета к провалидированным IP и сохранением TLS SNI."""

    def __init__(self, pinned_ips: dict[str, str]) -> None:
        super().__init__()
        self._conn_cls = _make_pinned_https_connection_cls(pinned_ips)

    def https_open(self, req: urllib.request.Request) -> Any:
        ctx = getattr(self, "_context", None)
        return self.do_open(self._conn_cls, req, context=ctx)


class _SSRFValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Обработчик HTTP-редиректов, проверяющий каждый целевой URL (или запрещающий редиректы)."""

    def __init__(
        self,
        *,
        allow_private_network: bool,
        allow_metadata: bool,
        allow_redirects: bool = True,
        pinned_ips: dict[str, str] | None = None,
    ) -> None:
        self._allow_private_network = allow_private_network
        self._allow_metadata = allow_metadata
        self._allow_redirects = allow_redirects
        self._pinned_ips = pinned_ips

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
        _, new_host, new_ip = resolve_and_validate_outbound_url(
            newurl,
            allow_private_network=self._allow_private_network,
            allow_metadata=self._allow_metadata,
        )
        if self._pinned_ips is not None:
            self._pinned_ips[new_host] = new_ip
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_ssrf_safe_opener(
    *,
    allow_private_network: bool = False,
    allow_metadata: bool = False,
    allow_redirects: bool = True,
    pinned_ips: dict[str, str] | None = None,
) -> urllib.request.OpenerDirector:
    """Создать ``OpenerDirector`` для ``urllib.request``, проверяющий редиректы и (опционально) пиннингующий IP."""
    handlers: list[Any] = [
        _SSRFValidatingRedirectHandler(
            allow_private_network=allow_private_network,
            allow_metadata=allow_metadata,
            allow_redirects=allow_redirects,
            pinned_ips=pinned_ips,
        )
    ]
    if pinned_ips is not None:
        handlers.append(_PinnedHTTPHandler(pinned_ips))
        handlers.append(_PinnedHTTPSHandler(pinned_ips))
    return urllib.request.build_opener(*handlers)


def open_ssrf_safe_url(
    req: urllib.request.Request,
    *,
    timeout: float,
    allow_private_network: bool = False,
    allow_metadata: bool = False,
    allow_redirects: bool = False,
) -> Any:
    """Выполнить HTTP/HTTPS-запрос с однократным DNS-резолвом и жёсткой привязкой сокета к IP (anti-TOCTOU)."""
    _, hostname, pinned_ip = resolve_and_validate_outbound_url(
        req.full_url,
        allow_private_network=allow_private_network,
        allow_metadata=allow_metadata,
    )
    pinned_map: dict[str, str] = {hostname: pinned_ip}
    opener = build_ssrf_safe_opener(
        allow_private_network=allow_private_network,
        allow_metadata=allow_metadata,
        allow_redirects=allow_redirects,
        pinned_ips=pinned_map,
    )
    return opener.open(req, timeout=timeout)


__all__ = [
    "build_ssrf_safe_opener",
    "open_ssrf_safe_url",
    "resolve_and_validate_outbound_url",
    "validate_outbound_url",
]
