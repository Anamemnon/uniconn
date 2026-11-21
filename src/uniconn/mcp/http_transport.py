# src/uniconn/mcp/http_transport.py
"""Сетевой ASGI-шлюз MCP Streamable HTTP / SSE поверх Starlette и Uvicorn."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from collections.abc import AsyncIterator, Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .._logging import SecretMaskingFilter
from ..exceptions import OptionalDependencyError
from .auth import (
    CallerIdentity,
    JsonFetcher,
    MCPAuthConfig,
    MCPAuthenticator,
    MCPAuthError,
    MCPHttpConfig,
    caller_identity_context,
)
from .sessions import (
    MCPSessionError,
    MCPSessionManager,
)

if TYPE_CHECKING:
    from .server import MCPServer

_LOGGER = logging.getLogger("uniconn.mcp.http")
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1", "testserver", "test"})
_LOOPBACK_BIND_ADDRS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


def _require_http_transport_deps() -> tuple[Any, Any, Any, Any, Any, Any]:
    """Лениво загрузить Starlette и Uvicorn из опционального extra ``uniconn[mcp-http]``."""
    try:
        import uvicorn
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response, StreamingResponse
        from starlette.routing import Route
    except ImportError as exc:
        raise OptionalDependencyError(
            "Remote network MCP HTTP/SSE transport requires optional dependencies "
            "(starlette, uvicorn, PyJWT, cryptography). Install with: pip install 'uniconn[mcp-http]'"
        ) from exc
    return Starlette, Request, JSONResponse, Response, StreamingResponse, (Route, uvicorn)


def _extract_host_without_port(raw_host: str) -> str:
    host = raw_host.strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 1 else host
    if ":" in host:
        return host.split(":", 1)[0]
    return host


def _validate_host_and_origin(
    headers: Mapping[str, str],
    http_config: MCPHttpConfig,
) -> str | None:
    """Проверить заголовки ``Host`` и ``Origin`` против DNS-rebinding атак.

    Возвращает текст причины отказа или ``None``, если запрос допустим.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    raw_host = lower_headers.get("host", "").strip()
    hostname = _extract_host_without_port(raw_host)

    if http_config.allowed_hosts:
        allowed_set = {h.strip().lower() for h in http_config.allowed_hosts if h.strip()}
        if raw_host.lower() not in allowed_set and hostname not in allowed_set:
            return f"Host header {raw_host!r} is not in allowed_hosts"
    elif http_config.host.strip().lower() in _LOOPBACK_BIND_ADDRS and hostname and hostname not in _LOOPBACK_HOSTS:
        return f"Host header {raw_host!r} rejected by loopback anti-DNS-rebinding policy"

    origin = lower_headers.get("origin")
    if origin is not None and origin.strip():
        parsed = urlsplit(origin.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return f"Malformed Origin header {origin!r}"
        norm_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
        if http_config.allowed_origins:
            allowed_origins = {o.strip().rstrip("/").lower() for o in http_config.allowed_origins if o.strip()}
            if norm_origin not in allowed_origins:
                return f"Origin {norm_origin!r} is not allowed"
        elif http_config.allow_localhost_origins:
            origin_host = (parsed.hostname or "").strip().lower()
            if origin_host not in {"localhost", "127.0.0.1", "::1"}:
                return f"Cross-origin request from {norm_origin!r} is forbidden"
        else:
            return f"Origin {norm_origin!r} is forbidden (no allowed_origins configured)"

    return None


def _build_resource_metadata_url(
    request: Any,
    auth_config: MCPAuthConfig,
    http_config: MCPHttpConfig,
) -> str:
    """Построить URL документа RFC 9728 Protected Resource Metadata."""
    if auth_config.oauth2 and auth_config.oauth2.resource_url:
        parsed = urlsplit(auth_config.oauth2.resource_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource"
    base = str(request.base_url).rstrip("/")
    return f"{base}/.well-known/oauth-protected-resource"


def _build_www_authenticate(
    err: MCPAuthError,
    request: Any,
    auth_config: MCPAuthConfig,
    http_config: MCPHttpConfig,
) -> str | None:
    """Сформировать заголовок ``WWW-Authenticate`` по RFC 6750 и RFC 9728."""
    if auth_config.mode == "mtls" and auth_config.oauth2 is None:
        return None
    parts: list[str] = []
    if http_config.enable_rfc9728_metadata:
        meta_url = _build_resource_metadata_url(request, auth_config, http_config)
        parts.append(f'resource_metadata="{meta_url}"')
    if err.error_code and err.status_code == 403 and err.error_code == "insufficient_scope":
        parts.append('error="insufficient_scope"')
        if err.required_scopes:
            parts.append(f'scope="{" ".join(err.required_scopes)}"')
    elif err.status_code == 401 and err.error_code:
        parts.append(f'error="{err.error_code}"')
    return "Bearer " + ", ".join(parts) if parts else "Bearer"


def _prefers_sse_response(accept_header: str | None) -> bool:
    """Определить, запросил ли клиент ответ на ``POST /mcp`` в формате ``text/event-stream``."""
    if not accept_header:
        return False
    lower = accept_header.lower()
    return "text/event-stream" in lower and "application/json" not in lower


def _format_sse_event(data_str: str, *, event_type: str = "message", event_id: str | None = None) -> bytes:
    lines: list[str] = []
    if event_id:
        lines.append(f"id: {event_id}")
    if event_type:
        lines.append(f"event: {event_type}")
    for data_line in data_str.splitlines() or [""]:
        lines.append(f"data: {data_line}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _extract_initialized_protocol_version(response: Any, fallback: str) -> str:
    if isinstance(response, dict):
        result = response.get("result")
        if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
            return result["protocolVersion"]
    return fallback


async def _read_bounded_body(request: Any, max_bytes: int) -> bytes | None:
    """Потоково прочитать тело запроса с жёстким лимитом ``max_bytes`` (защита от chunked-DoS)."""
    buf = bytearray()
    async for chunk in request.stream():
        if not chunk:
            continue
        buf.extend(chunk)
        if len(buf) > max_bytes:
            return None
    return bytes(buf)


def _build_peer_cert_h11_protocol() -> type[Any]:
    """Создать подкласс Uvicorn ``H11Protocol``, инжектирующий peer X.509 DER в ASGI ``scope``."""
    from uvicorn.protocols.http.h11_impl import H11Protocol

    base_h11_cls: Any = H11Protocol

    class _PeerCertH11Protocol(base_h11_cls):
        def connection_made(self, transport: Any) -> None:
            super().connection_made(transport)
            ssl_obj = transport.get_extra_info("ssl_object")
            self._peer_cert_der: bytes | None = None
            if ssl_obj is not None:
                try:
                    cert_der = ssl_obj.getpeercert(binary_form=True)
                    if isinstance(cert_der, bytes) and cert_der:
                        self._peer_cert_der = cert_der
                except Exception:
                    self._peer_cert_der = None

        @property
        def scope(self) -> Any:
            return getattr(self, "_uniconn_scope", None)

        @scope.setter
        def scope(self, value: Any) -> None:
            peer_der = getattr(self, "_peer_cert_der", None)
            if peer_der and isinstance(value, dict):
                value["client_cert_der"] = peer_der
                exts = value.setdefault("extensions", {})
                if isinstance(exts, dict):
                    tls_ext = exts.setdefault("tls", {})
                    if isinstance(tls_ext, dict):
                        tls_ext["client_cert_chain"] = (peer_der,)
            self._uniconn_scope = value

    return _PeerCertH11Protocol


def build_mcp_http_app(
    server: MCPServer,
    *,
    auth_config: MCPAuthConfig,
    http_config: MCPHttpConfig | None = None,
    jwks_fetcher: JsonFetcher | None = None,
) -> Any:
    """Создать ASGI-приложение Starlette для сетевого MCP Streamable HTTP / SSE шлюза."""
    starlette_cls, _request_cls, json_resp_cls, resp_cls, streaming_resp_cls, extra_deps = (
        _require_http_transport_deps()
    )
    route_cls, _ = extra_deps
    cfg = http_config or MCPHttpConfig()
    authenticator = MCPAuthenticator(auth_config, jwks_fetcher=jwks_fetcher)
    session_manager = MCPSessionManager(
        ttl_seconds=cfg.session_ttl_seconds,
        max_sessions_per_tenant=cfg.max_sessions_per_tenant,
        max_total_sessions=cfg.max_total_sessions,
    )

    def _auth_error_response(exc: MCPAuthError, request: Any) -> Any:
        headers: dict[str, str] = {}
        www_auth = _build_www_authenticate(exc, request, auth_config, cfg)
        if www_auth:
            headers["WWW-Authenticate"] = www_auth
        return json_resp_cls(
            {
                "error": exc.error_code,
                "error_description": SecretMaskingFilter._mask_string(str(exc)),
            },
            status_code=exc.status_code,
            headers=headers,
        )

    async def _authenticate_request(request: Any) -> tuple[CallerIdentity | None, Any | None]:
        guard_err = _validate_host_and_origin(request.headers, cfg)
        if guard_err is not None:
            return None, json_resp_cls(
                {"error": "forbidden_origin", "error_description": guard_err},
                status_code=403,
            )
        try:
            identity = await authenticator.authenticate(request.scope, request.headers)
        except MCPAuthError as exc:
            return None, _auth_error_response(exc, request)
        return identity, None

    async def protected_resource_metadata(request: Any) -> Any:
        if not cfg.enable_rfc9728_metadata:
            return json_resp_cls({"error": "not_found"}, status_code=404)
        oauth2_cfg = auth_config.oauth2
        resource_val = (
            oauth2_cfg.resource_url
            if (oauth2_cfg and oauth2_cfg.resource_url)
            else f"{str(request.base_url).rstrip('/')}{cfg.mcp_path}"
        )
        auth_servers = oauth2_cfg.effective_authorization_servers() if oauth2_cfg else []
        scopes_supported = (
            list(oauth2_cfg.scopes_supported)
            if (oauth2_cfg and oauth2_cfg.scopes_supported)
            else (list(oauth2_cfg.required_scopes) if oauth2_cfg else [])
        )
        payload: dict[str, Any] = {
            "resource": resource_val,
            "authorization_servers": auth_servers,
            "bearer_methods_supported": ["header"],
        }
        if scopes_supported:
            payload["scopes_supported"] = scopes_supported
        return json_resp_cls(payload, headers={"Cache-Control": "public, max-age=300"})

    async def handle_mcp_post(request: Any) -> Any:
        identity, err_resp = await _authenticate_request(request)
        if err_resp is not None or identity is None:
            return err_resp

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > cfg.max_request_bytes:
                    return json_resp_cls(
                        {"error": "payload_too_large", "error_description": "Request body exceeds max_request_bytes"},
                        status_code=413,
                    )
            except ValueError:
                return json_resp_cls({"error": "invalid_request"}, status_code=400)

        raw_body = await _read_bounded_body(request, cfg.max_request_bytes)
        if raw_body is None:
            return json_resp_cls(
                {"error": "payload_too_large", "error_description": "Request body exceeds max_request_bytes"},
                status_code=413,
            )

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return json_resp_cls(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                },
                status_code=400,
            )

        is_initialize = isinstance(payload, dict) and payload.get("method") == "initialize"
        active_session_id: str | None = None
        active_session = None

        if not cfg.stateless_mode and not is_initialize:
            req_sid = request.headers.get("mcp-session-id")
            if not req_sid or not req_sid.strip():
                return json_resp_cls(
                    {"error": "missing_session", "error_description": "Missing Mcp-Session-Id header"},
                    status_code=400,
                )
            try:
                active_session = session_manager.validate_session(req_sid, identity)
                active_session_id = active_session.session_id
            except MCPSessionError as exc:
                return json_resp_cls(
                    {"error": "session_error", "error_description": str(exc)},
                    status_code=exc.status_code,
                )

        bound_identity = (
            identity.model_copy(update={"session_id": active_session_id})
            if active_session_id
            else identity
        )

        with caller_identity_context(bound_identity):
            rpc_response = await server.handle_message(payload)

        resp_headers: dict[str, str] = {}
        if not cfg.stateless_mode and is_initialize and isinstance(rpc_response, dict) and "result" in rpc_response:
            proto_ver = _extract_initialized_protocol_version(rpc_response, "2025-03-26")
            try:
                active_session = session_manager.create_session(identity, protocol_version=proto_ver)
            except MCPSessionError as exc:
                return json_resp_cls(
                    {"error": "session_limit_exceeded", "error_description": str(exc)},
                    status_code=exc.status_code,
                )
            active_session_id = active_session.session_id
            resp_headers["Mcp-Session-Id"] = active_session_id
            resp_headers["MCP-Protocol-Version"] = proto_ver
        elif active_session is not None:
            resp_headers["Mcp-Session-Id"] = active_session.session_id
            resp_headers["MCP-Protocol-Version"] = active_session.protocol_version

        if rpc_response is None:
            return resp_cls(status_code=202, headers=resp_headers)

        if _prefers_sse_response(request.headers.get("accept")):
            serialized = json.dumps(rpc_response, ensure_ascii=False)
            ev_id = active_session.next_event_id() if active_session is not None else "1"

            async def _single_sse_gen() -> AsyncIterator[bytes]:
                yield _format_sse_event(serialized, event_type="message", event_id=ev_id)

            sse_headers = {
                **resp_headers,
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            }
            return streaming_resp_cls(_single_sse_gen(), media_type="text/event-stream", headers=sse_headers)

        return json_resp_cls(rpc_response, headers=resp_headers)

    async def handle_mcp_get_sse(request: Any) -> Any:
        identity, err_resp = await _authenticate_request(request)
        if err_resp is not None or identity is None:
            return err_resp

        if cfg.stateless_mode:
            return json_resp_cls(
                {"error": "method_not_allowed", "error_description": "SSE stream disabled in stateless mode"},
                status_code=405,
            )

        accept = (request.headers.get("accept") or "").lower()
        if "text/event-stream" not in accept and "*/*" not in accept:
            return json_resp_cls(
                {"error": "not_acceptable", "error_description": "GET SSE requires Accept: text/event-stream"},
                status_code=406,
            )

        req_sid = request.headers.get("mcp-session-id")
        if not req_sid or not req_sid.strip():
            return json_resp_cls(
                {"error": "missing_session", "error_description": "Missing Mcp-Session-Id header"},
                status_code=400,
            )
        try:
            session = session_manager.validate_session(req_sid, identity)
        except MCPSessionError as exc:
            return json_resp_cls(
                {"error": "session_error", "error_description": str(exc)},
                status_code=exc.status_code,
            )

        queue = session_manager.subscribe_sse(session)

        async def _sse_stream() -> AsyncIterator[bytes]:
            try:
                yield b": connected\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=cfg.sse_keepalive_seconds)
                    except TimeoutError:
                        if not session_manager.touch_session(session.session_id):
                            break
                        yield b": keepalive\n\n"
                        continue
                    if item is None:
                        break
                    session_manager.touch_session(session.session_id)
                    ev_id, ev_type, data_str = item
                    yield _format_sse_event(data_str, event_type=ev_type, event_id=ev_id)
            except asyncio.CancelledError:
                return
            finally:
                session_manager.unsubscribe_sse(session, queue)

        return streaming_resp_cls(
            _sse_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Mcp-Session-Id": session.session_id,
                "X-Accel-Buffering": "no",
            },
        )

    async def handle_mcp_delete(request: Any) -> Any:
        identity, err_resp = await _authenticate_request(request)
        if err_resp is not None or identity is None:
            return err_resp

        if cfg.stateless_mode:
            return json_resp_cls(
                {"error": "method_not_allowed", "error_description": "Sessions disabled in stateless mode"},
                status_code=405,
            )

        req_sid = request.headers.get("mcp-session-id")
        if not req_sid or not req_sid.strip():
            return json_resp_cls(
                {"error": "missing_session", "error_description": "Missing Mcp-Session-Id header"},
                status_code=400,
            )
        try:
            session_manager.close_session(req_sid, identity)
        except MCPSessionError as exc:
            return json_resp_cls(
                {"error": "session_error", "error_description": str(exc)},
                status_code=exc.status_code,
            )
        return resp_cls(status_code=204)

    async def mcp_endpoint(request: Any) -> Any:
        if request.method == "POST":
            return await handle_mcp_post(request)
        if request.method == "GET":
            return await handle_mcp_get_sse(request)
        if request.method == "DELETE":
            return await handle_mcp_delete(request)
        return resp_cls(status_code=405)

    routes = [
        route_cls(cfg.mcp_path, mcp_endpoint, methods=["POST", "GET", "DELETE"]),
        route_cls("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
        route_cls(
            f"/.well-known/oauth-protected-resource{cfg.mcp_path}",
            protected_resource_metadata,
            methods=["GET"],
        ),
    ]
    app = starlette_cls(debug=False, routes=routes)
    app.state.mcp_server = server
    app.state.session_manager = session_manager
    app.state.authenticator = authenticator
    app.state.auth_config = auth_config
    app.state.http_config = cfg
    return app


async def serve_mcp_http(
    server: MCPServer,
    *,
    auth_config: MCPAuthConfig,
    http_config: MCPHttpConfig | None = None,
    jwks_fetcher: JsonFetcher | None = None,
) -> None:
    """Запустить сетевой MCP Streamable HTTP / SSE сервер через Uvicorn (с поддержкой TLS/mTLS)."""
    _, _, _, _, _, (_, uvicorn) = _require_http_transport_deps()
    cfg = http_config or MCPHttpConfig()
    app = build_mcp_http_app(
        server,
        auth_config=auth_config,
        http_config=cfg,
        jwks_fetcher=jwks_fetcher,
    )

    ca_certs = cfg.tls_client_ca_path or (auth_config.mtls.ca_cert_path if auth_config.mtls else None)
    ssl_cert_reqs = ssl.CERT_NONE
    if ca_certs and cfg.tls_cert_path:
        if auth_config.mode in ("mtls", "both"):
            ssl_cert_reqs = ssl.CERT_REQUIRED
        elif auth_config.mode == "either":
            ssl_cert_reqs = ssl.CERT_OPTIONAL

    uvicorn_kwargs: dict[str, Any] = {
        "host": cfg.host,
        "port": cfg.port,
        "log_level": "warning",
    }
    if cfg.tls_cert_path and cfg.tls_key_path:
        uvicorn_kwargs["ssl_certfile"] = cfg.tls_cert_path
        uvicorn_kwargs["ssl_keyfile"] = cfg.tls_key_path
        if ca_certs:
            uvicorn_kwargs["ssl_ca_certs"] = ca_certs
            uvicorn_kwargs["ssl_cert_reqs"] = ssl_cert_reqs

    # Подключаем перехват peer DER-сертификата на уровне h11-протокола при активном mTLS
    if ssl_cert_reqs != ssl.CERT_NONE:
        try:
            uvicorn_kwargs["http"] = _build_peer_cert_h11_protocol()
        except Exception as exc:
            _LOGGER.debug("Falling back to default Uvicorn HTTP protocol: %s", exc)

    uv_config = uvicorn.Config(app, **uvicorn_kwargs)
    uv_server = uvicorn.Server(uv_config)
    await uv_server.serve()


__all__ = [
    "build_mcp_http_app",
    "serve_mcp_http",
]
