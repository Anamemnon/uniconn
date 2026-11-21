# tests/unit/mcp/test_mcp_http_transport.py
"""Unit-тесты сетевого MCP Streamable HTTP / SSE шлюза (POST/GET/DELETE /mcp, RFC 9728, сессии, DNS-rebinding)."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from uniconn.mcp import (
    MCPAuthConfig,
    MCPHostRegistry,
    MCPHttpConfig,
    MCPSecurityPolicy,
    MCPServer,
    OAuth2OIDCConfig,
)


def _generate_rsa_pair() -> tuple[Any, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, pub_pem


def _sign_token(
    private_key: Any,
    *,
    sub: str = "agent-http",
    role: str = "operator",
    tenant_id: str = "acme",
    scope: str = "mcp:read mcp:exec",
    aud: str = "https://mcp.example.com/mcp",
    iss: str = "https://idp.example.com",
    exp_delta_seconds: int = 300,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": sub,
        "role": role,
        "tenant_id": tenant_id,
        "scope": scope,
        "aud": aud,
        "iss": iss,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=exp_delta_seconds)).timestamp()),
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def _build_test_server_and_app(
    *,
    pub_pem: str,
    http_config: MCPHttpConfig | None = None,
    required_scopes: tuple[str, ...] = (),
) -> tuple[MCPServer, Any]:
    policy = MCPSecurityPolicy(allow_write=False, allow_sudo=False)
    reg = MCPHostRegistry.from_dict(
        {
            "hosts": {
                "acme-web-01": {"transport": "local", "tenant": "acme", "groups": ["web"]},
                "globex-db-01": {"transport": "local", "tenant": "globex", "groups": ["db"]},
            }
        },
        policy=policy,
    )
    auth_cfg = MCPAuthConfig(
        mode="oauth2",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.example.com",
            audience="https://mcp.example.com/mcp",
            static_public_key_pem=pub_pem,
            required_scopes=required_scopes,
            resource_url="https://mcp.example.com/mcp",
            scopes_supported=("mcp:read", "mcp:exec"),
        ),
        require_tenant=True,
    )
    server = MCPServer(registry=reg, auth_config=auth_cfg, http_config=http_config)
    app = server.build_http_app()
    return server, app


@pytest.mark.asyncio
async def test_streamable_http_full_lifecycle_json_sse_notifications_and_delete() -> None:
    """Полный цикл Streamable HTTP: initialize -> Mcp-Session-Id -> JSON/SSE POST -> 202 notify -> DELETE 204."""
    priv, pub_pem = _generate_rsa_pair()
    token = _sign_token(priv)
    _, app = _build_test_server_and_app(pub_pem=pub_pem)
    headers = {"Authorization": f"Bearer {token}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. RFC 9728 Protected Resource Metadata (public endpoint)
        meta_resp = await client.get("/.well-known/oauth-protected-resource")
        assert meta_resp.status_code == 200
        meta = meta_resp.json()
        assert meta["resource"] == "https://mcp.example.com/mcp"
        assert meta["authorization_servers"] == ["https://idp.example.com"]
        assert meta["bearer_methods_supported"] == ["header"]
        assert meta["scopes_supported"] == ["mcp:read", "mcp:exec"]

        # 2. Calling POST without session before initialize fails with 400
        no_sid = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
        )
        assert no_sid.status_code == 400

        # 3. initialize returns Mcp-Session-Id & MCP-Protocol-Version
        init_resp = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        assert init_resp.status_code == 200
        sid = init_resp.headers.get("Mcp-Session-Id")
        assert sid and len(sid) >= 16
        assert init_resp.headers.get("MCP-Protocol-Version") == "2025-03-26"
        assert init_resp.json()["result"]["protocolVersion"] == "2025-03-26"

        # 4. JSON-RPC notification returns 202 Accepted with empty body
        notif_resp = await client.post(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert notif_resp.status_code == 202
        assert notif_resp.content == b""

        # 5. JSON-RPC tools/call with JSON response
        call_resp = await client.post(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid},
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "uniconn_list_hosts", "arguments": {}},
            },
        )
        assert call_resp.status_code == 200
        tool_data = json.loads(call_resp.json()["result"]["content"][0]["text"])
        assert [h["name"] for h in tool_data["hosts"]] == ["acme-web-01"]

        # 6. JSON-RPC POST with Accept: text/event-stream returns SSE frame
        sse_post = await client.post(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid, "Accept": "text/event-stream"},
            json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
        )
        assert sse_post.status_code == 200
        assert "text/event-stream" in sse_post.headers["content-type"]
        body_text = sse_post.text
        assert "event: message" in body_text
        data_lines = [line[6:] for line in body_text.splitlines() if line.startswith("data: ")]
        assert len(data_lines) == 1
        assert json.loads(data_lines[0]) == {"jsonrpc": "2.0", "id": 3, "result": {}}

        # 7. JSON-RPC batch request
        batch_resp = await client.post(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid},
            json=[
                {"jsonrpc": "2.0", "id": 10, "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/ping"},
                {"jsonrpc": "2.0", "id": 11, "method": "tools/list"},
            ],
        )
        assert batch_resp.status_code == 200
        batch_data = batch_resp.json()
        assert isinstance(batch_data, list)
        assert len(batch_data) == 2
        assert {item["id"] for item in batch_data} == {10, 11}

        # 8. DELETE closes session (204), subsequent POST returns 404
        del_resp = await client.delete("/mcp", headers={**headers, "Mcp-Session-Id": sid})
        assert del_resp.status_code == 204
        after_del = await client.post(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid},
            json={"jsonrpc": "2.0", "id": 12, "method": "ping"},
        )
        assert after_del.status_code == 404


@pytest.mark.asyncio
async def test_streamable_http_get_sse_push_and_keepalive() -> None:
    """GET /mcp открывает SSE-поток, доставляет push-уведомления и закрывается при DELETE сессии."""
    priv, pub_pem = _generate_rsa_pair()
    token = _sign_token(priv)
    _, app = _build_test_server_and_app(
        pub_pem=pub_pem,
        http_config=MCPHttpConfig(sse_keepalive_seconds=0.2),
    )
    headers = {"Authorization": f"Bearer {token}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        init_resp = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        sid = init_resp.headers["Mcp-Session-Id"]

        # Reject GET without Accept: text/event-stream
        bad_accept = await client.get(
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid, "Accept": "application/json"},
        )
        assert bad_accept.status_code == 406

        # Push an event and close session after a short delay while SSE stream is open
        async def _push_and_close() -> None:
            await asyncio.sleep(0.05)
            delivered = app.state.session_manager.publish_event(
                sid,
                {"jsonrpc": "2.0", "method": "notifications/message", "params": {"info": "hello"}},
            )
            assert delivered == 1
            await asyncio.sleep(0.05)
            await client.delete("/mcp", headers={**headers, "Mcp-Session-Id": sid})

        pusher = asyncio.create_task(_push_and_close())
        chunks: list[str] = []
        async with client.stream(
            "GET",
            "/mcp",
            headers={**headers, "Mcp-Session-Id": sid, "Accept": "text/event-stream"},
        ) as stream_resp:
            assert stream_resp.status_code == 200
            async for line in stream_resp.aiter_lines():
                chunks.append(line)
        await pusher

        joined = "\n".join(chunks)
        assert ": connected" in joined
        assert "notifications/message" in joined


@pytest.mark.asyncio
async def test_streamable_http_dns_rebinding_size_limit_stateless_and_quotas() -> None:
    """Проверка защиты от DNS-rebinding (Origin/Host), лимита тела 413, квот 429 и stateless-режима."""
    priv, pub_pem = _generate_rsa_pair()
    token = _sign_token(priv)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Anti-DNS-rebinding Origin & Host, payload size limit 413, session quota 429, idle TTL 404
    _, app = _build_test_server_and_app(
        pub_pem=pub_pem,
        http_config=MCPHttpConfig(
            host="127.0.0.1",
            allowed_origins=("https://trusted.corp.internal",),
            max_request_bytes=1024,
            max_sessions_per_tenant=1,
            session_ttl_seconds=60.0,
        ),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # Evil Origin -> 403
        bad_origin = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://evil.attacker.tld"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert bad_origin.status_code == 403

        # Evil Host on loopback bind -> 403
        bad_host = await client.post(
            "/mcp",
            headers={**headers, "Host": "evil.rebind.tld:8080"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert bad_host.status_code == 403

        # Oversized body -> 413
        big_resp = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://trusted.corp.internal"},
            content=("x" * 2048).encode("utf-8"),
        )
        assert big_resp.status_code == 413

        # Invalid JSON -> 400 with JSON-RPC -32700
        bad_json = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://trusted.corp.internal"},
            content=b"{not-valid-json",
        )
        assert bad_json.status_code == 400
        assert bad_json.json()["error"]["code"] == -32700

        # Valid initialize #1 succeeds
        ok_init = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://trusted.corp.internal"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert ok_init.status_code == 200
        sid = ok_init.headers["Mcp-Session-Id"]

        # Quota exceeded (max_sessions_per_tenant=1) -> 429
        quota_resp = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://trusted.corp.internal"},
            json={"jsonrpc": "2.0", "id": 2, "method": "initialize"},
        )
        assert quota_resp.status_code == 429

        # Expire session via idle TTL -> 404
        app.state.session_manager._sessions[sid].last_seen = time.monotonic() - 120.0
        expired_resp = await client.post(
            "/mcp",
            headers={**headers, "Origin": "https://trusted.corp.internal", "Mcp-Session-Id": sid},
            json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
        )
        assert expired_resp.status_code == 404

    # 2. Stateless mode works without Mcp-Session-Id; GET/DELETE return 405
    _, stateless_app = _build_test_server_and_app(
        pub_pem=pub_pem,
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=stateless_app),
        base_url="http://testserver",
    ) as client:
        ping_resp = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert ping_resp.status_code == 200
        assert "Mcp-Session-Id" not in ping_resp.headers
        assert (await client.get("/mcp", headers={**headers, "Accept": "text/event-stream"})).status_code == 405
        assert (await client.delete("/mcp", headers=headers)).status_code == 405


@pytest.mark.asyncio
async def test_session_cert_thumbprint_binding_global_cap_full_queue_close_and_proto_negotiation() -> None:
    """Проверка привязки сессии к cert_thumbprint, глобальной квоты, закрытия полной SSE-очереди и protocolVersion."""
    from uniconn.mcp.auth import CallerIdentity
    from uniconn.mcp.sessions import (
        MCPSessionForbiddenError,
        MCPSessionLimitError,
        MCPSessionManager,
    )

    mgr = MCPSessionManager(ttl_seconds=60.0, max_sessions_per_tenant=5, max_total_sessions=2)
    id_cert1 = CallerIdentity(
        agent_id="bot-1",
        role="operator",
        tenant_id="acme",
        auth_method="mtls",
        cert_thumbprint_sha256="thumbprint-aaa",
        verified=True,
    )
    id_cert2 = id_cert1.model_copy(update={"cert_thumbprint_sha256": "thumbprint-bbb"})

    sess1 = mgr.create_session(id_cert1, protocol_version="2025-03-26")
    assert mgr.validate_session(sess1.session_id, id_cert1).session_id == sess1.session_id
    with pytest.raises(MCPSessionForbiddenError):
        mgr.validate_session(sess1.session_id, id_cert2)

    # Full SSE queue still receives None close sentinel on close_session()
    full_q = mgr.subscribe_sse(sess1, max_queue_size=1)
    assert mgr.publish_event(sess1.session_id, {"jsonrpc": "2.0", "method": "notifications/test"}) == 1
    assert full_q.full()
    mgr.close_session(sess1.session_id, id_cert1)
    assert full_q.get_nowait() is None

    # Global max_total_sessions cap across tenants
    id_t1 = CallerIdentity(agent_id="a", role="operator", tenant_id="t1", auth_method="oauth2", verified=True)
    id_t2 = CallerIdentity(agent_id="b", role="operator", tenant_id="t2", auth_method="oauth2", verified=True)
    id_t3 = CallerIdentity(agent_id="c", role="operator", tenant_id="t3", auth_method="oauth2", verified=True)
    mgr.create_session(id_t1, protocol_version="2025-03-26")
    mgr.create_session(id_t2, protocol_version="2025-03-26")
    with pytest.raises(MCPSessionLimitError, match="Global"):
        mgr.create_session(id_t3, protocol_version="2025-03-26")

    # Unsupported client protocolVersion negotiates to latest supported version ("2025-03-26")
    priv, pub_pem = _generate_rsa_pair()
    token = _sign_token(priv)
    _, app = _build_test_server_and_app(pub_pem=pub_pem, http_config=MCPHttpConfig(sse_keepalive_seconds=0.15))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        init_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "1999-01-01"},
            },
        )
        assert init_resp.status_code == 200
        assert init_resp.json()["result"]["protocolVersion"] == "2025-03-26"
        assert init_resp.headers["MCP-Protocol-Version"] == "2025-03-26"
        sid = init_resp.headers["Mcp-Session-Id"]

        # Active GET /mcp SSE keepalive refreshes session.last_seen
        sess_obj = app.state.session_manager._sessions[sid]
        sess_obj.last_seen = time.monotonic() - 10.0
        old_last_seen = sess_obj.last_seen
        refreshed_last_seen: float = old_last_seen

        async def _close_after_keepalive() -> None:
            nonlocal refreshed_last_seen
            await asyncio.sleep(0.28)
            refreshed_last_seen = sess_obj.last_seen
            await client.delete(
                "/mcp",
                headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": sid},
            )

        closer = asyncio.create_task(_close_after_keepalive())
        lines: list[str] = []
        async with client.stream(
            "GET",
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
                "Mcp-Session-Id": sid,
            },
        ) as sse_resp:
            async for line in sse_resp.aiter_lines():
                lines.append(line)
        await closer
        assert ": keepalive" in lines
        assert refreshed_last_seen > old_last_seen


@pytest.mark.asyncio
async def test_uvicorn_peer_cert_h11_protocol_injects_scope_and_chunked_body_limit() -> None:
    """Проверка _PeerCertH11Protocol (инжекция peer DER в ASGI scope) и лимита chunked-тела (413)."""
    from unittest.mock import MagicMock

    import uvicorn
    from uvicorn.server import ServerState

    from uniconn.mcp.http_transport import _build_peer_cert_h11_protocol

    # 1. Verify _PeerCertH11Protocol captures peer DER on connection_made and injects into scope setter
    proto_cls = _build_peer_cert_h11_protocol()
    uv_cfg = uvicorn.Config(app=lambda scope, receive, send: None, host="127.0.0.1", port=0)
    proto = proto_cls(config=uv_cfg, server_state=ServerState(), app_state={})

    fake_der = b"\x30\x82\x01\x0aFAKE-DER-BYTES"
    fake_ssl = MagicMock()
    fake_ssl.getpeercert.return_value = fake_der
    extra_map: dict[str, Any] = {
        "ssl_object": fake_ssl,
        "peername": ("127.0.0.1", 54321),
        "sockname": ("127.0.0.1", 8443),
        "socket": None,
    }
    fake_transport = MagicMock()
    fake_transport.get_extra_info.side_effect = lambda key, default=None: extra_map.get(key, default)
    proto.connection_made(fake_transport)
    sample_scope: dict[str, Any] = {"type": "http", "path": "/mcp"}
    proto.scope = sample_scope
    assert sample_scope["client_cert_der"] == fake_der
    assert sample_scope["extensions"]["tls"]["client_cert_chain"] == (fake_der,)

    # 2. Chunked request body without Content-Length exceeding max_request_bytes -> 413
    priv, pub_pem = _generate_rsa_pair()
    token = _sign_token(priv)
    _, app = _build_test_server_and_app(
        pub_pem=pub_pem,
        http_config=MCPHttpConfig(max_request_bytes=1024, stateless_mode=True),
    )

    async def _chunked_body() -> Any:
        for _ in range(5):
            yield b"a" * 300

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            content=_chunked_body(),
        )
        assert resp.status_code == 413
        assert resp.json()["error"] == "payload_too_large"


