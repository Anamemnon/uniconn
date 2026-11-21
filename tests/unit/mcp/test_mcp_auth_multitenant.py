# tests/unit/mcp/test_mcp_auth_multitenant.py
"""Unit- и security-тесты OAuth 2.1/OIDC JWKS, mTLS X.509/SPIFFE, anti-spoofing RBAC и multi-tenant изоляции."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from uniconn.mcp import (
    HITLPolicy,
    MCPAuthConfig,
    MCPHostRegistry,
    MCPHttpConfig,
    MCPSecurityPolicy,
    MCPServer,
    MTLSConfig,
    OAuth2OIDCConfig,
)
from uniconn.orchestration import Flow, task
from uniconn.security import DeclarativePolicyRule, EmbeddedPolicyEngine, PolicyGuardrailConfig


def _make_ca_and_client_cert(
    *,
    cn: str = "sre-bot",
    ou: str = "operator",
    org: str = "acme",
    spiffe_uri: str | None = None,
    expired: bool = False,
    ca_key: Any | None = None,
    ca_cert: Any | None = None,
) -> tuple[Any, Any, str, bytes, str, str]:
    """Сгенерировать корневой CA и клиентский X.509-сертификат (PEM + DER + RFC 8705 x5t#S256)."""
    now = datetime.now(UTC)
    if ca_key is None or ca_cert is None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Uniconn Test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    client_key = ec.generate_private_key(ec.SECP256R1())
    client_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    not_before = now - timedelta(days=10) if expired else now - timedelta(hours=1)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=7)
    builder = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if spiffe_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
    client_cert = builder.sign(ca_key, hashes.SHA256())
    der_bytes = client_cert.public_bytes(serialization.Encoding.DER)
    pem_str = client_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    x5t_s256 = base64.urlsafe_b64encode(hashlib.sha256(der_bytes).digest()).rstrip(b"=").decode("ascii")
    return ca_key, ca_cert, ca_pem, der_bytes, pem_str, x5t_s256


def _key_to_jwk(key: Any, kid: str) -> dict[str, Any]:
    pub = key.public_key()
    alg_cls = jwt.algorithms.RSAAlgorithm if isinstance(pub, rsa.RSAPublicKey) else jwt.algorithms.ECAlgorithm
    jwk_dict = json.loads(alg_cls.to_jwk(pub))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    return jwk_dict


def _make_jwt(
    key: Any,
    *,
    alg: str = "RS256",
    kid: str | None = None,
    claims: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": "agent-1",
        "role": "operator",
        "tenant_id": "acme",
        "scope": "mcp:read mcp:exec",
        "aud": "https://mcp.corp.internal/mcp",
        "iss": "https://idp.corp.internal",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
    }
    if claims:
        payload.update(claims)
    headers = {"kid": kid} if kid else None
    return jwt.encode(payload, key, algorithm=alg, headers=headers)


async def _mcp_call(
    client: httpx.AsyncClient,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    headers: dict[str, str],
) -> tuple[int, dict[str, Any], bool]:
    resp = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
    )
    if resp.status_code != 200:
        return resp.status_code, resp.json(), True
    rpc = resp.json()
    res = rpc["result"]
    return 200, json.loads(res["content"][0]["text"]), bool(res.get("isError", False))


@pytest.mark.asyncio
async def test_oauth2_oidc_jwks_rotation_scopes_and_rejection_cases() -> None:
    """OAuth 2.1/OIDC: RS256 + ES256, ротация kid через JWKS, 401/403 RFC 9728/6750, отказ HS256/none/exp/aud."""
    rsa_k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_k2 = ec.generate_private_key(ec.SECP256R1())
    jwks_state = {"keys": [_key_to_jwk(rsa_k1, "k1")]}
    fetch_calls: list[str] = []

    def _mock_fetcher(url: str, _timeout: float) -> dict[str, Any]:
        fetch_calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": "https://idp.corp.internal", "jwks_uri": "https://idp.corp.internal/jwks.json"}
        if url == "https://idp.corp.internal/jwks.json":
            return {"keys": list(jwks_state["keys"])}
        raise AssertionError(f"Unexpected URL {url}")

    reg = MCPHostRegistry.from_dict({"hosts": {"h1": {"transport": "local", "tenant": "acme"}}})
    auth_cfg = MCPAuthConfig(
        mode="oauth2",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.corp.internal",
            audience="https://mcp.corp.internal/mcp",
            role_claim="realm_access.roles",
            role_mapping={"corp-sre": "sre", "corp-ro": "readonly"},
            required_scopes=("mcp:read",),
            jwks_refresh_min_interval_seconds=0.0,
            resource_url="https://mcp.corp.internal/mcp",
        ),
        require_tenant=True,
    )
    server = MCPServer(registry=reg, auth_config=auth_cfg, http_config=MCPHttpConfig(stateless_mode=True))
    app = server.build_http_app(jwks_fetcher=_mock_fetcher)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Missing Bearer token -> 401 with RFC 9728 WWW-Authenticate
        unauth = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert unauth.status_code == 401
        assert 'resource_metadata="https://mcp.corp.internal/.well-known/oauth-protected-resource"' in unauth.headers[
            "WWW-Authenticate"
        ]

        # 2. Valid RS256 token with nested roles claim
        tok_k1 = _make_jwt(
            rsa_k1,
            alg="RS256",
            kid="k1",
            claims={"realm_access": {"roles": ["corp-ro", "corp-sre"]}},
        )
        ok_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_k1}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert ok_resp.status_code == 200
        assert len(fetch_calls) == 2  # discovery + jwks

        # 3. Rotate JWKS to ES256 k2 -> automatic refresh on unknown kid
        jwks_state["keys"] = [_key_to_jwk(ec_k2, "k2")]
        tok_k2 = _make_jwt(
            ec_k2,
            alg="ES256",
            kid="k2",
            claims={"realm_access": {"roles": ["corp-sre"]}},
        )
        ok_es = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_k2}"},
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert ok_es.status_code == 200

        # 4. Missing required_scopes -> 403 insufficient_scope
        no_scope_tok = _make_jwt(
            ec_k2,
            alg="ES256",
            kid="k2",
            claims={"scope": "openid profile", "realm_access": {"roles": ["corp-sre"]}},
        )
        scope_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {no_scope_tok}"},
            json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
        )
        assert scope_resp.status_code == 403
        assert 'error="insufficient_scope"' in scope_resp.headers["WWW-Authenticate"]
        assert 'scope="mcp:read"' in scope_resp.headers["WWW-Authenticate"]

        # 5. Expired token -> 401
        exp_tok = _make_jwt(
            ec_k2,
            alg="ES256",
            kid="k2",
            claims={
                "exp": int((datetime.now(UTC) - timedelta(minutes=5)).timestamp()),
                "realm_access": {"roles": ["corp-sre"]},
            },
        )
        assert (
            await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {exp_tok}"},
                json={"jsonrpc": "2.0", "id": 4, "method": "ping"},
            )
        ).status_code == 401

        # 6. Wrong audience -> 401
        bad_aud = _make_jwt(
            ec_k2,
            alg="ES256",
            kid="k2",
            claims={"aud": "https://other.service", "realm_access": {"roles": ["corp-sre"]}},
        )
        assert (
            await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {bad_aud}"},
                json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
            )
        ).status_code == 401

        # 7. alg=none & HS256 rejected -> 401
        hs_tok = jwt.encode(
            {"sub": "evil", "role": "admin", "tenant_id": "acme", "aud": "https://mcp.corp.internal/mcp"},
            "shared-secret-key-0123456789abcdef",
            algorithm="HS256",
        )
        assert (
            await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {hs_tok}"},
                json={"jsonrpc": "2.0", "id": 6, "method": "ping"},
            )
        ).status_code == 401

        none_hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        none_pl = base64.urlsafe_b64encode(b'{"sub":"evil","role":"admin","tenant_id":"acme"}').rstrip(b"=").decode()
        none_tok = f"{none_hdr}.{none_pl}."
        assert (
            await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {none_tok}"},
                json={"jsonrpc": "2.0", "id": 7, "method": "ping"},
            )
        ).status_code == 401

    # 8. OAuth2OIDCConfig rejects symmetric/none algorithms at config time
    with pytest.raises(ValueError, match="asymmetric only"):
        OAuth2OIDCConfig(issuer="https://idp.corp.internal", algorithms=("HS256",))

    # 9. SSRF protection rejects private/loopback JWKS URL when allow_private_network=False
    from uniconn.mcp import OAuth2JWTValidator

    validator = OAuth2JWTValidator(
        OAuth2OIDCConfig(jwks_url="http://127.0.0.1:9999/jwks.json", allow_private_network=False)
    )
    with pytest.raises(Exception, match=r"private|loopback|Failed|SSRF|blocked|invalid"):
        await validator.validate_token(tok_k1, allow_missing_tenant=True)


@pytest.mark.asyncio
async def test_mtls_direct_proxy_spiffe_and_rfc8705_both_mode() -> None:
    """mTLS: прямой DER, trusted proxy Nginx/Envoy, SPIFFE URI, отклонение untrusted proxy, RFC 8705 cnf.x5t#S256."""
    ca_key, ca_cert, ca_pem, der_bytes, pem_str, x5t_s256 = _make_ca_and_client_cert(
        cn="sre-payments",
        ou="sre",
        org="payments-org",
        spiffe_uri="spiffe://corp.internal/ns/payments/sa/sre-bot",
    )
    _, _, _, _, expired_pem, _ = _make_ca_and_client_cert(
        cn="expired-bot",
        ou="sre",
        org="payments-org",
        spiffe_uri="spiffe://corp.internal/ns/payments/sa/expired-bot",
        expired=True,
        ca_key=ca_key,
        ca_cert=ca_cert,
    )
    _, _, _, _, rogue_pem, _ = _make_ca_and_client_cert(
        cn="rogue-bot",
        ou="admin",
        org="payments-org",
        spiffe_uri="spiffe://corp.internal/ns/payments/sa/rogue-bot",
    )

    reg = MCPHostRegistry.from_dict({"hosts": {"pay-01": {"transport": "local", "tenant": "payments"}}})

    # 1. Pure mTLS with SPIFFE mapping & trusted proxy CIDR
    mtls_auth = MCPAuthConfig(
        mode="mtls",
        mtls=MTLSConfig(
            ca_cert_pem=ca_pem,
            role_source="spiffe_sa",
            role_mapping={"sre-bot": "sre"},
            tenant_source="spiffe_ns",
            agent_id_source="san_uri",
            trusted_proxy_cidrs=("10.0.0.0/8",),
        ),
        require_tenant=True,
    )
    server = MCPServer(registry=reg, auth_config=mtls_auth, http_config=MCPHttpConfig(stateless_mode=True))
    app = server.build_http_app()

    # 1a. Trusted proxy IP (10.1.2.3) passing URL-encoded X-SSL-Client-Cert succeeds
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("10.1.2.3", 50000)),
        base_url="http://testserver",
    ) as client:
        status, data, is_err = await _mcp_call(
            client,
            "uniconn_evaluate_policy",
            {"command": "uptime", "target": "pay-01", "role": "admin", "agent_id": "spoofed"},
            headers={"X-SSL-Client-Cert": quote(pem_str)},
        )
        assert status == 200
        assert not is_err
        subj = data["auth_context"]["subject"]
        assert subj["agent_id"] == "spiffe://corp.internal/ns/payments/sa/sre-bot"
        assert subj["role"] == "sre"
        assert subj["tenant_id"] == "payments"
        assert subj["auth_method"] == "mtls"

        # Envoy XFCC header also works
        xfcc_val = f'By=spiffe://corp/ns/mcp;Hash=abc;Cert="{quote(pem_str)}"'
        status2, data2, is_err2 = await _mcp_call(
            client,
            "uniconn_list_hosts",
            {},
            headers={"X-Forwarded-Client-Cert": xfcc_val},
        )
        assert status2 == 200 and not is_err2
        assert [h["name"] for h in data2["hosts"]] == ["pay-01"]

        # Expired cert rejected (401)
        exp_resp = await client.post(
            "/mcp",
            headers={"X-SSL-Client-Cert": quote(expired_pem)},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert exp_resp.status_code == 401

        # Rogue CA cert rejected (401)
        rogue_resp = await client.post(
            "/mcp",
            headers={"X-SSL-Client-Cert": quote(rogue_pem)},
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert rogue_resp.status_code == 401

    # 1b. Untrusted client IP (192.168.1.99) spoofing X-SSL-Client-Cert is rejected (401)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.168.1.99", 50000)),
        base_url="http://testserver",
    ) as client:
        spoof_resp = await client.post(
            "/mcp",
            headers={"X-SSL-Client-Cert": quote(pem_str)},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert spoof_resp.status_code == 401

    # 1c. Direct ASGI TLS extension / client_cert_der works without proxy headers
    async def _inject_der_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope["client_cert_der"] = der_bytes
        await app(scope, receive, send)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_inject_der_app, client=("192.168.1.99", 50000)),
        base_url="http://testserver",
    ) as client:
        direct_resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert direct_resp.status_code == 200

    # 2. Mode "both" with RFC 8705 cnf.x5t#S256 certificate-bound JWT
    jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwt_pub_pem = jwt_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    both_auth = MCPAuthConfig(
        mode="both",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.corp.internal",
            audience="https://mcp.corp.internal/mcp",
            static_public_key_pem=jwt_pub_pem,
        ),
        mtls=MTLSConfig(
            ca_cert_pem=ca_pem,
            role_source="ou",
            tenant_source="spiffe_ns",
            trusted_proxy_cidrs=("10.0.0.0/8",),
            require_jwt_cert_binding=True,
        ),
        require_tenant=True,
    )
    both_server = MCPServer(registry=reg, auth_config=both_auth, http_config=MCPHttpConfig(stateless_mode=True))
    both_app = both_server.build_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=both_app, client=("10.0.0.5", 44321)),
        base_url="http://testserver",
    ) as client:
        bound_tok = _make_jwt(
            jwt_key,
            claims={
                "sub": "sre-alice",
                "role": "operator",
                "tenant_id": "payments",
                "cnf": {"x5t#S256": x5t_s256},
            },
        )
        status_ok, eval_data, is_err = await _mcp_call(
            client,
            "uniconn_evaluate_policy",
            {"command": "uptime", "target": "pay-01"},
            headers={"Authorization": f"Bearer {bound_tok}", "X-SSL-Client-Cert": quote(pem_str)},
        )
        assert status_ok == 200 and not is_err
        assert eval_data["auth_context"]["subject"]["auth_method"] == "oauth2+mtls"

        # Mismatched cnf.x5t#S256 -> 401
        wrong_thumb_tok = _make_jwt(
            jwt_key,
            claims={
                "sub": "sre-alice",
                "role": "operator",
                "tenant_id": "payments",
                "cnf": {"x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            },
        )
        mismatch_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {wrong_thumb_tok}", "X-SSL-Client-Cert": quote(pem_str)},
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert mismatch_resp.status_code == 401

        # Tenant mismatch between JWT ("other-tenant") and cert ("payments") -> 403
        tenant_mismatch_tok = _make_jwt(
            jwt_key,
            claims={
                "sub": "sre-alice",
                "role": "operator",
                "tenant_id": "other-tenant",
                "cnf": {"x5t#S256": x5t_s256},
            },
        )
        tm_resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tenant_mismatch_tok}", "X-SSL-Client-Cert": quote(pem_str)},
            json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
        )
        assert tm_resp.status_code == 403


@pytest.mark.asyncio
async def test_strict_rbac_anti_spoofing_and_declarative_tenant_policy_rules(tmp_path: Path) -> None:
    """Anti-spoofing: аргументы role/agent_id игнорируются в сетевом режиме; policy rules видят tenant/scopes."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Declarative policy rules using new tenant_id, auth_method, and scopes conditions
    rules = [
        DeclarativePolicyRule.from_dict(
            {
                "name": "deny_readonly_mutations",
                "effect": "deny",
                "when": {"role": "readonly", "risk_tier": ["MUTATING", "DESTRUCTIVE"]},
                "reason": "Readonly callers cannot run mutating commands",
            }
        ),
        DeclarativePolicyRule.from_dict(
            {
                "name": "require_exec_scope_for_acme",
                "effect": "deny",
                "when": {
                    "tenant_id": "acme",
                    "auth_method": "oauth2",
                    "tool_name": "uniconn_run",
                    "command_regex": "echo",
                },
                "reason": "Blocked echo for testing tenant/auth_method rule matching",
            }
        ),
    ]
    policy = MCPSecurityPolicy(
        allow_write=True,
        hitl=HITLPolicy(enabled=True, store_path=str(tmp_path / "approvals.json")),
        guardrails=PolicyGuardrailConfig(enabled=True, preset="default"),
    )
    reg = MCPHostRegistry.from_dict(
        {"hosts": {"acme-app": {"transport": "local", "tenant": "acme", "groups": ["prod"]}}},
        policy=policy,
    )
    engine = EmbeddedPolicyEngine(declarative_rules=rules, preset="default")
    auth_cfg = MCPAuthConfig(
        mode="oauth2",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.corp.internal",
            audience="https://mcp.corp.internal/mcp",
            static_public_key_pem=pub_pem,
        ),
        require_tenant=True,
    )
    server = MCPServer(
        registry=reg,
        policy_engine=engine,
        auth_config=auth_cfg,
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    app = server.build_http_app()

    readonly_tok = _make_jwt(priv, claims={"sub": "bot-ro-99", "role": "readonly", "tenant_id": "acme"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        hdrs = {"Authorization": f"Bearer {readonly_tok}"}

        # 1. Spoofing role="admin", agent_id="root" in uniconn_evaluate_policy MUST be ignored!
        status, eval_data, is_err = await _mcp_call(
            client,
            "uniconn_evaluate_policy",
            {
                "command": "systemctl restart nginx",
                "target": "acme-app",
                "role": "admin",
                "agent_id": "root",
            },
            headers=hdrs,
        )
        assert status == 200 and not is_err
        assert eval_data["auth_context"]["subject"]["role"] == "readonly"
        assert eval_data["auth_context"]["subject"]["agent_id"] == "bot-ro-99"
        assert eval_data["auth_context"]["subject"]["tenant_id"] == "acme"
        assert eval_data["decision"] == "DENY"

        # 2. Spoofing role="admin" in uniconn_run is denied by policy (cannot escalate privileges)
        status_run, run_data, is_run_err = await _mcp_call(
            client,
            "uniconn_run",
            {
                "target": "acme-app",
                "command": "echo hello",
                "role": "admin",
                "agent_id": "root",
            },
            headers=hdrs,
        )
        assert status_run == 200 and is_run_err
        assert run_data["error"] == "PolicyViolationError"

        # 3. Proposing an action records the verified agent_id and tenant_id (ignoring spoofed agent_id)
        op_tok = _make_jwt(priv, claims={"sub": "sre-verified-1", "role": "operator", "tenant_id": "acme"})
        status_prop, prop_data, is_prop_err = await _mcp_call(
            client,
            "uniconn_propose_action",
            {
                "tool_name": "uniconn_run",
                "target": "acme-app",
                "command": "systemctl restart nginx",
                "agent_id": "evil-spoofed-agent",
                "role": "admin",
            },
            headers={"Authorization": f"Bearer {op_tok}"},
        )
        assert status_prop == 200 and not is_prop_err
        assert prop_data["approval"]["agent_id"] == "sre-verified-1"
        assert prop_data["approval"]["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_multitenant_full_isolation_hosts_sessions_hitl_and_checkpoints(tmp_path: Path) -> None:
    """Полная изоляция тенантов: shared inventory (fail-closed), per-tenant registry, сессии, HITL, чекпоинты."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Shared inventory with tenant-tagged hosts + an untagged host (hidden when allow_shared_hosts=False)
    base_policy = MCPSecurityPolicy(
        allow_write=False,
        hitl=HITLPolicy(enabled=True, store_path=str(tmp_path / "approvals.json")),
    )
    shared_reg = MCPHostRegistry.from_dict(
        {
            "hosts": {
                "acme-web-01": {"transport": "local", "tenant": "acme", "groups": ["web"]},
                "untagged-jump": {"transport": "local", "groups": ["shared"]},
            }
        },
        policy=base_policy,
    )

    # Dedicated per-tenant registry for globex with its own policy (allow_write=True)
    globex_policy = MCPSecurityPolicy(
        allow_write=True,
        hitl=HITLPolicy(enabled=True, store_path=str(tmp_path / "approvals.json")),
    )
    globex_reg = MCPHostRegistry.from_dict(
        {
            "hosts": {
                "globex-db-01": {"transport": "local", "groups": ["db"]},
            }
        },
        policy=globex_policy,
    )

    @task(name="fail_step")
    async def fail_step(conn: Any) -> Any:
        raise RuntimeError("intentional failure to create resumable checkpoint")

    sample_flow = Flow(name="diag_flow", tasks=[fail_step], risk_tier="safe")

    auth_cfg = MCPAuthConfig(
        mode="oauth2",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.corp.internal",
            audience="https://mcp.corp.internal/mcp",
            static_public_key_pem=pub_pem,
        ),
        require_tenant=True,
    )
    server = MCPServer(
        registry=shared_reg,
        allow_shared_hosts=False,
        auth_config=auth_cfg,
        http_config=MCPHttpConfig(stateless_mode=False),
        flows=[sample_flow],
    )
    server.register_tenant("globex", globex_reg)
    app = server.build_http_app()

    tok_acme = _make_jwt(priv, claims={"sub": "alice", "role": "operator", "tenant_id": "acme"})
    tok_globex = _make_jwt(priv, claims={"sub": "bob", "role": "operator", "tenant_id": "globex"})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Initialize separate sessions for acme and globex
        init_a = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_acme}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        sid_a = init_a.headers["Mcp-Session-Id"]

        init_b = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_globex}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        sid_b = init_b.headers["Mcp-Session-Id"]

        hdr_a = {"Authorization": f"Bearer {tok_acme}", "Mcp-Session-Id": sid_a}
        hdr_b = {"Authorization": f"Bearer {tok_globex}", "Mcp-Session-Id": sid_b}

        # 2. Cross-tenant session hijacking -> 403 Forbidden
        hijack = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok_acme}", "Mcp-Session-Id": sid_b},
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
        )
        assert hijack.status_code == 403

        # 3. Host isolation: acme sees ONLY acme-web-01 (no untagged-jump, no globex-db-01)
        _, hosts_a, err_a = await _mcp_call(client, "uniconn_list_hosts", {}, headers=hdr_a)
        assert not err_a
        assert [h["name"] for h in hosts_a["hosts"]] == ["acme-web-01"]
        assert hosts_a["security_policy"]["allow_write"] is False

        # globex sees ONLY globex-db-01 and gets its own policy (allow_write=True)
        _, hosts_b, err_b = await _mcp_call(client, "uniconn_list_hosts", {}, headers=hdr_b)
        assert not err_b
        assert [h["name"] for h in hosts_b["hosts"]] == ["globex-db-01"]
        assert hosts_b["security_policy"]["allow_write"] is True

        # acme cannot run command on globex-db-01 or untagged-jump
        _, cross_run, cross_err = await _mcp_call(
            client,
            "uniconn_run",
            {"target": "globex-db-01", "command": "uptime"},
            headers=hdr_a,
        )
        assert cross_err
        assert "not found" in cross_run["message"].lower()

        _, _untagged_run, untagged_err = await _mcp_call(
            client,
            "uniconn_run",
            {"target": "untagged-jump", "command": "uptime"},
            headers=hdr_a,
        )
        assert untagged_err

        # 4. HITL Approval isolation: acme creates an approval; globex cannot list, inspect, or consume it
        _, prop_a, prop_err_a = await _mcp_call(
            client,
            "uniconn_propose_action",
            {"tool_name": "uniconn_run", "target": "acme-web-01", "command": "systemctl restart nginx"},
            headers=hdr_a,
        )
        assert not prop_err_a
        appr_id_a = prop_a["approval"]["approval_id"]

        # acme sees its own approval
        _, list_appr_a, _ = await _mcp_call(client, "uniconn_check_approval", {}, headers=hdr_a)
        assert list_appr_a["count"] == 1
        assert list_appr_a["approvals"][0]["approval_id"] == appr_id_a

        # globex sees 0 approvals and gets error when querying acme's approval_id directly
        _, list_appr_b, _ = await _mcp_call(client, "uniconn_check_approval", {}, headers=hdr_b)
        assert list_appr_b["count"] == 0

        _, spy_appr_b, spy_err_b = await _mcp_call(
            client,
            "uniconn_check_approval",
            {"approval_id": appr_id_a},
            headers=hdr_b,
        )
        assert spy_err_b
        assert spy_appr_b["error"] == "KeyError"

        # Approve acme's request via operator, verify globex still cannot consume it
        await server.approval_manager.approve(appr_id_a, decided_by="ops")
        _, _steal_res, steal_err = await _mcp_call(
            client,
            "uniconn_run",
            {
                "target": "globex-db-01",
                "command": "systemctl restart nginx",
                "approval_id": appr_id_a,
            },
            headers=hdr_b,
        )
        assert steal_err

        # 5. Flow checkpoint isolation: acme runs failing flow -> checkpoint visible only to acme
        _, flow_res_a, flow_err_a = await _mcp_call(
            client,
            "uniconn_run_flow",
            {"flow_name": "diag_flow", "targets": ["acme-web-01"]},
            headers=hdr_a,
        )
        assert not flow_err_a
        assert flow_res_a["can_resume"] is True
        run_id_a = flow_res_a["run_id"]

        _, flows_a, _ = await _mcp_call(client, "uniconn_list_flows", {"include_checkpoints": True}, headers=hdr_a)
        assert any(cp["run_id"] == run_id_a for cp in flows_a["resumable_checkpoints"])

        _, flows_b, _ = await _mcp_call(client, "uniconn_list_flows", {"include_checkpoints": True}, headers=hdr_b)
        assert not any(cp["run_id"] == run_id_a for cp in flows_b["resumable_checkpoints"])

        _, hijack_resume, hijack_resume_err = await _mcp_call(
            client,
            "uniconn_resume_flow",
            {"run_id": run_id_a},
            headers=hdr_b,
        )
        assert hijack_resume_err
        assert hijack_resume["error"] == "KeyError"


@pytest.mark.asyncio
async def test_mtls_xfcc_quoted_commas_and_fail_closed_proxy_without_ca() -> None:
    """Envoy XFCC с запятыми внутри Subject='CN=...,OU=...' парсится корректно; прокси без CA -> fail-closed 401."""
    _, _, ca_pem, _, pem_str, _ = _make_ca_and_client_cert(
        cn="envoy-bot",
        ou="sre",
        org="acme",
        spiffe_uri="spiffe://prod.corp/ns/payments/sa/envoy-bot",
    )

    # 1. Envoy XFCC with commas inside quoted Subject BEFORE Cert="..."
    xfcc_val = (
        f'By=spiffe://cluster.local/ns/istio/sa/ingress;'
        f'Hash=deadbeef;'
        f'Subject="CN=envoy-bot,OU=sre,O=acme";'
        f'Cert="{quote(pem_str)}"'
        f',By=spiffe://cluster.local/ns/mesh/sa/hop2;Cert="ignored"'
    )
    reg = MCPHostRegistry.from_dict({"hosts": {"pay-01": {"transport": "local", "tenant": "payments"}}})
    server_ok = MCPServer(
        registry=reg,
        auth_config=MCPAuthConfig(
            mode="mtls",
            mtls=MTLSConfig(
                ca_cert_pem=ca_pem,
                role_source="ou",
                tenant_source="spiffe_ns",
                trusted_proxy_cidrs=("10.0.0.0/8",),
            ),
            require_tenant=True,
        ),
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    app_ok = server_ok.build_http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_ok, client=("10.0.0.7", 55000)),
        base_url="http://testserver",
    ) as client:
        status, data, is_err = await _mcp_call(
            client,
            "uniconn_list_hosts",
            {},
            headers={"X-Forwarded-Client-Cert": xfcc_val},
        )
        assert status == 200 and not is_err
        assert [h["name"] for h in data["hosts"]] == ["pay-01"]

    # 2. Fail-closed: trusted_proxy_cidrs + verify_proxy_cert_chain=True WITHOUT ca_cert_pem/ca_cert_path -> 401
    server_no_ca = MCPServer(
        registry=reg,
        auth_config=MCPAuthConfig(
            mode="mtls",
            mtls=MTLSConfig(
                role_source="ou",
                tenant_source="spiffe_ns",
                trusted_proxy_cidrs=("10.0.0.0/8",),
                verify_proxy_cert_chain=True,
            ),
            require_tenant=True,
        ),
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    app_no_ca = server_no_ca.build_http_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_no_ca, client=("10.0.0.7", 55001)),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(
            "/mcp",
            headers={"X-SSL-Client-Cert": quote(pem_str)},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert resp.status_code == 401
        assert "requires a configured CA" in resp.json()["error_description"]


@pytest.mark.asyncio
async def test_oidc_discovery_ssrf_jwks_returns_401_and_untagged_caller_cannot_see_tenant_hosts() -> None:
    """SSRF в jwks_uri из OIDC discovery возвращает 401 (не 500), а caller без tenant_id не видит чужие хосты."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # 1. OIDC discovery pointing to AWS metadata IP (SSRF) -> clean HTTP 401 (not 500)
    def _evil_oidc_fetcher(url: str, timeout: float) -> dict[str, Any]:
        assert url.endswith("/.well-known/openid-configuration")
        return {"jwks_uri": "http://169.254.169.254/latest/meta-data/"}

    ssrf_server = MCPServer(
        registry=MCPHostRegistry.from_sources(include_local=True),
        auth_config=MCPAuthConfig(
            mode="oauth2",
            oauth2=OAuth2OIDCConfig(
                issuer="https://idp.public.example",
                audience="https://mcp.corp.internal/mcp",
                allow_private_network=False,
            ),
        ),
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    ssrf_app = ssrf_server.build_http_app(jwks_fetcher=_evil_oidc_fetcher)
    tok = _make_jwt(priv, claims={"sub": "bot", "role": "operator", "tenant_id": "acme"}, kid="k1")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ssrf_app), base_url="http://testserver") as client:
        resp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {tok}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert resp.status_code == 401
        assert "Blocked JWKS URL" in resp.json()["error_description"]

    # 2. require_tenant=False verified caller with tenant_id=None MUST NOT see tenant-tagged hosts
    mixed_reg = MCPHostRegistry.from_dict(
        {
            "hosts": {
                "acme-only": {"transport": "local", "tenant": "acme"},
                "shared-jump": {"transport": "local"},
            }
        }
    )
    no_tenant_auth = MCPAuthConfig(
        mode="oauth2",
        oauth2=OAuth2OIDCConfig(
            issuer="https://idp.corp.internal",
            audience="https://mcp.corp.internal/mcp",
            static_public_key_pem=pub_pem,
        ),
        require_tenant=False,
    )
    tok_no_tenant = _make_jwt(priv, claims={"sub": "untagged-bot", "role": "operator", "tenant_id": None})

    # 2a. allow_shared_hosts=False -> 0 hosts visible
    srv_strict = MCPServer(
        registry=mixed_reg,
        allow_shared_hosts=False,
        auth_config=no_tenant_auth,
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=srv_strict.build_http_app()),
        base_url="http://testserver",
    ) as client:
        _, hosts_strict, err_strict = await _mcp_call(
            client,
            "uniconn_list_hosts",
            {},
            headers={"Authorization": f"Bearer {tok_no_tenant}"},
        )
        assert not err_strict
        assert hosts_strict["hosts"] == []

    # 2b. allow_shared_hosts=True -> only untagged shared-jump visible, NEVER acme-only
    srv_shared = MCPServer(
        registry=mixed_reg,
        allow_shared_hosts=True,
        auth_config=no_tenant_auth,
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=srv_shared.build_http_app()),
        base_url="http://testserver",
    ) as client:
        _, hosts_shared, err_shared = await _mcp_call(
            client,
            "uniconn_list_hosts",
            {},
            headers={"Authorization": f"Bearer {tok_no_tenant}"},
        )
        assert not err_shared
        assert [h["name"] for h in hosts_shared["hosts"]] == ["shared-jump"]

    # 3. MCPHttpConfig fails closed on partial TLS pair
    with pytest.raises(ValueError, match="tls_cert_path"):
        MCPHttpConfig(tls_cert_path="/etc/ssl/server.crt")
    with pytest.raises(ValueError, match="tls_key_path"):
        MCPHttpConfig(tls_key_path="/etc/ssl/server.key")


@pytest.mark.asyncio
async def test_untagged_verified_caller_cannot_access_tenant_approvals_or_checkpoints_and_non_scalar_jwt_rejected(
    tmp_path: Path,
) -> None:
    """Caller с tenant_id=None (require_tenant=False) не видит чужие HITL/checkpoints; нескалярные claims -> 401."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    @task(name="fail_step", tags=("mutating",))
    async def fail_step(conn: Any, ctx: Any) -> dict[str, Any]:
        raise RuntimeError("boom")

    flow = Flow("tenant_flow", tasks=[fail_step])
    policy = MCPSecurityPolicy(
        hitl=HITLPolicy(enabled=True, store_path=str(tmp_path / "approvals.json")),
    )
    reg = MCPHostRegistry.from_dict(
        {
            "hosts": {
                "acme-01": {"transport": "local", "tenant": "acme"},
                "shared-01": {"transport": "local"},
            }
        },
        policy=policy,
    )
    server = MCPServer(
        registry=reg,
        flows=[flow],
        allow_shared_hosts=True,
        auth_config=MCPAuthConfig(
            mode="oauth2",
            oauth2=OAuth2OIDCConfig(
                issuer="https://idp.corp.internal",
                audience="https://mcp.corp.internal/mcp",
                static_public_key_pem=pub_pem,
            ),
            require_tenant=False,
        ),
        http_config=MCPHttpConfig(stateless_mode=True),
    )
    app = server.build_http_app()

    tok_acme = _make_jwt(priv, claims={"sub": "acme-bot", "role": "operator", "tenant_id": "acme"})
    tok_untagged = _make_jwt(priv, claims={"sub": "anon-bot", "role": "operator", "tenant_id": None})
    tok_list_tenant = _make_jwt(priv, claims={"sub": "bad-bot", "role": "operator", "tenant_id": ["acme"]})
    tok_bool_tenant = _make_jwt(priv, claims={"sub": "bad-bot", "role": "operator", "tenant_id": True})

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Non-scalar tenant_id claims rejected fail-closed with 401
        for bad_tok in (tok_list_tenant, tok_bool_tenant):
            r_bad = await client.post(
                "/mcp",
                headers={"Authorization": f"Bearer {bad_tok}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert r_bad.status_code == 401

        # 2. Tenant 'acme' creates an approval and a failed flow checkpoint
        _, prop_a, prop_err = await _mcp_call(
            client,
            "uniconn_propose_action",
            {"tool_name": "uniconn_run", "target": "acme-01", "command": "systemctl restart nginx"},
            headers={"Authorization": f"Bearer {tok_acme}"},
        )
        assert not prop_err
        acme_appr_id = prop_a["approval"]["approval_id"]

        # Create a failed flow checkpoint owned by 'acme'
        await server.approval_manager.approve(acme_appr_id, decided_by="ops")
        cp_flow = await server.checkpoint_store.record_from_report(
            report=type(
                "_FakeReport",
                (),
                {"flow_name": "tenant_flow", "run_id": "run_acme_secret", "ok": False, "results": {}},
            )(),
            targets=["acme-01"],
            tenant_id="acme",
        )
        assert cp_flow.tenant_id == "acme"

        # 3. Verified untagged caller (tenant_id=None) sees ZERO acme approvals and ZERO acme checkpoints
        hdr_u = {"Authorization": f"Bearer {tok_untagged}"}
        _, list_u, err_u = await _mcp_call(client, "uniconn_check_approval", {}, headers=hdr_u)
        assert not err_u
        assert list_u["count"] == 0

        _, spy_u, spy_err = await _mcp_call(
            client,
            "uniconn_check_approval",
            {"approval_id": acme_appr_id},
            headers=hdr_u,
        )
        assert spy_err and spy_u["error"] == "KeyError"

        res_pending = await client.post(
            "/mcp",
            headers=hdr_u,
            json={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "resources/read",
                "params": {"uri": "uniconn://approvals/pending"},
            },
        )
        assert res_pending.status_code == 200
        pending_payload = json.loads(res_pending.json()["result"]["contents"][0]["text"])
        assert pending_payload["count"] == 0

        _, flows_u, flows_err = await _mcp_call(
            client,
            "uniconn_list_flows",
            {"include_checkpoints": True},
            headers=hdr_u,
        )
        assert not flows_err
        assert flows_u["resumable_checkpoints"] == []

        _, hijack_u, hijack_err = await _mcp_call(
            client,
            "uniconn_resume_flow",
            {"run_id": "run_acme_secret"},
            headers=hdr_u,
        )
        assert hijack_err and hijack_u["error"] == "KeyError"


