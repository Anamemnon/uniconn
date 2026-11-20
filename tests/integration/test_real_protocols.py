# tests/integration/test_real_protocols.py
"""Протокольные интеграционные тесты против реальных контейнеров (OpenSSH, OPA, NETCONF, gNMI)."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import pytest

from uniconn import Connection, PolicyDecision
from uniconn.pool.session_pool import SSHSessionPool
from uniconn.security import OPAPolicyEngine, PolicyGuardrailMiddleware, build_auth_context

pytestmark = pytest.mark.integration

SSH_URI = os.environ.get(
    "UNICONN_TEST_SSH_URI",
    "ssh://testuser:testpass@127.0.0.1:2222?known_hosts=none",
)
OPA_URL = os.environ.get(
    "UNICONN_TEST_OPA_URL",
    "http://127.0.0.1:8181/v1/data/uniconn/authz",
)
NETCONF_URI = os.environ.get(
    "UNICONN_TEST_NETCONF_URI",
    "netconf://netconf:secret@127.0.0.1:8300?known_hosts=none",
)
GNMI_URI = os.environ.get(
    "UNICONN_TEST_GNMI_URI",
    "gnmi://gnmi:secret@127.0.0.1:57400?tls=false",
)


def _tcp_reachable(uri: str, default_port: int, timeout: float = 1.5) -> bool:
    parsed = urlparse(uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or default_port
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _require_endpoint(uri: str, default_port: int, label: str) -> None:
    if not _tcp_reachable(uri, default_port):
        pytest.skip(f"{label} integration service is not reachable at {uri}")


class TestRealOpenSSHProtocol:
    """Интеграционные тесты против реального OpenSSH-сервера (sshd с MaxSessions=2)."""

    @pytest.mark.asyncio
    async def test_ssh_run_sftp_and_shell_session(self, tmp_path: Path) -> None:
        _require_endpoint(SSH_URI, 2222, "OpenSSH")

        async with Connection.from_uri(SSH_URI) as conn:
            res = await conn.run("echo uniconn-real-ssh && uname -s")
            assert res.ok is True
            assert "uniconn-real-ssh" in res.stdout

            remote_file = "/tmp/uniconn_integration_test.txt"
            payload = "hello-real-openssh-sftp\nline2\n"
            await conn.files.write_file(remote_file, payload)
            read_back = await conn.files.read_file(remote_file)
            assert read_back == payload

            local_dl = tmp_path / "downloaded.txt"
            await conn.files.download(remote_file, local_dl)
            assert local_dl.read_text(encoding="utf-8") == payload

            async with conn.open_shell() as shell:
                out = await shell.execute("echo shell-marker-ok")
                assert "shell-marker-ok" in out.stdout

            await conn.run(f"rm -f {remote_file}")

    @pytest.mark.asyncio
    async def test_ssh_session_pool_adaptive_scale_down_against_max_sessions(self) -> None:
        _require_endpoint(SSH_URI, 2222, "OpenSSH")

        # sshd настроен на MaxSessions=2; пул стартует с max_sessions_per_conn=6 и
        # обязан корректно обслужить конкурентную нагрузку через адаптивное открытие слотов.
        async with SSHSessionPool(
            SSH_URI,
            max_connections=4,
            max_sessions_per_conn=6,
        ) as spool:
            results = await asyncio.gather(
                *(spool.run(f"sleep 0.15 && echo worker-{i}") for i in range(6))
            )
            assert len(results) == 6
            assert all(r.ok for r in results)
            for idx, r in enumerate(results):
                assert f"worker-{idx}" in r.stdout


class TestRealOPAPolicyEngine:
    """Интеграционные тесты OPAPolicyEngine против реального контейнера Open Policy Agent."""

    @pytest.mark.asyncio
    async def test_opa_real_rego_allow_require_approval_and_deny(self) -> None:
        _require_endpoint(OPA_URL, 8181, "OPA")

        engine = OPAPolicyEngine(
            opa_url=OPA_URL,
            allow_private_network=True,
            cache_ttl_seconds=0.0,
        )

        # 1. Безопасная read-only команда -> ALLOW
        ctx_safe = build_auth_context(command="ls -la /tmp", environment="staging")
        res_safe = await engine.evaluate(ctx_safe)
        assert res_safe.decision == PolicyDecision.ALLOW
        assert res_safe.allowed is True

        # 2. Мутирующая команда на production -> REQUIRE_APPROVAL
        ctx_prod = build_auth_context(
            command="systemctl restart nginx",
            environment="production",
        )
        res_prod = await engine.evaluate(ctx_prod)
        assert res_prod.decision == PolicyDecision.REQUIRE_APPROVAL
        assert res_prod.requires_approval is True

        # 3. Запрещённая бинарная команда / доступ к /etc/shadow -> DENY
        ctx_deny = build_auth_context(command="cat /etc/shadow", environment="staging")
        res_deny = await engine.evaluate(ctx_deny)
        assert res_deny.decision == PolicyDecision.DENY
        assert res_deny.allowed is False

        # 4. Проверка middleware в конвейере Connection (local)
        mw = PolicyGuardrailMiddleware(engine=engine)
        async with Connection.local(middlewares=[mw]) as conn:
            ok_res = await conn.run("echo opa-middleware-ok")
            assert ok_res.ok is True
            assert "opa-middleware-ok" in ok_res.stdout


class TestRealNetworkProtocols:
    """Интеграционные smoke-тесты NETCONF и gNMI против контейнерных серверов."""

    @pytest.mark.asyncio
    async def test_netconf_get_and_edit_config_smoke(self) -> None:
        _require_endpoint(NETCONF_URI, 8300, "NETCONF")

        async with Connection.from_uri(NETCONF_URI) as conn:
            res = await conn.net.get()
            assert res.ok is True

    @pytest.mark.asyncio
    async def test_gnmi_get_smoke(self) -> None:
        _require_endpoint(GNMI_URI, 57400, "gNMI")

        async with Connection.from_uri(GNMI_URI) as conn:
            res = await conn.net.get("/system/config/hostname")
            assert res.ok is True
