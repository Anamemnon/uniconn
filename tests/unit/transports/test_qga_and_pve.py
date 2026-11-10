# tests/unit/transports/test_qga_and_pve.py
"""Комплексные unit-тесты для транспортов виртуализации QgaTransport (qga://, qemu-ga://) и PveTransport (pve://)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import (
    CapabilityNotSupportedError,
    CommandTransport,
    ConfigurationError,
    Connection,
    ConnectionConfig,
    FileCapableTransport,
    MockPveServer,
    MockQgaServer,
    PveTransport,
    QgaProtocolClient,
    QgaTransport,
    ShellCapableTransport,
    SshUnixSocketChannel,
    SyncConnection,
    TimeoutError,
    URIParser,
    VirshCommandChannel,
    supports_capability,
)


class TestVirtualizationURIParsing:
    """Тесты парсинга, сборки и маскирования URI для qga://, qemu-ga:// и pve://."""

    def test_qga_local_socket_uri(self) -> None:
        uri = "qga:///var/lib/libvirt/qemu/channel/target/domain-1-vm1/org.qemu.guest_agent.0"
        cfg = URIParser.parse(uri)
        assert cfg.transport == "qga"
        assert cfg.options["socket"] == "/var/lib/libvirt/qemu/channel/target/domain-1-vm1/org.qemu.guest_agent.0"
        assert cfg.options["backend"] == "socket"
        assert cfg.uri_safe == uri
        assert URIParser.build("qga", host=cfg.host, options=cfg.options) == uri

    def test_qemu_ga_remote_ssh_socket_uri(self) -> None:
        uri = "qemu-ga://root@kvm-host-01/vm-prod-01?socket=/var/run/qemu/vm-prod-01.sock"
        cfg = URIParser.parse(uri)
        assert cfg.transport == "qemu-ga"
        assert cfg.host == "kvm-host-01"
        assert cfg.port == 22
        assert cfg.username == "root"
        assert cfg.options["vm"] == "vm-prod-01"
        assert cfg.options["domain"] == "vm-prod-01"
        assert cfg.options["socket"] == "/var/run/qemu/vm-prod-01.sock"
        assert cfg.uri_safe == "qemu-ga://root@kvm-host-01:22/vm-prod-01"

    def test_qga_virsh_backend_uri(self) -> None:
        uri = "qga://root@kvm-host-01:2222/vm-prod-01?backend=virsh"
        cfg = URIParser.parse(uri)
        assert cfg.transport == "qga"
        assert cfg.host == "kvm-host-01"
        assert cfg.port == 2222
        assert cfg.options["vm"] == "vm-prod-01"
        assert cfg.options["backend"] == "virsh"

    def test_pve_token_uri_with_env_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PVE_TOKEN_SECRET", "super-secret-token-val")
        uri = "pve://root@pam@pve-host:8006/105?node=pve-node1&token_id=uniconn&secret=env://PVE_TOKEN_SECRET&verify_ssl=false"
        cfg = URIParser.parse(uri)
        assert cfg.transport == "pve"
        assert cfg.host == "pve-host"
        assert cfg.port == 8006
        assert cfg.username == "root@pam"
        assert cfg.options["vmid"] == 105
        assert cfg.options["node"] == "pve-node1"
        assert cfg.options["token_id"] == "uniconn"
        assert cfg.options["secret"] == "super-secret-token-val"
        assert cfg.options["verify_ssl"] is False
        assert "super-secret-token-val" not in cfg.uri_safe
        assert cfg.uri_safe == "pve://root@pam@pve-host:8006/105"

    def test_pve_password_uri_with_inline_env_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PVE_PASS", "my-pam-password")
        uri = "pve://root@pam:env://PVE_PASS@pve-host:8006/105?node=pve-node1&verify_ssl=true"
        cfg = URIParser.parse(uri)
        assert cfg.transport == "pve"
        assert cfg.host == "pve-host"
        assert cfg.port == 8006
        assert cfg.username == "root@pam"
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "my-pam-password"
        assert cfg.options["vmid"] == 105
        assert cfg.options["node"] == "pve-node1"
        assert cfg.options["verify_ssl"] is True
        assert "my-pam-password" not in cfg.uri_safe

    def test_pve_bang_token_syntax_in_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PVE_SECRET", "tok-secret-999")
        uri = "pve://root@pam!automation:env://PVE_SECRET@pve-cluster.local:8006/204"
        cfg = URIParser.parse(uri)
        assert cfg.username == "root@pam"
        assert cfg.options["token_id"] == "automation"
        assert cfg.options["secret"] == "tok-secret-999"
        assert cfg.options["vmid"] == 204
        rebuilt = URIParser.build("pve", host=cfg.host, port=cfg.port, username=cfg.username, options={"vmid": 204, "node": "pve1"})
        assert rebuilt == "pve://root@pam@pve-cluster.local:8006/204?node=pve1"


class TestQgaTransportAndMockServer:
    """Тесты QgaTransport поверх MockQgaServer (in-memory и UNIX domain socket)."""

    async def test_qga_in_memory_exec_ping_and_capabilities(self) -> None:
        mock_qga = MockQgaServer(
            hostname="vm-web-01",
            command_handlers={
                "ip link set dev eth0 up": (0, "eth0 link up\n", ""),
            },
            polls_before_exit=2,
        )
        cfg = ConnectionConfig.from_uri("qga:///tmp/mock.sock")
        transport = QgaTransport(cfg, channel=mock_qga)
        conn = Connection(transport, cfg)

        async with conn:
            assert supports_capability(conn.transport, CommandTransport) is True
            assert supports_capability(conn.transport, FileCapableTransport) is True
            assert supports_capability(conn.transport, ShellCapableTransport) is False

            ping = await conn.ping()
            assert ping.alive is True

            res = await conn.run("ip link set dev eth0 up")
            assert res.ok
            assert res.stdout.strip() == "eth0 link up"

            chunks = [line async for line in conn.stream("echo line1\necho line2")]
            assert "".join(chunks).strip().startswith("line1")

            with pytest.raises(CapabilityNotSupportedError):
                await conn.open_shell()

    @pytest.mark.skipif(sys.platform == "win32", reason="UNIX domain sockets test requires POSIX")
    async def test_qga_real_unix_domain_socket_handshake_and_files(self, tmp_path: Path) -> None:
        sock_path = tmp_path / "qga_test.sock"
        large_payload = b"0123456789abcdef" * 4096  # 64 KB (> 48 KB single chunk)

        async with MockQgaServer(
            socket_path=sock_path,
            files={"/etc/hostname": b"isolated-vm\n"},
        ) as server:
            conn = Connection.from_uri(f"qga://{sock_path}")
            async with conn:
                content = await conn.files.read_file("/etc/hostname", encoding="utf-8")
                assert content == "isolated-vm\n"

                # Запись большого бинарного файла чанками по 48 КБ и чтение обратно
                await conn.files.write_file("/var/tmp/blob.bin", large_payload, mode=0o600)
                read_back = await conn.files.read_file("/var/tmp/blob.bin", encoding=None)
                assert read_back == large_payload
                assert server.file_modes["/var/tmp/blob.bin"] == 0o600

                # Проверка stat, exists, listdir, remove_file
                st = await conn.files.stat("/var/tmp/blob.bin")
                assert st.st_size == len(large_payload)
                assert await conn.files.exists("/var/tmp/blob.bin") is True
                entries = await conn.files.listdir("/var/tmp")
                assert "blob.bin" in entries

                # Upload / Download
                local_src = tmp_path / "upload_src.txt"
                local_src.write_text("hello via qga upload\n", encoding="utf-8")
                await conn.files.upload(str(local_src), "/var/tmp/uploaded.txt")
                local_dst = tmp_path / "downloaded.txt"
                await conn.files.download("/var/tmp/uploaded.txt", str(local_dst))
                assert local_dst.read_text(encoding="utf-8") == "hello via qga upload\n"

                await conn.files.remove_file("/var/tmp/blob.bin")
                assert await conn.files.exists("/var/tmp/blob.bin") is False

    async def test_qga_hybrid_gather_facts_and_state_ensure_file(self) -> None:
        mock_qga = MockQgaServer(
            hostname="netbroken-vm",
            files={"/etc/netplan/01-netcfg.yaml": b"old_config\n"},
        )
        cfg = ConnectionConfig.from_uri("qga:///tmp/netbroken.sock")
        conn = Connection(QgaTransport(cfg, channel=mock_qga), cfg)

        async with conn:
            ensure_res = await conn.state.ensure_file(
                "/etc/netplan/01-netcfg.yaml",
                content="network:\n  version: 2\n",
                mode=0o600,
                sudo=False,
            )
            assert ensure_res.changed is True
            assert mock_qga.files["/etc/netplan/01-netcfg.yaml"] == b"network:\n  version: 2\n"

            # Повторный вызов идемпотентен
            ensure_res2 = await conn.state.ensure_file(
                "/etc/netplan/01-netcfg.yaml",
                content="network:\n  version: 2\n",
                mode=0o600,
                sudo=False,
            )
            assert ensure_res2.changed is False

            # Сбор гибридных фактов (включая нативные интерфейсы guest-network-get-interfaces)
            facts = await conn.gather_facts(refresh=True)
            assert facts.hostname == "netbroken-vm"
            assert facts.os_family == "Debian"
            assert "qga" in facts.custom
            by_if = {iface.name: iface for iface in facts.interfaces}
            assert "eth0" in by_if
            assert by_if["eth0"].mac == "52:54:00:12:34:56"
            assert "10.20.30.40" in by_if["eth0"].ipv4
            assert "fe80::5054:ff:fe12:3456" in by_if["eth0"].ipv6

    async def test_qga_exec_timeout_kills_guest_pid(self) -> None:
        mock_qga = MockQgaServer(polls_before_exit=9999)
        client = QgaProtocolClient(mock_qga, poll_interval=0.01, max_poll_interval=0.02)
        await client.connect()
        with pytest.raises(TimeoutError, match="timed out"):
            await client.exec_command("/bin/sh", ["-c", "sleep 100"], timeout=0.05)
        # Проверить, что процесс был принудительно убит в гостевой ОС
        assert mock_qga._processes[1000]["exited"] is True
        assert mock_qga._processes[1000]["exitcode"] == 137

    async def test_qga_virsh_channel_and_ssh_socket_channel(self) -> None:
        # 1. Тест VirshCommandChannel через локальный subprocess mock
        virsh_ch = VirshCommandChannel(domain="vm-prod-01")
        with patch("asyncio.create_subprocess_shell") as mock_subproc:
            proc_mock = MagicMock()
            proc_mock.returncode = 0
            proc_mock.communicate = AsyncMock(return_value=(b'{"return":{}}\n', b""))
            mock_subproc.return_value = proc_mock

            await virsh_ch.open(timeout=5.0)
            assert virsh_ch.is_open is True
            await virsh_ch.close()

        # 2. Тест SshUnixSocketChannel с автоопределением сокета
        ssh_ch = SshUnixSocketChannel(host="kvm-01", username="root", vm_name="105")
        reader = asyncio.StreamReader()
        reader.feed_data(b"\xff" + b'{"return":12345}\n')
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        ssh_conn_mock = MagicMock()
        ssh_conn_mock.run = AsyncMock(return_value=MagicMock(stdout="/run/qemu-server/105.qga\n"))
        ssh_conn_mock.open_unix_connection = AsyncMock(return_value=(reader, writer))
        ssh_conn_mock.close = MagicMock()
        ssh_conn_mock.wait_closed = AsyncMock()

        with (
            patch("asyncssh.connect", AsyncMock(return_value=ssh_conn_mock)),
            patch("random.randint", return_value=12345),
        ):
            await ssh_ch.open(timeout=5.0)
            assert ssh_ch.socket_path == "/run/qemu-server/105.qga"
            await ssh_ch.close()


class TestPveTransportAndMockServer:
    """Тесты PveTransport поверх MockPveServer (Token auth, Ticket+CSRF auth, QGA, Power, Snapshots)."""

    def _make_pve_connection(
        self,
        uri: str,
        mock_server: MockPveServer,
    ) -> Connection:
        cfg = ConnectionConfig.from_uri(uri)
        transport = PveTransport(cfg)
        http_client = transport._build_http_client()
        http_client.create_async_session = lambda: mock_server  # type: ignore[method-assign]
        transport._custom_http_client = http_client
        return Connection(transport, cfg)

    async def test_pve_token_auth_auto_node_discovery_and_exec(self) -> None:
        mock_pve = MockPveServer(node="pve-node2", vmid=105)
        uri = "pve://root@pam!uniconn:token-secret-123@pve.local:8006/105?verify_ssl=false"
        conn = self._make_pve_connection(uri, mock_pve)

        async with conn:
            # Нода должна автоматически определиться через /api2/json/cluster/resources
            assert isinstance(conn.transport, PveTransport)
            assert conn.transport.node == "pve-node2"

            ping = await conn.ping()
            assert ping.alive is True

            res = await conn.run("echo hello_from_pve_qga")
            assert res.ok
            assert res.stdout.strip() == "hello_from_pve_qga"

    async def test_pve_ticket_csrf_auth_files_and_facts(self) -> None:
        mock_pve = MockPveServer(node="pve-node1", vmid=105)
        mock_pve.qga.files["/etc/resolv.conf"] = b"nameserver 1.1.1.1\n"
        uri = "pve://root@pam:secret-pass@pve.local:8006/105?node=pve-node1&verify_ssl=false"
        conn = self._make_pve_connection(uri, mock_pve)

        async with conn:
            # 1. Чтение файла через GET /agent/file-read
            dns = await conn.files.read_file("/etc/resolv.conf", encoding="utf-8")
            assert dns == "nameserver 1.1.1.1\n"
            assert any(
                m == "GET" and "/agent/file-read" in p
                for m, p, _ in mock_pve.requests_log
            )

            # 2. Запись бинарного файла через POST /agent/file-write с encode=1
            await conn.files.write_file("/etc/custom.bin", b"\x00\x01\xfe\xff", mode=0o600)
            assert mock_pve.qga.files["/etc/custom.bin"] == b"\x00\x01\xfe\xff"
            assert any(
                m == "POST" and "/agent/file-write" in p and (b or {}).get("encode") == 1
                for m, p, b in mock_pve.requests_log
            )

            # 3. Гибридный сбор фактов
            facts = await conn.gather_facts(refresh=True)
            assert facts.hostname == "pve-vm-105"
            assert "pve" in facts.custom
            assert facts.custom["pve"]["vm_status"]["status"] == "running"
            assert any(i.name == "eth0" and "10.20.30.40" in i.ipv4 for i in facts.interfaces)

    async def test_pve_hypervisor_power_and_snapshot_commands(self) -> None:
        mock_pve = MockPveServer(node="pve-node1", vmid=105)
        uri = "pve://root@pam!uniconn:token-secret-123@pve.local:8006/105?node=pve-node1"
        conn = self._make_pve_connection(uri, mock_pve)

        async with conn:
            # Проверка статуса питания ВМ
            st_res = await conn.run("pve power status")
            assert st_res.json()["status"] == "running"

            # Остановка и запуск ВМ с ожиданием UPID
            stop_res = await conn.run("pve power stop")
            assert stop_res.json()["action"] == "stop"
            assert mock_pve.vm_state == "stopped"

            start_res = await conn.run("pve power start")
            assert start_res.json()["action"] == "start"
            assert mock_pve.vm_state == "running"

            # Создание, список, откат и удаление снапшотов
            create_snap = await conn.run(
                "pve snapshot create before_upgrade --description 'Pre-upgrade snapshot' --vmstate"
            )
            assert create_snap.json()["snapshot"] == "before_upgrade"

            list_snap = await conn.run("pve snapshot list")
            snap_names = [s["name"] for s in json.loads(list_snap.stdout)]
            assert "before_upgrade" in snap_names

            rb_snap = await conn.run("pve snapshot rollback before_upgrade")
            assert rb_snap.json()["action"] == "rolled_back"

            del_snap = await conn.run("pve snapshot delete before_upgrade")
            assert del_snap.json()["action"] == "deleted"

    def test_pve_sync_connection_and_cassette_replay(self, tmp_path: Path) -> None:
        mock_qga = MockQgaServer(hostname="sync-qga-vm")
        cfg = ConnectionConfig.from_uri("qga:///tmp/sync_qga.sock")
        async_conn = Connection(QgaTransport(cfg, channel=mock_qga), cfg)
        sync_conn: SyncConnection = async_conn.to_sync()
        cassette_file = tmp_path / "qga_session.yaml"

        with sync_conn:
            with sync_conn.use_cassette(cassette_file, mode="all"):
                res = sync_conn.run("echo sync_parity_ok")
                assert res.ok
                assert res.text == "sync_parity_ok"

        assert cassette_file.exists()
        # Воспроизведение из записанной кассеты без реального QGA-канала
        replay_conn = SyncConnection.from_uri(f"replay://qga?cassette={cassette_file}")
        with replay_conn:
            rep_res = replay_conn.run("echo sync_parity_ok")
            assert rep_res.text == "sync_parity_ok"

    def test_pve_missing_vmid_or_niquests_raises(self) -> None:
        cfg_no_vmid = ConnectionConfig.from_uri("pve://root@pam:pass@pve.local:8006")
        with pytest.raises(ConfigurationError, match="VMID"):
            PveTransport(cfg_no_vmid)

        with patch("uniconn.transports.virtualization.pve.niquests", None), patch(
            "uniconn.transports.virtualization.pve_client.niquests", None
        ):
            cfg = ConnectionConfig.from_uri("pve://root@pam:pass@pve.local:8006/105")
            with pytest.raises(ImportError, match=r"uniconn\[bmc\]"):
                PveTransport(cfg)

    async def test_qga_and_pve_cd_env_stdin_and_sudo_pipeline(self) -> None:
        from uniconn.exceptions import FileTransferError
        from uniconn.mcp.registry import mask_uri_secrets

        # 1. QGA: проверка cd(), env(), input и sudo_password через пайплайн Connection
        mock_qga = MockQgaServer(hostname="ctx-vm")
        cfg = ConnectionConfig.from_uri("qga:///tmp/ctx.sock")
        conn = Connection(QgaTransport(cfg, channel=mock_qga), cfg)

        async with conn:
            async with conn.cd("/srv/app"), conn.env(APP_ENV="staging"):
                await conn.run("pwd")
                assert "cd /srv/app && pwd" in mock_qga.executed_commands[-1]
                assert mock_qga.last_env == ["APP_ENV=staging"]

            cat_res = await conn.run("cat", input="hello_stdin_stream\n")
            assert cat_res.stdout == "hello_stdin_stream\n"

            await conn.run("id", sudo=True, sudo_password="my_sudo_pass")
            assert mock_qga.last_input_data == b"my_sudo_pass\n"

        # 2. PVE: проверка cd(), env(), input и fallback чтения при truncated=1
        mock_pve = MockPveServer(node="pve-node1", vmid=105)
        mock_pve.qga.files["/var/log/large.log"] = b"full_untruncated_payload_12345\n"
        mock_pve.force_truncate_reads = True  # type: ignore[attr-defined]
        pve_conn = self._make_pve_connection(
            "pve://root@pam!uniconn:token-secret-123@pve.local:8006/105?node=pve-node1",
            mock_pve,
        )
        async with pve_conn:
            async with pve_conn.cd("/opt/service"), pve_conn.env(SERVICE_MODE="ha"):
                await pve_conn.run(" ./run.sh")
                last_cmd = mock_pve.qga.executed_commands[-1]
                assert "export SERVICE_MODE=ha;" in last_cmd
                assert "cd /opt/service &&" in last_cmd

            pve_cat = await pve_conn.run("cat", input="pve_stdin_ok")
            assert pve_cat.stdout == "pve_stdin_ok"

            # При truncated=1 PveTransport автоматически дочитывает файл через base64 exec fallback
            data = await pve_conn.files.read_file("/var/log/large.log", encoding="utf-8")
            assert data == "full_untruncated_payload_12345\n"

        # 3. Защита от бесконечного цикла / порчи файла при count=0 в guest-file-write
        zero_write_qga = MockQgaServer()
        zero_write_qga._rpc_file_write = lambda args: {"count": 0, "eof": False}  # type: ignore[method-assign]
        client = QgaProtocolClient(zero_write_qga)
        await client.connect()
        with pytest.raises(FileTransferError, match="0 bytes written"):
            await client.write_file("/tmp/broken.bin", b"data")

        # 4. Маскирование секретов в MCP mask_uri_secrets для pve:// с inline env:// и token_secret
        masked1 = mask_uri_secrets(
            "pve://root@pam:env://PVE_PASS@pve.local:8006/105?token_secret=abc12345&node=pve1"
        )
        assert "PVE_PASS" not in masked1
        assert "abc12345" not in masked1
        assert "***REDACTED***" in masked1

    async def test_qga_windows_guest_auto_detection_and_file_ops(self) -> None:
        win_qga = MockQgaServer(
            hostname="win-srv-2022",
            osinfo={
                "id": "mswindows",
                "name": "Microsoft Windows",
                "pretty-name": "Windows Server 2022 Datacenter",
                "version-id": "2022",
                "kernel-release": "20348",
                "machine": "x86_64",
            },
            files={r"C:\Temp\app.conf": b"port=8080\r\n"},
        )
        cfg = ConnectionConfig.from_uri("qga:///tmp/win_qga.sock")
        conn = Connection(QgaTransport(cfg, channel=win_qga), cfg)

        async with conn:
            assert isinstance(conn.transport, QgaTransport)
            assert conn.transport._is_windows is True

            assert await conn.files.exists(r"C:\Temp\app.conf") is True
            st = await conn.files.stat(r"C:\Temp\app.conf")
            assert st.st_size == 11
            entries = await conn.files.listdir(r"C:\Temp")
            assert "app.conf" in entries

            await conn.files.mkdir(r"C:\Temp\SubDir")
            await conn.files.remove_file(r"C:\Temp\app.conf")
            assert await conn.files.exists(r"C:\Temp\app.conf") is False

            facts = await conn.gather_facts(refresh=True)
            assert facts.os_family == "Windows"
            assert facts.hostname == "win-srv-2022"
            assert "qga" in facts.custom

