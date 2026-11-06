# tests/unit/transports/test_winrm_transport.py
"""Комплексные unit-тесты для WinRM / PowerShell Remoting (winrm:// и wsman://)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from uniconn import (
    AuthenticationError,
    Connection,
    ConnectionConfig,
    ConnectionError,
    TimeoutError,
    URIParser,
    WinRMTransport,
)
from uniconn.background import (
    BackgroundCleanupManager,
    BackgroundLogCollector,
    BackgroundSession,
    WindowsJobBackend,
    resolve_backend,
)
from uniconn.plugins._loader import TransportLoader
from uniconn.transports._winrm import (
    build_powershell_encoded_command,
    clean_clixml_stderr,
)
from uniconn.transports.base import FileCapableTransport, supports_capability


def _decode_ps_script_from_args(args: list[str] | None) -> str:
    """Декодировать UTF-16LE Base64 скрипт из аргументов powershell -EncodedCommand."""
    assert args is not None
    idx = args.index("-EncodedCommand")
    b64 = args[idx + 1]
    return base64.b64decode(b64).decode("utf-16-le")


class FakeWinRMProtocol:
    """Фейковый pywinrm Protocol для детерминированного тестирования в памяти."""

    def __init__(self, **kwargs: object) -> None:
        self.init_kwargs = kwargs
        self.operation_timeout_sec = kwargs.get("operation_timeout_sec", 20)
        self.read_timeout_sec = kwargs.get("read_timeout_sec", 30)
        self.opened_shells: list[dict[str, object]] = []
        self.closed_shells: list[str] = []
        self.commands: list[tuple[str, str, list[str]]] = []
        self.cleaned_commands: list[tuple[str, str]] = []
        self.fs_files: dict[str, bytes] = {}
        self.fs_dirs: set[str] = {"C:\\", "C:\\Temp", "C:\\App"}
        self.custom_handler = None
        self.fail_open_shell: Exception | None = None

    def open_shell(self, **kwargs: object) -> str:
        if self.fail_open_shell is not None:
            raise self.fail_open_shell
        shell_id = f"shell-{len(self.opened_shells) + 1}"
        self.opened_shells.append({"id": shell_id, **kwargs})
        return shell_id

    def close_shell(self, shell_id: str) -> None:
        self.closed_shells.append(shell_id)

    def run_command(
        self,
        shell_id: str,
        command: str,
        arguments: list[str] | tuple[str, ...] = (),
    ) -> str:
        args_list = list(arguments)
        self.commands.append((shell_id, command, args_list))
        return f"cmd-{len(self.commands)}"

    def cleanup_command(self, shell_id: str, command_id: str) -> None:
        self.cleaned_commands.append((shell_id, command_id))

    def get_command_output(self, shell_id: str, command_id: str) -> tuple[bytes, bytes, int]:
        idx = int(command_id.split("-")[1]) - 1
        _, command, args = self.commands[idx]
        if self.custom_handler is not None:
            return self.custom_handler(command, args)
        if command.lower() == "powershell" and "-EncodedCommand" in args:
            ps_script = _decode_ps_script_from_args(args)
            return self._handle_ps_script(ps_script)
        return f"cmd:{command} {' '.join(args)}".encode(), b"", 0

    def _norm(self, path: str) -> str:
        p = path.replace("/", "\\")
        if len(p) > 3 and p.endswith("\\"):
            p = p.rstrip("\\")
        return p

    def _handle_ps_script(self, script: str) -> tuple[bytes, bytes, int]:
        # Test-Path (exists)
        if "if (Test-Path -LiteralPath " in script and "exit 0 } else { exit 1 }" in script:
            target = script.split("Test-Path -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            exists = norm in self.fs_files or norm in self.fs_dirs
            return b"", b"", (0 if exists else 1)

        # stat
        if "$item = Get-Item -LiteralPath '" in script and "ConvertTo-Json -Compress" in script:
            target = script.split("Get-Item -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            if norm in self.fs_dirs:
                payload = {
                    "size": 0,
                    "is_dir": True,
                    "is_file": False,
                    "is_symlink": False,
                    "mtime": 1700000000.0,
                    "atime": 1700000000.0,
                    "readonly": False,
                }
                return json.dumps(payload).encode("utf-8"), b"", 0
            if norm in self.fs_files:
                payload = {
                    "size": len(self.fs_files[norm]),
                    "is_dir": False,
                    "is_file": True,
                    "is_symlink": False,
                    "mtime": 1700000000.0,
                    "atime": 1700000000.0,
                    "readonly": False,
                }
                return json.dumps(payload).encode("utf-8"), b"", 0
            return b"", b"ItemNotFoundException", 2

        # listdir
        if "Get-ChildItem -LiteralPath '" in script and "ConvertTo-Json -InputObject $items" in script:
            target = script.split("Get-ChildItem -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            if norm not in self.fs_dirs:
                return b"", b"DirectoryNotFoundException", 2
            prefix = norm + "\\"
            names: set[str] = set()
            for fpath in list(self.fs_files) + list(self.fs_dirs):
                if fpath.startswith(prefix):
                    rel = fpath[len(prefix) :]
                    if rel and "\\" not in rel:
                        names.add(rel)
            return json.dumps(sorted(names)).encode("utf-8"), b"", 0

        # mkdir
        if "New-Item -ItemType Directory -Path '" in script:
            target = script.split("New-Item -ItemType Directory -Path '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            parts = norm.split("\\")
            cur = parts[0]
            for part in parts[1:]:
                cur = f"{cur}\\{part}"
                self.fs_dirs.add(cur)
            return b"", b"", 0

        # remove_file
        if "Remove-Item -LiteralPath '" in script:
            target = script.split("Remove-Item -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            self.fs_files.pop(norm, None)
            return b"", b"", 0

        # read_file
        if "[System.IO.File]::ReadAllBytes($item.FullName)" in script:
            target = script.split("Get-Item -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm = self._norm(target)
            if norm not in self.fs_files:
                return b"", b"FileNotFoundException", 2
            b64 = base64.b64encode(self.fs_files[norm]).decode("ascii")
            return b64.encode("ascii"), b"", 0

        # write_file / upload chunk
        if "[Convert]::FromBase64String('" in script:
            target = script.split("Combine((Get-Location).Path, '", 1)[1].split("'", 1)[0].replace("''", "'")
            b64 = script.split("FromBase64String('", 1)[1].split("'", 1)[0]
            raw = base64.b64decode(b64)
            norm = self._norm(target)
            if "WriteAllBytes($p, $bytes)" in script or norm not in self.fs_files:
                self.fs_files[norm] = raw
            else:
                self.fs_files[norm] += raw
            return b"", b"", 0

        # atomic Move-Item
        if "Move-Item -LiteralPath '" in script:
            src = script.split("Move-Item -LiteralPath '", 1)[1].split("'", 1)[0].replace("''", "'")
            dst = script.split("-Destination '", 1)[1].split("'", 1)[0].replace("''", "'")
            norm_src = self._norm(src)
            norm_dst = self._norm(dst)
            self.fs_files[norm_dst] = self.fs_files.pop(norm_src, b"")
            return b"", b"", 0

        return f"ps:{script}".encode(), b"", 0


def _make_fake_winrm_module(proto: FakeWinRMProtocol) -> SimpleNamespace:
    return SimpleNamespace(Protocol=MagicMock(return_value=proto))


class TestWinRMUriAndPluginLoader:
    """Тесты парсинга/сборки URI winrm:// и wsman:// и регистрации плагинов."""

    def test_uri_parse_winrm_defaults_and_options(self) -> None:
        cfg = URIParser.parse(
            "winrm://Administrator:Secret123@win-srv.local?transport=ntlm&server_cert_validation=ignore"
        )
        assert cfg.transport == "winrm"
        assert cfg.host == "win-srv.local"
        assert cfg.port == 5985
        assert cfg.username == "Administrator"
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "Secret123"
        assert cfg.options["transport"] == "ntlm"
        assert cfg.options["server_cert_validation"] == "ignore"

    def test_uri_parse_wsman_ssl_port_5986(self) -> None:
        cfg_ssl = URIParser.parse("wsman://admin:pass@win-srv.local?ssl=true&transport=kerberos")
        assert cfg_ssl.transport == "wsman"
        assert cfg_ssl.port == 5986
        assert cfg_ssl.options["ssl"] is True
        assert cfg_ssl.options["transport"] == "kerberos"

        cfg_https = URIParser.parse("winrm://admin:pass@win-srv.local?scheme=https")
        assert cfg_https.port == 5986

        cfg_transport_ssl = URIParser.parse("winrm://admin:pass@win-srv.local?transport=ssl")
        assert cfg_transport_ssl.port == 5986

    def test_uri_roundtrip_build(self) -> None:
        cfg = URIParser.parse("winrm://admin:pass@10.0.0.50:5986?transport=credssp")
        rebuilt = URIParser.build(
            transport=cfg.transport,
            host=cfg.host,
            port=cfg.port,
            username=cfg.username,
            password="pass",
            options=cfg.options,
        )
        assert rebuilt.startswith("winrm://admin:pass@10.0.0.50:5986")
        assert "transport=credssp" in rebuilt

    def test_transport_loader_registers_winrm_and_wsman(self) -> None:
        assert TransportLoader.get("winrm") is WinRMTransport
        assert TransportLoader.get("wsman") is WinRMTransport
        available = TransportLoader.list_available()
        assert "winrm" in available
        assert "wsman" in available


class TestClixmlAndPowerShellEncoding:
    """Тесты очистки CLIXML stderr и кодирования PowerShell команд."""

    def test_clean_clixml_extracts_error_and_ignores_progress(self) -> None:
        clixml = (
            "#< CLIXML\r\n"
            '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'
            '<Obj S="progress" RefId="0"><MS><I64 N="SourceId">1</I64></MS></Obj>'
            '<S S="Error">Get-Item : Cannot find path_x000D__x000A_</S>'
            '<S S="Error">At line:1 char:1_x000A_</S>'
            '<S S="warning">Low disk space</S>'
            "</Objs>"
        )
        cleaned = clean_clixml_stderr(clixml)
        assert "Get-Item : Cannot find path\nAt line:1 char:1" in cleaned
        assert "WARNING: Low disk space" in cleaned
        assert "SourceId" not in cleaned

    def test_clean_clixml_surrogate_pairs_and_multiple_headers(self) -> None:
        # U+1F680 (🚀) in UTF-16LE surrogate pair: D83D DE80
        clixml = (
            "#< CLIXML\n"
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
            '<S S="Error">Rocket _xD83D__xDE80_ failed!</S>'
            "</Objs>"
            "#< CLIXML\n"
            '<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">'
            '<S S="Error"> Second error</S>'
            "</Objs>"
        )
        cleaned = clean_clixml_stderr(clixml)
        assert cleaned == "Rocket 🚀 failed! Second error"
        assert cleaned.encode("utf-8")

    def test_build_powershell_encoded_command_includes_cwd_env_and_input(self) -> None:
        exe, args = build_powershell_encoded_command(
            "Write-Output $env:GREETING",
            cwd="C:\\Work\\Project's",
            env={"GREETING": "Hello 'World'"},
            input_data="some input",
        )
        assert exe == "powershell"
        decoded = _decode_ps_script_from_args(args)
        assert "Set-Location -LiteralPath 'C:\\Work\\Project''s' -ErrorAction Stop" in decoded
        assert "$env:GREETING = 'Hello ''World'''" in decoded
        assert "$__uniconn_input = 'some input'" in decoded
        assert "Write-Output $env:GREETING" in decoded


class TestWinRMTransportExecution:
    """Тесты жизненного цикла, выполнения команд (PS и CMD), стриминга и ошибок."""

    async def test_connect_run_ps_and_cmd_and_disconnect(self) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            cfg = URIParser.parse(
                "winrm://CORP\\Administrator:Pass@win-host?transport=ntlm&server_cert_validation=ignore"
            )
            transport = WinRMTransport(cfg)
            assert supports_capability(transport, FileCapableTransport)

            await transport.connect()
            assert transport.is_connected
            assert fake_mod.Protocol.call_args.kwargs["endpoint"] == "http://win-host:5985/wsman"
            assert fake_mod.Protocol.call_args.kwargs["transport"] == "ntlm"
            assert fake_mod.Protocol.call_args.kwargs["server_cert_validation"] == "ignore"
            assert fake_mod.Protocol.call_args.kwargs["username"] == "CORP\\Administrator"

            # Default shell is PowerShell
            res_ps = await transport.run("Get-Date", cwd="C:\\App", env={"STAGE": "prod"})
            assert res_ps.ok
            _, cmd_exe, cmd_args = proto.commands[-1]
            assert cmd_exe == "powershell"
            decoded = _decode_ps_script_from_args(cmd_args)
            assert "Set-Location -LiteralPath 'C:\\App' -ErrorAction Stop" in decoded
            assert "$env:STAGE = 'prod'" in decoded
            assert "Get-Date" in decoded

            # Explicit shell="cmd"
            res_cmd = await transport.run("dir /b", shell="cmd", cwd="C:\\App", env={"FOO": "bar"})
            assert res_cmd.ok
            _, cmd_exe2, cmd_args2 = proto.commands[-1]
            assert 'cd /d "C:\\App" && dir /b' in cmd_exe2
            assert cmd_args2 == []
            assert proto.opened_shells[-1]["working_directory"] == "C:\\App"
            assert proto.opened_shells[-1]["env_vars"] == {"FOO": "bar"}

            # Ping check
            assert await transport.ping() is True

            await transport.disconnect()
            assert not transport.is_connected

    async def test_timeout_restores_protocol_timeouts(self) -> None:
        proto = FakeWinRMProtocol(operation_timeout_sec=20, read_timeout_sec=30)
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            cfg = ConnectionConfig(transport="winrm", host="win-host", username="admin", password="pwd")
            transport = WinRMTransport(cfg)
            await transport.connect()
            orig_op = proto.operation_timeout_sec
            orig_read = proto.read_timeout_sec

            await transport.run("Get-Process", timeout=5.0)
            assert proto.operation_timeout_sec == orig_op
            assert proto.read_timeout_sec == orig_read

    async def test_error_mapping_auth_timeout_connection(self) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            cfg = ConnectionConfig(transport="winrm", host="win-host", username="admin", password="pwd")
            transport = WinRMTransport(cfg)
            await transport.connect()

            proto.fail_open_shell = Exception("401 Unauthorized: InvalidCredentialsError")
            with pytest.raises(AuthenticationError):
                await transport.run("whoami")

            proto.fail_open_shell = Exception("Read timed out (read timeout=30)")
            with pytest.raises(TimeoutError):
                await transport.run("whoami")

            proto.fail_open_shell = Exception("Connection refused by remote host")
            with pytest.raises(ConnectionError):
                await transport.run("whoami")

    async def test_stream_yields_lines_incrementally_with_raw_poll(self) -> None:
        proto = FakeWinRMProtocol()
        chunks = [
            (b"line 1\r\nli", b"", 0, False),
            (b"ne 2\r\nline 3", b"", 0, True),
        ]
        proto._raw_get_command_output = MagicMock(side_effect=chunks)  # type: ignore[attr-defined]
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            cfg = ConnectionConfig(transport="winrm", host="win-host", username="admin", password="pwd")
            transport = WinRMTransport(cfg)
            await transport.connect()
            collected = [line async for line in transport.stream("Get-Content -Wait app.log")]
            assert collected == ["line 1\r\n", "line 2\r\n", "line 3"]


class TestWinRMFileOperationsAndDomainServices:
    """Тесты FileCapableTransport (conn.files), gather_facts, temp_dir, run_script, wait_for_port и BackgroundSession."""

    async def test_file_capable_transport_and_conn_files(self, tmp_path: Path) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            async with Connection.from_uri("winrm://admin:pass@win-host") as conn:
                # Write & Read (including atomic=True and multi-chunk data)
                large_text = "Привет WinRM! " * 12000  # > 131072 bytes -> multiple chunks
                await conn.files.write_file("C:\\Temp\\big.txt", large_text, atomic=True)
                assert await conn.files.exists("C:\\Temp\\big.txt") is True

                stat_info = await conn.files.stat("C:\\Temp\\big.txt")
                assert stat_info["size"] == len(large_text.encode("utf-8"))
                assert stat_info["is_dir"] is False

                read_back = await conn.files.read_file("C:\\Temp\\big.txt")
                assert read_back == large_text

                # mkdir & listdir
                await conn.files.mkdir("C:\\Temp\\SubDir")
                entries = await conn.files.listdir("C:\\Temp")
                assert "big.txt" in entries
                assert "SubDir" in entries

                # upload & download single file
                local_src = tmp_path / "local.bin"
                local_src.write_bytes(b"\x00\x01\x02\xff" * 100)
                await conn.files.upload(local_src, "C:\\Temp\\uploaded.bin")
                local_dst = tmp_path / "downloaded.bin"
                await conn.files.download("C:\\Temp\\uploaded.bin", local_dst)
                assert local_dst.read_bytes() == local_src.read_bytes()

                # remove_file
                await conn.files.remove_file("C:\\Temp\\uploaded.bin")
                assert await conn.files.exists("C:\\Temp\\uploaded.bin") is False

    async def test_windows_cwd_context_and_path_joining(self) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            conn = Connection.from_uri("winrm://admin:pass@win-host")
            async with conn.cd("C:\\Program Files"), conn.cd("MyApp\\bin"):
                await conn.run("app.exe --version")

            _, _, args = proto.commands[-1]
            decoded = _decode_ps_script_from_args(args)
            assert "Set-Location -LiteralPath 'C:\\Program Files\\MyApp\\bin' -ErrorAction Stop" in decoded

    async def test_gather_facts_on_winrm_includes_cim_and_interfaces(self) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)

        def _facts_handler(command: str, args: list[str]) -> tuple[bytes, bytes, int]:
            payload = {
                "distro": "Microsoft Windows Server 2022 Datacenter",
                "kernel": "10.0.20348",
                "arch": "64-bit",
                "hostname": "WIN-SRV-01",
                "uptime": 7200.5,
                "cpu_count": 8,
                "mem_total": 17179869184,
                "mem_avail": 8589934592,
                "disks": [
                    {
                        "device": "C:",
                        "total": 100000000000,
                        "free": 60000000000,
                        "fstype": "NTFS",
                    }
                ],
                "interfaces": [
                    {
                        "name": "Intel(R) PRO/1000 MT Network Connection",
                        "mac": "00:15:5D:01:02:03",
                        "ipv4": ["10.0.0.50"],
                        "ipv6": ["fe80::1"],
                        "state": "UP",
                        "mtu": 1500,
                    }
                ],
            }
            return json.dumps(payload).encode("utf-8"), b"", 0

        proto.custom_handler = _facts_handler

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            conn = Connection.from_uri("winrm://admin:pass@win-srv-01")
            facts = await conn.gather_facts()
            assert facts.os_family == "Windows"
            assert facts.distro == "Microsoft Windows Server 2022 Datacenter"
            assert facts.hostname == "WIN-SRV-01"
            assert facts.cpu_count == 8
            assert len(facts.disks) == 1
            assert facts.disks[0].mountpoint == "C:\\"
            assert len(facts.interfaces) == 1
            assert facts.interfaces[0].ipv4 == ["10.0.0.50"]
            assert facts.interfaces[0].mac == "00:15:5D:01:02:03"

    async def test_temp_dir_run_script_and_wait_for_port_on_winrm(self, tmp_path: Path) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)
        executed_scripts: list[str] = []

        def _handler(command: str, args: list[str]) -> tuple[bytes, bytes, int]:
            ps_script = _decode_ps_script_from_args(args)
            executed_scripts.append(ps_script)
            if "New-Item -ItemType Directory" in ps_script and "Get-Random" in ps_script:
                return b"C:\\Users\\Admin\\AppData\\Local\\Temp\\uniconn_12345\r\n", b"", 0
            if "System.Net.Sockets.TcpClient" in ps_script:
                return b"", b"", 0
            return b"script-ok\r\n", b"", 0

        proto.custom_handler = _handler

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            conn = Connection.from_uri("winrm://admin:pass@win-host")

            # wait_for_port (remote PowerShell TcpClient check)
            elapsed = await conn.wait_for_port(3389, check_from="remote", timeout=5.0)
            assert elapsed >= 0.0
            assert any("System.Net.Sockets.TcpClient" in s for s in executed_scripts)

            # run_script on WinRM
            local_ps1 = tmp_path / "deploy.ps1"
            local_ps1.write_text("Write-Output 'Deployed'", encoding="utf-8")
            res = await conn.run_script(local_ps1, args=["--env", "prod"])
            assert res.ok
            assert any("deploy.ps1" in s and "--env" in s for s in executed_scripts)

    async def test_background_session_and_log_collector_on_winrm(self) -> None:
        proto = FakeWinRMProtocol()
        fake_mod = _make_fake_winrm_module(proto)
        alive_state = {"alive": False}

        def _bg_handler(command: str, args: list[str]) -> tuple[bytes, bytes, int]:
            ps_script = _decode_ps_script_from_args(args)
            if "Start-Process -FilePath 'powershell'" in ps_script:
                alive_state["alive"] = True
                return b"", b"", 0
            if "Get-Process -Id $procId" in ps_script and "Write-Output $procId" in ps_script:
                return (b"4567\r\n" if alive_state["alive"] else b""), b"", 0
            if "Get-Process -Id $procId" in ps_script:
                return b"", b"", (0 if alive_state["alive"] else 1)
            if "Stop-Process" in ps_script:
                alive_state["alive"] = False
                return b"", b"", 0
            if "(Get-Item '/tmp/s1.log').Length" in ps_script:
                return b"12\r\n", b"", 0
            if "System.IO.StreamReader" in ps_script:
                return b"hello winrm\n", b"", 0
            if "Get-Content -Path '/tmp/uniconn_s1.exit'" in ps_script:
                return b"0\r\n", b"", 0
            return b"", b"", 0

        proto.custom_handler = _bg_handler

        with patch("uniconn.transports._winrm.winrm", fake_mod):
            conn = Connection.from_uri("winrm://admin:pass@win-host")
            backend = await resolve_backend(conn, "auto")
            assert isinstance(backend, WindowsJobBackend)

            session = BackgroundSession(conn, "s1", "/tmp/s1.log", backend="auto")
            assert session.script_path == "/tmp/uniconn_s1.ps1"
            await session.create("Start-Sleep -Seconds 5")
            assert await session.is_alive() is True
            assert await session.get_pid() == 4567

            collector = BackgroundLogCollector(conn)
            lines, new_offset = await collector.read_chunk(session)
            assert lines == ["hello winrm\n"]
            assert new_offset == 12

            await session.kill(graceful=False)
            assert await session.is_alive() is False
            assert await session.get_exit_code() == 0
            await session.cleanup()

            cleanup_mgr = BackgroundCleanupManager("pool_win")
            await cleanup_mgr.install_server_side(conn)
