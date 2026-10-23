"""Тесты новой модульной архитектуры, доменных сервисов, пайплайна и протоколов возможностей."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import pytest

from uniconn import (
    AptStrategy,
    CapabilityNotSupportedError,
    CommandMiddleware,
    CommandPipeline,
    CommandRequest,
    CommandTransport,
    Connection,
    ConnectionConfig,
    EventLoopPortal,
    FileCapableTransport,
    FileOperationsService,
    InventoryLoader,
    OpenSSHConfigParser,
    PackageManagerStrategy,
    PosixMarkerProtocol,
    Result,
    ServiceManagerStrategy,
    ShellCapableTransport,
    StateManagementService,
    SyncContextBridge,
    SyncFileOperationsService,
    SyncStateManagementService,
    SyncTunnelService,
    SystemdStrategy,
    TemplateEngine,
    TunnelCapableTransport,
    TunnelService,
    require_capability,
    supports_capability,
)
from uniconn.transports._local import LocalTransport
from uniconn.transports._serial import SerialTransport
from uniconn.transports._ssh import SSHTransport
from uniconn.transports._telnet import TelnetTransport

if TYPE_CHECKING:
    from pathlib import Path


class DummyTransport:
    """Минимальный транспорт только с поддержкой команд (CommandTransport)."""

    name = "dummy"

    def __init__(self) -> None:
        """Инициализировать минимальный транспорт."""
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Статус подключения."""
        return self._connected

    async def connect(self) -> None:
        """Установить подключение."""
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть подключение."""
        self._connected = False

    async def run(self, command: str, timeout: float | None = None, **kwargs: Any) -> Result:
        """Выполнить команду."""
        _ = (timeout, kwargs)
        return Result(command=command, stdout="ok\n", stderr="", exit_code=0, duration=0.01)

    async def stream(self, command: str, timeout: float | None = None, **kwargs: Any) -> AsyncIterator[str]:
        """Потоковый вывод."""
        _ = (command, timeout, kwargs)
        yield "ok"

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверка связи."""
        _ = timeout
        return self._connected


class CustomHeaderMiddleware:
    """Тестовый middleware, модифицирующий команду и результат."""

    def __init__(self, tag: str) -> None:
        """Инициализировать middleware с префиксным тегом."""
        self.tag = tag
        self.calls: list[str] = []

    async def __call__(self, request: CommandRequest, call_next: Any) -> Result:
        """Добавить запись о вызове и модифицировать stdout результата."""
        self.calls.append(request.command)
        res = await call_next(request)
        return Result(
            command=res.command,
            stdout=f"[{self.tag}] {res.stdout}",
            stderr=res.stderr,
            exit_code=res.exit_code,
            duration=res.duration,
            host=res.host,
        )


def test_capability_protocols_runtime_check() -> None:
    """Проверка соответствия транспортов протоколам возможностей (ISP)."""
    local = LocalTransport(ConnectionConfig(transport="local"))
    ssh = SSHTransport(ConnectionConfig(transport="ssh", host="example.com"))
    telnet = TelnetTransport(ConnectionConfig(transport="telnet", host="example.com"))
    serial = SerialTransport(ConnectionConfig.from_uri("serial:///dev/ttyUSB0"))
    dummy = DummyTransport()

    assert supports_capability(local, CommandTransport)
    assert supports_capability(local, FileCapableTransport)
    assert supports_capability(local, ShellCapableTransport)
    assert not supports_capability(local, TunnelCapableTransport)

    assert supports_capability(ssh, CommandTransport)
    assert supports_capability(ssh, FileCapableTransport)
    assert supports_capability(ssh, ShellCapableTransport)
    assert supports_capability(ssh, TunnelCapableTransport)

    assert supports_capability(telnet, CommandTransport)
    assert supports_capability(telnet, ShellCapableTransport)
    assert not supports_capability(telnet, FileCapableTransport)
    assert not supports_capability(telnet, TunnelCapableTransport)

    assert supports_capability(serial, CommandTransport)
    assert supports_capability(serial, ShellCapableTransport)
    assert not supports_capability(serial, FileCapableTransport)
    assert not supports_capability(serial, TunnelCapableTransport)

    assert isinstance(dummy, CommandTransport)
    assert not isinstance(dummy, FileCapableTransport)


def test_require_capability_raises_not_supported() -> None:
    """require_capability выбрасывает CapabilityNotSupportedError (подкласс NotImplementedError)."""
    dummy = DummyTransport()
    checked = require_capability(dummy, CommandTransport, "run")
    assert checked is dummy

    with pytest.raises(CapabilityNotSupportedError) as exc_info:
        require_capability(dummy, FileCapableTransport, "upload")
    assert isinstance(exc_info.value, NotImplementedError)
    assert "upload" in str(exc_info.value)


@pytest.mark.asyncio
async def test_custom_command_pipeline_middleware() -> None:
    """Тестирование кастомного middleware в CommandPipeline."""
    mw: CommandMiddleware = CustomHeaderMiddleware("CUSTOM")
    pipeline = CommandPipeline([mw])

    async def terminal(req: CommandRequest) -> Result:
        return Result(command=req.exec_command, stdout="hello", stderr="", exit_code=0, duration=0.01)

    req = CommandRequest(raw_command="echo hello", command="echo hello", exec_command="echo hello")
    res = await pipeline.execute(req, terminal)
    assert res.stdout == "[CUSTOM] hello"
    assert isinstance(mw, CustomHeaderMiddleware)
    assert mw.calls == ["echo hello"]


@pytest.mark.asyncio
async def test_connection_domain_services_and_sync_parity(tmp_path: Path) -> None:
    """Проверка доменных сервисов conn.files, conn.state, conn.tunnels и их Sync-аналогов."""
    conn = Connection.from_uri("local://localhost")
    assert isinstance(conn.files, FileOperationsService)
    assert isinstance(conn.state, StateManagementService)
    assert isinstance(conn.tunnels, TunnelService)
    assert isinstance(conn.pipeline, CommandPipeline)

    sync_conn = conn.to_sync()
    assert isinstance(sync_conn.files, SyncFileOperationsService)
    assert isinstance(sync_conn.state, SyncStateManagementService)
    assert isinstance(sync_conn.tunnels, SyncTunnelService)

    test_file = tmp_path / "service_test.txt"
    with sync_conn:
        sync_conn.files.write_file(str(test_file), "domain-service-ok")
        assert sync_conn.files.exists(str(test_file))
        content = sync_conn.files.read_file(str(test_file))
        assert content == "domain-service-ok"

        facts = sync_conn.state.gather_facts()
        assert facts.os_family != ""


def test_event_loop_portal_and_sync_context_bridge() -> None:
    """Проверка универсального портала EventLoopPortal и моста контекстных менеджеров."""
    portal = EventLoopPortal("TestPortal")

    async def sample_coro(x: int) -> int:
        return x * 2

    try:
        assert portal.call(sample_coro(21)) == 42

        state: list[str] = []

        class DummyAsyncCM:
            async def __aenter__(self) -> str:
                state.append("enter")
                return "cm-value"

            async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                state.append("exit")

        with SyncContextBridge(portal, DummyAsyncCM()) as val:
            assert val == "cm-value"
            assert state == ["enter"]
        assert state == ["enter", "exit"]
    finally:
        portal.close()
        assert portal.closed


def test_package_and_service_strategies() -> None:
    """Проверка изолированных стратегий пакетных и сервисных менеджеров."""
    apt = PackageManagerStrategy.for_manager("apt")
    assert isinstance(apt, AptStrategy)
    assert "dpkg-query" in apt.check_installed_cmd("nginx")
    assert "apt-get install" in apt.install_cmd(["nginx"])
    assert "apt-get remove" in apt.remove_cmd(["nginx"])

    systemd = ServiceManagerStrategy.for_system("systemd")
    assert isinstance(systemd, SystemdStrategy)
    assert "is-active" in systemd.status_cmd("nginx")
    assert "systemctl start" in systemd.action_cmd("nginx", "start")
    assert "systemctl stop" in systemd.action_cmd("nginx", "stop")
    assert "systemctl restart" in systemd.action_cmd("nginx", "restart")
    assert "systemctl reload" in systemd.action_cmd("nginx", "reload")


def test_template_engine_and_marker_protocol() -> None:
    """Проверка TemplateEngine и PosixMarkerProtocol."""
    rendered = TemplateEngine.render("host=${host}", {"host": "node1"}, engine="string")
    assert rendered == "host=node1"

    marker = PosixMarkerProtocol()
    wrapped = marker.wrap_command("ls -la")
    assert marker.uuid in wrapped
    sample_buf = f"ls -la\nfile1\n__UNICONN_{marker.uuid}__0\n"
    match = marker.search(sample_buf)
    assert match is not None
    assert int(match.group(1)) == 0
    cleaned = marker.clean_output("ls -la\nfile1\n", "ls -la", wrapped)
    assert cleaned == "file1"


def test_inventory_loader_and_ssh_config_parser(tmp_path: Path) -> None:
    """Проверка изолированных парсеров InventoryLoader и OpenSSHConfigParser."""
    inv_data = {
        "defaults": {"transport": "ssh", "username": "admin", "port": 2222},
        "hosts": {"web1": {"host": "10.0.0.1"}},
    }
    parsed = InventoryLoader.parse_data(inv_data, host="web1")
    assert len(parsed) == 1
    assert parsed[0]["host"] == "10.0.0.1"
    assert parsed[0]["username"] == "admin"
    assert parsed[0]["port"] == 2222

    ssh_cfg = tmp_path / "ssh_config"
    ssh_cfg.write_text("Host prod-*\n  User deploy\n  Port 2200\n  HostName 192.168.1.50\n", encoding="utf-8")
    resolved = OpenSSHConfigParser.parse_file(ssh_cfg, "prod-web")
    assert resolved["hostname"] == "192.168.1.50"
    assert resolved["user"] == "deploy"
    assert resolved["port"] == 2200
