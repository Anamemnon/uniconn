from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from uniconn import (
    AutoDiagnosticMiddleware,
    Connection,
    ConnectionConfig,
    ContainerDiagnosticStrategy,
    DiagnosticSummary,
    ErrorCategory,
    ErrorClassifier,
    ExecutionError,
    LinuxDiagnosticStrategy,
    PassiveDiagnosticStrategy,
    PortConflictInfo,
    Result,
    SystemVitals,
    WindowsDiagnosticStrategy,
    resolve_diagnostic_strategy,
)
from uniconn.core.pipeline import _ACTIVE_DIAGNOSTIC_PROBE, CommandRequest
from uniconn.mcp.models import MCPSecurityPolicy
from uniconn.mcp.registry import MCPHostRegistry
from uniconn.mcp.server import MCPServer


class DummyShellTransport:
    """Minimal shell-capable mock transport for testing diagnostic probes."""

    name = "ssh"

    def __init__(self, responses: dict[str, Result] | None = None, default_result: Result | None = None) -> None:
        self.responses = responses or {}
        self.default_result = default_result or Result(
            exit_code=0, stdout="", stderr="", duration=0.01, command="mock"
        )
        self.executed_commands: list[tuple[str, float | None]] = []

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        return True

    async def open_shell(self, **kwargs):
        raise NotImplementedError

    async def run(self, command: str | list[str], timeout: float | None = None, **kwargs) -> Result:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        self.executed_commands.append((cmd_str, timeout))
        for pattern, res in self.responses.items():
            if pattern in cmd_str:
                return res
        return self.default_result


class NetconfDummyTransport:
    """Minimal non-shell transport named netconf to verify PassiveDiagnosticStrategy selection."""

    name = "netconf"

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    def is_connected(self) -> bool:
        return True

    async def run(self, command: str | list[str], timeout: float | None = None, **kwargs) -> Result:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        return Result(
            exit_code=1, stdout="", stderr="rpc-error: invalid-value", duration=0.01, command=cmd_str
        )


def test_diagnostic_models_serialization_and_slots() -> None:
    vitals = SystemVitals(
        cpu_load_1m=1.25,
        memory_total_mb=4096,
        memory_available_mb=512,
        memory_free_ratio=0.125,
        disk_root_free_mb=1024,
        disk_tmp_free_mb=512,
        disk_root_inodes_free=88000,
        oom_kill_count=0,
    )
    conflict = PortConflictInfo(
        port=80,
        protocol="tcp",
        conflicting_pid=1234,
        conflicting_process="apache2",
        listen_address="0.0.0.0",
    )
    summary = DiagnosticSummary(
        category=ErrorCategory.PORT_CONFLICT,
        root_cause_hint="Port 80/tcp on 0.0.0.0 is already bound by process 'apache2' (PID 1234)",
        vitals=vitals,
        relevant_logs=["bind() to 0.0.0.0:80 failed (98: Address already in use)"],
        port_conflict=conflict,
        dmesg_tail=[],
        suggested_actions=["Stop conflicting service: systemctl stop apache2"],
        collection_duration_ms=42.5,
    )

    assert not hasattr(vitals, "__dict__")
    assert not hasattr(conflict, "__dict__")
    assert not hasattr(summary, "__dict__")

    payload = summary.to_dict()
    assert payload["category"] == "PORT_CONFLICT"
    assert payload["port_conflict"]["conflicting_process"] == "apache2"

    restored = DiagnosticSummary.from_dict(payload)
    assert restored == summary

    res = Result(
        exit_code=1,
        stdout="",
        stderr="Job for nginx.service failed",
        duration=0.05,
        command="systemctl restart nginx",
        diagnostic=summary,
    )
    assert res.diagnostic is summary
    assert res.diagnostic_summary is summary
    assert res.to_dict()["diagnostic"]["category"] == "PORT_CONFLICT"

    with pytest.raises(ExecutionError) as exc_info:
        res.raise_for_status()
    assert exc_info.value.diagnostic is summary


@pytest.mark.parametrize(
    ("command", "exit_code", "stderr", "expected_cat", "expected_port", "expected_svc"),
    [
        (
            "nginx -g 'daemon off;'",
            1,
            "nginx: [emerg] bind() to 0.0.0.0:8080 failed (98: Address already in use)",
            ErrorCategory.PORT_CONFLICT,
            8080,
            None,
        ),
        (
            "dd if=/dev/zero of=/var/tmp/fill",
            1,
            "dd: writing to '/var/tmp/fill': No space left on device",
            ErrorCategory.DISK_FULL,
            None,
            None,
        ),
        (
            "python3 train.py",
            137,
            "Killed",
            ErrorCategory.OUT_OF_MEMORY,
            None,
            None,
        ),
        (
            "apt-get install -y curl",
            100,
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4512 (unattended-upgr)",
            ErrorCategory.PACKAGE_LOCK_CONFLICT,
            None,
            None,
        ),
        (
            "nginx -t",
            1,
            'nginx: [emerg] unknown directive "workr_processes" in /etc/nginx/nginx.conf:3\n'
            "configuration file /etc/nginx/nginx.conf test failed",
            ErrorCategory.CONFIG_SYNTAX_ERROR,
            None,
            None,
        ),
        (
            "htop --version",
            127,
            "bash: htop: command not found",
            ErrorCategory.COMMAND_NOT_FOUND,
            None,
            None,
        ),
        (
            "cat /etc/shadow",
            1,
            "cat: /etc/shadow: Permission denied",
            ErrorCategory.PERMISSION_DENIED,
            None,
            None,
        ),
        (
            "sudo systemctl start postgresql",
            1,
            "Job for postgresql.service failed because the control process exited with error code.",
            ErrorCategory.SERVICE_CRASH,
            None,
            "postgresql",
        ),
        (
            "curl https://internal.example.invalid",
            6,
            "curl: (6) Could not resolve host: internal.example.invalid",
            ErrorCategory.NETWORK_UNREACHABLE,
            None,
            None,
        ),
        (
            "false",
            1,
            "something unexpected went wrong",
            ErrorCategory.GENERIC_FAILURE,
            None,
            None,
        ),
    ],
)
def test_error_classifier_categories(
    command: str,
    exit_code: int,
    stderr: str,
    expected_cat: ErrorCategory,
    expected_port: int | None,
    expected_svc: str | None,
) -> None:
    match = ErrorClassifier.classify(command, "", stderr, exit_code)
    assert match.category == expected_cat
    assert match.port == expected_port
    assert match.service_unit == expected_svc


@pytest.mark.asyncio
async def test_linux_strategy_two_phase_cascade_service_crash_to_port_conflict() -> None:
    vitals_stdout = (
        "0.45 0.30 0.25 1/200 1234\n"
        "---MEM---\n"
        "MemTotal: 4096000 kB\n"
        "MemAvailable: 2048000 kB\n"
        "---DF---\n"
        "Filesystem 1048576-blocks Used Available Capacity Mounted on\n"
        "/dev/sda1 10000 4000 6000 40% /\n"
        "tmpfs 2000 100 1900 5% /tmp\n"
        "---INODE---\n"
        "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
        "/dev/sda1 10000 1000 9000 10% /\n"
    )
    journal_stdout = (
        "2026-11-11T00:00:01+0000 node nginx[999]: "
        "nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)\n"
        "2026-11-11T00:00:01+0000 node systemd[1]: nginx.service: Failed with result 'exit-code'.\n"
    )
    ss_stdout = 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=4321,fd=4))\n'

    calls: list[str] = []

    async def fake_probe(cmd: str) -> Result:
        calls.append(cmd)
        if "---MEM---" in cmd:
            return Result(exit_code=0, stdout=vitals_stdout, stderr="", duration=0.01, command=cmd)
        if "journalctl" in cmd:
            return Result(exit_code=0, stdout=journal_stdout, stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout=ss_stdout, stderr="", duration=0.01, command=cmd)

    command = "systemctl restart nginx"
    stderr = "Job for nginx.service failed because the control process exited with error code."
    initial_match = ErrorClassifier.classify(command, "", stderr, 1)
    assert initial_match.category == ErrorCategory.SERVICE_CRASH

    strategy = LinuxDiagnosticStrategy()
    summary = await strategy.collect(command, "", stderr, 1, fake_probe)

    # Verify two-phase cascade promoted SERVICE_CRASH -> PORT_CONFLICT and ran follow-up socket probe
    assert summary.category == ErrorCategory.PORT_CONFLICT
    assert summary.port_conflict is not None
    assert summary.port_conflict.port == 80
    assert summary.port_conflict.conflicting_pid == 4321
    assert summary.port_conflict.conflicting_process == "apache2"
    assert "apache2" in summary.root_cause_hint
    assert summary.vitals.disk_root_free_mb == 6000
    assert summary.vitals.disk_tmp_free_mb == 1900
    assert summary.vitals.disk_root_inodes_free == 9000
    assert summary.vitals.memory_available_mb == 2000
    assert summary.vitals.cpu_load_1m == 0.45
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_container_strategy_detects_cgroup_v2_oom_kill() -> None:
    probe_stdout = (
        "0.80 0.50 0.20 1/50 99\n"
        "---MEM---\n"
        "MemTotal: 1024000 kB\n"
        "MemAvailable: 64000 kB\n"
        "---DF---\n"
        "Filesystem 1048576-blocks Used Available Capacity Mounted on\n"
        "overlay 10000 2000 8000 20% /\n"
        "---INODE---\n"
        "Filesystem Inodes IUsed IFree IUse% Mounted on\n"
        "overlay 10000 100 9900 1% /\n"
        "---CGROUP---\n"
        "low 0\nhigh 2\nmax 5\noom 1\noom_kill 3\n"
    )

    async def fake_probe(cmd: str) -> Result:
        if "---CGROUP---" in cmd:
            return Result(exit_code=0, stdout=probe_stdout, stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

    strategy = ContainerDiagnosticStrategy()
    summary = await strategy.collect("python3 worker.py", "", "Killed", 137, fake_probe)

    assert summary.category == ErrorCategory.OUT_OF_MEMORY
    assert summary.vitals.oom_kill_count == 3
    assert "OOM" in summary.root_cause_hint


@pytest.mark.asyncio
async def test_windows_strategy_parses_powershell_json() -> None:
    vitals_json = '{"FreeMemKB": 1048576, "TotalMemKB": 4194304, "FreeDiskBytes": 10737418240}'
    port_json = '{"Port": 443, "Pid": 3120, "Process": "httpd", "Addr": "0.0.0.0"}'

    async def fake_probe(cmd: str) -> Result:
        if "Win32_OperatingSystem" in cmd:
            return Result(exit_code=0, stdout=vitals_json, stderr="", duration=0.01, command=cmd)
        if "Get-NetTCPConnection" in cmd:
            return Result(exit_code=0, stdout=port_json, stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

    strategy = WindowsDiagnosticStrategy()
    summary = await strategy.collect(
        "Start-Service MyService",
        "",
        "bind() to 0.0.0.0:443 failed: Address already in use",
        1,
        fake_probe,
    )

    assert summary.category == ErrorCategory.PORT_CONFLICT
    assert summary.vitals.memory_available_mb == 1024
    assert summary.vitals.memory_total_mb == 4096
    assert summary.vitals.disk_root_free_mb == 10240
    assert summary.port_conflict is not None
    assert summary.port_conflict.port == 443
    assert summary.port_conflict.conflicting_pid == 3120
    assert summary.port_conflict.conflicting_process == "httpd"


@pytest.mark.asyncio
async def test_middleware_recursion_guard_timeout_fallback_and_secret_masking() -> None:
    transport = DummyShellTransport(
        responses={
            "---MEM---": Result(
                exit_code=0,
                stdout=(
                    "1.00 0.50 0.25 1/100 99\n"
                    "---MEM---\n"
                    "MemTotal: 2048000 kB\n"
                    "MemAvailable: 512000 kB\n"
                    "---DF---\n"
                    "Filesystem 1048576-blocks Used Available Capacity Mounted on\n"
                    "/dev/sda1 1000 900 100 90% /\n"
                    "---INODE---\n"
                    "/dev/sda1 1000 100 900 10% /\n"
                ),
                stderr="",
                duration=0.01,
                command="probe",
            ),
            "journalctl": Result(
                exit_code=0,
                stdout="password=super_secret_token_123 failed on startup\n",
                stderr="",
                duration=0.01,
                command="journalctl",
            ),
        }
    )
    cfg = ConnectionConfig(host="localhost", transport="ssh")
    conn = Connection(config=cfg, transport=transport, auto_diagnostics=True)

    # 1. Execute failing command within broken conn.cd() and with sudo=True
    transport.responses["systemctl start app"] = Result(
        exit_code=1,
        stdout="",
        stderr="Job for app.service failed with password=super_secret_token_123",
        duration=0.01,
        command="systemctl start app",
    )
    async with conn.cd("/nonexistent/broken/dir"):
        res = await conn.run("systemctl start app", sudo=True)

    assert not res.ok
    assert res.diagnostic is not None
    # Verify secret was masked in logs and hint
    for line in res.diagnostic.relevant_logs:
        assert "super_secret_token_123" not in line
        assert "***" in line
    assert "super_secret_token_123" not in res.diagnostic.root_cause_hint

    # Verify diagnostic probe inherited sudo but bypassed broken cd("/nonexistent/broken/dir")
    probe_cmds = [cmd for cmd, _ in transport.executed_commands if "---MEM---" in cmd]
    assert len(probe_cmds) == 1
    assert "/nonexistent/broken/dir" not in probe_cmds[0]
    assert probe_cmds[0].startswith("sudo ")

    # 2. Verify recursion guard prevents probing when _ACTIVE_DIAGNOSTIC_PROBE is True
    token = _ACTIVE_DIAGNOSTIC_PROBE.set(True)
    try:
        res_guarded = await conn.run("systemctl start app")
        assert res_guarded.diagnostic is None
    finally:
        _ACTIVE_DIAGNOSTIC_PROBE.reset(token)

    # 3. Verify timeout budget falls back to PassiveDiagnosticStrategy without raising TimeoutError
    async def slow_handler(req: CommandRequest) -> Result:
        return Result(
            exit_code=1, stdout="", stderr="No space left on device", duration=0.01, command="write_data"
        )

    slow_transport = DummyShellTransport()

    async def slow_run(*args, **kwargs) -> Result:
        await asyncio.sleep(0.5)
        return Result(exit_code=0, stdout="", stderr="", duration=0.5, command="slow")

    slow_transport.run = slow_run  # type: ignore[method-assign]
    slow_conn = Connection(config=cfg, transport=slow_transport, auto_diagnostics=True)
    mw = AutoDiagnosticMiddleware(slow_conn, enabled=True, timeout_budget=0.05)

    req = CommandRequest(
        command="write_data",
        raw_command="write_data",
        exec_command="write_data",
        diagnose=True,
    )
    fallback_res = await mw(req, slow_handler)
    assert fallback_res.diagnostic is not None
    assert fallback_res.diagnostic.category == ErrorCategory.DISK_FULL
    assert "disk space" in fallback_res.diagnostic.root_cause_hint.lower()


@pytest.mark.asyncio
async def test_resolve_diagnostic_strategy_for_non_shell_transport() -> None:
    cfg = ConnectionConfig(host="router", transport="netconf")
    conn = Connection(config=cfg, transport=NetconfDummyTransport())  # type: ignore[arg-type]
    strategy = resolve_diagnostic_strategy(conn)
    assert isinstance(strategy, PassiveDiagnosticStrategy)

    res = await conn.run("edit-config", diagnose=True)
    assert res.diagnostic is not None
    assert res.diagnostic.category == ErrorCategory.GENERIC_FAILURE


@pytest.mark.asyncio
async def test_mcp_server_uniconn_run_includes_diagnostic_by_default() -> None:
    policy = MCPSecurityPolicy(allow_write=True)
    registry = MCPHostRegistry.from_sources(include_local=True, policy=policy)
    server = MCPServer(registry=registry)

    fake_diag = DiagnosticSummary(
        category=ErrorCategory.COMMAND_NOT_FOUND,
        root_cause_hint="Executable 'nonexistent_bin' was not found in PATH",
    )
    fake_conn = AsyncMock()
    fake_conn.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_conn.__aexit__ = AsyncMock(return_value=None)
    fake_conn.run = AsyncMock(
        return_value=Result(
            exit_code=127,
            stdout="",
            stderr="nonexistent_bin: command not found",
            duration=0.01,
            command="nonexistent_bin",
            host="localhost",
            diagnostic=fake_diag,
        )
    )
    registry.create_connection = lambda target: fake_conn  # type: ignore[method-assign]

    resp = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {"target": "local", "command": "nonexistent_bin"},
            },
        }
    )
    assert resp is not None
    fake_conn.run.assert_awaited_once()
    _, call_kwargs = fake_conn.run.call_args
    assert call_kwargs["diagnose"] is True

    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["ok"] is False
    assert payload["diagnostic"]["category"] == "COMMAND_NOT_FOUND"
    assert "nonexistent_bin" in payload["diagnostic"]["root_cause_hint"]


def test_port_conflict_disambiguates_prefix_ports_like_8080_vs_80() -> None:
    ss_output = (
        'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("java",pid=9999,fd=10))\n'
        'LISTEN 0 511 127.0.0.1:80 0.0.0.0:* users:(("nginx",pid=1111,fd=6))\n'
    )
    info = LinuxDiagnosticStrategy.parse_port_conflict(80, ss_output)
    assert info.port == 80
    assert info.conflicting_pid == 1111
    assert info.conflicting_process == "nginx"
    assert info.listen_address == "127.0.0.1"


def test_extractors_handle_urls_systemctl_flags_and_sudo_missing_cmd() -> None:
    path = ErrorClassifier.extract_path(
        "curl https://mirror.example.com/pub/pkg.tar.gz failed: No space left on device",
        "curl -o /var/cache/pkg.tar.gz https://mirror.example.com/pub/pkg.tar.gz",
    )
    assert path == "/var/cache/pkg.tar.gz"

    unit = ErrorClassifier.extract_service_unit(
        "sudo systemctl --system restart --no-block redis-server.service",
        "",
    )
    assert unit == "redis-server.service"

    missing = ErrorClassifier.extract_missing_command(
        "sudo: htop: command not found",
        "sudo -u root htop -d 10",
    )
    assert missing == "htop"


@pytest.mark.asyncio
async def test_cassette_and_raw_password_scrubbing_and_sync_parity() -> None:
    # 1. Cassette transport attribute forces PassiveDiagnosticStrategy even when transport.name == "ssh"
    class CassetteWrappedTransport(DummyShellTransport):
        cassette = object()

    cfg = ConnectionConfig(host="localhost", transport="ssh", password="MyRawSecretValue99!")
    conn = Connection(config=cfg, transport=CassetteWrappedTransport(), auto_diagnostics=True)
    assert isinstance(resolve_diagnostic_strategy(conn), PassiveDiagnosticStrategy)

    # 2. Unprefixed raw password in stderr is scrubbed from DiagnosticSummary
    conn.transport.responses["fail_echo"] = Result(  # type: ignore[attr-defined]
        exit_code=127,
        stdout="",
        stderr="auth token MyRawSecretValue99!: command not found",
        duration=0.01,
        command="fail_echo",
    )
    res = await conn.run("fail_echo")
    assert res.diagnostic is not None
    assert "MyRawSecretValue99!" not in res.diagnostic.root_cause_hint
    for log_line in res.diagnostic.relevant_logs:
        assert "MyRawSecretValue99!" not in log_line
        assert "***REDACTED***" in log_line

    # 3. SyncConnection parity
    sync_conn = conn.to_sync()
    assert sync_conn.auto_diagnostics is True
    sync_conn.auto_diagnostics = False
    assert conn.auto_diagnostics is False
    sync_res = sync_conn.run("fail_echo", diagnose=True)
    assert sync_res.diagnostic is not None
    assert sync_res.diagnostic.category == ErrorCategory.COMMAND_NOT_FOUND
