# tests/unit/services/test_windows_provisioning.py
"""Unit-тесты для Вектора 2.1: Полноценный Windows Provisioning поверх winrm:// (State Management 2.0)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest

from examples.dashboard.sandboxes.features import _execute_v080_sandbox
from uniconn import (
    ChocoStrategy,
    Connection,
    ConnectionPool,
    EnsureResult,
    HostFacts,
    PackageManagerStrategy,
    Result,
    ScoopStrategy,
    WingetStrategy,
    ensure_registry_key,
    ensure_windows_feature,
    ensure_windows_service,
)
from uniconn.services.provisioning import (
    build_registry_key_ps_script,
    build_windows_feature_ps_script,
    build_windows_service_ps_script,
    is_windows_connection,
    normalize_registry_path,
    normalize_registry_value_type,
)


class TestEnsureResultRebootRequired:
    """Проверка поля reboot_required в EnsureResult и его сериализации."""

    def test_ensure_result_default_and_explicit_reboot_required(self) -> None:
        res_default = EnsureResult(target="Git.Git", state="present", changed=True, ok=True)
        assert res_default.reboot_required is False
        assert res_default.to_dict()["reboot_required"] is False

        res_reboot = EnsureResult(
            target="Web-Server",
            state="present",
            changed=True,
            ok=True,
            reboot_required=True,
            details="Installed Web-Server (reboot required)",
        )
        assert res_reboot.reboot_required is True
        dumped = res_reboot.to_dict()
        assert dumped["reboot_required"] is True
        assert dumped["changed"] is True
        assert dumped["ok"] is True


class TestWindowsPackageManagers:
    """Тесты пакетных менеджеров Windows: WingetStrategy, ChocoStrategy, ScoopStrategy и auto-detection."""

    def test_windows_package_strategies_command_generation(self) -> None:
        winget = PackageManagerStrategy.for_manager("winget")
        assert isinstance(winget, WingetStrategy)
        assert winget.is_windows is True
        assert "--id 'Git.Git' --exact" in winget.check_installed_cmd("Git.Git")
        assert "winget install --id 'Git.Git' --exact --silent" in winget.install_cmd("Git.Git")
        assert "winget source update" in winget.install_cmd(["Git.Git", "7zip.7zip"], update_cache=True)
        assert "winget uninstall --id 'Git.Git' --exact --silent" in winget.remove_cmd("Git.Git")
        assert "; " in winget.remove_cmd(["Git.Git", "7zip.7zip"])

        choco = PackageManagerStrategy.for_manager("choco")
        assert isinstance(choco, ChocoStrategy)
        assert choco.is_windows is True
        assert "choco list --local-only --exact 'git'" in choco.check_installed_cmd("git")
        assert choco.install_cmd(["git", "curl"]) == "choco install 'git' 'curl' -y --no-progress"
        assert choco.remove_cmd("git") == "choco uninstall 'git' -y --no-progress"

        scoop = PackageManagerStrategy.for_manager("scoop")
        assert isinstance(scoop, ScoopStrategy)
        assert scoop.is_windows is True
        assert "scoop list 'jq'" in scoop.check_installed_cmd("jq")
        assert scoop.install_cmd("jq", update_cache=True) == "scoop update; scoop install 'jq'"
        assert scoop.remove_cmd("jq") == "scoop uninstall 'jq'"

    @pytest.mark.asyncio
    async def test_resolve_pkg_manager_auto_on_winrm(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        assert is_windows_connection(conn) is True

        conn.run = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                Result(exit_code=0, stdout="winget\r\n", stderr="", duration=0.01, command="probe"),
                Result(exit_code=0, stdout="choco\r\n", stderr="", duration=0.01, command="probe"),
                Result(exit_code=0, stdout="scoop\r\n", stderr="", duration=0.01, command="probe"),
                Result(exit_code=1, stdout="", stderr="", duration=0.01, command="probe"),
            ]
        )
        assert await conn.state.resolve_pkg_manager("auto") == "winget"
        assert await conn.state.resolve_pkg_manager("auto") == "choco"
        assert await conn.state.resolve_pkg_manager("auto") == "scoop"
        assert await conn.state.resolve_pkg_manager("auto") == "winget"

    @pytest.mark.asyncio
    async def test_resolve_pkg_manager_from_cached_windows_facts(self) -> None:
        conn = Connection.from_uri("ssh://admin@10.0.0.15")
        conn._cached_facts = HostFacts(hostname="win-ssh", os_family="Windows")
        assert is_windows_connection(conn) is True

        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(exit_code=0, stdout="choco\n", stderr="", duration=0.01, command="probe")
        )
        assert await conn.state.resolve_pkg_manager("auto") == "choco"

    @pytest.mark.asyncio
    async def test_ensure_package_winget_and_exit_code_3010_reboot_required(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                # 1. check_installed_cmd -> не установлен (exit_code=1)
                Result(
                    exit_code=1,
                    stdout="No installed package found matching input criteria.",
                    stderr="",
                    duration=0.01,
                    command="winget list",
                ),
                # 2. install_cmd -> возвращает 3010 (ERROR_SUCCESS_REBOOT_REQUIRED)
                Result(
                    exit_code=3010,
                    stdout="Successfully installed",
                    stderr="",
                    duration=0.2,
                    command="winget install",
                ),
                # 3. Повторный вызов -> уже установлен (exit_code=0)
                Result(
                    exit_code=0,
                    stdout="Git.Git 2.45.0",
                    stderr="",
                    duration=0.01,
                    command="winget list",
                ),
            ]
        )

        notified_events: list[EnsureResult] = []
        res1 = await conn.state.ensure_package(
            "Git.Git",
            manager="winget",
            state="present",
            notify=lambda res: notified_events.append(res),
        )
        assert res1.ok is True
        assert res1.changed is True
        assert res1.reboot_required is True
        assert res1.notified is True
        assert len(notified_events) == 1
        assert notified_events[0].reboot_required is True
        assert "reboot required" in res1.details

        # Проверим, что для Windows sudo автоматически отключён (sudo=False)
        for call in conn.run.call_args_list:
            assert call.kwargs.get("sudo") is False

        # Повторный вызов идемпотентен
        res2 = await conn.state.ensure_package("Git.Git", manager="winget", state="present")
        assert res2.ok is True
        assert res2.changed is False
        assert res2.reboot_required is False


class TestWindowsServicePrimitive:
    """Тесты примитива ensure_windows_service и делегирования из ensure_service."""

    def test_build_windows_service_ps_script_contains_scm_wait_and_delayed_autostart(self) -> None:
        script = build_windows_service_ps_script(
            "wuauserv",
            state="stopped",
            startup_type="delayed",
            timeout=45.0,
            dry_run=False,
        )
        assert "WaitForStatus('Running'" in script
        assert "WaitForStatus('Stopped'" in script
        assert "DelayedAutoStart" in script
        assert "[TimeSpan]::FromSeconds(45)" in script

    @pytest.mark.asyncio
    async def test_ensure_windows_service_lifecycle_and_diff(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                Result(
                    exit_code=0,
                    stdout=(
                        '{"ok":true,"changed":true,'
                        '"actions":["startup_type:automatic->disabled","stop"],'
                        '"before_status":"Running","after_status":"Stopped",'
                        '"before_startup":"automatic","after_startup":"disabled"}'
                    ),
                    stderr="",
                    duration=0.02,
                    command="powershell",
                ),
                Result(
                    exit_code=0,
                    stdout=(
                        '{"ok":true,"changed":false,"actions":[],'
                        '"before_status":"Stopped","after_status":"Stopped",'
                        '"before_startup":"disabled","after_startup":"disabled"}'
                    ),
                    stderr="",
                    duration=0.01,
                    command="powershell",
                ),
            ]
        )

        res1 = await conn.state.ensure_windows_service(
            name="wuauserv",
            state="stopped",
            startup_type="disabled",
        )
        assert res1.ok is True
        assert res1.changed is True
        assert "startup_type:automatic->disabled" in res1.details
        assert "stop" in res1.details
        assert res1.diff is not None
        assert "-status=Running" in res1.diff
        assert "+status=Stopped" in res1.diff
        assert "-startup_type=automatic" in res1.diff
        assert "+startup_type=disabled" in res1.diff

        res2 = await conn.state.ensure_windows_service(
            name="wuauserv",
            state="stopped",
            startup_type="disabled",
        )
        assert res2.ok is True
        assert res2.changed is False
        assert res2.diff is None

    @pytest.mark.asyncio
    async def test_ensure_service_delegates_to_ensure_windows_service_on_windows(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=0,
                stdout=(
                    '{"ok":true,"changed":true,"actions":["startup_type:manual->automatic","start"],'
                    '"before_status":"Stopped","after_status":"Running",'
                    '"before_startup":"manual","after_startup":"automatic"}'
                ),
                stderr="",
                duration=0.02,
                command="powershell",
            )
        )

        res = await conn.state.ensure_service("Spooler", state="started", enabled=True)
        assert res.ok is True
        assert res.changed is True
        assert "Windows service Spooler" in res.details

    @pytest.mark.asyncio
    async def test_ensure_windows_service_validation_and_missing_service(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        with pytest.raises(ValueError, match="cannot be empty"):
            await conn.state.ensure_windows_service("")
        with pytest.raises(ValueError, match="Unsupported Windows service state"):
            await conn.state.ensure_windows_service("wuauserv", state="invalid")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="Unsupported Windows service startup_type"):
            await conn.state.ensure_windows_service("wuauserv", startup_type="bogus")  # type: ignore[arg-type]

        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=1,
                stdout='{"ok":false,"changed":false,"error":"Service \'MissingSvc\' not found"}',
                stderr="",
                duration=0.01,
                command="powershell",
            )
        )
        res_err = await conn.state.ensure_windows_service("MissingSvc", state="started")
        assert res_err.ok is False
        assert res_err.changed is False
        assert "not found" in res_err.details


class TestWindowsRegistryPrimitive:
    """Тесты примитива ensure_registry_key и нормализации путей/типов реестра."""

    def test_normalize_registry_path_and_types(self) -> None:
        canon, ps_path = normalize_registry_path(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        )
        assert canon == r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        assert (
            ps_path
            == r"Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        )

        canon2, ps_path2 = normalize_registry_path("HKEY_CURRENT_USER:/Software/MyApp")
        assert canon2 == r"HKCU\Software\MyApp"
        assert ps_path2 == r"Registry::HKEY_CURRENT_USER\Software\MyApp"

        assert normalize_registry_value_type("DWORD") == "DWord"
        assert normalize_registry_value_type("qword") == "QWord"
        assert normalize_registry_value_type("MultiString") == "MultiString"
        assert normalize_registry_value_type("ExpandString") == "ExpandString"
        assert normalize_registry_value_type("Binary") == "Binary"
        assert normalize_registry_value_type("String") == "String"

        with pytest.raises(ValueError, match="Unsupported Windows registry root hive"):
            normalize_registry_path(r"HKINVALID\Software")
        with pytest.raises(ValueError, match="Unsupported Windows registry value type"):
            normalize_registry_value_type("InvalidType")

    def test_build_registry_key_ps_script_all_value_types(self) -> None:
        _, ps_path = normalize_registry_path(r"HKLM\Software\Demo")
        s_dword = build_registry_key_ps_script(
            ps_path, name="Flag", value=1, ps_type="DWord", state="present"
        )
        assert "([int64]1)" in s_dword

        s_multi = build_registry_key_ps_script(
            ps_path, name="Servers", value=["s1", "s2"], ps_type="MultiString", state="present"
        )
        assert "[string[]]@('s1', 's2')" in s_multi

        s_bin = build_registry_key_ps_script(
            ps_path, name="Raw", value=b"\xde\xad\xbe\xef", ps_type="Binary", state="present"
        )
        assert "FromBase64String" in s_bin
        assert "deadbeef" in s_bin

    @pytest.mark.asyncio
    async def test_ensure_registry_key_present_absent_and_diff(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                Result(
                    exit_code=0,
                    stdout='{"ok":true,"changed":true,"action":"updated_value","before":"DWord:0","after":"DWord:1"}',
                    stderr="",
                    duration=0.01,
                    command="powershell",
                ),
                Result(
                    exit_code=0,
                    stdout='{"ok":true,"changed":false,"action":"noop","before":"DWord:1","after":"DWord:1"}',
                    stderr="",
                    duration=0.01,
                    command="powershell",
                ),
                Result(
                    exit_code=0,
                    stdout='{"ok":true,"changed":true,"action":"removed_value","before":"DWord:1","after":null}',
                    stderr="",
                    duration=0.01,
                    command="powershell",
                ),
            ]
        )

        reg_path = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        res1 = await conn.state.ensure_registry_key(
            path=reg_path,
            name="NoAutoUpdate",
            value=1,
            type="DWORD",
            state="present",
        )
        assert res1.ok is True
        assert res1.changed is True
        assert res1.target == f"{reg_path}\\NoAutoUpdate"
        assert res1.diff is not None
        assert "-DWord:0" in res1.diff
        assert "+DWord:1" in res1.diff

        res2 = await conn.state.ensure_registry_key(
            path=reg_path,
            name="NoAutoUpdate",
            value=1,
            type="DWORD",
            state="present",
        )
        assert res2.ok is True
        assert res2.changed is False
        assert res2.diff is None

        res3 = await conn.state.ensure_registry_key(
            path=reg_path,
            name="NoAutoUpdate",
            state="absent",
        )
        assert res3.ok is True
        assert res3.changed is True
        assert res3.diff is not None
        assert "-DWord:1" in res3.diff


class TestWindowsFeaturePrimitive:
    """Тесты примитива ensure_windows_feature (ServerManager и DISM)."""

    def test_build_windows_feature_ps_script_options(self) -> None:
        script = build_windows_feature_ps_script(
            ["Web-Server", "Web-Common-Http"],
            state="present",
            include_sub_features=True,
            include_management_tools=True,
            source=r"D:\sources\sxs",
        )
        assert "'Web-Server', 'Web-Common-Http'" in script
        assert "Install-WindowsFeature" in script
        assert "Enable-WindowsOptionalFeature" in script
        assert "D:\\sources\\sxs" in script

    @pytest.mark.asyncio
    async def test_ensure_windows_feature_with_reboot_required(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            side_effect=[
                Result(
                    exit_code=0,
                    stdout=(
                        '{"ok":true,"changed":true,"modified":["Web-Server"],'
                        '"provider":"ServerManager","reboot_required":true}'
                    ),
                    stderr="",
                    duration=0.05,
                    command="powershell",
                ),
                Result(
                    exit_code=0,
                    stdout=(
                        '{"ok":true,"changed":false,"modified":[],'
                        '"provider":"ServerManager","reboot_required":false}'
                    ),
                    stderr="",
                    duration=0.02,
                    command="powershell",
                ),
            ]
        )

        res1 = await conn.state.ensure_windows_feature(
            "Web-Server",
            state="present",
            include_management_tools=True,
        )
        assert res1.ok is True
        assert res1.changed is True
        assert res1.reboot_required is True
        assert "ServerManager" in res1.details
        assert "reboot required" in res1.details

        res2 = await conn.state.ensure_windows_feature("Web-Server", state="present")
        assert res2.ok is True
        assert res2.changed is False
        assert res2.reboot_required is False


class TestWindowsProvisioningSyncPoolAndPerformance:
    """Тесты паритета Sync / Pool / DryRun, дашборда и производительности (< 2 ms)."""

    @pytest.mark.asyncio
    async def test_windows_primitives_dry_run_and_pool_fan_out(self) -> None:
        c1 = Connection.from_uri("winrm://Administrator:pass@10.0.0.11:5985", dry_run=True)
        c2 = Connection.from_uri("winrm://Administrator:pass@10.0.0.12:5985", dry_run=True)
        pool = ConnectionPool([c1, c2])

        svc_map = await pool.state.ensure_windows_service(
            "wuauserv", state="stopped", startup_type="disabled"
        )
        assert len(svc_map) == 2
        assert all(r.dry_run and r.changed and r.ok for r in svc_map.values())

        reg_map = await pool.state.ensure_registry_key(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            name="NoAutoUpdate",
            value=1,
            type="DWORD",
        )
        assert len(reg_map) == 2
        assert all(r.dry_run and r.changed and r.diff is not None for r in reg_map.values())

        feat_map = await pool.state.ensure_windows_feature("Containers", state="present")
        assert len(feat_map) == 2
        assert all(r.dry_run and r.changed for r in feat_map.values())

    def test_sync_connection_and_sync_pool_windows_state_parity(self) -> None:
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.15:5985", dry_run=True)
        sync_conn = conn.to_sync()
        res_svc = sync_conn.state.ensure_windows_service("wuauserv", state="stopped")
        assert res_svc.ok is True
        assert res_svc.dry_run is True

        res_reg = sync_conn.state.ensure_registry_key(
            r"HKLM\Software\Test", name="Enabled", value=1, type="DWORD"
        )
        assert res_reg.ok is True
        assert res_reg.dry_run is True

        res_feat = sync_conn.state.ensure_windows_feature("Telnet-Client", state="present")
        assert res_feat.ok is True
        assert res_feat.dry_run is True

        # Проверим прямые публичные реэкспорты функций
        assert callable(ensure_windows_service)
        assert callable(ensure_registry_key)
        assert callable(ensure_windows_feature)

    @pytest.mark.asyncio
    async def test_windows_provisioning_overhead_under_2ms(self) -> None:
        """Локальные накладные расходы генерации и диспетчеризации Windows-примитивов < 2 мс."""
        conn = Connection.from_uri("winrm://Administrator:pass@10.0.0.10:5985")
        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=0,
                stdout='{"ok":true,"changed":false,"action":"noop","before":"DWord:1","after":"DWord:1"}',
                stderr="",
                duration=0.0001,
                command="ps",
            )
        )
        # Прогрев
        await conn.state.ensure_registry_key(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            name="NoAutoUpdate",
            value=1,
            type="DWORD",
        )

        iterations = 100
        t0 = time.perf_counter()
        for _ in range(iterations):
            await conn.state.ensure_registry_key(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                name="NoAutoUpdate",
                value=1,
                type="DWORD",
            )
        avg_ms = ((time.perf_counter() - t0) / iterations) * 1000.0
        assert avg_ms < 2.0, f"Expected Windows provisioning overhead < 2.0 ms, got {avg_ms:.3f} ms"

    def test_dashboard_windows_provisioning_sandbox(self) -> None:
        resp = _execute_v080_sandbox({"feature": "windows_provisioning"})
        assert resp["status"] == "ok"
        assert resp["package"]["changed"] is True
        assert resp["service"]["changed"] is True
        assert resp["registry"]["changed"] is True
        assert resp["windows_feature"]["reboot_required"] is True

    def test_delayed_autostart_reset_in_powershell_script(self) -> None:
        """Проверка сброса DelayedAutoStart=0 в PowerShell-скрипте при переходе из delayed."""
        script_manual = build_windows_service_ps_script("TestSvc", state="started", startup_type="manual")
        assert "if ($curDelayed) { Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 0 -Type DWord }" in script_manual

        script_disabled = build_windows_service_ps_script("TestSvc", state="stopped", startup_type="disabled")
        assert "if ($curDelayed) { Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 0 -Type DWord }" in script_disabled

    def test_binary_normalization_formats(self) -> None:
        """Проверка нормализации типов Binary: bytes, bytearray, hex:, 0x, odd-length hex, и raw string."""
        from uniconn.services.provisioning.windows import _normalize_binary_bytes

        assert _normalize_binary_bytes(b"\xde\xad") == b"\xde\xad"
        assert _normalize_binary_bytes(bytearray([1, 2, 3])) == b"\x01\x02\x03"
        assert _normalize_binary_bytes("hex:01020304") == b"\x01\x02\x03\x04"
        assert _normalize_binary_bytes("0xdeadbeef") == b"\xde\xad\xbe\xef"
        # Нечетная длина hex дополняется ведущим нулем
        assert _normalize_binary_bytes("0x123") == b"\x01\x23"
        # Чистая hex-строка
        assert _normalize_binary_bytes("aabbcc") == b"\xaa\xbb\xcc"
        # Обычная строка
        assert _normalize_binary_bytes("hello world") == b"hello world"
        # Список байт
        assert _normalize_binary_bytes([0x0A, 0x0B]) == b"\x0a\x0b"

