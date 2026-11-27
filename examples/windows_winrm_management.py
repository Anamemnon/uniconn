"""Управление узлами Windows через WinRM / WS-Management (``winrm://``, ``wsman://``) и Windows Provisioning.

Демонстрирует:
- Подключение к Windows Server по HTTPS WinRM (NTLM / Kerberos, ``shell=ps|cmd``)
- Идемпотентные примитивы ``conn.state.ensure_windows_service``, ``ensure_registry_key`` и ``ensure_windows_feature``
- Просмотр unified diff и флага ``reboot_required`` в ``EnsureResult``
- Синхронный API (``SyncConnection``) и безопасный режим ``dry_run=True``
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Cassette, Connection, RecordedExecInteraction, SyncConnection
from uniconn.services.provisioning import (
    build_registry_key_ps_script,
    build_windows_feature_ps_script,
    build_windows_service_ps_script,
    normalize_registry_path,
)

# ─── Боевые примеры для Windows Server поверх WinRM ──────────────────────────


async def winrm_production_reference() -> None:
    """Справочный сценарий настройки реального сервера Windows через ``winrm://``."""
    uri = "winrm://Administrator:env://WIN_PASS@win-srv-01.corp:5986?ssl=true&transport=ntlm&shell=ps"
    async with Connection.from_uri(uri) as win:
        ps_ver = await win.run("$PSVersionTable.PSVersion.ToString()")
        print("PowerShell:", ps_ver.text)

        svc = await win.state.ensure_windows_service("W32Time", state="started", startup_type="automatic")
        reg = await win.state.ensure_registry_key(
            path=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            name="NoAutoUpdate",
            value=1,
            type="DWORD",
        )
        feat = await win.state.ensure_windows_feature("Web-Server", include_management_tools=True)
        print(f"Service changed={svc.changed}, Registry diff={reg.diff}, Reboot={feat.reboot_required}")


# ─── Самодостаточная локальная демонстрация через Replay-кассету ─────────────


async def main() -> None:
    """Локальный офлайн-прогон сценариев WinRM и Windows State Provisioning через кассету."""
    reg_path = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    _, ps_reg_path = normalize_registry_path(reg_path)

    svc_cmd = build_windows_service_ps_script("Spooler", state="started", startup_type="automatic", dry_run=False)
    reg_cmd = build_registry_key_ps_script(ps_reg_path, name="NoAutoUpdate", value=1, ps_type="DWord", state="present")
    feat_cmd = build_windows_feature_ps_script(["Web-Server"], state="present", include_management_tools=True)

    with tempfile.TemporaryDirectory(prefix="uniconn_winrm_") as tmpdir:
        cassette_path = Path(tmpdir) / "winrm_host.yaml"
        cassette = Cassette(
            transport="winrm",
            host="win-srv-01.corp",
            interactions=[
                RecordedExecInteraction(
                    command="Get-ComputerInfo | Select-Object CsName,OsName | ConvertTo-Json -Compress",
                    exit_code=0,
                    stdout='{"CsName":"WIN-SRV-01","OsName":"Microsoft Windows Server 2022 Standard"}\n',
                ),
                RecordedExecInteraction(
                    command=svc_cmd,
                    exit_code=0,
                    stdout=(
                        '{"ok":true,"changed":true,"actions":["startup_type:manual->automatic","start"],'
                        '"before_status":"Stopped","after_status":"Running",'
                        '"before_startup":"manual","after_startup":"automatic"}\n'
                    ),
                ),
                RecordedExecInteraction(
                    command=reg_cmd,
                    exit_code=0,
                    stdout='{"ok":true,"changed":true,"action":"updated_value","before":"DWord:0","after":"DWord:1"}\n',
                ),
                RecordedExecInteraction(
                    command=feat_cmd,
                    exit_code=3010,
                    stdout=(
                        '{"ok":true,"changed":true,"modified":["Web-Server"],'
                        '"provider":"ServerManager","reboot_required":true}\n'
                    ),
                ),
            ],
        )
        cassette.save(cassette_path)

        replay_uri = f"replay://win-srv-01.corp?cassette={cassette_path}&mode=none"
        async with Connection.from_uri(replay_uri) as win:
            print("=== 1. Информация о системе Windows (PowerShell JSON) ===")
            info = await win.run("Get-ComputerInfo | Select-Object CsName,OsName | ConvertTo-Json -Compress")
            print("Host info:", info.json())

            print("\n=== 2. Управление службой Windows (SCM) ===")
            svc_res = await win.state.ensure_windows_service("Spooler", state="started", startup_type="automatic")
            print(f"changed={svc_res.changed}, details={svc_res.details}")

            print("\n=== 3. Идемпотентная настройка реестра с unified diff ===")
            reg_res = await win.state.ensure_registry_key(
                path=reg_path,
                name="NoAutoUpdate",
                value=1,
                type="DWORD",
            )
            print(f"changed={reg_res.changed}, diff:\n{reg_res.diff}")

            print("\n=== 4. Установка роли ServerManager / DISM и контроль reboot_required ===")
            feat_res = await win.state.ensure_windows_feature("Web-Server", include_management_tools=True)
            print(f"changed={feat_res.changed}, reboot_required={feat_res.reboot_required}, details={feat_res.details}")

        print("\n=== 5. Синхронный dry_run через SyncConnection ===")
        with SyncConnection.from_uri(replay_uri, dry_run=True) as sync_win:
            dry_svc = sync_win.state.ensure_windows_service("W32Time", state="started", startup_type="automatic")
            print("Sync dry-run:", dry_svc.details)


if __name__ == "__main__":
    asyncio.run(main())
