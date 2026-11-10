# src/uniconn/services/provisioning/windows.py
"""Нативные примитивы провижининга Windows (SCM-службы, системный реестр, роли DISM/ServerManager)."""

from __future__ import annotations

import base64
import difflib
import json
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Literal

from ...result import EnsureResult
from ..facts import _is_windows_remote_connection

if TYPE_CHECKING:
    from ...core.connection import Connection
    from .facade import StateManagementService

WindowsServiceState = Literal["started", "stopped", "restarted"]
WindowsStartupType = Literal["automatic", "manual", "disabled", "delayed"]
RegistryValueType = Literal[
    "String", "ExpandString", "MultiString", "DWORD", "QWORD", "Binary"
]

_VALID_WIN_SERVICE_STATES: frozenset[str] = frozenset({"started", "stopped", "restarted"})
_VALID_WIN_STARTUP_TYPES: frozenset[str] = frozenset(
    {"automatic", "manual", "disabled", "delayed"}
)

_REGISTRY_HIVE_MAP: dict[str, tuple[str, str]] = {
    "HKLM": ("HKLM", "HKEY_LOCAL_MACHINE"),
    "HKEY_LOCAL_MACHINE": ("HKLM", "HKEY_LOCAL_MACHINE"),
    "HKCU": ("HKCU", "HKEY_CURRENT_USER"),
    "HKEY_CURRENT_USER": ("HKCU", "HKEY_CURRENT_USER"),
    "HKCR": ("HKCR", "HKEY_CLASSES_ROOT"),
    "HKEY_CLASSES_ROOT": ("HKCR", "HKEY_CLASSES_ROOT"),
    "HKU": ("HKU", "HKEY_USERS"),
    "HKEY_USERS": ("HKU", "HKEY_USERS"),
    "HKCC": ("HKCC", "HKEY_CURRENT_CONFIG"),
    "HKEY_CURRENT_CONFIG": ("HKCC", "HKEY_CURRENT_CONFIG"),
}

_REGISTRY_TYPE_MAP: dict[str, str] = {
    "STRING": "String",
    "REG_SZ": "String",
    "EXPANDSTRING": "ExpandString",
    "REG_EXPAND_SZ": "ExpandString",
    "MULTISTRING": "MultiString",
    "REG_MULTI_SZ": "MultiString",
    "DWORD": "DWord",
    "REG_DWORD": "DWord",
    "QWORD": "QWord",
    "REG_QWORD": "QWord",
    "BINARY": "Binary",
    "REG_BINARY": "Binary",
}

_REBOOT_EXIT_CODES: frozenset[int] = frozenset({3010, 1641})


def ps_quote(value: str) -> str:
    """Экранировать строку для безопасной подстановки в одинарные кавычки PowerShell."""
    return "'" + str(value).replace("'", "''") + "'"


def is_windows_connection(conn: Connection) -> bool:
    """Определить, относится ли подключение к семейству ОС Windows."""
    cached_facts = getattr(conn, "_cached_facts", None)
    if cached_facts is not None:
        os_fam = getattr(cached_facts, "os_family", "")
        if isinstance(os_fam, str) and os_fam.strip().lower() == "windows":
            return True
        if isinstance(os_fam, str) and os_fam.strip().lower() in (
            "debian",
            "alpine",
            "redhat",
            "arch",
            "suse",
            "linux",
            "darwin",
            "freebsd",
        ):
            return False
    if _is_windows_remote_connection(conn):
        return True
    return conn.transport_name == "local" and sys.platform == "win32"


def normalize_registry_path(path: str) -> tuple[str, str]:
    r"""Нормализовать путь реестра Windows в кортеж ``(canonical_path, ps_provider_path)``.

    Поддерживает нотации ``HKLM\Software\...``, ``HKLM:\Software\...``,
    ``HKEY_LOCAL_MACHINE\Software\...`` и ``Registry::HKEY_LOCAL_MACHINE\...``.
    """
    cleaned = str(path or "").strip().replace("/", "\\")
    if not cleaned:
        raise ValueError("Windows registry path cannot be empty")
    if cleaned.lower().startswith("registry::"):
        cleaned = cleaned[len("registry::") :].lstrip("\\")

    parts = [p for p in cleaned.split("\\") if p]
    if not parts:
        raise ValueError(f"Invalid Windows registry path: {path!r}")

    hive_raw = parts[0].rstrip(":").upper()
    mapped = _REGISTRY_HIVE_MAP.get(hive_raw)
    if mapped is None:
        raise ValueError(
            f"Unsupported Windows registry root hive {parts[0]!r} in path {path!r}"
        )

    short_hive, full_hive = mapped
    subpath = "\\".join(parts[1:])
    if subpath:
        canonical = f"{short_hive}\\{subpath}"
        ps_path = f"Registry::{full_hive}\\{subpath}"
    else:
        canonical = short_hive
        ps_path = f"Registry::{full_hive}"
    return canonical, ps_path


def normalize_registry_value_type(value_type: str) -> str:
    """Нормализовать имя типа значения реестра Windows к формату PowerShell ``PropertyType``."""
    key = str(value_type or "").strip().upper()
    normalized = _REGISTRY_TYPE_MAP.get(key)
    if normalized is None:
        raise ValueError(
            f"Unsupported Windows registry value type: {value_type!r}. "
            "Expected one of: String, ExpandString, MultiString, DWORD, QWORD, Binary."
        )
    return normalized


def _extract_json_payload(stdout: str) -> dict[str, Any] | None:
    """Извлечь JSON-словарь из вывода PowerShell (последняя JSON-строка или весь буфер)."""
    text = (stdout or "").strip()
    if not text:
        return None
    for candidate in (text, *reversed(text.splitlines())):
        line = candidate.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    return parsed
            except ValueError:
                continue
    return None


def _compute_unified_diff(
    before_text: str,
    after_text: str,
    *,
    target_label: str,
) -> str | None:
    """Сформировать компактный unified diff для изменённого ресурса Windows."""
    if before_text == after_text:
        return None
    b_lines = before_text.splitlines(keepends=True) if before_text else []
    a_lines = after_text.splitlines(keepends=True) if after_text else []
    diff = "".join(
        difflib.unified_diff(
            b_lines,
            a_lines,
            fromfile=f"a/{target_label}",
            tofile=f"b/{target_label}",
        )
    )
    return diff or None


def build_windows_service_ps_script(
    name: str,
    *,
    state: WindowsServiceState = "started",
    startup_type: WindowsStartupType | None = None,
    timeout: float = 30.0,
    dry_run: bool = False,
) -> str:
    """Сформировать однопроходный PowerShell-скрипт управления службой Windows (SCM)."""
    q_name = ps_quote(name)
    q_state = ps_quote(state)
    q_startup = ps_quote(startup_type or "")
    timeout_sec = max(1, round(timeout))
    dry_flag = "$true" if dry_run else "$false"

    return (
        f"$ErrorActionPreference = 'Stop'; "
        f"$svcName = {q_name}; "
        f"$targetState = {q_state}; "
        f"$targetStartup = {q_startup}; "
        f"$dryRun = {dry_flag}; "
        f"$timeoutSpan = [TimeSpan]::FromSeconds({timeout_sec}); "
        f"$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue; "
        f"if (-not $svc) {{ "
        f"@{{ ok = $false; changed = $false; error = \"Service '$svcName' not found\" }} "
        f"| ConvertTo-Json -Compress; exit 1 "
        f"}}; "
        f"if ($svc.Status -eq 'StartPending') {{ "
        f"$svc.WaitForStatus('Running', $timeoutSpan); $svc.Refresh() "
        f"}} elseif ($svc.Status -eq 'StopPending') {{ "
        f"$svc.WaitForStatus('Stopped', $timeoutSpan); $svc.Refresh() "
        f"}}; "
        f"$regPath = \"Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\$($svc.Name)\"; "
        f"$regItem = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue; "
        f"$curStart = [string]$svc.StartType; "
        f"$curDelayed = [bool]($regItem -and $regItem.DelayedAutoStart -eq 1); "
        f"if ($curStart -eq 'Automatic' -and $curDelayed) {{ $curStartupMode = 'delayed' }} "
        f"elseif ($curStart -eq 'Automatic') {{ $curStartupMode = 'automatic' }} "
        f"elseif ($curStart -eq 'Manual') {{ $curStartupMode = 'manual' }} "
        f"elseif ($curStart -eq 'Disabled') {{ $curStartupMode = 'disabled' }} "
        f"else {{ $curStartupMode = $curStart.ToLowerInvariant() }}; "
        f"$beforeStatus = [string]$svc.Status; "
        f"$afterStartup = $curStartupMode; "
        f"$actions = [System.Collections.Generic.List[string]]::new(); "
        f"if ($targetStartup -and $targetStartup -ne $curStartupMode) {{ "
        f"$actions.Add(\"startup_type:$curStartupMode->$targetStartup\"); "
        f"$afterStartup = $targetStartup; "
        f"if (-not $dryRun -and $targetStartup -ne 'disabled') {{ "
        f"if ($targetStartup -eq 'delayed') {{ "
        f"Set-Service -Name $svc.Name -StartupType Automatic; "
        f"Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 1 -Type DWord "
        f"}} elseif ($targetStartup -eq 'automatic') {{ "
        f"Set-Service -Name $svc.Name -StartupType Automatic; "
        f"if ($curDelayed) {{ Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 0 -Type DWord }} "
        f"}} elseif ($targetStartup -eq 'manual') {{ "
        f"Set-Service -Name $svc.Name -StartupType Manual; "
        f"if ($curDelayed) {{ Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 0 -Type DWord }} "
        f"}} "
        f"}} "
        f"}}; "
        f"$isRunning = ($svc.Status -eq 'Running'); "
        f"if ($targetState -eq 'started' -and -not $isRunning) {{ "
        f"$actions.Add('start'); "
        f"if (-not $dryRun) {{ "
        f"Start-Service -Name $svc.Name; $svc.Refresh(); "
        f"if ($svc.Status -ne 'Running') {{ $svc.WaitForStatus('Running', $timeoutSpan); $svc.Refresh() }} "
        f"}} "
        f"}} elseif ($targetState -eq 'stopped' -and $isRunning) {{ "
        f"$actions.Add('stop'); "
        f"if (-not $dryRun) {{ "
        f"Stop-Service -Name $svc.Name -Force; $svc.Refresh(); "
        f"if ($svc.Status -ne 'Stopped') {{ $svc.WaitForStatus('Stopped', $timeoutSpan); $svc.Refresh() }} "
        f"}} "
        f"}} elseif ($targetState -eq 'restarted') {{ "
        f"$actions.Add('restart'); "
        f"if (-not $dryRun) {{ "
        f"Restart-Service -Name $svc.Name -Force; $svc.Refresh(); "
        f"if ($svc.Status -ne 'Running') {{ $svc.WaitForStatus('Running', $timeoutSpan); $svc.Refresh() }} "
        f"}} "
        f"}}; "
        f"if ($targetStartup -eq 'disabled' -and $targetStartup -ne $curStartupMode -and -not $dryRun) {{ "
        f"Set-Service -Name $svc.Name -StartupType Disabled; "
        f"if ($curDelayed) {{ Set-ItemProperty -LiteralPath $regPath -Name 'DelayedAutoStart' -Value 0 -Type DWord }} "
        f"}}; "
        f"$afterStatus = if ($dryRun) {{ "
        f"if ($targetState -eq 'stopped') {{ 'Stopped' }} else {{ 'Running' }} "
        f"}} else {{ [string]$svc.Status }}; "
        f"@{{ "
        f"ok = $true; "
        f"changed = ($actions.Count -gt 0); "
        f"actions = @($actions); "
        f"before_status = $beforeStatus; "
        f"after_status = $afterStatus; "
        f"before_startup = $curStartupMode; "
        f"after_startup = $afterStartup "
        f"}} | ConvertTo-Json -Compress"
    )


async def ensure_windows_service(
    svc: StateManagementService,
    name: str,
    *,
    state: WindowsServiceState = "started",
    startup_type: WindowsStartupType | None = None,
    timeout: float = 30.0,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять службой Windows (SCM) с ожиданием переходных статусов."""
    svc_name = str(name or "").strip()
    if not svc_name:
        raise ValueError("Windows service name cannot be empty")
    if state not in _VALID_WIN_SERVICE_STATES:
        raise ValueError(
            f"Unsupported Windows service state: {state!r}. "
            "Expected 'started', 'stopped', or 'restarted'."
        )
    if startup_type is not None and startup_type not in _VALID_WIN_STARTUP_TYPES:
        raise ValueError(
            f"Unsupported Windows service startup_type: {startup_type!r}. "
            "Expected 'automatic', 'manual', 'disabled', or 'delayed'."
        )

    is_dry_run = svc._conn.dry_run if dry_run is None else dry_run
    if svc._conn.dry_run:
        startup_suffix = f", startup_type={startup_type}" if startup_type else ""
        return EnsureResult(
            target=svc_name,
            state=state,
            changed=True,
            ok=True,
            details=(
                f"[DRY-RUN] Would ensure Windows service {svc_name} "
                f"is {state}{startup_suffix}"
            ),
            dry_run=True,
        )

    ps_cmd = build_windows_service_ps_script(
        svc_name,
        state=state,
        startup_type=startup_type,
        timeout=timeout,
        dry_run=is_dry_run,
    )
    res = await svc._conn.run(
        ps_cmd,
        sudo=False,
        raise_on_error=False,
        dry_run=False,
    )

    payload = _extract_json_payload(res.stdout)
    reboot_req = res.exit_code in _REBOOT_EXIT_CODES or bool(
        payload and payload.get("reboot_required")
    )

    if payload is not None:
        ok = bool(payload.get("ok", res.ok or res.exit_code in _REBOOT_EXIT_CODES))
        changed = bool(payload.get("changed", False))
        if not ok:
            err_msg = str(
                payload.get("error") or res.stderr.strip() or f"Service {svc_name} failed"
            )
            return EnsureResult(
                target=svc_name,
                state=state,
                changed=False,
                ok=False,
                details=err_msg,
                dry_run=is_dry_run,
                reboot_required=reboot_req,
            )

        raw_actions = payload.get("actions") or []
        actions_list = (
            [str(a) for a in raw_actions]
            if isinstance(raw_actions, list)
            else [str(raw_actions)]
        )
        before_state_str = (
            f"status={payload.get('before_status')}\n"
            f"startup_type={payload.get('before_startup')}\n"
        )
        after_state_str = (
            f"status={payload.get('after_status')}\n"
            f"startup_type={payload.get('after_startup')}\n"
        )
        diff_str = (
            _compute_unified_diff(
                before_state_str,
                after_state_str,
                target_label=f"service/{svc_name}",
            )
            if changed
            else None
        )
        if not changed:
            details = f"Windows service {svc_name} already in state {state}"
        elif is_dry_run:
            details = (
                f"[DRY-RUN] Would update Windows service {svc_name}: "
                f"{', '.join(actions_list)}"
            )
        else:
            details = f"Windows service {svc_name}: {', '.join(actions_list)}"
        return EnsureResult(
            target=svc_name,
            state=state,
            changed=changed,
            ok=True,
            details=details,
            dry_run=is_dry_run,
            diff=diff_str,
            reboot_required=reboot_req,
        )

    is_ok = res.ok or res.exit_code in _REBOOT_EXIT_CODES
    return EnsureResult(
        target=svc_name,
        state=state,
        changed=is_ok,
        ok=is_ok,
        details=(
            res.stderr.strip()
            if not is_ok
            else (
                f"[DRY-RUN] Would ensure Windows service {svc_name} is {state}"
                if is_dry_run
                else f"Windows service {svc_name} ensured {state}"
            )
        ),
        dry_run=is_dry_run,
        reboot_required=reboot_req,
    )


def _normalize_binary_bytes(value: Any) -> bytes:
    """Преобразовать входное значение типа ``Binary`` в ``bytes``."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    if isinstance(value, str):
        raw_str = value.strip()
        is_hex_prefix = raw_str.startswith(("0x", "0X", "hex:", "HEX:"))
        if is_hex_prefix:
            cleaned = (
                raw_str[4:]
                if raw_str.lower().startswith("hex:")
                else raw_str[2:]
            )
            cleaned = cleaned.replace(" ", "").replace("-", "").replace(":", "")
            if len(cleaned) % 2 != 0:
                cleaned = "0" + cleaned
            try:
                return bytes.fromhex(cleaned)
            except ValueError as err:
                raise ValueError(
                    f"Invalid hexadecimal sequence for Binary registry value: {value!r}"
                ) from err
        # Проверяем, является ли строка чистым hex (например "deadbeef" или "01-02-03")
        cleaned = raw_str.replace(" ", "").replace("-", "").replace(":", "")
        if cleaned and len(cleaned) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return bytes.fromhex(cleaned)
        return raw_str.encode("utf-8")
    if isinstance(value, Sequence):
        return bytes(int(b) & 0xFF for b in value)
    raise ValueError(f"Unsupported Binary registry value: {value!r}")



def _format_registry_value_expression(
    value: Any,
    ps_type: str,
) -> tuple[str, str]:
    """Сформировать PowerShell-выражение значения реестра и каноническое строковое представление."""
    if ps_type in ("DWord", "QWord"):
        if value is None or isinstance(value, bool):
            raise ValueError(f"Registry type {ps_type} requires an integer value, got {value!r}")
        int_val = int(value, 0) if isinstance(value, str) else int(value)
        return f"([int64]{int_val})", str(int_val)

    if ps_type == "MultiString":
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, Sequence):
            items = [str(item) for item in value]
        else:
            raise ValueError(f"MultiString registry value must be a sequence of strings, got {value!r}")
        ps_items = ", ".join(ps_quote(s) for s in items)
        return f"[string[]]@({ps_items})", json.dumps(items, ensure_ascii=False)

    if ps_type == "Binary":
        raw_bytes = _normalize_binary_bytes(value)
        b64 = base64.b64encode(raw_bytes).decode("ascii")
        hex_repr = raw_bytes.hex()
        return f"[Convert]::FromBase64String({ps_quote(b64)})", f"hex:{hex_repr}"

    str_val = "" if value is None else str(value)
    return ps_quote(str_val), str_val


def build_registry_key_ps_script(
    ps_path: str,
    *,
    name: str | None = None,
    value: Any = None,
    ps_type: str = "String",
    state: Literal["present", "absent"] = "present",
    dry_run: bool = False,
) -> str:
    """Сформировать однопроходный PowerShell-скрипт идемпотентного управления реестром Windows."""
    q_path = ps_quote(ps_path)
    dry_flag = "$true" if dry_run else "$false"

    if name is None:
        if state == "present":
            return (
                f"$ErrorActionPreference = 'Stop'; "
                f"$regPath = {q_path}; $dryRun = {dry_flag}; "
                f"$exists = Test-Path -LiteralPath $regPath; "
                f"if (-not $exists) {{ "
                f"if (-not $dryRun) {{ New-Item -Path $regPath -Force | Out-Null }}; "
                f"@{{ ok = $true; changed = $true; action = 'created_key'; "
                f"before = 'absent'; after = 'present' }} | ConvertTo-Json -Compress "
                f"}} else {{ "
                f"@{{ ok = $true; changed = $false; action = 'noop'; "
                f"before = 'present'; after = 'present' }} | ConvertTo-Json -Compress "
                f"}}"
            )
        return (
            f"$ErrorActionPreference = 'Stop'; "
            f"$regPath = {q_path}; $dryRun = {dry_flag}; "
            f"$exists = Test-Path -LiteralPath $regPath; "
            f"if ($exists) {{ "
            f"if (-not $dryRun) {{ Remove-Item -LiteralPath $regPath -Recurse -Force }}; "
            f"@{{ ok = $true; changed = $true; action = 'removed_key'; "
            f"before = 'present'; after = 'absent' }} | ConvertTo-Json -Compress "
            f"}} else {{ "
            f"@{{ ok = $true; changed = $false; action = 'noop'; "
            f"before = 'absent'; after = 'absent' }} | ConvertTo-Json -Compress "
            f"}}"
        )

    q_name = ps_quote(name)
    if state == "absent":
        return (
            f"$ErrorActionPreference = 'Stop'; "
            f"$regPath = {q_path}; $valName = {q_name}; $dryRun = {dry_flag}; "
            f"if (-not (Test-Path -LiteralPath $regPath)) {{ "
            f"@{{ ok = $true; changed = $false; action = 'noop'; "
            f"before = $null; after = $null }} | ConvertTo-Json -Compress; exit 0 "
            f"}}; "
            f"$key = Get-Item -LiteralPath $regPath; "
            f"$curVal = $key.GetValue($valName, $null, 'DoNotExpandEnvironmentNames'); "
            f"if ($null -ne $curVal) {{ "
            f"$curKind = [string]$key.GetValueKind($valName); "
            f"$beforeStr = \"$curKind`:$curVal\"; "
            f"if (-not $dryRun) {{ Remove-ItemProperty -LiteralPath $regPath -Name $valName -Force }}; "
            f"@{{ ok = $true; changed = $true; action = 'removed_value'; "
            f"before = $beforeStr; after = $null }} | ConvertTo-Json -Compress "
            f"}} else {{ "
            f"@{{ ok = $true; changed = $false; action = 'noop'; "
            f"before = $null; after = $null }} | ConvertTo-Json -Compress "
            f"}}"
        )

    val_expr, canonical_after = _format_registry_value_expression(value, ps_type)
    q_type = ps_quote(ps_type)
    q_after_repr = ps_quote(f"{ps_type}:{canonical_after}")

    return (
        f"$ErrorActionPreference = 'Stop'; "
        f"$regPath = {q_path}; $valName = {q_name}; "
        f"$wantType = {q_type}; $wantVal = {val_expr}; "
        f"$afterRepr = {q_after_repr}; $dryRun = {dry_flag}; "
        f"$keyExists = Test-Path -LiteralPath $regPath; "
        f"$hasVal = $false; $curKind = ''; $curVal = $null; $beforeRepr = $null; "
        f"if ($keyExists) {{ "
        f"$key = Get-Item -LiteralPath $regPath; "
        f"$curVal = $key.GetValue($valName, $null, 'DoNotExpandEnvironmentNames'); "
        f"if ($null -ne $curVal) {{ "
        f"$hasVal = $true; "
        f"$curKind = [string]$key.GetValueKind($valName); "
        f"if ($curKind -eq 'Binary') {{ "
        f"$hex = ([BitConverter]::ToString([byte[]]$curVal) -replace '-', '').ToLowerInvariant(); "
        f"$beforeRepr = \"Binary:hex:$hex\" "
        f"}} elseif ($curKind -eq 'MultiString') {{ "
        f"$beforeRepr = \"MultiString:$(ConvertTo-Json @($curVal) -Compress)\" "
        f"}} else {{ "
        f"$beforeRepr = \"$curKind`:$curVal\" "
        f"}} "
        f"}} "
        f"}}; "
        f"$same = $false; "
        f"if ($hasVal -and $curKind -ieq $wantType) {{ "
        f"if ($wantType -eq 'Binary') {{ "
        f"$same = ([Linq.Enumerable]::SequenceEqual([byte[]]$curVal, [byte[]]$wantVal)) "
        f"}} elseif ($wantType -eq 'MultiString') {{ "
        f"$same = ([Linq.Enumerable]::SequenceEqual([string[]]$curVal, [string[]]$wantVal)) "
        f"}} elseif ($wantType -in @('DWord', 'QWord')) {{ "
        f"$same = ([int64]$curVal -eq [int64]$wantVal) "
        f"}} else {{ "
        f"$same = ([string]$curVal -ceq [string]$wantVal) "
        f"}} "
        f"}}; "
        f"if ($same) {{ "
        f"@{{ ok = $true; changed = $false; action = 'noop'; "
        f"before = $beforeRepr; after = $afterRepr }} | ConvertTo-Json -Compress "
        f"}} else {{ "
        f"if (-not $dryRun) {{ "
        f"if (-not $keyExists) {{ New-Item -Path $regPath -Force | Out-Null }}; "
        f"New-ItemProperty -LiteralPath $regPath -Name $valName -Value $wantVal "
        f"-PropertyType $wantType -Force | Out-Null "
        f"}}; "
        f"$act = if ($hasVal) {{ 'updated_value' }} else {{ 'created_value' }}; "
        f"@{{ ok = $true; changed = $true; action = $act; "
        f"before = $beforeRepr; after = $afterRepr }} | ConvertTo-Json -Compress "
        f"}}"
    )


async def ensure_registry_key(
    svc: StateManagementService,
    path: str,
    *,
    name: str | None = None,
    value: Any = None,
    type: RegistryValueType | str = "String",
    state: Literal["present", "absent"] = "present",
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять разделом или параметром системного реестра Windows."""
    if state not in ("present", "absent"):
        raise ValueError(
            f"Unsupported registry state: {state!r}. Expected 'present' or 'absent'."
        )
    canonical_path, ps_path = normalize_registry_path(path)
    ps_type = normalize_registry_value_type(type)
    target_label = f"{canonical_path}\\{name}" if name is not None else canonical_path
    is_dry_run = svc._conn.dry_run if dry_run is None else dry_run

    if name is not None and state == "present":
        # Валидируем значение на входе до обращения к транспорту
        _, canonical_after = _format_registry_value_expression(value, ps_type)
    else:
        canonical_after = state

    if svc._conn.dry_run:
        diff_preview = _compute_unified_diff(
            "",
            f"{name} = {ps_type}:{canonical_after}\n" if name else f"{canonical_path} ({state})\n",
            target_label=target_label,
        )
        return EnsureResult(
            target=target_label,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure registry {target_label} is {state}",
            dry_run=True,
            diff=diff_preview,
        )

    ps_cmd = build_registry_key_ps_script(
        ps_path,
        name=name,
        value=value,
        ps_type=ps_type,
        state=state,
        dry_run=is_dry_run,
    )
    res = await svc._conn.run(
        ps_cmd,
        sudo=False,
        raise_on_error=False,
        dry_run=False,
    )

    payload = _extract_json_payload(res.stdout)
    reboot_req = res.exit_code in _REBOOT_EXIT_CODES or bool(
        payload and payload.get("reboot_required")
    )

    if payload is not None:
        ok = bool(payload.get("ok", res.ok or res.exit_code in _REBOOT_EXIT_CODES))
        changed = bool(payload.get("changed", False))
        if not ok:
            err_msg = str(
                payload.get("error") or res.stderr.strip() or f"Registry {target_label} failed"
            )
            return EnsureResult(
                target=target_label,
                state=state,
                changed=False,
                ok=False,
                details=err_msg,
                dry_run=is_dry_run,
                reboot_required=reboot_req,
            )

        before_val = payload.get("before")
        after_val = payload.get("after")
        before_text = "" if before_val is None else f"{before_val}\n"
        after_text = "" if after_val is None else f"{after_val}\n"
        diff_str = (
            _compute_unified_diff(before_text, after_text, target_label=target_label)
            if changed
            else None
        )
        action = str(payload.get("action") or ("updated" if changed else "noop"))
        if not changed:
            details = f"Registry {target_label} already {state}"
        elif is_dry_run:
            details = f"[DRY-RUN] Would update registry {target_label} ({action})"
        else:
            details = f"Registry {target_label}: {action}"

        return EnsureResult(
            target=target_label,
            state=state,
            changed=changed,
            ok=True,
            details=details,
            dry_run=is_dry_run,
            diff=diff_str,
            reboot_required=reboot_req,
        )

    is_ok = res.ok or res.exit_code in _REBOOT_EXIT_CODES
    return EnsureResult(
        target=target_label,
        state=state,
        changed=is_ok,
        ok=is_ok,
        details=(
            res.stderr.strip()
            if not is_ok
            else (
                f"[DRY-RUN] Would ensure registry {target_label} is {state}"
                if is_dry_run
                else f"Registry {target_label} ensured {state}"
            )
        ),
        dry_run=is_dry_run,
        reboot_required=reboot_req,
    )


def build_windows_feature_ps_script(
    features: Sequence[str],
    *,
    state: Literal["present", "absent"] = "present",
    include_sub_features: bool = False,
    include_management_tools: bool = False,
    source: str | None = None,
    dry_run: bool = False,
) -> str:
    """Сформировать однопроходный PowerShell-скрипт управления ролями и фичами Windows (ServerManager / DISM)."""
    ps_features = ", ".join(ps_quote(f) for f in features)
    want_present = "$true" if state == "present" else "$false"
    sub_flag = "$true" if include_sub_features else "$false"
    mgmt_flag = "$true" if include_management_tools else "$false"
    q_source = ps_quote(source) if source else "$null"
    dry_flag = "$true" if dry_run else "$false"

    return (
        f"$ErrorActionPreference = 'Stop'; "
        f"$features = @({ps_features}); "
        f"$wantPresent = {want_present}; "
        f"$incSub = {sub_flag}; $incMgmt = {mgmt_flag}; "
        f"$src = {q_source}; $dryRun = {dry_flag}; "
        f"$toModify = [System.Collections.Generic.List[string]]::new(); "
        f"$rebootReq = $false; "
        f"$provider = 'dism'; "
        f"if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {{ "
        f"$provider = 'ServerManager'; "
        f"foreach ($f in $features) {{ "
        f"$info = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue; "
        f"if (-not $info) {{ "
        f"@{{ ok = $false; changed = $false; error = \"Windows feature '$f' not found\" }} "
        f"| ConvertTo-Json -Compress; exit 1 "
        f"}}; "
        f"$isInstalled = [bool]$info.Installed; "
        f"if ($isInstalled -ne $wantPresent) {{ $toModify.Add($f) }} "
        f"}}; "
        f"if ($toModify.Count -gt 0 -and -not $dryRun) {{ "
        f"if ($wantPresent) {{ "
        f"$params = @{{ Name = @($toModify); NoRestart = $true }}; "
        f"if ($incSub) {{ $params['IncludeAllSubFeature'] = $true }}; "
        f"if ($incMgmt) {{ $params['IncludeManagementTools'] = $true }}; "
        f"if ($src) {{ $params['Source'] = $src }}; "
        f"$res = Install-WindowsFeature @params; "
        f"if ($res.RestartNeeded -eq 'Yes' -or $LASTEXITCODE -eq 3010) {{ $rebootReq = $true }} "
        f"}} else {{ "
        f"$params = @{{ Name = @($toModify); NoRestart = $true }}; "
        f"if ($incMgmt) {{ $params['IncludeManagementTools'] = $true }}; "
        f"$res = Uninstall-WindowsFeature @params; "
        f"if ($res.RestartNeeded -eq 'Yes' -or $LASTEXITCODE -eq 3010) {{ $rebootReq = $true }} "
        f"}} "
        f"}} "
        f"}} else {{ "
        f"foreach ($f in $features) {{ "
        f"$info = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue; "
        f"if (-not $info) {{ "
        f"@{{ ok = $false; changed = $false; error = \"Windows optional feature '$f' not found\" }} "
        f"| ConvertTo-Json -Compress; exit 1 "
        f"}}; "
        f"$isEnabled = ([string]$info.State -eq 'Enabled'); "
        f"if ($isEnabled -ne $wantPresent) {{ $toModify.Add($f) }} "
        f"}}; "
        f"if ($toModify.Count -gt 0 -and -not $dryRun) {{ "
        f"foreach ($f in $toModify) {{ "
        f"if ($wantPresent) {{ "
        f"$params = @{{ Online = $true; FeatureName = $f; NoRestart = $true }}; "
        f"if ($incSub) {{ $params['All'] = $true }}; "
        f"if ($src) {{ $params['Source'] = $src }}; "
        f"$res = Enable-WindowsOptionalFeature @params; "
        f"if ($res.RestartNeeded -eq $true -or $LASTEXITCODE -eq 3010) {{ $rebootReq = $true }} "
        f"}} else {{ "
        f"$res = Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart; "
        f"if ($res.RestartNeeded -eq $true -or $LASTEXITCODE -eq 3010) {{ $rebootReq = $true }} "
        f"}} "
        f"}} "
        f"}} "
        f"}}; "
        f"@{{ "
        f"ok = $true; "
        f"changed = ($toModify.Count -gt 0); "
        f"modified = @($toModify); "
        f"provider = $provider; "
        f"reboot_required = [bool]$rebootReq "
        f"}} | ConvertTo-Json -Compress"
    )


async def ensure_windows_feature(
    svc: StateManagementService,
    name: str | Sequence[str],
    *,
    state: Literal["present", "absent"] = "present",
    include_sub_features: bool = False,
    include_management_tools: bool = False,
    source: str | None = None,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять ролями и компонентами Windows через ServerManager или DISM."""
    if state not in ("present", "absent"):
        raise ValueError(
            f"Unsupported Windows feature state: {state!r}. Expected 'present' or 'absent'."
        )
    features = (
        [name.strip()]
        if isinstance(name, str)
        else [str(item).strip() for item in name if str(item).strip()]
    )
    features = [f for f in features if f]
    if not features:
        raise ValueError("Windows feature name cannot be empty")

    target_str = ", ".join(features)
    is_dry_run = svc._conn.dry_run if dry_run is None else dry_run

    if svc._conn.dry_run:
        return EnsureResult(
            target=target_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure Windows feature(s) {target_str} are {state}",
            dry_run=True,
        )

    ps_cmd = build_windows_feature_ps_script(
        features,
        state=state,
        include_sub_features=include_sub_features,
        include_management_tools=include_management_tools,
        source=source,
        dry_run=is_dry_run,
    )
    res = await svc._conn.run(
        ps_cmd,
        sudo=False,
        raise_on_error=False,
        dry_run=False,
    )

    payload = _extract_json_payload(res.stdout)
    reboot_req = res.exit_code in _REBOOT_EXIT_CODES or bool(
        payload and payload.get("reboot_required")
    )

    if payload is not None:
        ok = bool(payload.get("ok", res.ok or res.exit_code in _REBOOT_EXIT_CODES))
        changed = bool(payload.get("changed", False))
        provider = str(payload.get("provider") or "DISM")
        if not ok:
            err_msg = str(
                payload.get("error")
                or res.stderr.strip()
                or f"Windows feature(s) {target_str} failed"
            )
            return EnsureResult(
                target=target_str,
                state=state,
                changed=False,
                ok=False,
                details=err_msg,
                dry_run=is_dry_run,
                reboot_required=reboot_req,
            )

        raw_mod = payload.get("modified") or []
        mod_list = (
            [str(x) for x in raw_mod]
            if isinstance(raw_mod, list)
            else [str(raw_mod)]
        )
        mod_str = ", ".join(mod_list) if mod_list else target_str
        reboot_note = " (reboot required)" if reboot_req else ""
        if not changed:
            details = f"Windows feature(s) {target_str} already {state} ({provider})"
        elif is_dry_run:
            details = f"[DRY-RUN] Would set Windows feature(s) {mod_str} to {state} via {provider}"
        else:
            details = f"Modified Windows feature(s) {mod_str} -> {state} via {provider}{reboot_note}"

        return EnsureResult(
            target=target_str,
            state=state,
            changed=changed,
            ok=True,
            details=details,
            dry_run=is_dry_run,
            reboot_required=reboot_req,
        )

    is_ok = res.ok or res.exit_code in _REBOOT_EXIT_CODES
    reboot_note = " (reboot required)" if reboot_req else ""
    return EnsureResult(
        target=target_str,
        state=state,
        changed=is_ok,
        ok=is_ok,
        details=(
            res.stderr.strip()
            if not is_ok
            else (
                f"[DRY-RUN] Would ensure Windows feature(s) {target_str} are {state}"
                if is_dry_run
                else f"Windows feature(s) {target_str} ensured {state}{reboot_note}"
            )
        ),
        dry_run=is_dry_run,
        reboot_required=reboot_req,
    )


__all__ = [
    "RegistryValueType",
    "WindowsServiceState",
    "WindowsStartupType",
    "build_registry_key_ps_script",
    "build_windows_feature_ps_script",
    "build_windows_service_ps_script",
    "ensure_registry_key",
    "ensure_windows_feature",
    "ensure_windows_service",
    "is_windows_connection",
    "normalize_registry_path",
    "normalize_registry_value_type",
    "ps_quote",
]
