# src/uniconn/services/provisioning/packages.py
"""Стратегии пакетных менеджеров ОС (PackageManagerStrategy) и идемпотентная установка пакетов."""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

from ...result import EnsureResult, Result
from .windows import is_windows_connection, ps_quote

if TYPE_CHECKING:
    from .facade import StateManagementService

PkgManagerName = Literal[
    "auto",
    "apt",
    "dnf",
    "yum",
    "apk",
    "pacman",
    "zypper",
    "winget",
    "choco",
    "scoop",
]

_OS_FAMILY_TO_PKG_MANAGER: dict[str, str] = {
    "debian": "apt",
    "alpine": "apk",
    "redhat": "dnf",
    "arch": "pacman",
    "suse": "zypper",
}

_DETECT_PKG_MANAGER_CMD = (
    "if command -v apt-get >/dev/null 2>&1; then echo apt; "
    "elif command -v dnf >/dev/null 2>&1; then echo dnf; "
    "elif command -v apk >/dev/null 2>&1; then echo apk; "
    "elif command -v yum >/dev/null 2>&1; then echo yum; "
    "elif command -v pacman >/dev/null 2>&1; then echo pacman; "
    "elif command -v zypper >/dev/null 2>&1; then echo zypper; "
    "else echo apt; fi"
)

_DETECT_WINDOWS_PKG_MANAGER_CMD = (
    "if (Get-Command winget -ErrorAction SilentlyContinue) { Write-Output 'winget' } "
    "elseif (Get-Command choco -ErrorAction SilentlyContinue) { Write-Output 'choco' } "
    "elseif (Get-Command scoop -ErrorAction SilentlyContinue) { Write-Output 'scoop' } "
    "else { Write-Output 'winget' }"
)

_WINDOWS_REBOOT_EXIT_CODES: frozenset[int] = frozenset({3010, 1641})


class PackageManagerStrategy(ABC):
    """Абстрактная стратегия работы с пакетным менеджером ОС."""

    name: str
    is_windows: bool = False

    @classmethod
    def for_manager(cls, manager: str) -> PackageManagerStrategy:
        """Получить экземпляр стратегии по имени пакетного менеджера."""
        strat = PACKAGE_STRATEGIES.get(manager)
        if strat is None:
            raise ValueError(f"Unsupported package manager: {manager!r}")
        return strat

    @abstractmethod
    def check_installed_cmd(self, pkg: str) -> str:
        """Сформировать команду проверки установленности пакета."""

    @abstractmethod
    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Сформировать команду установки списка пакетов."""

    @abstractmethod
    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Сформировать команду удаления списка пакетов."""

    def is_installed_result(self, res: Result, pkg: str) -> bool:
        """Проверить по результату команды, установлен ли пакет ``pkg``."""
        _ = pkg
        return res.ok

    @staticmethod
    def quote_packages(packages: Sequence[str] | str) -> str:
        """Безопасно экранировать имя или список имён пакетов для POSIX-оболочки."""
        if isinstance(packages, str):
            return shlex.quote(packages)
        return " ".join(shlex.quote(p) for p in packages)

    @staticmethod
    def ps_quote_packages(packages: Sequence[str] | str) -> str:
        """Безопасно экранировать имя или список имён пакетов для PowerShell."""
        if isinstance(packages, str):
            return ps_quote(packages)
        return " ".join(ps_quote(p) for p in packages)


class AptStrategy(PackageManagerStrategy):
    """Стратегия для Debian/Ubuntu (``apt-get`` / ``dpkg-query``)."""

    name = "apt"

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``dpkg-query``."""
        q_pkg = shlex.quote(pkg)
        return f"dpkg-query -W -f='${{Status}}' {q_pkg} 2>/dev/null | grep -q 'install ok installed'"

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда неинтерактивной установки через ``apt-get install``."""
        quoted = self.quote_packages(packages)
        prefix = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && " if update_cache else ""
        return f"{prefix}DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {quoted}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда неинтерактивного удаления через ``apt-get remove``."""
        quoted = self.quote_packages(packages)
        return f"DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq {quoted}"


class ApkStrategy(PackageManagerStrategy):
    """Стратегия для Alpine Linux (``apk``)."""

    name = "apk"

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``apk info -e``."""
        return f"apk info -e {shlex.quote(pkg)} >/dev/null 2>&1"

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда установки через ``apk add``."""
        upd = "--update-cache " if update_cache else ""
        return f"apk add --no-progress {upd}{self.quote_packages(packages)}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда удаления через ``apk del``."""
        return f"apk del --no-progress {self.quote_packages(packages)}"


class DnfYumStrategy(PackageManagerStrategy):
    """Стратегия для RHEL/Fedora/Rocky/AlmaLinux (``dnf`` или ``yum`` + ``rpm``)."""

    def __init__(self, binary: Literal["dnf", "yum"] = "dnf") -> None:
        """Инициализировать стратегию для ``dnf`` или ``yum``."""
        self.name = binary

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``rpm -q``."""
        return f"rpm -q {shlex.quote(pkg)} >/dev/null 2>&1"

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда установки через ``dnf/yum install -y``."""
        _ = update_cache
        return f"{self.name} install -y {self.quote_packages(packages)}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда удаления через ``dnf/yum remove -y``."""
        return f"{self.name} remove -y {self.quote_packages(packages)}"


class PacmanStrategy(PackageManagerStrategy):
    """Стратегия для Arch Linux (``pacman``)."""

    name = "pacman"

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``pacman -Qi``."""
        return f"pacman -Qi {shlex.quote(pkg)} >/dev/null 2>&1"

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда установки через ``pacman -S/-Syu``."""
        sync_flag = "-Syu" if update_cache else "-S"
        return f"pacman {sync_flag} --noconfirm {self.quote_packages(packages)}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда удаления через ``pacman -R``."""
        return f"pacman -R --noconfirm {self.quote_packages(packages)}"


class ZypperStrategy(PackageManagerStrategy):
    """Стратегия для openSUSE / SLES (``zypper`` + ``rpm``)."""

    name = "zypper"

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``rpm -q``."""
        return f"rpm -q {shlex.quote(pkg)} >/dev/null 2>&1"

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда установки через ``zypper --non-interactive install``."""
        _ = update_cache
        return f"zypper --non-interactive install {self.quote_packages(packages)}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда удаления через ``zypper --non-interactive remove``."""
        return f"zypper --non-interactive remove {self.quote_packages(packages)}"


class WingetStrategy(PackageManagerStrategy):
    """Стратегия для Windows Package Manager (``winget``)."""

    name = "winget"
    is_windows = True

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки пакета через ``winget list --id <pkg> --exact``."""
        q_pkg = ps_quote(pkg)
        return (
            f"winget list --id {q_pkg} --exact "
            "--accept-source-agreements --disable-interactivity"
        )

    def is_installed_result(self, res: Result, pkg: str) -> bool:
        """Проверить статус установки пакета ``winget`` с защитой от текстового отказа."""
        _ = pkg
        if not res.ok:
            return False
        low = res.stdout.lower()
        return "no installed package found" not in low

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда неинтерактивной установки через ``winget install``."""
        pkgs = [packages] if isinstance(packages, str) else list(packages)
        prefix = "winget source update --disable-interactivity; " if update_cache else ""
        if len(pkgs) == 1:
            q_pkg = ps_quote(pkgs[0])
            return (
                f"{prefix}winget install --id {q_pkg} --exact --silent "
                "--accept-package-agreements --accept-source-agreements --disable-interactivity"
            )
        parts = [
            f"winget install --id {ps_quote(p)} --exact --silent "
            "--accept-package-agreements --accept-source-agreements --disable-interactivity"
            for p in pkgs
        ]
        return prefix + "; ".join(parts)

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда неинтерактивного удаления через ``winget uninstall``."""
        pkgs = [packages] if isinstance(packages, str) else list(packages)
        if len(pkgs) == 1:
            q_pkg = ps_quote(pkgs[0])
            return (
                f"winget uninstall --id {q_pkg} --exact --silent "
                "--accept-source-agreements --disable-interactivity"
            )
        parts = [
            f"winget uninstall --id {ps_quote(p)} --exact --silent "
            "--accept-source-agreements --disable-interactivity"
            for p in pkgs
        ]
        return "; ".join(parts)


class ChocoStrategy(PackageManagerStrategy):
    """Стратегия для Chocolatey (``choco``) на Windows."""

    name = "choco"
    is_windows = True

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки установленности пакета через ``choco list --local-only --exact``."""
        q_pkg = ps_quote(pkg)
        return (
            f"$out = choco list --local-only --exact {q_pkg} --limit-output; "
            "if ($LASTEXITCODE -eq 0 -and $out) { Write-Output $out; exit 0 } else { exit 1 }"
        )

    def is_installed_result(self, res: Result, pkg: str) -> bool:
        """Проверить результат ``choco list`` с учётом пустого вывода или флага ``0 packages``."""
        _ = pkg
        if not res.ok:
            return False
        low = res.stdout.lower()
        return "0 packages installed" not in low

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда неинтерактивной установки через ``choco install -y --no-progress``."""
        _ = update_cache
        return f"choco install {self.ps_quote_packages(packages)} -y --no-progress"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда неинтерактивного удаления через ``choco uninstall -y --no-progress``."""
        return f"choco uninstall {self.ps_quote_packages(packages)} -y --no-progress"


class ScoopStrategy(PackageManagerStrategy):
    """Стратегия для пакетного менеджера Scoop (``scoop``) на Windows."""

    name = "scoop"
    is_windows = True

    def check_installed_cmd(self, pkg: str) -> str:
        """Команда проверки установленности пакета через ``scoop list``."""
        q_pkg = ps_quote(pkg)
        return (
            f"$out = scoop list {q_pkg} | Out-String; "
            f"if ($out -match ('(?m)^\\s*' + [regex]::Escape({q_pkg}) + '\\b')) "
            "{ exit 0 } else { exit 1 }"
        )

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда установки через ``scoop install``."""
        prefix = "scoop update; " if update_cache else ""
        return f"{prefix}scoop install {self.ps_quote_packages(packages)}"

    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Команда удаления через ``scoop uninstall``."""
        return f"scoop uninstall {self.ps_quote_packages(packages)}"


PACKAGE_STRATEGIES: dict[str, PackageManagerStrategy] = {
    "apt": AptStrategy(),
    "apk": ApkStrategy(),
    "dnf": DnfYumStrategy("dnf"),
    "yum": DnfYumStrategy("yum"),
    "pacman": PacmanStrategy(),
    "zypper": ZypperStrategy(),
    "winget": WingetStrategy(),
    "choco": ChocoStrategy(),
    "scoop": ScoopStrategy(),
}


async def resolve_pkg_manager(svc: StateManagementService, manager: PkgManagerName = "auto") -> str:
    """Определить пакетный менеджер хоста при ``manager='auto'`` (Linux и Windows)."""
    if manager != "auto":
        if manager not in PACKAGE_STRATEGIES:
            raise ValueError(f"Unsupported package manager: {manager!r}")
        return manager

    cached_facts = svc._conn._cached_facts
    if cached_facts is not None:
        os_family_low = cached_facts.os_family.lower()
        mapped = _OS_FAMILY_TO_PKG_MANAGER.get(os_family_low)
        if mapped is not None:
            return mapped

    if is_windows_connection(svc._conn):
        res_win = await svc._conn.run(
            _DETECT_WINDOWS_PKG_MANAGER_CMD,
            sudo=False,
            raise_on_error=False,
            dry_run=False,
        )
        detected_win = res_win.text.splitlines()[0].strip().lower() if res_win.text else "winget"
        return detected_win if detected_win in ("winget", "choco", "scoop") else "winget"

    res = await svc._conn.run(_DETECT_PKG_MANAGER_CMD, raise_on_error=False, dry_run=False)
    detected = res.text.splitlines()[0].strip() if res.text else "apt"
    return detected if detected in PACKAGE_STRATEGIES else "apt"


async def ensure_package(
    svc: StateManagementService,
    package: str | Sequence[str],
    state: Literal["present", "absent"] = "present",
    manager: PkgManagerName = "auto",
    update_cache: bool = False,
    sudo: bool = True,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте."""
    pkgs = [package] if isinstance(package, str) else [str(p) for p in package]
    target_str = ", ".join(pkgs)
    is_dry_run = svc._conn.dry_run if dry_run is None else dry_run

    if svc._conn.dry_run:
        return EnsureResult(
            target=target_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure package(s) {target_str} are {state}",
            dry_run=True,
        )

    mgr_name = await svc.resolve_pkg_manager(manager)
    strategy = PACKAGE_STRATEGIES.get(mgr_name, PACKAGE_STRATEGIES["apt"])
    want_installed = state == "present"
    to_modify: list[str] = []

    for pkg in pkgs:
        chk_res = await svc._conn.run(
            strategy.check_installed_cmd(pkg),
            sudo=False,
            raise_on_error=False,
            dry_run=False,
        )
        is_installed = strategy.is_installed_result(chk_res, pkg)
        if is_installed != want_installed:
            to_modify.append(pkg)

    if not to_modify:
        return EnsureResult(
            target=target_str,
            state=state,
            changed=False,
            ok=True,
            details=f"Package(s) {target_str} already {state} ({mgr_name})",
            dry_run=is_dry_run,
        )

    action_cmd = (
        strategy.install_cmd(to_modify, update_cache=update_cache)
        if want_installed
        else strategy.remove_cmd(to_modify)
    )
    if is_dry_run:
        return EnsureResult(
            target=target_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would run: {action_cmd}",
            dry_run=True,
        )

    effective_sudo = False if (strategy.is_windows or is_windows_connection(svc._conn)) else sudo
    act_res = await svc._conn.run(action_cmd, sudo=effective_sudo, raise_on_error=False)
    is_reboot_code = strategy.is_windows and act_res.exit_code in _WINDOWS_REBOOT_EXIT_CODES
    combined_out = f"{act_res.stdout}\n{act_res.stderr}".lower()
    reboot_required = is_reboot_code or (
        strategy.is_windows
        and any(
            marker in combined_out
            for marker in (
                "restart is required",
                "reboot is required",
                "reboot required",
                "exit code 3010",
            )
        )
    )
    is_ok = act_res.ok or is_reboot_code
    reboot_suffix = " (reboot required)" if reboot_required else ""
    return EnsureResult(
        target=target_str,
        state=state,
        changed=is_ok,
        ok=is_ok,
        details=(
            act_res.stderr.strip() or act_res.stdout.strip()
            if not is_ok
            else f"Modified {', '.join(to_modify)} via {mgr_name}{reboot_suffix}"
        ),
        dry_run=False,
        reboot_required=reboot_required,
    )
