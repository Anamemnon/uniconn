# src/uniconn/services/provisioning/packages.py
"""Стратегии пакетных менеджеров ОС (PackageManagerStrategy) и идемпотентная установка пакетов."""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal

from ...result import EnsureResult

if TYPE_CHECKING:
    from .facade import StateManagementService

PkgManagerName = Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"]

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


class PackageManagerStrategy(ABC):
    """Абстрактная стратегия работы с пакетным менеджером ОС."""

    name: str

    @classmethod
    def for_manager(cls, manager: str) -> PackageManagerStrategy:
        """Получить экземпляр стратегии по имени пакетного менеджера."""
        strat = PACKAGE_STRATEGIES.get(manager)
        if strat is None:
            raise ValueError(f"Unsupported package manager: {manager!r}")
        return strat

    @abstractmethod
    def check_installed_cmd(self, pkg: str) -> str:
        """Сформировать shell-команду проверки установленности пакета."""

    @abstractmethod
    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Сформировать shell-команду установки списка пакетов."""

    @abstractmethod
    def remove_cmd(self, packages: Sequence[str] | str) -> str:
        """Сформировать shell-команду удаления списка пакетов."""

    @staticmethod
    def quote_packages(packages: Sequence[str] | str) -> str:
        """Безопасно экранировать имя или список имён пакетов."""
        if isinstance(packages, str):
            return shlex.quote(packages)
        return " ".join(shlex.quote(p) for p in packages)


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


PACKAGE_STRATEGIES: dict[str, PackageManagerStrategy] = {
    "apt": AptStrategy(),
    "apk": ApkStrategy(),
    "dnf": DnfYumStrategy("dnf"),
    "yum": DnfYumStrategy("yum"),
    "pacman": PacmanStrategy(),
    "zypper": ZypperStrategy(),
}


async def resolve_pkg_manager(svc: StateManagementService, manager: PkgManagerName = "auto") -> str:
    """Определить пакетный менеджер хоста при ``manager='auto'``."""
    if manager != "auto":
        return manager

    cached_facts = svc._conn._cached_facts
    if cached_facts is not None:
        mapped = _OS_FAMILY_TO_PKG_MANAGER.get(cached_facts.os_family.lower())
        if mapped is not None:
            return mapped

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
            raise_on_error=False,
            dry_run=False,
        )
        if chk_res.ok != want_installed:
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

    act_res = await svc._conn.run(action_cmd, sudo=sudo, raise_on_error=False)
    return EnsureResult(
        target=target_str,
        state=state,
        changed=act_res.ok,
        ok=act_res.ok,
        details=act_res.stderr.strip() if not act_res.ok else f"Modified {', '.join(to_modify)} via {mgr_name}",
        dry_run=False,
    )
