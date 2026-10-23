# src/uniconn/services/provisioning.py
"""Доменный сервис идемпотентного управления состоянием (Strategy Pattern для пакетов и сервисов)."""

from __future__ import annotations

import re
import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..result import EnsureResult

if TYPE_CHECKING:
    from .._connection import Connection
    from .._facts import HostFacts

PkgManagerName = Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"]
ServiceState = Literal["started", "stopped", "restarted", "reloaded"]


# ─── Стратегии пакетных менеджеров (PackageManagerStrategy) ────────


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
    def install_cmd(self, packages: Sequence[str], update_cache: bool = False) -> str:
        """Сформировать shell-команду установки списка пакетов."""

    @abstractmethod
    def remove_cmd(self, packages: Sequence[str]) -> str:
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
        return (
            f"dpkg-query -W -f='${{Status}}' {q_pkg} 2>/dev/null "
            "| grep -q 'install ok installed'"
        )

    def install_cmd(self, packages: Sequence[str] | str, update_cache: bool = False) -> str:
        """Команда неинтерактивной установки через ``apt-get install``."""
        quoted = self.quote_packages(packages)
        prefix = (
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
            if update_cache
            else ""
        )
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


# ─── Стратегии систем инициализации (ServiceManagerStrategy) ──────


class ServiceManagerStrategy(ABC):
    """Абстрактная стратегия управления системными сервисами."""

    name: str

    @classmethod
    def for_system(
        cls,
        system: str = "auto",
        *,
        has_systemctl: bool | None = None,
    ) -> ServiceManagerStrategy:
        """Получить стратегию управления сервисами по имени системы инициализации."""
        if has_systemctl is True:
            return SERVICE_STRATEGIES["systemd"]
        if has_systemctl is False and system == "auto":
            return SERVICE_STRATEGIES["sysv"]
        strat = SERVICE_STRATEGIES.get(system)
        if strat is None:
            raise ValueError(f"Unsupported service manager: {system!r}")
        return strat

    @abstractmethod
    def status_cmd(self, service: str) -> str:
        """Команда проверки активности сервиса."""

    @abstractmethod
    def action_cmd(
        self,
        service: str,
        action: Literal["start", "stop", "restart", "reload"],
    ) -> str:
        """Команда выполнения действия над сервисом."""

    @abstractmethod
    def is_enabled_cmd(self, service: str) -> str:
        """Команда проверки автозапуска сервиса."""

    @abstractmethod
    def set_enabled_cmd(self, service: str, enabled: bool) -> str:
        """Команда включения или отключения автозапуска."""


class SystemdStrategy(ServiceManagerStrategy):
    """Стратегия для ``systemd`` (``systemctl``)."""

    name = "systemd"

    def status_cmd(self, service: str) -> str:
        """Команда ``systemctl is-active --quiet``."""
        return f"systemctl is-active --quiet {shlex.quote(service)}"

    def action_cmd(
        self,
        service: str,
        action: Literal["start", "stop", "restart", "reload"],
    ) -> str:
        """Команда ``systemctl <action>``."""
        return f"systemctl {action} {shlex.quote(service)}"

    def is_enabled_cmd(self, service: str) -> str:
        """Команда ``systemctl is-enabled --quiet``."""
        return f"systemctl is-enabled --quiet {shlex.quote(service)}"

    def set_enabled_cmd(self, service: str, enabled: bool) -> str:
        """Команда ``systemctl enable/disable``."""
        verb = "enable" if enabled else "disable"
        return f"systemctl {verb} {shlex.quote(service)}"


class OpenRCStrategy(ServiceManagerStrategy):
    """Стратегия для Alpine OpenRC (``rc-service`` / ``rc-update``)."""

    name = "openrc"

    def status_cmd(self, service: str) -> str:
        """Команда ``rc-service <svc> status``."""
        return f"rc-service {shlex.quote(service)} status >/dev/null 2>&1"

    def action_cmd(
        self,
        service: str,
        action: Literal["start", "stop", "restart", "reload"],
    ) -> str:
        """Команда ``rc-service <svc> <action>``."""
        return f"rc-service {shlex.quote(service)} {action}"

    def is_enabled_cmd(self, service: str) -> str:
        """Команда проверки сервиса в ``rc-update show default``."""
        return f"rc-update show default 2>/dev/null | grep -qw {shlex.quote(service)}"

    def set_enabled_cmd(self, service: str, enabled: bool) -> str:
        """Команда ``rc-update add/del <svc> default``."""
        verb = "add" if enabled else "del"
        return f"rc-update {verb} {shlex.quote(service)} default"


class SysVStrategy(ServiceManagerStrategy):
    """Стратегия для классического SysVinit (``service``)."""

    name = "sysv"

    def status_cmd(self, service: str) -> str:
        """Команда ``service <svc> status``."""
        return f"service {shlex.quote(service)} status >/dev/null 2>&1"

    def action_cmd(
        self,
        service: str,
        action: Literal["start", "stop", "restart", "reload"],
    ) -> str:
        """Команда ``service <svc> <action>``."""
        return f"service {shlex.quote(service)} {action}"

    def is_enabled_cmd(self, service: str) -> str:
        """Команда проверки автозапуска."""
        return f"systemctl is-enabled --quiet {shlex.quote(service)}"

    def set_enabled_cmd(self, service: str, enabled: bool) -> str:
        """Команда включения или отключения автозапуска."""
        verb = "enable" if enabled else "disable"
        return f"systemctl {verb} {shlex.quote(service)}"


class UniversalServiceStrategy(ServiceManagerStrategy):
    """Универсальная POSIX-стратегия (systemd -> OpenRC -> SysV за один shell-вызов)."""

    name = "auto"

    def status_cmd(self, service: str) -> str:
        """Универсальная команда проверки статуса сервиса."""
        q_svc = shlex.quote(service)
        return (
            f"if command -v systemctl >/dev/null 2>&1; then systemctl is-active --quiet {q_svc}; "
            f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} status >/dev/null 2>&1; "
            f"else service {q_svc} status >/dev/null 2>&1; fi"
        )

    def action_cmd(
        self,
        service: str,
        action: Literal["start", "stop", "restart", "reload"],
    ) -> str:
        """Универсальная команда выполнения действия над сервисом."""
        q_svc = shlex.quote(service)
        return (
            f"if command -v systemctl >/dev/null 2>&1; then systemctl {action} {q_svc}; "
            f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} {action}; "
            f"else service {q_svc} {action}; fi"
        )

    def is_enabled_cmd(self, service: str) -> str:
        """Команда проверки автозапуска."""
        return f"systemctl is-enabled --quiet {shlex.quote(service)}"

    def set_enabled_cmd(self, service: str, enabled: bool) -> str:
        """Команда включения или отключения автозапуска."""
        verb = "enable" if enabled else "disable"
        return f"systemctl {verb} {shlex.quote(service)}"


SERVICE_STRATEGIES: dict[str, ServiceManagerStrategy] = {
    "auto": UniversalServiceStrategy(),
    "systemd": SystemdStrategy(),
    "openrc": OpenRCStrategy(),
    "sysv": SysVStrategy(),
}


# ─── Сервис идемпотентного состояния (StateManagementService) ─────


class StateManagementService:
    """Доменный сервис идемпотентных проверок и конфигурации (``conn.state``)."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис для указанного подключения."""
        self._conn = conn

    async def gather_facts(
        self,
        *,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты о хосте (делегирует в ``conn.gather_facts``)."""
        return await self._conn.gather_facts(refresh=refresh, timeout=timeout)

    async def resolve_pkg_manager(self, manager: PkgManagerName = "auto") -> str:
        """Определить пакетный менеджер хоста при ``manager='auto'``."""
        if manager != "auto":
            return manager

        cached_facts = self._conn._cached_facts
        if cached_facts is not None:
            fam = cached_facts.os_family.lower()
            os_map = {
                "debian": "apt",
                "alpine": "apk",
                "redhat": "dnf",
                "arch": "pacman",
                "suse": "zypper",
            }
            if fam in os_map:
                return os_map[fam]

        detect_cmd = (
            "if command -v apt-get >/dev/null 2>&1; then echo apt; "
            "elif command -v dnf >/dev/null 2>&1; then echo dnf; "
            "elif command -v apk >/dev/null 2>&1; then echo apk; "
            "elif command -v yum >/dev/null 2>&1; then echo yum; "
            "elif command -v pacman >/dev/null 2>&1; then echo pacman; "
            "elif command -v zypper >/dev/null 2>&1; then echo zypper; "
            "else echo apt; fi"
        )
        res = await self._conn.run(detect_cmd, raise_on_error=False, dry_run=False)
        detected = res.text.splitlines()[0].strip() if res.text else "apt"
        return detected if detected in PACKAGE_STRATEGIES else "apt"

    async def ensure_package(
        self,
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
        is_dry_run = self._conn._dry_run if dry_run is None else dry_run

        if self._conn._dry_run:
            return EnsureResult(
                target=target_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure package(s) {target_str} are {state}",
                dry_run=True,
            )

        mgr_name = await self.resolve_pkg_manager(manager)
        strategy = PACKAGE_STRATEGIES.get(mgr_name, PACKAGE_STRATEGIES["apt"])
        to_modify: list[str] = []

        for pkg in pkgs:
            chk_cmd = strategy.check_installed_cmd(pkg)
            chk_res = await self._conn.run(chk_cmd, raise_on_error=False, dry_run=False)
            is_installed = chk_res.ok
            if (state == "present" and not is_installed) or (
                state == "absent" and is_installed
            ):
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
            if state == "present"
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

        act_res = await self._conn.run(action_cmd, sudo=sudo, raise_on_error=False)
        return EnsureResult(
            target=target_str,
            state=state,
            changed=act_res.ok,
            ok=act_res.ok,
            details=(
                act_res.stderr.strip()
                if not act_res.ok
                else f"Modified {', '.join(to_modify)} via {mgr_name}"
            ),
            dry_run=False,
        )

    async def ensure_service(
        self,
        service: str,
        state: ServiceState = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
        manager: Literal["auto", "systemd", "openrc", "sysv"] = "auto",
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса."""
        is_dry_run = self._conn._dry_run if dry_run is None else dry_run
        if self._conn._dry_run:
            return EnsureResult(
                target=service,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure service {service} is {state}",
                dry_run=True,
            )

        strategy = SERVICE_STRATEGIES.get(manager, SERVICE_STRATEGIES["auto"])
        status_res = await self._conn.run(
            strategy.status_cmd(service),
            raise_on_error=False,
            dry_run=False,
        )
        is_active = status_res.ok

        actions_taken: list[str] = []
        commands_to_run: list[str] = []

        if state == "started" and not is_active:
            actions_taken.append("start")
            commands_to_run.append(strategy.action_cmd(service, "start"))
        elif state == "stopped" and is_active:
            actions_taken.append("stop")
            commands_to_run.append(strategy.action_cmd(service, "stop"))
        elif state == "restarted":
            actions_taken.append("restart")
            commands_to_run.append(strategy.action_cmd(service, "restart"))
        elif state == "reloaded":
            actions_taken.append("reload")
            commands_to_run.append(strategy.action_cmd(service, "reload"))

        if enabled is not None:
            enabled_chk = await self._conn.run(
                strategy.is_enabled_cmd(service),
                raise_on_error=False,
                dry_run=False,
            )
            is_enabled = enabled_chk.ok
            if enabled and not is_enabled:
                actions_taken.append("enable")
                commands_to_run.append(strategy.set_enabled_cmd(service, True))
            elif not enabled and is_enabled:
                actions_taken.append("disable")
                commands_to_run.append(strategy.set_enabled_cmd(service, False))

        if not commands_to_run:
            return EnsureResult(
                target=service,
                state=state,
                changed=False,
                ok=True,
                details=f"Service {service} already in state {state}",
                dry_run=is_dry_run,
            )

        if is_dry_run:
            return EnsureResult(
                target=service,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would run actions on {service}: {', '.join(actions_taken)}",
                dry_run=True,
            )

        combined_cmd = " && ".join(commands_to_run)
        act_res = await self._conn.run(combined_cmd, sudo=sudo, raise_on_error=False)
        return EnsureResult(
            target=service,
            state=state,
            changed=act_res.ok,
            ok=act_res.ok,
            details=(
                act_res.stderr.strip()
                if not act_res.ok
                else f"Service {service}: {', '.join(actions_taken)}"
            ),
            dry_run=False,
        )

    async def ensure_line(
        self,
        remote_path: str | Path,
        line: str,
        state: Literal["present", "absent"] = "present",
        regex: str | None = None,
        create: bool = True,
        backup: bool = False,
        mode: int | None = None,
        encoding: str = "utf-8",
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие, замену или отсутствие строки в файле."""
        path_str = str(remote_path)
        clean_line = line.rstrip("\r\n")
        is_dry_run = self._conn._dry_run if dry_run is None else dry_run

        if self._conn._dry_run:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure line in {path_str} is {state}",
                dry_run=True,
            )

        file_exists = await self._conn.exists(path_str)
        original_text = ""
        existing_lines: list[str] = []

        if file_exists:
            raw_content = await self._conn.read_file(path_str, encoding=encoding)
            original_text = (
                raw_content
                if isinstance(raw_content, str)
                else raw_content.decode(encoding)
            )
            existing_lines = original_text.splitlines()
        elif state == "absent":
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=True,
                details=f"File {path_str} does not exist (already absent)",
                dry_run=is_dry_run,
            )
        elif not create:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=False,
                details=f"File {path_str} does not exist and create=False",
                dry_run=is_dry_run,
            )

        pattern = re.compile(regex) if regex is not None else None
        new_lines: list[str] = []
        changed = False
        details = "No changes needed"

        if state == "present":
            if not file_exists:
                new_lines = [clean_line]
                changed = True
                details = f"Created {path_str} with target line"
            elif pattern is not None:
                matched_any = False
                for existing in existing_lines:
                    if pattern.search(existing):
                        if not matched_any:
                            new_lines.append(clean_line)
                            matched_any = True
                            if existing != clean_line:
                                changed = True
                                details = f"Replaced matching line in {path_str}"
                        else:
                            changed = True
                            details = f"Collapsed duplicate matching lines in {path_str}"
                    else:
                        new_lines.append(existing)
                if not matched_any:
                    new_lines.append(clean_line)
                    changed = True
                    details = f"Appended line to {path_str}"
            else:
                if clean_line in existing_lines:
                    new_lines = list(existing_lines)
                    changed = False
                    details = f"Line already present in {path_str}"
                else:
                    new_lines = [*existing_lines, clean_line]
                    changed = True
                    details = f"Appended line to {path_str}"
        else:
            for existing in existing_lines:
                matches = (
                    bool(pattern.search(existing))
                    if pattern is not None
                    else (existing == clean_line)
                )
                if matches:
                    changed = True
                else:
                    new_lines.append(existing)
            details = (
                f"Removed matching line(s) from {path_str}"
                if changed
                else f"Line already absent in {path_str}"
            )

        if not changed:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=True,
                details=details,
                dry_run=is_dry_run,
            )

        if is_dry_run:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] {details}",
                dry_run=True,
            )

        if backup and file_exists:
            await self._conn.write_file(
                f"{path_str}.bak", original_text, encoding=encoding
            )

        new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
        await self._conn.write_file(
            path_str, new_content, mode=mode, encoding=encoding
        )
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=details,
            dry_run=False,
        )
