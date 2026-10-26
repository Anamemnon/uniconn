# src/uniconn/services/provisioning.py
"""Доменный сервис идемпотентного управления состоянием (Strategy Pattern для пакетов и сервисов)."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import os
import re
import shlex
import shutil
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..result import EnsureResult

if TYPE_CHECKING:
    from ..core.connection import Connection
    from .facts_models import FactSpec, HostFacts

PkgManagerName = Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"]
ServiceState = Literal["started", "stopped", "restarted", "reloaded"]


def _parse_mode(mode: int | str | None) -> int | None:
    """Нормализовать права доступа (``int`` вроде ``0o644`` или восьмеричную строку ``'0644'``/``'644'``)."""
    if mode is None:
        return None
    if isinstance(mode, int) and not isinstance(mode, bool):
        return mode & 0o7777
    if isinstance(mode, str):
        cleaned = mode.strip()
        try:
            return int(cleaned, 8) & 0o7777
        except ValueError as exc:
            raise ValueError(f"Invalid octal file mode: {mode!r}") from exc
    raise ValueError(f"Unsupported file mode type: {type(mode).__name__}")



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
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        """Собрать системные факты о хосте (делегирует в ``conn.gather_facts``)."""
        return await self._conn.gather_facts(
            refresh=refresh, timeout=timeout, spec=spec
        )

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
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run

        if self._conn.is_dry_run:
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
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run
        if self._conn.is_dry_run:
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

    def _can_inspect_in_dry_run(self) -> bool:
        """Проверить, можно ли безопасно выполнить read-only чтение с хоста при dry_run."""
        if not self._conn.is_dry_run:
            return True
        return (
            self._conn.transport.is_connected
            or self._conn.transport_name in ("local", "replay")
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
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run

        if not self._can_inspect_in_dry_run():
            synthetic_diff = (
                f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+{clean_line}\n"
                if state == "present"
                else f"--- a:{path_str}\n+++ b:{path_str}\n@@ -1 +0,0 @@\n-{clean_line}\n"
            )
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure line in {path_str} is {state}",
                dry_run=True,
                diff=synthetic_diff,
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
                diff=None,
            )
        elif not create:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=False,
                details=f"File {path_str} does not exist and create=False",
                dry_run=is_dry_run,
                diff=None,
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
                diff=None,
            )

        new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
        computed_diff = "".join(
            difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a:{path_str}" if file_exists else "/dev/null",
                tofile=f"b:{path_str}",
            )
        )

        if is_dry_run:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] {details}",
                dry_run=True,
                diff=computed_diff,
            )

        if backup and file_exists:
            await self._conn.write_file(
                f"{path_str}.bak", original_text, encoding=encoding
            )

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
            diff=computed_diff,
        )

    @staticmethod
    def _extract_stat_mode(st: Mapping[str, Any]) -> int:
        """Извлечь числовые права доступа (0o7777) из словаря FileStat."""
        raw_mode = st.get("mode")
        if raw_mode is not None:
            if isinstance(raw_mode, str):
                return int(raw_mode, 0) & 0o7777
            return int(raw_mode) & 0o7777
        raw_perm = st.get("permissions")
        if raw_perm is not None:
            if isinstance(raw_perm, str):
                return int(raw_perm, 0) & 0o7777
            return int(raw_perm) & 0o7777
        return -1

    async def _get_owner_group(
        self, path_str: str, *, sudo: bool = False, is_link: bool = False
    ) -> tuple[str | None, str | None]:
        """Получить текущие имя владельца и группы файла или директории."""
        if self._conn.transport_name == "local" and not sudo:
            eff_path = Path(self._conn.context.resolve_path(path_str))
            try:
                import grp
                import pwd

                st = eff_path.lstat() if is_link else eff_path.stat()
                u_name = pwd.getpwuid(st.st_uid).pw_name
                g_name = grp.getgrgid(st.st_gid).gr_name
                return u_name, g_name
            except Exception:
                return None, None

        deref_flag = "" if is_link else "-L "
        res = await self._conn.run(
            f"stat {deref_flag}-c '%U:%G' {shlex.quote(path_str)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if res.ok and ":" in res.text:
            u_str, g_str = res.text.split(":", 1)
            return u_str.strip(), g_str.strip()
        return None, None

    async def _apply_owner_group(
        self,
        path_str: str,
        *,
        owner: str | None,
        group: str | None,
        recurse: bool = False,
        is_link: bool = False,
        sudo: bool = False,
    ) -> None:
        """Применить владельца и/или группу к пути."""
        if owner is None and group is None:
            return
        if self._conn.transport_name == "local" and not sudo and not recurse and not is_link:
            eff_path = Path(self._conn.context.resolve_path(path_str))
            if owner is not None and group is not None:
                shutil.chown(eff_path, user=owner, group=group)
            elif owner is not None:
                shutil.chown(eff_path, user=owner)
            elif group is not None:
                shutil.chown(eff_path, group=group)
            return

        flags: list[str] = []
        if is_link:
            flags.append("-h")
        if recurse:
            flags.append("-R")
        flag_str = (" ".join(flags) + " ") if flags else ""
        if owner is not None and group is not None:
            spec = f"{owner}:{group}"
            cmd = f"chown {flag_str}{shlex.quote(spec)} {shlex.quote(path_str)}"
        elif owner is not None:
            cmd = f"chown {flag_str}{shlex.quote(owner)} {shlex.quote(path_str)}"
        else:
            assert group is not None
            cmd = f"chgrp {flag_str}{shlex.quote(group)} {shlex.quote(path_str)}"
        await self._conn.run(cmd, sudo=sudo, raise_on_error=True, dry_run=False)

    async def ensure_file(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent", "link"] = "present",
        content: str | bytes | None = None,
        target: str | Path | None = None,
        mode: int | str | None = None,
        owner: str | None = None,
        group: str | None = None,
        validate: str | None = None,
        encoding: str = "utf-8",
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять файлом или символической ссылкой на хосте.

        Поддерживает состояния ``present``, ``absent`` и ``link``, управление содержимым,
        правами доступа (``mode``), владельцем (``owner``, ``group``), команду предварительной
        валидации (``validate='nginx -t -c %s'``) и расчёт unified ``diff`` при ``dry_run=True``.
        """
        path_str = str(remote_path)
        parsed_mode = _parse_mode(mode)
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run

        if state == "link" and target is None:
            raise ValueError("Parameter 'target' is required when state='link'")

        if not self._can_inspect_in_dry_run():
            synth_diff = f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+state={state}\n"
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure file {path_str} is {state}",
                dry_run=True,
                diff=synth_diff,
            )

        # 1. state == "absent"
        if state == "absent":
            is_symlink = False
            if self._conn.transport_name == "local" and not sudo:
                eff = Path(self._conn.context.resolve_path(path_str))
                is_symlink = eff.is_symlink()
                exists = eff.exists() or is_symlink
            else:
                exists = await self._conn.exists(path_str)
                if not exists:
                    chk = await self._conn.run(
                        f"test -L {shlex.quote(path_str)}",
                        sudo=sudo,
                        raise_on_error=False,
                        dry_run=False,
                    )
                    is_symlink = chk.ok
                    exists = is_symlink

            if not exists:
                return EnsureResult(
                    target=path_str,
                    state="absent",
                    changed=False,
                    ok=True,
                    details=f"File {path_str} is already absent",
                    dry_run=is_dry_run,
                    diff=None,
                )

            old_text = ""
            if not is_symlink:
                with contextlib.suppress(Exception):
                    raw = await self._conn.read_file(path_str, encoding=encoding)
                    old_text = raw if isinstance(raw, str) else raw.decode(encoding, errors="replace")

            if old_text:
                diff_str = "".join(
                    difflib.unified_diff(
                        old_text.splitlines(keepends=True),
                        [],
                        fromfile=f"a:{path_str}",
                        tofile="/dev/null",
                    )
                )
            else:
                diff_str = f"--- a:{path_str}\n+++ /dev/null\n@@ -1 +0,0 @@\n-<removed>\n"

            if is_dry_run:
                return EnsureResult(
                    target=path_str,
                    state="absent",
                    changed=True,
                    ok=True,
                    details=f"[DRY-RUN] Would remove {path_str}",
                    dry_run=True,
                    diff=diff_str,
                )

            if self._conn.transport_name == "local" and not sudo:
                eff = Path(self._conn.context.resolve_path(path_str))
                eff.unlink(missing_ok=True)
            elif sudo or is_symlink:
                await self._conn.run(
                    f"rm -f {shlex.quote(path_str)}",
                    sudo=sudo,
                    raise_on_error=True,
                    dry_run=False,
                )
            else:
                await self._conn.remove_file(path_str)

            return EnsureResult(
                target=path_str,
                state="absent",
                changed=True,
                ok=True,
                details=f"Removed {path_str}",
                dry_run=False,
                diff=diff_str,
            )

        # 2. state == "link"
        if state == "link":
            target_str = str(target)
            current_target: str | None = None
            if self._conn.transport_name == "local" and not sudo:
                eff = Path(self._conn.context.resolve_path(path_str))
                if eff.is_symlink():
                    current_target = os.readlink(eff)
            else:
                rl_res = await self._conn.run(
                    f"readlink {shlex.quote(path_str)}",
                    sudo=sudo,
                    raise_on_error=False,
                    dry_run=False,
                )
                if rl_res.ok:
                    current_target = rl_res.stdout.rstrip("\r\n")

            actions: list[str] = []
            diff_parts: list[str] = []
            link_changed = current_target != target_str
            if link_changed:
                actions.append(f"symlink -> {target_str}")
                diff_parts.append(
                    f"--- a:{path_str}\n+++ b:{path_str}\n@@ -1 +1 @@\n"
                    f"-{current_target or '<absent>'}\n+{target_str}\n"
                )

            owner_changed = False
            if owner is not None or group is not None:
                cur_u, cur_g = await self._get_owner_group(
                    path_str, sudo=sudo, is_link=True
                )
                if (owner is not None and cur_u != owner) or (
                    group is not None and cur_g != group
                ):
                    owner_changed = True
                    ug_spec = f"{owner or cur_u or ''}:{group or cur_g or ''}".strip(":")
                    actions.append(f"owner {ug_spec}")
                    diff_parts.append(
                        f"--- a:{path_str} (owner)\n+++ b:{path_str} (owner)\n@@ -1 +1 @@\n"
                        f"-{cur_u or '?'}:{cur_g or '?'}\n+{ug_spec}\n"
                    )

            changed = link_changed or owner_changed
            full_diff = "\n".join(p.rstrip("\n") for p in diff_parts) + "\n" if diff_parts else None
            if not changed:
                return EnsureResult(
                    target=path_str,
                    state="link",
                    changed=False,
                    ok=True,
                    details=f"Symlink {path_str} -> {target_str} already in place",
                    dry_run=is_dry_run,
                    diff=None,
                )

            if is_dry_run:
                return EnsureResult(
                    target=path_str,
                    state="link",
                    changed=True,
                    ok=True,
                    details=f"[DRY-RUN] Would update symlink {path_str}: {', '.join(actions)}",
                    dry_run=True,
                    diff=full_diff,
                )

            if link_changed:
                if self._conn.transport_name == "local" and not sudo:
                    eff = Path(self._conn.context.resolve_path(path_str))
                    if eff.exists() or eff.is_symlink():
                        eff.unlink()
                    eff.parent.mkdir(parents=True, exist_ok=True)
                    eff.symlink_to(target_str)
                else:
                    await self._conn.run(
                        f"ln -sfn {shlex.quote(target_str)} {shlex.quote(path_str)}",
                        sudo=sudo,
                        raise_on_error=True,
                        dry_run=False,
                    )

            if owner_changed:
                await self._apply_owner_group(
                    path_str,
                    owner=owner,
                    group=group,
                    is_link=True,
                    sudo=sudo,
                )

            return EnsureResult(
                target=path_str,
                state="link",
                changed=True,
                ok=True,
                details=f"Symlink {path_str}: {', '.join(actions)}",
                dry_run=False,
                diff=full_diff,
            )

        # 3. state == "present"
        file_exists = await self._conn.exists(path_str)
        actions = []
        diff_parts = []
        content_changed = False
        old_bytes = b""

        if file_exists:
            with contextlib.suppress(Exception):
                raw_existing = await self._conn.read_file(path_str, encoding=None)
                old_bytes = (
                    raw_existing
                    if isinstance(raw_existing, bytes)
                    else raw_existing.encode(encoding)
                )

        if content is not None:
            new_bytes = (
                content.encode(encoding) if isinstance(content, str) else bytes(content)
            )
            if not file_exists or old_bytes != new_bytes:
                content_changed = True
                actions.append("created content" if not file_exists else "updated content")
                if isinstance(content, str):
                    old_text = (
                        old_bytes.decode(encoding, errors="replace")
                        if file_exists
                        else ""
                    )
                    u_diff = "".join(
                        difflib.unified_diff(
                            old_text.splitlines(keepends=True),
                            content.splitlines(keepends=True),
                            fromfile=f"a:{path_str}" if file_exists else "/dev/null",
                            tofile=f"b:{path_str}",
                        )
                    )
                    if u_diff:
                        diff_parts.append(u_diff)
                    else:
                        diff_parts.append(
                            f"--- {'a:' + path_str if file_exists else '/dev/null'}\n"
                            f"+++ b:{path_str}\n@@ -1 +1 @@\n+{content}\n"
                        )
                else:
                    old_hash = hashlib.sha256(old_bytes).hexdigest()[:12] if file_exists else "none"
                    new_hash = hashlib.sha256(new_bytes).hexdigest()[:12]
                    diff_parts.append(
                        f"--- {'a:' + path_str if file_exists else '/dev/null'}\n"
                        f"+++ b:{path_str}\n@@ -1 +1 @@\n"
                        f"-binary sha256={old_hash} ({len(old_bytes)} bytes)\n"
                        f"+binary sha256={new_hash} ({len(new_bytes)} bytes)\n"
                    )
        elif not file_exists:
            content_changed = True
            actions.append("created empty file")
            diff_parts.append(f"--- /dev/null\n+++ b:{path_str}\n@@ -0,0 +1,0 @@\n")

        mode_changed = False
        if parsed_mode is not None:
            if file_exists:
                try:
                    st = await self._conn.stat(path_str)
                    cur_mode = self._extract_stat_mode(st)
                except Exception:
                    cur_mode = -1
                if cur_mode != parsed_mode:
                    mode_changed = True
                    cur_oct = oct(cur_mode) if cur_mode >= 0 else "unknown"
                    actions.append(f"mode {cur_oct} -> {oct(parsed_mode)}")
                    diff_parts.append(
                        f"--- a:{path_str} (mode)\n+++ b:{path_str} (mode)\n@@ -1 +1 @@\n"
                        f"-{cur_oct}\n+{oct(parsed_mode)}\n"
                    )
            else:
                mode_changed = True
                actions.append(f"mode {oct(parsed_mode)}")

        owner_changed = False
        if owner is not None or group is not None:
            if file_exists:
                cur_u, cur_g = await self._get_owner_group(path_str, sudo=sudo)
                if (owner is not None and cur_u != owner) or (
                    group is not None and cur_g != group
                ):
                    owner_changed = True
                    ug_spec = f"{owner or cur_u or ''}:{group or cur_g or ''}".strip(":")
                    actions.append(f"owner {ug_spec}")
                    diff_parts.append(
                        f"--- a:{path_str} (owner)\n+++ b:{path_str} (owner)\n@@ -1 +1 @@\n"
                        f"-{cur_u or '?'}:{cur_g or '?'}\n+{ug_spec}\n"
                    )
            else:
                owner_changed = True
                ug_spec = f"{owner or ''}:{group or ''}".strip(":")
                actions.append(f"owner {ug_spec}")

        changed = content_changed or mode_changed or owner_changed
        full_diff = (
            "\n".join(p.rstrip("\n") for p in diff_parts) + "\n"
            if diff_parts
            else None
        )

        if not changed:
            return EnsureResult(
                target=path_str,
                state="present",
                changed=False,
                ok=True,
                details=f"File {path_str} already in desired state",
                dry_run=is_dry_run,
                diff=None,
            )

        if is_dry_run:
            return EnsureResult(
                target=path_str,
                state="present",
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would update {path_str}: {', '.join(actions)}",
                dry_run=True,
                diff=full_diff,
            )

        # Предварительная валидация через временный файл (если задан validate)
        if validate is not None:
            candidate_payload: str | bytes = (
                content
                if content is not None
                else (old_bytes if file_exists else "")
            )
            async with self._conn.temp_dir(prefix="uniconn_val_") as tmp_dir:
                tmp_candidate = f"{tmp_dir.rstrip('/')}/candidate"
                await self._conn.write_file(
                    tmp_candidate,
                    candidate_payload,
                    mode=parsed_mode,
                    encoding=encoding,
                )
                val_cmd = (
                    validate.replace("%s", shlex.quote(tmp_candidate))
                    if "%s" in validate
                    else f"{validate} {shlex.quote(tmp_candidate)}"
                )
                val_res = await self._conn.run(
                    val_cmd,
                    sudo=sudo,
                    raise_on_error=False,
                    dry_run=False,
                )
                if not val_res.ok:
                    err_msg = val_res.stderr.strip() or val_res.stdout.strip()
                    return EnsureResult(
                        target=path_str,
                        state="present",
                        changed=False,
                        ok=False,
                        details=f"Validation command failed ({validate}): {err_msg}",
                        dry_run=False,
                        diff=full_diff,
                    )

        if content_changed:
            write_payload: str | bytes = content if content is not None else ""
            if sudo and self._conn.transport_name != "local":
                async with self._conn.temp_dir(prefix="uniconn_stage_") as stage_dir:
                    staged = f"{stage_dir.rstrip('/')}/staged"
                    await self._conn.write_file(
                        staged, write_payload, mode=parsed_mode, encoding=encoding
                    )
                    await self._conn.run(
                        f"mv -f {shlex.quote(staged)} {shlex.quote(path_str)}",
                        sudo=True,
                        raise_on_error=True,
                        dry_run=False,
                    )
            else:
                await self._conn.write_file(
                    path_str, write_payload, mode=parsed_mode, encoding=encoding
                )

        if mode_changed and parsed_mode is not None:
            if sudo and self._conn.transport_name != "local":
                await self._conn.run(
                    f"chmod {parsed_mode:o} {shlex.quote(path_str)}",
                    sudo=sudo,
                    raise_on_error=True,
                    dry_run=False,
                )
            else:
                await self._conn.chmod(path_str, parsed_mode)

        if owner_changed:
            await self._apply_owner_group(
                path_str,
                owner=owner,
                group=group,
                sudo=sudo,
            )

        return EnsureResult(
            target=path_str,
            state="present",
            changed=True,
            ok=True,
            details=f"File {path_str}: {', '.join(actions)}",
            dry_run=False,
            diff=full_diff,
        )

    async def ensure_directory(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent"] = "present",
        mode: int | str | None = None,
        owner: str | None = None,
        group: str | None = None,
        recurse: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие директории, её прав и владельца."""
        path_str = str(remote_path)
        parsed_mode = _parse_mode(mode)
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run

        if not self._can_inspect_in_dry_run():
            synth_diff = f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+directory state={state}\n"
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure directory {path_str} is {state}",
                dry_run=True,
                diff=synth_diff,
            )

        dir_exists = await self._conn.exists(path_str)

        if state == "absent":
            if not dir_exists:
                return EnsureResult(
                    target=path_str,
                    state="absent",
                    changed=False,
                    ok=True,
                    details=f"Directory {path_str} is already absent",
                    dry_run=is_dry_run,
                    diff=None,
                )

            diff_str = f"--- a:{path_str}\n+++ /dev/null\n@@ -1 +0,0 @@\n-directory {path_str}\n"
            if is_dry_run:
                return EnsureResult(
                    target=path_str,
                    state="absent",
                    changed=True,
                    ok=True,
                    details=f"[DRY-RUN] Would remove directory {path_str}",
                    dry_run=True,
                    diff=diff_str,
                )

            if self._conn.transport_name == "local" and not sudo:
                eff = Path(self._conn.context.resolve_path(path_str))
                shutil.rmtree(eff)
            else:
                rm_cmd = f"rm -rf {shlex.quote(path_str)}"
                rm_res = await self._conn.run(
                    rm_cmd, sudo=sudo, raise_on_error=False, dry_run=False
                )
                if not rm_res.ok:
                    return EnsureResult(
                        target=path_str,
                        state="absent",
                        changed=False,
                        ok=False,
                        details=rm_res.stderr.strip() or f"Failed to remove directory {path_str}",
                        dry_run=False,
                        diff=diff_str,
                    )

            return EnsureResult(
                target=path_str,
                state="absent",
                changed=True,
                ok=True,
                details=f"Removed directory {path_str}",
                dry_run=False,
                diff=diff_str,
            )

        # state == "present"
        actions: list[str] = []
        diff_parts: list[str] = []
        created_dir = not dir_exists
        if created_dir:
            actions.append("created directory")
            diff_parts.append(f"--- /dev/null\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+directory {path_str}\n")

        mode_changed = False
        if parsed_mode is not None:
            if dir_exists:
                try:
                    st = await self._conn.stat(path_str)
                    cur_mode = self._extract_stat_mode(st)
                except Exception:
                    cur_mode = -1
                if cur_mode != parsed_mode or recurse:
                    mode_changed = True
                    cur_oct = oct(cur_mode) if cur_mode >= 0 else "unknown"
                    actions.append(f"mode {cur_oct} -> {oct(parsed_mode)}")
                    diff_parts.append(
                        f"--- a:{path_str} (mode)\n+++ b:{path_str} (mode)\n@@ -1 +1 @@\n"
                        f"-{cur_oct}\n+{oct(parsed_mode)}\n"
                    )
            else:
                mode_changed = True
                actions.append(f"mode {oct(parsed_mode)}")

        owner_changed = False
        if owner is not None or group is not None:
            if dir_exists:
                cur_u, cur_g = await self._get_owner_group(path_str, sudo=sudo)
                if (
                    (owner is not None and cur_u != owner)
                    or (group is not None and cur_g != group)
                    or recurse
                ):
                    owner_changed = True
                    ug_spec = f"{owner or cur_u or ''}:{group or cur_g or ''}".strip(":")
                    actions.append(f"owner {ug_spec}")
                    diff_parts.append(
                        f"--- a:{path_str} (owner)\n+++ b:{path_str} (owner)\n@@ -1 +1 @@\n"
                        f"-{cur_u or '?'}:{cur_g or '?'}\n+{ug_spec}\n"
                    )
            else:
                owner_changed = True
                ug_spec = f"{owner or ''}:{group or ''}".strip(":")
                actions.append(f"owner {ug_spec}")

        changed = created_dir or mode_changed or owner_changed
        full_diff = (
            "\n".join(p.rstrip("\n") for p in diff_parts) + "\n"
            if diff_parts
            else None
        )

        if not changed:
            return EnsureResult(
                target=path_str,
                state="present",
                changed=False,
                ok=True,
                details=f"Directory {path_str} already in desired state",
                dry_run=is_dry_run,
                diff=None,
            )

        if is_dry_run:
            return EnsureResult(
                target=path_str,
                state="present",
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would update directory {path_str}: {', '.join(actions)}",
                dry_run=True,
                diff=full_diff,
            )

        if created_dir:
            if sudo and self._conn.transport_name != "local":
                await self._conn.run(
                    f"mkdir -p {shlex.quote(path_str)}",
                    sudo=True,
                    raise_on_error=True,
                    dry_run=False,
                )
            else:
                await self._conn.mkdir(
                    path_str, parents=True, exist_ok=True, mode=parsed_mode
                )

        if mode_changed and parsed_mode is not None:
            if (sudo and self._conn.transport_name != "local") or recurse:
                rec_flag = "-R " if recurse else ""
                await self._conn.run(
                    f"chmod {rec_flag}{parsed_mode:o} {shlex.quote(path_str)}",
                    sudo=sudo,
                    raise_on_error=True,
                    dry_run=False,
                )
            else:
                await self._conn.chmod(path_str, parsed_mode)

        if owner_changed:
            await self._apply_owner_group(
                path_str,
                owner=owner,
                group=group,
                recurse=recurse,
                sudo=sudo,
            )

        return EnsureResult(
            target=path_str,
            state="present",
            changed=True,
            ok=True,
            details=f"Directory {path_str}: {', '.join(actions)}",
            dry_run=False,
            diff=full_diff,
        )

