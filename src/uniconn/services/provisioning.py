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
        atomic: bool = False,
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
                    path_str,
                    write_payload,
                    mode=parsed_mode,
                    encoding=encoding,
                    atomic=atomic,
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

    async def ensure_user(
        self,
        username: str,
        *,
        state: Literal["present", "absent"] = "present",
        uid: int | None = None,
        group: str | None = None,
        groups: Sequence[str] | None = None,
        shell: str | None = None,
        home: str | None = None,
        create_home: bool = True,
        system: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять системным пользователем и его группами."""
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run

        if not self._can_inspect_in_dry_run():
            synth_diff = (
                f"--- a:/etc/passwd ({username})\n+++ b:/etc/passwd ({username})\n"
                f"@@ -0,0 +1 @@\n+user={username} state={state}\n"
            )
            return EnsureResult(
                target=username,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure user {username} is {state}",
                dry_run=True,
                diff=synth_diff,
            )

        pw_res = await self._conn.run(
            f"getent passwd {shlex.quote(username)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        user_exists = pw_res.ok and bool(pw_res.stdout.strip())

        if state == "absent":
            if not user_exists:
                return EnsureResult(
                    target=username,
                    state="absent",
                    changed=False,
                    ok=True,
                    details=f"User {username} is already absent",
                    dry_run=is_dry_run,
                    diff=None,
                )
            diff_str = (
                f"--- a:/etc/passwd ({username})\n+++ /dev/null\n"
                f"@@ -1 +0,0 @@\n-user={username}\n"
            )
            if is_dry_run:
                return EnsureResult(
                    target=username,
                    state="absent",
                    changed=True,
                    ok=True,
                    details=f"[DRY-RUN] Would remove user {username}",
                    dry_run=True,
                    diff=diff_str,
                )
            del_res = await self._conn.run(
                f"userdel {shlex.quote(username)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            if not del_res.ok:
                return EnsureResult(
                    target=username,
                    state="absent",
                    changed=False,
                    ok=False,
                    details=del_res.stderr.strip() or f"Failed to remove user {username}",
                    dry_run=False,
                    diff=diff_str,
                )
            return EnsureResult(
                target=username,
                state="absent",
                changed=True,
                ok=True,
                details=f"Removed user {username}",
                dry_run=False,
                diff=diff_str,
            )

        # state == "present"
        if not user_exists:
            cmd_parts = ["useradd"]
            if system:
                cmd_parts.append("-r")
            cmd_parts.append("-m" if create_home else "-M")
            if uid is not None:
                cmd_parts.extend(["-u", str(uid)])
            if group is not None:
                cmd_parts.extend(["-g", shlex.quote(group)])
            if groups is not None:
                cmd_parts.extend(["-G", shlex.quote(",".join(groups))])
            if shell is not None:
                cmd_parts.extend(["-s", shlex.quote(shell)])
            if home is not None:
                cmd_parts.extend(["-d", shlex.quote(home)])
            cmd_parts.append(shlex.quote(username))

            spec_line = (
                f"+user={username} uid={uid if uid is not None else 'auto'} "
                f"group={group or 'default'} groups={','.join(groups or ())} "
                f"shell={shell or 'default'} home={home or 'default'}\n"
            )
            diff_str = (
                f"--- /dev/null\n+++ b:/etc/passwd ({username})\n"
                f"@@ -0,0 +1 @@\n{spec_line}"
            )
            if is_dry_run:
                return EnsureResult(
                    target=username,
                    state="present",
                    changed=True,
                    ok=True,
                    details=f"[DRY-RUN] Would create user {username}",
                    dry_run=True,
                    diff=diff_str,
                )
            add_res = await self._conn.run(
                " ".join(cmd_parts),
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            if not add_res.ok:
                return EnsureResult(
                    target=username,
                    state="present",
                    changed=False,
                    ok=False,
                    details=add_res.stderr.strip() or f"Failed to create user {username}",
                    dry_run=False,
                    diff=diff_str,
                )
            return EnsureResult(
                target=username,
                state="present",
                changed=True,
                ok=True,
                details=f"Created user {username}",
                dry_run=False,
                diff=diff_str,
            )

        # Пользователь существует — проверяем расхождения параметров
        pw_fields = pw_res.stdout.strip().splitlines()[0].split(":")
        cur_uid = int(pw_fields[2]) if len(pw_fields) > 2 and pw_fields[2].isdigit() else None
        cur_home = pw_fields[5] if len(pw_fields) > 5 else ""
        cur_shell = pw_fields[6] if len(pw_fields) > 6 else ""

        mod_flags: list[str] = []
        changes_desc: list[str] = []
        old_tokens: list[str] = []
        new_tokens: list[str] = []

        if uid is not None and cur_uid != uid:
            mod_flags.extend(["-u", str(uid)])
            changes_desc.append(f"uid {cur_uid} -> {uid}")
            old_tokens.append(f"uid={cur_uid}")
            new_tokens.append(f"uid={uid}")

        if group is not None:
            gn_res = await self._conn.run(
                f"id -gn {shlex.quote(username)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            cur_group = gn_res.stdout.strip() if gn_res.ok else ""
            if cur_group != group:
                mod_flags.extend(["-g", shlex.quote(group)])
                changes_desc.append(f"group {cur_group} -> {group}")
                old_tokens.append(f"group={cur_group}")
                new_tokens.append(f"group={group}")

        if groups is not None:
            all_g_res = await self._conn.run(
                f"id -Gn {shlex.quote(username)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            cur_all_groups = set(all_g_res.stdout.strip().split()) if all_g_res.ok else set()
            desired_supp = set(groups)
            if not desired_supp.issubset(cur_all_groups):
                mod_flags.extend(["-G", shlex.quote(",".join(groups))])
                changes_desc.append(f"groups -> {','.join(groups)}")
                old_tokens.append(f"groups={','.join(sorted(cur_all_groups))}")
                new_tokens.append(f"groups={','.join(groups)}")

        if shell is not None and cur_shell != shell:
            mod_flags.extend(["-s", shlex.quote(shell)])
            changes_desc.append(f"shell {cur_shell} -> {shell}")
            old_tokens.append(f"shell={cur_shell}")
            new_tokens.append(f"shell={shell}")

        if home is not None and cur_home != home:
            mod_flags.extend(["-d", shlex.quote(home)])
            changes_desc.append(f"home {cur_home} -> {home}")
            old_tokens.append(f"home={cur_home}")
            new_tokens.append(f"home={home}")

        if not mod_flags:
            return EnsureResult(
                target=username,
                state="present",
                changed=False,
                ok=True,
                details=f"User {username} already in desired state",
                dry_run=is_dry_run,
                diff=None,
            )

        diff_str = (
            f"--- a:/etc/passwd ({username})\n+++ b:/etc/passwd ({username})\n"
            f"@@ -1 +1 @@\n-{' '.join(old_tokens)}\n+{' '.join(new_tokens)}\n"
        )
        if is_dry_run:
            return EnsureResult(
                target=username,
                state="present",
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would update user {username}: {', '.join(changes_desc)}",
                dry_run=True,
                diff=diff_str,
            )

        mod_cmd = f"usermod {' '.join(mod_flags)} {shlex.quote(username)}"
        mod_res = await self._conn.run(
            mod_cmd,
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if not mod_res.ok:
            return EnsureResult(
                target=username,
                state="present",
                changed=False,
                ok=False,
                details=mod_res.stderr.strip() or f"Failed to modify user {username}",
                dry_run=False,
                diff=diff_str,
            )

        return EnsureResult(
            target=username,
            state="present",
            changed=True,
            ok=True,
            details=f"Updated user {username}: {', '.join(changes_desc)}",
            dry_run=False,
            diff=diff_str,
        )

    async def _resolve_user_home(self, user: str, *, sudo: bool = False) -> str:
        """Определить домашнюю директорию пользователя на целевом хосте."""
        pw_res = await self._conn.run(
            f"getent passwd {shlex.quote(user)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if pw_res.ok and pw_res.stdout.strip():
            fields = pw_res.stdout.strip().splitlines()[0].split(":")
            if len(fields) > 5 and fields[5]:
                return fields[5]
        return "/root" if user == "root" else f"/home/{user}"

    async def ensure_authorized_key(
        self,
        user: str,
        key: str,
        *,
        state: Literal["present", "absent"] = "present",
        exclusive: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять SSH-ключами в ``~/.ssh/authorized_keys``."""
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run
        clean_key = key.strip()
        if not clean_key:
            raise ValueError("SSH public key cannot be empty")

        if not self._can_inspect_in_dry_run():
            target_hint = f"~{user}/.ssh/authorized_keys"
            synth_diff = (
                f"--- a:{target_hint}\n+++ b:{target_hint}\n"
                f"@@ -0,0 +1 @@\n+{clean_key}\n"
            )
            return EnsureResult(
                target=target_hint,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure authorized_key for {user} is {state}",
                dry_run=True,
                diff=synth_diff,
            )

        home_dir = await self._resolve_user_home(user, sudo=sudo)
        ssh_dir = f"{home_dir.rstrip('/')}/.ssh"
        auth_file = f"{ssh_dir}/authorized_keys"

        file_exists = await self._conn.exists(auth_file)
        old_text = ""
        if file_exists:
            with contextlib.suppress(Exception):
                raw = await self._conn.read_file(auth_file, encoding="utf-8")
                old_text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")

        existing_lines = [ln.rstrip("\r") for ln in old_text.splitlines()]
        desired_keys = [ln.strip() for ln in clean_key.splitlines() if ln.strip()]

        if state == "present":
            if exclusive:
                new_lines = list(desired_keys)
            else:
                new_lines = list(existing_lines)
                existing_stripped = {ln.strip() for ln in existing_lines if ln.strip()}
                for k in desired_keys:
                    if k not in existing_stripped:
                        new_lines.append(k)
                        existing_stripped.add(k)
        else:
            remove_set = set(desired_keys)
            new_lines = [ln for ln in existing_lines if ln.strip() not in remove_set]

        new_text = ("\n".join(new_lines) + "\n") if new_lines else ""

        if (not file_exists and state == "absent") or (file_exists and old_text == new_text):
            return EnsureResult(
                target=auth_file,
                state=state,
                changed=False,
                ok=True,
                details=f"Authorized key for {user} already {state}",
                dry_run=is_dry_run,
                diff=None,
            )

        u_diff = "".join(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a:{auth_file}" if file_exists else "/dev/null",
                tofile=f"b:{auth_file}",
            )
        )

        if is_dry_run:
            return EnsureResult(
                target=auth_file,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would update {auth_file} for user {user}",
                dry_run=True,
                diff=u_diff or None,
            )

        dir_res = await self.ensure_directory(
            ssh_dir,
            state="present",
            mode=0o700,
            owner=user,
            sudo=sudo,
            dry_run=False,
        )
        if not dir_res.ok:
            return EnsureResult(
                target=auth_file,
                state=state,
                changed=False,
                ok=False,
                details=dir_res.details,
                dry_run=False,
                diff=u_diff or None,
            )

        file_res = await self.ensure_file(
            auth_file,
            state="present",
            content=new_text,
            mode=0o600,
            owner=user,
            atomic=True,
            sudo=sudo,
            dry_run=False,
        )
        return EnsureResult(
            target=auth_file,
            state=state,
            changed=True,
            ok=file_res.ok,
            details=(
                f"Updated {auth_file} for user {user}"
                if file_res.ok
                else file_res.details
            ),
            dry_run=False,
            diff=u_diff or file_res.diff,
        )

    async def ensure_systemd_unit(
        self,
        name: str,
        *,
        content: str | None = None,
        state: Literal["present", "absent", "started", "stopped", "restarted"] = "present",
        enabled: bool | None = None,
        unit_dir: str = "/etc/systemd/system",
        daemon_reload: bool = True,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять unit-файлом systemd с вызовом ``daemon-reload`` при изменениях."""
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run
        unit_name = name if "." in name else f"{name}.service"
        unit_path = f"{unit_dir.rstrip('/')}/{unit_name}"

        changed = False
        details_parts: list[str] = []
        diff_parts: list[str] = []

        if state == "absent":
            if enabled is False:
                svc_stop = await self.ensure_service(
                    unit_name,
                    state="stopped",
                    enabled=False,
                    sudo=sudo,
                    dry_run=is_dry_run,
                )
                if svc_stop.changed:
                    changed = True
                    details_parts.append(svc_stop.details)
            file_res = await self.ensure_file(
                unit_path,
                state="absent",
                sudo=sudo,
                dry_run=is_dry_run,
            )
            if not file_res.ok:
                return file_res
            if file_res.changed:
                changed = True
                details_parts.append(file_res.details)
                if file_res.diff:
                    diff_parts.append(file_res.diff)
                if daemon_reload:
                    if is_dry_run:
                        details_parts.append("[DRY-RUN] systemctl daemon-reload")
                    else:
                        rl_res = await self._conn.run(
                            "systemctl daemon-reload",
                            sudo=sudo,
                            raise_on_error=False,
                            dry_run=False,
                        )
                        if not rl_res.ok:
                            return EnsureResult(
                                target=unit_name,
                                state="absent",
                                changed=changed,
                                ok=False,
                                details=rl_res.stderr.strip() or "systemctl daemon-reload failed",
                                dry_run=False,
                                diff="\n".join(diff_parts) or None,
                            )
                        details_parts.append("systemctl daemon-reload")
            return EnsureResult(
                target=unit_name,
                state="absent",
                changed=changed,
                ok=True,
                details="; ".join(details_parts) or f"Unit {unit_name} is already absent",
                dry_run=is_dry_run,
                diff="\n".join(p.rstrip("\n") for p in diff_parts) + "\n" if diff_parts else None,
            )

        if content is not None:
            file_res = await self.ensure_file(
                unit_path,
                state="present",
                content=content,
                mode=0o644,
                atomic=True,
                sudo=sudo,
                dry_run=is_dry_run,
            )
            if not file_res.ok:
                return file_res
            if file_res.changed:
                changed = True
                details_parts.append(file_res.details)
                if file_res.diff:
                    diff_parts.append(file_res.diff)
                if daemon_reload:
                    if is_dry_run:
                        details_parts.append("[DRY-RUN] systemctl daemon-reload")
                    else:
                        rl_res = await self._conn.run(
                            "systemctl daemon-reload",
                            sudo=sudo,
                            raise_on_error=False,
                            dry_run=False,
                        )
                        if not rl_res.ok:
                            return EnsureResult(
                                target=unit_name,
                                state=state,
                                changed=changed,
                                ok=False,
                                details=rl_res.stderr.strip() or "systemctl daemon-reload failed",
                                dry_run=False,
                                diff="\n".join(diff_parts) or None,
                            )
                        details_parts.append("systemctl daemon-reload")

        if state in ("started", "stopped", "restarted") or enabled is not None:
            svc_state: ServiceState = (
                state if state in ("started", "stopped", "restarted") else "started"
            )
            svc_res = await self.ensure_service(
                unit_name,
                state=svc_state,
                enabled=enabled,
                sudo=sudo,
                dry_run=is_dry_run,
            )
            if not svc_res.ok:
                return EnsureResult(
                    target=unit_name,
                    state=state,
                    changed=changed or svc_res.changed,
                    ok=False,
                    details=svc_res.details,
                    dry_run=is_dry_run,
                    diff="\n".join(diff_parts) or svc_res.diff,
                )
            if svc_res.changed:
                changed = True
                details_parts.append(svc_res.details)
                if svc_res.diff:
                    diff_parts.append(svc_res.diff)

        return EnsureResult(
            target=unit_name,
            state=state,
            changed=changed,
            ok=True,
            details="; ".join(details_parts) or f"Unit {unit_name} already in desired state",
            dry_run=is_dry_run,
            diff="\n".join(p.rstrip("\n") for p in diff_parts) + "\n" if diff_parts else None,
        )

    async def ensure_sysctl(
        self,
        name: str,
        value: str | int,
        *,
        state: Literal["present", "absent"] = "present",
        config_file: str = "/etc/sysctl.d/99-uniconn.conf",
        reload: bool = True,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять параметром ядра ``sysctl`` и применять его на лету."""
        is_dry_run = self._conn.is_dry_run if dry_run is None else dry_run
        val_str = str(value).strip()
        line_str = f"{name} = {val_str}"
        regex_pat = rf"^\s*{re.escape(name)}\s*="

        if state == "absent":
            line_res = await self.ensure_line(
                config_file,
                line=line_str,
                regex=regex_pat,
                state="absent",
                create=False,
                dry_run=is_dry_run,
            )
            return EnsureResult(
                target=name,
                state="absent",
                changed=line_res.changed,
                ok=line_res.ok,
                details=line_res.details,
                dry_run=is_dry_run,
                diff=line_res.diff,
            )

        line_res = await self.ensure_line(
            config_file,
            line=line_str,
            regex=regex_pat,
            state="present",
            create=True,
            dry_run=is_dry_run,
        )
        if not line_res.ok:
            return EnsureResult(
                target=name,
                state="present",
                changed=False,
                ok=False,
                details=line_res.details,
                dry_run=is_dry_run,
                diff=line_res.diff,
            )

        runtime_changed = False
        rt_val: str | None = None
        if reload and self._can_inspect_in_dry_run():
            rt_res = await self._conn.run(
                f"sysctl -n {shlex.quote(name)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            if rt_res.ok:
                rt_val = " ".join(rt_res.stdout.strip().split())
                desired_norm = " ".join(val_str.split())
                if rt_val != desired_norm:
                    runtime_changed = True

        changed = line_res.changed or runtime_changed
        diff_str = line_res.diff
        if runtime_changed and not diff_str:
            diff_str = (
                f"--- a:sysctl:{name}\n+++ b:sysctl:{name}\n"
                f"@@ -1 +1 @@\n-{rt_val or '<unset>'}\n+{val_str}\n"
            )

        if not changed:
            return EnsureResult(
                target=name,
                state="present",
                changed=False,
                ok=True,
                details=f"sysctl {name} = {val_str} already in desired state",
                dry_run=is_dry_run,
                diff=None,
            )

        if is_dry_run:
            return EnsureResult(
                target=name,
                state="present",
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would set sysctl {name} = {val_str}",
                dry_run=True,
                diff=diff_str,
            )

        if reload:
            apply_res = await self._conn.run(
                f"sysctl -w {shlex.quote(f'{name}={val_str}')}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            if not apply_res.ok:
                return EnsureResult(
                    target=name,
                    state="present",
                    changed=line_res.changed,
                    ok=False,
                    details=apply_res.stderr.strip() or f"Failed to apply sysctl {name}={val_str}",
                    dry_run=False,
                    diff=diff_str,
                )

        return EnsureResult(
            target=name,
            state="present",
            changed=True,
            ok=True,
            details=f"Set sysctl {name} = {val_str}",
            dry_run=False,
            diff=diff_str,
        )


