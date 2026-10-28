# src/uniconn/services/provisioning/services.py
"""Стратегии систем инициализации (ServiceManagerStrategy) и табличная диспетчеризация состояний сервиса."""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal

from ...result import EnsureResult

if TYPE_CHECKING:
    from .service import StateManagementService

ServiceState = Literal["started", "stopped", "restarted", "reloaded"]
ServiceAction = Literal["start", "stop", "restart", "reload"]

# Таблица переходов состояний сервиса: устраняет каскад if/elif в ensure_service
_SERVICE_STATE_TRANSITIONS: dict[ServiceState, Callable[[bool], ServiceAction | None]] = {
    "started": lambda is_active: None if is_active else "start",
    "stopped": lambda is_active: "stop" if is_active else None,
    "restarted": lambda _is_active: "restart",
    "reloaded": lambda _is_active: "reload",
}


def resolve_service_transition(state: ServiceState, *, is_active: bool) -> ServiceAction | None:
    """Определить требуемое действие над сервисом по целевому состоянию и текущей активности."""
    resolver = _SERVICE_STATE_TRANSITIONS.get(state)
    return resolver(is_active) if resolver is not None else None


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
        action: ServiceAction,
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
        action: ServiceAction,
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
        action: ServiceAction,
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
        action: ServiceAction,
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
        action: ServiceAction,
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


async def ensure_service(
    svc: StateManagementService,
    service: str,
    state: ServiceState = "started",
    enabled: bool | None = None,
    sudo: bool = True,
    dry_run: bool | None = None,
    manager: Literal["auto", "systemd", "openrc", "sysv"] = "auto",
) -> EnsureResult:
    """Идемпотентно управлять состоянием системного сервиса."""
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run
    if svc._conn.is_dry_run:
        return EnsureResult(
            target=service,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure service {service} is {state}",
            dry_run=True,
        )

    strategy = SERVICE_STRATEGIES.get(manager, SERVICE_STRATEGIES["auto"])
    status_res = await svc._conn.run(
        strategy.status_cmd(service),
        raise_on_error=False,
        dry_run=False,
    )
    transition = resolve_service_transition(state, is_active=status_res.ok)

    actions_taken: list[str] = []
    commands_to_run: list[str] = []
    if transition is not None:
        actions_taken.append(transition)
        commands_to_run.append(strategy.action_cmd(service, transition))

    if enabled is not None:
        enabled_chk = await svc._conn.run(
            strategy.is_enabled_cmd(service),
            raise_on_error=False,
            dry_run=False,
        )
        if enabled != enabled_chk.ok:
            actions_taken.append("enable" if enabled else "disable")
            commands_to_run.append(strategy.set_enabled_cmd(service, enabled))

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

    act_res = await svc._conn.run(" && ".join(commands_to_run), sudo=sudo, raise_on_error=False)
    return EnsureResult(
        target=service,
        state=state,
        changed=act_res.ok,
        ok=act_res.ok,
        details=act_res.stderr.strip() if not act_res.ok else f"Service {service}: {', '.join(actions_taken)}",
        dry_run=False,
    )
