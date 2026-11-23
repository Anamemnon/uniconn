# src/uniconn/services/provisioning/facade.py
"""Фасад доменного сервиса идемпотентного управления состоянием (StateManagementService)."""

from __future__ import annotations

import contextvars
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ...result import EnsureResult
from ._fleet_plan import (
    IN_NOTIFY_HANDLER,
    ConnectionApplyPlanContext,
    ConnectionPlanContext,
    FleetChangePlan,
    _ServiceApplierBinding,
    _ServicePlanBinding,
    capture_before_snapshot,
    compute_before_digest,
    extract_actions_from_result,
)
from ._notify import (
    NotificationBatch,
    NotifySpec,
    finalize_ensure_with_notify,
    normalize_notify_spec,
)
from ._plan import (
    apply_owner_group,
    can_inspect_in_dry_run,
    extract_stat_mode,
    get_owner_group,
)
from .files import (
    ensure_directory as _ensure_directory,
)
from .files import (
    ensure_file as _ensure_file,
)
from .files import (
    ensure_line as _ensure_line,
)
from .packages import (
    PkgManagerName,
)
from .packages import (
    ensure_package as _ensure_package,
)
from .packages import (
    resolve_pkg_manager as _resolve_pkg_manager,
)
from .service_managers import (
    ServiceState,
)
from .service_managers import (
    ensure_service as _ensure_service,
)
from .system import (
    ensure_authorized_key as _ensure_authorized_key,
)
from .system import (
    ensure_sysctl as _ensure_sysctl,
)
from .system import (
    ensure_systemd_unit as _ensure_systemd_unit,
)
from .system import (
    ensure_user as _ensure_user,
)
from .system import (
    resolve_user_home as _resolve_user_home,
)
from .windows import (
    RegistryValueType,
    WindowsServiceState,
    WindowsStartupType,
)
from .windows import (
    ensure_registry_key as _ensure_registry_key,
)
from .windows import (
    ensure_windows_feature as _ensure_windows_feature,
)
from .windows import (
    ensure_windows_service as _ensure_windows_service,
)
from .yang import (
    ensure_yang as _ensure_yang,
)

if TYPE_CHECKING:
    from ...core.connection import Connection
    from ..facts_models import FactSpec, HostFacts

_ENSURE_NESTING_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar(
    "uniconn_ensure_nesting_depth", default=0
)


class StateManagementService:
    """Доменный сервис идемпотентных проверок и конфигурации (``conn.state``)."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис для указанного подключения."""
        self._conn = conn
        self._batch_stack: list[NotificationBatch] = []
        self._plan_recorders: list[_ServicePlanBinding] = []
        self._plan_appliers: list[_ServiceApplierBinding] = []

    def _push_batch(self, batch: NotificationBatch) -> None:
        """Активировать контекст батчинга уведомлений."""
        self._batch_stack.append(batch)

    def _pop_batch(self, batch: NotificationBatch) -> None:
        """Деактивировать контекст батчинга уведомлений."""
        if self._batch_stack and self._batch_stack[-1] is batch:
            self._batch_stack.pop()
        elif batch in self._batch_stack:
            self._batch_stack.remove(batch)

    def _current_batch(self) -> NotificationBatch | None:
        """Вернуть текущий активный контекст ``NotificationBatch`` или ``None``."""
        return self._batch_stack[-1] if self._batch_stack else None

    def share_batches_from(self, other: StateManagementService) -> None:
        """Разделить стек активных ``NotificationBatch`` с другим экземпляром ``StateManagementService``."""
        self._batch_stack = other._batch_stack

    def _share_plan_hooks_from(self, other: StateManagementService) -> None:
        """Разделить стеки активных ``PlanRecorder`` и ``PlanApplier`` с другим экземпляром сервиса."""
        self._plan_recorders = other._plan_recorders
        self._plan_appliers = other._plan_appliers

    def _push_plan_recorder(self, binding: _ServicePlanBinding) -> None:
        """Активировать перехватчик планирования ``PlanRecorder``."""
        self._plan_recorders.append(binding)

    def _pop_plan_recorder(self, binding: _ServicePlanBinding) -> None:
        """Снять перехватчик планирования ``PlanRecorder``."""
        if self._plan_recorders and self._plan_recorders[-1] is binding:
            self._plan_recorders.pop()
        elif binding in self._plan_recorders:
            self._plan_recorders.remove(binding)

    def _current_plan_recorder(self) -> _ServicePlanBinding | None:
        """Вернуть текущую активную привязку ``PlanRecorder`` или ``None``."""
        return self._plan_recorders[-1] if self._plan_recorders else None

    def _push_plan_applier(self, binding: _ServiceApplierBinding) -> None:
        """Активировать защитный контекст применения плана ``PlanApplier``."""
        self._plan_appliers.append(binding)

    def _pop_plan_applier(self, binding: _ServiceApplierBinding) -> None:
        """Снять контекст применения плана ``PlanApplier``."""
        if self._plan_appliers and self._plan_appliers[-1] is binding:
            self._plan_appliers.pop()
        elif binding in self._plan_appliers:
            self._plan_appliers.remove(binding)

    def _current_plan_applier(self) -> _ServiceApplierBinding | None:
        """Вернуть текущую активную привязку ``PlanApplier`` или ``None``."""
        return self._plan_appliers[-1] if self._plan_appliers else None

    def discard_batch(self, batch: NotificationBatch) -> None:
        """Безопасно удалить контекст ``NotificationBatch`` из стека активных батчей."""
        self._pop_batch(batch)

    def batch_notifications(self) -> NotificationBatch:
        """Создать контекстный менеджер для отложенного вызова и дедупликации ``notify``."""
        return NotificationBatch(self)

    def plan(self, *, flow_name: str | None = None) -> ConnectionPlanContext:
        """Создать read-only контекстный менеджер сбора ``FleetChangePlan`` для этого соединения."""
        return ConnectionPlanContext(self, flow_name=flow_name)

    def apply_plan(
        self,
        plan: FleetChangePlan,
        *,
        strict: bool = True,
    ) -> ConnectionApplyPlanContext:
        """Создать контекстный менеджер защищённого применения ``FleetChangePlan`` с проверкой дрейфа."""
        return ConnectionApplyPlanContext(self, plan, strict=strict)

    async def _finalize_ensure_result(
        self,
        res: EnsureResult,
        entries: list[Any],
    ) -> EnsureResult:
        """Завершить операцию ``ensure_*`` с обработкой отложенных или немедленных ``notify``."""
        if not entries:
            return res
        return await finalize_ensure_with_notify(
            self, res, entries, _pre_normalized=True
        )

    async def _record_planned_ensure(
        self,
        rec_binding: _ServicePlanBinding,
        depth: int,
        op_fn: Callable[..., Awaitable[EnsureResult]],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> EnsureResult:
        """Выполнить ``ensure_*`` в read-only режиме планирования и записать ``PlannedChange``."""
        kwargs["dry_run"] = True
        if depth > 0 or IN_NOTIFY_HANDLER.get():
            return await op_fn(self, *args, **kwargs)

        op_name = op_fn.__name__
        token = _ENSURE_NESTING_DEPTH.set(depth + 1)
        try:
            snapshot = await capture_before_snapshot(self, op_name, args, kwargs)
            res = await op_fn(self, *args, **kwargs)
        finally:
            _ENSURE_NESTING_DEPTH.reset(token)

        before_digest = compute_before_digest(
            operation=op_name,
            target=res.target,
            state=res.state,
            changed=res.changed,
            ok=res.ok,
            diff=res.diff,
            actions=extract_actions_from_result(res),
            snapshot=snapshot,
        )
        rec_binding.recorder.record_result(
            conn=self._conn,
            operation=op_name,
            res=res,
            before_digest=before_digest,
            host_override=rec_binding.host_override,
        )
        return res

    async def _apply_planned_ensure(
        self,
        app_binding: _ServiceApplierBinding,
        depth: int,
        op_fn: Callable[..., Awaitable[EnsureResult]],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> EnsureResult:
        """Выполнить pre-flight проверку дрейфа через ``PlanApplier`` и затем мутацию ``ensure_*``."""
        op_name = op_fn.__name__
        token = _ENSURE_NESTING_DEPTH.set(depth + 1)
        try:
            target_token = await app_binding.applier.verify_and_prepare(
                self,
                op_name,
                op_fn,
                args,
                kwargs,
                host_override=app_binding.host_override,
            )
            res = await op_fn(self, *args, **kwargs)
            app_binding.applier.mark_mutated(target_token, changed=res.changed)
            return res
        finally:
            _ENSURE_NESTING_DEPTH.reset(token)

    async def _execute_ensure(
        self,
        notify: NotifySpec,
        op_fn: Callable[..., Awaitable[EnsureResult]],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> EnsureResult:
        """Провалидировать ``notify``, применить хуки ``PlanRecorder``/``PlanApplier`` и выполнить ``ensure_*``."""
        entries = normalize_notify_spec(notify)
        depth = _ENSURE_NESTING_DEPTH.get()
        rec_binding = self._current_plan_recorder()
        if rec_binding is not None:
            return await self._record_planned_ensure(rec_binding, depth, op_fn, args, kwargs)

        app_binding = self._current_plan_applier()
        if depth == 0 and app_binding is not None and not IN_NOTIFY_HANDLER.get():
            explicit_dry = kwargs.get("dry_run")
            is_effective_dry = self._conn.dry_run if explicit_dry is None else bool(explicit_dry)
            if not is_effective_dry:
                res = await self._apply_planned_ensure(app_binding, depth, op_fn, args, kwargs)
                return await self._finalize_ensure_result(res, entries)

        token = _ENSURE_NESTING_DEPTH.set(depth + 1)
        try:
            res = await op_fn(self, *args, **kwargs)
        finally:
            _ENSURE_NESTING_DEPTH.reset(token)
        return await self._finalize_ensure_result(res, entries)

    async def gather_facts(
        self,
        *,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        ttl: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты о хосте (делегирует в ``conn.gather_facts``)."""
        return await self._conn.gather_facts(
            refresh=refresh,
            timeout=timeout,
            spec=spec,
            ttl=ttl,
        )

    async def resolve_pkg_manager(self, manager: PkgManagerName = "auto") -> str:
        """Определить пакетный менеджер хоста при ``manager='auto'``."""
        return await _resolve_pkg_manager(self, manager)

    async def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: PkgManagerName = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
        *,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте."""
        return await self._execute_ensure(
            notify,
            _ensure_package,
            package,
            state=state,
            manager=manager,
            update_cache=update_cache,
            sudo=sudo,
            dry_run=dry_run,
        )

    async def ensure_service(
        self,
        service: str,
        state: ServiceState = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
        manager: Literal["auto", "systemd", "openrc", "sysv", "windows"] = "auto",
        *,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса."""
        return await self._execute_ensure(
            notify,
            _ensure_service,
            service,
            state=state,
            enabled=enabled,
            sudo=sudo,
            dry_run=dry_run,
            manager=manager,
        )

    async def ensure_windows_service(
        self,
        name: str,
        *,
        state: WindowsServiceState = "started",
        startup_type: WindowsStartupType | None = None,
        timeout: float = 30.0,
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять службой Windows (SCM) с ожиданием переходных статусов."""
        return await self._execute_ensure(
            notify,
            _ensure_windows_service,
            name,
            state=state,
            startup_type=startup_type,
            timeout=timeout,
            dry_run=dry_run,
        )

    async def ensure_registry_key(
        self,
        path: str,
        *,
        name: str | None = None,
        value: Any = None,
        type: RegistryValueType | str = "String",
        state: Literal["present", "absent"] = "present",
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять разделом или параметром системного реестра Windows."""
        return await self._execute_ensure(
            notify,
            _ensure_registry_key,
            path,
            name=name,
            value=value,
            type=type,
            state=state,
            dry_run=dry_run,
        )

    async def ensure_windows_feature(
        self,
        name: str | Sequence[str],
        *,
        state: Literal["present", "absent"] = "present",
        include_sub_features: bool = False,
        include_management_tools: bool = False,
        source: str | None = None,
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять ролями и компонентами Windows через ServerManager или DISM."""
        return await self._execute_ensure(
            notify,
            _ensure_windows_feature,
            name,
            state=state,
            include_sub_features=include_sub_features,
            include_management_tools=include_management_tools,
            source=source,
            dry_run=dry_run,
        )

    def _can_inspect_in_dry_run(self) -> bool:
        """Проверить, можно ли безопасно выполнить read-only чтение с хоста при dry_run."""
        return can_inspect_in_dry_run(self._conn)

    @staticmethod
    def _extract_stat_mode(st: Mapping[str, Any]) -> int:
        """Извлечь числовые права доступа (0o7777) из словаря FileStat."""
        return extract_stat_mode(st)

    async def _get_owner_group(
        self, path_str: str, *, sudo: bool = False, is_link: bool = False
    ) -> tuple[str | None, str | None]:
        """Получить текущие имя владельца и группы файла или директории."""
        return await get_owner_group(self._conn, path_str, sudo=sudo, is_link=is_link)

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
        await apply_owner_group(
            self._conn,
            path_str,
            owner=owner,
            group=group,
            recurse=recurse,
            is_link=is_link,
            sudo=sudo,
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
        *,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие, замену или отсутствие строки в файле."""
        return await self._execute_ensure(
            notify,
            _ensure_line,
            remote_path,
            line,
            state=state,
            regex=regex,
            create=create,
            backup=backup,
            mode=mode,
            encoding=encoding,
            dry_run=dry_run,
        )

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
        backup: bool = False,
        encoding: str = "utf-8",
        atomic: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять файлом или символической ссылкой на хосте."""
        return await self._execute_ensure(
            notify,
            _ensure_file,
            remote_path,
            state=state,
            content=content,
            target=target,
            mode=mode,
            owner=owner,
            group=group,
            validate=validate,
            backup=backup,
            encoding=encoding,
            atomic=atomic,
            sudo=sudo,
            dry_run=dry_run,
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
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие директории, её прав и владельца."""
        return await self._execute_ensure(
            notify,
            _ensure_directory,
            remote_path,
            state=state,
            mode=mode,
            owner=owner,
            group=group,
            recurse=recurse,
            sudo=sudo,
            dry_run=dry_run,
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
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять системным пользователем и его группами."""
        return await self._execute_ensure(
            notify,
            _ensure_user,
            username,
            state=state,
            uid=uid,
            group=group,
            groups=groups,
            shell=shell,
            home=home,
            create_home=create_home,
            system=system,
            sudo=sudo,
            dry_run=dry_run,
        )

    async def _resolve_user_home(self, user: str, *, sudo: bool = False) -> str:
        """Определить домашнюю директорию пользователя на целевом хосте."""
        return await _resolve_user_home(self, user, sudo=sudo)

    async def ensure_authorized_key(
        self,
        user: str,
        key: str,
        *,
        state: Literal["present", "absent"] = "present",
        exclusive: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять SSH-ключами в ``~/.ssh/authorized_keys``."""
        return await self._execute_ensure(
            notify,
            _ensure_authorized_key,
            user,
            key,
            state=state,
            exclusive=exclusive,
            sudo=sudo,
            dry_run=dry_run,
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
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять unit-файлом systemd с вызовом ``daemon-reload`` при изменениях."""
        return await self._execute_ensure(
            notify,
            _ensure_systemd_unit,
            name,
            content=content,
            state=state,
            enabled=enabled,
            unit_dir=unit_dir,
            daemon_reload=daemon_reload,
            sudo=sudo,
            dry_run=dry_run,
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
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять параметром ядра ``sysctl`` и применять его на лету."""
        return await self._execute_ensure(
            notify,
            _ensure_sysctl,
            name,
            value,
            state=state,
            config_file=config_file,
            reload=reload,
            sudo=sudo,
            dry_run=dry_run,
        )

    async def ensure_yang(
        self,
        path: str,
        data: Mapping[str, Any] | str | bytes | None = None,
        *,
        datastore: str = "candidate",
        operation: Literal["merge", "replace"] = "merge",
        state: Literal["present", "absent"] = "present",
        auto_commit: bool = True,
        validate: bool = False,
        dry_run: bool | None = None,
        notify: NotifySpec = None,
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием узла YANG-конфигурации (NETCONF / RESTCONF / gNMI)."""
        return await self._execute_ensure(
            notify,
            _ensure_yang,
            path,
            data,
            datastore=datastore,
            operation=operation,
            state=state,
            auto_commit=auto_commit,
            validate=validate,
            dry_run=dry_run,
        )

    ensure_yang_config = ensure_yang

