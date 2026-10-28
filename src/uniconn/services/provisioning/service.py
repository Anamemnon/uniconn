# src/uniconn/services/provisioning/service.py
"""Фасад доменного сервиса идемпотентного управления состоянием (StateManagementService)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ...result import EnsureResult
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
from .services import (
    ServiceState,
)
from .services import (
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

if TYPE_CHECKING:
    from ...core.connection import Connection
    from ..facts_models import FactSpec, HostFacts


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
        return await self._conn.gather_facts(refresh=refresh, timeout=timeout, spec=spec)

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
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте."""
        return await _ensure_package(
            self,
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
        manager: Literal["auto", "systemd", "openrc", "sysv"] = "auto",
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса."""
        return await _ensure_service(
            self,
            service,
            state=state,
            enabled=enabled,
            sudo=sudo,
            dry_run=dry_run,
            manager=manager,
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
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие, замену или отсутствие строки в файле."""
        return await _ensure_line(
            self,
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
        encoding: str = "utf-8",
        atomic: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять файлом или символической ссылкой на хосте."""
        return await _ensure_file(
            self,
            remote_path,
            state=state,
            content=content,
            target=target,
            mode=mode,
            owner=owner,
            group=group,
            validate=validate,
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
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие директории, её прав и владельца."""
        return await _ensure_directory(
            self,
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
    ) -> EnsureResult:
        """Идемпотентно управлять системным пользователем и его группами."""
        return await _ensure_user(
            self,
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
    ) -> EnsureResult:
        """Идемпотентно управлять SSH-ключами в ``~/.ssh/authorized_keys``."""
        return await _ensure_authorized_key(
            self,
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
    ) -> EnsureResult:
        """Идемпотентно управлять unit-файлом systemd с вызовом ``daemon-reload`` при изменениях."""
        return await _ensure_systemd_unit(
            self,
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
    ) -> EnsureResult:
        """Идемпотентно управлять параметром ядра ``sysctl`` и применять его на лету."""
        return await _ensure_sysctl(
            self,
            name,
            value,
            state=state,
            config_file=config_file,
            reload=reload,
            sudo=sudo,
            dry_run=dry_run,
        )
