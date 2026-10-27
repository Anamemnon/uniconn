# src/uniconn/sync/services.py
"""Синхронные отражения доменных сервисов и диагностической сессии."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from ..core.bridge import SyncContextBridge
from ..result import EnsureResult, SyncResult
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts
from ..services.provisioning import (
    PackageManagerStrategy,
    PkgManagerName,
    ServiceState,
)
from ..transports.base import FileStat

if TYPE_CHECKING:
    from ..background._diagnostic import DiagnosticResult, DiagnosticSession
    from .connection import SyncConnection


class SyncFileOperationsService:
    """Синхронное отражение доменного сервиса ``FileOperationsService`` (``sync_conn.files``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на хост (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.upload(
                local_path, remote_path, recurse=recurse, verify=verify, **kwargs
            )
        )

    def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с хоста (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.download(
                remote_path, local_path, recurse=recurse, verify=verify, **kwargs
            )
        )

    def read_file(
        self,
        remote_path: str | Path,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла в память (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.read_file(remote_path, encoding=encoding)
        )

    def write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
        *,
        atomic: bool = False,
    ) -> None:
        """Записать строку или байты в файл (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.write_file(
                remote_path, content, mode=mode, encoding=encoding, atomic=atomic
            )
        )

    def checksum(
        self,
        remote_path: str | Path,
        algorithm: Literal["sha256", "sha1", "md5"] = "sha256",
        *,
        sudo: bool = False,
    ) -> str:
        """Вычислить контрольную сумму файла на хосте (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.checksum(
                remote_path, algorithm=algorithm, sudo=sudo
            )
        )

    def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование пути (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.exists(remote_path)
        )

    def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.mkdir(
                remote_path, parents=parents, exist_ok=exist_ok, mode=mode
            )
        )

    def chmod(self, remote_path: str | Path, mode: int) -> None:
        """Изменить права доступа (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.chmod(remote_path, mode)
        )

    def stat(self, remote_path: str | Path) -> FileStat:
        """Получить метаданные файла (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.stat(remote_path)
        )

    def listdir(self, remote_path: str | Path = ".") -> list[str]:
        """Получить список файлов в директории (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.listdir(remote_path)
        )

    def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.remove_file(remote_path)
        )

    def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
        *,
        atomic: bool = False,
    ) -> str:
        """Отрендерить шаблон и записать его на хост (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.write_template(
                remote_path=remote_path,
                template_str_or_path=template_str_or_path,
                context=context,
                mode=mode,
                encoding=encoding,
                engine=engine,
                atomic=atomic,
            )
        )

    def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Инкрементально синхронизировать директорию (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            )
        )


class SyncStateManagementService:
    """Синхронное отражение доменного сервиса ``StateManagementService`` (``sync_conn.state``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        """Инициализировать синхронный сервис состояния."""
        self._sync_conn = sync_conn

    def gather_facts(
        self,
        *,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        """Собрать системные факты о хосте (синхронно)."""
        return self._sync_conn.gather_facts(
            refresh=refresh, timeout=timeout, spec=spec
        )

    def resolve_pkg_manager(
        self, manager: PkgManagerName = "auto"
    ) -> PackageManagerStrategy:
        """Определить стратегию пакетного менеджера для хоста (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.resolve_pkg_manager(manager=manager)
        )

    def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: PkgManagerName = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_package(
                package=package,
                state=state,
                manager=manager,
                update_cache=update_cache,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_service(
        self,
        service: str,
        state: ServiceState = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_service(
                service=service,
                state=state,
                enabled=enabled,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_line(
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
        """Идемпотентно обеспечить наличие или отсутствие строки в файле (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_line(
                remote_path=remote_path,
                line=line,
                state=state,
                regex=regex,
                create=create,
                backup=backup,
                mode=mode,
                encoding=encoding,
                dry_run=dry_run,
            )
        )

    def ensure_file(
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
        """Идемпотентно управлять файлом или символической ссылкой на хосте (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_file(
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
        )

    def ensure_directory(
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
        """Идемпотентно обеспечить наличие или отсутствие директории, её прав и владельца (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_directory(
                remote_path,
                state=state,
                mode=mode,
                owner=owner,
                group=group,
                recurse=recurse,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_user(
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
        """Идемпотентно управлять системным пользователем и его группами (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_user(
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
        )

    def ensure_authorized_key(
        self,
        user: str,
        key: str,
        *,
        state: Literal["present", "absent"] = "present",
        exclusive: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять SSH-ключами в ``~/.ssh/authorized_keys`` (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_authorized_key(
                user,
                key,
                state=state,
                exclusive=exclusive,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_systemd_unit(
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
        """Идемпотентно управлять unit-файлом systemd (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_systemd_unit(
                name,
                content=content,
                state=state,
                enabled=enabled,
                unit_dir=unit_dir,
                daemon_reload=daemon_reload,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_sysctl(
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
        """Идемпотентно управлять параметром ядра ``sysctl`` (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.state.ensure_sysctl(
                name,
                value,
                state=state,
                config_file=config_file,
                reload=reload,
                sudo=sudo,
                dry_run=dry_run,
            )
        )


class SyncTunnelService:
    """Синхронное отражение доменного сервиса ``TunnelService`` (``sync_conn.tunnels``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> SyncContextBridge[int]:
        """Синхронный контекстный менеджер прямого проброса порта (Local Port Forwarding)."""
        return SyncContextBridge(
            self._sync_conn._portal,
            self._sync_conn._async_conn.tunnels.forward_local_port(
                remote_host=remote_host,
                remote_port=remote_port,
                local_host=local_host,
                local_port=local_port,
            ),
            cast_fn=int,
        )

    def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> SyncContextBridge[int]:
        """Синхронный контекстный менеджер обратного проброса порта (Remote Port Forwarding)."""
        return SyncContextBridge(
            self._sync_conn._portal,
            self._sync_conn._async_conn.tunnels.forward_remote_port(
                remote_host=remote_host,
                remote_port=remote_port,
                local_host=local_host,
                local_port=local_port,
            ),
            cast_fn=int,
        )


class SyncDiagnosticSession:
    """Синхронное отражение ``DiagnosticSession`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        async_session: DiagnosticSession,
        sync_conn: SyncConnection,
    ) -> None:
        self._async_session = async_session
        self._sync_conn = sync_conn

    @property
    def workspace_dir(self) -> Path:
        """Рабочая директория текущей диагностической сессии."""
        return self._async_session.workspace_dir

    @property
    def pre_facts(self) -> HostFacts | None:
        """Слепок системных фактов до начала теста."""
        return self._async_session.pre_facts

    @property
    def post_facts(self) -> HostFacts | None:
        """Слепок системных фактов после завершения теста."""
        return self._async_session.post_facts

    @property
    def facts_diff(self) -> FactsDiffReport | None:
        """Отчёт об изменениях системных фактов (pre vs post)."""
        return self._async_session.facts_diff

    @property
    def result(self) -> DiagnosticResult | None:
        """Итоговый результат и манифест диагностической сессии."""
        return self._async_session.result

    @property
    def errors(self) -> list[str]:
        """Список зафиксированных нефатальных ошибок сессии."""
        return self._async_session.errors

    def snapshot(self, label: str = "snapshot") -> HostFacts:
        """Сделать промежуточный слепок ``HostFacts`` во время теста (синхронно)."""
        return self._sync_conn._run_coro(self._async_session.snapshot(label=label))

    def emit_custom_log(self, name: str, text: str) -> None:
        """Записать пользовательскую строку в конвейер логов сессии (синхронно)."""
        self._sync_conn._run_coro(self._async_session.emit_custom_log(name, text))

    def __enter__(self) -> Self:
        self._sync_conn._run_coro(self._async_session.__aenter__())
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return bool(
            self._sync_conn._run_coro(
                self._async_session.__aexit__(exc_type, exc_val, exc_tb)
            )
        )
