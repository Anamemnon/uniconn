# src/uniconn/_sync.py
"""Синхронные обёртки над Connection, ConnectionPool и ShellSession.

Все синхронные классы разделяют единый инфраструктурный портал ``EventLoopPortal``
(``uniconn.core.bridge``), который управляет выделенным event loop в daemon-потоке.
Также предоставляет синхронные отражения доменных сервисов:
- ``sync_conn.files`` (``SyncFileOperationsService``)
- ``sync_conn.state`` (``SyncStateManagementService``)
- ``sync_conn.tunnels`` (``SyncTunnelService``)
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr

from ._connection import Connection
from ._facts import FactsDiffReport, FactSpec, HostFacts
from ._shell import ShellSession
from .core.bridge import EventLoopPortal, SyncContextBridge
from .core.context import CwdContext, EnvContext
from .core.pipeline import HookCallback, HookEvent
from .core.resilience import CircuitBreaker, RateLimiter
from .result import EnsureResult, PingResult, Result, SyncResult
from .services.provisioning import PkgManagerName, ServiceState

if TYPE_CHECKING:
    from ._pool import ConnectionPool
    from .background._diagnostic import (
        DiagnosticConfig,
        DiagnosticResult,
        DiagnosticSession,
        StreamSourceSpec,
    )


class SyncShellSession:
    """Синхронная обёртка над async ShellSession на базе ``EventLoopPortal``."""

    def __init__(self, async_session: ShellSession, sync_conn: SyncConnection) -> None:
        self._async_session = async_session
        self._sync_conn = sync_conn

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен."""
        return self._async_session.is_alive

    def execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        """Выполнить команду в stateful shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.execute(command, timeout=timeout)
        )

    def send(self, text: str) -> None:
        """Отправить текст в stdin оболочки (синхронно)."""
        self._sync_conn._run_coro(self._async_session.send(text))

    def receive(self, timeout: float | None = None) -> str:
        """Прочитать доступный вывод из stdout оболочки (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.receive(timeout=timeout)
        )

    def resize(self, cols: int, rows: int) -> None:
        """Изменить размер окна терминала PTY (синхронно)."""
        self._sync_conn._run_coro(self._async_session.resize(cols, rows))

    def expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        """Выполнить интерактивный диалог по regex-паттернам в shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.expect(
                command=command,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
                allow_eof=allow_eof,
            )
        )

    def close(self) -> None:
        """Закрыть shell-сессию (синхронно)."""
        if self._sync_conn._closed:
            return
        self._sync_conn._run_coro(self._async_session.close())

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class SyncFileOperationsService:
    """Синхронное отражение доменного сервиса ``FileOperationsService`` (``sync_conn.files``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на хост (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.upload(
                local_path, remote_path, recurse=recurse, **kwargs
            )
        )

    def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с хоста (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.download(
                remote_path, local_path, recurse=recurse, **kwargs
            )
        )

    def read_file(
        self,
        remote_path: str,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла в память (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.read_file(remote_path, encoding=encoding)
        )

    def write_file(
        self,
        remote_path: str,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты в файл (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.write_file(
                remote_path, content, mode=mode, encoding=encoding
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

    def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа (синхронно)."""
        self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.chmod(remote_path, mode)
        )

    def stat(self, remote_path: str) -> dict[str, Any]:
        """Получить метаданные файла (синхронно)."""
        return self._sync_conn._run_coro(
            self._sync_conn._async_conn.files.stat(remote_path)
        )

    def listdir(self, remote_path: str = ".") -> list[str]:
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


class SyncConnection:
    """Синхронная обёртка над async Connection на базе ``EventLoopPortal``."""

    def __init__(self, async_conn: Connection) -> None:
        self._async_conn = async_conn
        self._portal = EventLoopPortal(owner_name="SyncConnection")
        self.files = SyncFileOperationsService(self)
        self.state = SyncStateManagementService(self)
        self.tunnels = SyncTunnelService(self)

    @property
    def _closed(self) -> bool:
        """Признак закрытия синхронной обёртки."""
        return self._portal.closed

    def _run_coro(self, coro: Any) -> Any:
        """Запустить корутину синхронно через ``EventLoopPortal``."""
        return self._portal.call(coro)

    def cd(self, path: str | Path) -> CwdContext:
        """Контекстный менеджер смены рабочей директории (синхронный)."""
        return self._async_conn.cd(path)

    def env(
        self, mapping: dict[str, str] | None = None, **env_vars: str
    ) -> EnvContext:
        """Контекстный менеджер переменных окружения (синхронный)."""
        return self._async_conn.env(mapping, **env_vars)

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Ограничитель частоты команд (Token Bucket), если настроен."""
        return self._async_conn.rate_limiter

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Автоматический предохранитель (Circuit Breaker), если настроен."""
        return self._async_conn.circuit_breaker

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``)."""
        self._async_conn.add_hook(event, callback)
        return self

    def run(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        sensitive: bool = False,
        dry_run: bool | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду синхронно."""
        return self._run_coro(
            self._async_conn.run(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                input=input,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                sensitive=sensitive,
                dry_run=dry_run,
                **kwargs,
            )
        )

    def run_bytes(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду синхронно и вернуть сырой байтовый вывод."""
        return self._run_coro(
            self._async_conn.run_bytes(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                input=input,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                **kwargs,
            )
        )

    def read_file(
        self,
        remote_path: str,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла в память (синхронно)."""
        return self.files.read_file(remote_path, encoding=encoding)

    def write_file(
        self,
        remote_path: str,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты из памяти в файл (синхронно)."""
        self.files.write_file(
            remote_path, content, mode=mode, encoding=encoding
        )

    def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование файла или директории на хосте (синхронно)."""
        return self.files.exists(remote_path)

    def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте (синхронно)."""
        self.files.mkdir(
            remote_path, parents=parents, exist_ok=exist_ok, mode=mode
        )

    def temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> SyncContextBridge[str]:
        """Синхронный контекстный менеджер временной директории на хосте."""
        return SyncContextBridge(
            self._portal,
            self._async_conn.temp_dir(prefix=prefix, suffix=suffix, dir=dir),
        )

    def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл на хосте (синхронно)."""
        self.files.remove_file(remote_path)

    def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на хост (синхронно)."""
        self.files.upload(local_path, remote_path, recurse=recurse, **kwargs)

    def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с хоста (синхронно)."""
        self.files.download(remote_path, local_path, recurse=recurse, **kwargs)

    def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу на хосте (синхронно)."""
        self.files.chmod(remote_path, mode)

    def stat(self, remote_path: str) -> dict[str, Any]:
        """Получить метаданные файла на хосте (синхронно)."""
        return self.files.stat(remote_path)

    def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список файлов в директории на хосте (синхронно)."""
        return self.files.listdir(remote_path)

    def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон и записать его на хост (синхронно)."""
        return self.files.write_template(
            remote_path=remote_path,
            template_str_or_path=template_str_or_path,
            context=context,
            mode=mode,
            encoding=encoding,
            engine=engine,
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
        """Инкрементально синхронизировать директорию с хостом (синхронно)."""
        return self.files.sync_dir(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> SyncContextBridge[int]:
        """Синхронный контекстный менеджер прямого проброса порта (Local Port Forwarding)."""
        return self.tunnels.forward_local_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        )

    def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> SyncContextBridge[int]:
        """Синхронный контекстный менеджер обратного проброса порта (Remote Port Forwarding)."""
        return self.tunnels.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        )

    def expect(
        self,
        command: str | Sequence[str],
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Result:
        """Выполнить интерактивную команду с сопоставлением паттернов (синхронно)."""
        return self._run_coro(
            self._async_conn.expect(
                command=command,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
                term_type=term_type,
                term_size=term_size,
                **kwargs,
            )
        )

    def run_commands(
        self,
        commands: Sequence[str | Sequence[str]],
        stop_on_error: bool = True,
        **kwargs: Any,
    ) -> list[Result]:
        """Последовательно выполнить список команд (синхронно)."""
        return self._run_coro(
            self._async_conn.run_commands(
                commands,
                stop_on_error=stop_on_error,
                **kwargs,
            )
        )

    def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Синхронный генератор для потокового выполнения команды."""
        return self._portal.iter_async(
            self._async_conn.stream(command, timeout=timeout, **kwargs)
        )

    def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения (синхронно)."""
        return self._run_coro(self._async_conn.is_alive(timeout=timeout))

    def ping(self, timeout: float | None = None) -> PingResult:
        """Проверить доступность хоста с измерением задержки (синхронно)."""
        return self._run_coro(self._async_conn.ping(timeout=timeout))

    def run_script(
        self,
        local_path: str | Path,
        args: Sequence[str] | None = None,
        *,
        interpreter: str | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        raise_on_error: bool = False,
        sensitive: bool = False,
        dry_run: bool | None = None,
    ) -> Result:
        """Загрузить локальный скрипт во временную директорию, выполнить и удалить (синхронно)."""
        return self._run_coro(
            self._async_conn.run_script(
                local_path=local_path,
                args=args,
                interpreter=interpreter,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                env=env,
                timeout=timeout,
                raise_on_error=raise_on_error,
                sensitive=sensitive,
                dry_run=dry_run,
            )
        )

    def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> SyncShellSession:
        """Открыть интерактивную stateful PTY shell-сессию (синхронно)."""
        async_session = self._run_coro(
            self._async_conn.open_shell(
                term_type=term_type,
                term_size=term_size,
                init_posix=init_posix,
                **kwargs,
            )
        )
        return SyncShellSession(async_session, self)

    def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        """Собрать системные факты о целевом хосте (синхронно)."""
        return self._run_coro(
            self._async_conn.gather_facts(
                refresh=refresh, timeout=timeout, spec=spec
            )
        )

    def diagnostic_session(
        self,
        config: DiagnosticConfig | Mapping[str, Any] | str | Path | None = None,
        *,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        streams: Sequence[StreamSourceSpec | Mapping[str, Any] | str] | None = None,
        local_dir: str | Path | None = None,
        archive_path: str | Path | None = None,
        archive_format: Literal["tar.gz", "zip", "none"] | None = None,
        forward_to: SyncConnection | Connection | str | None = None,
        forward_remote_dir: str | None = None,
        fsync_realtime: bool | None = None,
        gather_pre_facts: bool | None = None,
        gather_post_facts: bool | None = None,
    ) -> SyncDiagnosticSession:
        """Открыть комплексную диагностическую сессию (синхронный контекстный менеджер)."""
        async_fwd: Connection | str | None = (
            forward_to._async_conn
            if isinstance(forward_to, SyncConnection)
            else forward_to
        )
        async_sess = self._async_conn.diagnostic_session(
            config=config,
            spec=spec,
            streams=streams,
            local_dir=local_dir,
            archive_path=archive_path,
            archive_format=archive_format,
            forward_to=async_fwd,
            forward_remote_dir=forward_remote_dir,
            fsync_realtime=fsync_realtime,
            gather_pre_facts=gather_pre_facts,
            gather_post_facts=gather_post_facts,
        )
        return SyncDiagnosticSession(async_sess, self)

    def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: PkgManagerName = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте (синхронно)."""
        return self.state.ensure_package(
            package=package,
            state=state,
            manager=manager,
            update_cache=update_cache,
            sudo=sudo,
            dry_run=dry_run,
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
        return self.state.ensure_service(
            service=service,
            state=state,
            enabled=enabled,
            sudo=sudo,
            dry_run=dry_run,
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
        return self.state.ensure_line(
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

    def close(self) -> None:
        """Закрыть подключение и освободить ресурсы фонового event loop."""
        cleanup = self._async_conn.close() if self._async_conn else None
        self._portal.close(cleanup_coro=cleanup)

    def __enter__(self) -> Self:
        self._run_coro(self._async_conn._transport.connect())
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class SyncConnectionPool:
    """Синхронная обёртка над ``ConnectionPool`` на базе ``EventLoopPortal``."""

    def __init__(self, async_pool: ConnectionPool) -> None:
        self._async_pool = async_pool
        self._portal = EventLoopPortal(owner_name="SyncConnectionPool")

    @property
    def _closed(self) -> bool:
        """Признак закрытия синхронного пула."""
        return self._portal.closed

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Общий ограничитель частоты команд пула (если настроен)."""
        return self._async_pool.rate_limiter

    @property
    def circuit_breakers(self) -> dict[str, CircuitBreaker]:
        """Словарь предохранителей ``CircuitBreaker`` по ключам хостов пула."""
        return self._async_pool.circuit_breakers

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        group: str | None = None,
        host: str | None = None,
        max_concurrent: int = 10,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: bool = False,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> Self:
        """Создать синхронный пул подключений из JSON или YAML инвентарного файла."""
        from ._pool import ConnectionPool

        pool = ConnectionPool.from_file(
            path,
            group=group,
            host=host,
            max_concurrent=max_concurrent,
            retry_attempts=retry_attempts,
            logger=logger,
            rate_limit=rate_limit,
            circuit_breaker=circuit_breaker,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )
        return cls(pool)

    def _run_coro(self, coro: Any) -> Any:
        """Выполнить корутину пула в фоновом event loop."""
        return self._portal.call(coro)

    def connect(self) -> None:
        """Открыть и удерживать соединения ко всем хостам пула (синхронно)."""
        self._run_coro(self._async_pool.connect())

    def close(self) -> None:
        """Закрыть все соединения пула и остановить фоновый event loop."""
        cleanup = self._async_pool.close() if self._async_pool else None
        self._portal.close(cleanup_coro=cleanup)

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def map(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        **kwargs: Any,
    ) -> list[Result]:
        """Параллельно выполнить команду на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.map(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                **kwargs,
            )
        )

    def map_safe(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> dict[str, Result | Exception]:
        """Параллельно выполнить команду без выброса исключений (синхронно)."""
        return self._run_coro(
            self._async_pool.map_safe(command, timeout=timeout, **kwargs)
        )

    def map_with_callback(
        self,
        command: str | Sequence[str],
        callback: Callable[[str, Result], None],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Параллельно выполнить команду с вызовом callback по мере готовности (синхронно)."""
        self._run_coro(
            self._async_pool.map_with_callback(
                command,
                callback=callback,
                timeout=timeout,
                **kwargs,
            )
        )

    def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула (синхронно)."""
        self._run_coro(
            self._async_pool.upload(
                local_path,
                remote_path,
                recurse=recurse,
                **kwargs,
            )
        )

    def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> dict[str, str]:
        """Параллельно скачать файл или директорию со всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.download(
                remote_path,
                local_path,
                recurse=recurse,
                **kwargs,
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
    ) -> dict[str, SyncResult]:
        """Параллельно синхронизировать директорию на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            )
        )

    def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> dict[str, str]:
        """Параллельно отрендерить и записать шаблон на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.write_template(
                remote_path=remote_path,
                template_str_or_path=template_str_or_path,
                context=context,
                mode=mode,
                encoding=encoding,
                engine=engine,
            )
        )

    def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> dict[str, HostFacts]:
        """Параллельно собрать системные факты (``HostFacts``) со всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.gather_facts(
                refresh=refresh, timeout=timeout, spec=spec
            )
        )

    def diff_facts(
        self,
        *,
        baseline_host: str | None = None,
        fields: Sequence[str] | None = None,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> FactsDiffReport:
        """Собрать системные факты со всех хостов пула и найти расхождения с эталоном (синхронно)."""
        return self._run_coro(
            self._async_pool.diff_facts(
                baseline_host=baseline_host,
                fields=fields,
                refresh=refresh,
                timeout=timeout,
                spec=spec,
            )
        )

    def ping(
        self,
        timeout: float | None = None,
    ) -> dict[str, PingResult]:
        """Параллельно проверить доступность всех хостов пула с измерением задержки (синхронно)."""
        return self._run_coro(self._async_pool.ping(timeout=timeout))

    def run_script(
        self,
        local_path: str | Path,
        args: Sequence[str] | None = None,
        *,
        interpreter: str | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        raise_on_error: bool = False,
        sensitive: bool = False,
        dry_run: bool | None = None,
    ) -> dict[str, Result]:
        """Параллельно загрузить, выполнить и удалить локальный скрипт на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.run_script(
                local_path=local_path,
                args=args,
                interpreter=interpreter,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                env=env,
                timeout=timeout,
                raise_on_error=raise_on_error,
                sensitive=sensitive,
                dry_run=dry_run,
            )
        )

    def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: PkgManagerName = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно проверить/установить/удалить пакет(ы) на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_package(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно привести состояние системного сервиса на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_service(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить наличие или отсутствие строки в файле на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_line(
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

    def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Iterator[tuple[str, str]]:
        """Синхронный генератор мульти-стриминга со всех хостов пула."""
        return self._portal.iter_async(
            self._async_pool.stream(command, timeout=timeout, **kwargs)
        )
