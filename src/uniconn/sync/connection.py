# src/uniconn/sync/connection.py
"""Синхронная обёртка над async Connection на базе ``EventLoopPortal``."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr

from ..config.models import ConnectionConfig
from ..core.bridge import EventLoopPortal, SyncContextBridge
from ..core.connection import Connection, OperationObserver
from ..core.context import CwdContext, EnvContext, ExecutionContext
from ..core.pipeline import CommandPipeline, HookCallback, HookEvent
from ..core.resilience import CircuitBreaker, RateLimiter
from ..result import EnsureResult, PingResult, Result, SyncResult
from ..services.facts_models import FactSpec, HostFacts
from ..services.provisioning import PkgManagerName, ServiceState
from ..transports.base import BaseTransport, FileStat
from .services import (
    SyncDiagnosticSession,
    SyncFileOperationsService,
    SyncStateManagementService,
    SyncTunnelService,
)
from .shell import SyncShellSession

if TYPE_CHECKING:
    from ..background._diagnostic import (
        DiagnosticConfig,
        StreamSourceSpec,
    )


class SyncConnection:
    """Синхронная обёртка над async Connection на базе ``EventLoopPortal``."""

    def __init__(self, async_conn: Connection) -> None:
        self._async_conn = async_conn
        self._portal = EventLoopPortal(owner_name="SyncConnection")
        self.files = SyncFileOperationsService(self)
        self.state = SyncStateManagementService(self)
        self.tunnels = SyncTunnelService(self)

    # ─── Фабричные методы и клонирование ───────────────────────────

    @classmethod
    def from_uri(
        cls,
        uri: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать синхронное подключение напрямую из URI строки."""
        return cls(
            Connection.from_uri(
                uri,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                before_run=before_run,
                after_run=after_run,
                on_error=on_error,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    @classmethod
    def from_config(
        cls,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать синхронное подключение из объекта ``ConnectionConfig``."""
        return cls(
            Connection.from_config(
                config,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                before_run=before_run,
                after_run=after_run,
                on_error=on_error,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
    ) -> Self:
        """Создать синхронное подключение из словаря."""
        return cls(
            Connection.from_dict(
                data,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
            )
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        *,
        host: str | None = None,
        group: str | None = None,
    ) -> list[Self]:
        """Создать список синхронных подключений из JSON/YAML/TOML файла."""
        conns = Connection.from_file(
            path,
            retry_attempts=retry_attempts,
            logger=logger,
            host=host,
            group=group,
        )
        return [cls(c) for c in conns]

    @classmethod
    def from_inventory(
        cls,
        path: str | Path,
        host: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать одиночное синхронное подключение по имени хоста из инвентарного файла."""
        return cls(
            Connection.from_inventory(
                path,
                host=host,
                retry_attempts=retry_attempts,
                logger=logger,
            )
        )

    def copy(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | SecretStr | None = None,
        key_file: str | None = None,
        passphrase: str | SecretStr | None = None,
        ssh_config: str | bool | None = None,
        timeout: float | None = None,
        options: dict[str, Any] | None = None,
        retry_attempts: int | None = None,
        logger: logging.Logger | None = None,
        dry_run: bool | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать копию синхронного подключения с возможностью изменения параметров."""
        return type(self)(
            self._async_conn.copy(
                host=host,
                port=port,
                username=username,
                password=password,
                key_file=key_file,
                passphrase=passphrase,
                ssh_config=ssh_config,
                timeout=timeout,
                options=options,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    def with_overrides(self, **overrides: Any) -> Self:
        """Создать копию синхронного подключения с переопределёнными параметрами."""
        return type(self)(self._async_conn.with_overrides(**overrides))

    @property
    def _closed(self) -> bool:
        """Признак закрытия синхронной обёртки."""
        return self._portal.closed

    @property
    def config(self) -> ConnectionConfig:
        """Конфигурация подключения."""
        return self._async_conn.config

    @property
    def transport(self) -> BaseTransport:
        """Низкоуровневый транспорт подключения."""
        return self._async_conn.transport

    def swap_transport(self, new_transport: BaseTransport) -> BaseTransport:
        """Заменить активный транспорт подключения и вернуть предыдущий."""
        return self._async_conn.swap_transport(new_transport)

    @property
    def context(self) -> ExecutionContext:
        """Текущий контекст выполнения."""
        return self._async_conn.context

    @property
    def logger(self) -> logging.Logger:
        """Логгер подключения."""
        return self._async_conn.logger

    @property
    def retry_attempts(self) -> int:
        """Количество повторных попыток подключения."""
        return self._async_conn.retry_attempts

    @property
    def is_dry_run(self) -> bool:
        """Включён ли глобальный режим симуляции (``dry_run``)."""
        return self._async_conn.is_dry_run

    @property
    def dry_run(self) -> bool:
        """Включён ли режим dry_run для данного подключения."""
        return self._async_conn.dry_run

    @property
    def transport_name(self) -> str:
        """Имя используемого транспорта."""
        return self._async_conn.transport_name

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека ``conn.cd()``."""
        return self._async_conn.current_cwd

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения из стека ``conn.env()``."""
        return self._async_conn.current_env

    @property
    def pipeline(self) -> CommandPipeline:
        """Конвейер выполнения команд."""
        return self._async_conn.pipeline

    def get_hooks(self, event: HookEvent) -> list[HookCallback]:
        """Вернуть копию списка зарегистрированных хуков."""
        return self._async_conn.get_hooks(event)

    @property
    def operation_observers(self) -> list[OperationObserver]:
        """Список наблюдателей за не-командными операциями."""
        return self._async_conn.operation_observers

    def add_operation_observer(self, observer: OperationObserver) -> Self:
        """Зарегистрировать наблюдателя за файловыми и интерактивными операциями."""
        self._async_conn.add_operation_observer(observer)
        return self

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

    @rate_limiter.setter
    def rate_limiter(self, value: float | RateLimiter | None) -> None:
        self._async_conn.rate_limiter = value

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Автоматический предохранитель (Circuit Breaker), если настроен."""
        return self._async_conn.circuit_breaker

    @circuit_breaker.setter
    def circuit_breaker(self, value: CircuitBreaker | None) -> None:
        self._async_conn.circuit_breaker = value

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
        sensitive: bool = False,
        dry_run: bool | None = None,
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
                sensitive=sensitive,
                dry_run=dry_run,
                **kwargs,
            )
        )

    def read_file(
        self,
        remote_path: str | Path,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла в память (синхронно)."""
        return self.files.read_file(remote_path, encoding=encoding)

    def write_file(
        self,
        remote_path: str | Path,
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
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на хост (синхронно)."""
        self.files.upload(local_path, remote_path, recurse=recurse, **kwargs)

    def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с хоста (синхронно)."""
        self.files.download(remote_path, local_path, recurse=recurse, **kwargs)

    def chmod(self, remote_path: str | Path, mode: int) -> None:
        """Изменить права доступа к файлу на хосте (синхронно)."""
        self.files.chmod(remote_path, mode)

    def stat(self, remote_path: str | Path) -> FileStat:
        """Получить метаданные файла на хосте (синхронно)."""
        return self.files.stat(remote_path)

    def listdir(self, remote_path: str | Path = ".") -> list[str]:
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
        sudo: bool = False,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять файлом или символической ссылкой на хосте (синхронно)."""
        return self.state.ensure_file(
            remote_path,
            state=state,
            content=content,
            target=target,
            mode=mode,
            owner=owner,
            group=group,
            validate=validate,
            encoding=encoding,
            sudo=sudo,
            dry_run=dry_run,
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
        return self.state.ensure_directory(
            remote_path,
            state=state,
            mode=mode,
            owner=owner,
            group=group,
            recurse=recurse,
            sudo=sudo,
            dry_run=dry_run,
        )

    def use_cassette(
        self,
        path: str | Path,
        *,
        mode: Any = "once",
        match_on: Sequence[Literal["command", "cwd", "sudo"]] = (
            "command",
            "cwd",
            "sudo",
        ),
        normalize_temp: bool = True,
        allow_playback_repeats: bool = True,
        mask_secrets: bool = True,
    ) -> Any:
        """Синхронный контекстный менеджер записи и воспроизведения кассет взаимодействий."""
        from ..transports.replay import SyncCassetteContext

        async_ctx = self._async_conn.use_cassette(
            path,
            mode=mode,
            match_on=match_on,
            normalize_temp=normalize_temp,
            allow_playback_repeats=allow_playback_repeats,
            mask_secrets=mask_secrets,
        )
        return SyncCassetteContext(async_ctx, self)

    def close(self) -> None:
        """Закрыть подключение и освободить ресурсы фонового event loop."""
        cleanup = self._async_conn.close() if self._async_conn else None
        self._portal.close(cleanup_coro=cleanup)

    def __enter__(self) -> Self:
        self._portal.reopen()
        self._run_coro(self._async_conn.transport.connect())
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
