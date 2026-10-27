# src/uniconn/sync/pool.py
"""Синхронная обёртка над ``ConnectionPool`` на базе ``EventLoopPortal``."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self, TypeVar

from pydantic import SecretStr

from ..core.bridge import EventLoopPortal, SyncContextBridge
from ..core.connection import Connection
from ..core.resilience import CircuitBreaker, RateLimiter
from ..result import EnsureResult, PingResult, Result, SyncResult
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts
from ..services.provisioning import PkgManagerName, ServiceState

if TYPE_CHECKING:
    from ..pool.connection_pool import ConnectionPool

T = TypeVar("T")


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

    def add_connection_initializer(
        self, initializer: Callable[[Connection], None]
    ) -> None:
        """Зарегистрировать колбэк инициализации каждого соединения пула."""
        self._async_pool.add_connection_initializer(initializer)

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
        batch_size: int | None = None,
        max_fail_ratio: float = 0.0,
    ) -> Self:
        """Создать синхронный пул подключений из JSON или YAML инвентарного файла."""
        from ..pool.connection_pool import ConnectionPool

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
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )
        return cls(pool)

    def select(
        self,
        hosts: Sequence[str] | Callable[[str], bool] | None = None,
        *,
        predicate: Callable[[str, Connection], bool] | None = None,
    ) -> SyncConnectionPool:
        """Выбрать подмножество хостов из синхронного пула с сохранением открытых сессий."""
        sub_async = self._async_pool.select(hosts=hosts, predicate=predicate)
        return SyncConnectionPool(sub_async)

    def _run_coro(self, coro: Any) -> Any:
        """Выполнить корутину пула в фоновом event loop."""
        return self._portal.call(coro)

    def connect(self) -> None:
        """Открыть и удерживать соединения ко всем хостам пула (синхронно)."""
        self._portal.reopen()
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
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> list[Result]:
        """Параллельно выполнить команду на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.map(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
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

    def apply(
        self,
        func: Callable[[Connection], Awaitable[T]],
    ) -> list[T]:
        """Параллельно выполнить произвольную async-функцию ``func(conn)`` на всех хостах пула (синхронно)."""
        return self._run_coro(self._async_pool.apply(func))

    def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула (синхронно)."""
        self._run_coro(
            self._async_pool.upload(
                local_path,
                remote_path,
                recurse=recurse,
                verify=verify,
                **kwargs,
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
    ) -> dict[str, str]:
        """Параллельно скачать файл или директорию со всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.download(
                remote_path,
                local_path,
                recurse=recurse,
                verify=verify,
                **kwargs,
            )
        )

    def checksum(
        self,
        remote_path: str | Path,
        algorithm: Literal["sha256", "sha1", "md5"] = "sha256",
        *,
        sudo: bool = False,
    ) -> dict[str, str]:
        """Параллельно вычислить контрольную сумму файла на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.checksum(
                remote_path, algorithm=algorithm, sudo=sudo
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
        *,
        atomic: bool = False,
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
                atomic=atomic,
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

    def wait_for_connection(
        self,
        timeout: float = 120.0,
        interval: float = 2.0,
        delay: float = 0.0,
    ) -> dict[str, PingResult]:
        """Параллельно ожидать восстановления доступности всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.wait_for_connection(
                timeout=timeout,
                interval=interval,
                delay=delay,
            )
        )

    def wait_for_port(
        self,
        port: int,
        *,
        host: str | None = None,
        state: Literal["open", "closed"] = "open",
        check_from: Literal["remote", "local"] = "remote",
        timeout: float = 60.0,
        interval: float = 1.0,
        delay: float = 0.0,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, float]:
        """Параллельно ожидать открытия или закрытия TCP-порта на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.wait_for_port(
                port,
                host=host,
                state=state,
                check_from=check_from,
                timeout=timeout,
                interval=interval,
                delay=delay,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
        )

    def wait_for_path(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent"] = "present",
        content_regex: str | None = None,
        timeout: float = 60.0,
        interval: float = 1.0,
        delay: float = 0.0,
        sudo: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, float]:
        """Параллельно ожидать появления или удаления пути на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.wait_for_path(
                remote_path,
                state=state,
                content_regex=content_regex,
                timeout=timeout,
                interval=interval,
                delay=delay,
                sudo=sudo,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
        )

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
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние файла или симлинка на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_file(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние директории на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_directory(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние пользователя на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_user(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно управлять SSH-ключами пользователя на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_authorized_key(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно управлять unit-файлом systemd на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_systemd_unit(
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
    ) -> dict[str, EnsureResult]:
        """Параллельно управлять параметром ядра ``sysctl`` на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_sysctl(
                name,
                value,
                state=state,
                config_file=config_file,
                reload=reload,
                sudo=sudo,
                dry_run=dry_run,
            )
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
    ) -> SyncContextBridge[dict[str, Any]]:
        """Синхронный контекстный менеджер записи/воспроизведения кассет для всего пула хостов."""
        self._portal.reopen()
        return SyncContextBridge(
            self._portal,
            self._async_pool.use_cassette(
                path,
                mode=mode,
                match_on=match_on,
                normalize_temp=normalize_temp,
                allow_playback_repeats=allow_playback_repeats,
                mask_secrets=mask_secrets,
            ),
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

