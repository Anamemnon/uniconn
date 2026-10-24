# src/uniconn/_connection.py
"""Фасад Connection для работы с удалёнными и локальными хостами.

Делегирует выполнение команд конвейеру ``CommandPipeline``, а доменные
операции — специализированным сервисам:
- ``conn.files`` (``FileOperationsService``)
- ``conn.state`` (``StateManagementService``)
- ``conn.tunnels`` (``TunnelService``)
- ``conn._facts_collector`` (``FactCollector``)
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import AsyncIterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr
from tenacity import wait_exponential_jitter

from ._config import ConnectionConfig
from ._facts import HostFacts
from ._logging import log_event
from ._shell import ShellSession
from .config.inventory import InventoryLoader
from .core.context import CwdContext, EnvContext, ExecutionContext, TempDirContext
from .core.pipeline import (
    CommandPipeline,
    CommandRequest,
    HookCallback,
    HookEvent,
    format_command,
    prepare_sudo_command,
)
from .plugins._loader import TransportLoader
from .result import EnsureResult, Result, SyncResult
from .services.facts import FactCollector
from .services.files import FileOperationsService
from .services.provisioning import PkgManagerName, ServiceState, StateManagementService
from .services.templates import render_template as render_template
from .services.tunnels import TunnelService
from .transports._base import BaseTransport

if TYPE_CHECKING:
    from ._sync import SyncConnection

logger = logging.getLogger(__name__)

# Псевдонимы для обратной совместимости внутренних импортов и моков
_CwdContext = CwdContext
_EnvContext = EnvContext
_TempDirContext = TempDirContext
_format_command = format_command
_parse_inventory_data = InventoryLoader.parse_data
_wait_exponential_jitter = wait_exponential_jitter


class Connection:
    """Основной класс-фасад для работы с удалёнными и локальными хостами.

    Предоставляет как плоские фасадные методы (``conn.run``, ``conn.read_file``,
    ``conn.ensure_package``, ``conn.forward_local_port``), так и модульные
    доменные пространства имён:
        - ``conn.files`` — файловые операции, SFTP, шаблоны и ``sync_dir``
        - ``conn.state`` — идемпотентное управление пакетами, сервисами и строками конфигов
        - ``conn.tunnels`` — сетевой проброс портов (Local/Remote Port Forwarding)
    """

    def __init__(
        self,
        transport: BaseTransport,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
    ) -> None:
        self._transport = transport
        self._config = config
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._dry_run = dry_run
        self._context = ExecutionContext()
        self._cwd_stack = self._context.cwd_stack
        self._env_stack = self._context.env_stack
        self._hooks: dict[HookEvent, list[HookCallback]] = {
            "before_run": list(before_run or []),
            "after_run": list(after_run or []),
            "on_error": list(on_error or []),
        }
        self._pipeline = CommandPipeline(self)
        self.files = FileOperationsService(self)
        self.state = StateManagementService(self)
        self.tunnels = TunnelService(self)
        self._facts_collector = FactCollector(self)

    @property
    def pipeline(self) -> CommandPipeline:
        """Конвейер выполнения команд (Middleware Pipeline)."""
        return self._pipeline

    @property
    def _cached_facts(self) -> HostFacts | None:
        """Кэшированный экземпляр HostFacts."""
        return self._facts_collector.cached

    @_cached_facts.setter
    def _cached_facts(self, value: HostFacts | None) -> None:
        self._facts_collector.cached = value

    # ─── Фабричные методы ──────────────────────────────────────────

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
    ) -> Self:
        """Создать подключение из URI строки."""
        config = ConnectionConfig.from_uri(uri)
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(
            transport,
            config,
            retry_attempts,
            logger,
            dry_run=dry_run,
            before_run=before_run,
            after_run=after_run,
            on_error=on_error,
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
    ) -> Self:
        """Создать подключение из конфигурации."""
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(
            transport,
            config,
            retry_attempts,
            logger,
            dry_run=dry_run,
            before_run=before_run,
            after_run=after_run,
            on_error=on_error,
        )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
    ) -> Self:
        """Создать подключение из словаря."""
        retry = data.get("retry_attempts", retry_attempts)
        effective_dry_run = bool(data.get("dry_run", dry_run))
        if "uri" in data:
            conn = cls.from_uri(
                str(data["uri"]),
                retry_attempts=retry,
                logger=logger,
                dry_run=effective_dry_run,
            )
            overrides = {
                k: v
                for k, v in data.items()
                if k
                not in (
                    "uri",
                    "transport",
                    "retry_attempts",
                    "logger",
                    "dry_run",
                    "name",
                    "groups",
                )
                and (
                    k != "host"
                    or conn.config.host is None
                    or (conn.config.transport == "local" and conn.config.host == "localhost")
                )
            }
            if overrides:
                conn = conn.with_overrides(**overrides)
            return conn
        config = ConnectionConfig(
            **{
                k: v
                for k, v in data.items()
                if k not in ("retry_attempts", "logger", "dry_run", "name", "groups")
            }
        )
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry, logger, dry_run=effective_dry_run)

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
        """Создать подключения из JSON/YAML файла (включая инвентарь с хостами и группами)."""
        entries = InventoryLoader.load_file(path, host=host, group=group)
        return [cls.from_dict(data, retry_attempts, logger) for data in entries]

    @classmethod
    def from_inventory(
        cls,
        path: str | Path,
        host: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать одиночное подключение по имени хоста из инвентарного файла (YAML/JSON)."""
        conns = cls.from_file(
            path,
            retry_attempts=retry_attempts,
            logger=logger,
            host=host,
        )
        return conns[0]

    # ─── Клонирование и модификация ────────────────────────────────

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
    ) -> Self:
        """Создать копию подключения с возможностью изменения параметров."""
        new_config = ConnectionConfig(
            transport=self._config.transport,
            host=host if host is not None else self._config.host,
            port=port if port is not None else self._config.port,
            username=username if username is not None else self._config.username,
            password=(
                SecretStr(password)
                if isinstance(password, str)
                else password
                if password is not None
                else self._config.password
            ),
            key_file=key_file if key_file is not None else self._config.key_file,
            passphrase=(
                SecretStr(passphrase)
                if isinstance(passphrase, str)
                else passphrase
                if passphrase is not None
                else self._config.passphrase
            ),
            ssh_config=(
                ssh_config if ssh_config is not None else self._config.ssh_config
            ),
            timeout=timeout if timeout is not None else self._config.timeout,
            options=options if options is not None else self._config.options,
        )
        transport_class = TransportLoader.get(new_config.transport)
        transport = transport_class(new_config)
        return type(self)(
            transport,
            new_config,
            retry_attempts or self._retry_attempts,
            logger or self._logger,
            dry_run=self._dry_run if dry_run is None else dry_run,
            before_run=self._hooks["before_run"],
            after_run=self._hooks["after_run"],
            on_error=self._hooks["on_error"],
        )

    def with_overrides(self, **overrides: Any) -> Self:
        """Создать копию подключения с переопределёнными параметрами."""
        return self.copy(
            host=overrides.get("host"),
            port=overrides.get("port"),
            username=overrides.get("username"),
            password=overrides.get("password"),
            key_file=overrides.get("key_file"),
            passphrase=overrides.get("passphrase"),
            ssh_config=overrides.get("ssh_config"),
            timeout=overrides.get("timeout"),
            options=overrides.get("options"),
            retry_attempts=overrides.get("retry_attempts"),
            logger=overrides.get("logger"),
            dry_run=overrides.get("dry_run"),
        )

    # ─── Контекстные менеджеры cd / env / temp_dir и Hooks ─────────

    def cd(self, path: str | Path) -> CwdContext:
        """Контекстный менеджер для временной смены рабочей директории."""
        return self._context.cd(path)

    def env(
        self, mapping: dict[str, str] | None = None, **env_vars: str
    ) -> EnvContext:
        """Контекстный менеджер для временной установки переменных окружения."""
        return self._context.env(mapping, **env_vars)

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека ``conn.cd()``."""
        return self._context.current_cwd

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения из стека ``conn.env()``."""
        return self._context.current_env

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``)."""
        if event not in self._hooks:
            raise ValueError(
                f"Unknown hook event: {event!r}. "
                "Expected 'before_run', 'after_run', or 'on_error'"
            )
        self._hooks[event].append(callback)
        return self

    def temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> TempDirContext:
        """Асинхронный контекстный менеджер временной директории на хосте."""
        return TempDirContext(self, prefix=prefix, suffix=suffix, dir=dir)

    async def _create_temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | None = None,
    ) -> str:
        """Создать временную директорию на хосте и вернуть путь к ней."""
        base_dir = dir or "/tmp"
        if self._dry_run:
            return f"{base_dir.rstrip('/')}/{prefix}dryrun{suffix}"

        if self.transport_name == "local":
            return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

        template = f"{base_dir.rstrip('/')}/{prefix}XXXXXX{suffix}"
        res = await self.run(["mktemp", "-d", template], raise_on_error=True)
        return res.text

    async def _remove_temp_dir(self, path: str) -> None:
        """Удалить временную директорию на хосте."""
        if self._dry_run or not path:
            return
        if self.transport_name == "local":
            shutil.rmtree(path, ignore_errors=True)
            return
        await self.run(["rm", "-rf", path])

    # ─── Выполнение команд (через CommandPipeline) ─────────────────

    async def run(
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
        """Выполнить команду на хосте через конвейер ``CommandPipeline``."""
        cmd_str = format_command(command)
        effective_dry_run = self._dry_run if dry_run is None else dry_run
        request = CommandRequest(
            raw_command=command,
            command=cmd_str,
            exec_command=cmd_str,
            timeout=timeout,
            raise_on_error=raise_on_error,
            input_data=input,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            sensitive=sensitive,
            dry_run=effective_dry_run,
            transport_kwargs=dict(kwargs),
        )
        return await self._pipeline.execute(request)

    async def run_bytes(
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
        """Выполнить команду и вернуть сырой байтовый вывод (``bytes``)."""
        cmd_str = format_command(command)
        self._context.apply_to_kwargs(kwargs)
        exec_cmd, effective_input = prepare_sudo_command(
            cmd_str,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            input_data=input,
            config_options=self._config.options,
            config_password=self._config.password,
        )
        if effective_input is not None:
            kwargs["input"] = effective_input

        if self._dry_run:
            return b""

        if not self._transport.is_connected:
            await self._transport.connect()

        effective_timeout = timeout or self._config.timeout
        return await self._transport.run_bytes(
            exec_cmd,
            timeout=effective_timeout,
            raise_on_error=raise_on_error,
            **kwargs,
        )

    async def run_commands(
        self,
        commands: Sequence[str | Sequence[str]],
        stop_on_error: bool = True,
        **kwargs: Any,
    ) -> list[Result]:
        """Последовательно выполнить список команд на хосте."""
        results: list[Result] = []
        for command in commands:
            result = await self.run(command, **kwargs)
            results.append(result)
            if stop_on_error and not result.ok:
                log_event(
                    self._logger,
                    logging.WARNING,
                    "command.batch_stopped",
                    f"run_commands: остановка на команде {command!r} "
                    f"(exit_code={result.exit_code})",
                    host=self._config.host,
                    command=format_command(command),
                    exit_code=result.exit_code,
                )
                break
        return results

    async def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое получение вывода команды."""
        cmd_str = format_command(command)
        self._context.apply_to_kwargs(kwargs)
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        async for line in self._transport.stream(cmd_str, timeout=timeout, **kwargs):
            yield line

    async def close(self) -> None:
        """Закрыть подключение."""
        await self._transport.disconnect()

    async def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения."""
        return await self._transport.ping(timeout=timeout)

    # ─── Файловые операции и шаблоны (делегация в conn.files) ──────

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на удалённый хост."""
        await self.files.upload(local_path, remote_path, recurse=recurse, **kwargs)

    async def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с удалённого хоста."""
        await self.files.download(remote_path, local_path, recurse=recurse, **kwargs)

    async def read_file(
        self,
        remote_path: str,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла с хоста напрямую в память."""
        return await self.files.read_file(remote_path, encoding=encoding)

    async def write_file(
        self,
        remote_path: str,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты из памяти в файл на хосте."""
        await self.files.write_file(
            remote_path, content, mode=mode, encoding=encoding
        )

    async def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование файла или директории на хосте."""
        return await self.files.exists(remote_path)

    async def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте."""
        await self.files.mkdir(
            remote_path, parents=parents, exist_ok=exist_ok, mode=mode
        )

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу на удалённом хосте."""
        await self.files.chmod(remote_path, mode)

    async def stat(self, remote_path: str) -> dict[str, Any]:
        """Получить информацию о файле на удалённом хосте."""
        return await self.files.stat(remote_path)

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список файлов в директории на удалённом хосте."""
        return await self.files.listdir(remote_path)

    async def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл на хосте."""
        await self.files.remove_file(remote_path)

    async def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон конфигурации и записать его на хост."""
        return await self.files.write_template(
            remote_path=remote_path,
            template_str_or_path=template_str_or_path,
            context=context,
            mode=mode,
            encoding=encoding,
            engine=engine,
        )

    async def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Инкрементально синхронизировать локальную директорию с удалённой."""
        return await self.files.sync_dir(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )

    # ─── Проброс портов (делегация в conn.tunnels) ─────────────────

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> Any:
        """Асинхронный контекстный менеджер прямого SSH-туннеля (Local Port Forwarding)."""
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
    ) -> Any:
        """Асинхронный контекстный менеджер обратного SSH-туннеля (Remote Port Forwarding)."""
        return self.tunnels.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        )

    # ─── Интерактивный Shell и Expect ──────────────────────────────

    async def expect(
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
        """Выполнить интерактивную команду с декларативным сопоставлением regex-паттернов."""
        cmd_str = format_command(command)
        if self._dry_run:
            self._logger.info(
                f"[DRY-RUN] Skipping expect {cmd_str!r} on {self._config.uri_safe}"
            )
            return Result(
                exit_code=0,
                stdout="",
                stderr="",
                duration=0.0,
                command=cmd_str,
                host=self._config.host,
                sensitive=sensitive,
            )

        session = await self.open_shell(
            term_type=term_type,
            term_size=term_size,
            init_posix=False,
            **kwargs,
        )
        try:
            return await session.expect(
                command=cmd_str,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
            )
        finally:
            await session.close()

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> ShellSession:
        """Открыть интерактивную stateful PTY shell-сессию."""
        if not self._transport.is_connected:
            await self._transport.connect()

        proc = await self._transport.open_shell(
            term_type=term_type,
            term_size=term_size,
            **kwargs,
        )
        session = ShellSession(
            proc=proc,
            host=self._config.host,
            default_timeout=self._config.timeout,
        )
        should_init_posix = (
            (self.transport_name != "serial") if init_posix is None else init_posix
        )
        if should_init_posix:
            await session.initialize()
        else:
            session._initialized = True
        return session

    # ─── Факты о системе и идемпотентные операции (conn.state) ─────

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты о целевом хосте за один батч-запрос."""
        return await self._facts_collector.gather(refresh=refresh, timeout=timeout)

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
        return await self.state.ensure_package(
            package=package,
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
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса (systemd / OpenRC / SysV)."""
        return await self.state.ensure_service(
            service=service,
            state=state,
            enabled=enabled,
            sudo=sudo,
            dry_run=dry_run,
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
        return await self.state.ensure_line(
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

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> SyncConnection:
        """Конвертировать в синхронную версию."""
        from ._sync import SyncConnection

        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        """Конфигурация подключения."""
        return self._config

    @property
    def transport_name(self) -> str:
        """Имя используемого транспорта."""
        return self._transport.name

    @property
    def dry_run(self) -> bool:
        """Включён ли режим dry_run для данного подключения."""
        return self._dry_run
