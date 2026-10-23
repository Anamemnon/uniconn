# src/uniconn/_connection.py
from __future__ import annotations

import builtins
import dataclasses
import inspect
import json
import logging
import shlex
import shutil
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from ._config import ConnectionConfig
from ._logging import log_context, log_event
from ._shell import ShellSession
from .exceptions import ConnectionError, TimeoutError
from .plugins._loader import TransportLoader
from .result import Result
from .transports._base import BaseTransport

if TYPE_CHECKING:
    from ._sync import SyncConnection

logger = logging.getLogger(__name__)

HookEvent = Literal["before_run", "after_run", "on_error"]
HookCallback = Callable[..., Any]


def _format_command(command: str | Sequence[str]) -> str:
    """Преобразовать команду (строку или список аргументов) в shell-строку."""
    if isinstance(command, str):
        return command
    return shlex.join(command)


class _CwdContext:
    """Универсальный (sync + async) контекстный менеджер смены рабочей директории."""

    def __init__(self, stack: list[str], new_cwd: str) -> None:
        self._stack = stack
        self._new_cwd = new_cwd

    def __enter__(self) -> None:
        if self._stack and not Path(self._new_cwd).is_absolute():
            resolved = str(Path(self._stack[-1]) / self._new_cwd)
        else:
            resolved = self._new_cwd
        self._stack.append(resolved)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._stack:
            self._stack.pop()

    async def __aenter__(self) -> None:
        self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


class _EnvContext:
    """Универсальный (sync + async) контекстный менеджер переменных окружения."""

    def __init__(self, stack: list[dict[str, str]], env_vars: dict[str, str]) -> None:
        self._stack = stack
        self._env_vars = env_vars

    def __enter__(self) -> None:
        self._stack.append(self._env_vars)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._stack:
            self._stack.pop()

    async def __aenter__(self) -> None:
        self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


class _TempDirContext:
    """Асинхронный контекстный менеджер временной директории на хосте."""

    def __init__(
        self,
        conn: Connection,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> None:
        self._conn = conn
        self._prefix = prefix
        self._suffix = suffix
        self._dir = str(dir) if dir is not None else None
        self._path: str | None = None

    async def __aenter__(self) -> str:
        self._path = await self._conn._create_temp_dir(
            prefix=self._prefix,
            suffix=self._suffix,
            dir=self._dir,
        )
        return self._path

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._path:
            await self._conn._remove_temp_dir(self._path)
            self._path = None


def _parse_inventory_data(
    raw_data: Any,
    host: str | None = None,
    group: str | None = None,
) -> list[dict[str, Any]]:
    """Нормализовать данные инвентаря (список или словарь с hosts/groups/defaults)."""
    entries: list[dict[str, Any]] = []
    group_map: dict[str, list[str]] = {}

    if isinstance(raw_data, list):
        for item in raw_data:
            if isinstance(item, str):
                entries.append({"uri": item})
            elif isinstance(item, dict):
                entries.append(dict(item))
    elif isinstance(raw_data, dict):
        if "hosts" in raw_data and isinstance(raw_data["hosts"], (dict, list)):
            defaults = (
                dict(raw_data.get("defaults", {}))
                if isinstance(raw_data.get("defaults"), dict)
                else {}
            )
            raw_groups = raw_data.get("groups")
            if isinstance(raw_groups, dict):
                for g_name, g_members in raw_groups.items():
                    if isinstance(g_members, list):
                        group_map[str(g_name)] = [str(m) for m in g_members]

            hosts_sec = raw_data["hosts"]
            if isinstance(hosts_sec, dict):
                for alias, h_val in hosts_sec.items():
                    if isinstance(h_val, str):
                        merged = {**defaults, "name": str(alias), "uri": h_val}
                    elif isinstance(h_val, dict):
                        merged = {**defaults, **h_val}
                        merged.setdefault("name", str(alias))
                        merged.setdefault("host", str(alias))
                    else:
                        continue
                    entries.append(merged)
            elif isinstance(hosts_sec, list):
                for item in hosts_sec:
                    if isinstance(item, str):
                        entries.append({**defaults, "uri": item})
                    elif isinstance(item, dict):
                        entries.append({**defaults, **item})
        elif "transport" in raw_data or "uri" in raw_data:
            entries.append(dict(raw_data))
        else:
            for alias, h_val in raw_data.items():
                if isinstance(h_val, str):
                    entries.append({"name": str(alias), "uri": h_val})
                elif isinstance(h_val, dict):
                    merged = dict(h_val)
                    merged.setdefault("name", str(alias))
                    merged.setdefault("host", str(alias))
                    entries.append(merged)

    if group is not None:
        explicit_members = set(group_map.get(group, []))
        filtered_by_group: list[dict[str, Any]] = []
        for entry in entries:
            entry_groups = entry.get("groups") or []
            if isinstance(entry_groups, str):
                entry_groups = [entry_groups]
            entry_name = entry.get("name") or entry.get("host")
            if group in entry_groups or (entry_name and str(entry_name) in explicit_members):
                filtered_by_group.append(entry)
        if not filtered_by_group:
            raise KeyError(f"Group {group!r} not found in inventory")
        entries = filtered_by_group

    if host is not None:
        filtered_by_host = [
            entry
            for entry in entries
            if entry.get("name") == host or entry.get("host") == host
        ]
        if not filtered_by_host:
            raise KeyError(f"Host {host!r} not found in inventory")
        entries = filtered_by_host

    return entries


class Connection:
    """Основной класс для работы с удалёнными хостами.

    Пример использования:
        async with Connection.from_uri("ssh://user@host") as conn:
            result = await conn.run("uptime")
            print(result.stdout)
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
    ):
        self._transport = transport
        self._config = config
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._dry_run = dry_run
        self._cwd_stack: list[str] = []
        self._env_stack: list[dict[str, str]] = []
        self._hooks: dict[HookEvent, list[HookCallback]] = {
            "before_run": list(before_run or []),
            "after_run": list(after_run or []),
            "on_error": list(on_error or []),
        }

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
        data: dict,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
    ) -> Self:
        """Создать подключение из словаря."""
        retry = data.get("retry_attempts", retry_attempts)
        effective_dry_run = bool(data.get("dry_run", dry_run))
        if "uri" in data and "transport" not in data:
            return cls.from_uri(
                str(data["uri"]),
                retry_attempts=retry,
                logger=logger,
                dry_run=effective_dry_run,
            )
        config = ConnectionConfig(**{
            k: v for k, v in data.items()
            if k not in ("retry_attempts", "logger", "dry_run", "name", "groups")
        })
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
        filepath = Path(path)
        content = filepath.read_text(encoding="utf-8")

        if filepath.suffix in (".yaml", ".yml"):
            try:
                import yaml
                raw_data = yaml.safe_load(content)
            except ImportError:
                raise ImportError(
                    "PyYAML not installed. "
                    "Run: pip install pyyaml"
                ) from None
        elif filepath.suffix == ".json":
            raw_data = json.loads(content)
        else:
            raise ValueError(
                f"Unsupported file format: {filepath.suffix}. "
                "Use .json, .yaml or .yml"
            )

        entries = _parse_inventory_data(raw_data, host=host, group=group)
        return [
            cls.from_dict(data, retry_attempts, logger)
            for data in entries
        ]

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
        options: dict | None = None,
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
                SecretStr(password) if isinstance(password, str)
                else password if password is not None
                else self._config.password
            ),
            key_file=key_file if key_file is not None else self._config.key_file,
            passphrase=(
                SecretStr(passphrase) if isinstance(passphrase, str)
                else passphrase if passphrase is not None
                else self._config.passphrase
            ),
            ssh_config=ssh_config if ssh_config is not None else self._config.ssh_config,
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

    def with_overrides(self, **overrides) -> Self:
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

    # ─── Контекстные менеджеры cd / env и Hooks (v0.4.0) ───────────

    def cd(self, path: str | Path) -> _CwdContext:
        """Контекстный менеджер для временной смены рабочей директории.

        Поддерживает как ``async with conn.cd(...)``, так и ``with conn.cd(...)``,
        а также вложенные вызовы с относительными путями.

        Пример:
            >>> async with conn.cd("/var"):
            ...     async with conn.cd("log"):
            ...         res = await conn.run("pwd")  # /var/log

        """
        return _CwdContext(self._cwd_stack, str(path))

    def env(self, mapping: dict[str, str] | None = None, **env_vars: str) -> _EnvContext:
        """Контекстный менеджер для временной установки переменных окружения.

        Поддерживает ``async with conn.env(FOO="1")`` и ``with conn.env({"FOO": "1"})``.

        Пример:
            >>> async with conn.env(APP_ENV="prod", DEBUG="0"):
            ...     await conn.run("env")

        """
        merged: dict[str, str] = {}
        if mapping:
            merged.update({str(k): str(v) for k, v in mapping.items()})
        if env_vars:
            merged.update({str(k): str(v) for k, v in env_vars.items()})
        return _EnvContext(self._env_stack, merged)

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека ``conn.cd()``."""
        return self._cwd_stack[-1] if self._cwd_stack else None

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения из стека ``conn.env()``."""
        merged: dict[str, str] = {}
        for frame in self._env_stack:
            merged.update(frame)
        return merged

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``).

        Поддерживает как синхронные, так и асинхронные функции обратного вызова.

        Args:
            event: Событие (``"before_run"``, ``"after_run"`` или ``"on_error"``)
            callback: Функция-обработчик

        Returns:
            Self (для цепочки вызовов)

        """
        if event not in self._hooks:
            raise ValueError(
                f"Unknown hook event: {event!r}. "
                "Expected 'before_run', 'after_run', or 'on_error'"
            )
        self._hooks[event].append(callback)
        return self

    async def _invoke_hooks(self, event: HookEvent, *args: Any) -> None:
        """Вызвать зарегистрированные хуки для указанного события."""
        for cb in self._hooks.get(event, ()):
            res = cb(*args)
            if inspect.isawaitable(res):
                await res

    def _apply_context_kwargs(self, kwargs: dict[str, Any]) -> None:
        """Применить активные контексты ``cd()`` и ``env()`` к аргументам вызова."""
        active_cwd = self.current_cwd
        if active_cwd is not None:
            explicit_cwd = kwargs.get("cwd")
            if explicit_cwd is None:
                kwargs["cwd"] = active_cwd
            elif not Path(str(explicit_cwd)).is_absolute():
                kwargs["cwd"] = str(Path(active_cwd) / str(explicit_cwd))

        active_env = self.current_env
        if active_env:
            explicit_env = kwargs.get("env")
            if explicit_env:
                kwargs["env"] = {**active_env, **explicit_env}
            else:
                kwargs["env"] = active_env

    def _prepare_sudo(
        self,
        cmd_str: str,
        sudo: bool,
        sudo_user: str | None,
        sudo_password: str | SecretStr | None,
        input_data: str | bytes | None,
    ) -> tuple[str, str | bytes | None]:
        """Обернуть команду в ``sudo`` и подготовить безопасную передачу пароля через stdin."""
        if not sudo:
            return cmd_str, input_data

        raw_pwd: Any = sudo_password
        if raw_pwd is None:
            raw_pwd = self._config.options.get("sudo_password")
        if raw_pwd is None and self._config.password is not None:
            raw_pwd = self._config.password

        pwd_str: str | None = None
        if isinstance(raw_pwd, SecretStr):
            pwd_str = raw_pwd.get_secret_value()
        elif raw_pwd is not None:
            pwd_str = str(raw_pwd)

        user_flag = f"-u {shlex.quote(sudo_user)} " if sudo_user else ""
        quoted_cmd = shlex.quote(cmd_str)

        if pwd_str:
            sudo_cmd = f"sudo -S -p '' {user_flag}-- sh -c {quoted_cmd}"
            if input_data is None:
                new_input: str | bytes | None = f"{pwd_str}\n"
            elif isinstance(input_data, bytes):
                new_input = f"{pwd_str}\n".encode() + input_data
            else:
                new_input = f"{pwd_str}\n{input_data}"
            return sudo_cmd, new_input

        sudo_cmd = f"sudo -n {user_flag}-- sh -c {quoted_cmd}"
        return sudo_cmd, input_data

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
        **kwargs
    ) -> Result:
        """Выполнить команду на удалённом хосте.

        Автоматически повторяет попытку при ConnectionError/TimeoutError
        с экспоненциальным backoff (до retry_attempts раз).
        Retry срабатывает как на ``uniconn.exceptions.TimeoutError``,
        так и на встроенный ``TimeoutError`` (например, из SSH-транспорта).
        Перед каждой следующей попыткой выполняется переподключение
        (disconnect + connect), т.к. соединение могло умереть.

        Args:
            command: Команда (строка или последовательность аргументов для ``shlex.join``)
            timeout: Таймаут в секундах
            raise_on_error: Raise ExecutionError если exit_code != 0
            input: Данные для передачи в stdin процесса (``str`` или ``bytes``)
            sudo: Выполнить команду с повышением привилегий через ``sudo``
            sudo_user: Целевой пользователь для ``sudo -u <user>``
            sudo_password: Пароль для ``sudo`` (передаётся через закрытый stdin)
            sensitive: Скрыть вывод команды в логах, ``repr(Result)`` и ``ExecutionError``
            dry_run: Не выполнять команду реально (переопределяет ``conn.dry_run``)
            **kwargs: Дополнительные аргументы для транспорта (например, ``cwd``, ``env``)

        Returns:
            Result объект с stdout, stderr, exit_code

        Raises:
            ConnectionError: При ошибке подключения после всех retry попыток
            TimeoutError: При таймауте после всех retry попыток

        """
        cmd_str = _format_command(command)
        self._apply_context_kwargs(kwargs)

        exec_cmd, effective_input = self._prepare_sudo(
            cmd_str,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            input_data=input,
        )
        if effective_input is not None:
            kwargs["input"] = effective_input

        effective_dry_run = self._dry_run if dry_run is None else dry_run
        log_cmd = "***SENSITIVE***" if sensitive else repr(cmd_str)

        await self._invoke_hooks("before_run", cmd_str, self._config.host, kwargs)

        with log_context(
            host=self._config.host,
            transport=self.transport_name,
            uri=self._config.uri_safe,
        ):
            if effective_dry_run:
                log_event(
                    self._logger,
                    logging.INFO,
                    "command.dry_run",
                    f"[DRY-RUN] Skipping command: {log_cmd} on {self._config.uri_safe}",
                    command="***REDACTED***" if sensitive else cmd_str,
                    dry_run=True,
                    sensitive=sensitive,
                )
                dry_result = Result(
                    exit_code=0,
                    stdout="",
                    stderr="",
                    duration=0.0,
                    command=cmd_str,
                    host=self._config.host,
                    sensitive=sensitive,
                )
                await self._invoke_hooks("after_run", dry_result)
                return dry_result

            try:
                if not self._transport.is_connected:
                    await self._transport.connect()

                timeout = timeout or self._config.timeout
                log_event(
                    self._logger,
                    logging.DEBUG,
                    "command.start",
                    f"Running command: {log_cmd} on {self._config.uri_safe}",
                    command="***REDACTED***" if sensitive else cmd_str,
                    sudo=sudo,
                    timeout=timeout,
                    sensitive=sensitive,
                )

                result: Result | None = None
                async for attempt in AsyncRetrying(
                    stop=stop_after_attempt(self._retry_attempts),
                    wait=wait_exponential_jitter(initial=1, max=10),
                    retry=retry_if_exception_type(
                        (ConnectionError, TimeoutError, builtins.TimeoutError)
                    ),
                    reraise=True,
                ):
                    with attempt:
                        try:
                            result = await self._transport.run(
                                exec_cmd, timeout=timeout, **kwargs
                            )
                        except (
                            ConnectionError,
                            TimeoutError,
                            builtins.TimeoutError,
                        ) as retry_exc:
                            attempt_num = attempt.retry_state.attempt_number
                            log_event(
                                self._logger,
                                logging.WARNING,
                                "command.retry",
                                f"Retry attempt {attempt_num}/{self._retry_attempts} "
                                f"for {log_cmd} on {self._config.uri_safe}",
                                command="***REDACTED***" if sensitive else cmd_str,
                                attempt=attempt_num,
                                max_attempts=self._retry_attempts,
                                error_type=type(retry_exc).__name__,
                                error=str(retry_exc),
                                sensitive=sensitive,
                            )
                            await self._transport.disconnect()
                            await self._transport.connect()
                            raise

                assert result is not None
                if isinstance(result, Result) and (
                    sensitive or result.command != cmd_str
                ):
                    result = dataclasses.replace(
                        result,
                        command=cmd_str,
                        sensitive=sensitive,
                    )

                if isinstance(result, Result):
                    log_event(
                        self._logger,
                        logging.DEBUG,
                        "command.finish",
                        f"Finished command: {log_cmd} on {self._config.uri_safe} "
                        f"(exit_code={result.exit_code})",
                        command="***REDACTED***" if sensitive else cmd_str,
                        exit_code=result.exit_code,
                        ok=result.ok,
                        duration_ms=round(result.duration * 1000, 3),
                        sensitive=sensitive,
                    )

                if raise_on_error:
                    result.raise_for_status()

            except BaseException as exc:
                log_event(
                    self._logger,
                    logging.DEBUG,
                    "command.error",
                    f"Command error: {log_cmd} on {self._config.uri_safe} "
                    f"({type(exc).__name__})",
                    command="***REDACTED***" if sensitive else cmd_str,
                    error_type=type(exc).__name__,
                    error="***REDACTED***" if sensitive else str(exc),
                    sensitive=sensitive,
                )
                await self._invoke_hooks("on_error", exc, cmd_str, self._config.host)
                raise

            await self._invoke_hooks("after_run", result)
            return result

    async def run_bytes(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        **kwargs,
    ) -> bytes:
        """Выполнить команду и вернуть сырой байтовый вывод (``bytes``).

        Поддерживает ``Sequence[str]``, контексты ``cd()``/``env()``, ``sudo`` и ``input``.

        Args:
            command: Команда (строка или список аргументов)
            timeout: Таймаут в секундах
            raise_on_error: Выбросить ``ExecutionError`` при ненулевом коде возврата
            input: Данные для передачи в stdin
            sudo: Выполнить команду через ``sudo``
            sudo_user: Пользователь для ``sudo -u``
            sudo_password: Пароль для ``sudo``
            **kwargs: Дополнительные аргументы транспорта

        Returns:
            Сырые байты из ``stdout``

        """
        cmd_str = _format_command(command)
        self._apply_context_kwargs(kwargs)
        exec_cmd, effective_input = self._prepare_sudo(
            cmd_str,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            input_data=input,
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
        **kwargs
    ) -> list[Result]:
        """Последовательно выполнить список команд на удалённом хосте.

        Args:
            commands: Список команд (строк или списков аргументов) для выполнения
            stop_on_error: Прервать выполнение при первой команде
                с ненулевым exit_code (по умолчанию True)
            **kwargs: Дополнительные аргументы для ``run()``
                (timeout, raise_on_error, sudo, sensitive и т.д.)

        Returns:
            Список Result в порядке выполнения команд.
            При ``stop_on_error=True`` и ошибке — только результаты
            до первой неудачной команды включительно.

        Пример:
            >>> results = await conn.run_commands(["uptime", "df -h", "free -m"])
            >>> for r in results:
            ...     print(r.command, r.exit_code)

        """
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
                    command=_format_command(command),
                    exit_code=result.exit_code,
                )
                break
        return results

    async def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs
    ):
        """Потоковое получение вывода команды."""
        cmd_str = _format_command(command)
        self._apply_context_kwargs(kwargs)
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        async for line in self._transport.stream(cmd_str, timeout=timeout, **kwargs):
            yield line

    async def close(self) -> None:
        """Закрыть подключение."""
        await self._transport.disconnect()

    async def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения.

        Делегирует проверку транспорту через ``ping()``.
        Для SSH — выполняет ``true`` через `asyncssh.run()`.
        Для IPMI — ``get_power`` команда.
        Для Local — всегда True (если подключён).

        Args:
            timeout: Таймаут проверки в секундах

        Returns:
            True если подключение живо и отвечает

        Пример:
            >>> async with Connection.from_uri("ssh://user@host") as conn:
            ...     if await conn.is_alive():
            ...         print("Host is alive")
            ...     else:
            ...         print("Host is unreachable")

        """
        return await self._transport.ping(timeout=timeout)

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs
    ) -> None:
        """Загрузить файл или директорию на удалённый хост.

        Работает только для SSH транспорта (SFTP).
        Автоматически определяет рекурсию если local_path — директория.

        Args:
            local_path: Путь к локальному файлу или директории
            remote_path: Путь на удалённом хосте
            recurse: Принудительная рекурсивная загрузка
            **kwargs: Дополнительные аргументы для транспорта

        Пример:
            >>> await conn.upload("/local/file.txt", "/remote/file.txt")
            >>> await conn.upload("/local/dir", "/remote/dir", recurse=True)

        """
        await self._transport.upload(
            local_path, remote_path, recurse=recurse, **kwargs
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs
    ) -> None:
        """Скачать файл или директорию с удалённого хоста.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь на удалённом хосте
            local_path: Путь для сохранения локально
            recurse: Рекурсивная загрузка директории
            **kwargs: Дополнительные аргументы для транспорта

        Пример:
            >>> await conn.download("/remote/file.txt", "/local/file.txt")
            >>> await conn.download("/remote/dir", "/local/dir", recurse=True)

        """
        await self._transport.download(
            remote_path, local_path, recurse=recurse, **kwargs
        )

    async def read_file(
        self,
        remote_path: str,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла с хоста напрямую в память.

        Поддерживается для ``SSHTransport`` (через SFTP) и ``LocalTransport``.
        Если активен контекст ``conn.cd()``, относительный ``remote_path``
        разрешается относительно текущей директории.

        Args:
            remote_path: Путь к файлу на хосте
            encoding: Кодировка для возврата ``str`` (по умолчанию ``"utf-8"``).
                Если передать ``encoding=None``, вернёт сырые ``bytes``.

        Returns:
            Содержимое файла (``str`` или ``bytes``)

        """
        if not self._transport.is_connected:
            await self._transport.connect()

        effective_path = remote_path
        if self.current_cwd and not Path(remote_path).is_absolute():
            effective_path = str(Path(self.current_cwd) / remote_path)

        raw = await self._transport.read_file(effective_path)
        if encoding is None:
            return raw
        return raw.decode(encoding)

    async def write_file(
        self,
        remote_path: str,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты из памяти в файл на хосте.

        Поддерживается для ``SSHTransport`` (через SFTP) и ``LocalTransport``.
        Если активен контекст ``conn.cd()``, относительный ``remote_path``
        разрешается относительно текущей директории.

        Args:
            remote_path: Путь к создаваемому/перезаписываемому файлу
            content: Содержимое (``str`` или ``bytes``)
            mode: Опциональные права доступа (например, ``0o600`` или ``0o755``)
            encoding: Кодировка при передаче ``str`` (по умолчанию ``"utf-8"``)

        """
        if self._dry_run:
            self._logger.info(
                f"[DRY-RUN] Skipping write_file to {remote_path!r} on {self._config.uri_safe}"
            )
            return

        if not self._transport.is_connected:
            await self._transport.connect()

        effective_path = remote_path
        if self.current_cwd and not Path(remote_path).is_absolute():
            effective_path = str(Path(self.current_cwd) / remote_path)

        data = content.encode(encoding) if isinstance(content, str) else bytes(content)
        await self._transport.write_file(effective_path, data, mode=mode)

    async def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование файла или директории на хосте.

        Если активен контекст ``conn.cd()``, относительный путь разрешается
        относительно текущей рабочей директории.
        """
        if not self._transport.is_connected:
            await self._transport.connect()

        effective_path = str(remote_path)
        if self.current_cwd and not Path(effective_path).is_absolute():
            effective_path = str(Path(self.current_cwd) / effective_path)

        return await self._transport.exists(effective_path)

    async def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте.

        Если активен контекст ``conn.cd()``, относительный путь разрешается
        относительно текущей рабочей директории.
        """
        if self._dry_run:
            self._logger.info(
                f"[DRY-RUN] Skipping mkdir {str(remote_path)!r} on {self._config.uri_safe}"
            )
            return

        if not self._transport.is_connected:
            await self._transport.connect()

        effective_path = str(remote_path)
        if self.current_cwd and not Path(effective_path).is_absolute():
            effective_path = str(Path(self.current_cwd) / effective_path)

        await self._transport.mkdir(
            effective_path,
            parents=parents,
            exist_ok=exist_ok,
            mode=mode,
        )

    def temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> _TempDirContext:
        r"""Асинхронный контекстный менеджер временной директории на хосте.

        Создаёт уникальную временную директорию при входе в блок ``async with``
        и автоматически удаляет её вместе со всем содержимым при выходе.

        Пример:
            >>> async with conn.temp_dir(prefix="build_") as tmp:
            ...     await conn.write_file(f"{tmp}/script.sh", "#!/bin/sh\necho ok")
            ...     res = await conn.run(["sh", f"{tmp}/script.sh"])
        """
        return _TempDirContext(self, prefix=prefix, suffix=suffix, dir=dir)

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

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к файлу на удалённом хосте
            mode: Права доступа (например, ``0o755``, ``0o644``)

        Пример:
            >>> await conn.chmod("/var/www/app.py", 0o755)

        """
        await self._transport.chmod(remote_path, mode)

    async def stat(
        self,
        remote_path: str,
    ) -> dict:
        """Получить информацию о файле на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к файлу на удалённом хосте

        Returns:
            Словарь: size, uid, gid, permissions, atime, mtime,
            is_file, is_dir, is_symlink

        Пример:
            >>> info = await conn.stat("/var/log/syslog")
            >>> print(info["size"], info["permissions"])

        """
        return await self._transport.stat(remote_path)

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов в директории на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к директории (по умолчанию ".")

        Returns:
            Список имён файлов и директорий

        Пример:
            >>> files = await conn.listdir("/var/log")
            >>> print(files)

        """
        return await self._transport.listdir(remote_path)

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs,
    ) -> ShellSession:
        """Открыть интерактивную stateful PTY shell-сессию.

        Работает поверх текущего SSH-подключения (автоматически вызывает
        ``connect()``, если соединение ещё не установлено) и позволяет
        выполнять команды с сохранением состояния (``cd``, ``export`` и т.д.),
        не разрывая соединение и параллельно с обычными вызовами ``run()``.

        Args:
            term_type: Тип терминала (по умолчанию "xterm")
            term_size: Размер терминала (cols, rows), по умолчанию (80, 24)
            **kwargs: Дополнительные параметры для транспорта

        Returns:
            Инициализированный экземпляр ``ShellSession``

        Raises:
            NotImplementedError: Если транспорт не поддерживает PTY shell

        Пример:
            >>> async with Connection.from_uri("ssh://user@host") as conn:
            ...     async with await conn.open_shell() as shell:
            ...         await shell.execute("cd /var/log")
            ...         res = await shell.execute("pwd")
            ...         print(res.stdout)  # /var/log

        """
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
        await session.initialize()
        return session

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> SyncConnection:
        """Конвертировать в синхронную версию."""
        from ._sync import SyncConnection
        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        return self._config

    @property
    def transport_name(self) -> str:
        return self._transport.name

    @property
    def dry_run(self) -> bool:
        """Включён ли режим dry_run для данного подключения."""
        return self._dry_run
