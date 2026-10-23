# src/uniconn/_connection.py
from __future__ import annotations

import builtins
import contextlib
import dataclasses
import fnmatch
import inspect
import json
import logging
import os
import re
import shlex
import shutil
import string
import tempfile
import time
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
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
from ._facts import FACT_COLLECTION_SCRIPT, HostFacts, parse_facts_output
from ._logging import log_context, log_event
from ._shell import ShellSession
from .exceptions import ConnectionError, TimeoutError, UniconnError
from .plugins._loader import TransportLoader
from .result import EnsureResult, Result, SyncResult
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


def render_template(
    template_str_or_path: str | Path,
    context: Mapping[str, Any] | None = None,
    engine: Literal["auto", "string", "jinja2"] = "auto",
) -> str:
    """Отрендерить конфигурационный шаблон со словарём переменных ``context``.

    Поддерживает два движка:
    - ``"string"`` — стандартный ``string.Template`` (переменные ``$var`` / ``${var}``)
    - ``"jinja2"`` — опциональный пакет ``jinja2`` (выражения ``{{ var }}``, ``{% if %}``)
    - ``"auto"`` — использует ``jinja2``, если передан файл ``.j2``/``.jinja``/``.jinja2``
      или в строке присутствуют теги ``{{`` / ``{%``, иначе ``string.Template``.

    Args:
        template_str_or_path: Путь к локальному файлу шаблона (``Path`` или строка-путь,
            если такой файл существует) либо непосредственно текст шаблона.
        context: Словарь подставляемых значений.
        engine: Выбранный шаблонизатор (``"auto"``, ``"string"``, ``"jinja2"``).

    Returns:
        Отрендеренная строка.

    """
    ctx = dict(context or {})
    is_jinja_ext = False

    if isinstance(template_str_or_path, Path):
        if not template_str_or_path.is_file():
            raise FileNotFoundError(f"Template file not found: {template_str_or_path}")
        raw_template = template_str_or_path.read_text(encoding="utf-8")
        is_jinja_ext = template_str_or_path.suffix.lower() in (".j2", ".jinja", ".jinja2")
    else:
        candidate = Path(template_str_or_path)
        try:
            is_existing_file = (
                "\n" not in template_str_or_path
                and len(template_str_or_path) < 4096
                and candidate.is_file()
            )
        except OSError:
            is_existing_file = False

        if is_existing_file:
            raw_template = candidate.read_text(encoding="utf-8")
            is_jinja_ext = candidate.suffix.lower() in (".j2", ".jinja", ".jinja2")
        else:
            raw_template = template_str_or_path

    chosen_engine = engine
    if chosen_engine == "auto":
        has_jinja = is_jinja_ext or "{{" in raw_template or "{%" in raw_template
        chosen_engine = "jinja2" if has_jinja else "string"

    if chosen_engine == "jinja2":
        try:
            import jinja2  # type: ignore[import-not-found]
        except ImportError as exc:
            if engine == "auto":
                return string.Template(raw_template).safe_substitute(ctx)
            raise UniconnError(
                "Jinja2 template engine requested, but 'jinja2' is not installed. "
                "Install it via 'pip install jinja2' or use engine='string'."
            ) from exc
        env = jinja2.Environment(
            autoescape=False,
            keep_trailing_newline=True,
            undefined=jinja2.StrictUndefined,
        )
        return env.from_string(raw_template).render(**ctx)

    if chosen_engine == "string":
        return string.Template(raw_template).safe_substitute(ctx)

    raise ValueError(f"Unsupported template engine: {engine!r}")



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
        self._cached_facts: HostFacts | None = None

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

    async def remove_file(
        self,
        remote_path: str | Path,
    ) -> None:
        """Удалить файл на хосте.

        Поддерживается для ``SSHTransport`` (SFTP) и ``LocalTransport``.
        Если активен контекст ``conn.cd()``, относительный путь разрешается
        относительно текущей директории.
        """
        if self._dry_run:
            self._logger.info(
                f"[DRY-RUN] Skipping remove_file {str(remote_path)!r} on {self._config.uri_safe}"
            )
            return

        if not self._transport.is_connected:
            await self._transport.connect()

        effective_path = str(remote_path)
        if self.current_cwd and not Path(effective_path).is_absolute():
            effective_path = str(Path(self.current_cwd) / effective_path)

        await self._transport.remove_file(effective_path)

    async def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон конфигурации и записать его на хост.

        Args:
            remote_path: Целевой путь файла на удалённом/локальном хосте.
            template_str_or_path: Строка шаблона или путь к локальному файлу шаблона.
            context: Словарь переменных для подстановки в шаблон.
            mode: Права доступа к создаваемому файлу (по умолчанию ``0o644``).
            encoding: Кодировка файла (по умолчанию ``"utf-8"``).
            engine: Шаблонизатор: ``"auto"``, ``"string"`` (``string.Template``)
                или ``"jinja2"``.

        Returns:
            Отрендеренное текстовое содержимое.

        """
        rendered = render_template(
            template_str_or_path=template_str_or_path,
            context=context,
            engine=engine,
        )
        await self.write_file(
            str(remote_path),
            rendered,
            mode=mode,
            encoding=encoding,
        )
        return rendered

    async def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Инкрементально синхронизировать локальную директорию с удалённой.

        Сравнивает размер (``size``) и время модификации (``mtime``) файлов
        через ``stat``/``listdir`` и передаёт только новые или изменившиеся файлы.

        Args:
            local_dir: Локальная директория-источник.
            remote_dir: Целевая директория на хосте.
            delete: Удалять ли на удалённом хосте файлы, отсутствующие локально.
            exclude: Список glob-паттернов для исключения (например, ``["*.pyc", ".git"]``).
            mtime_tolerance: Допустимая погрешность сравнения ``mtime`` в секундах.
            dry_run: Если ``True``, только вычислить список изменений без записи/удаления.

        Returns:
            Экземпляр ``SyncResult`` со списками ``uploaded``, ``skipped``, ``deleted``.

        """
        start_time = time.monotonic()
        is_dry = self._dry_run if dry_run is None else dry_run
        patterns = list(exclude or [])

        src_root = Path(local_dir)
        if not src_root.is_dir():
            raise FileNotFoundError(f"Local directory does not exist: {local_dir}")

        if not self._transport.is_connected and not is_dry:
            await self._transport.connect()

        effective_remote = str(remote_dir)
        if self.current_cwd and not Path(effective_remote).is_absolute():
            effective_remote = str(Path(self.current_cwd) / effective_remote)

        def _is_excluded(rel_posix: str, name: str) -> bool:
            for pat in patterns:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_posix, pat):
                    return True
                for part in rel_posix.split("/"):
                    if fnmatch.fnmatch(part, pat):
                        return True
            return False

        local_files: dict[str, tuple[Path, int, float]] = {}
        local_rel_dirs: set[str] = {""}

        for root, dirs, files in os.walk(src_root):
            rel_dir_path = Path(root).relative_to(src_root)
            rel_dir = "" if str(rel_dir_path) == "." else rel_dir_path.as_posix()

            # Фильтруем поддиректории in-place, чтобы не заходить в исключённые (.git и т.д.)
            kept_dirs: list[str] = []
            for d in dirs:
                d_rel = f"{rel_dir}/{d}" if rel_dir else d
                if not _is_excluded(d_rel, d):
                    kept_dirs.append(d)
                    local_rel_dirs.add(d_rel)
            dirs[:] = kept_dirs

            for fname in files:
                f_rel = f"{rel_dir}/{fname}" if rel_dir else fname
                if _is_excluded(f_rel, fname):
                    continue
                full_local = Path(root) / fname
                st = full_local.stat()
                local_files[f_rel] = (full_local, int(st.st_size), float(st.st_mtime))

        uploaded: list[str] = []
        skipped: list[str] = []
        deleted: list[str] = []
        bytes_transferred = 0

        if not is_dry:
            for rel_d in sorted(local_rel_dirs):
                target_d = f"{effective_remote.rstrip('/')}/{rel_d}" if rel_d else effective_remote
                await self._transport.mkdir(target_d, parents=True, exist_ok=True)

        for rel_path, (full_local, l_size, l_mtime) in sorted(local_files.items()):
            target_file = f"{effective_remote.rstrip('/')}/{rel_path}"
            needs_upload = True
            if not is_dry or self._transport.is_connected:
                with contextlib.suppress(Exception):
                    if await self._transport.exists(target_file):
                        r_stat = await self._transport.stat(target_file)
                        r_size = int(r_stat.get("size", -1))
                        r_mtime = float(r_stat.get("mtime") or 0.0)
                        if (
                            r_size == l_size
                            and r_mtime > 0
                            and (r_mtime + mtime_tolerance) >= l_mtime
                        ):
                            needs_upload = False

            if needs_upload:
                if not is_dry:
                    data = full_local.read_bytes()
                    mode = full_local.stat().st_mode & 0o777
                    await self._transport.write_file(target_file, data, mode=mode)
                uploaded.append(rel_path)
                bytes_transferred += l_size
            else:
                skipped.append(rel_path)

        if delete and (not is_dry or self._transport.is_connected):
            async def _walk_remote(rel_prefix: str) -> None:
                cur_remote = (
                    f"{effective_remote.rstrip('/')}/{rel_prefix}"
                    if rel_prefix
                    else effective_remote
                )
                try:
                    entries = await self._transport.listdir(cur_remote)
                except Exception:
                    return

                for entry in entries:
                    if entry in (".", ".."):
                        continue
                    entry_rel = f"{rel_prefix}/{entry}" if rel_prefix else entry
                    if _is_excluded(entry_rel, entry):
                        continue
                    entry_full = f"{effective_remote.rstrip('/')}/{entry_rel}"
                    try:
                        info = await self._transport.stat(entry_full)
                    except Exception:
                        continue
                    if info.get("is_dir"):
                        await _walk_remote(entry_rel)
                    elif entry_rel not in local_files:
                        if not is_dry:
                            await self._transport.remove_file(entry_full)
                        deleted.append(entry_rel)

            if await self._transport.exists(effective_remote):
                await _walk_remote("")

        duration = time.monotonic() - start_time
        return SyncResult(
            uploaded=uploaded,
            skipped=skipped,
            deleted=deleted,
            bytes_transferred=bytes_transferred,
            duration=duration,
            dry_run=is_dry,
        )

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Асинхронный контекстный менеджер прямого SSH-туннеля (Local Port Forwarding).

        Пробрасывает локальный порт ``local_host:local_port`` через SSH-соединение
        на ``remote_host:remote_port``. Если ``local_port=0``, ОС автоматически
        выделяет свободный порт, который возвращается в ``as bound_port``.

        Пример:
            >>> async with conn.forward_local_port("127.0.0.1", 5432) as port:
            ...     print(f"DB tunnel on 127.0.0.1:{port}")
        """
        if not self._transport.is_connected:
            await self._transport.connect()

        async with self._transport.forward_local_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port

    @contextlib.asynccontextmanager
    async def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AsyncIterator[int]:
        """Асинхронный контекстный менеджер обратного SSH-туннеля (Remote Port Forwarding).

        Открывает слушающий порт ``remote_host:remote_port`` на удалённом SSH-сервере
        и перенаправляет входящие соединения на локальный ``local_host:local_port``.

        Пример:
            >>> async with conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", 8000) as rport:
            ...     print(f"Remote server listening on port {rport}")
        """
        if not self._transport.is_connected:
            await self._transport.connect()

        async with self._transport.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port

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
        r"""Выполнить интерактивную команду с декларативным сопоставлением regex-паттернов.

        Открывает интерактивную сессию ``open_shell(init_posix=False)``, отправляет
        команду и автоматически отвечает на интерактивные запросы по словарю
        ``patterns`` (``{r"regex": "response\n"}``) до появления ``final_prompt``
        или закрытия потока (EOF). Работает поверх SSH, Telnet, Serial и Local.

        Args:
            command: Команда для запуска (строка или список аргументов).
            patterns: Словарь ``{regex_pattern: response}`` (поддерживает ``SecretStr``).
            final_prompt: Регулярное выражение финального приглашения для завершения.
            timeout: Общий таймаут ожидания в секундах.
            line_ending: Перевод строки при отправке ``command`` (по умолчанию ``"\n"``).
            sensitive: Скрывать ли вывод в ``Result`` и логах.
            term_type: Тип терминала PTY.
            term_size: Размер терминала PTY ``(cols, rows)``.
            **kwargs: Дополнительные параметры для ``open_shell()``.

        Returns:
            ``Result`` с собранным выводом интерактивного диалога.

        """
        cmd_str = _format_command(command)
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
        **kwargs,
    ) -> ShellSession:
        """Открыть интерактивную stateful PTY shell-сессию.

        Работает поверх текущего подключения (SSH, Telnet, Serial, Local;
        автоматически вызывает ``connect()``, если соединение ещё не установлено)
        и позволяет выполнять команды с сохранением состояния (``cd``, ``export``
        и т.д.) или интерактивные сценарии ``expect()``.

        Args:
            term_type: Тип терминала (по умолчанию "xterm")
            term_size: Размер терминала (cols, rows), по умолчанию (80, 24)
            init_posix: Отправлять ли инициализацию POSIX-оболочки (``PS1='', stty -echo``).
                По умолчанию ``True`` для SSH/Local/Telnet и ``False`` для Serial.
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
        should_init_posix = (
            (self.transport_name != "serial") if init_posix is None else init_posix
        )
        if should_init_posix:
            await session.initialize()
        else:
            session._initialized = True
        return session

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты о целевом хосте за один батч-запрос.

        Выполняет составной POSIX-скрипт за один вызов ``run()`` и возвращает
        типизированную модель ``HostFacts`` (ОС, ядро, CPU, память, диски, сеть).
        По умолчанию кэширует результат в экземпляре ``Connection`` до вызова
        с ``refresh=True``.

        Args:
            refresh: Принудительно обновить кэш фактов.
            timeout: Таймаут выполнения батч-скрипта в секундах.

        Returns:
            Экземпляр ``HostFacts``.

        """
        if not refresh and self._cached_facts is not None:
            return self._cached_facts

        default_host = self._config.host or "localhost"
        if self._dry_run:
            facts = HostFacts(hostname=default_host)
            self._cached_facts = facts
            return facts

        res = await self.run(
            FACT_COLLECTION_SCRIPT,
            timeout=timeout,
            raise_on_error=False,
        )
        facts = parse_facts_output(res.stdout, default_host=default_host)
        self._cached_facts = facts
        return facts

    async def _resolve_pkg_manager(
        self,
        manager: Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"],
    ) -> str:
        """Определить пакетный менеджер хоста при ``manager='auto'``."""
        if manager != "auto":
            return manager

        if self._cached_facts is not None:
            fam = self._cached_facts.os_family.lower()
            if fam == "debian":
                return "apt"
            if fam == "alpine":
                return "apk"
            if fam == "redhat":
                return "dnf"
            if fam == "arch":
                return "pacman"
            if fam == "suse":
                return "zypper"

        detect_cmd = (
            "if command -v apt-get >/dev/null 2>&1; then echo apt; "
            "elif command -v dnf >/dev/null 2>&1; then echo dnf; "
            "elif command -v apk >/dev/null 2>&1; then echo apk; "
            "elif command -v yum >/dev/null 2>&1; then echo yum; "
            "elif command -v pacman >/dev/null 2>&1; then echo pacman; "
            "elif command -v zypper >/dev/null 2>&1; then echo zypper; "
            "else echo apt; fi"
        )
        res = await self.run(detect_cmd, raise_on_error=False, dry_run=False)
        detected = res.text.splitlines()[0].strip() if res.text else "apt"
        return detected if detected in {"apt", "dnf", "yum", "apk", "pacman", "zypper"} else "apt"

    async def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"] = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте.

        Args:
            package: Имя пакета или список пакетов.
            state: Желаемое состояние (``"present"`` или ``"absent"``).
            manager: Пакетный менеджер (``"auto"``, ``"apt"``, ``"dnf"``, ``"yum"``,
                ``"apk"``, ``"pacman"``, ``"zypper"``).
            update_cache: Обновить ли индекс пакетов перед установкой.
            sudo: Использовать ли ``sudo`` при модифицирующих командах.
            dry_run: Проверить необходимость изменений без установки/удаления.

        Returns:
            ``EnsureResult`` с флагами ``changed``, ``ok`` и описанием ``details``.

        """
        pkgs = [package] if isinstance(package, str) else [str(p) for p in package]
        target_str = ", ".join(pkgs)
        is_dry_run = self._dry_run if dry_run is None else dry_run

        if self._dry_run:
            return EnsureResult(
                target=target_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure package(s) {target_str} are {state}",
                dry_run=True,
            )

        mgr = await self._resolve_pkg_manager(manager)
        to_modify: list[str] = []

        for pkg in pkgs:
            q_pkg = shlex.quote(pkg)
            if mgr == "apt":
                chk = f"dpkg-query -W -f='${{Status}}' {q_pkg} 2>/dev/null | grep -q 'install ok installed'"
            elif mgr == "apk":
                chk = f"apk info -e {q_pkg} >/dev/null 2>&1"
            elif mgr in ("dnf", "yum", "zypper"):
                chk = f"rpm -q {q_pkg} >/dev/null 2>&1"
            else:
                chk = f"pacman -Qi {q_pkg} >/dev/null 2>&1"

            chk_res = await self.run(chk, raise_on_error=False, dry_run=False)
            is_installed = chk_res.ok
            if (state == "present" and not is_installed) or (state == "absent" and is_installed):
                to_modify.append(pkg)

        if not to_modify:
            return EnsureResult(
                target=target_str,
                state=state,
                changed=False,
                ok=True,
                details=f"Package(s) {target_str} already {state} ({mgr})",
                dry_run=is_dry_run,
            )

        quoted_pkgs = " ".join(shlex.quote(p) for p in to_modify)
        if state == "present":
            if mgr == "apt":
                prefix = "DEBIAN_FRONTEND=noninteractive apt-get update -qq && " if update_cache else ""
                action_cmd = f"{prefix}DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {quoted_pkgs}"
            elif mgr == "apk":
                upd = "--update-cache " if update_cache else ""
                action_cmd = f"apk add --no-progress {upd}{quoted_pkgs}"
            elif mgr in ("dnf", "yum"):
                action_cmd = f"{mgr} install -y {quoted_pkgs}"
            elif mgr == "pacman":
                sync_flag = "-Syu" if update_cache else "-S"
                action_cmd = f"pacman {sync_flag} --noconfirm {quoted_pkgs}"
            else:
                action_cmd = f"zypper --non-interactive install {quoted_pkgs}"
        else:
            if mgr == "apt":
                action_cmd = f"DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq {quoted_pkgs}"
            elif mgr == "apk":
                action_cmd = f"apk del --no-progress {quoted_pkgs}"
            elif mgr in ("dnf", "yum"):
                action_cmd = f"{mgr} remove -y {quoted_pkgs}"
            elif mgr == "pacman":
                action_cmd = f"pacman -R --noconfirm {quoted_pkgs}"
            else:
                action_cmd = f"zypper --non-interactive remove {quoted_pkgs}"

        if is_dry_run:
            return EnsureResult(
                target=target_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would run: {action_cmd}",
                dry_run=True,
            )

        act_res = await self.run(action_cmd, sudo=sudo, raise_on_error=False)
        return EnsureResult(
            target=target_str,
            state=state,
            changed=act_res.ok,
            ok=act_res.ok,
            details=act_res.stderr.strip() if not act_res.ok else f"Modified {', '.join(to_modify)} via {mgr}",
            dry_run=False,
        )

    async def ensure_service(
        self,
        service: str,
        state: Literal["started", "stopped", "restarted", "reloaded"] = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса (systemd / OpenRC / SysV).

        Args:
            service: Имя сервиса (например, ``"nginx"``).
            state: Целевое состояние (``"started"``, ``"stopped"``, ``"restarted"``, ``"reloaded"``).
            enabled: Включить (``True``) или отключить (``False``) автозапуск.
            sudo: Использовать ли ``sudo`` для команд управления сервисом.
            dry_run: Проверить состояние без фактического перезапуска/остановки.

        Returns:
            ``EnsureResult`` с информацией о выполненных действиях.

        """
        is_dry_run = self._dry_run if dry_run is None else dry_run
        if self._dry_run:
            return EnsureResult(
                target=service,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure service {service} is {state}",
                dry_run=True,
            )

        q_svc = shlex.quote(service)
        status_cmd = (
            f"if command -v systemctl >/dev/null 2>&1; then systemctl is-active --quiet {q_svc}; "
            f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} status >/dev/null 2>&1; "
            f"else service {q_svc} status >/dev/null 2>&1; fi"
        )
        status_res = await self.run(status_cmd, raise_on_error=False, dry_run=False)
        is_active = status_res.ok

        actions_taken: list[str] = []
        commands_to_run: list[str] = []

        if state == "started" and not is_active:
            actions_taken.append("start")
            commands_to_run.append(
                f"if command -v systemctl >/dev/null 2>&1; then systemctl start {q_svc}; "
                f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} start; "
                f"else service {q_svc} start; fi"
            )
        elif state == "stopped" and is_active:
            actions_taken.append("stop")
            commands_to_run.append(
                f"if command -v systemctl >/dev/null 2>&1; then systemctl stop {q_svc}; "
                f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} stop; "
                f"else service {q_svc} stop; fi"
            )
        elif state == "restarted":
            actions_taken.append("restart")
            commands_to_run.append(
                f"if command -v systemctl >/dev/null 2>&1; then systemctl restart {q_svc}; "
                f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} restart; "
                f"else service {q_svc} restart; fi"
            )
        elif state == "reloaded":
            actions_taken.append("reload")
            commands_to_run.append(
                f"if command -v systemctl >/dev/null 2>&1; then systemctl reload {q_svc}; "
                f"elif command -v rc-service >/dev/null 2>&1; then rc-service {q_svc} reload; "
                f"else service {q_svc} reload; fi"
            )

        if enabled is not None:
            enabled_chk = await self.run(
                f"systemctl is-enabled --quiet {q_svc}",
                raise_on_error=False,
                dry_run=False,
            )
            is_enabled = enabled_chk.ok
            if enabled and not is_enabled:
                actions_taken.append("enable")
                commands_to_run.append(f"systemctl enable {q_svc}")
            elif not enabled and is_enabled:
                actions_taken.append("disable")
                commands_to_run.append(f"systemctl disable {q_svc}")

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
        act_res = await self.run(combined_cmd, sudo=sudo, raise_on_error=False)
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
        r"""Идемпотентно обеспечить наличие, замену или отсутствие строки в файле (аналог ``lineinfile``).

        Args:
            remote_path: Путь к целевому файлу на хосте.
            line: Целевая строка (без завершающего ``\n``).
            state: ``"present"`` (добавить/заменить) или ``"absent"`` (удалить).
            regex: Опциональное регулярное выражение для поиска заменяемой/удаляемой строки.
            create: Создавать ли файл, если он не существует (при ``state="present"``).
            backup: Создавать ли резервную копию ``<remote_path>.bak`` перед записью.
            mode: Права доступа к файлу при записи.
            encoding: Кодировка файла (по умолчанию ``"utf-8"``).
            dry_run: Проверить необходимость изменений без модификации файла.

        Returns:
            ``EnsureResult`` с флагами ``changed``, ``ok`` и описанием ``details``.

        """
        path_str = str(remote_path)
        clean_line = line.rstrip("\r\n")
        is_dry_run = self._dry_run if dry_run is None else dry_run

        if self._dry_run:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] Would ensure line in {path_str} is {state}",
                dry_run=True,
            )

        file_exists = await self.exists(path_str)
        original_text = ""
        existing_lines: list[str] = []

        if file_exists:
            raw_content = await self.read_file(path_str, encoding=encoding)
            original_text = raw_content if isinstance(raw_content, str) else raw_content.decode(encoding)
            existing_lines = original_text.splitlines()
        elif state == "absent":
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=True,
                details=f"File {path_str} does not exist (already absent)",
                dry_run=is_dry_run,
            )
        elif not create:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=False,
                details=f"File {path_str} does not exist and create=False",
                dry_run=is_dry_run,
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
                matches = bool(pattern.search(existing)) if pattern is not None else (existing == clean_line)
                if matches:
                    changed = True
                else:
                    new_lines.append(existing)
            details = f"Removed matching line(s) from {path_str}" if changed else f"Line already absent in {path_str}"

        if not changed:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=False,
                ok=True,
                details=details,
                dry_run=is_dry_run,
            )

        if is_dry_run:
            return EnsureResult(
                target=path_str,
                state=state,
                changed=True,
                ok=True,
                details=f"[DRY-RUN] {details}",
                dry_run=True,
            )

        if backup and file_exists:
            await self.write_file(f"{path_str}.bak", original_text, encoding=encoding)

        new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
        await self.write_file(path_str, new_content, mode=mode, encoding=encoding)
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=details,
            dry_run=False,
        )

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
