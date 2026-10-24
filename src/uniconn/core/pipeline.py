# src/uniconn/core/pipeline.py
"""Конвейер выполнения команд (Middleware Pipeline / Chain of Responsibility).

Разделяет сквозную функциональность (контекст cwd/env, sudo-эскалация,
lifecycle-хуки, маскирование секретов, dry-run, логирование и retry)
на изолированные переиспользуемые шаги.
"""

from __future__ import annotations

import builtins
import dataclasses
import inspect
import logging
import shlex
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from .._logging import log_context, log_event
from ..exceptions import CircuitOpenError, ConnectionError, TimeoutError
from ..result import Result
from .resilience import CircuitBreaker, RateLimiter

if TYPE_CHECKING:
    from .._connection import Connection

HookEvent = Literal["before_run", "after_run", "on_error"]
HookCallback = Callable[..., Any]


def format_command(command: str | Sequence[str]) -> str:
    """Преобразовать команду (строку или список аргументов) в shell-строку."""
    if isinstance(command, str):
        return command
    return shlex.join(command)


def prepare_sudo_command(
    cmd_str: str,
    sudo: bool,
    sudo_user: str | None,
    sudo_password: str | SecretStr | None,
    input_data: str | bytes | None,
    *,
    config_options: dict[str, Any] | None = None,
    config_password: SecretStr | None = None,
) -> tuple[str, str | bytes | None]:
    """Обернуть команду в ``sudo`` и подготовить безопасную передачу пароля через stdin."""
    if not sudo:
        return cmd_str, input_data

    raw_pwd: Any = sudo_password
    if raw_pwd is None and config_options is not None:
        raw_pwd = config_options.get("sudo_password")
    if raw_pwd is None and config_password is not None:
        raw_pwd = config_password

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


@dataclass(slots=True)
class CommandRequest:
    """Контекст запроса на выполнение команды, проходящий через конвейер Middleware."""

    raw_command: str | Sequence[str]
    command: str
    exec_command: str
    timeout: float | None = None
    raise_on_error: bool = False
    input_data: str | bytes | None = None
    sudo: bool = False
    sudo_user: str | None = None
    sudo_password: str | SecretStr | None = None
    sensitive: bool = False
    dry_run: bool = False
    transport_kwargs: dict[str, Any] = field(default_factory=dict)


NextHandler = Callable[[CommandRequest], Awaitable[Result]]


class CommandMiddleware(Protocol):
    """Протокол промежуточного обработчика (Middleware) в пайплайне выполнения команд."""

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Обработать запрос и передать управление следующему звену."""
        ...


class ContextMiddleware:
    """Применяет активные контексты ``cd()`` и ``env()`` к аргументам транспорта."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать ContextMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Применить контекст рабочей директории и окружения перед передачей запроса."""
        self._conn._context.apply_to_kwargs(request.transport_kwargs)
        return await call_next(request)


class SudoMiddleware:
    """Оборачивает команду в ``sudo -S/-n`` и инжектирует пароль в ``stdin``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать SudoMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """При необходимости обернуть команду в ``sudo``."""
        exec_cmd, effective_input = prepare_sudo_command(
            request.command,
            sudo=request.sudo,
            sudo_user=request.sudo_user,
            sudo_password=request.sudo_password,
            input_data=request.input_data,
            config_options=self._conn._config.options,
            config_password=self._conn._config.password,
        )
        request.exec_command = exec_cmd
        if effective_input is not None:
            request.transport_kwargs["input"] = effective_input
        return await call_next(request)


class HookMiddleware:
    """Управляет вызовом пользовательских хуков ``before_run``, ``after_run`` и ``on_error``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать HookMiddleware."""
        self._conn = conn

    async def invoke(self, event: HookEvent, *args: Any) -> None:
        """Вызвать зарегистрированные хуки для указанного события."""
        for cb in self._conn._hooks.get(event, ()):
            res = cb(*args)
            if inspect.isawaitable(res):
                await res

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Вызвать ``before_run`` до выполнения и ``after_run`` после выполнения."""
        await self.invoke(
            "before_run",
            request.command,
            self._conn._config.host,
            request.transport_kwargs,
        )
        result = await call_next(request)
        await self.invoke("after_run", result)
        return result


class DryRunMiddleware:
    """Короткое замыкание выполнения при активном режиме ``dry_run``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать DryRunMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Вернуть синтетический успешный ``Result`` без запуска транспорта при ``dry_run``."""
        if not request.dry_run:
            return await call_next(request)

        log_cmd = "***SENSITIVE***" if request.sensitive else repr(request.command)
        with log_context(
            host=self._conn._config.host,
            transport=self._conn.transport_name,
            uri=self._conn._config.uri_safe,
        ):
            log_event(
                self._conn._logger,
                logging.INFO,
                "command.dry_run",
                f"[DRY-RUN] Skipping command: {log_cmd} on {self._conn._config.uri_safe}",
                command="***REDACTED***" if request.sensitive else request.command,
                dry_run=True,
                sensitive=request.sensitive,
            )
            return Result(
                exit_code=0,
                stdout="",
                stderr="",
                duration=0.0,
                command=request.command,
                host=self._conn._config.host,
                sensitive=request.sensitive,
            )


class ObservabilityMiddleware:
    """Отвечает за структурированное логирование ``start``/``finish``/``error``, ``raise_on_error`` и ``on_error``."""

    def __init__(self, conn: Connection, hook_middleware: HookMiddleware) -> None:
        """Инициализировать ObservabilityMiddleware."""
        self._conn = conn
        self._hooks = hook_middleware

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Залогировать выполнение команды, обработать ошибки и ``raise_on_error``."""
        log_cmd = "***SENSITIVE***" if request.sensitive else repr(request.command)
        with log_context(
            host=self._conn._config.host,
            transport=self._conn.transport_name,
            uri=self._conn._config.uri_safe,
        ):
            try:
                request.timeout = request.timeout or self._conn._config.timeout
                log_event(
                    self._conn._logger,
                    logging.DEBUG,
                    "command.start",
                    f"Running command: {log_cmd} on {self._conn._config.uri_safe}",
                    command="***REDACTED***" if request.sensitive else request.command,
                    sudo=request.sudo,
                    timeout=request.timeout,
                    sensitive=request.sensitive,
                )

                result = await call_next(request)

                if isinstance(result, Result) and (
                    request.sensitive or result.command != request.command
                ):
                    result = dataclasses.replace(
                        result,
                        command=request.command,
                        sensitive=request.sensitive,
                    )

                if isinstance(result, Result):
                    log_event(
                        self._conn._logger,
                        logging.DEBUG,
                        "command.finish",
                        f"Finished command: {log_cmd} on {self._conn._config.uri_safe} "
                        f"(exit_code={result.exit_code})",
                        command="***REDACTED***" if request.sensitive else request.command,
                        exit_code=result.exit_code,
                        ok=result.ok,
                        duration_ms=round(result.duration * 1000, 3),
                        sensitive=request.sensitive,
                    )

                if request.raise_on_error:
                    result.raise_for_status()

                return result

            except BaseException as exc:
                log_event(
                    self._conn._logger,
                    logging.DEBUG,
                    "command.error",
                    f"Command error: {log_cmd} on {self._conn._config.uri_safe} "
                    f"({type(exc).__name__})",
                    command="***REDACTED***" if request.sensitive else request.command,
                    error_type=type(exc).__name__,
                    error="***REDACTED***" if request.sensitive else str(exc),
                    sensitive=request.sensitive,
                )
                await self._hooks.invoke(
                    "on_error",
                    exc,
                    request.command,
                    self._conn._config.host,
                )
                raise


class CircuitBreakerMiddleware:
    """Контролирует состояние ``CircuitBreaker`` до обращения к транспорту и фиксирует сбои."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать CircuitBreakerMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Проверить состояние цепи и обновить статистику успеха/сбоя."""
        cb = getattr(self._conn, "_circuit_breaker", None)
        if not isinstance(cb, CircuitBreaker):
            return await call_next(request)

        cb.check_or_raise(
            host=self._conn._config.host,
            command="***REDACTED***" if request.sensitive else request.command,
        )
        try:
            result = await call_next(request)
        except (
            ConnectionError,
            TimeoutError,
            builtins.TimeoutError,
        ) as exc:
            if not isinstance(exc, CircuitOpenError):
                cb.record_failure()
            raise
        else:
            cb.record_success()
            return result


class RateLimitMiddleware:
    """Ограничивает частоту запуска команд через ``RateLimiter`` (Token Bucket)."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать RateLimitMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Дождаться токена ``RateLimiter`` перед передачей запроса в транспорт."""
        rl = getattr(self._conn, "_rate_limiter", None)
        if isinstance(rl, RateLimiter):
            await rl.acquire()
        return await call_next(request)


class RetryMiddleware:
    """Выполняет повторные попытки (Exponential Backoff + Jitter) с переподключением транспорта."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать RetryMiddleware для указанного подключения."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Выполнить запрос с экспоненциальными повторными попытками при сбоях сети."""
        import sys

        conn_mod = sys.modules.get("uniconn._connection")
        wait_fn = getattr(conn_mod, "wait_exponential_jitter", wait_exponential_jitter)

        log_cmd = "***SENSITIVE***" if request.sensitive else repr(request.command)
        result: Result | None = None

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._conn._retry_attempts),
            wait=wait_fn(initial=1, max=10),
            retry=retry_if_exception_type(
                (ConnectionError, TimeoutError, builtins.TimeoutError)
            ),
            reraise=True,
        ):
            with attempt:
                try:
                    if not self._conn._transport.is_connected:
                        await self._conn._transport.connect()
                    result = await call_next(request)
                except (
                    ConnectionError,
                    TimeoutError,
                    builtins.TimeoutError,
                ) as retry_exc:
                    attempt_num = attempt.retry_state.attempt_number
                    log_event(
                        self._conn._logger,
                        logging.WARNING,
                        "command.retry",
                        f"Retry attempt {attempt_num}/{self._conn._retry_attempts} "
                        f"for {log_cmd} on {self._conn._config.uri_safe}",
                        command="***REDACTED***" if request.sensitive else request.command,
                        attempt=attempt_num,
                        max_attempts=self._conn._retry_attempts,
                        error_type=type(retry_exc).__name__,
                        error=str(retry_exc),
                        sensitive=request.sensitive,
                    )
                    await self._conn._transport.disconnect()
                    await self._conn._transport.connect()
                    raise

        assert result is not None
        return result


class CommandPipeline:
    """Конвейер выполнения команд с поддержкой цепочки Middleware."""

    def __init__(
        self,
        conn_or_middlewares: Connection | Sequence[CommandMiddleware] | None = None,
        middlewares: Sequence[CommandMiddleware] | None = None,
    ) -> None:
        """Инициализировать конвейер с набором Middleware."""
        if isinstance(conn_or_middlewares, Sequence):
            self._conn: Connection | None = None
            self._middlewares: list[CommandMiddleware] = list(conn_or_middlewares)
        else:
            self._conn = conn_or_middlewares
            if middlewares is not None:
                self._middlewares = list(middlewares)
            elif self._conn is not None:
                hook_mw = HookMiddleware(self._conn)
                self._middlewares = [
                    ContextMiddleware(self._conn),
                    SudoMiddleware(self._conn),
                    hook_mw,
                    DryRunMiddleware(self._conn),
                    ObservabilityMiddleware(self._conn, hook_mw),
                    CircuitBreakerMiddleware(self._conn),
                    RateLimitMiddleware(self._conn),
                    RetryMiddleware(self._conn),
                ]
            else:
                self._middlewares = []

    @property
    def middlewares(self) -> list[CommandMiddleware]:
        """Вернуть копию списка зарегистрированных Middleware в конвейере."""
        return list(self._middlewares)

    def add_middleware(self, middleware: CommandMiddleware) -> None:
        """Добавить пользовательский Middleware в конвейер."""
        self._middlewares.append(middleware)

    async def _terminal_dispatch(self, request: CommandRequest) -> Result:
        """Финальное звено пайплайна — вызов ``transport.run()``."""
        assert self._conn is not None
        return await self._conn._transport.run(
            request.exec_command,
            timeout=request.timeout,
            **request.transport_kwargs,
        )

    async def execute(
        self,
        request: CommandRequest,
        terminal_handler: NextHandler | None = None,
    ) -> Result:
        """Прогнать ``CommandRequest`` через цепочку Middleware и вернуть ``Result``."""
        handler: NextHandler = terminal_handler or self._terminal_dispatch
        for mw in reversed(self._middlewares):
            prev_handler = handler

            async def _step(
                req: CommandRequest,
                current_mw: CommandMiddleware = mw,
                nxt: NextHandler = prev_handler,
            ) -> Result:
                return await current_mw(req, nxt)

            handler = _step

        return await handler(request)

