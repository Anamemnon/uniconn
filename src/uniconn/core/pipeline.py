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
import time
from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from ..exceptions import CircuitOpenError, ConnectionError, TimeoutError
from ..result import Result
from ._middlewares import (
    _ACTIVE_DIAGNOSTIC_PROBE as _ACTIVE_DIAGNOSTIC_PROBE,
)
from ._middlewares import (
    _SUDO_PWD_REQUIRED_HINTS as _SUDO_PWD_REQUIRED_HINTS,
)
from ._middlewares import (
    AfterRunHook,
    AutoDiagnosticMiddleware,
    BeforeRunHook,
    CircuitBreakerMiddleware,
    CommandMiddleware,
    CommandRequest,
    ContextMiddleware,
    DryRunMiddleware,
    HITLApprovalMiddleware,
    HookCallback,
    HookEvent,
    HookMiddleware,
    NextHandler,
    ObservabilityMiddleware,
    OnErrorHook,
    RateLimitMiddleware,
    RetryMiddleware,
    SudoMiddleware,
    format_command,
    prepare_sudo_command,
)
from .resilience import CircuitBreaker, RateLimiter

if TYPE_CHECKING:
    from .connection import Connection


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
                    AutoDiagnosticMiddleware(self._conn),
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
        """Добавить пользовательский Middleware в конец конвейера."""
        self._middlewares.append(middleware)

    def insert_middleware(self, index: int, middleware: CommandMiddleware) -> None:
        """Вставить Middleware в указанную позицию конвейера."""
        self._middlewares.insert(index, middleware)

    async def _terminal_dispatch(self, request: CommandRequest) -> Result:
        """Финальное звено пайплайна — вызов ``transport.run()`` или ``transport.run_bytes()``."""
        assert self._conn is not None
        if request.output_format == "bytes":
            t0 = time.monotonic()
            raw = await self._conn.transport.run_bytes(
                request.exec_command,
                timeout=request.timeout,
                raise_on_error=request.raise_on_error,
                **request.transport_kwargs,
            )
            return Result(
                exit_code=0,
                stdout=raw.decode("utf-8", errors="replace"),
                stderr="",
                duration=time.monotonic() - t0,
                command=request.command,
                host=self._conn.config.host,
                sensitive=request.sensitive,
                raw_bytes=raw,
            )
        return await self._conn.transport.run(
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

        result = await handler(request)
        if request.parse is not None and request.parse is not False and isinstance(result, Result):
            if result.parse_spec is None:
                result = dataclasses.replace(
                    result,
                    parse_spec=request.parse,
                    _dry_run=request.dry_run,
                )
            if request.eager_parse and not request.dry_run:
                _ = result.parsed
        return result

    async def _invoke_on_error(self, exc: BaseException, command: str) -> None:
        """Вызвать зарегистрированные хуки ``on_error`` для потокового/пайплайн-сбоя."""
        if self._conn is None:
            return
        for cb in self._conn.get_hooks("on_error"):
            res = cb(exc, command, self._conn.config.host)
            if inspect.isawaitable(res):
                await res

    async def prepare_stream_request(self, request: CommandRequest) -> bool:
        """Прогнать ``CommandRequest`` для ``stream()`` через охранные и контекстные Middleware.

        Возвращает ``True``, если поток должен быть запущен на транспорте,
        или ``False``, если выполнение пропущено в режиме ``dry_run=True``.
        """
        request.metadata["is_stream"] = True
        reached_terminal = False

        async def _stream_gate(req: CommandRequest) -> Result:
            nonlocal reached_terminal
            reached_terminal = True
            return Result(
                exit_code=0,
                stdout="",
                stderr="",
                duration=0.0,
                command=req.command,
                host=self._conn.config.host if self._conn is not None else None,
                sensitive=req.sensitive,
            )

        skip_types = (
            ObservabilityMiddleware,
            AutoDiagnosticMiddleware,
            RetryMiddleware,
        )
        handler: NextHandler = _stream_gate
        for mw in reversed(self._middlewares):
            if isinstance(mw, skip_types) or type(mw).__name__ == "TracingMiddleware":
                continue
            prev_handler = handler
            if isinstance(mw, CircuitBreakerMiddleware):

                async def _cb_check_step(
                    req: CommandRequest,
                    current_mw: CircuitBreakerMiddleware = mw,
                    nxt: NextHandler = prev_handler,
                ) -> Result:
                    cb_inst = current_mw._conn.circuit_breaker
                    if isinstance(cb_inst, CircuitBreaker):
                        cb_inst.check_or_raise(
                            host=current_mw._conn.config.host,
                            command="***REDACTED***" if req.sensitive else req.command,
                        )
                    return await nxt(req)

                handler = _cb_check_step
            else:

                async def _step(
                    req: CommandRequest,
                    current_mw: CommandMiddleware = mw,
                    nxt: NextHandler = prev_handler,
                ) -> Result:
                    return await current_mw(req, nxt)

                handler = _step

        try:
            await handler(request)
        except CircuitOpenError as exc:
            await self._invoke_on_error(exc, request.command)
            raise
        return reached_terminal and not request.dry_run

    async def _stream_from_transport(
        self,
        stream_cmd: Any,
        *,
        timeout: float | None,
        sensitive: bool,
        cmd_label: str,
        transport_kwargs: dict[str, Any],
    ) -> AsyncIterator[str]:
        """Открыть поток транспорта, маскируя секреты и корректно фиксируя успех/сбой в CircuitBreaker."""
        assert self._conn is not None
        from .._logging import SecretMaskingFilter

        raw_cb = self._conn.circuit_breaker
        cb = raw_cb if isinstance(raw_cb, CircuitBreaker) else None
        completed_normally = False
        try:
            if not self._conn.transport.is_connected:
                await self._conn.transport.connect()
            async for line in self._conn.transport.stream(
                stream_cmd,
                timeout=timeout,
                **transport_kwargs,
            ):
                if sensitive:
                    yield "***REDACTED***"
                else:
                    yield SecretMaskingFilter._mask_string(line)
            completed_normally = True
        except Exception as exc:
            if (
                cb is not None
                and isinstance(exc, (ConnectionError, TimeoutError, builtins.TimeoutError))
                and not isinstance(exc, CircuitOpenError)
            ):
                cb.record_failure()
            await self._invoke_on_error(exc, cmd_label)
            raise
        finally:
            if completed_normally and cb is not None:
                cb.record_success()

    async def execute_stream(
        self,
        command: str | Sequence[str] | None = None,
        timeout: float | None = None,
        *,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        sensitive: bool = False,
        dry_run: bool | None = None,
        approval_id: str | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Подготовить и запустить потоковое чтение ``stream()`` через ``CommandPipeline``."""
        assert self._conn is not None
        effective_dry = self._conn.dry_run if dry_run is None else dry_run
        if command is None:
            if effective_dry:
                return
            self._conn.context.apply_to_kwargs(kwargs)
            raw_cb = self._conn.circuit_breaker
            if isinstance(raw_cb, CircuitBreaker):
                try:
                    raw_cb.check_or_raise(
                        host=self._conn.config.host,
                        command="<stream>",
                    )
                except CircuitOpenError as exc:
                    await self._invoke_on_error(exc, "<stream>")
                    raise
            raw_rl = self._conn.rate_limiter
            if isinstance(raw_rl, RateLimiter):
                await raw_rl.acquire()
            async for line in self._stream_from_transport(
                None,
                timeout=timeout if timeout is not None else self._conn.config.timeout,
                sensitive=sensitive,
                cmd_label="<stream>",
                transport_kwargs=kwargs,
            ):
                yield line
            return

        cmd_str = format_command(command)
        req = CommandRequest(
            raw_command=command,
            command=cmd_str,
            exec_command=cmd_str,
            timeout=timeout,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            sensitive=sensitive,
            dry_run=effective_dry,
            approval_id=approval_id,
            transport_kwargs=dict(kwargs),
        )
        should_stream = await self.prepare_stream_request(req)
        if not should_stream:
            return

        stream_cmd: Any = (
            command
            if (not req.sudo and req.exec_command == req.command)
            else req.exec_command
        )
        async for line in self._stream_from_transport(
            stream_cmd,
            timeout=req.timeout if req.timeout is not None else self._conn.config.timeout,
            sensitive=req.sensitive,
            cmd_label=req.command,
            transport_kwargs=req.transport_kwargs,
        ):
            yield line


__all__ = [
    "AfterRunHook",
    "AutoDiagnosticMiddleware",
    "BeforeRunHook",
    "CircuitBreakerMiddleware",
    "CommandMiddleware",
    "CommandPipeline",
    "CommandRequest",
    "ContextMiddleware",
    "DryRunMiddleware",
    "HITLApprovalMiddleware",
    "HookCallback",
    "HookEvent",
    "HookMiddleware",
    "NextHandler",
    "ObservabilityMiddleware",
    "OnErrorHook",
    "RateLimitMiddleware",
    "RetryMiddleware",
    "SudoMiddleware",
    "format_command",
    "prepare_sudo_command",
]
