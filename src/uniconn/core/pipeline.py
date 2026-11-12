# src/uniconn/core/pipeline.py
"""Конвейер выполнения команд (Middleware Pipeline / Chain of Responsibility).

Разделяет сквозную функциональность (контекст cwd/env, sudo-эскалация,
lifecycle-хуки, маскирование секретов, dry-run, логирование и retry)
на изолированные переиспользуемые шаги.
"""

from __future__ import annotations

import asyncio
import builtins
import dataclasses
import inspect
import logging
import shlex
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextvars import ContextVar
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
from ..result import DiagnosticSummary, Result
from .auto_diagnostics import (
    DiagnosticStrategy,
    PassiveDiagnosticStrategy,
    resolve_diagnostic_strategy,
)
from .resilience import CircuitBreaker, RateLimiter

if TYPE_CHECKING:
    from .connection import Connection

_ACTIVE_DIAGNOSTIC_PROBE: ContextVar[bool] = ContextVar(
    "_active_diagnostic_probe", default=False
)

HookEvent = Literal["before_run", "after_run", "on_error"]
BeforeRunHook = Callable[..., Awaitable[None] | None]
AfterRunHook = Callable[[Result], Awaitable[None] | None]
OnErrorHook = Callable[..., Awaitable[None] | None]
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
        sudo_cmd = f"sudo -S -k -p '' {user_flag}-- sh -c {quoted_cmd}"
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
    output_format: Literal["text", "bytes"] = "text"
    parse: Any = None
    eager_parse: bool = False
    diagnose: bool | None = None
    approval_id: str | None = None
    transport_kwargs: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


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
        self._conn.context.apply_to_kwargs(request.transport_kwargs)
        return await call_next(request)


class HITLApprovalMiddleware:
    """Промежуточный слой двухфазного согласования Human-in-the-Loop (HITL) для CommandPipeline."""

    def __init__(
        self,
        conn: Connection,
        *,
        policy: Any = None,
        manager: Any = None,
        is_production: bool = False,
    ) -> None:
        """Инициализировать HITLApprovalMiddleware."""
        self._conn = conn
        self._policy = policy
        self._manager = manager
        self._is_production = is_production

    @property
    def policy(self) -> Any:
        """Активная политика HITLPolicy (или None)."""
        return self._policy if self._policy is not None else getattr(self._conn, "_hitl_policy", None)

    @policy.setter
    def policy(self, value: Any) -> None:
        self._policy = value

    @property
    def manager(self) -> Any:
        """Активный экземпляр ApprovalManager."""
        if self._manager is not None:
            return self._manager
        conn_mgr = getattr(self._conn, "_approval_manager", None)
        if conn_mgr is not None:
            return conn_mgr
        pol = self.policy
        if pol is not None:
            from ..mcp.hitl import ApprovalManager

            self._manager = ApprovalManager(policy=pol)
            return self._manager
        return None

    def attach(self, conn: Connection | None = None) -> HITLApprovalMiddleware:
        """Встроить HITLApprovalMiddleware в конвейер ``Connection.pipeline`` (после ContextMiddleware)."""
        target = conn or self._conn
        self._conn = target
        if not any(isinstance(m, HITLApprovalMiddleware) for m in target.pipeline.middlewares):
            insert_idx = min(1, len(target.pipeline.middlewares))
            target.pipeline.insert_middleware(insert_idx, self)
        return self

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Проверить классификацию риска команды и двухфазное подтверждение до выполнения."""
        pol = self.policy
        if pol is None or not getattr(pol, "enabled", False) or request.dry_run or _ACTIVE_DIAGNOSTIC_PROBE.get():
            return await call_next(request)

        from ..exceptions import (
            ApprovalExpiredError,
            ApprovalRejectedError,
            ApprovalRequiredError,
        )
        from ..mcp.hitl import ActionRiskClassifier
        from ..mcp.models import ActionRiskTier, ApprovalStatus

        is_prod = self._is_production or bool(self._conn.config.options.get("is_production", False))
        assessment = ActionRiskClassifier.classify_command(
            request.command,
            sudo=request.sudo,
            is_production=is_prod,
            policy=pol,
        )
        host = self._conn.config.host or self._conn.transport_name
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"Command {request.command!r} on host {host!r} is forbidden by HITL policy "
                f"({'; '.join(assessment.reasons)})"
            )

        appr_id = request.approval_id or request.transport_kwargs.pop("approval_id", None)
        mgr = self.manager
        cwd = self._conn.current_cwd
        hmac_params = {"command": request.command, "sudo": request.sudo, "cwd": cwd or ""}
        if appr_id is not None and mgr is not None:
            await mgr.verify_and_consume(
                str(appr_id),
                target_host=host,
                tool_name="conn.run",
                command=request.command,
                sudo=request.sudo,
                cwd=cwd,
                parameters=hmac_params,
            )
            return await call_next(request)

        if assessment.requires_approval and mgr is not None:
            req = await mgr.create_request(
                target_host=host,
                tool_name="conn.run",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                command=request.command,
                sudo=request.sudo,
                cwd=cwd,
                parameters=hmac_params,
            )
            if getattr(pol, "wait_for_approval", False):
                decided = await mgr.wait_for_decision(
                    req.approval_id,
                    timeout=getattr(pol, "wait_timeout_seconds", 30.0),
                )
                if decided.status == ApprovalStatus.APPROVED:
                    await mgr.verify_and_consume(
                        req.approval_id,
                        target_host=host,
                        tool_name="conn.run",
                        command=request.command,
                        sudo=request.sudo,
                        cwd=cwd,
                        parameters=hmac_params,
                    )
                    return await call_next(request)
                if decided.status == ApprovalStatus.REJECTED:
                    raise ApprovalRejectedError(
                        f"Command {request.command!r} on {host!r} was rejected by operator "
                        f"({decided.decided_by or 'operator'}): {decided.decision_reason or 'Rejected'}",
                        approval_id=decided.approval_id,
                        decided_by=decided.decided_by,
                        decision_reason=decided.decision_reason,
                        approval_request=decided,
                        command=request.command,
                        host=host,
                    )
                if decided.status == ApprovalStatus.EXPIRED:
                    raise ApprovalExpiredError(
                        f"Approval request {decided.approval_id!r} for {request.command!r} expired",
                        approval_id=decided.approval_id,
                        approval_request=decided,
                        command=request.command,
                        host=host,
                    )
            raise ApprovalRequiredError(
                f"Command {request.command!r} on {host!r} requires human operator approval "
                f"(approval_id={req.approval_id!r}, tier={req.risk_tier.value})",
                approval_id=req.approval_id,
                approval_request=req,
                command=request.command,
                host=host,
            )

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
            config_options=self._conn.config.options,
            config_password=self._conn.config.password,
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
        for cb in self._conn.get_hooks(event):
            res = cb(*args)
            if inspect.isawaitable(res):
                await res

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Вызвать ``before_run`` до выполнения и ``after_run`` после выполнения."""
        await self.invoke(
            "before_run",
            request.command,
            self._conn.config.host,
            request.transport_kwargs,
        )
        result = await call_next(request)
        if not request.metadata.get("is_stream"):
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
            host=self._conn.config.host,
            transport=self._conn.transport_name,
            uri=self._conn.config.uri_safe,
        ):
            log_event(
                self._conn.logger,
                logging.INFO,
                "command.dry_run",
                f"[DRY-RUN] Skipping command: {log_cmd} on {self._conn.config.uri_safe}",
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
                host=self._conn.config.host,
                sensitive=request.sensitive,
                parse_spec=request.parse if request.parse is not False else None,
                _dry_run=True,
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
            host=self._conn.config.host,
            transport=self._conn.transport_name,
            uri=self._conn.config.uri_safe,
        ):
            try:
                request.timeout = request.timeout or self._conn.config.timeout
                log_event(
                    self._conn.logger,
                    logging.DEBUG,
                    "command.start",
                    f"Running command: {log_cmd} on {self._conn.config.uri_safe}",
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
                        self._conn.logger,
                        logging.DEBUG,
                        "command.finish",
                        f"Finished command: {log_cmd} on {self._conn.config.uri_safe} "
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
                    self._conn.logger,
                    logging.DEBUG,
                    "command.error",
                    f"Command error: {log_cmd} on {self._conn.config.uri_safe} "
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
                    self._conn.config.host,
                )
                raise


class AutoDiagnosticMiddleware:
    """Атомарно собирает диагностический контекст (Self-Healing) при сбоях команд."""

    def __init__(
        self,
        conn: Connection,
        *,
        enabled: bool | None = None,
        timeout_budget: float = 2.0,
        max_log_lines: int = 25,
        strategy: DiagnosticStrategy | None = None,
    ) -> None:
        """Инициализировать AutoDiagnosticMiddleware."""
        self._conn = conn
        self._enabled = enabled
        self._timeout_budget = timeout_budget
        self._max_log_lines = max_log_lines
        self._strategy = strategy

    @property
    def enabled(self) -> bool | None:
        """Явный флаг активности middleware (если ``None`` — наследуется от ``conn.auto_diagnostics``)."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool | None) -> None:
        self._enabled = value

    @property
    def timeout_budget(self) -> float:
        """Максимальный бюджет времени (в секундах) на сбор диагностики."""
        return self._timeout_budget

    @timeout_budget.setter
    def timeout_budget(self, value: float) -> None:
        self._timeout_budget = max(0.05, float(value))

    @property
    def max_log_lines(self) -> int:
        """Максимальное число строк релевантных логов в отчёте."""
        return self._max_log_lines

    @property
    def _is_probing(self) -> bool:
        """Флаг активного зондирования в текущей асинхронной задаче (защита от рекурсии)."""
        return _ACTIVE_DIAGNOSTIC_PROBE.get()

    def _known_secrets(self, request: CommandRequest) -> list[str]:
        """Собрать известные секретные строки соединения и запроса для гарантированного редактирования."""
        secrets: list[str] = []
        cfg = self._conn.config
        for val in (
            request.sudo_password,
            cfg.password,
            cfg.passphrase,
            cfg.options.get("sudo_password"),
        ):
            if isinstance(val, SecretStr):
                raw = val.get_secret_value()
                if raw:
                    secrets.append(raw)
            elif isinstance(val, str) and val:
                secrets.append(val)
        return secrets

    def _scrub_summary_secrets(
        self,
        summary: DiagnosticSummary,
        request: CommandRequest,
    ) -> DiagnosticSummary:
        """Удалить возможные вхождения сырых паролей соединения из диагностического отчёта."""
        secrets = self._known_secrets(request)
        if not secrets:
            return summary

        import re as _re

        def _scrub(text: str) -> str:
            res = text
            for secret in secrets:
                if not secret or secret not in res:
                    continue
                if len(secret) >= 4:
                    res = res.replace(secret, "***REDACTED***")
                else:
                    res = _re.sub(
                        rf"(?<=[=:\s'\"]){_re.escape(secret)}(?=$|[\s'\"&;])",
                        "***REDACTED***",
                        res,
                    )
            return res

        return dataclasses.replace(
            summary,
            root_cause_hint=_scrub(summary.root_cause_hint),
            relevant_logs=[_scrub(line) for line in summary.relevant_logs],
            dmesg_tail=[_scrub(line) for line in summary.dmesg_tail],
            suggested_actions=[_scrub(act) for act in summary.suggested_actions],
        )

    async def _collect_diagnostics(
        self,
        request: CommandRequest,
        result: Result,
    ) -> DiagnosticSummary:
        """Собрать диагностический контекст через изолированные зонды с контролем тайм-бюджета."""
        strategy = self._strategy or resolve_diagnostic_strategy(self._conn)
        t0 = time.monotonic()
        deadline = t0 + self._timeout_budget

        async def _run_probe(probe_cmd: str) -> Result:
            remaining = deadline - time.monotonic()
            if remaining <= 0.02:
                raise builtins.TimeoutError("Diagnostic timeout budget exhausted")

            exec_cmd, effective_input = prepare_sudo_command(
                probe_cmd,
                sudo=request.sudo,
                sudo_user=request.sudo_user,
                sudo_password=request.sudo_password,
                input_data=None,
                config_options=self._conn.config.options,
                config_password=self._conn.config.password,
            )
            probe_kwargs: dict[str, Any] = {}
            if effective_input is not None:
                probe_kwargs["input"] = effective_input

            try:
                return await asyncio.wait_for(
                    self._conn.transport.run(
                        exec_cmd,
                        timeout=remaining,
                        **probe_kwargs,
                    ),
                    timeout=remaining,
                )
            except builtins.TimeoutError:
                raise
            except Exception as exc:
                log_event(
                    self._conn.logger,
                    logging.DEBUG,
                    "diagnostic.probe_failed",
                    f"Diagnostic probe failed: {exc}",
                    probe_command=probe_cmd,
                    error=str(exc),
                )
                return Result(
                    exit_code=1,
                    stdout="",
                    stderr="",
                    duration=0.0,
                    command=probe_cmd,
                    host=self._conn.config.host,
                )

        try:
            summary = await asyncio.wait_for(
                strategy.collect(
                    request.command,
                    result.stdout,
                    result.stderr,
                    result.exit_code,
                    _run_probe,
                    max_log_lines=self._max_log_lines,
                ),
                timeout=self._timeout_budget,
            )
        except builtins.TimeoutError:
            fallback = await PassiveDiagnosticStrategy().collect(
                request.command,
                result.stdout,
                result.stderr,
                result.exit_code,
                _run_probe,
                max_log_lines=self._max_log_lines,
            )
            summary = dataclasses.replace(
                fallback,
                collection_duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
            )
        return self._scrub_summary_secrets(summary, request)

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Запустить сбор диагностики при ``result.exit_code != 0`` и активном ``diagnose``."""
        result = await call_next(request)

        if (
            not isinstance(result, Result)
            or result.ok
            or request.sensitive
            or request.dry_run
            or request.output_format == "bytes"
            or _ACTIVE_DIAGNOSTIC_PROBE.get()
        ):
            return result

        effective_diagnose = (
            request.diagnose
            if request.diagnose is not None
            else (
                self._enabled
                if self._enabled is not None
                else getattr(self._conn, "auto_diagnostics", False)
            )
        )
        if not effective_diagnose:
            return result

        token = _ACTIVE_DIAGNOSTIC_PROBE.set(True)
        try:
            diagnostic = await self._collect_diagnostics(request, result)
            return dataclasses.replace(result, diagnostic=diagnostic)
        except Exception as exc:
            log_event(
                self._conn.logger,
                logging.DEBUG,
                "diagnostic.error",
                f"AutoDiagnosticMiddleware error: {exc}",
                error=str(exc),
            )
            return result
        finally:
            _ACTIVE_DIAGNOSTIC_PROBE.reset(token)


class CircuitBreakerMiddleware:
    """Контролирует состояние ``CircuitBreaker`` до обращения к транспорту и фиксирует сбои."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать CircuitBreakerMiddleware."""
        self._conn = conn

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Проверить состояние цепи и обновить статистику успеха/сбоя."""
        cb = self._conn.circuit_breaker
        if not isinstance(cb, CircuitBreaker):
            return await call_next(request)

        cb.check_or_raise(
            host=self._conn.config.host,
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
        rl = self._conn.rate_limiter
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
        conn_mod = sys.modules.get("uniconn.core.connection")
        wait_fn = getattr(conn_mod, "wait_exponential_jitter", wait_exponential_jitter)

        log_cmd = "***SENSITIVE***" if request.sensitive else repr(request.command)
        result: Result | None = None
        max_attempts = self._conn.retry_attempts

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_fn(initial=1, max=10),
            retry=retry_if_exception_type(
                (ConnectionError, TimeoutError, builtins.TimeoutError)
            ),
            reraise=True,
        ):
            with attempt:
                try:
                    if not self._conn.transport.is_connected:
                        await self._conn.transport.connect()
                    result = await call_next(request)
                except (
                    ConnectionError,
                    TimeoutError,
                    builtins.TimeoutError,
                ) as retry_exc:
                    attempt_num = attempt.retry_state.attempt_number
                    log_event(
                        self._conn.logger,
                        logging.WARNING,
                        "command.retry",
                        f"Retry attempt {attempt_num}/{max_attempts} "
                        f"for {log_cmd} on {self._conn.config.uri_safe}",
                        command="***REDACTED***" if request.sensitive else request.command,
                        attempt=attempt_num,
                        max_attempts=max_attempts,
                        error_type=type(retry_exc).__name__,
                        error=str(retry_exc),
                        sensitive=request.sensitive,
                    )
                    otel_span = request.metadata.get("otel_span")
                    if otel_span is not None and hasattr(otel_span, "add_event"):
                        otel_span.add_event(
                            "command.retry",
                            {
                                "retry.attempt": attempt_num,
                                "retry.max_attempts": max_attempts,
                                "exception.type": type(retry_exc).__name__,
                                "exception.message": (
                                    "***REDACTED***" if request.sensitive else str(retry_exc)
                                ),
                            },
                        )
                    await self._conn.transport.disconnect()
                    if attempt_num < max_attempts:
                        await self._conn.transport.connect()
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
                timeout=timeout or self._conn.config.timeout,
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
            timeout=req.timeout or self._conn.config.timeout,
            sensitive=req.sensitive,
            cmd_label=req.command,
            transport_kwargs=req.transport_kwargs,
        ):
            yield line


