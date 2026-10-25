# src/uniconn/telemetry.py
"""Интеграция с OpenTelemetry для сквозной трассировки операций uniconn (v0.10.0).

Обеспечивает автоматическое создание span'ов для ``run()``, ``run_bytes()``,
``stream()``, файловых операций (``upload()``, ``download()``, ``read_file()``,
``write_file()``, ``sync_dir()``) и интерактивных PTY-сессий (``open_shell()``,
``execute()``, ``expect()``) без жёсткой зависимости от ``opentelemetry-api`` в ядре.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import importlib
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, Self, runtime_checkable

from ._logging import SecretMaskingFilter
from .core.pipeline import CommandRequest, NextHandler
from .exceptions import ExecutionError
from .result import Result, SyncResult

if TYPE_CHECKING:
    from ._connection import Connection

_CURRENT_SPAN_VAR: contextvars.ContextVar[ Any ] = contextvars.ContextVar(
    "uniconn_current_span",
    default=None,
)


@runtime_checkable
class SpanProtocol(Protocol):
    """Протокол совместимости с ``opentelemetry.trace.Span``."""

    def set_attribute(self, key: str, value: Any) -> Any:
        """Установить атрибут span'а."""
        ...

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> Any:
        """Добавить текстовое событие во временную шкалу span'а."""
        ...

    def record_exception(self, exception: BaseException) -> Any:
        """Зафиксировать исключение в span'е."""
        ...

    def set_status(self, status: Any, description: str | None = None) -> Any:
        """Установить итоговый статус выполнения span'а."""
        ...


@runtime_checkable
class TracerProtocol(Protocol):
    """Протокол совместимости с ``opentelemetry.trace.Tracer``."""

    def start_as_current_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> contextlib.AbstractContextManager[Any]:
        """Создать и активировать новый span как контекстный менеджер."""
        ...


@dataclass(slots=True)
class RecordedSpan:
    """Легковесное представление span'а для встроенного ``InMemoryTracer`` и тестов."""

    name: str
    parent_name: str | None = None
    span_id: int = 0
    parent_span_id: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    status_code: str = "UNSET"
    status_description: str | None = None
    start_time: float = field(default_factory=time.monotonic)
    end_time: float | None = None

    @property
    def duration_ms(self) -> float:
        """Длительность span'а в миллисекундах."""
        if self.end_time is None:
            return 0.0
        return round((self.end_time - self.start_time) * 1000.0, 3)

    def set_attribute(self, key: str, value: Any) -> None:
        """Установить атрибут span'а."""
        self.attributes[key] = value

    def add_event(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        """Добавить событие в span."""
        self.events.append((name, dict(attributes or {})))

    def record_exception(self, exception: BaseException) -> None:
        """Записать информацию об исключении."""
        self.exceptions.append(f"{type(exception).__name__}: {exception}")
        self.events.append(
            (
                "exception",
                {
                    "exception.type": type(exception).__name__,
                    "exception.message": str(exception),
                },
            )
        )

    def set_status(self, status: Any, description: str | None = None) -> None:
        """Установить статус span'а."""
        code_name = getattr(status, "name", str(status))
        self.status_code = code_name
        if description is not None:
            self.status_description = description


class InMemoryTracer:
    """Встроенный совместимый с OpenTelemetry трейсер, сохраняющий span'ы в памяти.

    Используется автоматически, если пакет ``opentelemetry-api`` не установлен,
    а также удобен для контрактного и unit-тестирования телеметрии.
    """

    def __init__(self, service_name: str = "uniconn") -> None:
        """Инициализировать InMemoryTracer."""
        self.service_name = service_name
        self.spans: list[RecordedSpan] = []
        self._counter = 0

    def clear(self) -> None:
        """Очистить накопленные span'ы."""
        self.spans.clear()

    @contextlib.contextmanager
    def start_as_current_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        **_kwargs: Any,
    ) -> Iterator[RecordedSpan]:
        """Создать ``RecordedSpan``, сделать его текущим в ``contextvars`` и закрыть по выходу."""
        self._counter += 1
        parent = _CURRENT_SPAN_VAR.get()
        parent_name = getattr(parent, "name", None) if parent is not None else None
        parent_id = getattr(parent, "span_id", None) if parent is not None else None

        span = RecordedSpan(
            name=name,
            parent_name=parent_name,
            span_id=self._counter,
            parent_span_id=parent_id,
            attributes=dict(attributes or {}),
        )
        self.spans.append(span)
        token = _CURRENT_SPAN_VAR.set(span)
        try:
            yield span
        finally:
            span.end_time = time.monotonic()
            _CURRENT_SPAN_VAR.reset(token)


def get_current_span() -> Any:
    """Вернуть текущий активный span из ``contextvars`` или ``opentelemetry.trace``."""
    local_span = _CURRENT_SPAN_VAR.get()
    if local_span is not None:
        return local_span
    with contextlib.suppress(Exception):
        otel_trace = importlib.import_module("opentelemetry.trace")
        return otel_trace.get_current_span()
    return None


def _resolve_default_tracer(service_name: str) -> TracerProtocol:
    """Получить глобальный OpenTelemetry Tracer или вернуть ``InMemoryTracer``."""
    try:
        otel_trace = importlib.import_module("opentelemetry.trace")
        return otel_trace.get_tracer(service_name)
    except Exception:
        return InMemoryTracer(service_name=service_name)


def _set_span_status(span: Any, *, ok: bool, description: str | None = None) -> None:
    """Безопасно выставить статус OK/ERROR для реального OTel Span или RecordedSpan."""
    try:
        otel_trace = importlib.import_module("opentelemetry.trace")
        status_code_enum = getattr(otel_trace, "StatusCode", None)
        if status_code_enum is not None:
            code = status_code_enum.OK if ok else status_code_enum.ERROR
            if ok:
                span.set_status(code)
            else:
                span.set_status(code, description)
            return
    except Exception:
        pass
    span.set_status("OK" if ok else "ERROR", description)


class TracingMiddleware:
    """Middleware конвейера ``CommandPipeline`` для создания span'ов ``uniconn.run``."""

    def __init__(self, conn: Connection, hook: OtelTracingHook) -> None:
        """Инициализировать TracingMiddleware."""
        self._conn = conn
        self._hook = hook

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Обернуть выполнение команды в OpenTelemetry span."""
        cmd_attr = (
            "***REDACTED***"
            if request.sensitive
            else self._hook._sanitize(request.command)
        )
        attrs: dict[str, Any] = {
            "rpc.system": "uniconn",
            "service.name": self._hook.service_name,
            "uniconn.transport": self._conn.transport_name,
            "server.address": self._conn.config.host or "localhost",
            "process.command_line": cmd_attr,
            "uniconn.sudo": request.sudo,
            "uniconn.dry_run": request.dry_run,
            "uniconn.sensitive": request.sensitive,
        }
        if self._conn.config.port is not None:
            attrs["server.port"] = self._conn.config.port

        with self._hook._start_span("uniconn.run", attributes=attrs) as span:
            request.metadata["otel_span"] = span
            try:
                result = await call_next(request)
            except BaseException as exc:
                if isinstance(exc, ExecutionError) and exc.exit_code is not None:
                    span.set_attribute("process.exit_code", exc.exit_code)
                span.set_attribute("uniconn.ok", False)
                span.record_exception(exc)
                _set_span_status(span, ok=False, description=str(exc))
                raise

            span.set_attribute("process.exit_code", result.exit_code)
            span.set_attribute("uniconn.ok", result.ok)
            span.set_attribute("uniconn.duration_ms", round(result.duration * 1000.0, 3))
            if self._hook.record_output:
                out_str = (
                    "***REDACTED***"
                    if (request.sensitive or result.sensitive)
                    else self._hook._sanitize(result.stdout)
                )
                err_str = (
                    "***REDACTED***"
                    if (request.sensitive or result.sensitive)
                    else self._hook._sanitize(result.stderr)
                )
                span.set_attribute("process.stdout", out_str)
                span.set_attribute("process.stderr", err_str)

            if result.ok:
                _set_span_status(span, ok=True)
            else:
                _set_span_status(
                    span,
                    ok=False,
                    description=f"Command exited with code {result.exit_code}",
                )
            return result


class OtelTracingHook:
    """Инструментатор сквозной трассировки OpenTelemetry для ``Connection`` и ``ConnectionPool``."""

    def __init__(
        self,
        tracer: TracerProtocol | None = None,
        *,
        service_name: str = "uniconn",
        record_output: bool = False,
        mask_secrets: bool = True,
        trace_files: bool = True,
        trace_shell: bool = True,
    ) -> None:
        """Инициализировать инструментатор OpenTelemetry."""
        self.service_name = service_name
        self.tracer: TracerProtocol = tracer or _resolve_default_tracer(service_name)
        self.record_output = record_output
        self.mask_secrets = mask_secrets
        self.trace_files = trace_files
        self.trace_shell = trace_shell

    def _sanitize(self, text: str) -> str:
        if not text or not self.mask_secrets:
            return text
        return SecretMaskingFilter._mask_string(text)

    @contextlib.contextmanager
    def _start_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
    ) -> Iterator[Any]:
        with self.tracer.start_as_current_span(name, attributes=attributes) as span:
            token = _CURRENT_SPAN_VAR.set(span)
            try:
                yield span
            finally:
                _CURRENT_SPAN_VAR.reset(token)

    def _base_attrs(self, conn: Connection) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "rpc.system": "uniconn",
            "service.name": self.service_name,
            "uniconn.transport": conn.transport_name,
            "server.address": conn.config.host or "localhost",
        }
        if conn.config.port is not None:
            attrs["server.port"] = conn.config.port
        return attrs

    def _instrument_files(self, conn: Connection) -> None:
        files_svc: Any = conn.files
        if getattr(files_svc, "_otel_instrumented", False):
            return
        files_svc._otel_instrumented = True

        orig_upload = files_svc.upload
        orig_download = files_svc.download
        orig_read_file = files_svc.read_file
        orig_write_file = files_svc.write_file
        orig_sync_dir = files_svc.sync_dir

        @functools.wraps(orig_upload)
        async def traced_upload(
            local_path: str,
            remote_path: str,
            recurse: bool = False,
            **kwargs: Any,
        ) -> None:
            attrs = {
                **self._base_attrs(conn),
                "file.local_path": str(local_path),
                "file.remote_path": str(remote_path),
                "file.recurse": recurse,
            }
            with self._start_span("uniconn.upload", attributes=attrs) as span:
                try:
                    await orig_upload(local_path, remote_path, recurse=recurse, **kwargs)
                    _set_span_status(span, ok=True)
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        @functools.wraps(orig_download)
        async def traced_download(
            remote_path: str,
            local_path: str,
            recurse: bool = False,
            **kwargs: Any,
        ) -> None:
            attrs = {
                **self._base_attrs(conn),
                "file.remote_path": str(remote_path),
                "file.local_path": str(local_path),
                "file.recurse": recurse,
            }
            with self._start_span("uniconn.download", attributes=attrs) as span:
                try:
                    await orig_download(remote_path, local_path, recurse=recurse, **kwargs)
                    _set_span_status(span, ok=True)
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        @functools.wraps(orig_read_file)
        async def traced_read_file(
            remote_path: str,
            encoding: str | None = "utf-8",
        ) -> str | bytes:
            attrs = {
                **self._base_attrs(conn),
                "file.remote_path": str(remote_path),
            }
            with self._start_span("uniconn.read_file", attributes=attrs) as span:
                try:
                    res = await orig_read_file(remote_path, encoding=encoding)
                    size = len(res.encode("utf-8")) if isinstance(res, str) else len(res)
                    span.set_attribute("file.bytes_transferred", size)
                    _set_span_status(span, ok=True)
                    return res
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        @functools.wraps(orig_write_file)
        async def traced_write_file(
            remote_path: str,
            content: str | bytes,
            mode: int | None = None,
            encoding: str = "utf-8",
        ) -> None:
            size = len(content.encode(encoding)) if isinstance(content, str) else len(content)
            attrs = {
                **self._base_attrs(conn),
                "file.remote_path": str(remote_path),
                "file.bytes_transferred": size,
            }
            with self._start_span("uniconn.write_file", attributes=attrs) as span:
                try:
                    await orig_write_file(
                        remote_path,
                        content,
                        mode=mode,
                        encoding=encoding,
                    )
                    _set_span_status(span, ok=True)
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        @functools.wraps(orig_sync_dir)
        async def traced_sync_dir(
            local_dir: str | Path,
            remote_dir: str | Path,
            delete: bool = False,
            exclude: Any = None,
            mtime_tolerance: float = 1.0,
            dry_run: bool | None = None,
        ) -> SyncResult:
            attrs = {
                **self._base_attrs(conn),
                "file.local_path": str(local_dir),
                "file.remote_path": str(remote_dir),
            }
            with self._start_span("uniconn.sync_dir", attributes=attrs) as span:
                try:
                    res = await orig_sync_dir(
                        local_dir=local_dir,
                        remote_dir=remote_dir,
                        delete=delete,
                        exclude=exclude,
                        mtime_tolerance=mtime_tolerance,
                        dry_run=dry_run,
                    )
                    span.set_attribute("file.bytes_transferred", res.bytes_transferred)
                    span.set_attribute("sync.uploaded_count", len(res.uploaded))
                    span.set_attribute("sync.skipped_count", len(res.skipped))
                    span.set_attribute("sync.deleted_count", len(res.deleted))
                    _set_span_status(span, ok=True)
                    return res
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        files_svc.upload = traced_upload
        files_svc.download = traced_download
        files_svc.read_file = traced_read_file
        files_svc.write_file = traced_write_file
        files_svc.sync_dir = traced_sync_dir

    def _instrument_shell_and_stream(self, conn: Connection) -> None:
        conn_any: Any = conn
        if getattr(conn_any, "_otel_shell_instrumented", False):
            return
        conn_any._otel_shell_instrumented = True

        orig_open_shell = conn.open_shell
        orig_stream = conn.stream

        @functools.wraps(orig_open_shell)
        async def traced_open_shell(
            term_type: str = "xterm",
            term_size: tuple[int, int] = (80, 24),
            init_posix: bool | None = None,
            **kwargs: Any,
        ) -> Any:
            attrs = {
                **self._base_attrs(conn),
                "shell.term_type": term_type,
                "shell.cols": term_size[0],
                "shell.rows": term_size[1],
            }
            with self._start_span("uniconn.open_shell", attributes=attrs) as span:
                try:
                    session = await orig_open_shell(
                        term_type=term_type,
                        term_size=term_size,
                        init_posix=init_posix,
                        **kwargs,
                    )
                    _set_span_status(span, ok=True)
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

            self._wrap_shell_session(conn, session)
            return session

        @functools.wraps(orig_stream)
        async def traced_stream(
            command: Any,
            timeout: float | None = None,
            **kwargs: Any,
        ) -> AsyncIterator[str]:
            cmd_str = command if isinstance(command, str) else " ".join(command)
            attrs = {
                **self._base_attrs(conn),
                "process.command_line": self._sanitize(cmd_str),
            }
            lines_count = 0
            with self._start_span("uniconn.stream", attributes=attrs) as span:
                try:
                    async for line in orig_stream(command, timeout=timeout, **kwargs):
                        lines_count += 1
                        yield line
                    span.set_attribute("stream.lines_count", lines_count)
                    _set_span_status(span, ok=True)
                except BaseException as exc:
                    span.set_attribute("stream.lines_count", lines_count)
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        if self.trace_shell:
            conn_any.open_shell = traced_open_shell
        conn_any.stream = traced_stream

    def _wrap_shell_session(self, conn: Connection, session: Any) -> None:
        if getattr(session, "_otel_instrumented", False):
            return
        session._otel_instrumented = True

        orig_execute = session.execute
        orig_expect = session.expect

        @functools.wraps(orig_execute)
        async def traced_execute(
            command: Any,
            timeout: float | None = None,
        ) -> Result:
            cmd_str = command if isinstance(command, str) else " ".join(command)
            attrs = {
                **self._base_attrs(conn),
                "shell.command": self._sanitize(cmd_str),
            }
            with self._start_span("uniconn.shell.execute", attributes=attrs) as span:
                try:
                    res = await orig_execute(command, timeout=timeout)
                    span.set_attribute("process.exit_code", res.exit_code)
                    span.set_attribute("uniconn.ok", res.ok)
                    _set_span_status(span, ok=res.ok)
                    return res
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        @functools.wraps(orig_expect)
        async def traced_expect(
            command: Any = None,
            patterns: Any = None,
            final_prompt: str | None = None,
            timeout: float | None = None,
            line_ending: str = "\n",
            sensitive: bool = False,
            allow_eof: bool = True,
        ) -> Result:
            raw_cmd = "" if command is None else (
                command if isinstance(command, str) else " ".join(command)
            )
            cmd_attr = "***REDACTED***" if sensitive else self._sanitize(raw_cmd)
            attrs = {
                **self._base_attrs(conn),
                "shell.command": cmd_attr,
                "uniconn.sensitive": sensitive,
            }
            with self._start_span("uniconn.shell.expect", attributes=attrs) as span:
                try:
                    res = await orig_expect(
                        command=command,
                        patterns=patterns,
                        final_prompt=final_prompt,
                        timeout=timeout,
                        line_ending=line_ending,
                        sensitive=sensitive,
                        allow_eof=allow_eof,
                    )
                    span.set_attribute("process.exit_code", res.exit_code)
                    _set_span_status(span, ok=res.ok)
                    return res
                except BaseException as exc:
                    span.record_exception(exc)
                    _set_span_status(span, ok=False, description=str(exc))
                    raise

        session.execute = traced_execute
        session.expect = traced_expect

    def _attach_connection(self, conn: Connection) -> None:
        if not any(isinstance(m, TracingMiddleware) for m in conn.pipeline._middlewares):
            # Вставляем TracingMiddleware сразу после ContextMiddleware и SudoMiddleware,
            # чтобы он оборачивал HookMiddleware, ObservabilityMiddleware и RetryMiddleware.
            insert_idx = min(2, len(conn.pipeline._middlewares))
            conn.pipeline._middlewares.insert(insert_idx, TracingMiddleware(conn, self))

        if self.trace_files:
            self._instrument_files(conn)
        self._instrument_shell_and_stream(conn)

    def _attach_pool(self, pool: Any) -> None:
        if getattr(pool, "_otel_instrumented", False):
            return
        pool._otel_instrumented = True

        if hasattr(pool, "_build_conn"):
            orig_build_conn = pool._build_conn

            @functools.wraps(orig_build_conn)
            def traced_build_conn(*args: Any, **kwargs: Any) -> Connection:
                conn = orig_build_conn(*args, **kwargs)
                self._attach_connection(conn)
                return conn

            pool._build_conn = traced_build_conn

        active_conns = getattr(pool, "_active_conns", None)
        if isinstance(active_conns, dict):
            for existing in active_conns.values():
                if hasattr(existing, "pipeline"):
                    self._attach_connection(existing)

        for item in getattr(pool, "_uris", ()):
            if hasattr(item, "pipeline"):
                self._attach_connection(item)

    def attach(self, target: Any) -> Self:
        """Привязать сквозную OpenTelemetry-трассировку к ``Connection``, ``SyncConnection`` или пулу."""
        if hasattr(target, "_async_conn"):
            self._attach_connection(target._async_conn)
        elif hasattr(target, "_async_pool"):
            self._attach_pool(target._async_pool)
        elif hasattr(target, "_build_conn") or hasattr(target, "_get_connections"):
            self._attach_pool(target)
        elif hasattr(target, "pipeline"):
            self._attach_connection(target)
        else:
            raise TypeError(
                f"Cannot attach OtelTracingHook to unsupported target: {type(target).__name__}"
            )
        return self


def otel_tracing_hook(
    tracer: TracerProtocol | None = None,
    *,
    service_name: str = "uniconn",
    record_output: bool = False,
    mask_secrets: bool = True,
    trace_files: bool = True,
    trace_shell: bool = True,
) -> OtelTracingHook:
    """Создать инструментатор OpenTelemetry для подключения к ``Connection`` или ``ConnectionPool``."""
    return OtelTracingHook(
        tracer=tracer,
        service_name=service_name,
        record_output=record_output,
        mask_secrets=mask_secrets,
        trace_files=trace_files,
        trace_shell=trace_shell,
    )


__all__ = [
    "InMemoryTracer",
    "OtelTracingHook",
    "RecordedSpan",
    "SpanProtocol",
    "TracerProtocol",
    "TracingMiddleware",
    "get_current_span",
    "otel_tracing_hook",
]
