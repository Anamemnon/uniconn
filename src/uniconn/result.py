# src/uniconn/result.py
"""Модель результата выполнения команды."""

import contextlib
import dataclasses
import json as json_module
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

T = TypeVar("T")
_UNSET: Any = object()


def _serialize_parsed_value(val: Any) -> Any:
    """Рекурсивно преобразовать спарсенное значение (включая BaseModel и dataclass) в JSON-совместимый вид."""
    if isinstance(val, BaseModel):
        return val.model_dump()
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        return dataclasses.asdict(val)
    if isinstance(val, list | tuple | set | frozenset):
        return [_serialize_parsed_value(item) for item in val]
    if isinstance(val, dict):
        return {str(k): _serialize_parsed_value(v) for k, v in val.items()}
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, Path):
        return val.as_posix()
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return val


@dataclass(frozen=True, slots=True)
class Result:
    """Результат выполнения команды."""

    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    timestamp: datetime = field(default_factory=datetime.now)
    host: str | None = None
    sensitive: bool = False
    raw_bytes: bytes = b""
    parse_spec: Any = field(default=None, compare=False, repr=False)
    _dry_run: bool = field(default=False, compare=False, repr=False)
    _parsed_cache: Any = field(default=_UNSET, init=False, compare=False, repr=False)

    @property
    def ok(self) -> bool:
        """True если exit_code == 0."""
        return self.exit_code == 0

    def __bool__(self) -> bool:
        """Позволяет использовать Result в условных выражениях (``if await conn.run(...):``)."""
        return self.ok

    @property
    def text(self) -> str:
        """Очищенный от краевых пробелов и переводов строк ``stdout`` (``stdout.strip()``)."""
        return self.stdout.strip()

    @property
    def lines(self) -> list[str]:
        """Список строк вывода ``stdout`` (без завершающих переводов строк)."""
        stripped = self.stdout.strip()
        if not stripped:
            return []
        return stripped.splitlines()

    def json(self) -> Any:
        """Распарсить ``stdout`` как JSON и вернуть Python-объект.

        Raises:
            ValueError: Если ``stdout`` не является валидным JSON.

        """
        return json_module.loads(self.stdout)

    def parse(self, spec: Any = None, **kwargs: Any) -> Any:
        """Семантически распарсить ``stdout`` с помощью указанной спецификации, схемы или автодетектора."""
        from .parsing.registry import default_registry

        target_spec = spec if spec is not None else (
            self.parse_spec if self.parse_spec is not None else "auto"
        )
        parsed_val = default_registry.parse(
            self.stdout,
            target_spec,
            command=self.command,
            dry_run=self._dry_run,
            **kwargs,
        )
        if spec is None and not kwargs:
            object.__setattr__(self, "_parsed_cache", parsed_val)
        return parsed_val

    @property
    def parsed(self) -> Any:
        """Лениво вычисленный и закэшированный результат семантического парсинга ``stdout``."""
        if self._parsed_cache is _UNSET:
            object.__setattr__(self, "_parsed_cache", self.parse())
        return self._parsed_cache

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать результат в сериализуемый словарь (с учётом ``sensitive`` и ``parsed``)."""
        payload: dict[str, Any] = {
            "host": self.host,
            "command": "***REDACTED***" if self.sensitive else self.command,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "stdout": "***REDACTED***" if self.sensitive else self.stdout,
            "stderr": "***REDACTED***" if self.sensitive else self.stderr,
            "duration": round(self.duration, 6),
            "timestamp": self.timestamp.isoformat(),
            "sensitive": self.sensitive,
        }
        if self.parse_spec is not None or self._parsed_cache is not _UNSET:
            if self.sensitive:
                payload["parsed"] = "***REDACTED***"
            else:
                with contextlib.suppress(Exception):
                    payload["parsed"] = _serialize_parsed_value(self.parsed)
        return payload

    def raise_for_status(self) -> None:
        """Raise ExecutionError if exit_code != 0."""
        from .exceptions import ExecutionError
        if not self.ok:
            raise ExecutionError(
                f"Command failed with exit code {self.exit_code}",
                command="***REDACTED***" if self.sensitive else self.command,
                exit_code=self.exit_code,
                stdout="***REDACTED***" if self.sensitive else self.stdout,
                stderr="***REDACTED***" if self.sensitive else self.stderr,
            )

    def __repr__(self) -> str:
        """Вернуть отладочное представление результата (с маскировкой при sensitive=True)."""
        stdout_repr = "'***REDACTED***'" if self.sensitive else repr(self.stdout)
        stderr_repr = "'***REDACTED***'" if self.sensitive else repr(self.stderr)
        cmd_repr = "'***REDACTED***'" if self.sensitive else repr(self.command)
        return (
            f"Result(exit_code={self.exit_code!r}, stdout={stdout_repr}, "
            f"stderr={stderr_repr}, duration={self.duration!r}, "
            f"command={cmd_repr}, timestamp={self.timestamp!r}, "
            f"host={self.host!r}, sensitive={self.sensitive!r})"
        )

    def __str__(self) -> str:
        """Вернуть краткое строковое представление результата."""
        return f"Result(exit_code={self.exit_code}, duration={self.duration:.2f}s)"


@dataclass(frozen=True, slots=True)
class SyncResult:
    """Результат инкрементальной синхронизации директории (``sync_dir``)."""

    uploaded: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    bytes_transferred: int = 0
    duration: float = 0.0
    dry_run: bool = False

    @property
    def total_checked(self) -> int:
        """Общее число проверенных локальных файлов (uploaded + skipped)."""
        return len(self.uploaded) + len(self.skipped)

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать отчёт синхронизации в сериализуемый словарь."""
        return {
            "uploaded": list(self.uploaded),
            "skipped": list(self.skipped),
            "deleted": list(self.deleted),
            "uploaded_count": len(self.uploaded),
            "skipped_count": len(self.skipped),
            "deleted_count": len(self.deleted),
            "bytes_transferred": self.bytes_transferred,
            "duration": round(self.duration, 6),
            "dry_run": self.dry_run,
        }


@dataclass(frozen=True, slots=True)
class EnsureResult:
    """Результат идемпотентной проверки или приведения состояния (``ensure_*``)."""

    target: str
    state: str
    changed: bool
    ok: bool = True
    details: str = ""
    dry_run: bool = False
    diff: str | None = None
    reboot_required: bool = False
    notified: bool = False
    notify_results: tuple[Any, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать отчёт идемпотентной проверки в сериализуемый словарь."""
        serialized_notify = [
            item.to_dict() if hasattr(item, "to_dict") and callable(item.to_dict) else item
            for item in self.notify_results
        ]
        return {
            "target": self.target,
            "state": self.state,
            "changed": self.changed,
            "ok": self.ok,
            "details": self.details,
            "dry_run": self.dry_run,
            "diff": self.diff,
            "reboot_required": self.reboot_required,
            "notified": self.notified,
            "notify_results": serialized_notify,
        }



@dataclass(frozen=True, slots=True)
class PingResult:
    """Результат проверки доступности хоста с измерением задержки (``ping``)."""

    host: str
    alive: bool
    latency_ms: float
    transport: str = "unknown"
    error: str | None = None

    def __bool__(self) -> bool:
        """Позволяет использовать PingResult в условных выражениях (``if await conn.ping():``)."""
        return self.alive

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать результат пинга в сериализуемый словарь."""
        return {
            "host": self.host,
            "alive": self.alive,
            "latency_ms": round(self.latency_ms, 3),
            "transport": self.transport,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class NetResult:
    """Структурированный результат сетевой операции (NETCONF / RESTCONF / gNMI)."""

    ok: bool
    data: Any = None
    text: str = ""
    raw: bytes = b""
    operation: str = ""
    datastore: str | None = None
    protocol: str = ""
    duration: float = 0.0
    errors: list[dict[str, Any]] = field(default_factory=list)
    host: str | None = None
    message_id: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def __bool__(self) -> bool:
        """Позволяет использовать NetResult в условных выражениях (``if await conn.net.get(...):``)."""
        return self.ok

    @property
    def stdout(self) -> str:
        """Алиас для совместимости с текстовым конвейером."""
        return self.text

    def json(self) -> Any:
        """Вернуть структурированные данные или распарсить ``text`` как JSON."""
        if self.data is not None and not isinstance(self.data, str | bytes):
            return _serialize_parsed_value(self.data)
        return json_module.loads(self.text)

    def raise_for_status(self) -> None:
        """Выбросить ``ExecutionError``, если операция завершилась с ошибкой (``not self.ok``)."""
        from .exceptions import ExecutionError

        if not self.ok:
            err_msg = (
                "; ".join(
                    str(e.get("error-message") or e.get("message") or e)
                    for e in self.errors
                )
                if self.errors
                else (self.text or f"Network operation {self.operation!r} failed")
            )
            raise ExecutionError(
                err_msg,
                command=f"{self.protocol}:{self.operation}",
                exit_code=1,
                stdout=self.text,
                stderr=err_msg,
                host=self.host,
            )

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать ``NetResult`` в сериализуемый словарь."""
        import base64

        return {
            "ok": self.ok,
            "data": _serialize_parsed_value(self.data),
            "text": self.text,
            "raw_base64": (
                base64.b64encode(self.raw).decode("ascii") if self.raw else ""
            ),
            "operation": self.operation,
            "datastore": self.datastore,
            "protocol": self.protocol,
            "duration": round(self.duration, 6),
            "errors": list(self.errors),
            "host": self.host,
            "message_id": self.message_id,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "NetResult":
        """Восстановить ``NetResult`` из сериализованного словаря."""
        import base64
        import binascii

        raw_b64 = payload.get("raw_base64")
        if isinstance(raw_b64, str) and raw_b64:
            try:
                raw_bytes = base64.b64decode(raw_b64.encode("ascii"), validate=True)
            except (binascii.Error, ValueError):
                raw_bytes = raw_b64.encode("utf-8")
        else:
            raw_bytes = str(payload.get("text") or "").encode("utf-8")
        ts_raw = payload.get("timestamp")
        ts = datetime.fromisoformat(ts_raw) if isinstance(ts_raw, str) else datetime.now()
        return cls(
            ok=bool(payload.get("ok", True)),
            data=payload.get("data"),
            text=str(payload.get("text") or ""),
            raw=raw_bytes,
            operation=str(payload.get("operation") or ""),
            datastore=payload.get("datastore"),
            protocol=str(payload.get("protocol") or ""),
            duration=float(payload.get("duration") or 0.0),
            errors=list(payload.get("errors") or []),
            host=payload.get("host"),
            message_id=payload.get("message_id"),
            timestamp=ts,
        )


@dataclass(frozen=True, slots=True)
class TelemetrySample:
    """Сэмпл потоковой сетевой телеметрии (gNMI Subscribe / NETCONF Notification / RESTCONF SSE)."""

    path: str
    values: dict[str, Any] = field(default_factory=dict)
    timestamp: int = 0
    prefix: str = ""
    deletes: list[str] = field(default_factory=list)
    sync_response: bool = False
    protocol: str = ""
    host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать сэмпл телеметрии в сериализуемый словарь."""
        return {
            "path": self.path,
            "values": _serialize_parsed_value(self.values),
            "timestamp": self.timestamp,
            "prefix": self.prefix,
            "deletes": list(self.deletes),
            "sync_response": self.sync_response,
            "protocol": self.protocol,
            "host": self.host,
        }

    def to_json(self) -> str:
        """Сериализовать сэмпл телеметрии в компактную JSON-строку."""
        return json_module.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TelemetrySample":
        """Восстановить ``TelemetrySample`` из словаря."""
        raw_vals = payload.get("values")
        return cls(
            path=str(payload.get("path") or ""),
            values=dict(raw_vals) if isinstance(raw_vals, dict) else {},
            timestamp=int(payload.get("timestamp") or 0),
            prefix=str(payload.get("prefix") or ""),
            deletes=[str(x) for x in (payload.get("deletes") or [])],
            sync_response=bool(payload.get("sync_response", False)),
            protocol=str(payload.get("protocol") or ""),
            host=payload.get("host"),
        )


__all__ = [
    "EnsureResult",
    "NetResult",
    "PingResult",
    "Result",
    "SyncResult",
    "TelemetrySample",
]



