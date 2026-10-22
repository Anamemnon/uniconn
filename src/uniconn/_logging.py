# src/uniconn/_logging.py
"""Модуль логирования uniconn с поддержкой structlog, JSONL и маскирования секретов.

Предоставляет:
- ``configure_logging()`` — единая настройка структурированных логов (``json`` для
  Grafana Loki / ClickHouse / InfluxDB или ``console`` для терминала) поверх
  ``structlog`` и стандартного ``logging``;
- ``get_struct_logger()`` — получение типизированного ``structlog``-логгера;
- ``log_context()`` / ``bind_log_context()`` / ``clear_log_context()`` — привязка
  контекстных метаданных (``host``, ``transport``, ``run_id``, ``env`` и др.) через
  ``contextvars`` для асинхронных и синхронных вызовов;
- ``redact_event_dict()`` и ``SecretMaskingFilter`` — автоматическая фильтрация
  паролей, ``SecretStr``, токенов и вывода ``sensitive``-команд;
- ``get_logger()`` и ``setup_file_logging()`` — функции настройки стандартного
  ``logging`` с ротацией файлов и обратной совместимостью.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import sys
from collections.abc import Iterator, MutableMapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, TextIO

import structlog
from pydantic import SecretStr

SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "sudo_password",
        "passphrase",
        "key_passphrase",
        "secret",
        "token",
        "api_key",
        "private_key",
    }
)


class SecretMaskingFilter(logging.Filter):
    """Фильтр для маскирования чувствительных данных в записях стандартного logging."""

    PATTERNS = [
        (re.compile(r"sudo_password[=:]\S+", re.IGNORECASE), "sudo_password=***"),
        (re.compile(r"passphrase[=:]\S+", re.IGNORECASE), "passphrase=***"),
        (re.compile(r"password[=:]\S+", re.IGNORECASE), "password=***"),
        (re.compile(r"pass[=:]\S+", re.IGNORECASE), "pass=***"),
        (re.compile(r"secret[=:]\S+", re.IGNORECASE), "secret=***"),
        (re.compile(r"token[=:]\S+", re.IGNORECASE), "token=***"),
        (re.compile(r"://[^:]+:[^@]+@", re.IGNORECASE), "://***:***@"),
    ]

    def __init__(self, name: str = "") -> None:
        """Инициализировать фильтр маскирования секретов."""
        super().__init__(name)
        self._enabled = True

    def filter(self, record: logging.LogRecord) -> bool:
        """Отфильтровать и замаскировать секреты в ``LogRecord``."""
        if not self._enabled:
            return True

        if isinstance(record.msg, str):
            record.msg = self._mask_string(record.msg)

        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(self._mask_value(arg) for arg in record.args)
            elif isinstance(record.args, dict):
                record.args = {
                    k: self._mask_value(v) for k, v in record.args.items()
                }

        return True

    @classmethod
    def _mask_string(cls, value: str) -> str:
        for pattern, replacement in cls.PATTERNS:
            value = pattern.sub(replacement, value)
        return value

    def _mask_value(self, value: Any) -> Any:
        if isinstance(value, SecretStr):
            return "***REDACTED***"
        if isinstance(value, str):
            return self._mask_string(value)
        return value


def _sanitize_value(key: str, value: Any, *, sensitive_mode: bool = False) -> Any:
    """Рекурсивно замаскировать секреты в значении поля структурированного лога."""
    key_lower = key.lower()
    if key_lower in SENSITIVE_KEYS or isinstance(value, SecretStr):
        return "***REDACTED***"

    if sensitive_mode and key_lower in {"command", "stdout", "stderr", "input"}:
        return "***REDACTED***"

    if isinstance(value, str):
        return SecretMaskingFilter._mask_string(value)

    if isinstance(value, dict):
        return {
            str(k): _sanitize_value(str(k), v, sensitive_mode=sensitive_mode)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple)):
        sanitized_items = [
            _sanitize_value(key, item, sensitive_mode=sensitive_mode)
            for item in value
        ]
        return tuple(sanitized_items) if isinstance(value, tuple) else sanitized_items

    return value


def redact_event_dict(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Процессор ``structlog`` для централизованного маскирования секретов в полях лога.

    Автоматически маскирует:
    - значения типа ``pydantic.SecretStr``;
    - ключи из ``SENSITIVE_KEYS`` (``password``, ``sudo_password``, ``token`` и т.д.);
    - поля ``command``, ``stdout``, ``stderr`` при ``sensitive=True``;
    - пароли внутри URI и подстрок вида ``password=...``.
    """
    is_sensitive = bool(event_dict.get("sensitive", False))
    for key in list(event_dict.keys()):
        if key.startswith("_"):
            continue
        event_dict[key] = _sanitize_value(
            key,
            event_dict[key],
            sensitive_mode=is_sensitive,
        )
    return event_dict


def _merge_record_extra(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Перенести структурированные поля из ``LogRecord._uniconn_fields`` в ``event_dict``."""
    record = event_dict.get("_record")
    if record is not None:
        extra_fields = getattr(record, "_uniconn_fields", None)
        if isinstance(extra_fields, dict):
            for k, v in extra_fields.items():
                event_dict.setdefault(k, v)
        event_name = getattr(record, "_uniconn_event", None)
        if isinstance(event_name, str) and event_name:
            event_dict["event"] = event_name
    return event_dict


# ─── Контекстные переменные (contextvars) ──────────────────────────


def bind_log_context(**kwargs: Any) -> dict[str, Any]:
    """Привязать структурированные поля к текущему асинхронному контексту (``contextvars``).

    Все последующие записи логов в текущей корутине или потоке автоматически
    получат указанные поля (например, ``host``, ``transport``, ``run_id``, ``env``).
    """
    return dict(structlog.contextvars.bind_contextvars(**kwargs))


def unbind_log_context(*keys: str) -> None:
    """Удалить указанные ключи из контекста логирования текущей задачи."""
    structlog.contextvars.unbind_contextvars(*keys)


def clear_log_context() -> None:
    """Очистить все контекстные переменные логирования в текущей задаче."""
    structlog.contextvars.clear_contextvars()


def get_log_context() -> dict[str, Any]:
    """Получить текущий словарь контекстных переменных логирования."""
    return structlog.contextvars.get_contextvars()


class _LogContextManager:
    """Универсальный (sync + async) контекстный менеджер для привязки полей лога."""

    def __init__(self, **kwargs: Any) -> None:
        self._kwargs = kwargs
        self._tokens: dict[str, Any] = {}

    def __enter__(self) -> _LogContextManager:
        self._tokens = dict(structlog.contextvars.bind_contextvars(**self._kwargs))
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._tokens:
            structlog.contextvars.reset_contextvars(**self._tokens)
            self._tokens = {}

    async def __aenter__(self) -> _LogContextManager:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


@contextmanager
def _sync_log_context(**kwargs: Any) -> Iterator[None]:
    with _LogContextManager(**kwargs):
        yield


def log_context(**kwargs: Any) -> _LogContextManager:
    """Контекстный менеджер (``with`` и ``async with``) для временной привязки полей лога.

    Пример:
        >>> with log_context(service="deploy", datacenter="eu-1"):
        ...     await conn.run("uptime")
    """
    return _LogContextManager(**kwargs)


# ─── Форматтеры и настройка structlog / stdlib ─────────────────────

DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DETAILED_FORMAT = (
    "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d"
    " - %(message)s"
)


def _build_processor_formatter(
    fmt: Literal["console", "json"] = "console",
    mask_secrets: bool = True,
) -> structlog.stdlib.ProcessorFormatter:
    """Создать ``ProcessorFormatter`` для рендеринга записей в JSON или консоль."""
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _merge_record_extra,
    ]
    if mask_secrets:
        shared_processors.append(redact_event_dict)

    renderer: Any
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer(ensure_ascii=False)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    return structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )


def configure_logging(
    level: int | str = logging.INFO,
    fmt: Literal["console", "json"] = "console",
    stream: TextIO | None = None,
    log_file: str | Path | None = None,
    mask_secrets: bool = True,
    logger_name: str = "uniconn",
) -> logging.Logger:
    """Настроить структурированное логирование ``uniconn`` на базе ``structlog``.

    В режиме ``fmt="json"`` каждая запись выводится в виде однострочного JSON-объекта
    с полями ``timestamp`` (ISO-8601 UTC), ``level``, ``logger``, ``event`` и всеми
    метриками выполнения (``host``, ``transport``, ``command``, ``exit_code``,
    ``ok``, ``duration_ms``, ``attempt``, ``run_id``), готовыми к отправке в
    Grafana Loki, ClickHouse, InfluxDB, Vector или ELK.

    Args:
        level: Уровень логирования (``"DEBUG"``, ``"INFO"``, ``"WARNING"``, ``"ERROR"``)
        fmt: Формат вывода — ``"console"`` (key-value) или ``"json"`` (JSONL)
        stream: Поток вывода (по умолчанию ``sys.stderr``)
        log_file: Опциональный путь к файлу для записи структурированных логов
        mask_secrets: Автоматически маскировать пароли и секреты (по умолчанию ``True``)
        logger_name: Имя корневого логгера пакета (по умолчанию ``"uniconn"``)

    Returns:
        Настроенный экземпляр ``logging.Logger``

    """
    resolved_level = (
        getattr(logging, level.upper(), logging.INFO)
        if isinstance(level, str)
        else level
    )

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if mask_secrets:
        processors.append(redact_event_dict)
    processors.append(structlog.stdlib.ProcessorFormatter.wrap_for_formatter)

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = _build_processor_formatter(fmt=fmt, mask_secrets=mask_secrets)
    logger = logging.getLogger(logger_name)
    logger.setLevel(resolved_level)
    logger.handlers.clear()
    logger.propagate = False

    target_stream = stream if stream is not None else sys.stderr
    stream_handler = logging.StreamHandler(target_stream)
    stream_handler.setLevel(resolved_level)
    stream_handler.setFormatter(formatter)
    if mask_secrets:
        stream_handler.addFilter(SecretMaskingFilter())
    logger.addHandler(stream_handler)

    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_handler.setLevel(resolved_level)
        file_handler.setFormatter(formatter)
        if mask_secrets:
            file_handler.addFilter(SecretMaskingFilter())
        logger.addHandler(file_handler)

    return logger


def get_struct_logger(
    name: str = "uniconn",
    **initial_values: Any,
) -> structlog.stdlib.BoundLogger:
    """Получить типизированный структурированный логгер ``structlog``.

    Args:
        name: Имя логгера (по умолчанию ``"uniconn"``)
        **initial_values: Начальные поля контекста для привязки к логгеру

    Returns:
        Экземпляр ``structlog.stdlib.BoundLogger``

    """
    return structlog.get_logger(name, **initial_values)


def log_event(
    logger: Any,
    level: int,
    event: str,
    message: str | None = None,
    **fields: Any,
) -> None:
    """Записать структурированное событие в ``structlog`` или стандартный ``logging.Logger``.

    Сохраняет полную совместимость со стандартным ``logging.Logger``:
    - если подключён ``ProcessorFormatter`` (через ``configure_logging()``),
      все ``fields`` и ``contextvars`` сериализуются как поля верхнего уровня в JSON
      или key-value консоль;
    - если используется стандартный текстовый ``Formatter``, выводится читаемое
      сообщение ``message`` (или ``event``), а поля передаются в ``extra``.
    """
    merged_fields: dict[str, Any] = {**get_log_context(), **fields}
    redacted_fields: MutableMapping[str, Any] = dict(merged_fields)
    redact_event_dict(logger, "log", redacted_fields)
    clean_fields = dict(redacted_fields)

    if isinstance(logger, logging.Logger):
        display_msg = message if message is not None else event
        logger.log(
            level,
            display_msg,
            extra={
                "_uniconn_fields": clean_fields,
                "_uniconn_event": event,
            },
        )
        return

    level_name = logging.getLevelName(level).lower()
    log_method = getattr(logger, level_name, None)
    if callable(log_method):
        log_method(event, **clean_fields)


def _create_handler(
    handler: logging.Handler,
    level: int | str,
    fmt: str,
    mask_secrets: bool,
) -> logging.Handler:
    """Настроить handler с форматтером и маскированием."""
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(fmt))
    if mask_secrets:
        handler.addFilter(SecretMaskingFilter())
    return handler


def setup_file_logging(
    log_file: str | Path,
    level: int | str = logging.DEBUG,
    fmt: str = DEFAULT_FORMAT,
    mask_secrets: bool = True,
    rotation: Literal["size", "time"] = "size",
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    when: str = "midnight",
    interval: int = 1,
    logger_name: str = "uniconn",
    also_console: bool = False,
    structured: bool = False,
) -> logging.Logger:
    """Настроить логирование в файл с ротацией.

    Поддерживает два режима ротации:
    - **size**: RotatingFileHandler — ротация по размеру файла
    - **time**: TimedRotatingFileHandler — ротация по времени

    При ``structured=True`` записи форматируются в однострочный JSONL через
    ``structlog`` (с полями ``timestamp``, ``level``, ``event``, ``host`` и т.д.).

    Args:
        log_file: Путь к файлу лога
        level: Уровень логирования (DEBUG, INFO, WARNING, ERROR)
        fmt: Формат сообщений (для текстового режима)
        mask_secrets: Маскировать пароли и секреты
        rotation: Тип ротации — ``"size"`` или ``"time"``
        max_bytes: Максимальный размер файла (для ``rotation="size"``)
        backup_count: Количество файлов backups
        when: Единица времени для time-ротации
            (``'S'``, ``'M'``, ``'H'``, ``'D'``, ``'midnight'``,
            ``'W0'``–``'W6'``)
        interval: Интервал ротации в единицах ``when``
        logger_name: Имя логгера
        also_console: Добавить также консольный handler
        structured: Использовать JSONL-формат ``structlog`` вместо текстового шаблона

    Returns:
        Настроенный Logger

    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler: logging.Handler
    if rotation == "size":
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    else:
        file_handler = logging.handlers.TimedRotatingFileHandler(
            str(log_path),
            when=when,
            interval=interval,
            backupCount=backup_count,
            encoding="utf-8",
        )

    if structured:
        json_formatter = _build_processor_formatter(
            fmt="json",
            mask_secrets=mask_secrets,
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(json_formatter)
        if mask_secrets:
            file_handler.addFilter(SecretMaskingFilter())
    else:
        _create_handler(file_handler, level, fmt, mask_secrets)

    logger.addHandler(file_handler)

    if also_console:
        console_handler = logging.StreamHandler()
        if structured:
            console_formatter = _build_processor_formatter(
                fmt="console",
                mask_secrets=mask_secrets,
            )
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(console_formatter)
            if mask_secrets:
                console_handler.addFilter(SecretMaskingFilter())
        else:
            _create_handler(console_handler, logging.INFO, fmt, mask_secrets)
        logger.addHandler(console_handler)

    return logger


def get_logger(
    name: str = "uniconn",
    level: int | str = logging.INFO,
    mask_secrets: bool = True,
) -> logging.Logger:
    """Получить logger с маскированием секретов.

    Маскирующий фильтр вешается на handlers, а не на logger:
    фильтры логгера применяются только к записям самого логгера
    и НЕ наследуются дочерними (``uniconn.transports._ssh`` и т.п.),
    а фильтры handler'ов срабатывают и на записи, проброшенные
    дочерними логгерами через propagation.

    Args:
        name: Имя логгера
        level: Уровень логирования
        mask_secrets: Маскировать пароли и секреты

    Returns:
        Настроенный Logger

    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        logger.addHandler(handler)

    if mask_secrets:
        for handler in logger.handlers:
            if not any(
                isinstance(f, SecretMaskingFilter) for f in handler.filters
            ):
                handler.addFilter(SecretMaskingFilter())

    return logger
