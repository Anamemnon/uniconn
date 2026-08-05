# src/uniconn/_logging.py
import logging
import logging.handlers
import re
from pathlib import Path
from typing import Literal


class SecretMaskingFilter(logging.Filter):
    """Фильтр для маскирования чувствительных данных в логах."""

    PATTERNS = [
        (re.compile(r'password[=:]\S+', re.IGNORECASE), 'password=***'),
        (re.compile(r'pass[=:]\S+', re.IGNORECASE), 'pass=***'),
        (re.compile(r'secret[=:]\S+', re.IGNORECASE), 'secret=***'),
        (re.compile(r'token[=:]\S+', re.IGNORECASE), 'token=***'),
        (re.compile(r'://[^:]+:[^@]+@', re.IGNORECASE), '://***:***@'),
    ]

    def __init__(self, name: str = ""):
        super().__init__(name)
        self._enabled = True

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._enabled:
            return True

        # Маскирование message
        if isinstance(record.msg, str):
            for pattern, replacement in self.PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)

        # Маскирование args
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    self._mask_value(arg) for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: self._mask_value(v) for k, v in record.args.items()
                }

        return True

    def _mask_value(self, value) -> str:
        if isinstance(value, str):
            for pattern, replacement in self.PATTERNS:
                value = pattern.sub(replacement, value)
        return value


# ─── Форматтеры ────────────────────────────────────────────────────

DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DETAILED_FORMAT = (
    '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d'
    ' - %(message)s'
)


def _create_handler(
    handler: logging.Handler,
    level: int,
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
    level: int = logging.DEBUG,
    fmt: str = DEFAULT_FORMAT,
    mask_secrets: bool = True,
    rotation: Literal["size", "time"] = "size",
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    when: str = "midnight",
    interval: int = 1,
    logger_name: str = "uniconn",
    also_console: bool = False,
) -> logging.Logger:
    """Настроить логирование в файл с ротацией.

    Поддерживает два режима ротации:
    - **size**: RotatingFileHandler — ротация по размеру файла
    - **time**: TimedRotatingFileHandler — ротация по времени

    Args:
        log_file: Путь к файлу лога
        level: Уровень логирования (DEBUG, INFO, WARNING, ERROR)
        fmt: Формат сообщений
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

    Returns:
        Настроенный Logger

    Примеры:
        Ротация по размеру (10 МБ, 5 backups)::

            logger = setup_file_logging(
                "uniconn.log",
                rotation="size",
                max_bytes=10_000_000,
                backup_count=5,
            )

        Ротация по времени (каждый день, 7 backups)::

            logger = setup_file_logging(
                "uniconn.log",
                rotation="time",
                when="midnight",
                interval=1,
                backup_count=7,
            )

        С консольным выводом::

            logger = setup_file_logging(
                "uniconn.log", also_console=True
            )
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)  # Логируем всё, фильтрация на handler

    # Создаём Path
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Файловый handler с ротацией
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

    _create_handler(file_handler, level, fmt, mask_secrets)
    logger.addHandler(file_handler)

    # Опционально консольный handler
    if also_console:
        console_handler = logging.StreamHandler()
        _create_handler(console_handler, logging.INFO, fmt, mask_secrets)
        logger.addHandler(console_handler)

    return logger


def get_logger(
    name: str = "uniconn",
    level: int = logging.INFO,
    mask_secrets: bool = True
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
