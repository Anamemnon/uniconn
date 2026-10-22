# src/uniconn/hooks.py
"""Готовые пресеты lifecycle-хуков для аудита, безопасности и метрик (v0.6.0).

Используются совместно с ``Connection.add_hook()`` или параметрами
``before_run`` / ``after_run`` / ``on_error``:

Пример:
    >>> from uniconn import Connection
    >>> from uniconn.hooks import (
    ...     allowlist_hook,
    ...     audit_log_hook,
    ...     blocklist_hook,
    ...     metrics_collector_hook,
    ... )
    >>> conn = Connection.from_uri("ssh://admin@server")
    >>> conn.add_hook("before_run", allowlist_hook(["uptime", "df", "ls", "systemctl status"]))
    >>> conn.add_hook("before_run", blocklist_hook())
    >>> conn.add_hook("after_run", audit_log_hook("/tmp/audit.jsonl"))
    >>> metrics = metrics_collector_hook().attach(conn)
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from ._logging import get_struct_logger, log_event
from .result import Result

DEFAULT_BLOCKED_PATTERNS: tuple[str, ...] = (
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/($|\s)",
    r"\bmkfs(\.[a-z0-9]+)?\b",
    r"\bdd\s+if=/dev/(zero|random|urandom)\b",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;:",
    r"\b(shutdown|poweroff|halt)\b",
)


def audit_log_hook(
    path: str | Path,
    *,
    include_output: bool = False,
) -> Callable[[Result], None]:
    """Создать хук ``after_run`` для записи JSONL-лога аудита выполненных команд.

    При ``result.sensitive == True`` команда и потоки вывода маскируются
    строкой ``"***REDACTED***"``.

    Args:
        path: Путь к JSONL-файлу аудита
        include_output: Включать ли ``stdout`` и ``stderr`` в запись

    Returns:
        Функция обратного вызова для ``conn.add_hook("after_run", ...)``

    """
    log_path = Path(path)

    def _on_after_run(result: Result) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "host": result.host,
            "command": "***REDACTED***" if result.sensitive else result.command,
            "exit_code": result.exit_code,
            "ok": result.ok,
            "duration": round(result.duration, 6),
            "sensitive": result.sensitive,
        }
        if include_output:
            entry["stdout"] = "***REDACTED***" if result.sensitive else result.stdout
            entry["stderr"] = "***REDACTED***" if result.sensitive else result.stderr

        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return _on_after_run


def allowlist_hook(
    allowed_prefixes: Sequence[str],
) -> Callable[[str, str | None, dict[str, Any]], None]:
    """Создать хук ``before_run``, разрешающий только команды из белого списка.

    Проверяет, что выполняемая команда (или её базовый исполняемый файл)
    начинается с одного из разрешённых префиксов.

    Args:
        allowed_prefixes: Список разрешённых команд или префиксов

    Returns:
        Функция обратного вызова для ``conn.add_hook("before_run", ...)``

    Raises:
        PermissionError: Если команда не входит в белый список

    """
    normalized = [p.strip() for p in allowed_prefixes if p.strip()]

    def _on_before_run(
        command: str,
        host: str | None,
        _kwargs: dict[str, Any],
    ) -> None:
        cmd_stripped = command.strip()
        if not cmd_stripped:
            raise PermissionError(f"Empty command is not allowed on host {host!r}")

        try:
            tokens = shlex.split(cmd_stripped)
        except ValueError:
            tokens = cmd_stripped.split()

        first_token = tokens[0] if tokens else ""
        for prefix in normalized:
            if (
                cmd_stripped == prefix
                or cmd_stripped.startswith(f"{prefix} ")
                or first_token == prefix
            ):
                return

        raise PermissionError(
            f"Command {cmd_stripped!r} on host {host!r} is not permitted by allowlist"
        )

    return _on_before_run


def blocklist_hook(
    blocked_patterns: Sequence[str] | None = None,
) -> Callable[[str, str | None, dict[str, Any]], None]:
    """Создать хук ``before_run``, блокирующий потенциально опасные команды.

    Args:
        blocked_patterns: Список регулярных выражений или подстрок для блокировки.
            Если ``None``, используется стандартный набор опасных паттернов
            (``rm -rf /``, ``mkfs``, ``dd if=/dev/zero``, fork-бомба, ``shutdown``).

    Returns:
        Функция обратного вызова для ``conn.add_hook("before_run", ...)``

    Raises:
        PermissionError: Если команда совпала с одним из запрещённых паттернов

    """
    patterns = (
        list(DEFAULT_BLOCKED_PATTERNS)
        if blocked_patterns is None
        else list(blocked_patterns)
    )
    compiled = [re.compile(p) for p in patterns]

    def _on_before_run(
        command: str,
        host: str | None,
        _kwargs: dict[str, Any],
    ) -> None:
        cmd_stripped = command.strip()
        for regex, raw_pat in zip(compiled, patterns, strict=True):
            if regex.search(cmd_stripped) or raw_pat in cmd_stripped:
                raise PermissionError(
                    f"Command {cmd_stripped!r} on host {host!r} blocked by pattern {raw_pat!r}"
                )

    return _on_before_run


class MetricsCollector:
    """Сборщик метрик выполнения команд через lifecycle-хуки ``Connection``."""

    def __init__(self) -> None:
        """Инициализировать счётчики метрик."""
        self.total_runs: int = 0
        self.failed_runs: int = 0
        self.errors_count: int = 0
        self.total_duration: float = 0.0
        self.by_host: dict[str, dict[str, int | float]] = {}

    @property
    def avg_duration(self) -> float:
        """Среднее время выполнения команды в секундах."""
        if self.total_runs == 0:
            return 0.0
        return self.total_duration / self.total_runs

    def after_run(self, result: Result) -> None:
        """Обработчик события ``after_run``."""
        self.total_runs += 1
        self.total_duration += result.duration
        if not result.ok:
            self.failed_runs += 1

        host_key = result.host or "unknown"
        stats = self.by_host.setdefault(
            host_key,
            {"runs": 0, "failed": 0, "errors": 0, "duration": 0.0},
        )
        stats["runs"] = int(stats["runs"]) + 1
        if not result.ok:
            stats["failed"] = int(stats["failed"]) + 1
        stats["duration"] = float(stats["duration"]) + result.duration

    def on_error(
        self,
        _exc: BaseException,
        _command: str,
        host: str | None,
    ) -> None:
        """Обработчик события ``on_error``."""
        self.errors_count += 1
        host_key = host or "unknown"
        stats = self.by_host.setdefault(
            host_key,
            {"runs": 0, "failed": 0, "errors": 0, "duration": 0.0},
        )
        stats["errors"] = int(stats["errors"]) + 1

    def attach(self, conn: Any) -> Self:
        """Привязать сборщик метрик к ``Connection`` или ``SyncConnection``."""
        conn.add_hook("after_run", self.after_run)
        conn.add_hook("on_error", self.on_error)
        return self

    def reset(self) -> None:
        """Сбросить накопленные метрики."""
        self.total_runs = 0
        self.failed_runs = 0
        self.errors_count = 0
        self.total_duration = 0.0
        self.by_host.clear()

    def to_dict(self) -> dict[str, Any]:
        """Вернуть сводку метрик в виде словаря."""
        return {
            "total_runs": self.total_runs,
            "failed_runs": self.failed_runs,
            "errors_count": self.errors_count,
            "total_duration": round(self.total_duration, 6),
            "avg_duration": round(self.avg_duration, 6),
            "by_host": dict(self.by_host),
        }


def metrics_collector_hook() -> MetricsCollector:
    """Создать новый экземпляр ``MetricsCollector`` для сбора метрик выполнения."""
    return MetricsCollector()


def structured_log_hook(
    logger: Any = None,
    *,
    level: int = logging.INFO,
    include_output: bool = False,
    tags: dict[str, Any] | None = None,
) -> Callable[[Result], None]:
    """Создать хук ``after_run`` для отправки структурированных метрик в ``structlog``.

    Формирует событие ``command.executed`` с полями ``host``, ``command``,
    ``exit_code``, ``ok``, ``duration_ms``, ``stdout_bytes``, ``stderr_bytes`` и
    произвольными ``tags``, оптимизированными для сохранения в ClickHouse,
    InfluxDB или Grafana Loki.

    Args:
        logger: Экземпляр ``structlog`` или ``logging.Logger`` (по умолчанию
            ``get_struct_logger("uniconn.telemetry")``)
        level: Уровень логирования (по умолчанию ``logging.INFO``)
        include_output: Включать ли ``stdout`` и ``stderr`` в событие
        tags: Дополнительные теги/метки (например, ``{"env": "prod", "cluster": "eu"}``)

    Returns:
        Функция обратного вызова для ``conn.add_hook("after_run", ...)``

    """
    target_logger = logger if logger is not None else get_struct_logger("uniconn.telemetry")
    extra_tags = dict(tags) if tags else {}

    def _on_after_run(result: Result) -> None:
        fields: dict[str, Any] = {
            **extra_tags,
            "host": result.host,
            "command": "***REDACTED***" if result.sensitive else result.command,
            "exit_code": result.exit_code,
            "ok": result.ok,
            "duration": round(result.duration, 6),
            "duration_ms": round(result.duration * 1000, 3),
            "stdout_bytes": len(result.stdout.encode("utf-8")),
            "stderr_bytes": len(result.stderr.encode("utf-8")),
            "sensitive": result.sensitive,
        }
        if include_output:
            fields["stdout"] = "***REDACTED***" if result.sensitive else result.stdout
            fields["stderr"] = "***REDACTED***" if result.sensitive else result.stderr

        log_event(
            target_logger,
            level,
            "command.executed",
            f"command.executed on {result.host} (exit_code={result.exit_code})",
            **fields,
        )

    return _on_after_run

