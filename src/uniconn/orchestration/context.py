# src/uniconn/orchestration/context.py
"""Контекст выполнения сценария оркестрации Flow."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import TaskResult


def normalize_host_id(host_or_conn: Any) -> tuple[str, str]:
    """Вернуть кортеж ``(primary_key, short_host)`` для строки или объекта соединения.

    Позволяет прозрачно обращаться к переменным хоста как по URI-ключу пула
    (``ssh://admin@web-01:2222``), так и по короткому имени хоста (``web-01``)
    или передавая сам экземпляр ``Connection`` / ``SyncConnection``.
    """
    if isinstance(host_or_conn, str):
        raw = host_or_conn
        after_scheme = raw.split("://", 1)[-1]
        after_at = after_scheme.rsplit("@", 1)[-1]
        short = after_at.split(":", 1)[0].split("/", 1)[0] or raw
        return raw, short

    cfg = getattr(host_or_conn, "config", None)
    if cfg is not None:
        cfg_host = getattr(cfg, "host", None)
        uri_safe = getattr(cfg, "uri_safe", None)
        primary = str(cfg_host or uri_safe or host_or_conn)
        short = str(cfg_host or primary.split("://", 1)[-1])
        return primary, short

    host_attr = getattr(host_or_conn, "host", None)
    if isinstance(host_attr, str) and host_attr:
        return host_attr, host_attr

    text = str(host_or_conn)
    return text, text


class FlowContext:
    """Потокобезопасный и корутино-безопасный контекст выполнения сценария ``Flow``.

    Хранит общие переменные сценария (``get`` / ``set``), изолированные переменные
    отдельных хостов (``host_get`` / ``host_set``) и результаты уже выполненных
    задач (``get_task_result``).
    """

    def __init__(
        self,
        flow_name: str = "uniconn_flow",
        initial_vars: Mapping[str, Any] | None = None,
    ) -> None:
        """Инициализировать контекст сценария ``Flow``."""
        self.flow_name = flow_name
        self._shared_vars: dict[str, Any] = dict(initial_vars or {})
        self._host_vars: dict[str, dict[str, Any]] = {}
        self._host_aliases: dict[str, str] = {}
        self._task_results: dict[str, dict[str, TaskResult]] = {}
        self._lock = asyncio.Lock()
        self._thread_lock = threading.RLock()

    @property
    def lock(self) -> asyncio.Lock:
        """Асинхронная блокировка контекста для пользовательских критических секций."""
        return self._lock

    @property
    def vars(self) -> dict[str, Any]:
        """Копия словаря глобальных переменных сценария."""
        with self._thread_lock:
            return dict(self._shared_vars)

    def register_host_alias(self, pool_key: str, conn: Any) -> None:
        """Связать ключ хоста из пула с коротким именем ``conn.config.host``."""
        primary, short = normalize_host_id(conn)
        with self._thread_lock:
            self._host_aliases[pool_key] = pool_key
            if primary:
                self._host_aliases.setdefault(primary, pool_key)
            if short:
                self._host_aliases.setdefault(short, pool_key)

    def _resolve_host_bucket(self, host_or_conn: Any) -> str:
        """Разрешить канонический ключ хоста в словаре ``_host_vars``."""
        primary, short = normalize_host_id(host_or_conn)
        if primary in self._host_aliases:
            return self._host_aliases[primary]
        if short in self._host_aliases:
            return self._host_aliases[short]
        if primary in self._host_vars:
            return primary
        if short in self._host_vars:
            return short
        return short or primary

    def get(self, key: str, default: Any = None) -> Any:
        """Получить значение общей переменной сценария."""
        with self._thread_lock:
            return self._shared_vars.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Установить значение общей переменной сценария."""
        with self._thread_lock:
            self._shared_vars[key] = value

    def update(self, mapping: Mapping[str, Any] | None = None, **kwargs: Any) -> None:
        """Массово обновить общие переменные сценария."""
        with self._thread_lock:
            if mapping:
                self._shared_vars.update(mapping)
            if kwargs:
                self._shared_vars.update(kwargs)

    def host_get(self, host_or_conn: Any, key: str, default: Any = None) -> Any:
        """Получить значение переменной для конкретного хоста."""
        with self._thread_lock:
            bucket = self._resolve_host_bucket(host_or_conn)
            if bucket in self._host_vars and key in self._host_vars[bucket]:
                return self._host_vars[bucket][key]
            primary, short = normalize_host_id(host_or_conn)
            for candidate in (primary, short):
                if candidate in self._host_vars and key in self._host_vars[candidate]:
                    return self._host_vars[candidate][key]
            return default

    def host_set(self, host_or_conn: Any, key: str, value: Any) -> None:
        """Установить значение переменной для конкретного хоста."""
        with self._thread_lock:
            bucket = self._resolve_host_bucket(host_or_conn)
            self._host_vars.setdefault(bucket, {})[key] = value
            primary, short = normalize_host_id(host_or_conn)
            for candidate in (primary, short):
                if candidate and candidate != bucket:
                    self._host_aliases.setdefault(candidate, bucket)

    def host_vars(self, host_or_conn: Any) -> dict[str, Any]:
        """Вернуть копию всех переменных, сохранённых для указанного хоста."""
        with self._thread_lock:
            bucket = self._resolve_host_bucket(host_or_conn)
            return dict(self._host_vars.get(bucket, {}))

    def record_task_result(self, host_or_conn: Any, result: TaskResult) -> None:
        """Записать результат выполнения задачи для хоста."""
        with self._thread_lock:
            bucket = self._resolve_host_bucket(host_or_conn)
            self._task_results.setdefault(bucket, {})[result.task_name] = result

    def get_task_result(
        self, host_or_conn: Any, task_or_name: Any
    ) -> TaskResult | None:
        """Получить ``TaskResult`` ранее выполненной задачи на указанном хосте."""
        task_name = (
            task_or_name
            if isinstance(task_or_name, str)
            else getattr(task_or_name, "name", str(task_or_name))
        )
        with self._thread_lock:
            bucket = self._resolve_host_bucket(host_or_conn)
            return self._task_results.get(bucket, {}).get(task_name)

    def get_result(
        self,
        task_or_name: Any,
        host: Any = None,
        default: Any = None,
    ) -> Any:
        """Получить возвращаемое значение (``return_value``) ранее выполненной задачи."""
        task_name = (
            task_or_name
            if isinstance(task_or_name, str)
            else getattr(task_or_name, "name", str(task_or_name))
        )
        with self._thread_lock:
            if host is not None:
                res = self.get_task_result(host, task_name)
                if res is not None and res.return_value is not None:
                    return res.return_value
                return default
            for host_map in self._task_results.values():
                if task_name in host_map and host_map[task_name].return_value is not None:
                    return host_map[task_name].return_value
            return default


__all__ = [
    "FlowContext",
    "normalize_host_id",
]
