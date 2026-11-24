# src/uniconn/mcp/storage.py
"""Облегчённый асинхронный слой состояния (StateStore Protocol, InMemory и stdlib SQLite WAL).

Предоставляет минимальный контракт ``StateStore`` с поддержкой:
- разделения по пространствам имён (``namespace``);
- оптимистических блокировок Compare-And-Swap (``expected_version``);
- TTL и очистки устаревших записей (``prune_expired``);
- изоляции арендаторов (``tenant_id`` / ``strict_tenant``).

Ядро библиотеки ``uniconn`` остаётся на 100% stateless и не требует БД;
встроенные реализации не добавляют ни одной внешней зависимости.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import sqlite3
import threading
import time
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Self, runtime_checkable

from ..exceptions import ConcurrencyConflictError

DEFAULT_STATE_DB_PATH: Path = Path.home() / ".uniconn" / "state.db"
HITL_STATE_NAMESPACE: str = "hitl_approvals"
FLOW_CHECKPOINT_NAMESPACE: str = "flow_checkpoints"
_META_STATE_NAMESPACE: str = "_uniconn_meta"

_SQLITE_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS state_entries (
        namespace TEXT NOT NULL,
        key TEXT NOT NULL,
        value_json TEXT NOT NULL,
        tenant_id TEXT,
        status TEXT,
        version INTEGER NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        expires_at REAL,
        PRIMARY KEY (namespace, key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_state_entries_ns_tenant_status
        ON state_entries (namespace, tenant_id, status)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_state_entries_ns_expires
        ON state_entries (namespace, expires_at)
    """,
)


def _normalize_tenant_id(tenant_id: str | None) -> str | None:
    """Нормализовать идентификатор арендатора (пустые строки приводятся к ``None``)."""
    return tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None


def _tenant_matches(
    record_tenant: str | None,
    query_tenant: str | None,
    *,
    strict_tenant: bool,
) -> bool:
    """Проверить соответствие арендатора записи с учётом режима ``strict_tenant``."""
    if strict_tenant or query_tenant is not None:
        return record_tenant == query_tenant
    return True


def _clone_json_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    """Сделать глубокую JSON-совместимую копию словаря для защиты от мутаций извне."""
    raw = json.dumps(dict(value), ensure_ascii=False)
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        raise ValueError("StateStore record value must serialize to a JSON object")
    return loaded


def _normalize_status(status: str | None) -> str | None:
    """Нормализовать строковый статус (пустые строки приводятся к ``None``)."""
    return status.strip() if isinstance(status, str) and status.strip() else None


def _compute_expires_at(now: float, ttl_seconds: float | None) -> float | None:
    """Проверить конечность ``ttl_seconds`` и вычислить ``expires_at``."""
    if ttl_seconds is None:
        return None
    ttl_val = float(ttl_seconds)
    if not math.isfinite(ttl_val):
        raise ValueError("ttl_seconds must be a finite number")
    return now + max(0.0, ttl_val)


def _validate_namespace_and_key(namespace: str, key: str) -> tuple[str, str]:
    ns = namespace.strip()
    k = key.strip()
    if not ns:
        raise ValueError("StateStore namespace must not be empty")
    if not k:
        raise ValueError("StateStore key must not be empty")
    return ns, k


def _clone_record(rec: StateRecord) -> StateRecord:
    """Создать копию ``StateRecord`` с глубокой копией ``value``."""
    return StateRecord(
        namespace=rec.namespace,
        key=rec.key,
        value=_clone_json_dict(rec.value),
        tenant_id=rec.tenant_id,
        status=rec.status,
        version=rec.version,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        expires_at=rec.expires_at,
    )


@dataclass(frozen=True, slots=True)
class StateRecord:
    """Иммутабельная запись состояния с версией CAS, метаданными арендатора и TTL."""

    namespace: str
    key: str
    value: dict[str, Any]
    tenant_id: str | None = None
    status: str | None = None
    version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0
    expires_at: float | None = None

    def is_expired(self, now: float | None = None) -> bool:
        """Проверить, истёк ли срок жизни записи ``expires_at``."""
        if self.expires_at is None:
            return False
        ref = time.time() if now is None else float(now)
        return ref >= self.expires_at


@runtime_checkable
class StateStore(Protocol):
    """Минимальный асинхронный контракт хранилища состояния с CAS, TTL и изоляцией тенантов."""

    async def get(
        self,
        namespace: str,
        key: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> StateRecord | None:
        """Получить запись по ``(namespace, key)`` с проверкой ``tenant_id`` (или ``None``)."""
        ...

    async def put(
        self,
        namespace: str,
        key: str,
        value: Mapping[str, Any],
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        ttl_seconds: float | None = None,
        expected_version: int | None = None,
    ) -> StateRecord:
        """Атомарно сохранить запись.

        Семантика ``expected_version``:
        - ``0``: вставка только новой записи (при существовании — ``ConcurrencyConflictError``);
        - ``>= 1``: оптимистическое обновление CAS (при расхождении версии — ``ConcurrencyConflictError``);
        - ``None``: безусловный upsert с инкрементом версии.
        """
        ...

    async def list(
        self,
        namespace: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
        status: str | None = None,
        include_expired: bool = False,
    ) -> list[StateRecord]:
        """Вернуть список записей namespace (отсортированных по ``created_at DESC``)."""
        ...

    async def delete(self, namespace: str, key: str) -> bool:
        """Удалить запись по ``(namespace, key)``; вернуть ``True``, если запись существовала."""
        ...

    async def prune_expired(self, namespace: str, *, now: float | None = None) -> int:
        """Удалить просроченные записи ``expires_at <= now`` и вернуть количество удалённых строк."""
        ...

    async def close(self) -> None:
        """Освободить ресурсы подключения хранилища."""
        ...


class InMemoryStateStore:
    """Zero-disk асинхронное хранилище в памяти (режим по умолчанию для SDK и тестов)."""

    def __init__(self) -> None:
        """Инициализировать пустое in-memory хранилище."""
        self._lock = asyncio.Lock()
        self._entries: dict[tuple[str, str], StateRecord] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def get(
        self,
        namespace: str,
        key: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> StateRecord | None:
        """Получить запись из памяти с проверкой ``tenant_id``."""
        ns, k = _validate_namespace_and_key(namespace, key)
        norm_tenant = _normalize_tenant_id(tenant_id)
        async with self._lock:
            rec = self._entries.get((ns, k))
            if rec is None:
                return None
            if not _tenant_matches(rec.tenant_id, norm_tenant, strict_tenant=strict_tenant):
                return None
            return _clone_record(rec)

    async def put(
        self,
        namespace: str,
        key: str,
        value: Mapping[str, Any],
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        ttl_seconds: float | None = None,
        expected_version: int | None = None,
    ) -> StateRecord:
        """Атомарно записать или обновить запись с проверкой ``expected_version``."""
        ns, k = _validate_namespace_and_key(namespace, key)
        if expected_version is not None and expected_version < 0:
            raise ValueError("expected_version must be >= 0 or None")
        norm_tenant = _normalize_tenant_id(tenant_id)
        norm_status = _normalize_status(status)
        cloned_val = _clone_json_dict(value)
        now = time.time()
        expires_at = _compute_expires_at(now, ttl_seconds)

        async with self._lock:
            existing = self._entries.get((ns, k))
            if expected_version == 0:
                if existing is not None:
                    raise ConcurrencyConflictError(
                        f"State entry ({ns!r}, {k!r}) already exists (version={existing.version})",
                        namespace=ns,
                        key=k,
                        expected_version=0,
                        actual_version=existing.version,
                    )
                new_version = 1
                created_at = now
            elif expected_version is not None:
                if existing is None or existing.version != expected_version:
                    actual_v = existing.version if existing is not None else None
                    raise ConcurrencyConflictError(
                        f"CAS version mismatch for ({ns!r}, {k!r}): "
                        f"expected={expected_version}, actual={actual_v}",
                        namespace=ns,
                        key=k,
                        expected_version=expected_version,
                        actual_version=actual_v,
                    )
                new_version = existing.version + 1
                created_at = existing.created_at
            else:
                new_version = (existing.version + 1) if existing is not None else 1
                created_at = existing.created_at if existing is not None else now

            stored = StateRecord(
                namespace=ns,
                key=k,
                value=cloned_val,
                tenant_id=norm_tenant,
                status=norm_status,
                version=new_version,
                created_at=created_at,
                updated_at=now,
                expires_at=expires_at,
            )
            self._entries[(ns, k)] = stored
            return _clone_record(stored)

    async def list(
        self,
        namespace: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
        status: str | None = None,
        include_expired: bool = False,
    ) -> list[StateRecord]:
        """Вернуть список записей namespace с фильтрацией по арендатору, статусу и TTL."""
        ns = namespace.strip()
        if not ns:
            raise ValueError("StateStore namespace must not be empty")
        norm_tenant = _normalize_tenant_id(tenant_id)
        norm_status = _normalize_status(status)
        now = time.time()

        async with self._lock:
            matched: list[StateRecord] = []
            for (rec_ns, _), rec in self._entries.items():
                if rec_ns != ns:
                    continue
                if not include_expired and rec.is_expired(now):
                    continue
                if not _tenant_matches(rec.tenant_id, norm_tenant, strict_tenant=strict_tenant):
                    continue
                if norm_status is not None and rec.status != norm_status:
                    continue
                matched.append(_clone_record(rec))
        matched.sort(key=lambda r: (r.created_at, r.key), reverse=True)
        return matched

    async def delete(self, namespace: str, key: str) -> bool:
        """Удалить запись из памяти."""
        ns, k = _validate_namespace_and_key(namespace, key)
        async with self._lock:
            return self._entries.pop((ns, k), None) is not None

    async def prune_expired(self, namespace: str, *, now: float | None = None) -> int:
        """Удалить просроченные записи ``namespace`` из памяти."""
        ns = namespace.strip()
        if not ns:
            raise ValueError("StateStore namespace must not be empty")
        ref = time.time() if now is None else float(now)
        async with self._lock:
            to_delete = [
                pair
                for pair, rec in self._entries.items()
                if pair[0] == ns and rec.is_expired(ref)
            ]
            for pair in to_delete:
                self._entries.pop(pair, None)
            return len(to_delete)

    async def close(self) -> None:
        """No-op закрытие in-memory хранилища."""
        return None


def _close_sqlite_conn(conn: sqlite3.Connection) -> None:
    with contextlib.suppress(Exception):
        conn.close()


class SQLiteStateStore:
    """Zero-dependency ACID-хранилище на stdlib ``sqlite3`` в режиме WAL для одиночных хостов и IPC."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_STATE_DB_PATH,
        *,
        busy_timeout_ms: int = 5000,
    ) -> None:
        """Открыть (или создать) БД SQLite в режиме WAL с проверкой симлинков и правами ``0o600``."""
        raw_str = str(db_path).strip()
        if not raw_str:
            raise ValueError("SQLiteStateStore db_path must not be empty")
        self._is_memory: bool = raw_str == ":memory:"
        self.db_path: Path | None = None if self._is_memory else Path(raw_str).expanduser()
        self._busy_timeout_ms = max(100, int(busy_timeout_ms))
        self._thread_lock = threading.Lock()
        self._closed = False
        self._sidecars_hardened = self._is_memory
        self._conn = self._open_and_init_sync()
        self._finalizer = weakref.finalize(self, _close_sqlite_conn, self._conn)

    def _validate_and_prepare_path_sync(self) -> str:
        if self._is_memory or self.db_path is None:
            return ":memory:"
        target = self.db_path
        if target.is_symlink():
            raise PermissionError(f"Refusing to open symlink SQLite state database: {target}")
        if target.is_dir():
            raise IsADirectoryError(f"SQLite state database path is a directory: {target}")
        for sidecar_suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{target}{sidecar_suffix}")
            if sidecar.is_symlink():
                raise PermissionError(f"Refusing to open symlink SQLite sidecar file: {sidecar}")
        parent_existed = target.parent.exists()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent_existed:
            with contextlib.suppress(OSError):
                os.chmod(target.parent, 0o700)
        return str(target)

    def _harden_file_permissions_sync(self, *, force: bool = False) -> None:
        if self._is_memory or self.db_path is None:
            return
        if self._sidecars_hardened and not force:
            return
        with contextlib.suppress(OSError):
            if self.db_path.exists() and not self.db_path.is_symlink():
                os.chmod(self.db_path, 0o600)
        hardened_sidecars = 0
        for sidecar_suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.db_path}{sidecar_suffix}")
            with contextlib.suppress(OSError):
                if sidecar.exists() and not sidecar.is_symlink():
                    os.chmod(sidecar, 0o600)
                    hardened_sidecars += 1
        if hardened_sidecars == 2:
            self._sidecars_hardened = True

    def _open_and_init_sync(self) -> sqlite3.Connection:
        dsn = self._validate_and_prepare_path_sync()
        conn = sqlite3.connect(
            dsn,
            timeout=self._busy_timeout_ms / 1000.0,
            isolation_level=None,  # Явное управление транзакциями BEGIN IMMEDIATE / COMMIT / ROLLBACK
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            conn.execute("PRAGMA temp_store = MEMORY")
            for attempt in range(5):
                try:
                    if not self._is_memory:
                        conn.execute("PRAGMA journal_mode = WAL")
                        conn.execute("PRAGMA synchronous = NORMAL")
                    for stmt in _SQLITE_SCHEMA_STATEMENTS:
                        conn.execute(stmt)
                    break
                except sqlite3.OperationalError as exc:
                    msg = str(exc).lower()
                    if ("locked" in msg or "busy" in msg) and attempt < 4:
                        time.sleep(0.05 * (attempt + 1))
                        continue
                    raise
        except Exception:
            conn.close()
            raise
        self._harden_file_permissions_sync(force=True)
        return conn

    def _ensure_open_locked(self) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("SQLiteStateStore is already closed")
        return self._conn

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> StateRecord:
        raw_val = json.loads(row["value_json"])
        val_dict = raw_val if isinstance(raw_val, dict) else {}
        return StateRecord(
            namespace=str(row["namespace"]),
            key=str(row["key"]),
            value=val_dict,
            tenant_id=str(row["tenant_id"]) if row["tenant_id"] is not None else None,
            status=str(row["status"]) if row["status"] is not None else None,
            version=int(row["version"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
        )

    def get_or_create_meta_sync(self, key: str, default_value: Mapping[str, Any]) -> dict[str, Any]:
        """Атомарно прочитать или инициализировать системный мета-ключ (синхронно для ``__init__``)."""
        ns, k = _validate_namespace_and_key(_META_STATE_NAMESPACE, key)
        serialized = json.dumps(_clone_json_dict(default_value), ensure_ascii=False)
        now = time.time()
        with self._thread_lock:
            conn = self._ensure_open_locked()
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO state_entries
                        (namespace, key, value_json, tenant_id, status, version, created_at, updated_at, expires_at)
                    VALUES (?, ?, ?, NULL, NULL, 1, ?, ?, NULL)
                    """,
                    (ns, k, serialized, now, now),
                )
                row = conn.execute(
                    "SELECT value_json FROM state_entries WHERE namespace = ? AND key = ?",
                    (ns, k),
                ).fetchone()
                conn.execute("COMMIT")
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            self._harden_file_permissions_sync()
            if row is None:
                return _clone_json_dict(default_value)
            loaded = json.loads(row["value_json"])
            return loaded if isinstance(loaded, dict) else _clone_json_dict(default_value)

    def _get_sync(
        self,
        ns: str,
        k: str,
        norm_tenant: str | None,
        strict_tenant: bool,
    ) -> StateRecord | None:
        with self._thread_lock:
            conn = self._ensure_open_locked()
            row = conn.execute(
                """
                SELECT namespace, key, value_json, tenant_id, status, version, created_at, updated_at, expires_at
                FROM state_entries
                WHERE namespace = ? AND key = ?
                """,
                (ns, k),
            ).fetchone()
        if row is None:
            return None
        rec = self._row_to_record(row)
        if not _tenant_matches(rec.tenant_id, norm_tenant, strict_tenant=strict_tenant):
            return None
        return rec

    def _put_sync(
        self,
        ns: str,
        k: str,
        value: dict[str, Any],
        norm_tenant: str | None,
        norm_status: str | None,
        ttl_seconds: float | None,
        expected_version: int | None,
    ) -> StateRecord:
        serialized = json.dumps(value, ensure_ascii=False)
        now = time.time()
        expires_at = _compute_expires_at(now, ttl_seconds)

        with self._thread_lock:
            conn = self._ensure_open_locked()
            conn.execute("BEGIN IMMEDIATE")
            try:
                if expected_version == 0:
                    try:
                        conn.execute(
                            """
                            INSERT INTO state_entries
                                (namespace, key, value_json, tenant_id, status,
                                 version, created_at, updated_at, expires_at)
                            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                            """,
                            (ns, k, serialized, norm_tenant, norm_status, now, now, expires_at),
                        )
                    except sqlite3.IntegrityError as exc:
                        row = conn.execute(
                            "SELECT version FROM state_entries WHERE namespace = ? AND key = ?",
                            (ns, k),
                        ).fetchone()
                        actual_v = int(row["version"]) if row is not None else None
                        conn.execute("ROLLBACK")
                        raise ConcurrencyConflictError(
                            f"State entry ({ns!r}, {k!r}) already exists (version={actual_v})",
                            namespace=ns,
                            key=k,
                            expected_version=0,
                            actual_version=actual_v,
                        ) from exc
                    new_version = 1
                    created_at = now
                elif expected_version is not None:
                    cur = conn.execute(
                        """
                        UPDATE state_entries
                        SET value_json = ?, tenant_id = ?, status = ?,
                            version = version + 1, updated_at = ?, expires_at = ?
                        WHERE namespace = ? AND key = ? AND version = ?
                        """,
                        (serialized, norm_tenant, norm_status, now, expires_at, ns, k, expected_version),
                    )
                    if cur.rowcount == 0:
                        row = conn.execute(
                            "SELECT version FROM state_entries WHERE namespace = ? AND key = ?",
                            (ns, k),
                        ).fetchone()
                        actual_v = int(row["version"]) if row is not None else None
                        conn.execute("ROLLBACK")
                        raise ConcurrencyConflictError(
                            f"CAS version mismatch for ({ns!r}, {k!r}): "
                            f"expected={expected_version}, actual={actual_v}",
                            namespace=ns,
                            key=k,
                            expected_version=expected_version,
                            actual_version=actual_v,
                        )
                    meta_row = conn.execute(
                        "SELECT version, created_at FROM state_entries WHERE namespace = ? AND key = ?",
                        (ns, k),
                    ).fetchone()
                    new_version = int(meta_row["version"])
                    created_at = float(meta_row["created_at"])
                else:
                    conn.execute(
                        """
                        INSERT INTO state_entries
                            (namespace, key, value_json, tenant_id, status,
                             version, created_at, updated_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                        ON CONFLICT(namespace, key) DO UPDATE SET
                            value_json = excluded.value_json,
                            tenant_id = excluded.tenant_id,
                            status = excluded.status,
                            version = state_entries.version + 1,
                            updated_at = excluded.updated_at,
                            expires_at = excluded.expires_at
                        """,
                        (ns, k, serialized, norm_tenant, norm_status, now, now, expires_at),
                    )
                    meta_row = conn.execute(
                        "SELECT version, created_at FROM state_entries WHERE namespace = ? AND key = ?",
                        (ns, k),
                    ).fetchone()
                    new_version = int(meta_row["version"])
                    created_at = float(meta_row["created_at"])

                conn.execute("COMMIT")
            except ConcurrencyConflictError:
                raise
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            self._harden_file_permissions_sync()

        return StateRecord(
            namespace=ns,
            key=k,
            value=value,
            tenant_id=norm_tenant,
            status=norm_status,
            version=new_version,
            created_at=created_at,
            updated_at=now,
            expires_at=expires_at,
        )

    def _list_sync(
        self,
        ns: str,
        norm_tenant: str | None,
        strict_tenant: bool,
        norm_status: str | None,
        include_expired: bool,
    ) -> list[StateRecord]:
        clauses: list[str] = ["namespace = ?"]
        params: list[Any] = [ns]
        if strict_tenant or norm_tenant is not None:
            if norm_tenant is None:
                clauses.append("tenant_id IS NULL")
            else:
                clauses.append("tenant_id = ?")
                params.append(norm_tenant)
        if norm_status is not None:
            clauses.append("status = ?")
            params.append(norm_status)
        if not include_expired:
            clauses.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(time.time())

        sql = (
            "SELECT namespace, key, value_json, tenant_id, status, version, created_at, updated_at, expires_at "
            f"FROM state_entries WHERE {' AND '.join(clauses)} "
            "ORDER BY created_at DESC, key DESC"
        )
        with self._thread_lock:
            conn = self._ensure_open_locked()
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def _delete_sync(self, ns: str, k: str) -> bool:
        with self._thread_lock:
            conn = self._ensure_open_locked()
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "DELETE FROM state_entries WHERE namespace = ? AND key = ?",
                    (ns, k),
                )
                conn.execute("COMMIT")
                return cur.rowcount > 0
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise

    def _prune_expired_sync(self, ns: str, ref: float) -> int:
        with self._thread_lock:
            conn = self._ensure_open_locked()
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "DELETE FROM state_entries WHERE namespace = ? AND expires_at IS NOT NULL AND expires_at <= ?",
                    (ns, ref),
                )
                conn.execute("COMMIT")
                return cur.rowcount
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise

    def close_sync(self) -> None:
        """Синхронно закрыть соединение SQLite."""
        with self._thread_lock:
            if not self._closed:
                self._closed = True
                self._finalizer.detach()
                _close_sqlite_conn(self._conn)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def get(
        self,
        namespace: str,
        key: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> StateRecord | None:
        """Асинхронно получить запись из SQLite WAL."""
        ns, k = _validate_namespace_and_key(namespace, key)
        norm_tenant = _normalize_tenant_id(tenant_id)
        return await asyncio.to_thread(self._get_sync, ns, k, norm_tenant, strict_tenant)

    async def put(
        self,
        namespace: str,
        key: str,
        value: Mapping[str, Any],
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        ttl_seconds: float | None = None,
        expected_version: int | None = None,
    ) -> StateRecord:
        """Асинхронно выполнить атомарную запись / CAS-обновление в SQLite WAL."""
        ns, k = _validate_namespace_and_key(namespace, key)
        if expected_version is not None and expected_version < 0:
            raise ValueError("expected_version must be >= 0 or None")
        norm_tenant = _normalize_tenant_id(tenant_id)
        norm_status = _normalize_status(status)
        if ttl_seconds is not None and not math.isfinite(float(ttl_seconds)):
            raise ValueError("ttl_seconds must be a finite number")
        cloned_val = _clone_json_dict(value)
        return await asyncio.to_thread(
            self._put_sync,
            ns,
            k,
            cloned_val,
            norm_tenant,
            norm_status,
            ttl_seconds,
            expected_version,
        )

    async def list(
        self,
        namespace: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
        status: str | None = None,
        include_expired: bool = False,
    ) -> list[StateRecord]:
        """Асинхронно вернуть список записей namespace из SQLite WAL."""
        ns = namespace.strip()
        if not ns:
            raise ValueError("StateStore namespace must not be empty")
        norm_tenant = _normalize_tenant_id(tenant_id)
        norm_status = _normalize_status(status)
        return await asyncio.to_thread(
            self._list_sync,
            ns,
            norm_tenant,
            strict_tenant,
            norm_status,
            include_expired,
        )

    async def delete(self, namespace: str, key: str) -> bool:
        """Асинхронно удалить запись из SQLite WAL."""
        ns, k = _validate_namespace_and_key(namespace, key)
        return await asyncio.to_thread(self._delete_sync, ns, k)

    async def prune_expired(self, namespace: str, *, now: float | None = None) -> int:
        """Асинхронно удалить просроченные записи ``namespace`` из SQLite WAL."""
        ns = namespace.strip()
        if not ns:
            raise ValueError("StateStore namespace must not be empty")
        ref = time.time() if now is None else float(now)
        return await asyncio.to_thread(self._prune_expired_sync, ns, ref)

    async def close(self) -> None:
        """Асинхронно закрыть соединение SQLite."""
        await asyncio.to_thread(self.close_sync)


def resolve_state_store(
    store_path: str | Path | None = None,
    *,
    backend: str | None = None,
    backend_options: Mapping[str, Any] | None = None,
) -> tuple[StateStore, Path | None]:
    """Создать ``StateStore`` (``SQLiteStateStore``, ``InMemoryStateStore`` или плагин ``uniconn.storage``)."""
    raw = str(store_path).strip() if store_path is not None else ""
    opts = dict(backend_options or {})

    if backend is not None and backend.strip():
        from ..plugins._loader import (
            PluginLoader,
            _callable_accepts_positional,
            _callable_has_explicit_kwarg,
        )

        backend_name = PluginLoader.normalize_name(backend, group="uniconn.storage")
        loaded = PluginLoader.load("uniconn.storage", backend_name)

        if loaded is InMemoryStateStore:
            return InMemoryStateStore(), None
        if loaded is SQLiteStateStore:
            sqlite_path: str | Path = raw or str(opts.pop("db_path", "")).strip() or DEFAULT_STATE_DB_PATH
            if isinstance(sqlite_path, str):
                if sqlite_path.lower().startswith("sqlite://"):
                    sqlite_path = sqlite_path[len("sqlite://") :]
                    if sqlite_path in ("", "/:memory:", ":memory:"):
                        return InMemoryStateStore(), None
                elif sqlite_path == ":memory:":
                    return InMemoryStateStore(), None
            sqlite_store = SQLiteStateStore(sqlite_path, **opts)
            return sqlite_store, sqlite_store.db_path

        if isinstance(loaded, StateStore) and not isinstance(loaded, type):
            instance: Any = loaded
        elif isinstance(loaded, type) or callable(loaded):
            wants_raw = bool(raw) and "db_path" not in opts and "uri" not in opts and "url" not in opts
            if wants_raw and _callable_accepts_positional(loaded):
                instance = loaded(raw, **opts)
            elif wants_raw:
                kw_target = next(
                    (p for p in ("uri", "url", "db_path") if _callable_has_explicit_kwarg(loaded, p)),
                    None,
                )
                instance = loaded(**{kw_target: raw, **opts}) if kw_target else loaded(**opts)
            else:
                instance = loaded(**opts)
        else:
            instance = loaded

        PluginLoader.validate_contract(instance, StateStore, group="uniconn.storage", name=backend_name)
        return instance, getattr(instance, "db_path", None)

    if raw and "://" in raw:
        scheme, _, rest = raw.partition("://")
        norm_scheme = scheme.strip().lower()
        if norm_scheme == "file":
            file_target = rest.strip()
            if not file_target or file_target in (":memory:", "/:memory:"):
                return InMemoryStateStore(), None
            sqlite_store = SQLiteStateStore(file_target, **opts)
            return sqlite_store, sqlite_store.db_path
        if norm_scheme and norm_scheme[0].isalpha() and all(
            ch.isalnum() or ch in "+.-_" for ch in norm_scheme
        ):
            return resolve_state_store(raw, backend=norm_scheme, backend_options=opts)

    if raw and raw != ":memory:":
        sqlite_store = SQLiteStateStore(raw)
        return sqlite_store, sqlite_store.db_path
    return InMemoryStateStore(), None


async def sync_meta_secret(
    store: StateStore,
    meta_key: str,
    candidate: str,
) -> str:
    """Атомарно прочитать или зарегистрировать общий системный секрет в ``_uniconn_meta`` через CAS."""
    existing = await store.get(_META_STATE_NAMESPACE, meta_key)
    if existing is not None and isinstance(existing.value.get("secret"), str) and existing.value["secret"]:
        return str(existing.value["secret"])
    try:
        await store.put(
            _META_STATE_NAMESPACE,
            meta_key,
            {"secret": candidate},
            expected_version=0,
        )
        return candidate
    except ConcurrencyConflictError:
        winner = await store.get(_META_STATE_NAMESPACE, meta_key)
        if winner is not None and isinstance(winner.value.get("secret"), str) and winner.value["secret"]:
            return str(winner.value["secret"])
        return candidate


__all__ = [
    "DEFAULT_STATE_DB_PATH",
    "FLOW_CHECKPOINT_NAMESPACE",
    "HITL_STATE_NAMESPACE",
    "InMemoryStateStore",
    "SQLiteStateStore",
    "StateRecord",
    "StateStore",
]
