# src/uniconn/mcp/sessions.py
"""Менеджер привязанных к тенанту и идентичности сессий MCP Streamable HTTP и SSE-брокер."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .auth import CallerIdentity


class MCPSessionError(Exception):
    """Базовое исключение управления сессиями MCP Streamable HTTP."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class MCPSessionNotFoundError(MCPSessionError):
    """Сессия ``Mcp-Session-Id`` не найдена или истекла по TTL (HTTP 404)."""

    def __init__(self, message: str = "MCP session not found or expired") -> None:
        super().__init__(message, status_code=404)


class MCPSessionForbiddenError(MCPSessionError):
    """Попытка использовать чужой ``Mcp-Session-Id`` другого тенанта/субъекта (HTTP 403)."""

    def __init__(self, message: str = "MCP session belongs to another principal") -> None:
        super().__init__(message, status_code=403)


class MCPSessionLimitError(MCPSessionError):
    """Превышен лимит активных сессий на тенанта (HTTP 429)."""

    def __init__(self, message: str = "Maximum active MCP sessions per tenant exceeded") -> None:
        super().__init__(message, status_code=429)


@dataclass(slots=True)
class MCPSession:
    """Состояние сетевой MCP-сессии, жёстко привязанной к ``(tenant_id, agent_id, role)``."""

    session_id: str
    tenant_id: str | None
    agent_id: str
    role: str
    auth_method: str
    protocol_version: str
    cert_thumbprint_sha256: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    event_counter: int = 0
    sse_queues: list[asyncio.Queue[tuple[str, str, str] | None]] = field(default_factory=list)

    def matches_identity(self, identity: CallerIdentity) -> bool:
        """Проверить совпадение владельца сессии с криптографической идентичностью вызывающего."""
        if (
            self.tenant_id != identity.tenant_id
            or self.agent_id != identity.agent_id
            or self.role != identity.role
        ):
            return False
        if self.cert_thumbprint_sha256 is not None:
            if not identity.cert_thumbprint_sha256:
                return False
            return hmac.compare_digest(self.cert_thumbprint_sha256, identity.cert_thumbprint_sha256)
        return True

    def next_event_id(self) -> str:
        """Сгенерировать монотонный идентификатор SSE-события в рамках сессии."""
        self.event_counter += 1
        return f"{self.session_id[:12]}-{self.event_counter}"


class MCPSessionManager:
    """Хранилище активных MCP-сессий с idle-TTL, квотами на тенант и SSE-подписками."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 1800.0,
        max_sessions_per_tenant: int = 100,
        max_total_sessions: int = 10_000,
    ) -> None:
        """Инициализировать менеджер сессий с idle-TTL, квотой на тенант и глобальным лимитом."""
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.max_sessions_per_tenant = max(1, int(max_sessions_per_tenant))
        self.max_total_sessions = max(1, int(max_total_sessions))
        self._sessions: dict[str, MCPSession] = {}

    def prune_expired(self, *, now: float | None = None) -> int:
        """Удалить просроченные по idle-TTL сессии и закрыть их SSE-подписки."""
        ref = time.monotonic() if now is None else now
        expired_ids = [
            sid
            for sid, sess in self._sessions.items()
            if (ref - sess.last_seen) >= self.ttl_seconds
        ]
        for sid in expired_ids:
            sess = self._sessions.pop(sid, None)
            if sess is not None:
                self._close_queues(sess)
        return len(expired_ids)

    def create_session(
        self,
        identity: CallerIdentity,
        *,
        protocol_version: str,
    ) -> MCPSession:
        """Создать криптографически стойкую 256-битную сессию, привязанную к ``identity``."""
        self.prune_expired()
        if len(self._sessions) >= self.max_total_sessions:
            raise MCPSessionLimitError(
                f"Global active MCP session limit ({self.max_total_sessions}) reached"
            )
        tenant_count = sum(
            1 for sess in self._sessions.values() if sess.tenant_id == identity.tenant_id
        )
        if tenant_count >= self.max_sessions_per_tenant:
            raise MCPSessionLimitError(
                f"Active session limit ({self.max_sessions_per_tenant}) reached for tenant"
            )
        session_id = secrets.token_urlsafe(32)
        now = time.monotonic()
        sess = MCPSession(
            session_id=session_id,
            tenant_id=identity.tenant_id,
            agent_id=identity.agent_id,
            role=identity.role,
            auth_method=identity.auth_method,
            protocol_version=protocol_version,
            cert_thumbprint_sha256=identity.cert_thumbprint_sha256,
            created_at=now,
            last_seen=now,
        )
        self._sessions[session_id] = sess
        return sess

    def validate_session(
        self,
        session_id: str,
        identity: CallerIdentity,
    ) -> MCPSession:
        """Проверить существование и принадлежность ``Mcp-Session-Id`` к ``identity``."""
        self.prune_expired()
        sess = self._sessions.get(session_id.strip())
        if sess is None:
            raise MCPSessionNotFoundError()
        if not sess.matches_identity(identity):
            raise MCPSessionForbiddenError()
        sess.last_seen = time.monotonic()
        return sess

    def close_session(
        self,
        session_id: str,
        identity: CallerIdentity,
    ) -> None:
        """Проверить владение сессией, закрыть её SSE-потоки и удалить из реестра."""
        sess = self.validate_session(session_id, identity)
        self._sessions.pop(sess.session_id, None)
        self._close_queues(sess)

    def subscribe_sse(
        self,
        session: MCPSession,
        *,
        max_queue_size: int = 256,
    ) -> asyncio.Queue[tuple[str, str, str] | None]:
        """Подписать клиентский ``GET /mcp`` поток на SSE-уведомления сессии."""
        queue: asyncio.Queue[tuple[str, str, str] | None] = asyncio.Queue(maxsize=max_queue_size)
        session.sse_queues.append(queue)
        return queue

    def unsubscribe_sse(
        self,
        session: MCPSession,
        queue: asyncio.Queue[tuple[str, str, str] | None],
    ) -> None:
        """Отписать SSE-очередь при закрытии соединения клиентом."""
        if queue in session.sse_queues:
            session.sse_queues.remove(queue)

    def publish_event(
        self,
        session_id: str,
        payload: dict[str, Any],
        *,
        event_type: str = "message",
    ) -> int:
        """Опубликовать JSON-RPC событие всем активным SSE-подписчикам указанной сессии."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return 0
        event_id = sess.next_event_id()
        serialized = json.dumps(payload, ensure_ascii=False)
        delivered = 0
        for q in list(sess.sse_queues):
            if q.full():
                continue
            q.put_nowait((event_id, event_type, serialized))
            delivered += 1
        return delivered

    def active_count(self, *, tenant_id: str | None = None) -> int:
        """Вернуть число активных сессий (опционально в рамках одного ``tenant_id``)."""
        self.prune_expired()
        if tenant_id is None:
            return len(self._sessions)
        return sum(1 for sess in self._sessions.values() if sess.tenant_id == tenant_id)

    def touch_session(self, session_id: str) -> bool:
        """Продлить ``last_seen`` активной сессии (например, на keepalive/событии SSE)."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return False
        sess.last_seen = time.monotonic()
        return True

    @staticmethod
    def _close_queues(session: MCPSession) -> None:
        for q in list(session.sse_queues):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(None)
        session.sse_queues.clear()


__all__ = [
    "MCPSession",
    "MCPSessionError",
    "MCPSessionForbiddenError",
    "MCPSessionLimitError",
    "MCPSessionManager",
    "MCPSessionNotFoundError",
]
