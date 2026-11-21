# src/uniconn/mcp/hitl.py
"""Движок классификации рисков (ActionRiskClassifier) и двухфазных согласований (ApprovalManager).

Реализует классификацию рисков команд/файлов, криптографическое связывание HMAC-SHA256
и каналы доставки уведомлений оператору (Human-in-the-Loop, MCP 2.0).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, Self

from .._logging import SecretMaskingFilter
from ..exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ApprovalTamperingError,
    ConcurrencyConflictError,
    ConfigurationError,
)
from ..security.url_validation import open_ssrf_safe_url, validate_outbound_url
from .models import (
    ActionRiskTier,
    ApprovalRequest,
    ApprovalStatus,
    HITLPolicy,
    RiskAssessment,
)
from .risk_classifier import (
    _DESTRUCTIVE_PATTERNS,
    _FORBIDDEN_FILE_PREFIXES,
    _FORBIDDEN_PATTERNS,
    _MUTATING_PATTERNS,
    _PROTECTED_PATH_PREFIXES,
    _SAFE_COMMANDS,
    ActionRiskClassifier,
    _extract_first_subcommand,
    _split_shell_segments,
    build_unified_diff,
)
from .storage import (
    DEFAULT_STATE_DB_PATH,
    HITL_STATE_NAMESPACE,
    SQLiteStateStore,
    StateRecord,
    StateStore,
    resolve_state_store,
    sync_meta_secret,
)

DEFAULT_APPROVAL_STORE_PATH = DEFAULT_STATE_DB_PATH
_LOGGER = logging.getLogger("uniconn.mcp.hitl")

_ = (
    RiskAssessment,
    _DESTRUCTIVE_PATTERNS,
    _FORBIDDEN_FILE_PREFIXES,
    _FORBIDDEN_PATTERNS,
    _MUTATING_PATTERNS,
    _PROTECTED_PATH_PREFIXES,
    _SAFE_COMMANDS,
    _extract_first_subcommand,
    _split_shell_segments,
)

# ─── Каналы доставки запросов оператору ──────────────────────────────────────


class ApprovalChannel(Protocol):
    """Протокол канала уведомления оператора о новой заявке HITL."""

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Отправить уведомление оператору и опционально вернуть синхронное решение."""


class TerminalApprovalChannel:
    """Безопасный для JSON-RPC stdio терминальный канал (рендеринг строго в sys.stderr)."""

    def __init__(
        self,
        *,
        stream: Any = None,
        interactive_tty: bool = False,
    ) -> None:
        """Инициализировать терминальный канал (по умолчанию поток sys.stderr)."""
        self._stream = stream
        self._interactive_tty = interactive_tty

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Вывести Rich-панель заявки в stderr (никогда в stdout) и опционально опросить /dev/tty."""
        target_stream = self._stream if self._stream is not None else sys.stderr
        try:
            from rich.console import Console
            from rich.panel import Panel

            console = Console(file=target_stream, force_terminal=False)
            lines = [
                f"[bold]Request ID[/bold] : {request.approval_id}",
                f"[bold]Target Host[/bold]: {request.target_host}",
                f"[bold]Tool[/bold]       : {request.tool_name}",
                f"[bold]Risk Tier[/bold]  : {request.risk_tier.value}",
            ]
            if request.command:
                lines.append(f"[bold]Command[/bold]    : {SecretMaskingFilter._mask_string(request.command)}")
            if request.sudo:
                lines.append("[bold]Privileges[/bold] : sudo=True")
            if request.risk_reasons:
                lines.append(f"[bold]Reasons[/bold]    : {'; '.join(request.risk_reasons)}")
            if request.diff:
                lines.append(f"\n[bold]Diff[/bold]:\n{request.diff}")
            lines.append(f"\n[bold]Approve via CLI[/bold]: uniconn approval approve {request.approval_id}")
            lines.append(f"[bold]Reject via CLI[/bold] : uniconn approval reject {request.approval_id}")

            panel = Panel(
                "\n".join(lines),
                title=f"[uniconn-mcp] ACTION REQUIRES APPROVAL (Tier: {request.risk_tier.value})",
                border_style="red" if request.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE else "yellow",
            )
            console.print(panel)
        except Exception:
            summary = (
                f"[uniconn-mcp] ACTION REQUIRES APPROVAL ({request.risk_tier.value}) "
                f"id={request.approval_id} host={request.target_host} "
                f"cmd={SecretMaskingFilter._mask_string(request.command or request.tool_name)}\n"
            )
            with contextlib.suppress(Exception):
                target_stream.write(summary)
                target_stream.flush()

        if self._interactive_tty:
            return await asyncio.to_thread(self._prompt_controlling_tty, request)
        return None

    @staticmethod
    def _prompt_controlling_tty(request: ApprovalRequest) -> dict[str, Any] | None:
        """Прочитать ответ [y/N] напрямую из управляющего терминала (/dev/tty), не трогая sys.stdin."""
        tty_path = "CONIN$" if os.name == "nt" else "/dev/tty"
        try:
            with open(tty_path, encoding="utf-8") as tty_in:
                sys.stderr.write(f"Approve {request.approval_id}? [y/N]: ")
                sys.stderr.flush()
                answer = tty_in.readline().strip().lower()
                if answer in ("y", "yes", "approve"):
                    return {
                        "decision": "APPROVED",
                        "decided_by": os.environ.get("USER") or os.environ.get("USERNAME") or "tty_operator",
                        "reason": "Approved interactively via controlling TTY",
                    }
                if answer in ("n", "no", "reject"):
                    return {
                        "decision": "REJECTED",
                        "decided_by": os.environ.get("USER") or os.environ.get("USERNAME") or "tty_operator",
                        "reason": "Rejected interactively via controlling TTY",
                    }
        except OSError:
            return None
        return None


def _compute_webhook_signature(secret: str, body: bytes) -> str:
    """Вычислить заголовок подписи HMAC-SHA256 в формате ``sha256=<hex>``."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _verify_webhook_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    """Проверить подпись ``X-Uniconn-Response-Signature`` за константное время."""
    if not secret or not signature_header:
        return False
    expected = _compute_webhook_signature(secret, body)
    return hmac.compare_digest(expected, signature_header.strip())


class WebhookApprovalChannel:
    """Канал отправки запросов согласования во внешний Webhook (Slack/Telegram/Custom API) с HMAC-SHA256."""

    def __init__(
        self,
        url: str,
        *,
        secret: str | None = None,
        timeout: float = 5.0,
        allow_private_network: bool = False,
        require_signed_response: bool = True,
        sender: Callable[[str, bytes, dict[str, str], float], dict[str, Any] | None] | None = None,
    ) -> None:
        """Инициализировать Webhook-канал с URL, защитой от SSRF и опциональным секретом подписи."""
        self.allow_private_network = bool(allow_private_network)
        self.require_signed_response = bool(require_signed_response)
        self.url = validate_outbound_url(
            url,
            allow_private_network=self.allow_private_network,
            resolve_dns=False,
        )
        self.secret = secret or ""
        self.timeout = timeout
        self._sender = sender

    def sign_payload(self, body: bytes) -> str:
        """Вычислить заголовок подписи X-Uniconn-Signature (sha256=<hex>)."""
        return _compute_webhook_signature(self.secret, body)

    def verify_response_signature(self, body: bytes, signature_header: str | None) -> bool:
        """Проверить HMAC-SHA256 подпись синхронного ответа вебхука (X-Uniconn-Response-Signature)."""
        return _verify_webhook_signature(self.secret, body, signature_header)

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Отправить подписанный JSON-запрос на корпоративный вебхук."""
        payload = {
            "event": "approval_requested",
            "approval": request.to_public_dict(),
        }
        raw_body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Uniconn-Event": "approval_requested",
            "X-Uniconn-Signature": self.sign_payload(raw_body),
        }
        if self._sender is not None:
            return await asyncio.to_thread(self._sender, self.url, raw_body, headers, self.timeout)
        return await asyncio.to_thread(
            self._default_send,
            self.url,
            raw_body,
            headers,
            self.timeout,
            allow_private_network=self.allow_private_network,
            secret=self.secret,
            require_signed_response=self.require_signed_response,
        )

    @staticmethod
    def _default_send(
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout: float,
        *,
        allow_private_network: bool = False,
        secret: str = "",
        require_signed_response: bool = True,
    ) -> dict[str, Any] | None:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with open_ssrf_safe_url(
                req,
                timeout=timeout,
                allow_private_network=allow_private_network,
                allow_redirects=False,
            ) as resp:
                resp_bytes = resp.read(16384)
                if resp_bytes:
                    data = json.loads(resp_bytes.decode("utf-8", errors="replace"))
                    if isinstance(data, dict):
                        if "decision" in data and require_signed_response:
                            sig_hdr = resp.headers.get("X-Uniconn-Response-Signature") if resp.headers else None
                            if not _verify_webhook_signature(secret, resp_bytes, sig_hdr):
                                _LOGGER.warning(
                                    "Rejected synchronous webhook decision with missing/invalid HMAC from %r",
                                    url,
                                )
                                return None
                        return data
        except ConfigurationError as exc:
            _LOGGER.warning("Blocked webhook delivery to unsafe URL %r: %s", url, exc)
        except (OSError, urllib.error.URLError, ValueError) as exc:
            _LOGGER.debug("Webhook approval delivery failed for %r: %s", url, exc)
        return None


# ─── Менеджер жизненного цикла заявок (ApprovalManager) ──────────────────────


def _normalize_parameters_for_hmac(parameters: Mapping[str, Any] | None) -> dict[str, Any]:
    """Нормализовать словарь параметров для безопасного хранения (секреты маскируются, content хешируется)."""
    if not parameters:
        return {}
    excluded = {"approval_id", "wait_for_approval"}
    cleaned: dict[str, Any] = {}
    for k, v in sorted(parameters.items()):
        if k in excluded:
            continue
        if k == "content" and isinstance(v, str):
            cleaned["content_sha256"] = hashlib.sha256(v.encode("utf-8")).hexdigest()
        elif isinstance(v, str):
            cleaned[str(k)] = SecretMaskingFilter._mask_string(v)
        else:
            cleaned[str(k)] = v
    return cleaned


def _canonicalize_value_unmasked(value: Any) -> Any:
    """Рекурсивно канонизировать значение без маскировки (строки заменяются на криптографический SHA-256)."""
    if isinstance(value, str):
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    if isinstance(value, Mapping):
        return {str(k): _canonicalize_value_unmasked(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_canonicalize_value_unmasked(v) for v in value]
    return value


def _canonicalize_parameters_for_hmac(parameters: Mapping[str, Any] | None) -> dict[str, Any]:
    """Построить канонический словарь параметров для HMAC по исходным (немаскированным) значениям."""
    if not parameters:
        return {}
    excluded = {"approval_id", "wait_for_approval"}
    canonical: dict[str, Any] = {}
    for k, v in sorted(parameters.items()):
        if k in excluded:
            continue
        if k == "content" and isinstance(v, str):
            canonical["content_sha256"] = hashlib.sha256(v.encode("utf-8")).hexdigest()
        else:
            canonical[str(k)] = _canonicalize_value_unmasked(v)
    return canonical


class ApprovalManager:
    """Асинхронный менеджер двухфазных согласований (HITL) с HMAC и атомарным CAS поверх ``StateStore``."""

    def __init__(
        self,
        policy: HITLPolicy | None = None,
        *,
        secret: str | None = None,
        store: StateStore | None = None,
        store_path: str | Path | None = None,
        channels: Sequence[ApprovalChannel] | None = None,
        retention_seconds: float = 86400.0,
    ) -> None:
        """Инициализировать менеджер заявок (по умолчанию 100% in-memory ``InMemoryStateStore``)."""
        self.policy = policy or HITLPolicy(enabled=True)
        self._retention_seconds = max(1.0, float(retention_seconds))
        self._secret_lock = asyncio.Lock()
        self._events: dict[str, asyncio.Event] = {}

        if store is not None:
            self._store: StateStore = store
            self._owns_store = False
            db_attr = getattr(store, "db_path", None)
            self.store_path: Path | None = db_attr if isinstance(db_attr, Path) else None
        else:
            resolved_store = (
                store_path
                or self.policy.store_path
                or os.environ.get("UNICONN_STATE_DB")
                or os.environ.get("UNICONN_APPROVAL_STORE")
            )
            self._store, self.store_path = resolve_state_store(resolved_store)
            self._owns_store = True

        env_secret = os.environ.get("UNICONN_HITL_SECRET")
        # Внутренний HMAC-ключ заявок изолирован от webhook_secret (защита от утечки ключа)
        if secret or env_secret:
            self._secret: str = str(secret or env_secret)
            self._secret_synced = True
        elif isinstance(self._store, SQLiteStateStore):
            meta = self._store.get_or_create_meta_sync(
                "hitl_hmac_secret",
                {"secret": secrets.token_hex(32)},
            )
            self._secret = str(meta.get("secret") or secrets.token_hex(32))
            self._secret_synced = True
        else:
            self._secret = secrets.token_hex(32)
            self._secret_synced = False

        if channels is not None:
            self._channels: list[ApprovalChannel] = list(channels)
        else:
            self._channels = self._build_default_channels()

    @property
    def store(self) -> StateStore:
        """Активный бэкенд ``StateStore`` менеджера согласований."""
        return self._store

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Освободить ресурсы собственного ``StateStore`` (если создан менеджером)."""
        if self._owns_store:
            await self._store.close()

    async def _ensure_secret_synced(self) -> str:
        """Синхронизировать внутренний HMAC-секрет через ``StateStore`` для общих/кластерных бэкендов."""
        if self._secret_synced:
            return self._secret
        async with self._secret_lock:
            if self._secret_synced:
                return self._secret
            candidate = self._secret or secrets.token_hex(32)
            self._secret = await sync_meta_secret(self._store, "hitl_hmac_secret", candidate)
            self._secret_synced = True
            return self._secret

    def _build_default_channels(self) -> list[ApprovalChannel]:
        built: list[ApprovalChannel] = []
        chan_set = {c.strip().lower() for c in self.policy.channels if c.strip()}
        if "terminal" in chan_set:
            built.append(TerminalApprovalChannel(interactive_tty=False))
        if "webhook" in chan_set and self.policy.webhook_url:
            webhook_secret = (
                self.policy.webhook_secret
                or os.environ.get("UNICONN_WEBHOOK_SECRET")
                or hmac.new(
                    self._secret.encode("utf-8"),
                    b"uniconn:webhook-signing:v1",
                    hashlib.sha256,
                ).hexdigest()
            )
            built.append(
                WebhookApprovalChannel(
                    self.policy.webhook_url,
                    secret=webhook_secret,
                )
            )
        return built

    def compute_hmac(
        self,
        *,
        approval_id: str,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
        diff_sha256: str | None = None,
        tenant_id: str | None = None,
    ) -> str:
        """Вычислить HMAC-SHA256 подпись канонического дайджеста исходных (немаскированных) параметров."""
        raw_cmd = (command or "").strip()
        cmd_digest = hashlib.sha256(raw_cmd.encode("utf-8")).hexdigest()
        effective_diff_sha256 = (
            diff_sha256
            if diff_sha256 is not None
            else hashlib.sha256((diff or "").encode("utf-8")).hexdigest()
        )
        canonical_dict: dict[str, Any] = {
            "approval_id": approval_id,
            "target_host": target_host.strip(),
            "tool_name": tool_name.strip(),
            "command_sha256": cmd_digest,
            "sudo": bool(sudo),
            "cwd": (cwd or "").strip(),
            "parameters": _canonicalize_parameters_for_hmac(parameters),
            "diff_sha256": effective_diff_sha256,
        }
        if tenant_id is not None and tenant_id.strip():
            canonical_dict["tenant_id"] = tenant_id.strip()
        canonical_json = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hmac.new(
            self._secret.encode("utf-8"),
            canonical_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_request_hmac(
        self,
        request: ApprovalRequest,
        *,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
        tenant_id: str | None = None,
    ) -> bool:
        """Проверить неизменность исходных параметров операции относительно подписанной заявки."""
        eff_tenant = tenant_id if tenant_id is not None else request.tenant_id
        expected = self.compute_hmac(
            approval_id=request.approval_id,
            target_host=target_host,
            tool_name=tool_name,
            command=command,
            sudo=sudo,
            cwd=cwd,
            parameters=parameters,
            diff=diff if diff is not None else request.diff,
            diff_sha256=None if diff is not None else request.diff_sha256,
            tenant_id=eff_tenant,
        )
        return hmac.compare_digest(request.hmac_signature, expected)

    def _write_audit_entry(self, event: str, request: ApprovalRequest, **extra: Any) -> None:
        audit_path_str = self.policy.audit_log_path
        if not audit_path_str:
            return
        audit_path = Path(audit_path_str).expanduser()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            "approval_id": request.approval_id,
            "status": request.status.value,
            "agent_id": request.agent_id,
            "tenant_id": request.tenant_id,
            "target_host": request.target_host,
            "tool_name": request.tool_name,
            "command": SecretMaskingFilter._mask_string(request.command) if request.command else None,
            "sudo": request.sudo,
            "risk_tier": request.risk_tier.value,
            "decided_by": request.decided_by,
            "decision_reason": SecretMaskingFilter._mask_string(request.decision_reason)
            if request.decision_reason
            else None,
            **extra,
        }
        with contextlib.suppress(OSError), audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    @staticmethod
    def _normalize_tenant_id(tenant_id: str | None) -> str | None:
        return tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None

    def _signal_local_event(self, approval_id: str) -> None:
        ev = self._events.get(approval_id)
        if ev is not None:
            ev.set()

    def _cleanup_local_events(self, max_events: int = 1024) -> None:
        if len(self._events) <= max_events:
            return
        done_keys = [k for k, ev in self._events.items() if ev.is_set()]
        for k in done_keys[: max(0, len(self._events) - max_events // 2)]:
            self._events.pop(k, None)

    @staticmethod
    def _raise_for_terminal_status(
        req: ApprovalRequest,
        appr_key: str,
        *,
        command: str | None = None,
        host: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Выбросить доменное исключение, если заявка в терминальном статусе CONSUMED/REJECTED/EXPIRED."""
        if req.status == ApprovalStatus.CONSUMED:
            raise ApprovalAlreadyConsumedError(
                f"Single-use approval token {appr_key!r} has already been consumed",
                approval_id=appr_key,
                approval_request=req,
                command=command,
                host=host,
            ) from cause
        if req.status == ApprovalStatus.REJECTED:
            raise ApprovalRejectedError(
                f"Action rejected by operator ({req.decided_by or 'operator'}): "
                f"{req.decision_reason or 'No reason provided'}",
                approval_id=appr_key,
                decided_by=req.decided_by,
                decision_reason=req.decision_reason,
                approval_request=req,
                command=command,
                host=host,
            ) from cause
        if req.status == ApprovalStatus.EXPIRED:
            raise ApprovalExpiredError(
                f"Approval request {appr_key!r} expired at {req.expires_at.isoformat()}",
                approval_id=appr_key,
                approval_request=req,
                command=command,
                host=host,
            ) from cause

    async def _try_mark_expired(
        self,
        req: ApprovalRequest,
        state_rec: StateRecord,
    ) -> tuple[ApprovalRequest, StateRecord]:
        """Перевести просроченную PENDING-заявку в EXPIRED через CAS (идемпотентно)."""
        if req.status != ApprovalStatus.PENDING or not req.is_expired():
            return req, state_rec
        expired_req = req.model_copy(update={"status": ApprovalStatus.EXPIRED})
        try:
            updated = await self._store.put(
                HITL_STATE_NAMESPACE,
                expired_req.approval_id,
                expired_req.model_dump(mode="json"),
                tenant_id=expired_req.tenant_id,
                status=ApprovalStatus.EXPIRED.value,
                ttl_seconds=self._retention_seconds,
                expected_version=state_rec.version,
            )
            self._write_audit_entry("approval.expired", expired_req)
            self._signal_local_event(expired_req.approval_id)
            return expired_req, updated
        except ConcurrencyConflictError:
            latest = await self._store.get(HITL_STATE_NAMESPACE, req.approval_id)
            if latest is not None:
                latest_req = ApprovalRequest.model_validate(latest.value)
                if latest_req.status != ApprovalStatus.PENDING:
                    self._signal_local_event(req.approval_id)
                return latest_req, latest
            return expired_req, state_rec

    async def create_request(
        self,
        *,
        target_host: str,
        tool_name: str,
        risk_tier: ActionRiskTier,
        risk_reasons: Sequence[str] = (),
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
        agent_id: str | None = None,
        tenant_id: str | None = None,
        timeout_seconds: float | None = None,
        deduplicate: bool = True,
    ) -> ApprovalRequest:
        """Создать новую заявку на согласование (или вернуть идентичную активную PENDING-заявку)."""
        await self._ensure_secret_synced()
        await self._store.prune_expired(HITL_STATE_NAMESPACE)
        self._cleanup_local_events()

        norm_tenant = self._normalize_tenant_id(tenant_id)
        norm_host = target_host.strip()
        norm_tool = tool_name.strip()
        norm_cwd = (cwd or "").strip() or None
        norm_params = _normalize_parameters_for_hmac(parameters)
        masked_cmd = SecretMaskingFilter._mask_string(command.strip()) if command is not None else None
        masked_diff = SecretMaskingFilter._mask_string(diff) if diff is not None else None
        diff_sha256 = hashlib.sha256((diff or "").encode("utf-8")).hexdigest()

        if deduplicate:
            pending_recs = await self._store.list(
                HITL_STATE_NAMESPACE,
                tenant_id=norm_tenant,
                strict_tenant=True,
                status=ApprovalStatus.PENDING.value,
            )
            for rec in pending_recs:
                existing = ApprovalRequest.model_validate(rec.value)
                if existing.is_expired():
                    await self._try_mark_expired(existing, rec)
                    continue
                if (
                    existing.tenant_id == norm_tenant
                    and existing.target_host == norm_host
                    and existing.tool_name == norm_tool
                    and existing.sudo == bool(sudo)
                    and existing.cwd == norm_cwd
                ):
                    expected_existing = self.compute_hmac(
                        approval_id=existing.approval_id,
                        target_host=norm_host,
                        tool_name=norm_tool,
                        command=command,
                        sudo=sudo,
                        cwd=norm_cwd,
                        parameters=parameters,
                        diff=diff,
                        diff_sha256=diff_sha256,
                        tenant_id=norm_tenant,
                    )
                    if hmac.compare_digest(existing.hmac_signature, expected_existing):
                        return existing

        approval_id = f"appr_{secrets.token_hex(6)}"
        now = datetime.now(UTC)
        ttl = float(timeout_seconds if timeout_seconds is not None else self.policy.timeout_seconds)
        effective_ttl = max(0.1, ttl)
        expires_at = now + timedelta(seconds=effective_ttl)

        sig = self.compute_hmac(
            approval_id=approval_id,
            target_host=norm_host,
            tool_name=norm_tool,
            command=command,
            sudo=sudo,
            cwd=norm_cwd,
            parameters=parameters,
            diff=diff,
            diff_sha256=diff_sha256,
            tenant_id=norm_tenant,
        )

        req = ApprovalRequest(
            approval_id=approval_id,
            created_at=now,
            expires_at=expires_at,
            agent_id=agent_id,
            tenant_id=norm_tenant,
            target_host=norm_host,
            tool_name=norm_tool,
            command=masked_cmd,
            sudo=bool(sudo),
            cwd=norm_cwd,
            parameters=norm_params,
            risk_tier=risk_tier,
            risk_reasons=list(risk_reasons),
            diff=masked_diff,
            diff_sha256=diff_sha256,
            status=ApprovalStatus.PENDING,
            hmac_signature=sig,
        )
        await self._store.put(
            HITL_STATE_NAMESPACE,
            approval_id,
            req.model_dump(mode="json"),
            tenant_id=norm_tenant,
            status=ApprovalStatus.PENDING.value,
            ttl_seconds=effective_ttl + self._retention_seconds,
            expected_version=0,
        )
        self._events[approval_id] = asyncio.Event()
        self._write_audit_entry("approval.requested", req)

        # Оповещаем подключённые каналы (например, stderr или webhook)
        for channel in self._channels:
            try:
                chan_resp = await channel.notify(req)
                if isinstance(chan_resp, dict):
                    decision = str(chan_resp.get("decision") or "").upper()
                    by_user = str(chan_resp.get("decided_by") or "channel_operator")
                    reason = chan_resp.get("reason")
                    if decision == "APPROVED":
                        await self.approve(
                            req.approval_id,
                            decided_by=by_user,
                            reason=str(reason) if reason else None,
                        )
                    elif decision == "REJECTED":
                        await self.reject(
                            req.approval_id,
                            decided_by=by_user,
                            reason=str(reason) if reason else None,
                        )
            except Exception as exc:
                _LOGGER.debug(
                    "HITL channel %s notification failed for %s: %s",
                    type(channel).__name__,
                    approval_id,
                    exc,
                )

        return await self.get_request(req.approval_id, tenant_id=norm_tenant)

    async def get_request(
        self,
        approval_id: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> ApprovalRequest:
        """Получить заявку по ID с проверкой ``tenant_id`` и актуализацией таймаута."""
        await self._ensure_secret_synced()
        appr_key = approval_id.strip()
        norm_tenant = self._normalize_tenant_id(tenant_id)
        rec = await self._store.get(
            HITL_STATE_NAMESPACE,
            appr_key,
            tenant_id=norm_tenant,
            strict_tenant=strict_tenant,
        )
        if rec is None or rec.is_expired():
            raise KeyError(f"Approval request {approval_id!r} not found")
        req = ApprovalRequest.model_validate(rec.value)
        if req.status == ApprovalStatus.PENDING and req.is_expired():
            req, _ = await self._try_mark_expired(req, rec)
        elif req.status != ApprovalStatus.PENDING:
            self._signal_local_event(appr_key)
        return req

    async def list_requests(
        self,
        *,
        status: ApprovalStatus | str | None = None,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> list[ApprovalRequest]:
        """Вернуть список всех заявок (опционально отфильтрованный по статусу и ``tenant_id``)."""
        await self._ensure_secret_synced()
        await self._store.prune_expired(HITL_STATE_NAMESPACE)
        norm_tenant = self._normalize_tenant_id(tenant_id)
        target_status = ApprovalStatus(str(status).upper()) if status is not None else None

        # Актуализируем истёкшие PENDING-заявки, если фильтр может их затронуть
        if target_status in (None, ApprovalStatus.PENDING, ApprovalStatus.EXPIRED):
            pending_recs = await self._store.list(
                HITL_STATE_NAMESPACE,
                tenant_id=norm_tenant,
                strict_tenant=strict_tenant,
                status=ApprovalStatus.PENDING.value,
            )
            for rec in pending_recs:
                parsed = ApprovalRequest.model_validate(rec.value)
                if parsed.is_expired():
                    await self._try_mark_expired(parsed, rec)

        recs = await self._store.list(
            HITL_STATE_NAMESPACE,
            tenant_id=norm_tenant,
            strict_tenant=strict_tenant,
            status=target_status.value if target_status is not None else None,
        )
        items = [ApprovalRequest.model_validate(rec.value) for rec in recs]
        return sorted(items, key=lambda r: r.created_at, reverse=True)

    async def approve(
        self,
        approval_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Одобрить заявку оператором (PENDING -> APPROVED) через атомарный CAS."""
        await self._ensure_secret_synced()
        appr_key = approval_id.strip()
        rec = await self._store.get(HITL_STATE_NAMESPACE, appr_key)
        if rec is None or rec.is_expired():
            raise KeyError(f"Approval request {approval_id!r} not found")
        req = ApprovalRequest.model_validate(rec.value)

        if req.status == ApprovalStatus.CONSUMED:
            self._raise_for_terminal_status(req, appr_key)
        if req.status == ApprovalStatus.EXPIRED or req.is_expired():
            req, _ = await self._try_mark_expired(req, rec)
            if req.status != ApprovalStatus.EXPIRED:
                req = req.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self._raise_for_terminal_status(req, appr_key)
        self._raise_for_terminal_status(req, appr_key)

        approved_req = req.model_copy(
            update={
                "status": ApprovalStatus.APPROVED,
                "decided_by": decided_by.strip() or "operator",
                "decided_at": datetime.now(UTC),
                "decision_reason": reason,
            }
        )
        try:
            await self._store.put(
                HITL_STATE_NAMESPACE,
                appr_key,
                approved_req.model_dump(mode="json"),
                tenant_id=approved_req.tenant_id,
                status=ApprovalStatus.APPROVED.value,
                ttl_seconds=approved_req.remaining_seconds() + self._retention_seconds,
                expected_version=rec.version,
            )
        except ConcurrencyConflictError as exc:
            latest_rec = await self._store.get(HITL_STATE_NAMESPACE, appr_key)
            if latest_rec is None:
                raise KeyError(f"Approval request {approval_id!r} not found") from exc
            latest = ApprovalRequest.model_validate(latest_rec.value)
            if latest.status not in (ApprovalStatus.CONSUMED, ApprovalStatus.REJECTED) and latest.is_expired():
                latest = latest.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self._raise_for_terminal_status(latest, appr_key, cause=exc)
            self._signal_local_event(appr_key)
            return latest

        self._write_audit_entry("approval.approved", approved_req)
        self._signal_local_event(appr_key)
        return approved_req

    async def reject(
        self,
        approval_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Отклонить заявку оператором (PENDING/APPROVED -> REJECTED) через атомарный CAS."""
        await self._ensure_secret_synced()
        appr_key = approval_id.strip()
        actor = decided_by.strip() or "operator"

        for _attempt in range(3):
            rec = await self._store.get(HITL_STATE_NAMESPACE, appr_key)
            if rec is None or rec.is_expired():
                raise KeyError(f"Approval request {approval_id!r} not found")
            req = ApprovalRequest.model_validate(rec.value)

            if req.status == ApprovalStatus.CONSUMED:
                self._raise_for_terminal_status(req, appr_key)
            if req.status == ApprovalStatus.REJECTED:
                self._signal_local_event(appr_key)
                return req

            rejected_req = req.model_copy(
                update={
                    "status": ApprovalStatus.REJECTED,
                    "decided_by": actor,
                    "decided_at": datetime.now(UTC),
                    "decision_reason": reason,
                }
            )
            try:
                await self._store.put(
                    HITL_STATE_NAMESPACE,
                    appr_key,
                    rejected_req.model_dump(mode="json"),
                    tenant_id=rejected_req.tenant_id,
                    status=ApprovalStatus.REJECTED.value,
                    ttl_seconds=self._retention_seconds,
                    expected_version=rec.version,
                )
            except ConcurrencyConflictError as exc:
                latest_rec = await self._store.get(HITL_STATE_NAMESPACE, appr_key)
                if latest_rec is None:
                    raise KeyError(f"Approval request {approval_id!r} not found") from exc
                latest = ApprovalRequest.model_validate(latest_rec.value)
                if latest.status == ApprovalStatus.CONSUMED:
                    self._raise_for_terminal_status(latest, appr_key, cause=exc)
                if latest.status == ApprovalStatus.REJECTED:
                    self._signal_local_event(appr_key)
                    return latest
                # Если параллельно выполнился approve() (PENDING -> APPROVED), повторяем CAS для REJECTED
                continue

            self._write_audit_entry("approval.rejected", rejected_req)
            self._signal_local_event(appr_key)
            return rejected_req

        raise ConcurrencyConflictError(
            f"Failed to reject approval {appr_key!r} due to repeated concurrent updates",
            namespace=HITL_STATE_NAMESPACE,
            key=appr_key,
        )

    async def wait_for_decision(
        self,
        approval_id: str,
        *,
        timeout: float | None = None,
        poll_interval: float = 0.1,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> ApprovalRequest:
        """Ожидать решения оператора (в памяти или через межпроцессный ``StateStore``)."""
        appr_key = approval_id.strip()
        req = await self.get_request(appr_key, tenant_id=tenant_id, strict_tenant=strict_tenant)
        if req.status != ApprovalStatus.PENDING:
            return req

        max_wait = (
            min(float(timeout), req.remaining_seconds())
            if timeout is not None
            else req.remaining_seconds()
        )
        deadline = time.monotonic() + max(0.01, max_wait)
        ev = self._events.setdefault(appr_key, asyncio.Event())

        while time.monotonic() < deadline:
            req = await self.get_request(appr_key, tenant_id=tenant_id, strict_tenant=strict_tenant)
            if req.status != ApprovalStatus.PENDING:
                return req
            step = min(poll_interval, max(0.01, deadline - time.monotonic()))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(ev.wait(), timeout=step)
            if ev.is_set():
                return await self.get_request(appr_key, tenant_id=tenant_id, strict_tenant=strict_tenant)

        return await self.get_request(appr_key, tenant_id=tenant_id, strict_tenant=strict_tenant)

    async def verify_and_consume(
        self,
        approval_id: str,
        *,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> ApprovalRequest:
        """Проверить статус, ``tenant_id`` и HMAC-подпись одобренной заявки и атомарно погасить токен (CAS)."""
        await self._ensure_secret_synced()
        appr_key = approval_id.strip()
        norm_tenant = self._normalize_tenant_id(tenant_id)
        rec = await self._store.get(
            HITL_STATE_NAMESPACE,
            appr_key,
            tenant_id=norm_tenant,
            strict_tenant=strict_tenant,
        )
        if rec is None or rec.is_expired():
            raise KeyError(f"Approval request {approval_id!r} not found")
        req = ApprovalRequest.model_validate(rec.value)

        if req.status == ApprovalStatus.CONSUMED:
            self._write_audit_entry("approval.replay_blocked", req)
            self._raise_for_terminal_status(req, appr_key, command=command, host=target_host)

        if req.status == ApprovalStatus.EXPIRED or req.is_expired():
            req, _ = await self._try_mark_expired(req, rec)
            if req.status != ApprovalStatus.EXPIRED:
                req = req.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self._raise_for_terminal_status(req, appr_key, command=command, host=target_host)

        if req.status == ApprovalStatus.REJECTED:
            self._raise_for_terminal_status(req, appr_key, command=command, host=target_host)

        if req.status == ApprovalStatus.PENDING:
            raise ApprovalRequiredError(
                f"Approval request {appr_key!r} is still PENDING operator confirmation",
                approval_id=appr_key,
                approval_request=req,
                command=command,
                host=target_host,
            )

        if not self.verify_request_hmac(
            req,
            target_host=target_host,
            tool_name=tool_name,
            command=command,
            sudo=sudo,
            cwd=cwd,
            parameters=parameters,
            diff=diff,
            tenant_id=norm_tenant if norm_tenant is not None else req.tenant_id,
        ):
            masked_cmd = SecretMaskingFilter._mask_string(command) if command is not None else None
            self._write_audit_entry(
                "approval.tampering_detected",
                req,
                attempted_host=target_host,
                attempted_tool=tool_name,
                attempted_command=masked_cmd,
                attempted_sudo=sudo,
            )
            raise ApprovalTamperingError(
                f"HMAC signature mismatch for approval {appr_key!r}: "
                "target host, command, sudo flag, or parameters do not match the approved request",
                approval_id=appr_key,
                approval_request=req,
                command=command,
                host=target_host,
            )

        consumed_req = req.model_copy(
            update={
                "status": ApprovalStatus.CONSUMED,
                "consumed_at": datetime.now(UTC),
            }
        )
        try:
            await self._store.put(
                HITL_STATE_NAMESPACE,
                appr_key,
                consumed_req.model_dump(mode="json"),
                tenant_id=consumed_req.tenant_id,
                status=ApprovalStatus.CONSUMED.value,
                ttl_seconds=self._retention_seconds,
                expected_version=rec.version,
            )
        except ConcurrencyConflictError as exc:
            latest_rec = await self._store.get(HITL_STATE_NAMESPACE, appr_key)
            if latest_rec is None:
                raise KeyError(f"Approval request {approval_id!r} not found") from exc
            latest = ApprovalRequest.model_validate(latest_rec.value)
            if latest.status in (ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED):
                self._raise_for_terminal_status(
                    latest,
                    appr_key,
                    command=command,
                    host=target_host,
                    cause=exc,
                )
            self._write_audit_entry("approval.replay_blocked", latest)
            raise ApprovalAlreadyConsumedError(
                f"Single-use approval token {appr_key!r} has already been consumed",
                approval_id=appr_key,
                approval_request=latest,
                command=command,
                host=target_host,
            ) from exc

        self._write_audit_entry("approval.consumed", consumed_req)
        return consumed_req


__all__ = [
    "DEFAULT_APPROVAL_STORE_PATH",
    "ActionRiskClassifier",
    "ApprovalChannel",
    "ApprovalManager",
    "TerminalApprovalChannel",
    "WebhookApprovalChannel",
    "build_unified_diff",
]

