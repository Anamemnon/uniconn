# src/uniconn/transports/replay/_proxy_advanced.py
"""Операции туннелей, PTY-оболочки и Python RPC для CassetteTransportProxy."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from ...exceptions import (
    CapabilityNotSupportedError,
    CassetteError,
    CassetteMissError,
)
from ..base import (
    BaseTransport,
    FileCapableTransport,
    ShellCapableTransport,
    TunnelCapableTransport,
    supports_capability,
)
from ._proxy_matching import _CassetteMatchingMixin
from .models import (
    RecordedExecInteraction,
    RecordedPyRpcInteraction,
    RecordedShellInteraction,
)
from .shell_proxy import ReplayShellProcess, _RecordingShellProcessProxy

if TYPE_CHECKING:
    from ...config.models import ConnectionConfig
    from .models import Cassette


class _CassetteAdvancedMixin(_CassetteMatchingMixin):
    """Миксин туннелей, PTY-сессий и ``run_python`` RPC для ``CassetteTransportProxy``."""

    if TYPE_CHECKING:
        config: ConnectionConfig
        _cassette: Cassette
        _wrapped: BaseTransport | None
        _dirty: bool

        @property
        def name(self) -> str: ...

        async def _ensure_real_connected(self) -> BaseTransport: ...

    def _supports_capability(self, protocol: type[Any]) -> bool:
        """Точная проверка поддержки протокола возможностей кассетой или обёрнутым транспортом."""
        if self._wrapped is not None and not self._can_replay():
            return supports_capability(self._wrapped, protocol)
        if protocol is FileCapableTransport:
            return "file" in self._cassette.capabilities
        if protocol is ShellCapableTransport:
            return "shell" in self._cassette.capabilities
        if protocol is TunnelCapableTransport:
            if "tunnel" in self._cassette.capabilities:
                return True
            if self._wrapped is not None:
                return supports_capability(self._wrapped, TunnelCapableTransport)
            return self.name in ("ssh", "kubectl", "docker", "podman")
        return isinstance(self, protocol)

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Открыть прямой проброс порта через обёрнутый транспорт или эмулировать в кассете."""
        if self._can_replay():
            if not self._supports_capability(TunnelCapableTransport):
                raise CapabilityNotSupportedError(
                    f"forward_local_port not supported for {self.name} transport",
                    host=self.config.host,
                )
            yield local_port if local_port > 0 else 49152
            return

        real = await self._ensure_real_connected()
        if not supports_capability(real, TunnelCapableTransport):
            raise CapabilityNotSupportedError(
                f"forward_local_port not supported for {real.name} transport",
                host=self.config.host,
            )
        async with real.forward_local_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port

    @contextlib.asynccontextmanager
    async def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AsyncIterator[int]:
        """Открыть обратный проброс порта через обёрнутый транспорт или эмулировать в кассете."""
        if self._can_replay():
            if not self._supports_capability(TunnelCapableTransport) or self.name in ("docker", "podman", "kubectl"):
                raise CapabilityNotSupportedError(
                    f"forward_remote_port not supported for {self.name} transport",
                    host=self.config.host,
                )
            yield remote_port if remote_port > 0 else 49153
            return

        real = await self._ensure_real_connected()
        if not supports_capability(real, TunnelCapableTransport):
            raise CapabilityNotSupportedError(
                f"forward_remote_port not supported for {real.name} transport",
                host=self.config.host,
            )
        async with real.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Any:
        """Открыть интерактивную PTY-сессию из кассеты или реального транспорта."""
        if "shell" not in self._cassette.capabilities:
            raise CapabilityNotSupportedError(
                f"open_shell not supported for {self.name} transport",
                host=self.config.host,
            )
        if self._can_replay():
            matched: RecordedShellInteraction | None = None
            matched_repeat: RecordedShellInteraction | None = None
            for idx, item in enumerate(self._cassette.interactions):
                if isinstance(item, RecordedShellInteraction):
                    if idx not in self._consumed_indices:
                        self._consumed_indices.add(idx)
                        matched = item
                        break
                    matched_repeat = item
            if matched is None and self._allow_playback_repeats:
                matched = matched_repeat

            exec_eps = [
                it
                for it in self._cassette.interactions
                if isinstance(it, RecordedExecInteraction)
            ]
            if matched is not None:
                return ReplayShellProcess(
                    matched,
                    exec_eps,
                    normalize_temp=self._normalize_temp,
                )
            if exec_eps:
                synth_shell = RecordedShellInteraction(
                    term_type=term_type,
                    term_size=term_size,
                    steps=[],
                )
                return ReplayShellProcess(
                    synth_shell,
                    exec_eps,
                    normalize_temp=self._normalize_temp,
                )
            if not self._can_record():
                raise CassetteMissError(
                    "No matching shell interaction in cassette for open_shell()",
                    kind="shell",
                    command="open_shell",
                    host=self.config.host,
                )

        real = await self._ensure_real_connected()
        if not supports_capability(real, ShellCapableTransport):
            raise CapabilityNotSupportedError(
                f"open_shell not supported for {real.name} transport",
                host=self.config.host,
            )
        real_proc = await real.open_shell(term_type=term_type, term_size=term_size, **kwargs)
        shell_rec = RecordedShellInteraction(
            term_type=term_type,
            term_size=term_size,
            steps=[],
        )
        self._cassette.interactions.append(shell_rec)
        self._dirty = True
        return _RecordingShellProcessProxy(real_proc, shell_rec, self)  # type: ignore[arg-type]

    async def record_or_replay_py_rpc(
        self,
        worker: Any,
        *,
        op: str,
        timeout: float | None = None,
        sudo: bool = False,
        allow_oneshot_fallback: bool = True,
        **params: Any,
    ) -> Any:
        """Записать или воспроизвести вызов ``RemotePythonWorker`` (``run_python``) в кассете."""
        import time as time_mod

        from ...core.python_worker import _decode_worker_value, _encode_worker_value

        func_name = str(params.get("func_name", op))
        source = str(params.get("source", ""))
        args = _encode_worker_value(list(params.get("args") or []))
        if op == "call":
            kwargs = _encode_worker_value(dict(params.get("kwargs") or {}))
        else:
            excluded = {"args", "kwargs", "source", "func_name", "is_expr", "cwd", "env"}
            kwargs = _encode_worker_value({k: v for k, v in params.items() if k not in excluded})
        cwd = params.get("cwd")

        if self._can_replay():
            matched = self._match_py_rpc(op, func_name, source, args, kwargs)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"run_python({func_name})",
                    host=self.config.host,
                )
                return _decode_worker_value(matched.result)
            if not self._can_record():
                candidates = [
                    f"{it.op}:{it.func_name}"
                    for it in self._cassette.interactions
                    if isinstance(it, RecordedPyRpcInteraction)
                ]
                raise CassetteMissError(
                    f"No matching py_rpc interaction in cassette for {op}:{func_name}",
                    kind="py_rpc",
                    command=f"run_python({func_name})",
                    host=self.config.host,
                    candidates=candidates,
                )

        if self._wrapped is None:
            raise CassetteError(
                "Real transport is not available for recording py_rpc in standalone ReplayTransport",
                host=self.config.host,
            )

        sanitized_source = self._sanitize_text(source, normalize=True)
        sanitized_cwd = self._sanitize_text(str(cwd), normalize=True) if cwd else None
        start_t = time_mod.monotonic()

        prev_tr = worker._conn.swap_transport(self._wrapped)
        try:
            res = await worker._raw_request(
                op,
                timeout=timeout,
                sudo=sudo,
                allow_oneshot_fallback=allow_oneshot_fallback,
                **params,
            )
        except Exception as exc:
            self._cassette.interactions.append(
                RecordedPyRpcInteraction(
                    op=op,
                    func_name=func_name,
                    source=sanitized_source,
                    args=args,
                    kwargs=kwargs,
                    cwd=sanitized_cwd,
                    duration=round(time_mod.monotonic() - start_t, 6),
                    error_class=type(exc).__name__,
                    error_message=self._sanitize_text(str(exc)),
                )
            )
            self._dirty = True
            raise
        finally:
            worker._conn.swap_transport(prev_tr)

        self._cassette.interactions.append(
            RecordedPyRpcInteraction(
                op=op,
                func_name=func_name,
                source=sanitized_source,
                args=args,
                kwargs=kwargs,
                cwd=sanitized_cwd,
                result=_encode_worker_value(res),
                duration=round(time_mod.monotonic() - start_t, 6),
            )
        )
        self._dirty = True
        return res


__all__ = ["_CassetteAdvancedMixin"]
