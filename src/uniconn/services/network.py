# src/uniconn/services/network.py
"""Доменный сервис управления сетевыми конфигурациями и потоковой телеметрией (conn.net)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import CapabilityNotSupportedError
from ..result import NetResult, TelemetrySample
from ..transports.network.base import StructuredNetworkTransport

if TYPE_CHECKING:
    from ..core.connection import Connection


class NetworkOperationsService:
    """Доменный сервис работы со структурированными сетевыми протоколами (``conn.net``).

    Обеспечивает единый интерфейс для ``netconf://``, ``restconf://`` и ``gnmi://``:
    - Чтение состояния и конфигурации: ``get()``, ``get_config()``, ``capabilities()``
    - Модификация и атомарные транзакции: ``edit()``, ``commit()``, ``commit_confirm()``,
      ``discard_changes()``, ``validate()``, ``lock()``, ``unlock()``, ``locked()``, ``transaction()``
    - Произвольные RPC: ``rpc()``
    - Потоковая телеметрия: ``subscribe()``
    """

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сетевой сервис для подключения."""
        self._conn = conn

    def _resolve_transport(self) -> tuple[StructuredNetworkTransport | None, Any]:
        """Вернуть ``(real_structured_transport, cassette_proxy_or_none)``."""
        tr = self._conn.transport
        wrapped = getattr(tr, "_wrapped", None)
        if wrapped is not None and hasattr(tr, "_can_replay"):
            if isinstance(wrapped, StructuredNetworkTransport):
                return wrapped, tr
            return None, tr
        if getattr(tr, "name", "") == "replay" or hasattr(tr, "cassette"):
            return None, tr
        if isinstance(tr, StructuredNetworkTransport):
            return tr, None
        raise CapabilityNotSupportedError(
            f"Structured network operations (conn.net) are not supported for {tr.name!r} transport",
            host=self._conn.config.host,
        )

    async def _ensure_connected(self, real_tr: Any) -> None:
        if real_tr is not None and not real_tr.is_connected:
            await real_tr.connect()

    async def _exec_via_cassette_or_transport(
        self,
        op_key: str,
        coro_factory: Any,
        *,
        is_mutation: bool = False,
        datastore: str | None = None,
    ) -> NetResult:
        """Выполнить сетевую операцию с поддержкой режима ``dry_run`` и записи/воспроизведения кассет."""
        if is_mutation and self._conn.dry_run:
            return NetResult(
                ok=True,
                data={"dry_run": True, "operation": op_key},
                text=json.dumps({"dry_run": True, "operation": op_key}),
                raw=b"",
                operation=op_key,
                datastore=datastore,
                protocol=self._conn.transport_name,
                host=self._conn.config.host,
            )

        real_tr, cassette_proxy = self._resolve_transport()
        if cassette_proxy is not None:
            can_replay = (
                cassette_proxy._can_replay()
                if hasattr(cassette_proxy, "_can_replay")
                else True
            )
            can_record = (
                cassette_proxy._can_record()
                if hasattr(cassette_proxy, "_can_record")
                else False
            )
            cmd_tag = f"net:{op_key}"
            if can_replay:
                try:
                    replay_res = await cassette_proxy.run(cmd_tag)
                    payload = json.loads(replay_res.stdout)
                    if isinstance(payload, dict) and "__net_result__" in payload:
                        return NetResult.from_dict(payload)
                    return NetResult(
                        ok=replay_res.ok,
                        data=payload,
                        text=replay_res.stdout,
                        raw=replay_res.stdout.encode("utf-8"),
                        operation=op_key,
                        datastore=datastore,
                        protocol=self._conn.transport_name,
                        duration=replay_res.duration,
                        host=self._conn.config.host,
                    )
                except Exception:
                    if not can_record or real_tr is None:
                        raise

            assert real_tr is not None
            await self._ensure_connected(real_tr)
            net_res: NetResult = await coro_factory(real_tr)
            from ..transports.replay.models import RecordedExecInteraction

            serialized_dict = net_res.to_dict()
            serialized_dict["__net_result__"] = True
            cassette_proxy.cassette.interactions.append(
                RecordedExecInteraction(
                    command=cmd_tag,
                    exit_code=0 if net_res.ok else 1,
                    stdout=json.dumps(serialized_dict, ensure_ascii=False),
                    stderr="",
                    duration=round(net_res.duration, 6),
                )
            )
            if hasattr(cassette_proxy, "mark_dirty"):
                cassette_proxy.mark_dirty()
            return net_res

        assert real_tr is not None
        await self._ensure_connected(real_tr)
        return await coro_factory(real_tr)

    async def get(
        self,
        path: str = "",
        *,
        datastore: str = "running",
        filter_type: Literal["xpath", "subtree"] = "xpath",
        depth: int | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Получить конфигурацию и операционное состояние по пути YANG / XPath / OpenConfig."""
        return await self._exec_via_cassette_or_transport(
            f"get:{datastore}:{path}",
            lambda tr: tr.net_get(
                path,
                datastore=datastore,
                filter_type=filter_type,
                depth=depth,
                timeout=timeout,
            ),
            datastore=datastore,
        )

    async def get_config(
        self,
        datastore: str | None = None,
        path: str = "",
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        timeout: float | None = None,
    ) -> NetResult:
        """Получить конфигурацию из хранилища ``datastore`` (``running``, ``candidate``, ``startup``)."""
        eff_ds = datastore or "running"
        return await self._exec_via_cassette_or_transport(
            f"get-config:{eff_ds}:{path}",
            lambda tr: tr.net_get_config(
                eff_ds,
                path,
                filter_type=filter_type,
                timeout=timeout,
            ),
            datastore=eff_ds,
        )

    async def edit(
        self,
        config: Mapping[str, Any] | Sequence[Mapping[str, Any]] | str | bytes,
        *,
        path: str = "",
        datastore: str | None = None,
        operation: Literal["merge", "replace", "create", "delete", "remove", "patch"] = "merge",
        default_operation: str | None = None,
        test_option: str | None = None,
        error_option: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Модифицировать конфигурацию в хранилище (``merge``, ``replace``, ``create``, ``delete``, ``patch``)."""
        return await self._exec_via_cassette_or_transport(
            f"edit:{operation}:{datastore or 'default'}:{path}",
            lambda tr: tr.net_edit(
                config,
                path=path,
                datastore=datastore,
                operation=operation,
                default_operation=default_operation,
                test_option=test_option,
                error_option=error_option,
                timeout=timeout,
            ),
            is_mutation=True,
            datastore=datastore,
        )

    async def commit(
        self,
        *,
        confirmed: bool = False,
        confirm_timeout: int = 60,
        persist: str | None = None,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Зафиксировать конфигурацию (с поддержкой двухфазного ``confirmed=True`` и автоотката)."""
        tag = f"commit:confirmed={confirmed}:timeout={confirm_timeout}"
        return await self._exec_via_cassette_or_transport(
            tag,
            lambda tr: tr.net_commit(
                confirmed=confirmed,
                confirm_timeout=confirm_timeout,
                persist=persist,
                persist_id=persist_id,
                timeout=timeout,
            ),
            is_mutation=True,
            datastore="running",
        )

    async def commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтвердить активный двухфазный ``confirmed commit``."""
        return await self._exec_via_cassette_or_transport(
            "commit-confirm",
            lambda tr: tr.net_commit_confirm(
                persist_id=persist_id,
                timeout=timeout,
            ),
            is_mutation=True,
            datastore="running",
        )

    async def discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Откатить все незафиксированные изменения в хранилище ``candidate``."""
        return await self._exec_via_cassette_or_transport(
            "discard-changes",
            lambda tr: tr.net_discard_changes(timeout=timeout),
            is_mutation=True,
            datastore="candidate",
        )

    async def validate(
        self,
        *,
        source: str = "candidate",
        timeout: float | None = None,
    ) -> NetResult:
        """Проверить корректность конфигурации в хранилище ``source``."""
        return await self._exec_via_cassette_or_transport(
            f"validate:{source}",
            lambda tr: tr.net_validate(source=source, timeout=timeout),
            datastore=source,
        )

    async def lock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Заблокировать конфигурационное хранилище ``datastore``."""
        return await self._exec_via_cassette_or_transport(
            f"lock:{datastore}",
            lambda tr: tr.net_lock(datastore, timeout=timeout),
            datastore=datastore,
        )

    async def unlock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Разблокировать конфигурационное хранилище ``datastore``."""
        return await self._exec_via_cassette_or_transport(
            f"unlock:{datastore}",
            lambda tr: tr.net_unlock(datastore, timeout=timeout),
            datastore=datastore,
        )

    async def capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Получить список поддерживаемых YANG-моделей и возможностей устройства."""
        return await self._exec_via_cassette_or_transport(
            "capabilities",
            lambda tr: tr.net_capabilities(timeout=timeout),
        )

    async def rpc(
        self,
        payload: Mapping[str, Any] | str,
        *,
        path: str = "",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить произвольный RPC-вызов или операцию YANG."""
        return await self._exec_via_cassette_or_transport(
            f"rpc:{path}",
            lambda tr: tr.net_rpc(payload, path=path, timeout=timeout),
        )

    async def subscribe(
        self,
        paths: Sequence[str] | str,
        *,
        mode: Literal["sample", "on_change", "target_defined"] = "sample",
        sample_interval: float = 5.0,
        suppress_redundant: bool = False,
        heartbeat_interval: float | None = None,
        once: bool = False,
        encoding: str | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[TelemetrySample]:
        """Подписаться на потоковую телеметрию в реальном времени и получать ``TelemetrySample``."""
        path_list = [paths] if isinstance(paths, str) else list(paths)
        real_tr, cassette_proxy = self._resolve_transport()
        stream_key = f"net:subscribe:{mode}:{','.join(path_list)}"

        if cassette_proxy is not None:
            can_replay = (
                cassette_proxy._can_replay()
                if hasattr(cassette_proxy, "_can_replay")
                else True
            )
            can_record = (
                cassette_proxy._can_record()
                if hasattr(cassette_proxy, "_can_record")
                else False
            )
            if can_replay:
                replayed = False
                with contextlib.suppress(Exception):
                    async for line in cassette_proxy.stream(stream_key, timeout=timeout):
                        replayed = True
                        yield TelemetrySample.from_dict(json.loads(line))
                if replayed or not can_record or real_tr is None:
                    return

            assert real_tr is not None
            await self._ensure_connected(real_tr)
            from ..transports.replay.models import RecordedStreamInteraction

            recorded_lines: list[str] = []
            try:
                async for sample in real_tr.net_subscribe(
                    path_list,
                    mode=mode,
                    sample_interval=sample_interval,
                    suppress_redundant=suppress_redundant,
                    heartbeat_interval=heartbeat_interval,
                    once=once,
                    encoding=encoding,
                    timeout=timeout,
                ):
                    recorded_lines.append(sample.to_json())
                    yield sample
            finally:
                cassette_proxy.cassette.interactions.append(
                    RecordedStreamInteraction(
                        command=stream_key,
                        lines=recorded_lines,
                    )
                )
                if hasattr(cassette_proxy, "mark_dirty"):
                    cassette_proxy.mark_dirty()
            return

        assert real_tr is not None
        await self._ensure_connected(real_tr)
        async for sample in real_tr.net_subscribe(
            path_list,
            mode=mode,
            sample_interval=sample_interval,
            suppress_redundant=suppress_redundant,
            heartbeat_interval=heartbeat_interval,
            once=once,
            encoding=encoding,
            timeout=timeout,
        ):
            yield sample

    @contextlib.asynccontextmanager
    async def locked(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> AsyncIterator[NetResult]:
        """Асинхронный контекстный менеджер монопольной блокировки хранилища с гарантированным ``unlock``."""
        lock_res = await self.lock(datastore, timeout=timeout)
        lock_res.raise_for_status()
        try:
            yield lock_res
        finally:
            with contextlib.suppress(Exception):
                await self.unlock(datastore, timeout=timeout)

    @contextlib.asynccontextmanager
    async def transaction(
        self,
        *,
        datastore: str = "candidate",
        lock: bool = True,
        validate: bool = True,
        confirmed: bool = False,
        confirm_timeout: int = 60,
        timeout: float | None = None,
    ) -> AsyncIterator[NetworkOperationsService]:
        """Транзакционный контекстный менеджер: ``lock`` -> изменения -> ``validate`` -> ``commit``."""
        if lock:
            lock_res = await self.lock(datastore, timeout=timeout)
            lock_res.raise_for_status()
        try:
            yield self
            if validate:
                val_res = await self.validate(source=datastore, timeout=timeout)
                val_res.raise_for_status()
            commit_res = await self.commit(
                confirmed=confirmed,
                confirm_timeout=confirm_timeout,
                timeout=timeout,
            )
            commit_res.raise_for_status()
        except Exception:
            with contextlib.suppress(Exception):
                await self.discard_changes(timeout=timeout)
            raise
        finally:
            if lock:
                with contextlib.suppress(Exception):
                    await self.unlock(datastore, timeout=timeout)


__all__ = ["NetworkOperationsService"]
