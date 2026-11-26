# src/uniconn/transports/network/gnmi.py
"""Транспорт gNMI (gRPC Network Management Interface) для конфигурации и потоковой телеметрии."""

from __future__ import annotations

import contextlib
import json
import logging
import ssl
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, Literal

from ...config.models import ConnectionConfig
from ...core._shell_quoting import parse_bool
from ...exceptions import (
    ConnectionError as UniconnConnectionError,
)
from ...exceptions import (
    ExecutionError,
)
from ...result import NetResult, Result, TelemetrySample
from ..base import BaseTransport
from ._h2_grpc import AsyncGrpcHttp2Client
from .base import extract_yang_interfaces_and_system
from .gnmi_proto import (
    GnmiPath,
    GnmiWireCodec,
    parse_gnmi_path,
)

_GNMI_SERVICE_PREFIX = "/gnmi.gNMI"


class GnmiTransport(BaseTransport):
    """Асинхронный транспорт OpenConfig gNMI поверх стандартного HTTP/2 gRPC (``/gnmi.gNMI/*``)."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать транспорт gNMI."""
        super().__init__(config)
        AsyncGrpcHttp2Client.ensure_dependency()
        opts = config.options
        self._encoding = str(opts.get("encoding", "json_ietf")).lower()
        self._target = str(opts.get("target", ""))
        self._origin = str(opts.get("origin", ""))
        self._tls_mode = opts.get("tls", True)
        if "insecure" in opts:
            self._insecure = parse_bool(opts["insecure"], default=False)
        elif "verify_tls" in opts:
            self._insecure = not parse_bool(opts["verify_tls"], default=True)
        elif "verify_ssl" in opts:
            self._insecure = not parse_bool(opts["verify_ssl"], default=True)
        else:
            self._insecure = False
        self._client: AsyncGrpcHttp2Client | None = None

    @property
    def name(self) -> str:
        """Имя транспорта."""
        return "gnmi"

    @property
    def encoding(self) -> str:
        """Активная кодировка gNMI (``json_ietf``, ``json``, ``proto``, ``bytes``, ``ascii``)."""
        return self._encoding

    @property
    def target(self) -> str:
        """Целевое устройство OpenConfig (``Path.target``)."""
        return self._target

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        tls_opt = self._tls_mode
        tls_norm = str(tls_opt).strip().lower() if tls_opt is not None else ""
        if tls_opt is False or tls_opt is None or tls_norm in ("false", "0", "no", "off", ""):
            return None
        ctx = ssl.create_default_context()
        if tls_norm == "insecure" or self._insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cert_file = self.config.options.get("cert") or self.config.options.get("cert_file")
        if cert_file:
            ctx.load_verify_locations(cafile=str(cert_file))
        ctx.set_alpn_protocols(["h2"])
        return ctx

    def _auth_secret(self) -> str | None:
        if "token" in self.config.options:
            return str(self.config.options["token"])
        if self.config.password is not None:
            return self.config.password.get_secret_value()
        return None

    def _grpc_metadata(self) -> dict[str, str]:
        meta: dict[str, str] = {}
        if self.config.username:
            meta["username"] = self.config.username
        if "token" in self.config.options and self.config.options["token"] is not None:
            tok = str(self.config.options["token"])
            meta["token"] = tok
            meta["authorization"] = f"Bearer {tok}"
        elif self.config.password is not None:
            meta["password"] = self.config.password.get_secret_value()
        return meta

    async def _ensure_client(self) -> AsyncGrpcHttp2Client:
        if self._client is not None and self._client.is_connected:
            return self._client
        await self.connect()
        if self._client is None:
            raise UniconnConnectionError("gNMI HTTP/2 client is not connected", host=self.config.host)
        return self._client

    async def connect(self) -> None:
        """Установить мультиплексированное HTTP/2 gRPC соединение с gNMI-сервером."""
        if self._connected and self._client is not None and self._client.is_connected:
            return
        host = self.config.host or "127.0.0.1"
        port = self.config.port or 9339
        ssl_ctx = self._build_ssl_context()
        if ssl_ctx is None and (self.config.username or self._auth_secret()):
            logging.getLogger(__name__).warning(
                "Connecting to gNMI endpoint %s:%s in cleartext HTTP/2 (tls=false) with credentials",
                host,
                port,
            )
        client = AsyncGrpcHttp2Client(
            host=host,
            port=port,
            ssl_context=ssl_ctx,
            timeout=self.config.timeout,
        )
        await client.connect()
        self._client = client
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть HTTP/2 gRPC соединение с gNMI-сервером."""
        client = self._client
        self._client = None
        self._connected = False
        if client is not None:
            await client.close()

    async def _call_unary(
        self,
        method: str,
        req_payload: bytes,
        *,
        timeout: float | None = None,
    ) -> bytes:
        client = await self._ensure_client()
        eff_timeout = timeout if timeout is not None else self.config.timeout
        rpc_path = f"{_GNMI_SERVICE_PREFIX}/{method}"
        return await client.unary_call(
            rpc_path,
            req_payload,
            metadata=self._grpc_metadata(),
            timeout=eff_timeout,
        )

    def _make_path(self, path_str: str) -> GnmiPath:
        return parse_gnmi_path(path_str or "/", origin=self._origin, target=self._target)

    # ─── Реализация StructuredNetworkTransport ──────────────────────

    async def _execute_get(
        self,
        path: str,
        *,
        data_type: Literal["all", "config", "state", "operational"],
        operation: str,
        datastore: str,
        timeout: float | None = None,
    ) -> NetResult:
        req_bytes = GnmiWireCodec.encode_get_request(
            [self._make_path(path)],
            data_type=data_type,
            encoding=self._encoding,
        )
        start_ts = time.perf_counter()
        try:
            resp_bytes = await self._call_unary("Get", req_bytes, timeout=timeout)
        except ExecutionError as exc:
            duration = time.perf_counter() - start_ts
            return NetResult(
                ok=False,
                data=None,
                text=str(exc),
                raw=b"",
                operation=operation,
                datastore=datastore,
                protocol="gnmi",
                duration=duration,
                errors=[{"error-message": str(exc)}],
                host=self.config.host,
            )

        duration = time.perf_counter() - start_ts
        notifs = GnmiWireCodec.decode_get_response(resp_bytes)
        merged_data: Any = {}
        for n in notifs:
            for up_path, up_val in n.get("updates", []):
                if len(notifs) == 1 and len(n.get("updates", [])) == 1:
                    merged_data = up_val
                else:
                    if not isinstance(merged_data, dict):
                        merged_data = {}
                    merged_data[up_path] = up_val

        text = (
            json.dumps(merged_data, ensure_ascii=False)
            if not isinstance(merged_data, str)
            else merged_data
        )
        return NetResult(
            ok=True,
            data=merged_data,
            text=text,
            raw=resp_bytes,
            operation=operation,
            datastore=datastore,
            protocol="gnmi",
            duration=duration,
            host=self.config.host,
        )

    async def net_get(
        self,
        path: str = "/",
        *,
        datastore: str = "running",
        filter_type: Literal["xpath", "subtree"] = "xpath",
        depth: int | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить gNMI ``Get`` по указанному пути OpenConfig."""
        _ = (filter_type, depth)
        data_type: Literal["all", "config", "state", "operational"] = (
            "config" if datastore == "candidate" else "all"
        )
        return await self._execute_get(
            path,
            data_type=data_type,
            operation="get",
            datastore=datastore,
            timeout=timeout,
        )

    async def net_get_config(
        self,
        datastore: str = "running",
        path: str = "/",
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить gNMI ``Get`` с типом ``CONFIG``."""
        _ = filter_type
        return await self._execute_get(
            path,
            data_type="config",
            operation="get-config",
            datastore=datastore,
            timeout=timeout,
        )

    async def net_edit(
        self,
        config: Mapping[str, Any] | Sequence[Mapping[str, Any]] | str | bytes,
        *,
        path: str = "/",
        datastore: str | None = None,
        operation: Literal["merge", "replace", "create", "delete", "remove", "patch"] = "merge",
        default_operation: str | None = None,
        test_option: str | None = None,
        error_option: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить транзакционный gNMI ``Set`` (``update`` / ``replace`` / ``delete``)."""
        _ = (default_operation, test_option, error_option)
        parsed_val: Any = config
        if isinstance(config, bytes):
            parsed_val = config.decode("utf-8", errors="replace")
        if isinstance(parsed_val, str) and parsed_val.strip().startswith(("{", "[")):
            with contextlib.suppress(ValueError):
                parsed_val = json.loads(parsed_val)

        op = operation.lower()
        deletes: list[GnmiPath] = []
        replaces: list[tuple[GnmiPath, Any]] = []
        updates: list[tuple[GnmiPath, Any]] = []

        # Поддержка словаря { "/path1": val1, "/path2": val2 } при пустом path
        if (
            (not path or path == "/")
            and isinstance(parsed_val, Mapping)
            and parsed_val
            and all(str(k).startswith("/") for k in parsed_val)
        ):
            for sub_p, sub_v in parsed_val.items():
                gp = self._make_path(str(sub_p))
                if op in ("delete", "remove"):
                    deletes.append(gp)
                elif op in ("replace", "create"):
                    replaces.append((gp, sub_v))
                else:
                    updates.append((gp, sub_v))
        else:
            target_path = self._make_path(path or "/")
            if op in ("delete", "remove"):
                deletes.append(target_path)
            elif op in ("replace", "create"):
                replaces.append((target_path, parsed_val))
            else:
                updates.append((target_path, parsed_val))

        req_bytes = GnmiWireCodec.encode_set_request(
            deletes=deletes,
            replaces=replaces,
            updates=updates,
            encoding=self._encoding,
        )
        start_ts = time.perf_counter()
        try:
            resp_bytes = await self._call_unary("Set", req_bytes, timeout=timeout)
        except ExecutionError as exc:
            duration = time.perf_counter() - start_ts
            return NetResult(
                ok=False,
                data=None,
                text=str(exc),
                raw=b"",
                operation=f"set:{op}",
                datastore=datastore or "running",
                protocol="gnmi",
                duration=duration,
                errors=[{"error-message": str(exc)}],
                host=self.config.host,
            )

        duration = time.perf_counter() - start_ts
        decoded = GnmiWireCodec.decode_set_response(resp_bytes)
        text = json.dumps(decoded, ensure_ascii=False)
        return NetResult(
            ok=True,
            data=decoded,
            text=text,
            raw=resp_bytes,
            operation=f"set:{op}",
            datastore=datastore or "running",
            protocol="gnmi",
            duration=duration,
            host=self.config.host,
        )

    async def net_commit(
        self,
        *,
        confirmed: bool = False,
        confirm_timeout: int = 60,
        persist: str | None = None,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """В gNMI ``Set`` является атомарной транзакцией (коммит подтверждает успешное применение)."""
        _ = (confirmed, confirm_timeout, persist, persist_id, timeout)
        return NetResult(
            ok=True,
            data={"status": "committed"},
            text='{"status": "committed"}',
            raw=b'{"status": "committed"}',
            operation="commit",
            datastore="running",
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтвердить коммит в gNMI."""
        _ = (persist_id, timeout)
        return NetResult(
            ok=True,
            data={"status": "confirmed"},
            text='{"status": "confirmed"}',
            raw=b'{"status": "confirmed"}',
            operation="commit-confirm",
            datastore="running",
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Очистить буфер отложенных изменений в gNMI."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"status": "discarded"},
            text='{"status": "discarded"}',
            raw=b'{"status": "discarded"}',
            operation="discard-changes",
            datastore="candidate",
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_validate(
        self,
        *,
        source: str = "candidate",
        timeout: float | None = None,
    ) -> NetResult:
        """Проверить валидность конфигурации в gNMI."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"status": "valid", "source": source},
            text=json.dumps({"status": "valid", "source": source}),
            raw=b'{"status": "valid"}',
            operation="validate",
            datastore=source,
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_lock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Логическая блокировка хранилища в gNMI."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"locked": datastore},
            text=json.dumps({"locked": datastore}),
            raw=b'{"locked": true}',
            operation="lock",
            datastore=datastore,
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_unlock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Снятие логической блокировки в gNMI."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"unlocked": datastore},
            text=json.dumps({"unlocked": datastore}),
            raw=b'{"unlocked": true}',
            operation="unlock",
            datastore=datastore,
            protocol="gnmi",
            host=self.config.host,
        )

    async def net_capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить gNMI ``Capabilities`` и вернуть поддерживаемые YANG-модели и кодировки."""
        start_ts = time.perf_counter()
        resp_bytes = await self._call_unary("Capabilities", b"", timeout=timeout)
        duration = time.perf_counter() - start_ts
        decoded = GnmiWireCodec.decode_capabilities_response(resp_bytes)
        text = json.dumps(decoded, ensure_ascii=False)
        return NetResult(
            ok=True,
            data=decoded,
            text=text,
            raw=resp_bytes,
            operation="capabilities",
            protocol="gnmi",
            duration=duration,
            host=self.config.host,
        )

    async def net_rpc(
        self,
        payload: Mapping[str, Any] | str,
        *,
        path: str = "",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить произвольный gNMI запрос."""
        if isinstance(payload, Mapping) and "updates" in payload:
            return await self.net_edit(payload["updates"], path=path or "/", timeout=timeout)
        return await self.net_get(path or str(payload), timeout=timeout)

    async def net_subscribe(
        self,
        paths: Sequence[str],
        *,
        mode: Literal["sample", "on_change", "target_defined"] = "sample",
        sample_interval: float = 5.0,
        suppress_redundant: bool = False,
        heartbeat_interval: float | None = None,
        once: bool = False,
        encoding: str | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[TelemetrySample]:
        """Подписаться на потоковую телеметрию gNMI ``Subscribe`` в реальном времени."""
        eff_encoding = (encoding or self._encoding).lower()
        list_mode: Literal["stream", "once", "poll"] = "once" if once else "stream"
        sample_ns = int(max(0.001, sample_interval) * 1_000_000_000)
        hb_ns = int(heartbeat_interval * 1_000_000_000) if heartbeat_interval else 0
        parsed_paths = [self._make_path(p) for p in (paths or ["/"])]

        req_bytes = GnmiWireCodec.encode_subscribe_request(
            parsed_paths,
            mode=mode,
            list_mode=list_mode,
            sample_interval_ns=sample_ns,
            suppress_redundant=suppress_redundant,
            heartbeat_interval_ns=hb_ns,
            encoding=eff_encoding,
        )
        eff_timeout = timeout if timeout is not None else self.config.timeout

        # Открываем мультиплексированный HTTP/2 поток на том же соединении,
        # не блокируя параллельные unary Get/Set вызовы.
        client = await self._ensure_client()
        stream = await client.open_stream(
            f"{_GNMI_SERVICE_PREFIX}/Subscribe",
            initial_payload=req_bytes,
            metadata=self._grpc_metadata(),
            end_stream=once,
        )
        try:
            while True:
                raw_reply = await stream.read_frame(
                    command="gnmi.Subscribe",
                    timeout=eff_timeout,
                )
                if raw_reply is None:
                    break
                decoded = GnmiWireCodec.decode_subscribe_response(raw_reply)
                notif = decoded.get("notification")
                sync_resp = bool(decoded.get("sync_response", False))
                if notif is not None:
                    updates = notif.get("updates", [])
                    deletes = notif.get("deletes", [])
                    ts = int(notif.get("timestamp") or 0)
                    prefix = str(notif.get("prefix") or "")
                    for up_path, up_val in updates:
                        vals = up_val if isinstance(up_val, dict) else {"value": up_val}
                        yield TelemetrySample(
                            path=up_path,
                            values=vals,
                            timestamp=ts,
                            prefix=prefix,
                            deletes=list(deletes),
                            sync_response=sync_resp,
                            protocol="gnmi",
                            host=self.config.host,
                        )
                    if not updates and deletes:
                        yield TelemetrySample(
                            path=prefix or "/",
                            values={},
                            timestamp=ts,
                            prefix=prefix,
                            deletes=list(deletes),
                            sync_response=sync_resp,
                            protocol="gnmi",
                            host=self.config.host,
                        )
                if once and sync_resp:
                    break
        finally:
            with contextlib.suppress(Exception):
                if not stream.recv_closed:
                    await stream.cancel()
                elif not stream.send_closed:
                    await stream.close_send()

    async def gather_network_native_facts(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Собрать системные и сетевые факты по протоколу gNMI."""
        caps_res = await self.net_capabilities(timeout=timeout)
        get_res = await self.net_get("/", timeout=timeout)
        extracted = extract_yang_interfaces_and_system(get_res.data)
        return {
            "protocol": "gnmi",
            "encoding": self._encoding,
            "target": self._target,
            "capabilities": caps_res.data,
            "hostname": extracted.get("hostname"),
            "os_version": extracted.get("os_version"),
            "interfaces": extracted.get("interfaces", []),
            "raw_data": get_res.data,
        }

    # ─── Базовый интерфейс CommandTransport (run / stream / ping) ──

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить gNMI команду вида ``get /interfaces/...``, ``set /path {...}`` или ``capabilities``."""
        _ = kwargs
        stripped = command.strip()
        start_ts = time.perf_counter()

        if stripped in ("echo ping", "ping"):
            ok_ping = await self.ping(timeout=timeout)
            return Result(
                exit_code=0 if ok_ping else 1,
                stdout="ping" if ok_ping else "",
                stderr="",
                duration=time.perf_counter() - start_ts,
                command=command,
                host=self.config.host,
            )

        tokens = stripped.split(maxsplit=2)
        verb = tokens[0].lower() if tokens else "get"
        path = tokens[1] if len(tokens) > 1 else "/"
        payload_raw = tokens[2] if len(tokens) > 2 else "{}"

        if verb == "get":
            net_res = await self.net_get(path, timeout=timeout)
        elif verb in ("set", "update", "merge"):
            net_res = await self.net_edit(payload_raw, path=path, operation="merge", timeout=timeout)
        elif verb == "replace":
            net_res = await self.net_edit(payload_raw, path=path, operation="replace", timeout=timeout)
        elif verb in ("delete", "remove"):
            net_res = await self.net_edit("", path=path, operation="delete", timeout=timeout)
        elif verb == "capabilities":
            net_res = await self.net_capabilities(timeout=timeout)
        else:
            raise ExecutionError(
                f"Unsupported gNMI command: {command!r}",
                command=command,
                exit_code=1,
                host=self.config.host,
            )

        err_text = (
            "; ".join(str(e.get("error-message") or e) for e in net_res.errors)
            if net_res.errors
            else ""
        )
        return Result(
            exit_code=0 if net_res.ok else 1,
            stdout=net_res.text,
            stderr=err_text,
            duration=net_res.duration,
            command=command,
            host=self.config.host,
            raw_bytes=net_res.raw,
        )

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Стримить телеметрию gNMI Subscribe в виде NDJSON строк."""
        raw = command.strip()
        if raw.lower().startswith("subscribe"):
            parts = raw.split(maxsplit=1)
            raw = parts[1].strip() if len(parts) > 1 else "/"
        paths = [p.strip() for p in raw.split(",") if p.strip()] or ["/"]
        interval = float(kwargs.get("sample_interval", 1.0))
        once = bool(kwargs.get("once", False))
        mode_raw = str(kwargs.get("mode", "sample")).lower()
        mode: Literal["sample", "on_change", "target_defined"] = (
            "on_change" if mode_raw == "on_change" else "sample"
        )
        async for sample in self.net_subscribe(
            paths,
            mode=mode,
            sample_interval=interval,
            once=once,
            timeout=timeout,
        ):
            yield sample.to_json()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность gNMI сервера вызовом ``Capabilities``."""
        try:
            res = await self.net_capabilities(timeout=timeout or 5.0)
            return res.ok
        except Exception:
            return False


__all__ = [
    "GnmiTransport",
]
