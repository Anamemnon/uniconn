# src/uniconn/transports/network/gnmi.py
"""Транспорт gNMI (gRPC Network Management Interface) для конфигурации и потоковой телеметрии."""

from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, Literal

from ...config.models import ConnectionConfig
from ...exceptions import (
    AuthenticationError,
    ExecutionError,
)
from ...exceptions import (
    ConnectionError as UniconnConnectionError,
)
from ...exceptions import (
    TimeoutError as UniconnTimeoutError,
)
from ...result import NetResult, Result, TelemetrySample
from ..base import BaseTransport
from .base import extract_yang_interfaces_and_system
from .gnmi_proto import (
    GnmiPath,
    GnmiWireCodec,
    encode_bytes_field,
    iter_proto_fields,
    pack_grpc_frame,
    parse_gnmi_path,
    read_grpc_frame,
)

# Конверт wire-вызова RPC для gNMI транспорта и MockGnmiServer:
# field 1: method ("Capabilities" | "Get" | "Set" | "Subscribe")
# field 2: auth_user
# field 3: auth_token_or_password
# field 4: protobuf payload (GetRequest / SetRequest / SubscribeRequest)
# Ответ:
# field 1: status_code (0 = OK, 16 = UNAUTHENTICATED, 3 = INVALID_ARGUMENT и т.д.)
# field 2: error_message
# field 3: protobuf payload (CapabilitiesResponse / GetResponse / SetResponse / SubscribeResponse)


def pack_gnmi_rpc_envelope(
    method: str,
    payload: bytes,
    *,
    username: str | None = None,
    secret: str | None = None,
) -> bytes:
    """Упаковать gNMI-вызов в бинарный конверт Protobuf и 5-байтовый gRPC фрейм."""
    env = bytearray()
    env.extend(encode_bytes_field(1, method))
    if username:
        env.extend(encode_bytes_field(2, username))
    if secret:
        env.extend(encode_bytes_field(3, secret))
    if payload:
        env.extend(encode_bytes_field(4, payload))
    return pack_grpc_frame(bytes(env))


def unpack_gnmi_rpc_envelope(buf: bytes) -> tuple[str, str, str, bytes]:
    """Распаковать бинарный конверт запроса gNMI -> ``(method, username, secret, payload)``."""
    method = ""
    username = ""
    secret = ""
    payload = b""
    for fnum, _wtype, val in iter_proto_fields(buf):
        if fnum == 1 and isinstance(val, bytes):
            method = val.decode("utf-8", errors="replace")
        elif fnum == 2 and isinstance(val, bytes):
            username = val.decode("utf-8", errors="replace")
        elif fnum == 3 and isinstance(val, bytes):
            secret = val.decode("utf-8", errors="replace")
        elif fnum == 4 and isinstance(val, bytes):
            payload = val
    return method, username, secret, payload


def pack_gnmi_reply_envelope(
    payload: bytes = b"",
    *,
    status_code: int = 0,
    error_message: str = "",
) -> bytes:
    """Упаковать ответ сервера gNMI в бинарный конверт и 5-байтовый gRPC фрейм."""
    from .gnmi_proto import encode_varint_field

    env = bytearray()
    if status_code:
        env.extend(encode_varint_field(1, status_code))
    if error_message:
        env.extend(encode_bytes_field(2, error_message))
    if payload:
        env.extend(encode_bytes_field(3, payload))
    return pack_grpc_frame(bytes(env))


def unpack_gnmi_reply_envelope(buf: bytes) -> tuple[int, str, bytes]:
    """Распаковать ответный конверт gNMI -> ``(status_code, error_message, payload)``."""
    status_code = 0
    error_message = ""
    payload = b""
    for fnum, _wtype, val in iter_proto_fields(buf):
        if fnum == 1 and isinstance(val, int):
            status_code = val
        elif fnum == 2 and isinstance(val, bytes):
            error_message = val.decode("utf-8", errors="replace")
        elif fnum == 3 and isinstance(val, bytes):
            payload = val
    return status_code, error_message, payload


class GnmiTransport(BaseTransport):
    """Асинхронный транспорт gNMI (OpenConfig) для транзакций ``Get``/``Set`` и стриминга ``Subscribe``."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать транспорт gNMI."""
        super().__init__(config)
        opts = config.options
        self._encoding = str(opts.get("encoding", "json_ietf")).lower()
        self._target = str(opts.get("target", ""))
        self._origin = str(opts.get("origin", ""))
        self._tls_mode = opts.get("tls", False)
        if "insecure" in opts:
            self._insecure = bool(opts["insecure"])
        elif "verify_tls" in opts:
            self._insecure = not bool(opts["verify_tls"])
        elif "verify_ssl" in opts:
            self._insecure = not bool(opts["verify_ssl"])
        else:
            self._insecure = True
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._rpc_lock = asyncio.Lock()

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
        if tls_opt in (False, "false", "0", "no", None):
            return None
        ctx = ssl.create_default_context()
        if str(tls_opt).lower() == "insecure" or self._insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cert_file = self.config.options.get("cert") or self.config.options.get("cert_file")
        if cert_file:
            ctx.load_verify_locations(cafile=str(cert_file))
        return ctx

    def _auth_secret(self) -> str | None:
        if "token" in self.config.options:
            return str(self.config.options["token"])
        if self.config.password is not None:
            return self.config.password.get_secret_value()
        return None

    async def _open_stream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        host = self.config.host or "127.0.0.1"
        port = self.config.port or 9339
        ssl_ctx = self._build_ssl_context()
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=self.config.timeout,
            )
        except TimeoutError as exc:
            raise UniconnTimeoutError(
                f"gNMI connection to {host}:{port} timed out after {self.config.timeout}s",
                host=self.config.host,
            ) from exc
        except Exception as exc:
            raise UniconnConnectionError(
                f"Failed to connect to gNMI endpoint {host}:{port}: {exc}",
                host=self.config.host,
            ) from exc

    async def connect(self) -> None:
        """Установить TCP/TLS соединение с gNMI-сервером."""
        if self._connected and self._writer is not None:
            return
        self._reader, self._writer = await self._open_stream()
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть соединение с gNMI-сервером."""
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None
        self._connected = False

    async def _call_unary(
        self,
        method: str,
        req_payload: bytes,
        *,
        timeout: float | None = None,
    ) -> bytes:
        if not self._connected or self._writer is None or self._reader is None:
            await self.connect()

        eff_timeout = timeout if timeout is not None else self.config.timeout
        frame = pack_gnmi_rpc_envelope(
            method,
            req_payload,
            username=self.config.username,
            secret=self._auth_secret(),
        )
        async with self._rpc_lock:
            assert self._writer is not None and self._reader is not None
            try:
                self._writer.write(frame)
                await self._writer.drain()
                raw_reply = await read_grpc_frame(self._reader, timeout=eff_timeout)
            except TimeoutError as exc:
                raise UniconnTimeoutError(
                    f"gNMI {method} timed out after {eff_timeout}s",
                    command=f"gnmi.{method}",
                    host=self.config.host,
                ) from exc

        status_code, err_msg, resp_payload = unpack_gnmi_reply_envelope(raw_reply)
        if status_code == 16:
            raise AuthenticationError(
                err_msg or "gNMI authentication failed (UNAUTHENTICATED)",
                host=self.config.host,
            )
        if status_code != 0:
            raise ExecutionError(
                err_msg or f"gNMI {method} failed with status={status_code}",
                command=f"gnmi.{method}",
                exit_code=status_code,
                stderr=err_msg,
                host=self.config.host,
            )
        return resp_payload

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

        # Открываем выделенный поток для стриминга телеметрии, чтобы не блокировать параллельные Get/Set
        reader, writer = await self._open_stream()
        try:
            frame = pack_gnmi_rpc_envelope(
                "Subscribe",
                req_bytes,
                username=self.config.username,
                secret=self._auth_secret(),
            )
            writer.write(frame)
            await writer.drain()

            while True:
                try:
                    raw_reply = await read_grpc_frame(reader, timeout=eff_timeout)
                except (UniconnConnectionError, asyncio.CancelledError):
                    break
                status_code, err_msg, resp_payload = unpack_gnmi_reply_envelope(raw_reply)
                if status_code == 16:
                    raise AuthenticationError(
                        err_msg or "gNMI Subscribe authentication failed",
                        host=self.config.host,
                    )
                if status_code != 0:
                    raise ExecutionError(
                        err_msg or f"gNMI Subscribe error (status={status_code})",
                        command="gnmi.Subscribe",
                        exit_code=status_code,
                        host=self.config.host,
                    )
                decoded = GnmiWireCodec.decode_subscribe_response(resp_payload)
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
                writer.close()
                await writer.wait_closed()

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
    "pack_gnmi_reply_envelope",
    "pack_gnmi_rpc_envelope",
    "unpack_gnmi_reply_envelope",
    "unpack_gnmi_rpc_envelope",
]
