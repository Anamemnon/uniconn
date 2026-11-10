# src/uniconn/transports/network/netconf.py
"""Транспорт NETCONF (RFC 6241 / RFC 6242) поверх подсистемы AsyncSSH."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, Literal

import asyncssh

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
from .base import (
    data_to_xml,
    extract_yang_interfaces_and_system,
    safe_parse_xml,
    xml_to_data,
)
from .netconf_protocol import (
    BASE_10_CAP,
    BASE_11_CAP,
    CANDIDATE_CAP,
    NETCONF_BASE_NS,
    NETCONF_NOTIFICATION_NS,
    XPATH_CAP,
    NetconfFrameCodec,
    NetconfVendorAdapter,
    parse_rpc_reply,
)


class NetconfTransport(BaseTransport):
    """Асинхронный транспорт NETCONF поверх SSH-подсистемы ``netconf`` (порт 830)."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать транспорт NETCONF."""
        super().__init__(config)
        self._ssh_conn: asyncssh.SSHClientConnection | None = None
        self._process: Any = None
        self._read_buf = bytearray()
        self._rpc_lock = asyncio.Lock()
        self._msg_counter = 100
        self._framing_version: Literal["1.0", "1.1"] = "1.0"
        self._server_capabilities: list[str] = []
        self._session_id: str | None = None
        self._vendor: str = "ietf"
        self._default_datastore: str = str(config.options.get("datastore") or "candidate")

    @property
    def name(self) -> str:
        """Имя транспорта."""
        return "netconf"

    @property
    def session_id(self) -> str | None:
        """Идентификатор сессии NETCONF, выданный сервером в ``<hello>``."""
        return self._session_id

    @property
    def server_capabilities(self) -> list[str]:
        """Список capabilities, объявленных сервером в ``<hello>``."""
        return list(self._server_capabilities)

    @property
    def framing_version(self) -> Literal["1.0", "1.1"]:
        """Активная версия кадрирования сессии (``"1.0"`` RFC 4742 или ``"1.1"`` RFC 6242)."""
        return self._framing_version

    @property
    def vendor(self) -> str:
        """Определённый диалект сетевого вендора (``ietf``, ``junos``, ``ios-xe``, ``ios-xr``, ``arista`` и др.)."""
        return self._vendor

    @property
    def default_datastore(self) -> str:
        """Целевое хранилище конфигурации по умолчанию (``candidate`` или ``running``)."""
        return self._default_datastore

    def _next_message_id(self) -> str:
        self._msg_counter += 1
        return str(self._msg_counter)

    def _supports_xpath(self) -> bool:
        if not self._server_capabilities:
            return True
        return any(XPATH_CAP in cap or ":xpath:" in cap for cap in self._server_capabilities)

    async def connect(self) -> None:
        """Установить соединение SSH, открыть подсистему ``netconf`` и выполнить рукопожатие ``<hello>``."""
        if self._connected:
            return

        opts = self.config.options
        req_version = str(opts.get("version", "auto")).strip()
        client_caps = [BASE_10_CAP]
        if req_version != "1.0":
            client_caps.append(BASE_11_CAP)
        extra_caps = opts.get("capabilities")
        if isinstance(extra_caps, list | tuple):
            for c in extra_caps:
                if str(c) not in client_caps:
                    client_caps.append(str(c))

        self._read_buf.clear()
        custom_channel_factory = opts.get("_channel_factory")
        try:
            if callable(custom_channel_factory):
                ch_res: Any = custom_channel_factory()
                self._process = await ch_res if asyncio.iscoroutine(ch_res) else ch_res
            else:
                connect_kwargs: dict[str, Any] = {
                    "host": self.config.host or "127.0.0.1",
                    "port": self.config.port or 830,
                    "username": self.config.username,
                    "encoding": None,
                }
                if self.config.password is not None:
                    connect_kwargs["password"] = self.config.password.get_secret_value()
                if self.config.key_file:
                    connect_kwargs["client_keys"] = [self.config.key_file]
                if self.config.passphrase is not None:
                    connect_kwargs["passphrase"] = self.config.passphrase.get_secret_value()
                strict_hk = bool(
                    opts.get("strict_host_key_checking", opts.get("verify_host_key", False))
                )
                if not strict_hk:
                    connect_kwargs["known_hosts"] = None
                elif "known_hosts" in opts:
                    connect_kwargs["known_hosts"] = opts["known_hosts"]

                self._ssh_conn = await asyncio.wait_for(
                    asyncssh.connect(**connect_kwargs),
                    timeout=self.config.timeout,
                )
                self._process = await asyncio.wait_for(
                    self._ssh_conn.create_process(subsystem="netconf", encoding=None),
                    timeout=self.config.timeout,
                )

            # 1. Отправляем клиентский <hello> (всегда с разделителем 1.0 ]]>]]>)
            hello_bytes = NetconfFrameCodec.encode_hello(client_caps)
            self._process.stdin.write(hello_bytes)
            if hasattr(self._process.stdin, "drain"):
                res_drain = self._process.stdin.drain()
                if asyncio.iscoroutine(res_drain):
                    await res_drain

            # 2. Читаем серверный <hello> (всегда в формате 1.0 ]]>]]>)
            server_hello_raw = await NetconfFrameCodec.read_frame(
                self._process.stdout,
                self._read_buf,
                version="1.0",
                timeout=self.config.timeout,
            )
            self._server_capabilities, self._session_id = NetconfFrameCodec.decode_hello(
                server_hello_raw
            )

            # 3. Проверка strict_capabilities
            if bool(opts.get("strict_capabilities", False)):
                required_caps = opts.get("required_capabilities") or [BASE_10_CAP]
                if isinstance(required_caps, str):
                    required_caps = [c.strip() for c in required_caps.split(",") if c.strip()]
                missing = [
                    req
                    for req in required_caps
                    if not any(req in srv_cap for srv_cap in self._server_capabilities)
                ]
                if missing:
                    raise UniconnConnectionError(
                        f"NETCONF server missing required capabilities: {missing}",
                        host=self.config.host,
                    )

            # 4. Переключение на RFC 6242 v1.1 chunked framing (если согласовано)
            self._framing_version = NetconfFrameCodec.negotiate_version(
                client_caps,
                self._server_capabilities,
                requested_version=req_version,
            )
            self._vendor = NetconfVendorAdapter.detect_vendor(
                self._server_capabilities,
                hint=str(opts.get("vendor", "auto")),
            )
            if "datastore" not in opts:
                has_candidate = any(
                    CANDIDATE_CAP in cap or ":candidate:" in cap
                    for cap in self._server_capabilities
                )
                self._default_datastore = "candidate" if has_candidate else "running"

            self._connected = True
        except asyncssh.PermissionDenied as exc:
            await self._cleanup_resources()
            raise AuthenticationError(
                f"NETCONF SSH authentication failed: {exc}",
                host=self.config.host,
            ) from exc
        except TimeoutError as exc:
            await self._cleanup_resources()
            raise UniconnTimeoutError(
                f"NETCONF connection timed out after {self.config.timeout}s",
                host=self.config.host,
            ) from exc
        except UniconnConnectionError:
            await self._cleanup_resources()
            raise
        except Exception as exc:
            await self._cleanup_resources()
            raise UniconnConnectionError(
                f"Failed to establish NETCONF session: {exc}",
                host=self.config.host,
            ) from exc

    async def _cleanup_resources(self) -> None:
        if self._process is not None:
            with contextlib.suppress(Exception):
                self._process.close()
            self._process = None
        if self._ssh_conn is not None:
            with contextlib.suppress(Exception):
                self._ssh_conn.close()
                await self._ssh_conn.wait_closed()
            self._ssh_conn = None
        self._connected = False

    async def disconnect(self) -> None:
        """Корректно закрыть сессию NETCONF (``<close-session/>``) и SSH-канал."""
        if self._connected and self._process is not None:
            with contextlib.suppress(Exception):
                await self.send_rpc(
                    "<close-session/>",
                    operation="close-session",
                    timeout=2.0,
                )
        await self._cleanup_resources()

    async def send_rpc(
        self,
        inner_xml: str,
        *,
        operation: str = "rpc",
        datastore: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Отправить XML-RPC запрос и вернуть типизированный ``NetResult``."""
        if not self._connected or self._process is None:
            await self.connect()

        eff_timeout = timeout if timeout is not None else self.config.timeout
        msg_id = self._next_message_id()
        stripped = inner_xml.strip()
        if stripped.startswith("<rpc"):
            root = safe_parse_xml(stripped)
            msg_id = root.attrib.get("message-id") or msg_id
            root.set("message-id", msg_id)
            if "xmlns" not in root.attrib and not root.tag.startswith("{"):
                root.set("xmlns", NETCONF_BASE_NS)
            rpc_xml = ET.tostring(root, encoding="unicode")
        else:
            rpc_xml = (
                f'<rpc message-id="{msg_id}" xmlns="{NETCONF_BASE_NS}">'
                f"{stripped}"
                "</rpc>"
            )

        encoded_frame = NetconfFrameCodec.encode_frame(
            rpc_xml,
            version=self._framing_version,
        )
        start_ts = time.perf_counter()
        async with self._rpc_lock:
            assert self._process is not None
            try:
                self._process.stdin.write(encoded_frame)
                if hasattr(self._process.stdin, "drain"):
                    res_drain = self._process.stdin.drain()
                    if asyncio.iscoroutine(res_drain):
                        await res_drain
                reply_bytes = await NetconfFrameCodec.read_frame(
                    self._process.stdout,
                    self._read_buf,
                    version=self._framing_version,
                    timeout=eff_timeout,
                )
            except TimeoutError as exc:
                raise UniconnTimeoutError(
                    f"NETCONF RPC {operation!r} timed out after {eff_timeout}s",
                    command=operation,
                    host=self.config.host,
                ) from exc

        duration = time.perf_counter() - start_ts
        ok, data, text, errors, reply_msg_id = parse_rpc_reply(
            reply_bytes,
            operation=operation,
            datastore=datastore,
            duration=duration,
            host=self.config.host,
        )
        return NetResult(
            ok=ok,
            data=data,
            text=text,
            raw=reply_bytes,
            operation=operation,
            datastore=datastore,
            protocol="netconf",
            duration=duration,
            errors=errors,
            host=self.config.host,
            message_id=reply_msg_id or msg_id,
        )

    # ─── Реализация StructuredNetworkTransport ──────────────────────

    async def net_get(
        self,
        path: str = "",
        *,
        datastore: str = "running",
        filter_type: Literal["xpath", "subtree"] = "xpath",
        depth: int | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<get>`` с опциональным XPath или subtree фильтром."""
        _ = depth
        filter_xml = NetconfVendorAdapter.build_filter_xml(
            path,
            filter_type=filter_type,
            supports_xpath=self._supports_xpath(),
        )
        rpc_body = f"<get>{filter_xml}</get>"
        return await self.send_rpc(
            rpc_body,
            operation="get",
            datastore=datastore,
            timeout=timeout,
        )

    async def net_get_config(
        self,
        datastore: str | None = None,
        path: str = "",
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<get-config>`` из указанного хранилища."""
        target_ds = datastore or self._default_datastore
        filter_xml = NetconfVendorAdapter.build_filter_xml(
            path,
            filter_type=filter_type,
            supports_xpath=self._supports_xpath(),
        )
        rpc_body = f"<get-config><source><{target_ds}/></source>{filter_xml}</get-config>"
        return await self.send_rpc(
            rpc_body,
            operation="get-config",
            datastore=target_ds,
            timeout=timeout,
        )

    async def net_edit(
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
        """Выполнить NETCONF ``<edit-config>`` на целевом хранилище."""
        target_ds = datastore or self._default_datastore
        if isinstance(config, Sequence) and not isinstance(config, (str, bytes)):
            merged_seq: dict[str, Any] = {}
            for item in config:
                merged_seq.update(item)
            config = merged_seq
        payload_data: Mapping[str, Any] | str | bytes = config
        if path and isinstance(config, Mapping):
            from .base import parse_yang_path_steps

            steps = parse_yang_path_steps(path)
            wrapped: Any = dict(config)
            if operation in ("delete", "remove"):
                wrapped["@operation"] = operation
            for node_name, keys in reversed(steps):
                if (
                    isinstance(wrapped, Mapping)
                    and len(wrapped) == 1
                    and next(iter(wrapped.keys())).split(":")[-1] == node_name
                ):
                    inner_dict = dict(next(iter(wrapped.values())))
                    for k, v in keys.items():
                        inner_dict.setdefault(k, v)
                    wrapped = {node_name: inner_dict}
                else:
                    merged_node: dict[str, Any] = {**keys}
                    if isinstance(wrapped, Mapping):
                        merged_node.update(wrapped)
                    wrapped = {node_name: merged_node}
            payload_data = wrapped

        config_xml = data_to_xml(payload_data, root_tag="config", default_ns=NETCONF_BASE_NS)
        def_op = default_operation or (operation if operation in ("merge", "replace", "none") else "merge")
        def_op_xml = f"<default-operation>{def_op}</default-operation>" if def_op else ""
        test_xml = f"<test-option>{test_option}</test-option>" if test_option else ""
        err_xml = f"<error-option>{error_option}</error-option>" if error_option else ""

        rpc_body = (
            f"<edit-config>"
            f"<target><{target_ds}/></target>"
            f"{def_op_xml}{test_xml}{err_xml}"
            f"{config_xml}"
            f"</edit-config>"
        )
        return await self.send_rpc(
            rpc_body,
            operation="edit-config",
            datastore=target_ds,
            timeout=timeout,
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
        """Выполнить NETCONF ``<commit>`` (с поддержкой ``<confirmed/>`` и ``<confirm-timeout>``)."""
        parts = ["<commit>"]
        if confirmed:
            parts.append("<confirmed/>")
            parts.append(f"<confirm-timeout>{int(confirm_timeout)}</confirm-timeout>")
        if persist:
            parts.append(f"<persist>{persist}</persist>")
        if persist_id:
            parts.append(f"<persist-id>{persist_id}</persist-id>")
        parts.append("</commit>")
        return await self.send_rpc(
            "".join(parts),
            operation="commit",
            datastore="running",
            timeout=timeout,
        )

    async def net_commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтвердить активный ``confirmed commit`` отправкой подтверждающего ``<commit>``."""
        rpc_body = (
            f"<commit><persist-id>{persist_id}</persist-id></commit>"
            if persist_id
            else "<commit/>"
        )
        return await self.send_rpc(
            rpc_body,
            operation="commit-confirm",
            datastore="running",
            timeout=timeout,
        )

    async def net_discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<discard-changes/>``."""
        return await self.send_rpc(
            "<discard-changes/>",
            operation="discard-changes",
            datastore="candidate",
            timeout=timeout,
        )

    async def net_validate(
        self,
        *,
        source: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<validate>`` для хранилища ``source``."""
        target_src = source or self._default_datastore
        rpc_body = f"<validate><source><{target_src}/></source></validate>"
        return await self.send_rpc(
            rpc_body,
            operation="validate",
            datastore=target_src,
            timeout=timeout,
        )

    async def net_lock(
        self,
        datastore: str | None = None,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<lock>`` для указанного хранилища."""
        target_ds = datastore or self._default_datastore
        rpc_body = f"<lock><target><{target_ds}/></target></lock>"
        return await self.send_rpc(
            rpc_body,
            operation="lock",
            datastore=target_ds,
            timeout=timeout,
        )

    async def net_unlock(
        self,
        datastore: str | None = None,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить NETCONF ``<unlock>`` для указанного хранилища."""
        target_ds = datastore or self._default_datastore
        rpc_body = f"<unlock><target><{target_ds}/></target></unlock>"
        return await self.send_rpc(
            rpc_body,
            operation="unlock",
            datastore=target_ds,
            timeout=timeout,
        )

    async def net_capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Вернуть согласованные capabilities сессии NETCONF в виде ``NetResult``."""
        _ = timeout
        if not self._connected:
            await self.connect()
        payload = {
            "session_id": self._session_id,
            "framing_version": self._framing_version,
            "vendor": self._vendor,
            "capabilities": list(self._server_capabilities),
        }
        text = json.dumps(payload, ensure_ascii=False)
        return NetResult(
            ok=True,
            data=payload,
            text=text,
            raw=text.encode("utf-8"),
            operation="capabilities",
            protocol="netconf",
            host=self.config.host,
        )

    async def net_rpc(
        self,
        payload: Mapping[str, Any] | str,
        *,
        path: str = "",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить произвольный NETCONF XML-RPC."""
        _ = path
        if isinstance(payload, Mapping):
            xml_str = data_to_xml(payload, root_tag="rpc-payload", default_ns=None)
            root = safe_parse_xml(xml_str)
            inner = "".join(ET.tostring(child, encoding="unicode") for child in root)
        else:
            inner = str(payload)
        return await self.send_rpc(inner, operation="rpc", timeout=timeout)

    async def net_subscribe(
        self,
        paths: Sequence[str] = (),
        *,
        mode: Literal["sample", "on_change", "target_defined"] = "sample",
        sample_interval: float = 5.0,
        suppress_redundant: bool = False,
        heartbeat_interval: float | None = None,
        once: bool = False,
        encoding: str | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[TelemetrySample]:
        """Подписаться на поток уведомлений NETCONF (``<create-subscription>`` RFC 5277)."""
        _ = (mode, sample_interval, suppress_redundant, heartbeat_interval, encoding)
        if not self._connected or self._process is None:
            await self.connect()

        stream_name = "NETCONF"
        filter_xml = ""
        if paths:
            first_path = paths[0]
            if not first_path.startswith("/"):
                stream_name = first_path
            else:
                filter_xml = NetconfVendorAdapter.build_filter_xml(
                    first_path,
                    filter_type="xpath",
                    supports_xpath=self._supports_xpath(),
                )
        sub_rpc = (
            f'<create-subscription xmlns="{NETCONF_NOTIFICATION_NS}">'
            f"<stream>{stream_name}</stream>"
            f"{filter_xml}"
            "</create-subscription>"
        )
        res = await self.send_rpc(sub_rpc, operation="create-subscription", timeout=timeout)
        res.raise_for_status()

        eff_timeout = timeout if timeout is not None else self.config.timeout
        while self._connected and self._process is not None:
            try:
                frame = await NetconfFrameCodec.read_frame(
                    self._process.stdout,
                    self._read_buf,
                    version=self._framing_version,
                    timeout=eff_timeout,
                )
            except (UniconnConnectionError, asyncio.CancelledError):
                break
            root = safe_parse_xml(frame)
            parsed = xml_to_data(root)
            event_time = 0
            if isinstance(parsed, Mapping) and "eventTime" in parsed:
                parsed = dict(parsed)
                parsed.pop("eventTime", None)
            yield TelemetrySample(
                path=paths[0] if paths else f"/{stream_name}",
                values=parsed if isinstance(parsed, dict) else {"value": parsed},
                timestamp=event_time or int(time.time() * 1e9),
                protocol="netconf",
                host=self.config.host,
            )
            if once:
                break

    async def gather_network_native_facts(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Собрать сетевые и системные факты через NETCONF ``<get>``."""
        res = await self.net_get(path="", timeout=timeout)
        extracted = extract_yang_interfaces_and_system(res.data)
        return {
            "protocol": "netconf",
            "vendor": self._vendor,
            "session_id": self._session_id,
            "framing_version": self._framing_version,
            "capabilities": list(self._server_capabilities),
            "hostname": extracted.get("hostname"),
            "os_version": extracted.get("os_version"),
            "interfaces": extracted.get("interfaces", []),
            "raw_data": res.data,
        }

    # ─── Базовый интерфейс CommandTransport (run / stream / ping) ──

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить сырой XML-RPC или текстовую команду NETCONF и вернуть ``Result``."""
        _ = kwargs
        stripped = command.strip()
        start_ts = time.perf_counter()

        if stripped in ("echo ping", "ping"):
            if not self._connected:
                await self.connect()
            return Result(
                exit_code=0,
                stdout="ping",
                stderr="",
                duration=time.perf_counter() - start_ts,
                command=command,
                host=self.config.host,
            )

        if stripped.startswith("<"):
            net_res = await self.send_rpc(stripped, operation="raw-rpc", timeout=timeout)
        else:
            parts = stripped.split(maxsplit=1)
            verb = parts[0].lower() if parts else ""
            arg = parts[1].strip() if len(parts) > 1 else ""
            if verb == "get":
                net_res = await self.net_get(path=arg, timeout=timeout)
            elif verb == "get-config":
                sub_parts = arg.split(maxsplit=1)
                ds = sub_parts[0] if sub_parts else self._default_datastore
                xpath = sub_parts[1] if len(sub_parts) > 1 else ""
                net_res = await self.net_get_config(datastore=ds, path=xpath, timeout=timeout)
            elif verb in ("edit", "edit-config"):
                net_res = await self.net_edit(arg, timeout=timeout)
            elif verb == "commit":
                is_conf = "confirmed" in arg.lower()
                net_res = await self.net_commit(confirmed=is_conf, timeout=timeout)
            elif verb in ("discard", "discard-changes"):
                net_res = await self.net_discard_changes(timeout=timeout)
            elif verb == "validate":
                net_res = await self.net_validate(source=arg or None, timeout=timeout)
            elif verb == "lock":
                net_res = await self.net_lock(datastore=arg or None, timeout=timeout)
            elif verb == "unlock":
                net_res = await self.net_unlock(datastore=arg or None, timeout=timeout)
            elif verb == "capabilities":
                net_res = await self.net_capabilities(timeout=timeout)
            else:
                raise ExecutionError(
                    f"Unsupported NETCONF command: {command!r}",
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
        """Стримить события NETCONF Notification в виде JSON-строк."""
        _ = kwargs
        path = command.strip() if command else "NETCONF"
        if path.lower().startswith("subscribe"):
            parts = path.split(maxsplit=1)
            path = parts[1].strip() if len(parts) > 1 else "NETCONF"
        async for sample in self.net_subscribe([path], timeout=timeout):
            yield sample.to_json()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить активность сессии NETCONF."""
        try:
            if not self._connected:
                await self.connect()
            return self._connected and self._process is not None
        except Exception:
            return False


__all__ = ["NetconfTransport"]
