# src/uniconn/mock/netconf_server.py
"""Сокетный MockNetconfServer (и SyncMockNetconfServer) поверх подсистемы AsyncSSH."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, Self

import asyncssh

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..transports.network.base import (
    apply_yang_edit,
    data_to_xml,
    query_yang_tree,
    safe_parse_xml,
    strip_xml_ns,
    xml_to_data,
)
from ..transports.network.netconf_protocol import (
    BASE_10_CAP,
    BASE_11_CAP,
    CANDIDATE_CAP,
    CONFIRMED_COMMIT_11_CAP,
    NETCONF_BASE_NS,
    NOTIFICATION_CAP,
    ROLLBACK_ON_ERROR_CAP,
    VALIDATE_11_CAP,
    WRITABLE_RUNNING_CAP,
    XPATH_CAP,
    NetconfFrameCodec,
)
from .facade import _get_ephemeral_host_key

DEFAULT_NETCONF_SERVER_CAPABILITIES: tuple[str, ...] = (
    BASE_10_CAP,
    BASE_11_CAP,
    CANDIDATE_CAP,
    CONFIRMED_COMMIT_11_CAP,
    VALIDATE_11_CAP,
    WRITABLE_RUNNING_CAP,
    XPATH_CAP,
    ROLLBACK_ON_ERROR_CAP,
    NOTIFICATION_CAP,
    "urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&revision=2018-02-20",
    "urn:ietf:params:xml:ns:yang:ietf-system?module=ietf-system&revision=2014-08-06",
)


def _default_initial_running() -> dict[str, Any]:
    return {
        "system": {
            "hostname": "mock-edge-rtr-01",
            "platform": {"os-name": "IOS-XE", "os-version": "17.9.4a"},
        },
        "interfaces": {
            "interface": [
                {
                    "name": "GigabitEthernet0/0/0",
                    "description": "WAN Primary",
                    "enabled": True,
                    "mtu": 1500,
                    "phys-address": "00:50:56:ab:cd:01",
                    "oper-status": "up",
                    "ipv4": {"address": [{"ip": "192.0.2.1", "prefix-length": 30}]},
                },
                {
                    "name": "Loopback0",
                    "description": "Router-ID",
                    "enabled": True,
                    "mtu": 65535,
                    "oper-status": "up",
                    "ipv4": {"address": [{"ip": "10.255.255.1", "prefix-length": 32}]},
                },
            ]
        },
        "bgp-state": {"status": "Established", "as": 65001},
    }


class _NetconfServerSSHInterface(asyncssh.SSHServer):
    """Адаптер аутентификации AsyncSSH для ``MockNetconfServer``."""

    def __init__(self, server: MockNetconfServer) -> None:
        self._server = server

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._server._active_connections.add(conn)

    def connection_lost(self, exc: Exception | None) -> None:
        _ = exc

    def begin_auth(self, username: str) -> bool:
        _ = username
        return not self._server.allow_any_auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if self._server.allow_any_auth:
            return True
        return (
            username == (self._server.username or "admin")
            and password == (self._server.password or "secret")
        )


class MockNetconfServer:
    """Асинхронный Mock-сервер протокола NETCONF (RFC 6241 / RFC 6242) поверх AsyncSSH."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        username: str | None = "admin",
        password: str | None = "secret",
        allow_any_auth: bool = False,
        capabilities: Sequence[str] = DEFAULT_NETCONF_SERVER_CAPABILITIES,
        initial_running: Mapping[str, Any] | None = None,
        notifications: Sequence[Mapping[str, Any] | str] = (),
        validator: Callable[[dict[str, Any]], tuple[bool, str]] | None = None,
    ) -> None:
        """Инициализировать ``MockNetconfServer``."""
        self.host = host
        self._port = port
        self.username = username
        self.password = password
        self.allow_any_auth = allow_any_auth
        self.capabilities = list(capabilities)
        self.running: dict[str, Any] = (
            copy.deepcopy(dict(initial_running))
            if initial_running is not None
            else _default_initial_running()
        )
        self.candidate: dict[str, Any] = copy.deepcopy(self.running)
        self.notifications: list[Mapping[str, Any] | str] = list(notifications)
        self.validator = validator
        self.locks: dict[str, str] = {}
        self.history: list[dict[str, Any]] = []
        self._pre_confirmed_running: dict[str, Any] | None = None
        self._confirm_timer_task: asyncio.Task[None] | None = None
        self._session_counter = 0
        self._server: asyncssh.SSHAcceptor | None = None
        self._active_connections: set[asyncssh.SSHServerConnection] = set()

    @property
    def port(self) -> int:
        """Фактический TCP-порт запущенного сервера."""
        return self._port

    @property
    def uri(self) -> str:
        """URI подключения ``netconf://...``."""
        if self.username and self.password:
            return f"netconf://{self.username}:{self.password}@{self.host}:{self._port}"
        if self.username:
            return f"netconf://{self.username}@{self.host}:{self._port}"
        return f"netconf://{self.host}:{self._port}"

    @property
    def is_running(self) -> bool:
        """Запущен ли сервер."""
        return self._server is not None

    def _schedule_confirmed_rollback(self, timeout_sec: float) -> None:
        if self._confirm_timer_task is not None and not self._confirm_timer_task.done():
            self._confirm_timer_task.cancel()

        async def _rollback_on_timeout() -> None:
            await asyncio.sleep(max(0.01, timeout_sec))
            if self._pre_confirmed_running is not None:
                self.running = copy.deepcopy(self._pre_confirmed_running)
                self.candidate = copy.deepcopy(self.running)
                self._pre_confirmed_running = None

        self._confirm_timer_task = asyncio.create_task(_rollback_on_timeout())

    def _cancel_confirmed_timer(self) -> None:
        if self._confirm_timer_task is not None and not self._confirm_timer_task.done():
            self._confirm_timer_task.cancel()
        self._confirm_timer_task = None
        self._pre_confirmed_running = None

    async def _handle_process(self, process: asyncssh.SSHServerProcess[Any]) -> None:
        get_subsys = getattr(process, "get_subsystem", None)
        subsystem = get_subsys() if callable(get_subsys) else getattr(process, "subsystem", None)
        if subsystem != "netconf":
            process.exit(1)
            return

        self._session_counter += 1
        session_id = str(self._session_counter)
        read_buf = bytearray()

        try:
            # 1. Отправляем серверный <hello> (всегда в формате 1.0 ]]>]]>)
            srv_hello = NetconfFrameCodec.encode_hello(self.capabilities, session_id=session_id)
            process.stdout.write(srv_hello)
            await process.stdout.drain()

            # 2. Читаем клиентский <hello>
            cli_hello = await NetconfFrameCodec.read_frame(
                process.stdin,
                read_buf,
                version="1.0",
                timeout=10.0,
            )
            client_caps, _ = NetconfFrameCodec.decode_hello(cli_hello)
            framing_ver: Literal["1.0", "1.1"] = NetconfFrameCodec.negotiate_version(
                client_caps,
                self.capabilities,
                requested_version="auto",
            )

            # 3. Основной цикл обработки <rpc>
            while True:
                try:
                    raw_frame = await NetconfFrameCodec.read_frame(
                        process.stdin,
                        read_buf,
                        version=framing_ver,
                        timeout=30.0,
                    )
                except Exception:
                    break

                reply_xml, should_close, stream_notifs = self._dispatch_rpc(
                    raw_frame,
                    session_id=session_id,
                )
                out_frame = NetconfFrameCodec.encode_frame(reply_xml, version=framing_ver)
                process.stdout.write(out_frame)
                await process.stdout.drain()

                if stream_notifs:
                    for notif_item in stream_notifs:
                        if isinstance(notif_item, str) and notif_item.strip().startswith("<"):
                            notif_xml = notif_item.strip()
                        else:
                            inner = data_to_xml(
                                notif_item if isinstance(notif_item, Mapping) else {"event": str(notif_item)},
                                root_tag="event",
                                default_ns=None,
                            )
                            notif_xml = (
                                '<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">'
                                "<eventTime>2026-11-10T03:00:00Z</eventTime>"
                                f"{inner}"
                                "</notification>"
                            )
                        n_frame = NetconfFrameCodec.encode_frame(notif_xml, version=framing_ver)
                        process.stdout.write(n_frame)
                        await process.stdout.drain()

                if should_close:
                    break
        finally:
            # Освобождаем все локи, удерживаемые этой сессией
            for ds, owner in list(self.locks.items()):
                if owner == session_id:
                    self.locks.pop(ds, None)
            with contextlib.suppress(Exception):
                process.exit(0)
                process.close()

    def _dispatch_rpc(
        self,
        raw_frame: bytes,
        *,
        session_id: str,
    ) -> tuple[str, bool, list[Any]]:
        root = safe_parse_xml(raw_frame)
        msg_id = root.attrib.get("message-id", "1")
        op_elem = next(iter(root), None)
        if op_elem is None:
            return self._error_reply(msg_id, "missing-element", "Empty RPC"), False, []

        op_name = strip_xml_ns(op_elem.tag)
        self.history.append(
            {
                "session_id": session_id,
                "message_id": msg_id,
                "operation": op_name,
                "raw": raw_frame.decode("utf-8", errors="replace"),
            }
        )

        if op_name == "close-session":
            return self._ok_reply(msg_id), True, []

        if op_name in ("get", "get-config"):
            ds = "running"
            filter_path = ""
            for child in op_elem:
                ctag = strip_xml_ns(child.tag)
                if ctag == "source":
                    src_child = next(iter(child), None)
                    if src_child is not None:
                        ds = strip_xml_ns(src_child.tag)
                elif ctag == "filter":
                    if "select" in child.attrib:
                        filter_path = child.attrib["select"]
                    else:
                        sub_dict = xml_to_data(child)
                        if isinstance(sub_dict, Mapping) and sub_dict:
                            filter_path = self._subtree_dict_to_xpath(sub_dict)

            target_store = self.candidate if ds == "candidate" else self.running
            queried = query_yang_tree(target_store, filter_path) if filter_path else target_store
            if queried is None:
                data_xml = f'<data xmlns="{NETCONF_BASE_NS}"/>'
            else:
                if filter_path:
                    from ..transports.network.base import parse_yang_path_steps

                    steps = parse_yang_path_steps(filter_path)
                    cur_wrap: Any = dict(queried) if isinstance(queried, Mapping) else queried
                    for step_name, _ in reversed(steps):
                        if not (isinstance(cur_wrap, Mapping) and step_name in cur_wrap):
                            cur_wrap = {step_name: cur_wrap}
                    wrapped_data: dict[str, Any] = (
                        dict(cur_wrap) if isinstance(cur_wrap, Mapping) else {"value": cur_wrap}
                    )
                else:
                    wrapped_data = dict(queried) if isinstance(queried, Mapping) else {"value": queried}
                data_xml = data_to_xml(wrapped_data, root_tag="data", default_ns=NETCONF_BASE_NS)
            return self._data_reply(msg_id, data_xml), False, []

        if op_name == "edit-config":
            ds = "candidate"
            def_op = "merge"
            cfg_elem: ET.Element | None = None
            for child in op_elem:
                ctag = strip_xml_ns(child.tag)
                if ctag == "target":
                    t_child = next(iter(child), None)
                    if t_child is not None:
                        ds = strip_xml_ns(t_child.tag)
                elif ctag == "default-operation" and child.text:
                    def_op = child.text.strip()
                elif ctag == "config":
                    cfg_elem = child

            lock_owner = self.locks.get(ds)
            if lock_owner is not None and lock_owner != session_id:
                return (
                    self._error_reply(
                        msg_id,
                        "lock-denied",
                        f"Datastore {ds} is locked by session {lock_owner}",
                        lock_session_id=lock_owner,
                    ),
                    False,
                    [],
                )

            if cfg_elem is not None:
                parsed_cfg = xml_to_data(cfg_elem)
                target_store = self.candidate if ds == "candidate" else self.running
                if isinstance(parsed_cfg, Mapping):
                    # Проверяем атрибут @operation внутри узлов (например, delete)
                    self._apply_parsed_xml_config(target_store, parsed_cfg, default_op=def_op)
            return self._ok_reply(msg_id), False, []

        if op_name == "validate":
            ds = "candidate"
            for child in op_elem:
                if strip_xml_ns(child.tag) == "source":
                    s_child = next(iter(child), None)
                    if s_child is not None:
                        ds = strip_xml_ns(s_child.tag)
            target_store = self.candidate if ds == "candidate" else self.running
            if self.validator is not None:
                is_valid, reason = self.validator(target_store)
                if not is_valid:
                    return self._error_reply(msg_id, "invalid-value", reason), False, []
            return self._ok_reply(msg_id), False, []

        if op_name == "commit":
            is_confirmed = any(strip_xml_ns(c.tag) == "confirmed" for c in op_elem)
            timeout_sec = 60.0
            for child in op_elem:
                if strip_xml_ns(child.tag) == "confirm-timeout" and child.text:
                    with contextlib.suppress(ValueError):
                        timeout_sec = float(child.text.strip())

            if is_confirmed:
                if self._pre_confirmed_running is None:
                    self._pre_confirmed_running = copy.deepcopy(self.running)
                self.running = copy.deepcopy(self.candidate)
                self._schedule_confirmed_rollback(timeout_sec)
            else:
                self._cancel_confirmed_timer()
                self.running = copy.deepcopy(self.candidate)
            return self._ok_reply(msg_id), False, []

        if op_name == "discard-changes":
            if self._pre_confirmed_running is not None:
                self.running = copy.deepcopy(self._pre_confirmed_running)
                self._cancel_confirmed_timer()
            self.candidate = copy.deepcopy(self.running)
            return self._ok_reply(msg_id), False, []

        if op_name == "lock":
            ds = "candidate"
            for child in op_elem:
                if strip_xml_ns(child.tag) == "target":
                    t_child = next(iter(child), None)
                    if t_child is not None:
                        ds = strip_xml_ns(t_child.tag)
            if ds in self.locks:
                owner = self.locks[ds]
                return (
                    self._error_reply(
                        msg_id,
                        "lock-denied",
                        f"Lock failed, lock is already held by session {owner}",
                        lock_session_id=owner,
                    ),
                    False,
                    [],
                )
            self.locks[ds] = session_id
            return self._ok_reply(msg_id), False, []

        if op_name == "unlock":
            ds = "candidate"
            for child in op_elem:
                if strip_xml_ns(child.tag) == "target":
                    t_child = next(iter(child), None)
                    if t_child is not None:
                        ds = strip_xml_ns(t_child.tag)
            if self.locks.get(ds) == session_id:
                self.locks.pop(ds, None)
                return self._ok_reply(msg_id), False, []
            return (
                self._error_reply(msg_id, "operation-failed", f"Lock on {ds} is not held by this session"),
                False,
                [],
            )

        if op_name == "create-subscription":
            notifs = list(self.notifications) or [
                {"interface-notif": {"name": "GigabitEthernet0/0/0", "state": "up"}}
            ]
            return self._ok_reply(msg_id), False, notifs

        return self._ok_reply(msg_id), False, []

    @classmethod
    def _subtree_dict_to_xpath(cls, sub_dict: Mapping[str, Any]) -> str:
        """Преобразовать распарсенный subtree-фильтр обратно в XPath с предикатами ключей."""
        steps: list[str] = []
        cur: Any = sub_dict
        while isinstance(cur, Mapping):
            non_attr = [(str(k), v) for k, v in cur.items() if not str(k).startswith("@")]
            if not non_attr:
                break
            if len(non_attr) == 1:
                k, v = non_attr[0]
                if isinstance(v, Mapping):
                    sub_non_attr = {
                        str(sk): sv for sk, sv in v.items() if not str(sk).startswith("@")
                    }
                    # Если внутри есть скалярный ключ (например, name) и пустой/вложенный элемент
                    scalar_keys = {
                        sk: sv
                        for sk, sv in sub_non_attr.items()
                        if not isinstance(sv, Mapping | list) and sv not in ("", None, {})
                    }
                    nested_keys = {
                        sk: sv
                        for sk, sv in sub_non_attr.items()
                        if isinstance(sv, Mapping) or sv in ("", None, {})
                    }
                    if scalar_keys:
                        preds = "".join(f"[{sk}={sv}]" for sk, sv in scalar_keys.items())
                        steps.append(f"{k}{preds}")
                        if len(nested_keys) == 1:
                            nk, nv = next(iter(nested_keys.items()))
                            cur = {nk: nv}
                            continue
                        break
                steps.append(k)
                cur = v
            else:
                break
        return "/" + "/".join(steps) if steps else ""

    def _apply_parsed_xml_config(
        self,
        store: dict[str, Any],
        cfg: Mapping[str, Any],
        *,
        default_op: str = "merge",
        prefix: str = "",
    ) -> None:
        cleaned = {str(k): v for k, v in cfg.items() if not str(k).startswith("@")}
        op = str(cfg.get("@operation", default_op)).lower()
        if op in ("delete", "remove") and prefix:
            apply_yang_edit(store, prefix, {}, operation="delete")
            return
        if op == "replace" and prefix:
            apply_yang_edit(store, prefix, cleaned, operation="replace")
            return

        for k, v in list(cleaned.items()):
            child_path = f"{prefix}/{k}" if prefix else f"/{k}"
            if isinstance(v, Mapping):
                child_op = str(v.get("@operation", "")).lower()
                if child_op in ("delete", "remove"):
                    apply_yang_edit(store, child_path, {}, operation="delete")
                    cleaned.pop(k, None)
                elif any(
                    isinstance(sub_v, Mapping) and "@operation" in sub_v
                    for sub_v in v.values()
                ):
                    self._apply_parsed_xml_config(
                        store,
                        v,
                        default_op=default_op,
                        prefix=child_path,
                    )
                    cleaned.pop(k, None)
        if cleaned:
            apply_yang_edit(store, prefix, cleaned, operation=op)

    @staticmethod
    def _ok_reply(msg_id: str) -> str:
        return f'<rpc-reply message-id="{msg_id}" xmlns="{NETCONF_BASE_NS}"><ok/></rpc-reply>'

    @staticmethod
    def _data_reply(msg_id: str, data_xml: str) -> str:
        return f'<rpc-reply message-id="{msg_id}" xmlns="{NETCONF_BASE_NS}">{data_xml}</rpc-reply>'

    @staticmethod
    def _error_reply(
        msg_id: str,
        error_tag: str,
        message: str,
        *,
        lock_session_id: str | None = None,
    ) -> str:
        info_xml = (
            f"<error-info><session-id>{lock_session_id}</session-id></error-info>"
            if lock_session_id
            else ""
        )
        return (
            f'<rpc-reply message-id="{msg_id}" xmlns="{NETCONF_BASE_NS}">'
            "<rpc-error>"
            "<error-type>protocol</error-type>"
            f"<error-tag>{error_tag}</error-tag>"
            "<error-severity>error</error-severity>"
            f"<error-message>{message}</error-message>"
            f"{info_xml}"
            "</rpc-error>"
            "</rpc-reply>"
        )

    async def start(self) -> Self:
        """Запустить сокетный сервер NETCONF."""
        if self._server is not None:
            return self
        host_key = _get_ephemeral_host_key()
        self._server = await asyncssh.create_server(
            lambda: _NetconfServerSSHInterface(self),
            host=self.host,
            port=self._port,
            server_host_keys=[host_key],
            process_factory=self._handle_process,
            encoding=None,
            line_editor=False,
        )
        sockets = self._server.sockets
        if sockets:
            self._port = int(sockets[0].getsockname()[1])
        return self

    async def stop(self) -> None:
        """Остановить сервер NETCONF и закрыть все соединения."""
        self._cancel_confirmed_timer()
        if self._server is not None:
            self._server.close()
            for conn in list(self._active_connections):
                conn.close()
            self._active_connections.clear()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    def to_sync(self) -> SyncMockNetconfServer:
        """Вернуть синхронную обёртку ``SyncMockNetconfServer``."""
        return SyncMockNetconfServer(self)


class SyncMockNetconfServer(SyncProxyMixin):
    """Синхронный фасад ``MockNetconfServer`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        server: MockNetconfServer | None = None,
        portal: EventLoopPortal | None = None,
        **kwargs: Any,
    ) -> None:
        self._async_target = server if isinstance(server, MockNetconfServer) else MockNetconfServer(**kwargs)
        self._portal = portal or EventLoopPortal(owner_name="SyncMockNetconfServer")

    start = sync_method(MockNetconfServer.start)
    stop = sync_method(MockNetconfServer.stop)

    @property
    def host(self) -> str:
        return self._async_target.host

    @property
    def port(self) -> int:
        return self._async_target.port

    @property
    def uri(self) -> str:
        return self._async_target.uri

    @property
    def is_running(self) -> bool:
        return self._async_target.is_running

    @property
    def username(self) -> str | None:
        return self._async_target.username

    @property
    def password(self) -> str | None:
        return self._async_target.password

    @property
    def allow_any_auth(self) -> bool:
        return self._async_target.allow_any_auth

    @property
    def capabilities(self) -> list[str]:
        return self._async_target.capabilities

    @property
    def running(self) -> dict[str, Any]:
        return self._async_target.running

    @property
    def candidate(self) -> dict[str, Any]:
        return self._async_target.candidate

    @property
    def notifications(self) -> list[Any]:
        return self._async_target.notifications

    @property
    def validator(self) -> Any:
        return self._async_target.validator

    @property
    def locks(self) -> dict[str, str]:
        return self._async_target.locks

    @property
    def history(self) -> list[dict[str, Any]]:
        return self._async_target.history

    def __enter__(self) -> Self:
        self._portal.reopen()
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


__all__ = [
    "DEFAULT_NETCONF_SERVER_CAPABILITIES",
    "MockNetconfServer",
    "SyncMockNetconfServer",
]
