# src/uniconn/mock/restconf_server.py
"""Асинхронный HTTP MockRestconfServer (и SyncMockRestconfServer) для тестирования RFC 8040 / RFC 8072."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any, Self
from urllib.parse import parse_qs, unquote, urlparse

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..transports.network.base import (
    apply_yang_edit,
    data_to_xml,
    query_yang_tree,
    safe_parse_xml,
    strip_xml_ns,
    xml_to_data,
)
from .netconf_server import _default_initial_running


def _restconf_error_payload(
    *,
    error_type: str = "protocol",
    error_tag: str = "invalid-value",
    error_message: str,
    wants_xml: bool = False,
) -> str:
    err_obj = {
        "error": [
            {
                "error-type": error_type,
                "error-tag": error_tag,
                "error-message": error_message,
            }
        ]
    }
    if wants_xml:
        return data_to_xml(err_obj, root_tag="errors", default_ns=None)
    return json.dumps({"ietf-restconf:errors": err_obj})


def _serialize_restconf_body(
    payload: Mapping[str, Any],
    *,
    wants_xml: bool,
    xml_root_tag: str = "data",
    xml_inner: Mapping[str, Any] | None = None,
) -> str:
    if wants_xml:
        return data_to_xml(
            xml_inner if xml_inner is not None else payload,
            root_tag=xml_root_tag,
            default_ns=None,
        )
    return json.dumps(payload, ensure_ascii=False)


class MockRestconfServer:
    """Асинхронный HTTP-сервер, эмулирующий RESTCONF API (RFC 8040, RFC 8072 и опционально SSE/NETCONF-ops)."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        root: str = "/restconf",
        username: str | None = "admin",
        password: str | None = "secret",
        token: str | None = None,
        allow_any_auth: bool = False,
        initial_data: Mapping[str, Any] | None = None,
        support_netconf_ops: bool = False,
        sse_enabled: bool = True,
        sse_events: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        """Инициализировать ``MockRestconfServer``."""
        self.host = host
        self._port = port
        self.root = "/" + root.strip("/") if root.strip("/") else "/restconf"
        self.username = username
        self.password = password
        self.token = token
        self.allow_any_auth = allow_any_auth
        self.datastore: dict[str, Any] = (
            copy.deepcopy(dict(initial_data))
            if initial_data is not None
            else _default_initial_running()
        )
        self.support_netconf_ops = bool(support_netconf_ops)
        self.candidate_datastore: dict[str, Any] = copy.deepcopy(self.datastore)
        self._locks: set[str] = set()
        self.sse_enabled = bool(sse_enabled)
        self.sse_events: list[dict[str, Any]] = (
            [copy.deepcopy(dict(ev)) for ev in sse_events]
            if sse_events is not None
            else []
        )
        self.history: list[dict[str, Any]] = []
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """Фактический TCP-порт запущенного сервера."""
        return self._port

    @property
    def uri(self) -> str:
        """URI подключения ``restconf://...`` (со схемой ``http`` для локального мока)."""
        if self.username and self.password:
            return (
                f"restconf://{self.username}:{self.password}@{self.host}:{self._port}"
                f"{self.root}?scheme=http&verify_ssl=false"
            )
        return f"restconf://{self.host}:{self._port}{self.root}?scheme=http&verify_ssl=false"

    @property
    def is_running(self) -> bool:
        """Запущен ли сервер."""
        return self._server is not None

    def _check_auth(self, headers: Mapping[str, str]) -> bool:
        if self.allow_any_auth or (not self.username and not self.token):
            return True
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.startswith("Bearer "):
            tok = auth_hdr[7:].strip()
            return tok in (self.token, self.password)
        if auth_hdr.startswith("Basic "):
            with contextlib.suppress(Exception):
                decoded = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                u, p = decoded.split(":", 1)
                return u == self.username and p == (self.password or "")
        return False

    def _operations_catalog(self) -> dict[str, list[None]]:
        ops: dict[str, list[None]] = {"reboot": [None]}
        if self.support_netconf_ops:
            for op_name in (
                "ietf-netconf:lock",
                "ietf-netconf:unlock",
                "ietf-netconf:validate",
                "ietf-netconf:commit",
                "ietf-netconf:discard-changes",
                "ietf-netconf:cancel-commit",
            ):
                ops[op_name] = [None]
        return ops

    def _extract_datastore_target(self, body_str: str, default: str = "candidate") -> str:
        stripped = body_str.strip()
        if not stripped:
            return default
        with contextlib.suppress(Exception):
            parsed: Any = (
                xml_to_data(safe_parse_xml(stripped))
                if stripped.startswith("<")
                else json.loads(stripped)
            )
            if isinstance(parsed, Mapping):
                inp = parsed.get("ietf-netconf:input") or parsed.get("input") or parsed
                if isinstance(inp, Mapping):
                    tgt = inp.get("target") or inp.get("source")
                    if isinstance(tgt, Mapping) and tgt:
                        return str(next(iter(tgt.keys())))
        return default

    def _handle_netconf_operation(
        self,
        op_name: str,
        body_str: str,
        resp_mime: str,
        *,
        wants_xml: bool = False,
    ) -> tuple[int, str, str]:
        if not self.support_netconf_ops:
            return 404, resp_mime, _restconf_error_payload(
                error_tag="operation-not-supported",
                error_message=f"Operation not supported: {op_name}",
                wants_xml=wants_xml,
            )

        def _ok_output(out_fields: dict[str, Any]) -> tuple[int, str, str]:
            body = _serialize_restconf_body(
                {"ietf-restconf:output": out_fields},
                wants_xml=wants_xml,
                xml_root_tag="output",
                xml_inner=out_fields,
            )
            return 200, resp_mime, body

        short_op = op_name.split(":", 1)[-1]
        if short_op == "lock":
            target = self._extract_datastore_target(body_str)
            if target in self._locks:
                return 409, resp_mime, _restconf_error_payload(
                    error_tag="lock-denied",
                    error_message=f"Datastore {target!r} is already locked",
                    wants_xml=wants_xml,
                )
            self._locks.add(target)
            return _ok_output({"status": "locked", "target": target})

        if short_op == "unlock":
            target = self._extract_datastore_target(body_str)
            self._locks.discard(target)
            return _ok_output({"status": "unlocked", "target": target})

        if short_op == "validate":
            source = self._extract_datastore_target(body_str)
            return _ok_output({"status": "valid", "source": source})

        if short_op == "commit":
            self.datastore = copy.deepcopy(self.candidate_datastore)
            return _ok_output({"status": "committed"})

        if short_op == "discard-changes":
            self.candidate_datastore = copy.deepcopy(self.datastore)
            return _ok_output({"status": "discarded"})

        if short_op == "cancel-commit":
            return _ok_output({"status": "cancelled"})

        return 404, resp_mime, _restconf_error_payload(
            error_tag="operation-not-supported",
            error_message=f"Unknown NETCONF operation: {op_name}",
            wants_xml=wants_xml,
        )

    def _build_default_sse_events(self, url_path: str) -> list[dict[str, Any]]:
        if self.sse_events:
            return list(self.sse_events)
        sys_data = self.datastore.get("system") or self.datastore
        return [
            {
                "id": "1",
                "event": "notification",
                "data": {
                    "ietf-restconf:notification": {
                        "eventTime": "2026-01-01T00:00:00Z",
                        "path": "/system",
                        "system": copy.deepcopy(sys_data),
                        "stream": url_path,
                    }
                },
            },
            {
                "id": "2",
                "event": "notification",
                "data": {
                    "ietf-restconf:notification": {
                        "eventTime": "2026-01-01T00:00:01Z",
                        "path": "/system",
                        "system": copy.deepcopy(sys_data),
                        "seq": 2,
                    }
                },
            },
        ]

    @staticmethod
    def _format_sse_event(ev: Mapping[str, Any]) -> str:
        frame_lines: list[str] = []
        if ev.get("id"):
            frame_lines.append(f"id: {ev['id']}\n")
        if ev.get("event"):
            frame_lines.append(f"event: {ev['event']}\n")
        payload_json = json.dumps(ev.get("data", {}), ensure_ascii=False, indent=2)
        for json_line in payload_json.splitlines():
            frame_lines.append(f"data: {json_line}\n")
        frame_lines.append("\n")
        return "".join(frame_lines)

    def handle_request(
        self,
        method: str,
        raw_target: str,
        *,
        data: bytes | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, str, str]:
        """Обработать RESTCONF-запрос и вернуть ``(status_code, content_type, body_text)``."""
        norm_headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        parsed_url = urlparse(raw_target)
        url_path = unquote(parsed_url.path)
        query_params = dict(params or {})
        if parsed_url.query:
            for k, vals in parse_qs(parsed_url.query).items():
                query_params.setdefault(k, vals[-1])

        body_str = data.decode("utf-8", errors="replace") if data else ""
        self.history.append(
            {
                "method": method.upper(),
                "path": url_path,
                "params": query_params,
                "body": body_str,
                "headers": norm_headers,
            }
        )

        # 1. RFC 8040 Root Discovery (/.well-known/host-meta)
        if url_path == "/.well-known/host-meta":
            xrd = (
                "<?xml version='1.0' encoding='UTF-8'?>"
                "<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>"
                f"<Link rel='restconf' href='{self.root}'/>"
                "</XRD>"
            )
            return 200, "application/xrd+xml", xrd

        # 2. Проверка аутентификации
        if not self._check_auth(norm_headers):
            return 401, "application/yang-data+json", _restconf_error_payload(
                error_tag="access-denied",
                error_message="Authentication required",
            )

        wants_xml = (
            "application/yang-data+xml" in norm_headers.get("accept", "")
            and "application/yang-data+json" not in norm_headers.get("accept", "")
        )
        resp_mime = "application/yang-data+xml" if wants_xml else "application/yang-data+json"

        # 3. Корневой ресурс /restconf
        if url_path.rstrip("/") == self.root.rstrip("/"):
            root_inner = {
                "data": {},
                "operations": self._operations_catalog(),
                "yang-library-version": "2019-01-04",
            }
            return 200, resp_mime, _serialize_restconf_body(
                {"ietf-restconf:restconf": root_inner},
                wants_xml=wants_xml,
                xml_root_tag="restconf",
                xml_inner=root_inner,
            )

        # 4. Поддерево операций /restconf/operations/...
        ops_prefix = f"{self.root.rstrip('/')}/operations"
        if url_path.rstrip("/") == ops_prefix and method.upper() == "GET":
            ops_cat = self._operations_catalog()
            return 200, resp_mime, _serialize_restconf_body(
                {"ietf-restconf:operations": ops_cat},
                wants_xml=wants_xml,
                xml_root_tag="operations",
                xml_inner=ops_cat,
            )
        if url_path.startswith(ops_prefix):
            op_name = url_path[len(ops_prefix) :].strip("/")
            if op_name.startswith("ietf-netconf:"):
                return self._handle_netconf_operation(op_name, body_str, resp_mime, wants_xml=wants_xml)
            out_inner = {"operation": op_name or "default", "result": "ok"}
            return 200, resp_mime, _serialize_restconf_body(
                {"ietf-restconf:output": out_inner},
                wants_xml=wants_xml,
                xml_root_tag="output",
                xml_inner=out_inner,
            )

        # 5. Потоковый SSE эндпоинт /restconf/streams/... (для прямых HTTP/handler вызовов)
        streams_prefix = f"{self.root.rstrip('/')}/streams"
        if url_path.startswith(streams_prefix):
            if not self.sse_enabled:
                return 404, resp_mime, _restconf_error_payload(
                    error_type="application",
                    error_tag="data-missing",
                    error_message="SSE event stream endpoint is disabled",
                    wants_xml=wants_xml,
                )
            sse_payload = "".join(
                self._format_sse_event(ev) for ev in self._build_default_sse_events(url_path)
            )
            return 200, "text/event-stream", sse_payload

        # 6. Поддерево данных /restconf/data/...
        data_prefix = f"{self.root.rstrip('/')}/data"
        if not url_path.startswith(data_prefix):
            return 404, resp_mime, _restconf_error_payload(
                error_tag="invalid-value",
                error_message=f"Unknown endpoint: {url_path}",
                wants_xml=wants_xml,
            )

        yang_path = url_path[len(data_prefix) :].strip("/")
        if yang_path == "ietf-yang-library:modules-state":
            mod_list = [
                {"name": "ietf-interfaces", "revision": "2018-02-20"},
                {"name": "ietf-system", "revision": "2014-08-06"},
            ]
            if self.support_netconf_ops:
                mod_list.append({"name": "ietf-netconf", "revision": "2011-06-01"})
            mods_inner = {"module-set-id": "1", "module": mod_list}
            return 200, resp_mime, _serialize_restconf_body(
                {"ietf-yang-library:modules-state": mods_inner},
                wants_xml=wants_xml,
                xml_root_tag="modules-state",
                xml_inner=mods_inner,
            )

        if yang_path == "ietf-restconf-monitoring:restconf-state/streams":
            if not self.sse_enabled:
                return 404, resp_mime, _restconf_error_payload(
                    error_type="application",
                    error_tag="data-missing",
                    error_message="No SSE streams available",
                    wants_xml=wants_xml,
                )
            streams_inner = {
                "stream": [
                    {
                        "name": "NETCONF",
                        "description": "Default RESTCONF event stream",
                        "access": [
                            {
                                "encoding": "json",
                                "location": f"{self.root.rstrip('/')}/streams/NETCONF",
                            }
                        ],
                    }
                ]
            }
            return 200, resp_mime, _serialize_restconf_body(
                {"ietf-restconf-monitoring:streams": streams_inner},
                wants_xml=wants_xml,
                xml_root_tag="streams",
                xml_inner=streams_inner,
            )

        use_candidate = (
            self.support_netconf_ops
            and str(query_params.get("datastore", "")).lower() == "candidate"
        )
        active_tree = self.candidate_datastore if use_candidate else self.datastore

        m = method.upper()
        if m == "GET":
            queried = query_yang_tree(active_tree, yang_path) if yang_path else active_tree
            if queried is None:
                return 404, resp_mime, _restconf_error_payload(
                    error_type="application",
                    error_tag="data-missing",
                    error_message=f"Resource not found: {yang_path}",
                )
            if wants_xml:
                wrapped = queried if isinstance(queried, Mapping) else {"value": queried}
                return 200, resp_mime, data_to_xml(wrapped, root_tag="data", default_ns=None)
            return 200, resp_mime, json.dumps(queried, ensure_ascii=False)

        if m == "DELETE":
            apply_yang_edit(active_tree, yang_path, {}, operation="delete")
            return 204, resp_mime, ""

        # Разбор входного тела JSON / XML
        parsed_body: Any = {}
        if body_str.strip():
            if body_str.strip().startswith("<"):
                elem = safe_parse_xml(body_str)
                root_tag = strip_xml_ns(elem.tag)
                xml_val = xml_to_data(elem)
                target_tail = yang_path.split("/")[-1].split(":")[-1] if yang_path else ""
                if root_tag in ("data", "config", "restconf") or (target_tail and root_tag == target_tail):
                    parsed_body = xml_val
                else:
                    parsed_body = {root_tag: xml_val}
            else:
                try:
                    parsed_body = json.loads(body_str)
                except ValueError:
                    return 400, resp_mime, _restconf_error_payload(
                        error_tag="malformed-message",
                        error_message="Invalid JSON payload",
                        wants_xml=wants_xml,
                    )

        # Поддержка RFC 8072 YANG-Patch
        if isinstance(parsed_body, Mapping) and (
            "ietf-yang-patch:yang-patch" in parsed_body or "yang-patch" in parsed_body
        ):
            patch_obj = parsed_body.get("ietf-yang-patch:yang-patch") or parsed_body.get("yang-patch") or {}
            for edit_item in patch_obj.get("edit", []):
                if not isinstance(edit_item, Mapping):
                    continue
                target_sub = str(edit_item.get("target") or "").strip("/")
                full_target = f"{yang_path}/{target_sub}".strip("/")
                op = str(edit_item.get("operation") or "merge").lower()
                val = edit_item.get("value", {})
                apply_yang_edit(active_tree, full_target, val, operation=op)
            status_body = {
                "ietf-yang-patch:yang-patch-status": {
                    "patch-id": patch_obj.get("patch-id", "1"),
                    "ok": [None],
                }
            }
            return 200, resp_mime, json.dumps(status_body)

        edit_op = "replace" if m == "PUT" else ("create" if m == "POST" else "merge")
        apply_yang_edit(active_tree, yang_path, parsed_body, operation=edit_op)
        status_code = 201 if m == "POST" else 204
        return status_code, resp_mime, ""

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        streams_prefix = f"{self.root.rstrip('/')}/streams"
        try:
            while True:
                req_line = await reader.readline()
                if not req_line:
                    break
                parts = req_line.decode("latin-1").strip().split()
                if len(parts) < 2:
                    break
                method, target = parts[0], parts[1]
                headers: dict[str, str] = {}
                while True:
                    hline = await reader.readline()
                    if not hline or hline in (b"\r\n", b"\n"):
                        break
                    h_str = hline.decode("latin-1").strip()
                    if ":" in h_str:
                        hk, hv = h_str.split(":", 1)
                        headers[hk.strip().lower()] = hv.strip()

                content_len = int(headers.get("content-length", "0"))
                body = await reader.readexactly(content_len) if content_len > 0 else b""

                parsed_url = urlparse(target)
                url_path = unquote(parsed_url.path)
                is_sse_req = (
                    method.upper() == "GET"
                    and url_path.startswith(streams_prefix)
                    and "text/event-stream" in headers.get("accept", "").lower()
                    and self.sse_enabled
                    and self._check_auth(headers)
                )
                if is_sse_req:
                    sse_params = {k: vals[-1] for k, vals in parse_qs(parsed_url.query).items()}
                    self.history.append(
                        {
                            "method": "GET",
                            "path": url_path,
                            "params": sse_params,
                            "body": "",
                            "headers": headers,
                        }
                    )
                    sse_hdr = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/event-stream\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Transfer-Encoding: chunked\r\n"
                        "Connection: keep-alive\r\n\r\n"
                    ).encode("latin-1")
                    writer.write(sse_hdr)
                    await writer.drain()
                    sse_evs = self._build_default_sse_events(url_path)
                    for idx, ev in enumerate(sse_evs):
                        chunk_bytes = self._format_sse_event(ev).encode("utf-8")
                        writer.write(f"{len(chunk_bytes):x}\r\n".encode("ascii") + chunk_bytes + b"\r\n")
                        await writer.drain()
                        if idx + 1 < len(sse_evs):
                            await asyncio.sleep(0.005)
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                    continue

                status, mime, resp_text = self.handle_request(
                    method,
                    target,
                    data=body,
                    headers=headers,
                )
                resp_bytes = resp_text.encode("utf-8")
                reason = {
                    200: "OK",
                    201: "Created",
                    204: "No Content",
                    400: "Bad Request",
                    401: "Unauthorized",
                    404: "Not Found",
                    409: "Conflict",
                }.get(status, "OK")
                http_resp = (
                    f"HTTP/1.1 {status} {reason}\r\n"
                    f"Content-Type: {mime}\r\n"
                    f"Content-Length: {len(resp_bytes)}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode("latin-1") + resp_bytes
                writer.write(http_resp)
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def start(self) -> Self:
        """Запустить TCP HTTP-сервер RESTCONF."""
        if self._server is not None:
            return self
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self._port,
        )
        sockets = self._server.sockets
        if sockets:
            self._port = int(sockets[0].getsockname()[1])
        return self

    async def stop(self) -> None:
        """Остановить HTTP-сервер RESTCONF."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    def to_sync(self) -> SyncMockRestconfServer:
        """Вернуть синхронный фасад ``SyncMockRestconfServer``."""
        return SyncMockRestconfServer(self)


class SyncMockRestconfServer(SyncProxyMixin):
    """Синхронный фасад ``MockRestconfServer`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        server: MockRestconfServer | None = None,
        portal: EventLoopPortal | None = None,
        **kwargs: Any,
    ) -> None:
        self._async_target = (
            server if isinstance(server, MockRestconfServer) else MockRestconfServer(**kwargs)
        )
        self._portal = portal or EventLoopPortal(owner_name="SyncMockRestconfServer")

    start = sync_method(MockRestconfServer.start)
    stop = sync_method(MockRestconfServer.stop)
    handle_request = MockRestconfServer.handle_request

    @property
    def host(self) -> str:
        return self._async_target.host

    @property
    def port(self) -> int:
        return self._async_target.port

    @property
    def root(self) -> str:
        return self._async_target.root

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
    def token(self) -> str | None:
        return self._async_target.token

    @property
    def allow_any_auth(self) -> bool:
        return self._async_target.allow_any_auth

    @property
    def datastore(self) -> dict[str, Any]:
        return self._async_target.datastore

    @property
    def history(self) -> list[dict[str, Any]]:
        return self._async_target.history

    @property
    def support_netconf_ops(self) -> bool:
        return self._async_target.support_netconf_ops

    @property
    def sse_enabled(self) -> bool:
        return self._async_target.sse_enabled

    def __enter__(self) -> Self:
        self._portal.reopen()
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


__all__ = [
    "MockRestconfServer",
    "SyncMockRestconfServer",
]
