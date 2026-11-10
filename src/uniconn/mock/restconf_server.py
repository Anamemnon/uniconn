# src/uniconn/mock/restconf_server.py
"""Асинхронный HTTP MockRestconfServer (и SyncMockRestconfServer) для тестирования RFC 8040 / RFC 8072."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
from collections.abc import Mapping
from typing import Any, Self
from urllib.parse import parse_qs, unquote, urlparse

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..transports.network.base import (
    apply_yang_edit,
    data_to_xml,
    query_yang_tree,
    safe_parse_xml,
    xml_to_data,
)
from .netconf_server import _default_initial_running


class MockRestconfServer:
    """Асинхронный HTTP-сервер, эмулирующий RESTCONF API (RFC 8040 и YANG-Patch RFC 8072)."""

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
            err = {
                "ietf-restconf:errors": {
                    "error": [
                        {
                            "error-type": "protocol",
                            "error-tag": "access-denied",
                            "error-message": "Authentication required",
                        }
                    ]
                }
            }
            return 401, "application/yang-data+json", json.dumps(err)

        wants_xml = (
            "application/yang-data+xml" in norm_headers.get("accept", "")
            and "application/yang-data+json" not in norm_headers.get("accept", "")
        )
        resp_mime = "application/yang-data+xml" if wants_xml else "application/yang-data+json"

        # 3. Корневой ресурс /restconf
        if url_path.rstrip("/") == self.root.rstrip("/"):
            root_info = {
                "ietf-restconf:restconf": {
                    "data": {},
                    "operations": {},
                    "yang-library-version": "2019-01-04",
                }
            }
            return 200, resp_mime, json.dumps(root_info)

        # 4. Поддерево операций /restconf/operations/...
        ops_prefix = f"{self.root.rstrip('/')}/operations"
        if url_path.startswith(ops_prefix):
            op_name = url_path[len(ops_prefix) :].strip("/")
            out = {"ietf-restconf:output": {"operation": op_name or "default", "result": "ok"}}
            return 200, resp_mime, json.dumps(out)

        # 5. Поддерево данных /restconf/data/...
        data_prefix = f"{self.root.rstrip('/')}/data"
        if not url_path.startswith(data_prefix):
            return 404, resp_mime, json.dumps(
                {
                    "ietf-restconf:errors": {
                        "error": [
                            {
                                "error-type": "protocol",
                                "error-tag": "invalid-value",
                                "error-message": f"Unknown endpoint: {url_path}",
                            }
                        ]
                    }
                }
            )

        yang_path = url_path[len(data_prefix) :].strip("/")
        if yang_path == "ietf-yang-library:modules-state":
            mods = {
                "ietf-yang-library:modules-state": {
                    "module-set-id": "1",
                    "module": [
                        {"name": "ietf-interfaces", "revision": "2018-02-20"},
                        {"name": "ietf-system", "revision": "2014-08-06"},
                    ],
                }
            }
            return 200, resp_mime, json.dumps(mods)

        m = method.upper()
        if m == "GET":
            queried = query_yang_tree(self.datastore, yang_path) if yang_path else self.datastore
            if queried is None:
                return 404, resp_mime, json.dumps(
                    {
                        "ietf-restconf:errors": {
                            "error": [
                                {
                                    "error-type": "application",
                                    "error-tag": "data-missing",
                                    "error-message": f"Resource not found: {yang_path}",
                                }
                            ]
                        }
                    }
                )
            if wants_xml:
                wrapped = queried if isinstance(queried, Mapping) else {"value": queried}
                return 200, resp_mime, data_to_xml(wrapped, root_tag="data", default_ns=None)
            return 200, resp_mime, json.dumps(queried, ensure_ascii=False)

        if m == "DELETE":
            apply_yang_edit(self.datastore, yang_path, {}, operation="delete")
            return 204, resp_mime, ""

        # Разбор входного тела JSON / XML
        parsed_body: Any = {}
        if body_str.strip():
            if body_str.strip().startswith("<"):
                parsed_body = xml_to_data(safe_parse_xml(body_str))
            else:
                try:
                    parsed_body = json.loads(body_str)
                except ValueError:
                    return 400, resp_mime, json.dumps(
                        {
                            "ietf-restconf:errors": {
                                "error": [
                                    {
                                        "error-type": "protocol",
                                        "error-tag": "malformed-message",
                                        "error-message": "Invalid JSON payload",
                                    }
                                ]
                            }
                        }
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
                apply_yang_edit(self.datastore, full_target, val, operation=op)
            status_body = {
                "ietf-yang-patch:yang-patch-status": {
                    "patch-id": patch_obj.get("patch-id", "1"),
                    "ok": [None],
                }
            }
            return 200, resp_mime, json.dumps(status_body)

        edit_op = "replace" if m == "PUT" else ("create" if m == "POST" else "merge")
        apply_yang_edit(self.datastore, yang_path, parsed_body, operation=edit_op)
        status_code = 201 if m == "POST" else 204
        return status_code, resp_mime, ""

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
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
