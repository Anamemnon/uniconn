# src/uniconn/transports/network/restconf.py
"""Транспорт RESTCONF (RFC 8040 / RFC 8072 YANG-Patch) поверх асинхронного HTTP/2 клиента niquests."""

from __future__ import annotations

import asyncio
import codecs
import json
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from typing import Any, Literal

from ..._logging import get_logger
from ...config.models import ConnectionConfig
from ...exceptions import (
    AuthenticationError,
    CapabilityNotSupportedError,
    ExecutionError,
)
from ...exceptions import ConnectionError as UniconnConnectionError
from ...exceptions import TimeoutError as UniconnTimeoutError
from ...result import NetResult, Result, TelemetrySample
from .._http_base import BaseAsyncHttpClient, builtins_timeout_errors, resolve_niquests_module
from ..base import BaseTransport
from .base import (
    data_to_xml,
    extract_yang_interfaces_and_system,
    safe_parse_xml,
    xml_to_data,
)

_logger = get_logger("uniconn.transports.network.restconf")

YANG_JSON_MIME = "application/yang-data+json"
YANG_XML_MIME = "application/yang-data+xml"
YANG_PATCH_JSON_MIME = "application/yang-patch+json"
YANG_PATCH_XML_MIME = "application/yang-patch+xml"
SSE_MIME = "text/event-stream"

_HOST_META_LINK_RE = re.compile(
    r"""<Link[^>]+rel=['"]restconf['"][^>]+href=['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class _SseUnsupportedError(Exception):
    """Внутреннее исключение о недоступности или отклонении SSE-потока RESTCONF."""

    def __init__(self, reason: str, *, status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class _SseEventParser:
    """Инкрементальный парсер событий Server-Sent Events (RFC 8040 / WHATWG)."""

    def __init__(self) -> None:
        self._line_buf = ""
        self._ev_name = ""
        self._ev_id = ""
        self._data_lines: list[str] = []

    def _emit_ready(self) -> dict[str, str] | None:
        if not self._data_lines:
            self._ev_name = ""
            return None
        ev = {
            "event": self._ev_name or "message",
            "data": "\n".join(self._data_lines),
            "id": self._ev_id,
        }
        self._ev_name = ""
        self._data_lines = []
        return ev

    def _process_line(self, raw_line: str) -> dict[str, str] | None:
        line = raw_line.rstrip("\r\n")
        if line == "":
            return self._emit_ready()
        if line.startswith(":"):
            return None
        if ":" in line:
            field_name, value = line.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field_name, value = line, ""

        if field_name == "event":
            self._ev_name = value
        elif field_name == "data":
            self._data_lines.append(value)
        elif field_name == "id" and "\x00" not in value:
            self._ev_id = value
        return None

    def feed(self, text_chunk: str) -> list[dict[str, str]]:
        """Добавить очередной текстовый фрагмент и вернуть все завершённые SSE-события."""
        if not text_chunk:
            return []
        combined = self._line_buf + text_chunk
        # Придерживаем хвостовой '\r' до следующего куска, чтобы корректно склеить '\r\n' на стыке чанков
        if combined.endswith("\r"):
            prefix, trailing_cr = combined[:-1], "\r"
        else:
            prefix, trailing_cr = combined, ""
        self._line_buf = prefix.replace("\r\n", "\n").replace("\r", "\n") + trailing_cr

        events: list[dict[str, str]] = []
        while "\n" in self._line_buf:
            sep_idx = self._line_buf.index("\n")
            one_line = self._line_buf[: sep_idx + 1]
            self._line_buf = self._line_buf[sep_idx + 1 :]
            ready = self._process_line(one_line)
            if ready is not None:
                events.append(ready)
        return events

    def finish(self) -> list[dict[str, str]]:
        """Завершить разбор при закрытии потока и вернуть оставшиеся события."""
        events: list[dict[str, str]] = []
        if self._line_buf:
            for one_line in self._line_buf.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                ready = self._process_line(one_line)
                if ready is not None:
                    events.append(ready)
            self._line_buf = ""
        tail = self._emit_ready()
        if tail is not None:
            events.append(tail)
        return events


class RestconfClient(BaseAsyncHttpClient):
    """Асинхронный HTTP/HTTPS клиент для работы с RESTCONF API (RFC 8040)."""

    def __init__(
        self,
        base_url: str,
        *,
        root: str = "/restconf",
        fmt: Literal["json", "xml"] = "json",
        auth_type: str = "basic",
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_ssl: bool | str = True,
        timeout: float = 30.0,
        discover_root: bool = False,
        http_handler: Callable[..., Any] | None = None,
    ) -> None:
        """Инициализировать клиент RESTCONF."""
        super().__init__(
            base_url=base_url,
            verify=verify_ssl,
            default_timeout=timeout,
            multiplexed=False,
            error_prefix="RESTCONF",
        )
        self.root = "/" + root.strip("/") if root.strip("/") else "/restconf"
        self.fmt: Literal["json", "xml"] = "xml" if str(fmt).lower() == "xml" else "json"
        self.auth_type = auth_type.lower()
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.discover_root = discover_root
        self._http_handler = http_handler
        self._connected = False

    @property
    def _session(self) -> Any:
        return self.session

    @_session.setter
    def _session(self, value: Any) -> None:
        self.session = value

    def _get_niquests(self) -> Any:
        return resolve_niquests_module(__name__)

    @property
    def is_connected(self) -> bool:
        """Активна ли HTTP-сессия."""
        return self._connected

    def _default_headers(self, *, is_patch: bool = False) -> dict[str, str]:
        accept_mime = YANG_XML_MIME if self.fmt == "xml" else YANG_JSON_MIME
        content_mime = (
            (YANG_PATCH_XML_MIME if self.fmt == "xml" else YANG_PATCH_JSON_MIME)
            if is_patch
            else accept_mime
        )
        headers = {
            "Accept": f"{accept_mime}, application/json, application/xml, */*",
            "Content-Type": content_mime,
        }
        if self.auth_type in ("bearer", "token") and (self.token or self.password):
            tok = self.token or self.password or ""
            headers["Authorization"] = f"Bearer {tok}"
        return headers

    async def connect(self) -> None:
        """Открыть сессию ``niquests.AsyncSession`` и при необходимости выполнить RFC 8040 Root Discovery."""
        if self._connected:
            return
        if self._http_handler is None:
            auth = None
            if self.auth_type == "basic" and self.username is not None:
                auth = (self.username, self.password or "")
            self.session = self._build_session(
                install_extra="restconf",
                use_optional_dep=True,
                pass_base_url=False,
                auth=auth,
            )

        self._connected = True
        try:
            if self.discover_root:
                await self._discover_restconf_root()
        except Exception:
            await self.close()
            raise

    async def _discover_restconf_root(self) -> str:
        """Определить корневой путь RESTCONF через ``GET /.well-known/host-meta`` (RFC 8040 Section 3.1)."""
        status, text, _raw = await self.raw_request(
            "GET",
            "/.well-known/host-meta",
            headers={"Accept": "application/xrd+xml, text/xml, */*"},
        )
        if 200 <= status < 300 and text:
            match = _HOST_META_LINK_RE.search(text)
            if match:
                self.root = "/" + match.group(1).strip("/")
        return self.root

    async def close(self) -> None:
        """Закрыть HTTP-сессию."""
        await super().close()
        self._connected = False

    def _resolve_url(self, url_path: str) -> str:
        return (
            url_path
            if url_path.startswith(("http://", "https://"))
            else f"{self.base_url}/{url_path.lstrip('/')}"
        )

    async def _invoke_http_handler(
        self,
        method: str,
        url_path: str,
        *,
        data: bytes | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str],
    ) -> tuple[int, dict[str, str], Any]:
        handler = self._http_handler
        if handler is None:
            raise RuntimeError("HTTP handler is not configured")
        res = handler(
            method.upper(),
            url_path,
            data=data,
            params=dict(params or {}),
            headers=dict(headers),
        )
        if asyncio.iscoroutine(res):
            res = await res
        if isinstance(res, tuple) and len(res) == 3:
            status_raw, middle, resp_body = res
            if isinstance(middle, str):
                resp_hdrs = {"content-type": middle}
            elif isinstance(middle, Mapping):
                resp_hdrs = {str(k).lower(): str(v) for k, v in middle.items()}
            else:
                resp_hdrs = {}
            return int(status_raw), resp_hdrs, resp_body
        status_raw, resp_body = res
        return int(status_raw), {}, resp_body

    async def raw_request(
        self,
        method: str,
        url_path: str,
        *,
        data: bytes | str | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, str, bytes]:
        """Выполнить HTTP-запрос и вернуть ``(status_code, text, content_bytes)``."""
        if not self._connected:
            await self.connect()

        eff_timeout = timeout if timeout is not None else self.timeout
        req_headers = self._default_headers()
        if headers:
            req_headers.update(headers)

        full_url = self._resolve_url(url_path)
        body_bytes = (
            data.encode("utf-8")
            if isinstance(data, str)
            else (bytes(data) if data is not None else None)
        )

        if self._http_handler is not None:
            status_code, _hdrs, resp_body = await self._invoke_http_handler(
                method,
                url_path,
                data=body_bytes,
                params=params,
                headers=req_headers,
            )
            if isinstance(resp_body, bytes):
                return status_code, resp_body.decode("utf-8", errors="replace"), resp_body
            if isinstance(resp_body, str):
                return status_code, resp_body, resp_body.encode("utf-8")
            serialized = json.dumps(resp_body, ensure_ascii=False)
            return status_code, serialized, serialized.encode("utf-8")

        resp = await self._send_session_request(
            self.session,
            method.upper(),
            full_url,
            timeout=eff_timeout,
            params=params,
            data=body_bytes,
            headers=req_headers,
            use_method_attr=False,
        )
        raw_content = resp.content or b""
        text_content = resp.text or raw_content.decode("utf-8", errors="replace")
        return int(resp.status_code), text_content, raw_content

    async def stream_sse(
        self,
        url_path: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[dict[str, str]]:
        """Открыть поток Server-Sent Events (``text/event-stream``) и выдавать события."""
        if not self._connected:
            await self.connect()

        eff_timeout = timeout if timeout is not None else self.timeout
        req_headers = self._default_headers()
        req_headers.pop("Content-Type", None)
        req_headers["Accept"] = SSE_MIME
        req_headers["Cache-Control"] = "no-cache"
        if headers:
            req_headers.update(headers)

        full_url = self._resolve_url(url_path)
        parser = _SseEventParser()

        if self._http_handler is not None:
            status_code, resp_hdrs, resp_body = await self._invoke_http_handler(
                "GET",
                url_path,
                data=None,
                params=params,
                headers=req_headers,
            )
            if status_code in (401, 403):
                raise AuthenticationError(f"RESTCONF SSE authentication failed (HTTP {status_code})")
            if not (200 <= status_code < 300):
                raise _SseUnsupportedError(f"HTTP {status_code}", status=status_code)
            ctype = resp_hdrs.get("content-type", SSE_MIME).lower()
            if SSE_MIME not in ctype:
                raise _SseUnsupportedError(f"Unexpected Content-Type {ctype!r}")
            text_body = (
                resp_body.decode("utf-8", errors="replace")
                if isinstance(resp_body, bytes | bytearray)
                else str(resp_body)
            )
            for ev in parser.feed(text_body):
                yield ev
            for ev in parser.finish():
                yield ev
            return

        timeout_errors = builtins_timeout_errors(self._get_niquests())
        try:
            resp = await self.session.get(
                full_url,
                params=dict(params) if params else None,
                headers=req_headers,
                timeout=eff_timeout,
                stream=True,
            )
        except timeout_errors as exc:
            raise UniconnTimeoutError(
                f"RESTCONF SSE GET {full_url} timed out after {eff_timeout}s"
            ) from exc
        except Exception as exc:
            raise UniconnConnectionError(f"RESTCONF SSE GET {full_url} failed: {exc}") from exc

        try:
            status_code = int(resp.status_code)
            if status_code in (401, 403):
                raise AuthenticationError(
                    f"RESTCONF SSE authentication failed (HTTP {status_code})"
                )
            if status_code in (404, 405, 406, 501) or status_code >= 400:
                raise _SseUnsupportedError(f"HTTP {status_code}", status=status_code)

            content_type = str(getattr(resp, "headers", {}).get("content-type", "")).lower()
            if SSE_MIME not in content_type:
                raise _SseUnsupportedError(f"Unexpected Content-Type {content_type!r}")

            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            content_iter = resp.iter_content(chunk_size=1024)
            if asyncio.iscoroutine(content_iter):
                content_iter = await content_iter
            async for chunk in content_iter:
                if not chunk:
                    continue
                text_part = (
                    decoder.decode(bytes(chunk), final=False)
                    if isinstance(chunk, bytes | bytearray)
                    else str(chunk)
                )
                for ready in parser.feed(text_part):
                    yield ready

            tail = decoder.decode(b"", final=True)
            for ready in parser.feed(tail):
                yield ready
            for final_ev in parser.finish():
                yield final_ev
        except timeout_errors as exc:
            raise UniconnTimeoutError(
                f"RESTCONF SSE stream timed out after {eff_timeout}s"
            ) from exc
        finally:
            close_fn = getattr(resp, "close", None)
            if callable(close_fn):
                res_close = close_fn()
                if asyncio.iscoroutine(res_close):
                    await res_close


class RestconfTransport(BaseTransport):
    """Транспорт RESTCONF (RFC 8040 / RFC 8072) с поддержкой JSON/XML, проверкой операций и SSE-телеметрией."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать транспорт RESTCONF."""
        super().__init__(config)
        opts = config.options
        scheme = str(opts.get("scheme", "https")).lower()
        host = config.host or "127.0.0.1"
        port = config.port or (80 if scheme == "http" else 443)
        base_url = f"{scheme}://{host}:{port}"
        root_raw = str(opts.get("root", "/restconf")).strip()
        is_auto_root = root_raw.lower() in ("auto", "/auto")
        root = "/restconf" if is_auto_root else root_raw
        fmt_raw = str(opts.get("format", "json")).lower()
        fmt: Literal["json", "xml"] = "xml" if fmt_raw == "xml" else "json"
        auth_type = str(opts.get("auth", "basic")).lower()
        from ...core._shell_quoting import parse_bool, parse_verify_ssl

        if "verify_ssl" in opts:
            verify_ssl: bool | str = parse_verify_ssl(opts["verify_ssl"], default=True)
        elif "verify_tls" in opts:
            verify_ssl = parse_bool(opts["verify_tls"], default=True)
        elif "insecure" in opts:
            verify_ssl = not parse_bool(opts["insecure"], default=False)
        else:
            verify_ssl = True
        discover_root = parse_bool(opts.get("discover_root"), default=False) or is_auto_root
        password_str = config.password.get_secret_value() if config.password else None
        token_str = str(opts["token"]) if "token" in opts else None

        self._client = RestconfClient(
            base_url,
            root=root,
            fmt=fmt,
            auth_type=auth_type,
            username=config.username,
            password=password_str,
            token=token_str,
            verify_ssl=verify_ssl,
            timeout=config.timeout,
            discover_root=discover_root,
            http_handler=opts.get("_http_handler"),
        )
        self._supported_operations: set[str] | None = None

    @property
    def name(self) -> str:
        """Имя транспорта."""
        return "restconf"

    @property
    def client(self) -> RestconfClient:
        """Низкоуровневый клиент ``RestconfClient``."""
        return self._client

    def _data_path(self, path: str = "") -> str:
        clean = path.strip().lstrip("/")
        root = self._client.root.rstrip("/")
        if clean.startswith(root.lstrip("/") + "/"):
            return "/" + clean
        if not clean:
            return f"{root}/data"
        return f"{root}/data/{clean}"

    def _operations_path(self, operation: str = "") -> str:
        clean = operation.strip().lstrip("/")
        root = self._client.root.rstrip("/")
        if clean.startswith(root.lstrip("/") + "/"):
            return "/" + clean
        if not clean:
            return f"{root}/operations"
        return f"{root}/operations/{clean}"

    def _encode_payload(self, payload: Mapping[str, Any] | str | bytes | None) -> bytes | None:
        if payload is None:
            return None
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        if self._client.fmt == "xml":
            if len(payload) == 1:
                only_k = next(iter(payload.keys()))
                inner_v = payload[only_k]
                tag = only_k.split(":")[-1]
                root = ET.Element(tag)
                from .base import _dict_to_xml_elements

                _dict_to_xml_elements(root, inner_v)
                return ET.tostring(root, encoding="utf-8")
            xml_str = data_to_xml(payload, root_tag="data", default_ns=None)
            return xml_str.encode("utf-8")
        return json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")

    def _parse_response(
        self,
        status: int,
        text: str,
        raw: bytes,
        *,
        operation: str,
        datastore: str | None = None,
        duration: float = 0.0,
    ) -> NetResult:
        if status in (401, 403):
            raise AuthenticationError(
                f"RESTCONF authentication failed (HTTP {status}): {text}",
                host=self.config.host,
            )

        ok = 200 <= status < 300
        parsed_data: Any = None
        errors: list[dict[str, Any]] = []
        stripped = text.strip()

        if stripped:
            if stripped.startswith("<"):
                root = safe_parse_xml(stripped)
                parsed_data = xml_to_data(root)
            else:
                try:
                    parsed_data = json.loads(stripped)
                except ValueError:
                    parsed_data = stripped

        if not ok:
            if isinstance(parsed_data, Mapping):
                err_container = (
                    parsed_data.get("ietf-restconf:errors")
                    or parsed_data.get("errors")
                    or parsed_data
                )
                if isinstance(err_container, Mapping):
                    err_list = err_container.get("error")
                    if isinstance(err_list, list):
                        errors.extend(
                            dict(e) if isinstance(e, Mapping) else {"error-message": str(e)}
                            for e in err_list
                        )
                    elif isinstance(err_list, Mapping):
                        errors.append(dict(err_list))
            if not errors:
                errors.append(
                    {
                        "error-type": "protocol",
                        "error-tag": f"http-{status}",
                        "error-message": stripped or f"HTTP {status}",
                    }
                )

        return NetResult(
            ok=ok,
            data=parsed_data,
            text=stripped,
            raw=raw,
            operation=operation,
            datastore=datastore or "running",
            protocol="restconf",
            duration=duration,
            errors=errors,
            host=self.config.host,
        )

    async def connect(self) -> None:
        """Установить сессию RESTCONF."""
        await self._client.connect()
        self._supported_operations = None
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть сессию RESTCONF."""
        self._supported_operations = None
        await self._client.close()
        self._connected = False

    async def _discover_operations(
        self,
        *,
        timeout: float | None = None,
        refresh: bool = False,
    ) -> set[str]:
        """Запросить и закэшировать поддерживаемые RPC в ``/restconf/operations``."""
        if self._supported_operations is not None and not refresh:
            return self._supported_operations

        ops: set[str] = set()
        status, text, raw = await self._client.raw_request(
            "GET",
            self._operations_path(""),
            timeout=timeout,
        )
        res = self._parse_response(status, text, raw, operation="discover-operations")
        if res.ok and isinstance(res.data, Mapping):
            container = (
                res.data.get("ietf-restconf:operations")
                or res.data.get("operations")
                or res.data
            )
            if isinstance(container, Mapping):
                for raw_key in container:
                    k = str(raw_key).strip().lower()
                    if not k or k in ("ietf-restconf:operations", "operations"):
                        continue
                    ops.add(k)
                    if ":" in k:
                        ops.add(k.split(":", 1)[1])

        self._supported_operations = ops
        return ops

    async def _supports_operation(self, op_name: str, *, timeout: float | None = None) -> bool:
        ops = await self._discover_operations(timeout=timeout)
        norm = op_name.strip().lower()
        return f"ietf-netconf:{norm}" in ops or norm in ops

    async def _exec_netconf_operation(
        self,
        op_name: str,
        *,
        payload: Mapping[str, Any] | None = None,
        datastore: str = "running",
        result_operation: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить операцию ``ietf-netconf:*`` с проверкой capability сервера."""
        if not await self._supports_operation(op_name, timeout=timeout):
            raise CapabilityNotSupportedError(
                f"RESTCONF server {self.config.host or 'endpoint'} does not support "
                f"operation 'ietf-netconf:{op_name}'",
                command=f"restconf.{op_name}",
                host=self.config.host,
            )

        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "POST",
            self._operations_path(f"ietf-netconf:{op_name}"),
            data=self._encode_payload(payload),
            timeout=timeout,
        )
        if status in (404, 405, 501):
            raise CapabilityNotSupportedError(
                f"RESTCONF server rejected operation 'ietf-netconf:{op_name}' (HTTP {status})",
                command=f"restconf.{op_name}",
                host=self.config.host,
            )
        return self._parse_response(
            status,
            text,
            raw,
            operation=result_operation or op_name,
            datastore=datastore,
            duration=time.perf_counter() - start_ts,
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
        """Выполнить RESTCONF ``GET /restconf/data/{path}``."""
        _ = filter_type
        params: dict[str, Any] = {}
        if depth is not None:
            params["depth"] = depth
        if datastore == "candidate" and await self._supports_operation("commit", timeout=timeout):
            params["datastore"] = "candidate"
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "GET",
            self._data_path(path),
            params=params or None,
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation="get",
            datastore=datastore,
            duration=time.perf_counter() - start_ts,
        )

    async def net_get_config(
        self,
        datastore: str = "running",
        path: str = "",
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        timeout: float | None = None,
    ) -> NetResult:
        """Получить только конфигурационные узлы (``content=config``) через RESTCONF ``GET``."""
        _ = filter_type
        params: dict[str, Any] = {"content": "config"}
        if datastore == "candidate" and await self._supports_operation("commit", timeout=timeout):
            params["datastore"] = "candidate"
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "GET",
            self._data_path(path),
            params=params,
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation="get-config",
            datastore=datastore,
            duration=time.perf_counter() - start_ts,
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
        """Применить изменения конфигурации через HTTP ``PATCH`` / ``PUT`` / ``POST`` / ``DELETE``."""
        _ = (default_operation, test_option, error_option)
        params: dict[str, Any] = {}
        if datastore == "candidate" and await self._supports_operation("commit", timeout=timeout):
            params["datastore"] = "candidate"

        if isinstance(config, Sequence) and not isinstance(config, str | bytes):
            return await self.yang_patch(
                path,
                config,
                datastore=datastore,
                params=params or None,
                timeout=timeout,
            )
        op = operation.lower()
        method_map = {
            "merge": "PATCH",
            "patch": "PATCH",
            "replace": "PUT",
            "create": "POST",
            "delete": "DELETE",
            "remove": "DELETE",
        }
        http_method = method_map.get(op, "PATCH")
        body = None if http_method == "DELETE" else self._encode_payload(config)
        is_yang_patch = (
            isinstance(config, Mapping)
            and ("ietf-yang-patch:yang-patch" in config or "yang-patch" in config)
        )
        headers = self._client._default_headers(is_patch=is_yang_patch)
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            http_method,
            self._data_path(path),
            data=body,
            params=params or None,
            headers=headers,
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation=f"edit:{op}",
            datastore=datastore or "running",
            duration=time.perf_counter() - start_ts,
        )

    async def yang_patch(
        self,
        path: str,
        edits: Sequence[Mapping[str, Any]],
        *,
        patch_id: str = "uniconn-patch-1",
        comment: str | None = None,
        datastore: str | None = None,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить атомарный RFC 8072 YANG-Patch запрос (``application/yang-patch+json``)."""
        patch_body: dict[str, Any] = {
            "ietf-yang-patch:yang-patch": {
                "patch-id": patch_id,
                **({"comment": comment} if comment else {}),
                "edit": list(edits),
            }
        }
        eff_params = dict(params or {})
        eff_datastore = datastore or str(eff_params.get("datastore") or "running")
        if (
            datastore == "candidate"
            and "datastore" not in eff_params
            and await self._supports_operation("commit", timeout=timeout)
        ):
            eff_params["datastore"] = "candidate"

        headers = self._client._default_headers(is_patch=True)
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "PATCH",
            self._data_path(path),
            data=json.dumps(patch_body, ensure_ascii=False).encode("utf-8"),
            params=eff_params or None,
            headers=headers,
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation="yang-patch",
            datastore=eff_datastore,
            duration=time.perf_counter() - start_ts,
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
        """Выполнить ``POST /restconf/operations/ietf-netconf:commit`` или бросить ``CapabilityNotSupportedError``."""
        inp: dict[str, Any] = {}
        if confirmed:
            inp["confirmed"] = [None]
            inp["confirm-timeout"] = int(confirm_timeout)
        if persist:
            inp["persist"] = persist
        if persist_id:
            inp["persist-id"] = persist_id
        payload = {"ietf-netconf:input": inp} if inp else None
        return await self._exec_netconf_operation(
            "commit",
            payload=payload,
            datastore="running",
            result_operation="commit",
            timeout=timeout,
        )

    async def net_commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтвердить confirmed-commit через ``ietf-netconf:commit`` или бросить ``CapabilityNotSupportedError``."""
        payload = {"ietf-netconf:input": {"persist-id": persist_id}} if persist_id else None
        return await self._exec_netconf_operation(
            "commit",
            payload=payload,
            datastore="running",
            result_operation="commit-confirm",
            timeout=timeout,
        )

    async def net_discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить ``POST /restconf/operations/ietf-netconf:discard-changes``."""
        return await self._exec_netconf_operation(
            "discard-changes",
            datastore="candidate",
            result_operation="discard-changes",
            timeout=timeout,
        )

    async def net_validate(
        self,
        *,
        source: str = "candidate",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить ``POST /restconf/operations/ietf-netconf:validate``."""
        return await self._exec_netconf_operation(
            "validate",
            payload={"ietf-netconf:input": {"source": {source: [None]}}},
            datastore=source,
            result_operation="validate",
            timeout=timeout,
        )

    async def net_lock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить ``POST /restconf/operations/ietf-netconf:lock``."""
        return await self._exec_netconf_operation(
            "lock",
            payload={"ietf-netconf:input": {"target": {datastore: [None]}}},
            datastore=datastore,
            result_operation="lock",
            timeout=timeout,
        )

    async def net_unlock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить ``POST /restconf/operations/ietf-netconf:unlock``."""
        return await self._exec_netconf_operation(
            "unlock",
            payload={"ietf-netconf:input": {"target": {datastore: [None]}}},
            datastore=datastore,
            result_operation="unlock",
            timeout=timeout,
        )

    async def net_capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Получить список поддерживаемых YANG-моделей из ``/restconf/data/ietf-yang-library:modules-state``."""
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "GET",
            self._data_path("ietf-yang-library:modules-state"),
            timeout=timeout,
        )
        if status == 404:
            status, text, raw = await self._client.raw_request(
                "GET",
                self._client.root,
                timeout=timeout,
            )
        return self._parse_response(
            status,
            text,
            raw,
            operation="capabilities",
            duration=time.perf_counter() - start_ts,
        )

    async def net_rpc(
        self,
        payload: Mapping[str, Any] | str,
        *,
        path: str = "",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить операцию YANG RPC через ``POST /restconf/operations/{path}``."""
        op_path = path
        body_payload: Mapping[str, Any] | str | None = payload
        if not op_path and isinstance(payload, str):
            op_path = payload
            body_payload = None
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "POST",
            self._operations_path(op_path),
            data=self._encode_payload(body_payload),
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation=f"rpc:{op_path}",
            duration=time.perf_counter() - start_ts,
        )

    async def _discover_sse_stream_url(
        self,
        *,
        timeout: float | None = None,
    ) -> str:
        explicit_url = self.config.options.get("stream_url")
        if explicit_url:
            return str(explicit_url)

        root = self._client.root.rstrip("/")
        streams_res = await self.net_get(
            "ietf-restconf-monitoring:restconf-state/streams",
            timeout=timeout,
        )
        if streams_res.ok and isinstance(streams_res.data, Mapping):
            container = (
                streams_res.data.get("ietf-restconf-monitoring:streams")
                or streams_res.data.get("streams")
                or streams_res.data
            )
            if isinstance(container, Mapping):
                stream_list = container.get("stream")
                if isinstance(stream_list, Mapping):
                    stream_list = [stream_list]
                if isinstance(stream_list, list):
                    for item in stream_list:
                        if not isinstance(item, Mapping):
                            continue
                        access_list = item.get("access")
                        if isinstance(access_list, Mapping):
                            access_list = [access_list]
                        if isinstance(access_list, list):
                            for acc in access_list:
                                if isinstance(acc, Mapping) and acc.get("location"):
                                    return str(acc["location"])
        return f"{root}/streams/NETCONF"

    def _parse_sse_notification(
        self,
        sse_event: Mapping[str, str],
        *,
        default_path: str,
        stream_url: str,
    ) -> TelemetrySample:
        raw_data = sse_event.get("data", "").strip()
        parsed: Any = {}
        if raw_data:
            if raw_data.startswith("<"):
                parsed = xml_to_data(safe_parse_xml(raw_data))
            else:
                try:
                    parsed = json.loads(raw_data)
                except ValueError:
                    parsed = {"raw": raw_data}

        ev_path = default_path or "/"
        vals: dict[str, Any] = parsed if isinstance(parsed, dict) else {"value": parsed}
        if isinstance(parsed, Mapping):
            notif = parsed.get("ietf-restconf:notification") or parsed.get("notification")
            if isinstance(notif, Mapping):
                if notif.get("path"):
                    ev_path = str(notif["path"])
                elif notif.get("event"):
                    ev_path = default_path or "/"
                vals = dict(notif)

        meta: dict[str, Any] = {
            "transport_mode": "sse",
            "stream_url": stream_url,
        }
        if sse_event.get("event"):
            meta["event"] = sse_event["event"]
        if sse_event.get("id"):
            meta["sse_id"] = sse_event["id"]

        return TelemetrySample(
            path=ev_path,
            values=vals,
            timestamp=int(time.time() * 1e9),
            protocol="restconf",
            host=self.config.host,
            metadata=meta,
        )

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
        """Подписаться на телеметрию: сначала RFC 8040/8639 SSE, затем fallback на HTTP polling."""
        _ = (suppress_redundant, heartbeat_interval, encoding)
        target_paths = list(paths) or [""]
        forced_mode = str(self.config.options.get("subscribe_mode", "auto")).lower()
        fallback_reason: str | None = None

        if forced_mode != "polling":
            default_stream_url = f"{self._client.root.rstrip('/')}/streams/NETCONF"
            stream_url = default_stream_url
            sse_params: dict[str, Any] = {"mode": mode}
            non_empty_paths = [p for p in target_paths if p and p != "/"]
            if non_empty_paths:
                sse_params["filter"] = ",".join(non_empty_paths)

            yielded_sse = False
            try:
                stream_url = await self._discover_sse_stream_url(timeout=timeout)
                async for sse_ev in self._client.stream_sse(
                    stream_url,
                    params=sse_params,
                    timeout=timeout,
                ):
                    yielded_sse = True
                    sample = self._parse_sse_notification(
                        sse_ev,
                        default_path=target_paths[0] or "/",
                        stream_url=stream_url,
                    )
                    yield sample
                    if once:
                        return
                if yielded_sse:
                    return
                fallback_reason = "SSE stream ended without events"
            except _SseUnsupportedError as exc:
                fallback_reason = exc.reason
            except UniconnConnectionError as exc:
                if yielded_sse:
                    raise
                fallback_reason = str(exc)

            _logger.warning(
                "RESTCONF SSE subscription unavailable at %s (%s); falling back to periodic GET polling",
                stream_url,
                fallback_reason,
            )
        else:
            fallback_reason = "Explicitly configured subscribe_mode=polling"

        poll_meta: dict[str, Any] = {
            "transport_mode": "polling",
            "fallback_reason": fallback_reason or "sse_unavailable",
        }
        while self._connected:
            for p in target_paths:
                res = await self.net_get(p, timeout=timeout)
                if res.ok:
                    vals = res.data if isinstance(res.data, dict) else {"value": res.data}
                    yield TelemetrySample(
                        path=p or "/",
                        values=vals,
                        timestamp=int(time.time() * 1e9),
                        protocol="restconf",
                        host=self.config.host,
                        metadata=dict(poll_meta),
                    )
                else:
                    _logger.debug("RESTCONF polling GET %s failed: %s", p or "/", res.text)
            if once:
                break
            await asyncio.sleep(max(0.01, sample_interval))

    async def gather_network_native_facts(
        self,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Собрать сетевые и системные факты через RESTCONF."""
        res = await self.net_get("", timeout=timeout)
        extracted = extract_yang_interfaces_and_system(res.data)
        return {
            "protocol": "restconf",
            "root": self._client.root,
            "format": self._client.fmt,
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
        """Выполнить RESTCONF-команду вида ``GET /ietf-interfaces:interfaces`` или ``PATCH /path {...}``."""
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
        method = tokens[0].upper() if tokens else "GET"
        path = tokens[1] if len(tokens) > 1 else ""
        payload_raw = tokens[2] if len(tokens) > 2 else None

        if method == "GET":
            net_res = await self.net_get(path, timeout=timeout)
        elif method in ("PATCH", "MERGE"):
            net_res = await self.net_edit(payload_raw or "{}", path=path, operation="merge", timeout=timeout)
        elif method in ("PUT", "REPLACE"):
            net_res = await self.net_edit(payload_raw or "{}", path=path, operation="replace", timeout=timeout)
        elif method in ("POST", "CREATE"):
            net_res = await self.net_edit(payload_raw or "{}", path=path, operation="create", timeout=timeout)
        elif method in ("DELETE", "REMOVE"):
            net_res = await self.net_edit("", path=path, operation="delete", timeout=timeout)
        elif method == "RPC":
            net_res = await self.net_rpc(payload_raw or "{}", path=path, timeout=timeout)
        else:
            raise ExecutionError(
                f"Unsupported RESTCONF command: {command!r}",
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
        """Стримить сэмплы состояния RESTCONF в виде NDJSON строк."""
        path = command.strip()
        if path.upper().startswith("GET "):
            path = path[4:].strip()
        once = bool(kwargs.get("once", False))
        interval = float(kwargs.get("sample_interval", 1.0))
        async for sample in self.net_subscribe([path], sample_interval=interval, once=once, timeout=timeout):
            yield sample.to_json()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность RESTCONF эндпоинта."""
        try:
            status, _, _ = await self._client.raw_request(
                "GET",
                self._client.root,
                timeout=timeout or 5.0,
            )
            return status < 500
        except Exception:
            return False


__all__ = [
    "YANG_JSON_MIME",
    "YANG_PATCH_JSON_MIME",
    "YANG_PATCH_XML_MIME",
    "YANG_XML_MIME",
    "RestconfClient",
    "RestconfTransport",
]
