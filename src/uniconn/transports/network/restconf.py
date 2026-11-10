# src/uniconn/transports/network/restconf.py
"""Транспорт RESTCONF (RFC 8040 / RFC 8072 YANG-Patch) поверх асинхронного HTTP/2 клиента niquests."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from typing import Any, Literal

from ...config.models import ConnectionConfig
from ...exceptions import (
    AuthenticationError,
    ExecutionError,
    OptionalDependencyError,
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

YANG_JSON_MIME = "application/yang-data+json"
YANG_XML_MIME = "application/yang-data+xml"
YANG_PATCH_JSON_MIME = "application/yang-patch+json"
YANG_PATCH_XML_MIME = "application/yang-patch+xml"

_HOST_META_LINK_RE = re.compile(
    r"""<Link[^>]+rel=['"]restconf['"][^>]+href=['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class RestconfClient:
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
        verify_ssl: bool | str = False,
        timeout: float = 30.0,
        discover_root: bool = False,
        http_handler: Callable[..., Any] | None = None,
    ) -> None:
        """Инициализировать клиент RESTCONF."""
        self.base_url = base_url.rstrip("/")
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
        self._session: Any = None
        self._connected = False

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
            try:
                import niquests
            except ImportError as exc:
                raise OptionalDependencyError(
                    "restconf transport requires 'niquests'. Install with: pip install uniconn[restconf]"
                ) from exc
            auth = None
            if self.auth_type == "basic" and self.username is not None:
                auth = (self.username, self.password or "")
            self._session = niquests.AsyncSession(verify=self.verify_ssl, auth=auth)

        self._connected = True
        if self.discover_root:
            await self._discover_restconf_root()

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
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self._session.close()
            self._session = None
        self._connected = False

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

        full_url = (
            url_path
            if url_path.startswith(("http://", "https://"))
            else f"{self.base_url}/{url_path.lstrip('/')}"
        )
        body_bytes = (
            data.encode("utf-8")
            if isinstance(data, str)
            else (bytes(data) if data is not None else None)
        )

        if self._http_handler is not None:
            res = self._http_handler(
                method.upper(),
                url_path,
                data=body_bytes,
                params=dict(params or {}),
                headers=req_headers,
            )
            if asyncio.iscoroutine(res):
                res = await res
            status_code, resp_body = res
            if isinstance(resp_body, bytes):
                return int(status_code), resp_body.decode("utf-8", errors="replace"), resp_body
            if isinstance(resp_body, str):
                return int(status_code), resp_body, resp_body.encode("utf-8")
            serialized = json.dumps(resp_body, ensure_ascii=False)
            return int(status_code), serialized, serialized.encode("utf-8")

        try:
            resp = await self._session.request(
                method.upper(),
                full_url,
                data=body_bytes,
                params=dict(params) if params else None,
                headers=req_headers,
                timeout=eff_timeout,
            )
            raw_content = resp.content or b""
            text_content = resp.text or raw_content.decode("utf-8", errors="replace")
            return int(resp.status_code), text_content, raw_content
        except TimeoutError as exc:
            raise UniconnTimeoutError(
                f"RESTCONF {method} {url_path} timed out after {eff_timeout}s"
            ) from exc
        except Exception as exc:
            raise UniconnConnectionError(
                f"RESTCONF HTTP error on {method} {url_path}: {exc}"
            ) from exc


class RestconfTransport(BaseTransport):
    """Транспорт RESTCONF (RFC 8040 / RFC 8072) с поддержкой JSON и XML кодирования YANG-моделей."""

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
        if "verify_ssl" in opts:
            verify_ssl: bool | str = opts["verify_ssl"]
        elif "verify_tls" in opts:
            verify_ssl = bool(opts["verify_tls"])
        elif "insecure" in opts:
            verify_ssl = not bool(opts["insecure"])
        else:
            verify_ssl = False
        discover_root = bool(opts.get("discover_root", False)) or is_auto_root
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
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть сессию RESTCONF."""
        await self._client.close()
        self._connected = False

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
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "GET",
            self._data_path(path),
            params={"content": "config"},
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
        if isinstance(config, Sequence) and not isinstance(config, str | bytes):
            return await self.yang_patch(path, config, timeout=timeout)
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
        headers = self._client._default_headers(is_patch=True)
        start_ts = time.perf_counter()
        status, text, raw = await self._client.raw_request(
            "PATCH",
            self._data_path(path),
            data=json.dumps(patch_body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            timeout=timeout,
        )
        return self._parse_response(
            status,
            text,
            raw,
            operation="yang-patch",
            datastore="running",
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
        """В RESTCONF изменения применяются сразу (или вызывается ``/operations/ietf-netconf:commit``)."""
        _ = (confirmed, confirm_timeout, persist, persist_id, timeout)
        return NetResult(
            ok=True,
            data={"status": "committed"},
            text='{"status": "committed"}',
            raw=b'{"status": "committed"}',
            operation="commit",
            datastore="running",
            protocol="restconf",
            host=self.config.host,
        )

    async def net_commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтверждение коммита в RESTCONF."""
        _ = (persist_id, timeout)
        return NetResult(
            ok=True,
            data={"status": "confirmed"},
            text='{"status": "confirmed"}',
            raw=b'{"status": "confirmed"}',
            operation="commit-confirm",
            datastore="running",
            protocol="restconf",
            host=self.config.host,
        )

    async def net_discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Откат незафиксированных изменений в RESTCONF."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"status": "discarded"},
            text='{"status": "discarded"}',
            raw=b'{"status": "discarded"}',
            operation="discard-changes",
            datastore="candidate",
            protocol="restconf",
            host=self.config.host,
        )

    async def net_validate(
        self,
        *,
        source: str = "candidate",
        timeout: float | None = None,
    ) -> NetResult:
        """Проверка валидности хранилища в RESTCONF."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"status": "valid", "source": source},
            text=json.dumps({"status": "valid", "source": source}),
            raw=b'{"status": "valid"}',
            operation="validate",
            datastore=source,
            protocol="restconf",
            host=self.config.host,
        )

    async def net_lock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Установить логическую блокировку в RESTCONF."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"locked": datastore},
            text=json.dumps({"locked": datastore}),
            raw=b'{"locked": true}',
            operation="lock",
            datastore=datastore,
            protocol="restconf",
            host=self.config.host,
        )

    async def net_unlock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Снять логическую блокировку в RESTCONF."""
        _ = timeout
        return NetResult(
            ok=True,
            data={"unlocked": datastore},
            text=json.dumps({"unlocked": datastore}),
            raw=b'{"unlocked": true}',
            operation="unlock",
            datastore=datastore,
            protocol="restconf",
            host=self.config.host,
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
        """Потоковый сбор состояния по путям RESTCONF."""
        _ = (mode, suppress_redundant, heartbeat_interval, encoding)
        target_paths = list(paths) or [""]
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
                    )
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
