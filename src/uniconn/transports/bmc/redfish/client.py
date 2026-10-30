# src/uniconn/transports/bmc/redfish/client.py
"""Асинхронный HTTP/2 клиент Redfish на базе niquests с поддержкой сессий и ETag."""

from __future__ import annotations

import builtins
import contextlib
import sys
from typing import Any
from urllib.parse import urlsplit

from ....exceptions import (
    AuthenticationError,
    ConnectionError,
    TimeoutError,
)

try:
    import niquests
except ImportError:
    niquests = None  # type: ignore[assignment]


def get_niquests_module() -> Any:
    """Получить модуль niquests с учётом возможного патчинга в bmc._redfish."""
    shim_mod = sys.modules.get("uniconn.transports.bmc._redfish")
    if shim_mod is not None and "niquests" in shim_mod.__dict__:
        return shim_mod.__dict__["niquests"]
    return niquests


def builtins_timeout_errors() -> tuple[type[BaseException], ...]:
    """Собрать кортеж классов исключений таймаута (включая builtins.TimeoutError и niquests)."""
    errs: list[type[BaseException]] = [builtins.TimeoutError]
    niq = get_niquests_module()
    if niq is not None:
        niq_timeout = getattr(getattr(niq, "exceptions", None), "Timeout", None)
        if isinstance(niq_timeout, type) and issubclass(niq_timeout, BaseException):
            errs.append(niq_timeout)
    return tuple(errs)


def normalize_redfish_path(path: str) -> str:
    """Нормализовать путь или полный URL Redfish к относительному пути ``/redfish/...``."""
    stripped = path.strip()
    if stripped.startswith(("http://", "https://")):
        parsed = urlsplit(stripped)
        rel = parsed.path or "/"
        if parsed.query:
            rel = f"{rel}?{parsed.query}"
        return rel if rel.startswith("/") else f"/{rel}"
    return stripped if stripped.startswith("/") else f"/{stripped}"


async def resolve_lazy_response(session: Any, resp: Any) -> Any:
    """Разрешить отложенный (lazy) ответ ``niquests`` при ``multiplexed=True``."""
    if getattr(resp, "lazy", False) is True and hasattr(session, "gather"):
        await session.gather(resp)
    return resp


class RedfishHttpClient:
    """Менеджер HTTP/2-сессии, аутентификации (X-Auth-Token / Basic) и ETag для Redfish."""

    def __init__(
        self,
        *,
        base_url: str,
        verify: bool | str,
        multiplexed: bool,
        auth_pref: str,
        username: str | None,
        password: str,
        default_timeout: float,
    ) -> None:
        self.base_url = base_url
        self.verify = verify
        self.multiplexed = multiplexed
        self.auth_pref = auth_pref
        self.username = username
        self.password = password
        self.default_timeout = default_timeout

        self.session: Any = None
        self.auth_mode: str = "none"
        self.session_token: str | None = None
        self.session_location: str | None = None
        self.etags: dict[str, str] = {}
        self.last_response_headers: dict[str, str] = {}

    def create_async_session(self) -> Any:
        """Создать и сконфигурировать экземпляр ``niquests.AsyncSession``."""
        niq = get_niquests_module()
        if niq is None:
            raise ImportError("niquests not installed. Run: pip install uniconn[bmc]")
        session = niq.AsyncSession(
            base_url=self.base_url,
            multiplexed=self.multiplexed,
        )
        session.verify = self.verify
        session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "OData-Version": "4.0",
            }
        )
        return session

    async def try_create_redfish_session(
        self,
        session: Any,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        """Попытаться создать сессию через POST /redfish/v1/SessionService/Sessions."""
        resp = await session.post(
            "/redfish/v1/SessionService/Sessions",
            json={"UserName": username, "Password": password},
            timeout=timeout,
        )
        await resolve_lazy_response(session, resp)
        status = int(getattr(resp, "status_code", 0) or 0)
        headers = getattr(resp, "headers", {}) or {}
        token = headers.get("X-Auth-Token") or headers.get("x-auth-token")

        if status in (200, 201, 202, 204) and token:
            session.headers["X-Auth-Token"] = str(token)
            self.session_token = str(token)
            location = headers.get("Location") or headers.get("location")
            if not location:
                with contextlib.suppress(Exception):
                    body = resp.json()
                    if isinstance(body, dict) and "@odata.id" in body:
                        location = str(body["@odata.id"])
            self.session_location = (
                normalize_redfish_path(str(location)) if location else None
            )
            return True

        # 401/403 означает, что SessionService активен, но учётные данные отвергнуты BMC.
        # Выбрасываем AuthenticationError сразу, чтобы избежать ложноположительного
        # отката на публичный анонимный эндпоинт /redfish/v1.
        if status in (401, 403):
            raise AuthenticationError(
                f"Redfish session login rejected on {self.base_url} (HTTP {status})"
            )

        if self.auth_pref == "session":
            raise ConnectionError(
                f"Redfish SessionService unavailable on {self.base_url} (HTTP {status})"
            )
        return False

    def cache_etag(self, norm_path: str, headers: Any, data: dict[str, Any]) -> None:
        """Сохранить ETag ресурса из HTTP-заголовков или поля ``@odata.etag``."""
        clean_path = norm_path.split("?", 1)[0].rstrip("/") or "/"
        etag_hdr = None
        if isinstance(headers, dict):
            etag_hdr = headers.get("ETag") or headers.get("etag")
        else:
            with contextlib.suppress(Exception):
                etag_hdr = headers.get("ETag") or headers.get("etag")
        etag_val = etag_hdr or data.get("@odata.etag")
        if etag_val:
            self.etags[clean_path] = str(etag_val)

    def get_cached_etag(self, norm_path: str) -> str | None:
        """Получить ранее сохранённый ETag для указанного пути."""
        clean_path = norm_path.split("?", 1)[0].rstrip("/") or "/"
        return self.etags.get(clean_path)

    async def request_json(
        self,
        session: Any,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        _retry_on_401: bool = True,
        _retry_on_412: bool = True,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        """Выполнить HTTP-запрос и вернуть ``(status_code, json_dict, response_headers)``."""
        eff_timeout = timeout if timeout is not None else self.default_timeout
        norm_path = normalize_redfish_path(path)
        method_upper = method.upper()

        req_headers: dict[str, str] = dict(headers) if headers else {}
        if method_upper in ("PATCH", "PUT") and "If-Match" not in req_headers:
            cached_etag = self.get_cached_etag(norm_path)
            if cached_etag:
                req_headers["If-Match"] = cached_etag

        try:
            req_fn = getattr(session, method.lower())
            call_kwargs: dict[str, Any] = {"timeout": eff_timeout}
            if payload is not None:
                call_kwargs["json"] = payload
            if req_headers:
                call_kwargs["headers"] = req_headers
            resp = await req_fn(norm_path, **call_kwargs)
            await resolve_lazy_response(session, resp)
        except builtins_timeout_errors() as exc:
            raise TimeoutError(
                f"Redfish {method_upper} {norm_path} timed out after {eff_timeout}s"
            ) from exc
        except Exception as exc:
            raise ConnectionError(
                f"Redfish {method_upper} {norm_path} failed: {exc}"
            ) from exc

        status = int(getattr(resp, "status_code", 0) or 0)
        raw_headers = getattr(resp, "headers", {}) or {}
        resp_headers: dict[str, str] = {}
        if isinstance(raw_headers, dict):
            resp_headers = {str(k): str(v) for k, v in raw_headers.items()}
        else:
            with contextlib.suppress(Exception):
                resp_headers = {str(k): str(v) for k, v in dict(raw_headers).items()}
        self.last_response_headers = resp_headers

        # Автоматическое пересоздание сессии при истечении X-Auth-Token (HTTP 401)
        if (
            status == 401
            and _retry_on_401
            and self.auth_mode == "session"
            and self.username
        ):
            with contextlib.suppress(Exception):
                session.headers.pop("X-Auth-Token", None)
                refreshed = await self.try_create_redfish_session(
                    session,
                    self.username,
                    self.password,
                    eff_timeout,
                )
                if refreshed:
                    return await self.request_json(
                        session,
                        method,
                        path,
                        payload=payload,
                        headers=headers,
                        timeout=timeout,
                        _retry_on_401=False,
                        _retry_on_412=_retry_on_412,
                    )

        # Автоматическое получение свежего ETag при HTTP 412 / 428 на PATCH/PUT
        if (
            status in (412, 428)
            and _retry_on_412
            and method_upper in ("PATCH", "PUT")
        ):
            get_st, get_data, get_hdrs = await self.request_json(
                session,
                "GET",
                norm_path,
                timeout=eff_timeout,
                _retry_on_401=False,
                _retry_on_412=False,
            )
            if 200 <= get_st < 300:
                fresh_etag = (
                    get_hdrs.get("ETag")
                    or get_hdrs.get("etag")
                    or get_data.get("@odata.etag")
                    or self.get_cached_etag(norm_path)
                )
                if fresh_etag:
                    retry_hdrs = dict(headers) if headers else {}
                    retry_hdrs["If-Match"] = str(fresh_etag)
                    return await self.request_json(
                        session,
                        method,
                        path,
                        payload=payload,
                        headers=retry_hdrs,
                        timeout=timeout,
                        _retry_on_401=False,
                        _retry_on_412=False,
                    )

        if status in (401, 403):
            raise AuthenticationError(
                f"Redfish {method_upper} {norm_path} unauthorized (HTTP {status})"
            )

        data: dict[str, Any] = {}
        raw_text = getattr(resp, "text", "")
        if raw_text:
            try:
                parsed = resp.json()
                data = parsed if isinstance(parsed, dict) else {"data": parsed}
            except Exception:
                data = {"raw": str(raw_text)}

        if 200 <= status < 300:
            self.cache_etag(norm_path, resp_headers, data)

        return status, data, resp_headers


__all__ = [
    "RedfishHttpClient",
    "builtins_timeout_errors",
    "get_niquests_module",
    "niquests",
    "normalize_redfish_path",
    "resolve_lazy_response",
]
