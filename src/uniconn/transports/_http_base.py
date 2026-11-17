# src/uniconn/transports/_http_base.py
"""Общий асинхронный HTTP-клиент и утилиты ``niquests`` для REST-транспортов (Redfish, PVE, RESTCONF)."""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import json
import logging
import sys
from collections.abc import Mapping
from typing import Any

from ..exceptions import ConnectionError as UniconnConnectionError
from ..exceptions import OptionalDependencyError
from ..exceptions import TimeoutError as UniconnTimeoutError

try:
    import niquests
except ImportError:
    niquests = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def resolve_niquests_module(*shim_module_names: str, fallback: Any = None) -> Any:
    """Найти модуль ``niquests`` с учётом monkeypatch в указанных модулях."""
    for mod_name in shim_module_names:
        mod = sys.modules.get(mod_name)
        if mod is not None and "niquests" in mod.__dict__:
            return mod.__dict__["niquests"]
    return fallback if fallback is not None else niquests


def builtins_timeout_errors(niq_module: Any = None) -> tuple[type[BaseException], ...]:
    """Собрать кортеж классов исключений таймаута (включая ``builtins.TimeoutError`` и ``niquests``)."""
    errs: list[type[BaseException]] = [builtins.TimeoutError]
    niq = niq_module if niq_module is not None else niquests
    if niq is not None:
        niq_timeout = getattr(getattr(niq, "exceptions", None), "Timeout", None)
        if isinstance(niq_timeout, type) and issubclass(niq_timeout, BaseException):
            errs.append(niq_timeout)
    return tuple(errs)


async def resolve_lazy_response(session: Any, resp: Any) -> Any:
    """Разрешить отложенный (lazy) ответ ``niquests`` при ``multiplexed=True``."""
    if getattr(resp, "lazy", False) is True and hasattr(session, "gather"):
        await session.gather(resp)
    return resp


def extract_response_headers(resp: Any) -> dict[str, str]:
    """Безопасно извлечь заголовки ответа HTTP в виде ``dict[str, str]``."""
    raw_headers = getattr(resp, "headers", None)
    if not raw_headers:
        return {}
    if isinstance(raw_headers, Mapping):
        return {str(k): str(v) for k, v in raw_headers.items()}
    try:
        return {str(k): str(v) for k, v in dict(raw_headers).items()}
    except (TypeError, ValueError):
        return {}


def parse_json_dict(resp: Any) -> dict[str, Any]:
    """Безопасно распарсить JSON-тело ответа в словарь (или вернуть ``{'raw': ...}``)."""
    raw_text = getattr(resp, "text", "")
    if raw_text:
        try:
            parsed = resp.json()
            return parsed if isinstance(parsed, dict) else {"data": parsed}
        except (json.JSONDecodeError, ValueError, TypeError):
            return {"raw": str(raw_text)}
    try:
        parsed = resp.json()
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
        pass
    return {}


class BaseAsyncHttpClient:
    """Базовый класс управления сессией ``niquests.AsyncSession`` и безопасного выполнения HTTP-запросов."""

    def __init__(
        self,
        *,
        base_url: str,
        verify: bool | str = True,
        default_timeout: float = 30.0,
        multiplexed: bool = False,
        error_prefix: str = "HTTP",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.default_timeout = default_timeout
        self.multiplexed = multiplexed
        self._error_prefix = error_prefix
        self.session: Any = None

    def _get_niquests(self) -> Any:
        """Вернуть актуальный модуль ``niquests`` (может переопределяться наследниками для monkeypatch)."""
        return niquests

    def _require_niquests(self, install_extra: str = "bmc", *, use_optional_dep: bool = False) -> Any:
        niq = self._get_niquests()
        if niq is None:
            msg = f"niquests not installed. Run: pip install uniconn[{install_extra}]"
            if use_optional_dep:
                raise OptionalDependencyError(msg)
            raise ImportError(msg)
        return niq

    def _build_session(
        self,
        *,
        install_extra: str = "bmc",
        use_optional_dep: bool = False,
        pass_base_url: bool = True,
        headers: Mapping[str, str] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> Any:
        """Создать и сконфигурировать ``niquests.AsyncSession``."""
        niq = self._require_niquests(install_extra=install_extra, use_optional_dep=use_optional_dep)
        session_kwargs: dict[str, Any] = {}
        if pass_base_url:
            session_kwargs["base_url"] = self.base_url
            session_kwargs["multiplexed"] = self.multiplexed
        else:
            session_kwargs["verify"] = self.verify
        if auth is not None:
            session_kwargs["auth"] = auth

        session = niq.AsyncSession(**session_kwargs)
        session.verify = self.verify
        if headers:
            session.headers.update(dict(headers))
        return session

    async def close(self) -> None:
        """Корректно закрыть активную HTTP-сессию ``niquests.AsyncSession``."""
        session = self.session
        self.session = None
        if session is None:
            return
        close_fn = getattr(session, "close", None)
        if not callable(close_fn):
            return
        try:
            res = close_fn()
            if asyncio.iscoroutine(res):
                await res
        except (OSError, RuntimeError) as exc:
            logger.debug("%s session close failed: %s", self._error_prefix, exc)

    async def _send_session_request(
        self,
        session: Any,
        method: str,
        target: str,
        *,
        timeout: float | None = None,
        params: Mapping[str, Any] | None = None,
        json_payload: dict[str, Any] | None = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        use_method_attr: bool = True,
    ) -> Any:
        """Выполнить HTTP-вызов через ``session`` с разрешением lazy-ответов и маппингом таймаутов/сбоев."""
        eff_timeout = timeout if timeout is not None else self.default_timeout
        method_upper = method.upper()
        call_kwargs: dict[str, Any] = {"timeout": eff_timeout}
        if params:
            call_kwargs["params"] = dict(params)
        if json_payload is not None:
            call_kwargs["json"] = json_payload
        if data is not None:
            call_kwargs["data"] = data
        if headers:
            call_kwargs["headers"] = dict(headers)

        timeout_errors = builtins_timeout_errors(self._get_niquests())
        try:
            if use_method_attr and hasattr(session, method_upper.lower()):
                req_fn = getattr(session, method_upper.lower())
                resp = await req_fn(target, **call_kwargs)
            else:
                resp = await session.request(method_upper, target, **call_kwargs)
            await resolve_lazy_response(session, resp)
            return resp
        except timeout_errors as exc:
            raise UniconnTimeoutError(
                f"{self._error_prefix} {method_upper} {target} timed out after {eff_timeout}s"
            ) from exc
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            raise UniconnConnectionError(
                f"{self._error_prefix} {method_upper} {target} failed: {exc}"
            ) from exc
        except Exception as exc:
            with contextlib.suppress(ImportError):
                niq = self._get_niquests()
                niq_exc = getattr(getattr(niq, "exceptions", None), "RequestException", None)
                if niq_exc is not None and isinstance(exc, niq_exc):
                    raise UniconnConnectionError(
                        f"{self._error_prefix} {method_upper} {target} failed: {exc}"
                    ) from exc
            raise UniconnConnectionError(
                f"{self._error_prefix} {method_upper} {target} failed: {exc}"
            ) from exc


__all__ = [
    "BaseAsyncHttpClient",
    "builtins_timeout_errors",
    "extract_response_headers",
    "niquests",
    "parse_json_dict",
    "resolve_lazy_response",
    "resolve_niquests_module",
]
