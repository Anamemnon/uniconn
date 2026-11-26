# src/uniconn/transports/_http_base.py
"""Общий асинхронный HTTP-клиент и утилиты ``niquests`` для REST-транспортов (Redfish, PVE, RESTCONF)."""

from __future__ import annotations

import builtins
import codecs
import contextlib
import inspect
import json
import logging
import sys
from collections.abc import AsyncIterator, Iterable, Mapping
from typing import Any

from ..exceptions import ConnectionError as UniconnConnectionError
from ..exceptions import OptionalDependencyError
from ..exceptions import TimeoutError as UniconnTimeoutError

SSE_MIME = "text/event-stream"

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
            if inspect.isawaitable(res):
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
        except Exception as exc:
            raise UniconnConnectionError(
                f"{self._error_prefix} {method_upper} {target} failed: {exc}"
            ) from exc


class SseEventParser:
    """Инкрементальный парсер событий Server-Sent Events (RFC 8040 / WHATWG / DMTF Redfish)."""

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


async def close_response_quietly(resp: Any) -> None:
    """Безопасно закрыть HTTP-ответ ``niquests`` (поддерживает sync и awaitable ``close()``)."""
    close_fn = getattr(resp, "close", None)
    if callable(close_fn):
        with contextlib.suppress(Exception):
            res_close = close_fn()
            if inspect.isawaitable(res_close):
                await res_close


def _decode_sse_chunk(chunk: Any, decoder: codecs.IncrementalDecoder) -> str:
    """Декодировать очередной фрагмент SSE-потока в текст UTF-8."""
    if isinstance(chunk, bytes | bytearray):
        return decoder.decode(bytes(chunk), final=False)
    return str(chunk)


async def iter_sse_response(
    resp: Any,
    *,
    timeout: float | None = None,
    timeout_errors: tuple[type[BaseException], ...] = (),
    error_prefix: str = "HTTP SSE",
) -> AsyncIterator[dict[str, str]]:
    """Потоково декодировать HTTP-ответ ``text/event-stream`` в последовательность SSE-событий."""
    parser = SseEventParser()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    eff_timeout_errors = timeout_errors or builtins_timeout_errors()
    content_iter: Any = None

    try:
        iter_fn = getattr(resp, "iter_content", None)
        content_iter = iter_fn(chunk_size=1024) if callable(iter_fn) else None
        if inspect.isawaitable(content_iter):
            content_iter = await content_iter

        if isinstance(content_iter, AsyncIterator):
            async for chunk in content_iter:
                if not chunk:
                    continue
                for ready in parser.feed(_decode_sse_chunk(chunk, decoder)):
                    yield ready
        elif isinstance(content_iter, Iterable) and not isinstance(content_iter, str | bytes | bytearray):
            for chunk in content_iter:
                if not chunk:
                    continue
                for ready in parser.feed(_decode_sse_chunk(chunk, decoder)):
                    yield ready
        else:
            raw_content = getattr(resp, "content", None)
            raw_text = getattr(resp, "text", None)
            if isinstance(raw_content, bytes | bytearray) and raw_content:
                for ready in parser.feed(decoder.decode(bytes(raw_content), final=False)):
                    yield ready
            elif isinstance(raw_text, str) and raw_text:
                for ready in parser.feed(raw_text):
                    yield ready

        tail = decoder.decode(b"", final=True)
        for ready in parser.feed(tail):
            yield ready
        for final_ev in parser.finish():
            yield final_ev
    except eff_timeout_errors as exc:
        timeout_hint = f" after {timeout}s" if timeout is not None else ""
        raise UniconnTimeoutError(f"{error_prefix} stream timed out{timeout_hint}") from exc
    finally:
        if isinstance(content_iter, AsyncIterator):
            aclose_fn = getattr(content_iter, "aclose", None)
            if callable(aclose_fn):
                with contextlib.suppress(Exception):
                    res_aclose = aclose_fn()
                    if inspect.isawaitable(res_aclose):
                        await res_aclose
        await close_response_quietly(resp)


__all__ = [
    "SSE_MIME",
    "BaseAsyncHttpClient",
    "SseEventParser",
    "builtins_timeout_errors",
    "close_response_quietly",
    "extract_response_headers",
    "iter_sse_response",
    "niquests",
    "parse_json_dict",
    "resolve_lazy_response",
    "resolve_niquests_module",
]
