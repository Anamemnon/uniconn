"""Unit-тесты для общего HTTP-клиента и утилит uniconn.transports._http_base."""

from __future__ import annotations

import builtins
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn.exceptions import ConnectionError as UniconnConnectionError
from uniconn.exceptions import OptionalDependencyError
from uniconn.exceptions import TimeoutError as UniconnTimeoutError
from uniconn.transports._http_base import (
    BaseAsyncHttpClient,
    builtins_timeout_errors,
    extract_response_headers,
    parse_json_dict,
    resolve_lazy_response,
    resolve_niquests_module,
)


class _DummyTimeoutError(Exception):
    pass


class _DummyRequestError(Exception):
    pass


def _make_fake_niquests() -> tuple[Any, MagicMock]:
    fake_session = MagicMock()
    fake_session.headers = {}
    fake_session.verify = True
    fake_session.close = AsyncMock()
    fake_session.gather = AsyncMock()
    fake_session.get = AsyncMock()
    fake_session.request = AsyncMock()

    niq_mod = SimpleNamespace(
        AsyncSession=MagicMock(return_value=fake_session),
        exceptions=SimpleNamespace(
            Timeout=_DummyTimeoutError,
            RequestException=_DummyRequestError,
        ),
    )
    return niq_mod, fake_session


class _DummyHttpClient(BaseAsyncHttpClient):
    def __init__(self, niq_mod: Any, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._niq_mod = niq_mod

    def _get_niquests(self) -> Any:
        return self._niq_mod


class TestHttpBaseHelpers:
    """Тесты вспомогательных функций модуля _http_base."""

    def test_extract_response_headers_handles_mapping_iterable_and_invalid(self) -> None:
        assert extract_response_headers(SimpleNamespace(headers={"X-One": 1, "Content-Type": "application/json"})) == {
            "X-One": "1",
            "Content-Type": "application/json",
        }
        assert extract_response_headers(SimpleNamespace(headers=[("A", "b"), ("C", "d")])) == {
            "A": "b",
            "C": "d",
        }
        assert extract_response_headers(SimpleNamespace(headers=None)) == {}
        assert extract_response_headers(SimpleNamespace(headers=12345)) == {}

    def test_parse_json_dict_variants(self) -> None:
        resp_dict = SimpleNamespace(text='{"k": "v"}', json=lambda: {"k": "v"})
        assert parse_json_dict(resp_dict) == {"k": "v"}

        resp_list = SimpleNamespace(text="[1, 2]", json=lambda: [1, 2])
        assert parse_json_dict(resp_list) == {"data": [1, 2]}

        def _bad_json() -> Any:
            raise json.JSONDecodeError("bad", "x", 0)

        resp_raw = SimpleNamespace(text="plain-body", json=_bad_json)
        assert parse_json_dict(resp_raw) == {"raw": "plain-body"}

        resp_empty = SimpleNamespace(text="", json=_bad_json)
        assert parse_json_dict(resp_empty) == {}

    def test_builtins_timeout_errors_and_resolve_niquests(self, monkeypatch: pytest.MonkeyPatch) -> None:
        niq_mod, _ = _make_fake_niquests()
        errs = builtins_timeout_errors(niq_mod)
        assert builtins.TimeoutError in errs
        assert _DummyTimeoutError in errs

        shim = SimpleNamespace(niquests=niq_mod)
        monkeypatch.setitem(__import__("sys").modules, "uniconn._dummy_http_shim", shim)
        assert resolve_niquests_module("uniconn._dummy_http_shim") is niq_mod
        assert resolve_niquests_module("uniconn._nonexistent_shim", fallback="fb") == "fb"

    @pytest.mark.asyncio
    async def test_resolve_lazy_response_calls_gather_when_lazy(self) -> None:
        session = SimpleNamespace(gather=AsyncMock())
        lazy_resp = SimpleNamespace(lazy=True)
        normal_resp = SimpleNamespace(lazy=False)

        assert await resolve_lazy_response(session, normal_resp) is normal_resp
        session.gather.assert_not_awaited()

        assert await resolve_lazy_response(session, lazy_resp) is lazy_resp
        session.gather.assert_awaited_once_with(lazy_resp)


class TestBaseAsyncHttpClient:
    """Тесты BaseAsyncHttpClient: создание сессий, закрытие и маппинг исключений."""

    def test_build_session_and_missing_dependency(self) -> None:
        missing_client = _DummyHttpClient(None, base_url="https://10.0.0.1/")
        with pytest.raises(ImportError, match="uniconn\\[bmc\\]"):
            missing_client._require_niquests("bmc", use_optional_dep=False)
        with pytest.raises(OptionalDependencyError, match="uniconn\\[network\\]"):
            missing_client._require_niquests("network", use_optional_dep=True)

        niq_mod, fake_session = _make_fake_niquests()
        client = _DummyHttpClient(
            niq_mod,
            base_url="https://bmc.local/",
            verify=False,
            multiplexed=True,
        )
        sess = client._build_session(
            pass_base_url=True,
            headers={"Accept": "application/json"},
            auth=("admin", "secret"),
        )
        assert sess is fake_session
        niq_mod.AsyncSession.assert_called_once_with(
            base_url="https://bmc.local",
            multiplexed=True,
            auth=("admin", "secret"),
        )
        assert fake_session.verify is False
        assert fake_session.headers == {"Accept": "application/json"}

        niq_mod.AsyncSession.reset_mock()
        sess2 = client._build_session(pass_base_url=False)
        assert sess2 is fake_session
        niq_mod.AsyncSession.assert_called_once_with(verify=False)

    @pytest.mark.asyncio
    async def test_close_handles_async_sync_and_oserror(self) -> None:
        niq_mod, fake_session = _make_fake_niquests()
        client = _DummyHttpClient(niq_mod, base_url="https://bmc.local", error_prefix="Redfish")
        client.session = fake_session
        await client.close()
        assert client.session is None
        fake_session.close.assert_awaited_once()

        sync_session = MagicMock()
        sync_session.close = MagicMock()
        client.session = sync_session
        await client.close()
        sync_session.close.assert_called_once()

        failing_session = MagicMock()
        failing_session.close = AsyncMock(side_effect=OSError("socket closed"))
        client.session = failing_session
        await client.close()
        assert client.session is None

    @pytest.mark.asyncio
    async def test_send_session_request_routes_and_maps_exceptions(self) -> None:
        niq_mod, fake_session = _make_fake_niquests()
        client = _DummyHttpClient(
            niq_mod,
            base_url="https://bmc.local",
            default_timeout=12.5,
            error_prefix="PVE",
        )

        lazy_ok = SimpleNamespace(lazy=True, status_code=200)
        fake_session.get.return_value = lazy_ok
        resp = await client._send_session_request(
            fake_session,
            "get",
            "/api2/json/nodes",
            params={"limit": 5},
            headers={"X-Test": "1"},
        )
        assert resp is lazy_ok
        fake_session.get.assert_awaited_once_with(
            "/api2/json/nodes",
            timeout=12.5,
            params={"limit": 5},
            headers={"X-Test": "1"},
        )
        fake_session.gather.assert_awaited_once_with(lazy_ok)

        fake_session.request.return_value = SimpleNamespace(lazy=False, status_code=200)
        await client._send_session_request(
            fake_session,
            "post",
            "/api2/json/action",
            timeout=5.0,
            json_payload={"ok": True},
            use_method_attr=False,
        )
        fake_session.request.assert_awaited_once_with(
            "POST",
            "/api2/json/action",
            timeout=5.0,
            json={"ok": True},
        )

        fake_session.get.side_effect = _DummyTimeoutError("read timed out")
        with pytest.raises(UniconnTimeoutError, match=r"PVE GET /slow timed out after 3\.0s"):
            await client._send_session_request(fake_session, "GET", "/slow", timeout=3.0)

        fake_session.get.side_effect = builtins.TimeoutError("deadline")
        with pytest.raises(UniconnTimeoutError, match=r"PVE GET /slow2 timed out after 12\.5s"):
            await client._send_session_request(fake_session, "GET", "/slow2")

        fake_session.get.side_effect = OSError("connection reset")
        with pytest.raises(UniconnConnectionError, match="PVE GET /down failed"):
            await client._send_session_request(fake_session, "GET", "/down")

        fake_session.get.side_effect = _DummyRequestError("tls failure")
        with pytest.raises(UniconnConnectionError, match="PVE GET /tls failed: tls failure"):
            await client._send_session_request(fake_session, "GET", "/tls")
