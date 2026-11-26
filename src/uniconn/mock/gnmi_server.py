# src/uniconn/mock/gnmi_server.py
"""Асинхронный сокетный MockGnmiServer (и SyncMockGnmiServer) для тестирования OpenConfig gNMI."""

from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import Mapping, Sequence
from typing import Any, Self

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..transports.network._h2_grpc import GrpcServerStream, serve_grpc_http2_client
from ..transports.network.base import apply_yang_edit, query_yang_tree
from ..transports.network.gnmi_proto import GnmiWireCodec

DEFAULT_GNMI_MODELS: tuple[dict[str, str], ...] = (
    {
        "name": "openconfig-interfaces",
        "organization": "OpenConfig working group",
        "version": "2.4.3",
    },
    {
        "name": "openconfig-system",
        "organization": "OpenConfig working group",
        "version": "0.17.1",
    },
    {
        "name": "ietf-interfaces",
        "organization": "IETF",
        "version": "2018-02-20",
    },
)


def _default_gnmi_tree() -> dict[str, Any]:
    return {
        "system": {
            "config": {"hostname": "spine-switch-01"},
            "state": {"hostname": "spine-switch-01"},
        },
        "interfaces": {
            "interface": [
                {
                    "name": "Ethernet1/1",
                    "config": {"name": "Ethernet1/1", "enabled": True, "mtu": 9216},
                    "state": {
                        "name": "Ethernet1/1",
                        "oper-status": "UP",
                        "mtu": 9216,
                        "hardware-address": "00:1c:73:aa:bb:01",
                        "counters": {
                            "in-octets": 1048576,
                            "out-octets": 2097152,
                            "in-errors": 0,
                        },
                    },
                    "subinterfaces": {
                        "subinterface": [
                            {
                                "index": 0,
                                "ipv4": {
                                    "addresses": {
                                        "address": [{"ip": "10.0.0.1"}]
                                    }
                                },
                            }
                        ]
                    },
                }
            ]
        },
    }


class MockGnmiServer:
    """Асинхронный сервер HTTP/2 gRPC OpenConfig gNMI (``Capabilities``, ``Get``, ``Set``, ``Subscribe``)."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        username: str | None = "admin",
        password: str | None = "secret",
        token: str | None = None,
        allow_any_auth: bool = False,
        initial_data: Mapping[str, Any] | None = None,
        models: Sequence[Mapping[str, str]] = DEFAULT_GNMI_MODELS,
        max_stream_samples: int = 3,
    ) -> None:
        """Инициализировать ``MockGnmiServer``."""
        self.host = host
        self._port = port
        self.username = username
        self.password = password
        self.token = token
        self.allow_any_auth = allow_any_auth
        self.datastore: dict[str, Any] = (
            copy.deepcopy(dict(initial_data))
            if initial_data is not None
            else _default_gnmi_tree()
        )
        self.models = [dict(m) for m in models]
        self.max_stream_samples = max_stream_samples
        self.history: list[dict[str, Any]] = []
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        """Фактический TCP-порт сервера."""
        return self._port

    @property
    def uri(self) -> str:
        """URI подключения ``gnmi://...``."""
        if self.username and (self.token or self.password):
            sec = self.token or self.password
            return f"gnmi://{self.username}:{sec}@{self.host}:{self._port}?tls=false"
        return f"gnmi://{self.host}:{self._port}?tls=false"

    @property
    def is_running(self) -> bool:
        """Запущен ли сервер."""
        return self._server is not None

    def _check_auth(self, user: str, secret: str) -> bool:
        if self.allow_any_auth or (not self.username and not self.token and not self.password):
            return True
        if self.token and secret == self.token:
            return True
        return user == (self.username or "") and secret == (self.password or "")

    def _extract_auth_from_headers(self, headers: Mapping[str, str]) -> tuple[str, str]:
        user = headers.get("username", "")
        secret = headers.get("password", "") or headers.get("token", "")
        auth_hdr = headers.get("authorization", "")
        if not secret and auth_hdr.lower().startswith("bearer "):
            secret = auth_hdr[7:].strip()
        return user, secret

    async def _handle_grpc_stream(self, stream: GrpcServerStream) -> None:
        rpc_path = stream.path
        method = rpc_path.rsplit("/", 1)[-1] if "/" in rpc_path else rpc_path
        user, secret = self._extract_auth_from_headers(stream.headers)
        auth_ok = self._check_auth(user, secret)
        self.history.append(
            {
                "method": method,
                "path": rpc_path,
                "username": user,
                "authenticated": auth_ok,
                "stream_id": stream.stream_id,
                "content_type": stream.headers.get("content-type", ""),
            }
        )

        if not auth_ok:
            await stream.finish(
                grpc_status=16,
                grpc_message="gNMI authentication failed: invalid credentials",
            )
            return

        payload = await stream.read_frame(timeout=30.0) or b""

        if rpc_path == "/gnmi.gNMI/Capabilities":
            cap_bytes = GnmiWireCodec.encode_capabilities_response(self.models)
            await stream.send_frame(cap_bytes)
            await stream.finish(grpc_status=0)
            return

        if rpc_path == "/gnmi.gNMI/Get":
            req = GnmiWireCodec.decode_get_request(payload)
            paths = req.get("paths") or ["/"]
            enc = str(req.get("encoding", "json_ietf"))
            notifs: list[bytes] = []
            now_ns = int(time.time() * 1e9)
            for p in paths:
                val = query_yang_tree(self.datastore, p)
                if val is None:
                    await stream.finish(
                        grpc_status=5,
                        grpc_message=f"gNMI path not found: {p}",
                    )
                    return
                notifs.append(
                    GnmiWireCodec.encode_notification(
                        timestamp=now_ns,
                        updates=[(p, val)],
                        encoding=enc,
                    )
                )
            resp_bytes = GnmiWireCodec.encode_get_response(notifs)
            await stream.send_frame(resp_bytes)
            await stream.finish(grpc_status=0)
            return

        if rpc_path == "/gnmi.gNMI/Set":
            req = GnmiWireCodec.decode_set_request(payload)
            results_meta: list[tuple[str, Any]] = []
            for del_path in req.get("deletes", []):
                apply_yang_edit(self.datastore, del_path, {}, operation="delete")
                results_meta.append((del_path, "delete"))
            for rep_path, rep_val in req.get("replaces", []):
                apply_yang_edit(self.datastore, rep_path, rep_val, operation="replace")
                results_meta.append((rep_path, "replace"))
            for up_path, up_val in req.get("updates", []):
                apply_yang_edit(self.datastore, up_path, up_val, operation="merge")
                results_meta.append((up_path, "update"))
            resp_bytes = GnmiWireCodec.encode_set_response(
                results_meta,
                timestamp=int(time.time() * 1e9),
            )
            await stream.send_frame(resp_bytes)
            await stream.finish(grpc_status=0)
            return

        if rpc_path == "/gnmi.gNMI/Subscribe":
            sub_req = GnmiWireCodec.decode_subscribe_request(payload)
            paths = sub_req.get("paths") or ["/"]
            list_mode = sub_req.get("list_mode", "stream")
            enc = str(sub_req.get("encoding", "json_ietf"))
            interval_ns = int(sub_req.get("sample_interval_ns") or 10_000_000)
            sleep_sec = min(0.05, max(0.005, interval_ns / 1e9))
            count = 1 if list_mode == "once" else self.max_stream_samples

            for i in range(count):
                if stream.finished:
                    break
                now_ns = int(time.time() * 1e9) + i * 1000
                for p in paths:
                    val = query_yang_tree(self.datastore, p)
                    if isinstance(val, dict) and "in-octets" in val:
                        val = dict(val)
                        val["in-octets"] = int(val["in-octets"]) + i * 1024
                        val["out-octets"] = int(val.get("out-octets", 0)) + i * 2048
                    notif_bytes = GnmiWireCodec.encode_notification(
                        timestamp=now_ns,
                        updates=[(p, val if val is not None else {})],
                        encoding=enc,
                    )
                    sub_resp = GnmiWireCodec.encode_subscribe_response(
                        notification=notif_bytes,
                        sync_response=(i == 0),
                    )
                    await stream.send_frame(sub_resp)
                if i + 1 < count and not stream.finished:
                    await asyncio.sleep(sleep_sec)
            await stream.finish(grpc_status=0)
            return

        await stream.finish(
            grpc_status=12,
            grpc_message=f"Unimplemented gRPC method: {rpc_path}",
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await serve_grpc_http2_client(reader, writer, self._handle_grpc_stream)

    async def start(self) -> Self:
        """Запустить сокетный сервер gNMI."""
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
        """Остановить сокетный сервер gNMI."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    def to_sync(self) -> SyncMockGnmiServer:
        """Вернуть синхронный фасад ``SyncMockGnmiServer``."""
        return SyncMockGnmiServer(self)


class SyncMockGnmiServer(SyncProxyMixin):
    """Синхронный фасад ``MockGnmiServer`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        server: MockGnmiServer | None = None,
        portal: EventLoopPortal | None = None,
        **kwargs: Any,
    ) -> None:
        self._async_target = (
            server if isinstance(server, MockGnmiServer) else MockGnmiServer(**kwargs)
        )
        self._portal = portal or EventLoopPortal(owner_name="SyncMockGnmiServer")

    start = sync_method(MockGnmiServer.start)
    stop = sync_method(MockGnmiServer.stop)

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
    def token(self) -> str | None:
        return self._async_target.token

    @property
    def allow_any_auth(self) -> bool:
        return self._async_target.allow_any_auth

    @property
    def datastore(self) -> dict[str, Any]:
        return self._async_target.datastore

    @property
    def models(self) -> list[dict[str, str]]:
        return self._async_target.models

    @property
    def max_stream_samples(self) -> int:
        return self._async_target.max_stream_samples

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
    "DEFAULT_GNMI_MODELS",
    "MockGnmiServer",
    "SyncMockGnmiServer",
]
