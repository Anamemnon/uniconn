"""Unit tests for v0.14.0 features:
DMTF Redfish BMC Transport (redfish://) powered by niquests.AsyncSession:
- URIParser parsing and round-trip building for redfish:// (default port 443, query options, SecretResolver)
- TransportLoader discovery and Connection.from_uri("redfish://...") instantiation
- Redfish Session Token authentication (X-Auth-Token + DELETE on disconnect) & fallback to HTTP Basic Auth
- Resource auto-discovery (/redfish/v1/Systems, /redfish/v1/Chassis, /redfish/v1/Managers) and explicit IDs
- Power management: power status, on, off, graceful_off, cycle, graceful_restart, nmi
- Telemetry & sensors: concurrent Thermal + Power collection via asyncio.gather
- System Event Logs (SEL): logs, logs <limit>, sel clear, and line-by-line conn.stream("sel")
- Boot override: boot status, boot pxe once uefi, boot hdd continuous legacy
- Virtual Media: virtual_media status, mount <iso_url>, unmount / eject
- Raw REST escape hatch: GET / POST / PATCH / DELETE /redfish/v1/...
- HostFacts integration: conn.gather_facts() and diff_facts() for redfish://
- Cassette recording & deterministic replay with conn.use_cassette()
"""

from __future__ import annotations

import builtins
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import uniconn
from uniconn import (
    AuthenticationError,
    BMCCapabilityError,
    CommandTransport,
    Connection,
    FileCapableTransport,
    RedfishTransport,
    ShellCapableTransport,
    SyncConnection,
    TimeoutError,
    TunnelCapableTransport,
    URIParser,
    diff_facts,
    supports_capability,
)


def _make_niq_response(
    status_code: int = 200,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock niquests Response with synchronous .json() and .text."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    if payload is not None:
        resp.text = json.dumps(payload)
        resp.json = MagicMock(return_value=payload)
    else:
        resp.text = ""
        resp.json = MagicMock(return_value={})
    return resp


def _build_fake_redfish_session(
    *,
    session_auth_supported: bool = True,
    auth_fail: bool = False,
) -> MagicMock:
    """Create a mock niquests.AsyncSession configured with realistic DMTF Redfish endpoints."""
    session = MagicMock()
    session.headers = {}
    session.verify = False
    session.auth = None
    session.close = AsyncMock(return_value=None)

    routes_get: dict[str, tuple[int, dict[str, Any]]] = {
        "/redfish/v1": (
            200,
            {
                "@odata.id": "/redfish/v1",
                "RedfishVersion": "1.18.0",
                "Name": "Root Service",
            },
        ),
        "/redfish/v1/Systems": (
            200,
            {
                "Members": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1"}],
                "Members@odata.count": 1,
            },
        ),
        "/redfish/v1/Chassis": (
            200,
            {
                "Members": [{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1"}],
                "Members@odata.count": 1,
            },
        ),
        "/redfish/v1/Managers": (
            200,
            {
                "Members": [{"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"}],
                "Members@odata.count": 1,
            },
        ),
        "/redfish/v1/Systems/System.Embedded.1": (
            200,
            {
                "@odata.id": "/redfish/v1/Systems/System.Embedded.1",
                "Id": "System.Embedded.1",
                "Manufacturer": "Dell Inc.",
                "Model": "PowerEdge R760",
                "SerialNumber": "SRV760XYZ",
                "SKU": "SKU-R760",
                "UUID": "4c4c4544-0053-5210-8056-b7c04f58595a",
                "HostName": "node01-bmc.dc.local",
                "PowerState": "On",
                "IndicatorLED": "Off",
                "BiosVersion": "2.1.5",
                "Status": {"State": "Enabled", "Health": "OK"},
                "ProcessorSummary": {
                    "Count": 2,
                    "Model": "Intel(R) Xeon(R) Gold 6430",
                    "InstructionSet": "x86-64",
                },
                "MemorySummary": {
                    "TotalSystemMemoryGiB": 256.0,
                    "Status": {"Health": "OK"},
                },
                "Boot": {
                    "BootSourceOverrideTarget": "Pxe",
                    "BootSourceOverrideEnabled": "Once",
                    "BootSourceOverrideMode": "UEFI",
                    "UefiTargetBootSourceOverride": None,
                },
            },
        ),
        "/redfish/v1/Managers/iDRAC.Embedded.1": (
            200,
            {
                "@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1",
                "Id": "iDRAC.Embedded.1",
                "Manufacturer": "Dell Inc.",
                "Model": "iDRAC9",
                "FirmwareVersion": "7.10.30.00",
            },
        ),
        "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces": (
            200,
            {
                "Members": [
                    {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.1"}
                ]
            },
        ),
        "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.1": (
            200,
            {
                "Id": "NIC.1",
                "Name": "System Ethernet Interface 1",
                "MACAddress": "AA:BB:CC:DD:EE:01",
                "LinkStatus": "LinkUp",
                "InterfaceEnabled": True,
                "MTUSize": 9000,
                "IPv4Addresses": [{"Address": "10.20.30.40"}],
                "IPv6Addresses": [{"Address": "fe80::1"}],
            },
        ),
        "/redfish/v1/Chassis/System.Embedded.1/Thermal": (
            200,
            {
                "Temperatures": [
                    {
                        "Name": "System Board Inlet Temp",
                        "ReadingCelsius": 23,
                        "UpperThresholdCritical": 47,
                        "Status": {"Health": "OK"},
                    },
                    {
                        "Name": "CPU1 Temp",
                        "ReadingCelsius": 54,
                        "UpperThresholdCritical": 95,
                        "Status": {"Health": "OK"},
                    },
                ],
                "Fans": [
                    {
                        "Name": "Fan1A",
                        "Reading": 6400,
                        "ReadingUnits": "RPM",
                        "Status": {"Health": "OK"},
                    }
                ],
            },
        ),
        "/redfish/v1/Chassis/System.Embedded.1/Power": (
            200,
            {
                "PowerControl": [
                    {
                        "PowerConsumedWatts": 310,
                        "PowerCapacityWatts": 1400,
                    }
                ],
                "PowerSupplies": [
                    {
                        "Name": "PSU.Slot.1",
                        "Model": "PWR-1400W",
                        "PowerOutputWatts": 160,
                        "Status": {"Health": "OK"},
                    }
                ],
            },
        ),
        "/redfish/v1/Systems/System.Embedded.1/LogServices": (
            200,
            {
                "Members": [
                    {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/LogServices/Sel"}
                ]
            },
        ),
        "/redfish/v1/Systems/System.Embedded.1/LogServices/Sel/Entries": (
            200,
            {
                "Members": [
                    {
                        "Id": "1",
                        "Created": "2026-10-25T10:00:00Z",
                        "Severity": "OK",
                        "Message": "System Chassis Intrusion cleared.",
                        "SensorType": "Physical Chassis Security",
                    },
                    {
                        "Id": "2",
                        "Created": "2026-10-26T11:30:00Z",
                        "Severity": "Warning",
                        "Message": "Power supply redundancy degraded.",
                        "SensorType": "Power Supply",
                    },
                ]
            },
        ),
        "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia": (
            200,
            {
                "Members": [
                    {"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD"}
                ]
            },
        ),
        "/redfish/v1/Managers/iDRAC.Embedded.1/VirtualMedia/CD": (
            200,
            {
                "Id": "CD",
                "Image": "https://repo.local/ubuntu-24.04.iso",
                "Inserted": True,
                "MediaTypes": ["CD", "DVD"],
                "ConnectedVia": "URI",
            },
        ),
    }

    async def _fake_get(path: str, timeout: float | None = None, **kwargs: Any) -> MagicMock:
        _ = (timeout, kwargs)
        if auth_fail:
            return _make_niq_response(401, {"error": "Unauthorized"})
        if path in routes_get:
            st, body = routes_get[path]
            return _make_niq_response(st, body)
        return _make_niq_response(404, {"error": f"Not found: {path}"})

    async def _fake_post(
        path: str,
        json: dict[str, Any] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> MagicMock:
        _ = (timeout, kwargs)
        if path == "/redfish/v1/SessionService/Sessions":
            if auth_fail:
                return _make_niq_response(401, {"error": "Invalid credentials"})
            if not session_auth_supported:
                return _make_niq_response(404, {"error": "SessionService not implemented"})
            return _make_niq_response(
                201,
                {"@odata.id": "/redfish/v1/SessionService/Sessions/sess-42", "Id": "sess-42"},
                headers={
                    "X-Auth-Token": "tok-secret-xyz",
                    "Location": "/redfish/v1/SessionService/Sessions/sess-42",
                },
            )
        return _make_niq_response(200, {"status": "Accepted", "path": path, "payload": json or {}})

    async def _fake_patch(
        path: str,
        json: dict[str, Any] | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> MagicMock:
        _ = (timeout, kwargs)
        return _make_niq_response(200, {"status": "Patched", "path": path, "payload": json or {}})

    async def _fake_delete(path: str, timeout: float | None = None, **kwargs: Any) -> MagicMock:
        _ = (timeout, kwargs)
        return _make_niq_response(200, {"status": "Deleted", "path": path})

    session.get = AsyncMock(side_effect=_fake_get)
    session.post = AsyncMock(side_effect=_fake_post)
    session.patch = AsyncMock(side_effect=_fake_patch)
    session.delete = AsyncMock(side_effect=_fake_delete)
    return session


class TestRedfishURIParsingAndVersion:
    """Tests for v0.14.0 version bump and redfish:// URI parsing."""

    def test_version_is_0140(self) -> None:
        assert uniconn.__version__ == "0.16.1"

    def test_parse_redfish_uri_defaults_and_options(self) -> None:
        uri = (
            "redfish://admin:calvin@10.0.0.100"
            "?verify_ssl=false&system_id=System.Embedded.1&multiplexed=true"
        )
        cfg = URIParser.parse(uri)
        assert cfg.transport == "redfish"
        assert cfg.host == "10.0.0.100"
        assert cfg.port == 443
        assert cfg.username == "admin"
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "calvin"
        assert cfg.options["verify_ssl"] is False
        assert cfg.options["system_id"] == "System.Embedded.1"
        assert cfg.options["multiplexed"] is True

        rebuilt = URIParser.build(
            "redfish",
            host=cfg.host,
            port=cfg.port,
            username=cfg.username,
            password=cfg.password.get_secret_value(),
            options=cfg.options,
        )
        assert rebuilt.startswith("redfish://admin:calvin@10.0.0.100:443?")

    def test_connection_from_uri_resolves_redfish_transport(self) -> None:
        conn = Connection.from_uri("redfish://root:secret@bmc.example.com:8443?verify_ssl=false")
        assert isinstance(conn._transport, RedfishTransport)
        assert conn._transport.name == "redfish"
        assert conn._transport.base_url == "https://bmc.example.com:8443"
        assert supports_capability(conn._transport, CommandTransport)
        assert not supports_capability(conn._transport, FileCapableTransport)
        assert not supports_capability(conn._transport, ShellCapableTransport)
        assert not supports_capability(conn._transport, TunnelCapableTransport)

    def test_parse_redfish_http_scheme_defaults_to_port_80(self) -> None:
        cfg = URIParser.parse("redfish://admin:calvin@10.0.0.100?scheme=http")
        assert cfg.transport == "redfish"
        assert cfg.port == 80
        assert cfg.options["scheme"] == "http"
        conn = Connection.from_config(cfg)
        assert isinstance(conn._transport, RedfishTransport)
        assert conn._transport.base_url == "http://10.0.0.100:80"


class TestRedfishSessionAndBasicAuth:
    """Tests for niquests.AsyncSession lifecycle, Session Token auth, and Basic Auth fallback."""

    @pytest.mark.asyncio
    async def test_session_token_auth_and_clean_logout_on_disconnect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session(session_auth_supported=True)
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            assert isinstance(conn._transport, RedfishTransport)
            assert conn._transport.is_connected
            assert conn._transport.auth_mode == "session"
            assert fake_session.headers.get("X-Auth-Token") == "tok-secret-xyz"
            ping_res = await conn.ping()
            assert ping_res.alive is True

        assert not conn._transport.is_connected
        fake_session.delete.assert_awaited_once_with(
            "/redfish/v1/SessionService/Sessions/sess-42", timeout=5.0
        )
        fake_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fallback_to_basic_auth_when_session_service_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session(session_auth_supported=False)
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            assert isinstance(conn._transport, RedfishTransport)
            assert conn._transport.auth_mode == "basic"
            assert fake_session.auth == ("admin", "calvin")

        fake_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_authentication_error_on_invalid_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session(auth_fail=True)
        conn = Connection.from_uri("redfish://admin:wrong@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        with pytest.raises(AuthenticationError):
            async with conn:
                pass
        fake_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_timeout_raises_uniconn_timeout_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = MagicMock()
        fake_session.headers = {}
        fake_session.close = AsyncMock()
        fake_session.post = AsyncMock(side_effect=builtins.TimeoutError("timed out"))

        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        with pytest.raises(TimeoutError, match="timed out"):
            async with conn:
                pass
        fake_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lazy_multiplexed_response_and_full_url_normalization(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base_session = _build_fake_redfish_session(session_auth_supported=True)
        orig_post = base_session.post.side_effect
        orig_get = base_session.get.side_effect

        def _make_lazy(resp: MagicMock) -> MagicMock:
            real_status = resp.status_code
            real_headers = resp.headers
            real_text = resp.text
            real_json = resp.json
            resp.lazy = True
            resp.status_code = None
            resp.headers = {}
            resp.text = ""
            resp._restore = (real_status, real_headers, real_text, real_json)
            return resp

        async def _gather(*resps: Any) -> None:
            for r in resps:
                if getattr(r, "lazy", False):
                    st, hdrs, txt, jfn = r._restore
                    r.status_code = st
                    r.headers = hdrs
                    r.text = txt
                    r.json = jfn
                    r.lazy = False

        async def _lazy_post(path: str, **kw: Any) -> MagicMock:
            r = await orig_post(path, **kw)
            r.headers["Location"] = (
                "https://10.0.0.100/redfish/v1/SessionService/Sessions/sess-42"
            )
            return _make_lazy(r)

        async def _lazy_get(path: str, **kw: Any) -> MagicMock:
            r = await orig_get(path, **kw)
            if path == "/redfish/v1/Systems":
                payload = {
                    "Members": [
                        {
                            "@odata.id": "https://10.0.0.100/redfish/v1/Systems/System.Embedded.1"
                        }
                    ]
                }
                r = _make_niq_response(200, payload)
            return _make_lazy(r)

        base_session.post = AsyncMock(side_effect=_lazy_post)
        base_session.get = AsyncMock(side_effect=_lazy_get)
        base_session.gather = AsyncMock(side_effect=_gather)

        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: base_session)

        async with conn:
            res = await conn.run("power status")
            assert res.ok
            assert json.loads(res.stdout)["PowerState"] == "On"
            assert base_session.gather.await_count >= 2

        base_session.delete.assert_awaited_once_with(
            "/redfish/v1/SessionService/Sessions/sess-42", timeout=5.0
        )


class TestRedfishBMCCommands:
    """Tests for power, sensors, inventory, sel/logs, boot, virtual_media, and raw REST."""

    @pytest.mark.asyncio
    async def test_power_status_and_reset_actions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            st_res = await conn.run("power status")
            assert st_res.ok
            st_data = json.loads(st_res.stdout)
            assert st_data["PowerState"] == "On"
            assert st_data["SystemUri"] == "/redfish/v1/Systems/System.Embedded.1"

            cycle_res = await conn.run("power cycle")
            assert cycle_res.ok
            cycle_data = json.loads(cycle_res.stdout)
            assert cycle_data["ok"] is True
            assert cycle_data["ResetType"] == "ForceRestart"

            off_res = await conn.run("power graceful_off")
            assert json.loads(off_res.stdout)["ResetType"] == "GracefulShutdown"

    @pytest.mark.asyncio
    async def test_sensors_and_inventory_commands(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            sens_res = await conn.run("sensors")
            assert sens_res.ok
            sens = json.loads(sens_res.stdout)
            assert sens["power_consumed_watts"] == 310
            assert sens["power_capacity_watts"] == 1400
            assert len(sens["temperatures"]) == 2
            assert sens["temperatures"][0]["reading_celsius"] == 23
            assert sens["fans"][0]["reading"] == 6400

            inv_res = await conn.run("inventory")
            assert inv_res.ok
            inv = json.loads(inv_res.stdout)
            assert inv["manufacturer"] == "Dell Inc."
            assert inv["model"] == "PowerEdge R760"
            assert inv["serial_number"] == "SRV760XYZ"
            assert inv["bmc_firmware_version"] == "7.10.30.00"
            assert inv["memory_summary"]["total_system_memory_gib"] == 256.0

    @pytest.mark.asyncio
    async def test_sel_logs_stream_and_clear(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            logs_res = await conn.run("logs 1")
            assert logs_res.ok
            logs_data = json.loads(logs_res.stdout)
            assert logs_data["count"] == 1
            assert logs_data["entries"][0]["severity"] == "Warning"

            streamed_lines: list[str] = []
            async for line in conn.stream("sel"):
                streamed_lines.append(line)
            assert len(streamed_lines) == 2
            assert "[OK] System Chassis Intrusion cleared." in streamed_lines[0]
            assert "[Warning] Power supply redundancy degraded." in streamed_lines[1]

            clear_res = await conn.run("sel clear")
            assert clear_res.ok
            assert json.loads(clear_res.stdout)["action"] == "LogService.ClearLog"

    @pytest.mark.asyncio
    async def test_boot_override_and_virtual_media_commands(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            boot_st = await conn.run("boot status")
            assert json.loads(boot_st.stdout)["BootSourceOverrideTarget"] == "Pxe"

            boot_set = await conn.run("boot pxe once uefi")
            assert boot_set.ok
            boot_patch = json.loads(boot_set.stdout)["Boot"]
            assert boot_patch == {
                "BootSourceOverrideTarget": "Pxe",
                "BootSourceOverrideEnabled": "Once",
                "BootSourceOverrideMode": "UEFI",
            }

            vm_st = await conn.run("virtual_media status")
            assert json.loads(vm_st.stdout)["inserted"] is True

            vm_mount = await conn.run("virtual_media mount https://iso.local/debian.iso")
            assert vm_mount.ok
            assert json.loads(vm_mount.stdout)["Image"] == "https://iso.local/debian.iso"

            vm_eject = await conn.run("virtual_media unmount")
            assert vm_eject.ok
            assert json.loads(vm_eject.stdout)["action"] == "VirtualMedia.EjectMedia"

    @pytest.mark.asyncio
    async def test_raw_rest_and_unknown_command_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            raw_get = await conn.run("GET /redfish/v1")
            assert raw_get.ok
            assert json.loads(raw_get.stdout)["RedfishVersion"] == "1.18.0"

            raw_patch = await conn.run(
                'PATCH /redfish/v1/Systems/System.Embedded.1 {"AssetTag": "RACK-12"}'
            )
            assert raw_patch.ok
            assert json.loads(raw_patch.stdout)["payload"] == {"AssetTag": "RACK-12"}

            with pytest.raises(BMCCapabilityError):
                await conn.run("unsupported_bmc_cmd")


class TestRedfishFactsAndCassette:
    """Tests for conn.gather_facts(), diff_facts(), and Cassette replay on redfish://."""

    @pytest.mark.asyncio
    async def test_gather_facts_and_diff_facts_on_redfish(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            facts = await conn.gather_facts()
            assert facts.os_family == "BMC"
            assert facts.distro == "Dell Inc. PowerEdge R760"
            assert facts.kernel == "7.10.30.00"
            assert facts.hostname == "node01-bmc.dc.local"
            assert facts.cpu_count == 2
            assert facts.memory_total_bytes == 256 * 1024**3
            assert facts.custom["redfish"]["serial_number"] == "SRV760XYZ"
            assert facts.custom["redfish"]["bios_version"] == "2.1.5"
            assert facts.custom["redfish"]["power_consumed_watts"] == 310
            assert len(facts.interfaces) == 1
            assert facts.interfaces[0].mac == "AA:BB:CC:DD:EE:01"

            # Verify diff_facts works with BMC facts and custom.redfish.* fields
            facts_peer = facts.model_copy(deep=True)
            facts_peer.kernel = "7.00.00.00"
            facts_peer.custom["redfish"]["bios_version"] = "2.0.1"
            report = diff_facts(
                {"bmc-01": facts, "bmc-02": facts_peer},
                fields=["os_family", "kernel", "custom.redfish.bios_version"],
            )
            assert report.has_drift
            assert "kernel" in report.drifted_hosts["bmc-02"]
            assert "custom.redfish.bios_version" in report.drifted_hosts["bmc-02"]

    @pytest.mark.asyncio
    async def test_cassette_record_and_replay_for_redfish(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cassette_file = tmp_path / "redfish_bmc.json"
        fake_session = _build_fake_redfish_session()
        conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(conn._transport, "_create_async_session", lambda: fake_session)

        async with conn:
            async with conn.use_cassette(cassette_file, mode="all"):
                res_power = await conn.run("power status")
                res_sens = await conn.run("sensors")
                facts_rec = await conn.gather_facts(refresh=True)
                assert res_power.ok
                assert res_sens.ok
                assert facts_rec.os_family == "BMC"

        assert cassette_file.exists()

        # Replay without network access (including ping + gather_facts)
        replay_conn = Connection.from_uri("redfish://admin:calvin@10.0.0.100")
        async with replay_conn.use_cassette(cassette_file, mode="none"):
            ping_replay = await replay_conn.ping()
            assert ping_replay.alive is True
            replayed_power = await replay_conn.run("power status")
            replayed_sens = await replay_conn.run("sensors")
            replayed_facts = await replay_conn.gather_facts(refresh=True)
            assert json.loads(replayed_power.stdout)["PowerState"] == "On"
            assert json.loads(replayed_sens.stdout)["power_consumed_watts"] == 310
            assert replayed_facts.os_family == "BMC"
            assert replayed_facts.distro == "Dell Inc. PowerEdge R760"

        # Standalone replay:// URI also auto-detects Redfish facts
        async with Connection.from_uri(f"replay://{cassette_file}") as standalone_replay:
            standalone_facts = await standalone_replay.gather_facts(refresh=True)
            assert standalone_facts.os_family == "BMC"
            assert standalone_facts.kernel == "7.10.30.00"


class TestRedfishSyncConnectionAndLiveHTTPServer:
    """Tests for SyncConnection parity and real niquests.AsyncSession over local HTTP."""

    def test_sync_connection_redfish_parity(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        fake_session = _build_fake_redfish_session()
        sync_conn = SyncConnection.from_uri("redfish://admin:calvin@10.0.0.100")
        monkeypatch.setattr(
            sync_conn._async_conn._transport,
            "_create_async_session",
            lambda: fake_session,
        )

        with sync_conn:
            ping_res = sync_conn.ping()
            assert ping_res.alive is True

            pw_res = sync_conn.run("power status")
            assert pw_res.ok
            assert json.loads(pw_res.stdout)["PowerState"] == "On"

            facts = sync_conn.gather_facts()
            assert facts.os_family == "BMC"
            assert facts.distro == "Dell Inc. PowerEdge R760"

            lines = list(sync_conn.stream("sel"))
            assert len(lines) == 2

            cassette_path = tmp_path / "sync_redfish.json"
            with sync_conn.use_cassette(cassette_path, mode="all"):
                c_res = sync_conn.run("sensors")
                assert c_res.ok
            assert cassette_path.exists()

    @pytest.mark.asyncio
    async def test_real_niquests_async_session_against_local_http_server(self) -> None:
        deleted_sessions: list[str] = []

        class _RedfishMockHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                _ = (format, args)

            def _send_json(
                self,
                status: int,
                body: dict[str, Any],
                extra_headers: dict[str, str] | None = None,
            ) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (extra_headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length) if length else b""
                if self.path == "/redfish/v1/SessionService/Sessions":
                    self._send_json(
                        201,
                        {"Id": "1", "@odata.id": "/redfish/v1/SessionService/Sessions/1"},
                        extra_headers={
                            "X-Auth-Token": "live-token-123",
                            "Location": "/redfish/v1/SessionService/Sessions/1",
                        },
                    )
                else:
                    self._send_json(200, {"TaskState": "Completed"})

            def do_GET(self) -> None:
                if self.headers.get("X-Auth-Token") != "live-token-123":
                    self._send_json(401, {"error": "Unauthorized"})
                    return
                if self.path == "/redfish/v1":
                    self._send_json(200, {"RedfishVersion": "1.18.0"})
                elif self.path == "/redfish/v1/Systems":
                    self._send_json(
                        200,
                        {"Members": [{"@odata.id": "/redfish/v1/Systems/1"}]},
                    )
                elif self.path == "/redfish/v1/Systems/1":
                    self._send_json(
                        200,
                        {
                            "PowerState": "On",
                            "HostName": "live-bmc-node",
                            "Status": {"Health": "OK"},
                        },
                    )
                else:
                    self._send_json(404, {"error": "Not found"})

            def do_DELETE(self) -> None:
                deleted_sessions.append(self.path)
                self._send_json(200, {"Deleted": True})

        server = ThreadingHTTPServer(("127.0.0.1", 0), _RedfishMockHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            uri = f"redfish://admin:calvin@127.0.0.1:{port}?scheme=http&multiplexed=true"
            async with Connection.from_uri(uri) as conn:
                ping_res = await conn.ping()
                assert ping_res.alive is True

                st_res = await conn.run("power status")
                assert st_res.ok
                data = json.loads(st_res.stdout)
                assert data["PowerState"] == "On"
                assert data["HostName"] == "live-bmc-node"

            assert deleted_sessions == ["/redfish/v1/SessionService/Sessions/1"]
        finally:
            server.shutdown()
            server.server_close()
