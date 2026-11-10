# tests/unit/transports/test_network_protocols.py
"""Модульные тесты структурированных сетевых протоколов: NETCONF, RESTCONF, gNMI."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from uniconn import (
    AuthenticationError,
    Connection,
    ConnectionPool,
    ExecutionError,
    GnmiWireCodec,
    MockGnmiServer,
    MockNetconfServer,
    MockRestconfServer,
    NetconfFrameCodec,
    NetconfVendorAdapter,
    NetResult,
    SyncMockGnmiServer,
    SyncMockNetconfServer,
    SyncMockRestconfServer,
    TelemetrySample,
    URIParser,
    format_gnmi_path,
    parse_gnmi_path,
    safe_parse_xml,
)

# ─── 1. Парсинг URI и секретов ──────────────────────────────────────


def test_uri_parser_structured_network_schemes(monkeypatch: pytest.MonkeyPatch) -> None:
    """URIParser корректно разбирает netconf://, restconf:// и gnmi:// со всеми параметрами."""
    monkeypatch.setenv("NET_PASS", "s3cr3t")

    nc_cfg = URIParser.parse(
        "netconf://admin:env://NET_PASS@10.0.0.1?vendor=junos&version=1.0&verify_host_key=false"
    )
    assert nc_cfg.transport == "netconf"
    assert nc_cfg.host == "10.0.0.1"
    assert nc_cfg.port == 830
    assert nc_cfg.username == "admin"
    assert nc_cfg.password is not None
    assert nc_cfg.password.get_secret_value() == "s3cr3t"
    assert nc_cfg.options["vendor"] == "junos"
    assert nc_cfg.options["version"] == "1.0"
    assert nc_cfg.options["verify_host_key"] is False

    rc_cfg = URIParser.parse(
        "restconf://admin:pass@router.local/restconf?verify_tls=false&format=json"
    )
    assert rc_cfg.transport == "restconf"
    assert rc_cfg.port == 443
    assert rc_cfg.options["root"] == "/restconf"
    assert rc_cfg.options["verify_tls"] is False
    assert rc_cfg.options["format"] == "json"

    rc_http = URIParser.parse("restconf://admin:pass@127.0.0.1?scheme=http")
    assert rc_http.port == 80

    gnmi_cfg = URIParser.parse(
        "gnmi://admin:pass@10.0.0.2?insecure=true&encoding=json_ietf&origin=openconfig"
    )
    assert gnmi_cfg.transport == "gnmi"
    assert gnmi_cfg.port == 9339
    assert gnmi_cfg.options["insecure"] is True
    assert gnmi_cfg.options["encoding"] == "json_ietf"
    assert gnmi_cfg.options["origin"] == "openconfig"


# ─── 2. Кадрирование NETCONF (RFC 4742 v1.0 / RFC 6242 v1.1) и XXE ─


async def test_netconf_frame_codec_v10_and_v11() -> None:
    """NetconfFrameCodec кодирует и декодирует фреймы 1.0 (]]>]]>) и 1.1 (chunked)."""
    encoded_hello = NetconfFrameCodec.encode_hello(
        capabilities=[
            "urn:ietf:params:netconf:base:1.0",
            "urn:ietf:params:netconf:base:1.1",
            "urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&revision=2018-02-20",
        ],
        session_id=42,
    )
    assert encoded_hello.endswith(b"]]>]]>")
    caps, sid = NetconfFrameCodec.decode_hello(encoded_hello[:-6])
    assert sid == "42"
    assert "urn:ietf:params:netconf:base:1.1" in caps
    assert any("revision=2018-02-20" in c for c in caps)

    negotiated = NetconfFrameCodec.negotiate_version(
        ["urn:ietf:params:netconf:base:1.0", "urn:ietf:params:netconf:base:1.1"],
        caps,
        requested_version="auto",
    )
    assert negotiated == "1.1"

    rpc_xml = '<rpc message-id="101"><get/></rpc>'
    encoded_11 = NetconfFrameCodec.encode_frame(rpc_xml, version="1.1")
    assert encoded_11.startswith(b"\n#")
    assert encoded_11.endswith(b"\n##\n")

    # Проверка потокового чтения фрагментированного чанка 1.1
    chunks = [encoded_11[i : i + 5] for i in range(0, len(encoded_11), 5)]

    class _ChunkedReader:
        def __init__(self, parts: list[bytes]) -> None:
            self._parts = list(parts)

        async def read(self, _n: int = 65536) -> bytes:
            if not self._parts:
                return b""
            return self._parts.pop(0)

    buf = bytearray()
    raw_frame = await NetconfFrameCodec.read_frame(
        _ChunkedReader(chunks),
        buf,
        version="1.1",
    )
    assert raw_frame.decode("utf-8") == rpc_xml


def test_xxe_protection_rejects_doctype_and_entity() -> None:
    """safe_parse_xml блокирует XML-пейлоады с DOCTYPE и ENTITY (защита от XXE)."""
    malicious = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<rpc>&xxe;</rpc>"
    )
    with pytest.raises(ExecutionError, match="DOCTYPE and ENTITY"):
        safe_parse_xml(malicious)


def test_netconf_vendor_adapter_profiles() -> None:
    """NetconfVendorAdapter определяет семейство сетевой ОС и строит фильтры XPath/Subtree."""
    detected = NetconfVendorAdapter.detect_vendor(
        ["http://xml.juniper.net/netconf/junos/1.0"]
    )
    assert detected == "junos"
    xpath_xml = NetconfVendorAdapter.build_filter_xml(
        "/interfaces/interface[name='ge-0/0/0']",
        filter_type="xpath",
        supports_xpath=True,
    )
    assert 'type="xpath"' in xpath_xml
    subtree_xml = NetconfVendorAdapter.build_filter_xml(
        "/interfaces/interface[name=eth0]",
        filter_type="subtree",
        supports_xpath=False,
    )
    assert 'type="subtree"' in subtree_xml
    assert "<interfaces><interface><name>eth0</name></interface></interfaces>" in subtree_xml


# ─── 3. Тестирование NETCONF + MockNetconfServer ───────────────────


async def test_netconf_crud_locks_confirmed_commit_and_notifications() -> None:
    """Полный цикл работы NetconfTransport и conn.net против MockNetconfServer."""
    async with (
        MockNetconfServer(
            notifications=[{"link-up": {"interface": "GigabitEthernet0/0/0", "status": "up"}}]
        ) as server,
        Connection.from_uri(server.uri) as conn,
    ):
        caps_res = await conn.net.capabilities()
        assert caps_res.ok
        assert any(
            "urn:ietf:params:netconf:base:1.1" in c
            for c in caps_res.data["capabilities"]
        )

        # Чтение конфигурации и состояния
        res_get = await conn.net.get("/system")
        assert res_get.ok
        assert res_get.protocol == "netconf"
        assert res_get.data["system"]["hostname"] == "mock-edge-rtr-01"

        # Транзакционное изменение через candidate datastore
        async with conn.net.transaction(datastore="candidate"):
            edit_res = await conn.net.edit(
                {"system": {"hostname": "core-sw-01"}},
                datastore="candidate",
            )
            assert edit_res.ok
            val_res = await conn.net.validate(source="candidate")
            assert val_res.ok

        # После выхода из transaction изменения закоммичены в running
        after_commit = await conn.net.get_config("running", "/system")
        assert after_commit.data["system"]["hostname"] == "core-sw-01"

        # Проверка отката transaction при исключении
        with pytest.raises(RuntimeError, match="abort change"):
            async with conn.net.transaction(datastore="candidate"):
                await conn.net.edit(
                    {"system": {"hostname": "bad-hostname"}},
                    datastore="candidate",
                )
                raise RuntimeError("abort change")

        still_valid = await conn.net.get_config("running", "/system")
        assert still_valid.data["system"]["hostname"] == "core-sw-01"

        # Проверка confirmed-commit с автоматическим откатом по таймеру
        await conn.net.edit(
            {"system": {"hostname": "temp-hostname"}},
            datastore="candidate",
        )
        cc_res = await conn.net.commit(confirmed=True, confirm_timeout=1)
        assert cc_res.ok
        during_cc = await conn.net.get_config("running", "/system")
        assert during_cc.data["system"]["hostname"] == "temp-hostname"

        # Ждём истечения confirm_timeout (1s)
        await asyncio.sleep(1.15)
        rolled_back = await conn.net.get_config("running", "/system")
        assert rolled_back.data["system"]["hostname"] == "core-sw-01"

        # Проверка блокировки (lock contention между двумя сессиями)
        async with Connection.from_uri(server.uri) as conn2:
            async with conn.net.locked("candidate"):
                lock_denied = await conn2.net.lock("candidate")
                assert not lock_denied.ok
                assert any(
                    err.get("error-tag") == "lock-denied" for err in lock_denied.errors
                )

            # После выхода из locked() второй клиент может взять блокировку
            lock_ok = await conn2.net.lock("candidate")
            assert lock_ok.ok
            await conn2.net.unlock("candidate")

        # Подписка на NETCONF notifications
        samples: list[TelemetrySample] = []
        async for sample in conn.net.subscribe(["NETCONF"], once=True):
            samples.append(sample)
        assert len(samples) == 1
        assert samples[0].protocol == "netconf"
        assert (
            samples[0].values["event"]["link-up"]["interface"]
            == "GigabitEthernet0/0/0"
        )

        # Эмуляция conn.run() для совместимости с CommandPipeline
        cli_res = await conn.run("get /system")
        assert cli_res.ok
        assert "core-sw-01" in cli_res.stdout


def test_sync_netconf_connection_and_mock_server() -> None:
    """Синхронные обёртки SyncMockNetconfServer и SyncConnection.net работают прозрачно."""
    with (
        SyncMockNetconfServer() as server,
        Connection.from_uri(server.uri).to_sync() as conn,
    ):
        res = conn.net.get("/system")
        assert res.ok
        assert res.data["system"]["hostname"] == "mock-edge-rtr-01"

        with conn.net.locked("running"):
            conn.net.edit({"system": {"hostname": "sync-router"}}, datastore="running")

        updated = conn.net.get_config("running", "/system")
        assert updated.data["system"]["hostname"] == "sync-router"


# ─── 4. Тестирование RESTCONF + MockRestconfServer ─────────────────


async def test_restconf_discovery_crud_yang_patch_and_xml() -> None:
    """RestconfTransport поддерживает /.well-known/host-meta, JSON/XML и RFC 8072 YANG-Patch."""
    async with MockRestconfServer() as server:
        # Авто-дискавери root=auto через /.well-known/host-meta
        uri_auto = f"restconf://admin:secret@{server.host}:{server.port}?scheme=http&root=auto"
        async with Connection.from_uri(uri_auto) as conn:
            caps = await conn.net.capabilities()
            assert caps.ok
            assert "ietf-yang-library:modules-state" in caps.data

            # GET JSON
            res = await conn.net.get("/system")
            assert res.ok
            assert res.data["hostname"] == "mock-edge-rtr-01"

            # EDIT merge
            edit_res = await conn.net.edit(
                {"hostname": "restconf-edge-01"},
                path="/system",
                operation="merge",
            )
            assert edit_res.ok

            # RFC 8072 YANG-Patch (пакет правок)
            patch_res = await conn.net.edit(
                {
                    "ietf-yang-patch:yang-patch": {
                        "patch-id": "patch-1",
                        "edit": [
                            {
                                "edit-id": "edit-1",
                                "operation": "merge",
                                "target": "/system",
                                "value": {"domain-name": "corp.local"},
                            }
                        ],
                    }
                },
                operation="merge",
            )
            assert patch_res.ok

            verify_res = await conn.net.get("/system")
            assert verify_res.data["hostname"] == "restconf-edge-01"
            assert verify_res.data["domain-name"] == "corp.local"

            # Вызов RPC /operations/reboot
            rpc_res = await conn.net.rpc({"input": {"delay": 5}}, path="reboot")
            assert rpc_res.ok
            assert rpc_res.data["ietf-restconf:output"]["result"] == "ok"

        # Проверка XML-формата RESTCONF
        uri_xml = f"{server.uri}&format=xml"
        async with Connection.from_uri(uri_xml) as conn_xml:
            xml_res = await conn_xml.net.get("/system")
            assert xml_res.ok
            assert xml_res.data["hostname"] == "restconf-edge-01"

        # Проверка ошибки аутентификации 401
        bad_uri = f"restconf://admin:wrong@{server.host}:{server.port}/restconf?scheme=http"
        async with Connection.from_uri(bad_uri) as bad_conn:
            with pytest.raises(AuthenticationError):
                await bad_conn.net.get("/system")


def test_sync_restconf_server() -> None:
    """SyncMockRestconfServer работает с SyncConnection.net."""
    with (
        SyncMockRestconfServer() as server,
        Connection.from_uri(server.uri).to_sync() as conn,
    ):
        res = conn.net.get("/interfaces")
        assert res.ok
        assert "interface" in res.data


# ─── 5. Тестирование gNMI + MockGnmiServer + GnmiWireCodec ─────────


def test_gnmi_path_and_wire_codec_roundtrip() -> None:
    """Парсер путей gNMI и встроенный Protobuf-кодек GnmiWireCodec сериализуют сообщения без потерь."""
    path_str = "/interfaces/interface[name=eth0/0][subindex=1]/state/counters"
    parsed = parse_gnmi_path(path_str, origin="openconfig")
    assert parsed.origin == "openconfig"
    assert len(parsed.elem) == 4
    assert parsed.elem[1].name == "interface"
    assert parsed.elem[1].key == {"name": "eth0/0", "subindex": "1"}
    assert format_gnmi_path(parsed) == f"openconfig:{path_str}"

    get_bytes = GnmiWireCodec.encode_get_request([path_str], data_type="config")
    decoded_get = GnmiWireCodec.decode_get_request(get_bytes)
    assert decoded_get["data_type"] == "config"
    assert decoded_get["paths"] == [path_str]


async def test_gnmi_capabilities_get_set_and_streaming_subscribe() -> None:
    """GnmiTransport выполняет Capabilities, Get, Set и потоковую телеметрию Subscribe."""
    async with MockGnmiServer() as server, Connection.from_uri(server.uri) as conn:
        caps = await conn.net.capabilities()
        assert caps.ok
        assert caps.data["gnmi_version"] == "0.10.0"
        assert any(
            m["name"] == "openconfig-interfaces"
            for m in caps.data["supported_models"]
        )

        # Get
        res = await conn.net.get("/system")
        assert res.ok
        assert res.protocol == "gnmi"
        assert res.data["config"]["hostname"] == "spine-switch-01"

        # Set (update / replace / delete)
        edit_res = await conn.net.edit(
            {"config": {"hostname": "gnmi-spine-01", "banner": "welcome"}},
            path="/system",
            operation="merge",
        )
        assert edit_res.ok

        verify = await conn.net.get("/system")
        assert verify.data["config"]["hostname"] == "gnmi-spine-01"

        # Потоковая телеметрия Subscribe (SAMPLE)
        samples: list[TelemetrySample] = []
        async for sample in conn.net.subscribe(
            ["/interfaces/interface[name=Ethernet1/1]/state/counters"],
            mode="sample",
            sample_interval=0.01,
        ):
            samples.append(sample)
            if len(samples) >= 2:
                break

        assert len(samples) >= 2
        assert samples[0].protocol == "gnmi"
        assert samples[0].sync_response is True
        assert samples[0].values["in-octets"] == 1048576
        assert samples[1].values["in-octets"] == 1048576 + 1024


def test_sync_gnmi_server_and_subscribe() -> None:
    """SyncMockGnmiServer и SyncConnection.net.subscribe работают синхронно."""
    with (
        SyncMockGnmiServer() as server,
        Connection.from_uri(server.uri).to_sync() as conn,
    ):
        res = conn.net.get("/system")
        assert res.ok
        for sample in conn.net.subscribe(["/system"], once=True):
            assert sample.protocol == "gnmi"
            break


# ─── 6. Идемпотентный провижининг YANG (ensure_yang) и HostFacts ───


async def test_ensure_yang_idempotency_dry_run_and_gather_facts() -> None:
    """conn.state.ensure_yang обеспечивает идемпотентность, dry_run diff и сбор фактов."""
    async with MockRestconfServer() as server:
        async with Connection.from_uri(server.uri) as conn:
            # 1. Dry-run: вычисляет diff, но не меняет состояние на устройстве
            async with Connection.from_uri(server.uri, dry_run=True) as dry_conn:
                dry_res = await dry_conn.state.ensure_yang(
                    "/system",
                    {"hostname": "intended-router"},
                )
                assert dry_res.ok
                assert dry_res.changed is True
                assert "intended-router" in dry_res.diff

            unchanged = await conn.net.get("/system")
            assert unchanged.data["hostname"] == "mock-edge-rtr-01"

            # 2. Первое реальное применение -> changed=True
            res1 = await conn.state.ensure_yang(
                "/system",
                {"hostname": "intended-router"},
            )
            assert res1.ok
            assert res1.changed is True
            assert "intended-router" in res1.diff

            # 3. Повторное применение того же дерева -> changed=False (идемпотентно)
            res2 = await conn.state.ensure_yang(
                "/system",
                {"hostname": "intended-router"},
            )
            assert res2.ok
            assert res2.changed is False
            assert not res2.diff

            # 4. Сбор фактов gather_facts() через структурированное дерево YANG
            facts = await conn.gather_facts(refresh=True)
            assert facts.os_family == "NetworkOS"
            assert facts.hostname == "intended-router"
            assert len(facts.interfaces) >= 1
            assert facts.interfaces[0].name == "GigabitEthernet0/0/0"


# ─── 7. Групповые операции пула (ConnectionPool.net) и Кассеты ─────


async def test_connection_pool_net_and_cassette_replay(tmp_path: Path) -> None:
    """ConnectionPool.net выполняет групповые сетевые операции, а use_cassette записывает и воспроизводит их."""
    async with MockRestconfServer() as srv1, MockRestconfServer() as srv2:
        async with ConnectionPool([srv1.uri, srv2.uri], batch_size=1) as pool:
            get_map = await pool.net.get("/system")
            assert len(get_map) == 2
            assert all(isinstance(v, NetResult) and v.ok for v in get_map.values())

            ensure_map = await pool.state.ensure_yang(
                "/system",
                {"hostname": "fleet-node"},
            )
            assert all(r.ok and r.changed for r in ensure_map.values())

        # Запись кассеты VCR для сетевых операций
        cassette_file = tmp_path / "net_ops.yaml"
        async with (
            Connection.from_uri(srv1.uri) as conn,
            conn.use_cassette(cassette_file, mode="all"),
        ):
            rec_res = await conn.net.get("/system")
            assert rec_res.ok
            assert rec_res.data["hostname"] == "fleet-node"

    # Серверы остановлены! Проверяем оффлайн-воспроизведение из кассеты (mode="none")
    offline_conn = Connection.from_uri(
        "restconf://admin:secret@127.0.0.1:65530/restconf?scheme=http"
    )
    async with offline_conn.use_cassette(cassette_file, mode="none"):
        replay_res = await offline_conn.net.get("/system")
        assert replay_res.ok
        assert replay_res.data["hostname"] == "fleet-node"


# ─── 8. Регрессионные тесты по итогам Code Review ──────────────────


def test_net_result_binary_raw_roundtrip_and_restconf_uri_build() -> None:
    """NetResult сохраняет бинарный Protobuf raw без потерь, а URIParser.build восстанавливает root."""
    binary_payload = b"\x00\x00\x00\x00\x05\x08\x96\x01\xff\xfe\xfd"
    original = NetResult(
        ok=True,
        data={"gnmi": True},
        text='{"gnmi": true}',
        raw=binary_payload,
        operation="get",
        datastore="running",
        protocol="gnmi",
        host="10.0.0.1",
    )
    restored = NetResult.from_dict(original.to_dict())
    assert restored.raw == binary_payload
    assert restored.data == {"gnmi": True}
    assert restored.protocol == "gnmi"

    # Проверка URIParser.build для restconf:// с кастомным root
    cfg = URIParser.parse("restconf://admin:secret@10.0.0.1:8443/restconf/v2?verify_tls=false")
    assert cfg.options["root"] == "/restconf/v2"
    built_uri = URIParser.build(
        cfg.transport,
        host=cfg.host,
        port=cfg.port,
        username=cfg.username,
        options=cfg.options,
    )
    assert "/restconf/v2" in built_uri
    reparsed = URIParser.parse(built_uri)
    assert reparsed.options["root"] == "/restconf/v2"
    assert reparsed.options["verify_tls"] is False


async def test_netconf_subtree_fallback_and_ensure_yang_state_absent() -> None:
    """NETCONF корректно переключается на subtree-фильтр без :xpath:1.0 и удаляет вложенные узлы."""
    caps_no_xpath = [
        "urn:ietf:params:netconf:base:1.0",
        "urn:ietf:params:netconf:base:1.1",
        "urn:ietf:params:netconf:capability:candidate:1.0",
    ]
    async with (
        MockNetconfServer(capabilities=caps_no_xpath) as server,
        Connection.from_uri(server.uri) as conn,
    ):
        # Автоматический выбор subtree-фильтр с предикатом ключа
        lo_res = await conn.net.get("/interfaces/interface[name=Loopback0]")
        assert lo_res.ok
        assert lo_res.data["interfaces"]["interface"]["ipv4"]["address"]["ip"] == "10.255.255.1"

        # Идемпотентное удаление вложенного узла через ensure_yang(state="absent")
        del_res = await conn.state.ensure_yang(
            "/system/platform",
            state="absent",
            datastore="running",
        )
        assert del_res.ok
        assert del_res.changed is True

        # Повторное удаление того же узла -> changed=False
        del_again = await conn.state.ensure_yang(
            "/system/platform",
            state="absent",
            datastore="running",
        )
        assert del_again.ok
        assert del_again.changed is False


async def test_restconf_yang_patch_list_and_gnmi_multipath_edit() -> None:
    """RESTCONF поддерживает список правок YANG-Patch, а gNMI — мульти-путевой словарь и ошибки Get."""
    async with MockRestconfServer() as rc_srv, Connection.from_uri(rc_srv.uri) as rc_conn:
        patch_res = await rc_conn.net.edit(
            [
                {
                    "edit-id": "e1",
                    "operation": "merge",
                    "target": "/hostname",
                    "value": "patched-rtr",
                },
                {
                    "edit-id": "e2",
                    "operation": "merge",
                    "target": "/domain-name",
                    "value": "corp.local",
                },
            ],
            path="/system",
            operation="patch",
        )
        assert patch_res.ok
        sys_res = await rc_conn.net.get("/system")
        assert sys_res.data["hostname"] == "patched-rtr"
        assert sys_res.data["domain-name"] == "corp.local"

    async with MockGnmiServer() as gnmi_srv, Connection.from_uri(gnmi_srv.uri) as gnmi_conn:
        multi_res = await gnmi_conn.net.edit(
            {
                "/system/config": {"hostname": "multi-gnmi-rtr"},
                "/bgp/global": {"as": 65100},
            },
            operation="merge",
        )
        assert multi_res.ok
        bgp_res = await gnmi_conn.net.get_config(path="/bgp/global")
        assert bgp_res.ok
        assert bgp_res.data["as"] == 65100

        # Запрос несуществующего пути в get_config возвращает NetResult(ok=False) вместо необработанного исключения
        missing_res = await gnmi_conn.net.get_config(path="/non-existent-subtree")
        assert missing_res.ok is False
        assert missing_res.errors

