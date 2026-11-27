"""Сетевая автоматизация на базе YANG-моделей: NETCONF, RESTCONF (SSE) и gNMI (HTTP/2 gRPC).

Демонстрирует:
- Единый сервис ``conn.net`` (``capabilities``, ``get``, ``edit``, ``transaction``, ``subscribe``)
- Идемпотентную конфигурацию YANG через ``conn.state.ensure_yang`` с unified diff
- Настоящий HTTP/2 gRPC мультиплексированный клиент ``gnmi://`` (``jh2``)
- Транзакции ``candidate`` и потоковые уведомления SSE в ``restconf://``
- Самодостаточный локальный запуск против ``MockNetconfServer``, ``MockRestconfServer`` и ``MockGnmiServer``
"""

from __future__ import annotations

import asyncio

from uniconn import Connection
from uniconn.mock import MockGnmiServer, MockNetconfServer, MockRestconfServer


async def main() -> None:
    """Локальный прогон NETCONF, RESTCONF и gNMI против встроенных in-process Mock-серверов."""
    print("=== 1. NETCONF (RFC 6241/6242): capabilities, get и ensure_yang ===")
    async with (
        MockNetconfServer() as nc_srv,
        Connection.from_uri(f"{nc_srv.uri}?known_hosts=no") as nc,
    ):
        caps = await nc.net.capabilities()
        print("NETCONF capabilities count:", len(caps.data["capabilities"]))

        ens = await nc.state.ensure_yang(
            "/system",
            data={"hostname": "core-edge-rtr-01"},
            validate=True,
        )
        print(f"ensure_yang changed={ens.changed}, diff=\n{ens.diff}")

    print("\n=== 2. RESTCONF (RFC 8040): транзакция candidate и SSE-стриминг ===")
    async with (
        MockRestconfServer(support_netconf_ops=True, sse_enabled=True) as rc_srv,
        Connection.from_uri(rc_srv.uri) as rc,
    ):
        async with rc.net.transaction(datastore="candidate"):
            await rc.net.edit(
                {"hostname": "edge-gw-01"},
                path="/system",
                datastore="candidate",
                operation="merge",
            )
        system_cfg = await rc.net.get("/system")
        print("RESTCONF committed system:", system_cfg.data)

        sse_samples = []
        async for sample in rc.net.subscribe(["/system"], mode="on_change"):
            sse_samples.append(sample)
            if len(sse_samples) >= 2:
                break
        print(
            f"RESTCONF subscribe samples={len(sse_samples)}, "
            f"mode={sse_samples[0].metadata.get('transport_mode')}"
        )

    print("\n=== 3. gNMI (HTTP/2 gRPC): мультиплексирование Subscribe + Get/Set ===")
    async with (
        MockGnmiServer() as gnmi_srv,
        Connection.from_uri(gnmi_srv.uri) as gnmi,
    ):
        g_caps = await gnmi.net.capabilities()
        print("gNMI supported models:", len(g_caps.data.get("supported_models", [])))

        telemetry_samples = []
        async for sample in gnmi.net.subscribe(
            ["/interfaces/interface[name=Ethernet1/1]/state/counters"],
            mode="sample",
            sample_interval=0.02,
        ):
            telemetry_samples.append(sample)
            if len(telemetry_samples) == 1:
                await gnmi.net.edit(
                    {"config": {"hostname": "spine-01-updated"}},
                    path="/system",
                    operation="merge",
                )
            if len(telemetry_samples) >= 2:
                break

        updated = await gnmi.net.get("/system")
        print(
            f"gNMI samples={len(telemetry_samples)}, updated hostname={updated.data['config']['hostname']}"
        )


if __name__ == "__main__":
    asyncio.run(main())
