# tests/unit/releases/test_v0100_features.py
"""Приёмочные unit-тесты для релиза uniconn v0.10.0.

Покрывают:
- Контрактное тестирование и запись сессий (ReplayTransport, Cassette, use_cassette)
- Сквозную трассировку OpenTelemetry (OtelTracingHook, TracingMiddleware, InMemoryTracer)
- Совместную работу ReplayTransport + OpenTelemetry + gather_facts() без реального хоста
"""

from __future__ import annotations

from pathlib import Path

import pytest

from uniconn import (
    Cassette,
    Connection,
    InMemoryTracer,
    RecordedExecInteraction,
    RecordedFsInteraction,
    otel_tracing_hook,
)
from uniconn._facts import FACT_COLLECTION_SCRIPT


class TestReleaseV0100Integration:
    """Комплексная проверка совместной работы кассет и OpenTelemetry в v0.10.0."""

    @pytest.mark.asyncio
    async def test_gather_facts_over_replay_cassette_with_otel_spans(
        self,
        tmp_path: Path,
    ) -> None:
        """Сбор фактов gather_facts() поверх ReplayTransport создаёт иерархию OpenTelemetry span'ов."""
        cassette_path = tmp_path / "ubuntu_node.yaml"
        Cassette(
            transport="ssh",
            host="edge-node-01",
            capabilities=["exec", "stream", "file", "shell"],
            interactions=[
                RecordedExecInteraction(
                    command=FACT_COLLECTION_SCRIPT,
                    stdout=(
                        "===UNICONN_SECTION:UNAME===\n"
                        "Linux edge-node-01 6.8.0-generic x86_64\n"
                        "===UNICONN_SECTION:HOSTNAME===\n"
                        "edge-node-01\n"
                        "===UNICONN_SECTION:OS_RELEASE===\n"
                        'PRETTY_NAME="Ubuntu 24.04 LTS"\n'
                        "===UNICONN_SECTION:UPTIME===\n"
                        "3600.50 7000.00\n"
                        "===UNICONN_SECTION:CPU===\n"
                        "8\n"
                        "===UNICONN_SECTION:MEMINFO===\n"
                        "MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\n"
                        "===UNICONN_SECTION:DISKS===\n"
                        "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
                        "/dev/sda1 ext4 100000 20000 80000 20% /\n"
                        "===UNICONN_SECTION:NET_JSON===\n"
                        '[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"local":"10.0.0.10"}]}]\n'
                        "===UNICONN_SECTION:NET_TEXT===\n"
                        "===UNICONN_SECTION:END===\n"
                    ),
                ),
                RecordedExecInteraction(
                    command="head -c 65536 /etc/hostname 2>/dev/null || true",
                    stdout="edge-node-01\n",
                ),
                RecordedFsInteraction(
                    operation="read_file",
                    path="/etc/hostname",
                    content_utf8="edge-node-01\n",
                ),
            ],
        ).save(cassette_path)

        tracer = InMemoryTracer(service_name="edge-inspector")
        conn = Connection.from_uri(f"replay://edge-node-01?cassette={cassette_path}")
        otel_tracing_hook(tracer=tracer, service_name="edge-inspector").attach(conn)

        with tracer.start_as_current_span("inspect_edge_node"):
            facts = await conn.gather_facts(
                spec={"files": {"etc_hostname": "/etc/hostname"}},
            )
            raw_hostname = await conn.read_file("/etc/hostname")

        assert facts.hostname == "edge-node-01"
        assert facts.distro == "Ubuntu 24.04 LTS"
        assert facts.cpu_count == 8
        assert facts.custom["etc_hostname"] == "edge-node-01"
        assert raw_hostname.strip() == "edge-node-01"

        span_names = [s.name for s in tracer.spans]
        assert "inspect_edge_node" in span_names
        assert "uniconn.run" in span_names
        assert "uniconn.read_file" in span_names
        for child in tracer.spans:
            if child.name in ("uniconn.run", "uniconn.read_file"):
                assert child.parent_name == "inspect_edge_node"
