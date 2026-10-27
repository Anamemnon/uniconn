"""Unit tests for v0.8.0 features: HostFacts, ensure_*, pool.stream(), SyncConnectionPool, CLI & Dashboard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from examples.dashboard.server import _execute_pool_sandbox, _execute_v080_sandbox
from uniconn import (
    Connection,
    ConnectionPool,
    DiskInfo,
    EnsureResult,
    FactCollector,
    FactSpec,
    FileSourceSpec,
    HostFacts,
    NetworkInterface,
    Result,
    SyncConnectionPool,
    cli,
)
from uniconn._facts import parse_facts_output

SAMPLE_UBUNTU_FACTS_RAW = """\
===UNICONN_SECTION:UNAME===
Linux 6.8.0-45-generic x86_64 web-prod-01
===UNICONN_SECTION:HOSTNAME===
web-prod-01.eu.internal
===UNICONN_SECTION:OS_RELEASE===
NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
===UNICONN_SECTION:UPTIME===
123456.78 987654.32
===UNICONN_SECTION:CPU===
8
===UNICONN_SECTION:MEMINFO===
MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:   12288000 kB
Buffers:          512000 kB
Cached:          4096000 kB
===UNICONN_SECTION:DISKS===
Filesystem     Type     1024-blocks     Used Available Capacity Mounted on
/dev/sda1      ext4       104857600 41943040  62914560      40% /
tmpfs          tmpfs        8192000        0   8192000       0% /dev/shm
/dev/sdb1      xfs        209715200 52428800 157286400      25% /data
===UNICONN_SECTION:NET_JSON===
[
  {
    "ifname": "lo",
    "link_type": "loopback",
    "operstate": "UNKNOWN",
    "mtu": 65536,
    "addr_info": [
      {"family": "inet", "local": "127.0.0.1"},
      {"family": "inet6", "local": "::1"}
    ]
  },
  {
    "ifname": "eth0",
    "address": "52:54:00:12:34:56",
    "operstate": "UP",
    "mtu": 1500,
    "addr_info": [
      {"family": "inet", "local": "10.10.0.15"},
      {"family": "inet6", "local": "fe80::5054:ff:fe12:3456"}
    ]
  }
]
===UNICONN_SECTION:NET_TEXT===
===UNICONN_SECTION:END===
"""

SAMPLE_ALPINE_FACTS_RAW = """\
===UNICONN_SECTION:UNAME===
Linux 6.6.30-0-virt aarch64 edge-alpine
===UNICONN_SECTION:HOSTNAME===
edge-alpine
===UNICONN_SECTION:OS_RELEASE===
NAME="Alpine Linux"
ID=alpine
PRETTY_NAME="Alpine Linux v3.20"
===UNICONN_SECTION:UPTIME===
3600.5 7000.0
===UNICONN_SECTION:CPU===
4
===UNICONN_SECTION:MEMINFO===
              total        used        free      shared  buff/cache   available
Mem:     4294967296  1073741824  2147483648           0  1073741824  3221225472
===UNICONN_SECTION:DISKS===
Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/vda1             20971520   5242880  15728640  25% /
===UNICONN_SECTION:NET_JSON===
===UNICONN_SECTION:NET_TEXT===
1: lo:    inet 127.0.0.1/8 scope host lo
2: eth0:  inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
2: eth0:  inet6 fd00::50/64 scope global
===UNICONN_SECTION:END===
"""


class TestHostFactsParsingAndCollection:
    """Тесты парсинга и сбора HostFacts (v0.8.0 2.1)."""

    def test_parse_ubuntu_facts_full(self) -> None:
        facts = parse_facts_output(SAMPLE_UBUNTU_FACTS_RAW)
        assert isinstance(facts, HostFacts)
        assert facts.os_family == "Debian"
        assert facts.distro == "Ubuntu 24.04.1 LTS"
        assert facts.kernel == "6.8.0-45-generic"
        assert facts.arch == "x86_64"
        assert facts.hostname == "web-prod-01.eu.internal"
        assert facts.uptime_seconds == pytest.approx(123456.78)
        assert facts.cpu_count == 8
        assert facts.memory_total_bytes == 16384000 * 1024
        assert facts.memory_available_bytes == 12288000 * 1024

        # tmpfs отфильтрован, остались / и /data
        assert len(facts.disks) == 2
        assert isinstance(facts.disks[0], DiskInfo)
        assert facts.disks[0].device == "/dev/sda1"
        assert facts.disks[0].mountpoint == "/"
        assert facts.disks[0].fstype == "ext4"
        assert facts.disks[0].use_percent == 40.0

        assert len(facts.interfaces) == 2
        assert isinstance(facts.interfaces[1], NetworkInterface)
        assert facts.interfaces[1].name == "eth0"
        assert facts.interfaces[1].mac == "52:54:00:12:34:56"
        assert facts.interfaces[1].ipv4 == ["10.10.0.15"]
        assert facts.interfaces[1].state == "UP"
        assert facts.interfaces[1].mtu == 1500
        assert facts.to_dict()["hostname"] == "web-prod-01.eu.internal"

    def test_parse_alpine_facts_fallbacks(self) -> None:
        facts = parse_facts_output(SAMPLE_ALPINE_FACTS_RAW)
        assert facts.os_family == "Alpine"
        assert facts.distro == "Alpine Linux v3.20"
        assert facts.arch == "aarch64"
        assert facts.cpu_count == 4
        assert facts.memory_total_bytes == 4294967296
        assert facts.memory_available_bytes == 3221225472
        assert len(facts.disks) == 1
        assert facts.disks[0].mountpoint == "/"
        assert len(facts.interfaces) == 2
        eth0 = next(i for i in facts.interfaces if i.name == "eth0")
        assert eth0.ipv4 == ["192.168.1.50"]
        assert eth0.ipv6 == ["fd00::50"]

    @pytest.mark.asyncio
    async def test_connection_gather_facts_local_and_cache(self) -> None:
        async with Connection.from_uri("local://") as conn:
            facts1 = await conn.gather_facts()
            assert isinstance(facts1, HostFacts)
            assert facts1.cpu_count >= 1
            assert facts1.memory_total_bytes > 0
            assert facts1.kernel != "Unknown"

            # Повторный вызов возвращает закэшированный объект без нового запроса
            facts2 = await conn.gather_facts(refresh=False)
            assert facts2 is facts1

            # С refresh=True пересобирает факты
            facts3 = await conn.gather_facts(refresh=True)
            assert facts3.hostname == facts1.hostname

    @pytest.mark.asyncio
    async def test_connection_gather_facts_dry_run(self) -> None:
        async with Connection.from_uri("local://?host=dry-node", dry_run=True) as conn:
            facts = await conn.gather_facts()
            assert facts.os_family == "Unknown"

    @pytest.mark.asyncio
    async def test_fact_collector_spec_files_native_read(self, tmp_path: Path) -> None:
        """FactCollector считывает файлы из spec.files нативно через conn.read_file без shell head."""
        sample_file = tmp_path / "app_version.txt"
        sample_file.write_text("v2.5.1-custom\n", encoding="utf-8")

        json_file = tmp_path / "metadata.json"
        json_file.write_text('{"env": "production", "tier": 1}\n', encoding="utf-8")

        async with Connection.from_uri("local://") as conn:
            spec = FactSpec(
                files=[
                    FileSourceSpec(name="version", path=str(sample_file), max_bytes=6),
                    FileSourceSpec(name="meta", path=str(json_file), parse_json=True),
                ]
            )
            collector = FactCollector(conn)
            facts = HostFacts(hostname="test-host")
            await collector._collect_spec_sources(facts, spec, default_timeout=5.0)

            assert facts.custom["version"] == "v2.5.1"
            assert facts.custom["meta"] == {"env": "production", "tier": 1}


class TestIdempotentEnsureMethods:
    """Тесты идемпотентных проверок ensure_line, ensure_package, ensure_service."""

    @pytest.mark.asyncio
    async def test_ensure_line_lifecycle(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "app.conf"
        async with Connection.from_uri("local://") as conn:
            # 1. Создание файла с нуля
            res1 = await conn.ensure_line(cfg_file, "listen_port = 8080")
            assert isinstance(res1, EnsureResult)
            assert res1.ok is True
            assert res1.changed is True
            assert cfg_file.read_text(encoding="utf-8") == "listen_port = 8080\n"

            # 2. Повторный вызов — идемпотентно (changed=False)
            res2 = await conn.ensure_line(cfg_file, "listen_port = 8080")
            assert res2.changed is False

            # 3. Замена по регулярному выражению с созданием .bak
            res3 = await conn.ensure_line(
                cfg_file,
                "listen_port = 9090",
                regex=r"^listen_port\s*=",
                backup=True,
            )
            assert res3.changed is True
            assert cfg_file.read_text(encoding="utf-8") == "listen_port = 9090\n"
            assert (tmp_path / "app.conf.bak").read_text(encoding="utf-8") == "listen_port = 8080\n"

            # 4. Удаление строки (state="absent")
            res4 = await conn.ensure_line(cfg_file, "listen_port = 9090", state="absent")
            assert res4.changed is True
            assert cfg_file.read_text(encoding="utf-8") == ""

            # 5. Повторное удаление — changed=False
            res5 = await conn.ensure_line(cfg_file, "listen_port = 9090", state="absent")
            assert res5.changed is False
            assert res5.to_dict()["state"] == "absent"

    @pytest.mark.asyncio
    async def test_ensure_package_mocked_managers(self) -> None:
        async with Connection.from_uri("local://") as conn:
            run_mock = AsyncMock(
                side_effect=[
                    # 1-й вызов: проверка dpkg-query -> пакет отсутствует (exit_code=1)
                    Result(exit_code=1, stdout="", stderr="", duration=0.01, command="dpkg-query"),
                    # 2-й вызов: apt-get install -> успех (exit_code=0)
                    Result(exit_code=0, stdout="installed", stderr="", duration=0.1, command="apt-get"),
                    # 3-й вызов: повторная проверка -> уже установлен (exit_code=0)
                    Result(exit_code=0, stdout="install ok installed", stderr="", duration=0.01, command="dpkg-query"),
                ]
            )
            conn.run = run_mock  # type: ignore[method-assign]

            res_install = await conn.ensure_package("htop", state="present", manager="apt", update_cache=True)
            assert res_install.ok is True
            assert res_install.changed is True
            assert "apt" in res_install.details

            res_noop = await conn.ensure_package("htop", state="present", manager="apt")
            assert res_noop.ok is True
            assert res_noop.changed is False

    @pytest.mark.asyncio
    async def test_ensure_service_mocked(self) -> None:
        async with Connection.from_uri("local://") as conn:
            run_mock = AsyncMock(
                side_effect=[
                    # 1. is-active -> 3 (не активен)
                    Result(exit_code=3, stdout="", stderr="", duration=0.01, command="systemctl is-active"),
                    # 2. is-enabled -> 1 (не включён)
                    Result(exit_code=1, stdout="", stderr="", duration=0.01, command="systemctl is-enabled"),
                    # 3. start && enable -> 0
                    Result(exit_code=0, stdout="", stderr="", duration=0.05, command="systemctl start"),
                ]
            )
            conn.run = run_mock  # type: ignore[method-assign]

            res = await conn.ensure_service("nginx", state="started", enabled=True)
            assert res.ok is True
            assert res.changed is True
            assert "start" in res.details
            assert "enable" in res.details


class TestConnectionPoolStreamAndSyncPool:
    """Тесты мульти-стриминга pool.stream() (v0.8.0 2.2) и SyncConnectionPool (v0.8.0 2.3)."""

    @pytest.mark.asyncio
    async def test_pool_stream_multiplexes_all_hosts(self) -> None:
        c1 = Connection.from_uri("local://").with_overrides(host="node-alpha")
        c2 = Connection.from_uri("local://").with_overrides(host="node-beta")
        pool = ConnectionPool([c1, c2], max_concurrent=2)

        received: list[tuple[str, str]] = []
        async with pool:
            async for host, line in pool.stream("printf 'first\\nsecond\\n'"):
                received.append((host, line.strip()))

        hosts_seen = {h for h, _ in received}
        assert hosts_seen == {"node-alpha", "node-beta"}
        assert len(received) == 4

    @pytest.mark.asyncio
    async def test_pool_stream_early_break_cancels_cleanly(self) -> None:
        c1 = Connection.from_uri("local://").with_overrides(host="node-1")
        c2 = Connection.from_uri("local://").with_overrides(host="node-2")
        pool = ConnectionPool([c1, c2])

        collected: list[tuple[str, str]] = []
        async for host, line in pool.stream("python3 -c 'import time; print(\"tick\", flush=True); time.sleep(5)'"):
            collected.append((host, line.strip()))
            if len(collected) >= 1:
                break

        assert len(collected) == 1
        assert collected[0][1] == "tick"

    def test_sync_connection_pool_full_workflow(self, tmp_path: Path) -> None:
        c1 = Connection.from_uri("local://").with_overrides(host="sync-node-1")
        c2 = Connection.from_uri("local://").with_overrides(host="sync-node-2")
        pool = ConnectionPool([c1, c2], max_concurrent=2)

        target_file = tmp_path / "sync_pool_line.conf"
        with pool.to_sync() as sync_pool:
            assert isinstance(sync_pool, SyncConnectionPool)
            results = sync_pool.map("echo hello-sync-pool")
            assert len(results) == 2
            assert all(r.text == "hello-sync-pool" for r in results)

            safe_map = sync_pool.map_safe("echo safe-ok")
            assert len(safe_map) == 2

            facts_map = sync_pool.gather_facts()
            assert set(facts_map.keys()) == {"sync-node-1", "sync-node-2"}
            assert facts_map["sync-node-1"].cpu_count >= 1

            ens_map = sync_pool.ensure_line(target_file, "ENABLE_METRICS=1")
            assert len(ens_map) == 2
            assert target_file.read_text(encoding="utf-8") == "ENABLE_METRICS=1\n"

            streamed = list(sync_pool.stream("printf 's1\\ns2\\n'"))
            assert len(streamed) == 4


class TestCliAndDashboardV080:
    """Тесты CLI-команд `uniconn facts` / `uniconn tail` и Dashboard `/api/v080`."""

    def test_cli_facts_and_tail_commands(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr("sys.argv", ["uniconn", "facts", "local://", "--format", "json"])
        with pytest.raises(SystemExit) as exc_facts:
            cli.main()
        assert exc_facts.value.code == 0
        out_facts = capsys.readouterr().out
        assert "os_family" in out_facts

        monkeypatch.setattr("sys.argv", ["uniconn", "facts", "local://", "--format", "table"])
        with pytest.raises(SystemExit) as exc_tbl:
            cli.main()
        assert exc_tbl.value.code == 0
        out_tbl = capsys.readouterr().out
        assert "Host Facts" in out_tbl

        log_file = tmp_path / "access.log"
        log_file.write_text("GET /health 200\nPOST /api/v080 200\n", encoding="utf-8")
        monkeypatch.setattr(
            "sys.argv",
            ["uniconn", "tail", str(log_file), "local://", "-n", "2", "--format", "json"],
        )
        with pytest.raises(SystemExit) as exc_tail:
            cli.main()
        assert exc_tail.value.code == 0
        out_tail = capsys.readouterr().out
        assert "POST /api/v080 200" in out_tail

    def test_dashboard_v080_and_pool_endpoints(self) -> None:
        facts_resp = _execute_v080_sandbox({"feature": "gather_facts"})
        assert facts_resp["status"] == "ok"
        assert "os_family" in facts_resp["facts"]

        line_resp = _execute_v080_sandbox({"feature": "ensure_line"})
        assert line_resp["status"] == "ok"
        assert line_resp["pass1"]["changed"] is True
        assert line_resp["pass2"]["changed"] is False

        pkg_resp = _execute_v080_sandbox({"feature": "ensure_package", "package": "curl"})
        assert pkg_resp["status"] == "ok"
        assert pkg_resp["result"]["dry_run"] is True

        svc_resp = _execute_v080_sandbox({"feature": "ensure_service", "service": "nginx"})
        assert svc_resp["status"] == "ok"
        assert svc_resp["result"]["dry_run"] is True

        stream_resp = _execute_v080_sandbox({"feature": "pool_stream"})
        assert stream_resp["status"] == "ok"
        assert len(stream_resp["lines"]) == 4

        sync_pool_resp = _execute_v080_sandbox({"feature": "sync_pool"})
        assert sync_pool_resp["status"] == "ok"
        assert sync_pool_resp["hosts_count"] == 2

        pool_facts = _execute_pool_sandbox({"operation": "gather_facts", "group": "web"})
        assert pool_facts["status"] == "ok"
        assert len(pool_facts["nodes"]) == 2
