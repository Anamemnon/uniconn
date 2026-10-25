# tests/unit/screen/test_diagnostic_session.py
"""Тесты расширенного gather_facts (FactSpec, ExternalToolRunner), LogPipeline и DiagnosticSession."""

from __future__ import annotations

import asyncio
import json
import tarfile
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

from uniconn import (
    ArchiveHandler,
    Connection,
    CustomCommandSpec,
    DiagnosticConfig,
    DirectStreamCollector,
    ExternalToolSpec,
    FactSpec,
    FileSourceSpec,
    ForwardHandler,
    LocalFileHandler,
    LogPipeline,
    PingResult,
    Result,
    StreamSourceSpec,
    diff_facts,
)

SAMPLE_FACTS_STDOUT = """===UNICONN_SECTION:UNAME===
Linux 6.8.0-generic x86_64 node-01
===UNICONN_SECTION:HOSTNAME===
node-01
===UNICONN_SECTION:OS_RELEASE===
ID=ubuntu
PRETTY_NAME="Ubuntu 24.04 LTS"
===UNICONN_SECTION:UPTIME===
1234.56 4000.00
===UNICONN_SECTION:CPU===
8
===UNICONN_SECTION:MEMINFO===
MemTotal:       16384000 kB
MemAvailable:   12288000 kB
===UNICONN_SECTION:DISKS===
Filesystem     Type  1024-blocks    Used Available Capacity Mounted on
/dev/sda1      ext4     50000000 10000000  40000000      20% /
===UNICONN_SECTION:NET_JSON===
[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:01","operstate":"UP","mtu":1500,"addr_info":[{"family":"inet","local":"10.0.0.10"}]}]
===UNICONN_SECTION:NET_TEXT===
===UNICONN_SECTION:END===
"""


def _ok_res(stdout: str = "", command: str = "cmd", exit_code: int = 0) -> Result:
    return Result(
        exit_code=exit_code,
        stdout=stdout,
        stderr="" if exit_code == 0 else "error",
        duration=0.01,
        command=command,
        host="node-01",
    )


class TestFactSpecAndExternalTools:
    """Тесты декларативной спецификации FactSpec и ExternalToolRunner."""

    def test_fact_spec_from_dict_shorthand_and_files(self, tmp_path: Path) -> None:
        """FactSpec поддерживает краткую запись словарей и загрузку из YAML/JSON/TOML."""
        raw = {
            "include_builtin": True,
            "commands": {
                "kernel_cmdline": "cat /proc/cmdline",
                "cpu_json": {"command": "lscpu -J", "parse_json": True},
            },
            "files": {
                "hostname_file": "/etc/hostname",
            },
            "tools": {
                "lshw": {"command": "lshw -json", "output_mode": "json"},
            },
        }
        spec = FactSpec.from_dict(raw)
        assert spec.include_builtin is True
        assert len(spec.commands) == 2
        assert spec.commands[1].parse_json is True
        assert len(spec.files) == 1
        assert spec.files[0].path == "/etc/hostname"
        assert len(spec.tools) == 1
        assert spec.tools[0].output_mode == "json"
        assert spec.tools[0].resolved_binary() == "lshw"

        json_file = tmp_path / "spec.json"
        json_file.write_text(json.dumps(raw), encoding="utf-8")
        loaded_json = FactSpec.from_file(json_file)
        assert len(loaded_json.commands) == 2

        yaml_file = tmp_path / "spec.yaml"
        yaml_file.write_text(
            "include_builtin: false\ncommands:\n  uptime_raw: uptime\n",
            encoding="utf-8",
        )
        loaded_yaml = FactSpec.from_file(yaml_file)
        assert loaded_yaml.include_builtin is False
        assert loaded_yaml.commands[0].name == "uptime_raw"

        toml_file = tmp_path / "spec.toml"
        toml_file.write_text(
            'include_builtin = true\n[commands]\nwhoami = "id -un"\n',
            encoding="utf-8",
        )
        loaded_toml = FactSpec.from_file(toml_file)
        assert loaded_toml.commands[0].name == "whoami"

    async def test_gather_facts_with_spec_and_external_tools(
        self, tmp_path: Path
    ) -> None:
        """conn.gather_facts(spec=...) собирает команды, файлы и внешние утилиты (json/artifact/missing)."""
        conn = Connection.from_uri("local://")

        async def fake_run(cmd: Any, **kwargs: Any) -> Result:
            cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
            if "===UNICONN_SECTION:UNAME===" in cmd_str:
                return _ok_res(SAMPLE_FACTS_STDOUT, cmd_str)
            if cmd_str == "echo '{\"temp\": 42}'":
                return _ok_res('{"temp": 42}\n', cmd_str)
            if "head -c" in cmd_str and "/proc/cmdline" in cmd_str:
                return _ok_res("BOOT_IMAGE=/vmlinuz quiet\n", cmd_str)
            if "command -v lshw" in cmd_str:
                return _ok_res("", cmd_str, exit_code=0)
            if cmd_str == "lshw -json":
                return _ok_res('[{"id": "core", "product": "ServerBoard"}]', cmd_str)
            if "command -v missing_tool" in cmd_str:
                return _ok_res("", cmd_str, exit_code=1)
            if "command -v sosreport" in cmd_str:
                return _ok_res("", cmd_str, exit_code=0)
            if "sosreport --batch" in cmd_str:
                return _ok_res(
                    "Your sosreport has been generated:\n  /tmp/sosreport-node01.tar.xz\n",
                    cmd_str,
                )
            return _ok_res("", cmd_str)

        async def fake_download(remote_path: str, local_path: str, **kwargs: Any) -> None:
            Path(local_path).write_bytes(b"fake-sosreport-archive")

        conn.run = AsyncMock(side_effect=fake_run)  # type: ignore[method-assign]
        conn.download = AsyncMock(side_effect=fake_download)  # type: ignore[method-assign]
        conn.remove_file = AsyncMock()  # type: ignore[method-assign]

        spec = FactSpec(
            commands=[
                CustomCommandSpec(
                    name="sensor", command="echo '{\"temp\": 42}'", parse_json=True
                )
            ],
            files=[FileSourceSpec(name="cmdline", path="/proc/cmdline")],
            tools=[
                ExternalToolSpec(
                    name="lshw", command="lshw -json", output_mode="json"
                ),
                ExternalToolSpec(
                    name="missing", command="missing_tool --all", output_mode="stdout"
                ),
                ExternalToolSpec(
                    name="sos",
                    command="sosreport --batch",
                    output_mode="artifact",
                    local_dir=str(tmp_path),
                ),
            ],
        )

        facts = await conn.gather_facts(spec=spec)
        assert facts.hostname == "node-01"
        assert facts.custom["sensor"] == {"temp": 42}
        assert facts.custom["cmdline"] == "BOOT_IMAGE=/vmlinuz quiet"
        assert facts.tools["lshw"] == [{"id": "core", "product": "ServerBoard"}]
        assert facts.tools["missing"]["ok"] is False
        assert "not found" in facts.tools["missing"]["error"]
        assert facts.tools["sos"]["ok"] is True
        assert Path(facts.tools["sos"]["artifact_path"]).exists()
        conn.remove_file.assert_awaited_once_with("/tmp/sosreport-node01.tar.xz")

    def test_diff_facts_detects_custom_fields_drift(self) -> None:
        """diff_facts автоматически проверяет расхождения по ключам custom.*."""
        from uniconn import HostFacts

        f1 = HostFacts(
            hostname="n1",
            os_family="Debian",
            custom={"bios_version": "1.2.0", "bmc_fw": "3.0"},
        )
        f2 = HostFacts(
            hostname="n2",
            os_family="Debian",
            custom={"bios_version": "1.1.0", "bmc_fw": "3.0"},
        )
        report = diff_facts({"n1": f1, "n2": f2}, baseline_host="n1")
        assert report.has_drift is True
        assert "custom.bios_version" in report.drifted_hosts["n2"]
        assert report.drifted_hosts["n2"]["custom.bios_version"] == {
            "expected": "1.2.0",
            "actual": "1.1.0",
        }


class TestPipelineEnhancementsAndArchiving:
    """Тесты fsync в LocalFileHandler, буферизации ForwardHandler, ArchiveHandler и DirectStreamCollector."""

    async def test_local_file_handler_fsync_and_archive_handler(
        self, tmp_path: Path
    ) -> None:
        """LocalFileHandler с fsync=True пишет файлы, а ArchiveHandler упаковывает их в .tar.gz и .zip."""
        logs_dir = tmp_path / "logs"
        handler = LocalFileHandler(logs_dir, strategy="realtime", fsync=True)
        await handler.handle("dmesg", ["[0.001] Booting Linux\n", "[0.002] ACPI init\n"])
        assert "dmesg" in handler.written_paths

        tar_dest = tmp_path / "bundle.tar.gz"
        ArchiveHandler.build_archive(logs_dir, tar_dest, fmt="tar.gz")
        assert tar_dest.exists()
        with tarfile.open(tar_dest, "r:gz") as tf:
            assert "dmesg.log" in tf.getnames()

        zip_dest = tmp_path / "bundle.zip"
        ArchiveHandler.build_archive(logs_dir, zip_dest, fmt="zip")
        assert zip_dest.exists()
        with zipfile.ZipFile(zip_dest, "r") as zf:
            assert "dmesg.log" in zf.namelist()

    async def test_forward_handler_session_template_and_buffering(self) -> None:
        """ForwardHandler подставляет {session_id} и буферизует чанки при flush_interval > 0."""
        conn = Connection.from_uri("local://")
        conn.run = AsyncMock(return_value=_ok_res())  # type: ignore[method-assign]

        fwd = ForwardHandler(
            conn,
            remote_path="/var/backup/{session_id}.log",
            flush_interval=3600.0,
        )
        await fwd.handle("kernel/dmesg", ["line1\n"])
        await fwd.handle("kernel/dmesg", ["line2\n"])
        assert conn.run.await_count == 0

        await fwd.finalize()
        assert conn.run.await_count == 1
        called_cmd = conn.run.call_args[0][0]
        assert "/var/backup/kernel_dmesg.log" in called_cmd
        assert "line1\nline2\n" in called_cmd

    async def test_direct_stream_collector_survives_disconnect(
        self, tmp_path: Path
    ) -> None:
        """DirectStreamCollector записывает чанки в реальном времени и переживает обрыв потока."""
        conn = Connection.from_uri("local://")

        async def crashing_stream(
            command: str, timeout: float | None = None, **kwargs: Any
        ) -> AsyncIterator[str]:
            yield "normal log line 1\n"
            yield "normal log line 2\n"
            raise RuntimeError("SSH connection reset by peer (Kernel Panic)")

        conn.stream = crashing_stream  # type: ignore[method-assign]

        local_handler = LocalFileHandler(tmp_path, strategy="realtime", fsync=True)
        pipeline = LogPipeline([local_handler])
        collector = DirectStreamCollector(
            connection=conn,
            name="dmesg",
            command="dmesg -w",
            pipeline=pipeline,
        )
        task = collector.start()
        await task
        await collector.stop()

        assert collector.lines_collected == 2
        assert collector.error is not None
        assert "Kernel Panic" in collector.error
        saved = (tmp_path / "dmesg.log").read_text(encoding="utf-8")
        assert saved == "normal log line 1\nnormal log line 2\n"


class TestDiagnosticSessionLifecycle:
    """Тесты фасада conn.diagnostic_session (нормальный цикл, сбой хоста и SyncDiagnosticSession)."""

    async def test_diagnostic_session_normal_and_forwarding(
        self, tmp_path: Path
    ) -> None:
        """conn.diagnostic_session собирает pre/post факты, потоки, пересылает на backup и создаёт .tar.gz."""
        conn = Connection.from_uri("local://")
        backup_conn = Connection.from_uri("local://")

        call_counter = {"facts": 0}

        async def fake_run(cmd: Any, **kwargs: Any) -> Result:
            cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
            if "===UNICONN_SECTION:UNAME===" in cmd_str:
                call_counter["facts"] += 1
                return _ok_res(SAMPLE_FACTS_STDOUT, cmd_str)
            if cmd_str == "cat /sys/power/state":
                val = "mem" if call_counter["facts"] <= 1 else "freeze"
                return _ok_res(f"{val}\n", cmd_str)
            return _ok_res("", cmd_str)

        async def fake_stream(
            command: str, timeout: float | None = None, **kwargs: Any
        ) -> AsyncIterator[str]:
            yield "[stream] event 1\n"
            yield "[stream] event 2\n"
            await asyncio.sleep(0.01)

        conn.run = AsyncMock(side_effect=fake_run)  # type: ignore[method-assign]
        conn.stream = fake_stream  # type: ignore[method-assign]
        conn.ping = AsyncMock(  # type: ignore[method-assign]
            return_value=PingResult(
                host="node-01", alive=True, latency_ms=1.2, transport="local"
            )
        )

        backup_conn.run = AsyncMock(return_value=_ok_res())  # type: ignore[method-assign]
        backup_conn.upload = AsyncMock()  # type: ignore[method-assign]

        archive_target = tmp_path / "out" / "diag_{host}.tar.gz"
        config = DiagnosticConfig(
            facts=FactSpec(
                commands=[
                    CustomCommandSpec(
                        name="power_state", command="cat /sys/power/state"
                    )
                ]
            ),
            streams=[StreamSourceSpec(name="dmesg", command="dmesg -w")],
            local_dir=str(tmp_path / "work"),
            archive_path=str(archive_target),
            archive_format="tar.gz",
            forward_remote_dir="/var/diag_backup",
        )

        async with conn.diagnostic_session(
            config=config, forward_to=backup_conn
        ) as diag:
            await asyncio.sleep(0.03)
            await diag.emit_custom_log("test_runner", "stress step 1 completed")
            snap = await diag.snapshot("mid_test")
            assert snap.hostname == "node-01"

        assert diag.result is not None
        assert diag.result.host_survived is True
        assert diag.pre_facts is not None
        assert diag.post_facts is not None
        assert diag.facts_diff is not None
        assert diag.facts_diff.has_drift is True
        assert "custom.power_state" in diag.facts_diff.drifted_hosts["post"]

        built_archive = Path(diag.result.archive_path or "")
        assert built_archive.exists()
        with tarfile.open(built_archive, "r:gz") as tf:
            names = set(tf.getnames())
            assert "manifest.json" in names
            assert "pre_facts.json" in names
            assert "post_facts.json" in names
            assert "facts_diff.json" in names
            assert "snapshots/mid_test.json" in names
            assert "streams/dmesg.log" in names
            assert "streams/test_runner.log" in names

        backup_conn.upload.assert_awaited_once()

    async def test_diagnostic_session_survives_host_crash(
        self, tmp_path: Path
    ) -> None:
        """При зависании хоста во время теста (ping=False на выходе) логи и архив сохраняются."""
        conn = Connection.from_uri("local://")

        async def fake_run(cmd: Any, **kwargs: Any) -> Result:
            cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
            if "===UNICONN_SECTION:UNAME===" in cmd_str:
                return _ok_res(SAMPLE_FACTS_STDOUT, cmd_str)
            return _ok_res("", cmd_str)

        async def panic_stream(
            command: str, timeout: float | None = None, **kwargs: Any
        ) -> AsyncIterator[str]:
            yield "[  100.123] BUG: soft lockup - CPU#0 stuck for 22s!\n"
            yield "[  100.125] Kernel panic - not syncing: Fatal exception\n"
            raise ConnectionError("SSH transport closed abruptly")

        conn.run = AsyncMock(side_effect=fake_run)  # type: ignore[method-assign]
        conn.stream = panic_stream  # type: ignore[method-assign]
        conn.ping = AsyncMock(  # type: ignore[method-assign]
            return_value=PingResult(
                host="node-01",
                alive=False,
                latency_ms=3000.0,
                transport="local",
                error="Connection timed out",
            )
        )

        async with conn.diagnostic_session(
            streams=["dmesg -w"],
            local_dir=tmp_path / "crash_work",
            archive_path=tmp_path / "crash_bundle.tar.gz",
        ) as diag:
            await asyncio.sleep(0.03)

        assert diag.result is not None
        assert diag.result.host_survived is False
        assert diag.pre_facts is not None
        assert diag.post_facts is None
        assert any("post_ping_failed" in err for err in diag.result.errors)

        archive_file = tmp_path / "crash_bundle.tar.gz"
        assert archive_file.exists()
        with tarfile.open(archive_file, "r:gz") as tf:
            manifest_member = tf.extractfile("manifest.json")
            assert manifest_member is not None
            manifest = json.loads(manifest_member.read().decode("utf-8"))
            assert manifest["host_survived"] is False
            assert manifest["has_pre_facts"] is True
            assert manifest["has_post_facts"] is False

            dmesg_member = tf.extractfile("streams/dmesg.log")
            assert dmesg_member is not None
            dmesg_text = dmesg_member.read().decode("utf-8")
            assert "Kernel panic - not syncing" in dmesg_text

    def test_sync_diagnostic_session_and_sync_gather_facts(
        self, tmp_path: Path
    ) -> None:
        """Синхронная обёртка SyncConnection.diagnostic_session и gather_facts(spec=...) работают."""
        async_conn = Connection.from_uri("local://")

        async def fake_run(cmd: Any, **kwargs: Any) -> Result:
            cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
            if "===UNICONN_SECTION:UNAME===" in cmd_str:
                return _ok_res(SAMPLE_FACTS_STDOUT, cmd_str)
            if cmd_str == "echo sync_ok":
                return _ok_res("sync_ok\n", cmd_str)
            return _ok_res("", cmd_str)

        async_conn.run = AsyncMock(side_effect=fake_run)  # type: ignore[method-assign]
        async_conn.ping = AsyncMock(  # type: ignore[method-assign]
            return_value=PingResult(
                host="node-01", alive=True, latency_ms=0.5, transport="local"
            )
        )

        sync_conn = async_conn.to_sync()
        try:
            facts = sync_conn.gather_facts(
                spec={"commands": {"check": "echo sync_ok"}}
            )
            assert facts.custom["check"] == "sync_ok"

            with sync_conn.diagnostic_session(
                spec={"commands": {"check": "echo sync_ok"}},
                local_dir=tmp_path / "sync_work",
                archive_path=tmp_path / "sync_bundle.tar.gz",
            ) as s_diag:
                s_diag.emit_custom_log("sync_log", "step 1")
                snap = s_diag.snapshot("mid")
                assert snap.custom["check"] == "sync_ok"

            assert s_diag.result is not None
            assert s_diag.result.host_survived is True
            assert (tmp_path / "sync_bundle.tar.gz").exists()
        finally:
            sync_conn.close()
