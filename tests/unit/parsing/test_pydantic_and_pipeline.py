# tests/unit/parsing/test_pydantic_and_pipeline.py
"""Unit-тесты валидации Pydantic TypeAdapter, кэша Result.parsed, пайплайна, пулов и CLI --parse."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel

from uniconn import (
    Connection,
    ConnectionPool,
    ParsingError,
    Result,
    default_registry,
)
from uniconn.cli import CliRunner, create_cli_app


class DiskUsage(BaseModel):
    filesystem: str
    mounted_on: str
    percent_used: int


class UptimeStats(BaseModel):
    users: int
    load_1m: float
    load_5m: float
    load_15m: float


@dataclass
class RouteRow:
    destination: str
    dev: str


DF_SAMPLE = (
    "Filesystem      Size  Used Avail Use% Mounted on\n"
    "/dev/sda1        50G   20G   28G  42% /\n"
    "/dev/sdb1       100G   85G   15G  85% /var/lib/docker\n"
)


def test_result_parse_with_pydantic_generic_list_and_single_model() -> None:
    res = Result(exit_code=0, stdout=DF_SAMPLE, stderr="", duration=0.05, command="df -h")
    disks = res.parse(list[DiskUsage])
    assert len(disks) == 2
    assert isinstance(disks[0], DiskUsage)
    assert disks[0].filesystem == "/dev/sda1"
    assert disks[0].percent_used == 42
    assert disks[1].mounted_on == "/var/lib/docker"
    assert disks[1].percent_used == 85

    up_res = Result(
        exit_code=0,
        stdout=" 10:00:00 up 5 days, 2:10, 4 users, load average: 0.15, 0.25, 0.35\n",
        stderr="",
        duration=0.01,
        command="uptime",
    )
    stats = up_res.parse(UptimeStats)
    assert isinstance(stats, UptimeStats)
    assert stats.users == 4
    assert stats.load_1m == 0.15

    route_res = Result(
        exit_code=0,
        stdout="default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 scope link\n",
        stderr="",
        duration=0.01,
        command="ip route",
    )
    routes = route_res.parse(list[RouteRow])
    assert routes == [
        RouteRow(destination="default", dev="eth0"),
        RouteRow(destination="10.0.0.0/24", dev="eth0"),
    ]


def test_result_parse_pydantic_validation_error_raises_parsing_error() -> None:
    res = Result(
        exit_code=0,
        stdout='[{"filesystem": "/dev/sda1", "mounted_on": "/", "percent_used": "not-an-int"}]',
        stderr="",
        duration=0.01,
        command="custom-json",
    )
    with pytest.raises(ParsingError, match="Schema validation failed"):
        res.parse(list[DiskUsage])


def test_result_parsed_lazy_caching_and_sensitive_redaction() -> None:
    call_count = 0

    def _counting_parser(text: str) -> dict[str, int]:
        nonlocal call_count
        call_count += 1
        return {"lines": len(text.splitlines())}

    res = Result(
        exit_code=0,
        stdout="line1\nline2\n",
        stderr="",
        duration=0.01,
        command="custom",
        parse_spec=_counting_parser,
    )
    assert call_count == 0
    assert res.parsed == {"lines": 2}
    assert res.parsed == {"lines": 2}
    assert call_count == 1
    assert res.to_dict()["parsed"] == {"lines": 2}

    # Проверка маскировки при sensitive=True
    sec_res = Result(
        exit_code=0,
        stdout='{"token": "topsecret"}',
        stderr="",
        duration=0.01,
        command="get-token --json",
        sensitive=True,
        parse_spec="json",
    )
    assert sec_res.to_dict()["parsed"] == "***REDACTED***"


def test_custom_parser_registration_in_registry() -> None:
    default_registry.register_parser("upper_lines", lambda txt: [s.upper() for s in txt.splitlines()])
    res = Result(exit_code=0, stdout="alpha\nbeta", stderr="", duration=0.01, command="any")
    assert res.parse("upper_lines") == ["ALPHA", "BETA"]


@pytest.mark.asyncio
async def test_connection_run_pool_map_shell_and_sync_parity() -> None:
    async with Connection.from_uri("local://") as conn:
        conn.transport.run = AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout=DF_SAMPLE,
                stderr="",
                duration=0.01,
                command="df -h",
            )
        )
        res = await conn.run("df -h", parse=True)
        assert res.parsed[0]["percent_used"] == 42

        # Eager validation with Pydantic model list
        typed_res = await conn.run("df -h", parse=list[DiskUsage], eager_parse=True)
        assert isinstance(typed_res.parsed[0], DiskUsage)
        assert typed_res.to_dict()["parsed"][0]["filesystem"] == "/dev/sda1"

        # Dry-run safety: returns empty list without crashing on empty stdout
        dry_res = await conn.run("df -h", dry_run=True, parse=list[DiskUsage], eager_parse=True)
        assert dry_res.parsed == []

    # SyncConnection parity
    with Connection.from_uri("local://").to_sync() as sync_conn:
        sync_conn.transport.run = AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout='{"service": "api", "healthy": true}',
                stderr="",
                duration=0.01,
                command="healthcheck --json",
            )
        )
        s_res = sync_conn.run("healthcheck --json", parse=True)
        assert s_res.parsed == {"service": "api", "healthy": True}

    # ConnectionPool.map with parse=True
    c1 = Connection.from_uri("local://host1")
    c2 = Connection.from_uri("local://host2")
    c1.transport.run = AsyncMock(
        return_value=Result(exit_code=0, stdout=DF_SAMPLE, stderr="", duration=0.01, command="df -h")
    )
    c2.transport.run = AsyncMock(
        return_value=Result(exit_code=0, stdout=DF_SAMPLE, stderr="", duration=0.01, command="df -h")
    )
    async with ConnectionPool([c1, c2]) as pool:
        pool_results = await pool.map("df -h", parse=True)
        assert len(pool_results) == 2
        assert pool_results[0].parsed[1]["mounted_on"] == "/var/lib/docker"
        assert pool_results[1].parsed[0]["percent_used"] == 42


def test_cli_run_and_run_multi_with_parse_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    app = create_cli_app()

    async def _fake_run(self: Connection, command: str, **kwargs: object) -> Result:
        return Result(
            exit_code=0,
            stdout=DF_SAMPLE,
            stderr="",
            duration=0.02,
            command=command,
            host=self.config.host,
            parse_spec=kwargs.get("parse"),
        )

    monkeypatch.setattr(Connection, "run", _fake_run)

    # 1. uniconn run --parse auto --format json
    res_json = runner.invoke(
        app,
        ["run", "local://localhost", "df -h", "--parse", "auto", "--format", "json"],
    )
    assert res_json.exit_code == 0
    payload = json.loads(res_json.stdout)
    assert payload["parsed"][0]["filesystem"] == "/dev/sda1"
    assert payload["parsed"][0]["percent_used"] == 42

    # 2. uniconn run --parse df --format table
    res_table = runner.invoke(
        app,
        ["run", "local://localhost", "df -h", "--parse", "df", "--format", "table"],
    )
    assert res_table.exit_code == 0
    assert "/dev/sda1" in res_table.stdout
    assert "mounted_on" in res_table.stdout
    assert "85" in res_table.stdout

    # 3. uniconn run-multi --parse auto --format json
    res_multi = runner.invoke(
        app,
        [
            "run-multi",
            "local://node1",
            "local://node2",
            "-c",
            "df -h",
            "--parse",
            "auto",
            "--format",
            "json",
        ],
    )
    assert res_multi.exit_code == 0
    multi_data = json.loads(res_multi.stdout)
    assert len(multi_data) == 2
    assert multi_data[0]["parsed"][0]["percent_used"] == 42


@pytest.mark.asyncio
async def test_dry_run_dict_vs_list_and_pydantic_models() -> None:
    conn = Connection.from_uri("local://localhost", dry_run=True)

    # 1. List spec on dry run -> []
    res_list = await conn.run("df -h", parse="df")
    assert res_list.parsed == []

    # 2. Dict spec on dry run -> {}
    res_dict = await conn.run("uptime", parse="uptime")
    assert res_dict.parsed == {}

    # 3. Pydantic BaseModel on dry run -> None
    res_model = await conn.run("uptime", parse=UptimeStats)
    assert res_model.parsed is None

    # 4. list[BaseModel] on dry run -> []
    res_model_list = await conn.run("df -h", parse=list[DiskUsage])
    assert res_model_list.parsed == []

    await conn.close()


def test_serialize_parsed_value_with_path_set_datetime_bytes() -> None:
    from datetime import datetime
    from pathlib import Path

    now = datetime(2026, 11, 8, 12, 0, 0)
    data = {
        "path": Path("/var/log/syslog"),
        "tags": {"prod", "web"},
        "time": now,
        "raw": b"binary-data",
        "nested": [Path("/etc/hosts")],
    }
    res = Result(
        exit_code=0,
        stdout="",
        stderr="",
        duration=0.01,
        command="test",
        parse_spec="custom",
    )
    object.__setattr__(res, "_parsed_cache", data)
    d = res.to_dict()
    assert d["parsed"]["path"] == "/var/log/syslog"
    assert set(d["parsed"]["tags"]) == {"prod", "web"}
    assert d["parsed"]["time"] == "2026-11-08T12:00:00"
    assert d["parsed"]["raw"] == "binary-data"
    assert d["parsed"]["nested"] == ["/etc/hosts"]


def test_cli_renderer_supports_pydantic_models() -> None:
    from rich.console import Console

    from uniconn.cli.renderers import CLIOutputRenderer

    console = Console(record=True, width=120)
    renderer = CLIOutputRenderer(console)

    models = [
        DiskUsage(filesystem="/dev/sda1", mounted_on="/", percent_used=40),
        DiskUsage(filesystem="/dev/sdb1", mounted_on="/data", percent_used=75),
    ]
    renderer.render_parsed_data(models, title="Disk Table")
    output = console.export_text()
    assert "/dev/sda1" in output
    assert "/data" in output
    assert "40" in output


@pytest.mark.asyncio
async def test_session_expect_with_parse_parameter() -> None:
    from uniconn.shell.session import ShellSession

    fake_proc = AsyncMock()
    fake_proc.is_alive = True
    session = ShellSession(proc=fake_proc, host="test-host")

    # Mock _raw_expect returning a Result with table-like stdout
    async def _mock_raw_expect(*args: object, **kwargs: object) -> Result:
        return Result(
            exit_code=0,
            stdout=DF_SAMPLE,
            stderr="",
            duration=0.01,
            command="df -h",
        )

    session._raw_expect = _mock_raw_expect
    res = await session.expect(command="df -h", parse="df", eager_parse=True)
    assert res.parse_spec == "df"
    assert len(res.parsed) == 2
    assert res.parsed[0]["filesystem"] == "/dev/sda1"

