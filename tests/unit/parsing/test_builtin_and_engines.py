# tests/unit/parsing/test_builtin_and_engines.py
"""Unit-тесты встроенных zero-dependency парсеров и адаптеров внешних движков (jc, ttp, textfsm)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from uniconn import (
    BuiltinEngine,
    JCEngine,
    OptionalDependencyError,
    ParserNotFoundError,
    ParsingError,
    TextFSMEngine,
    TTPEngine,
    UniconnError,
    parse_output,
)


def test_builtin_df_parser_handles_standard_and_wrapped_lines() -> None:
    df_out = (
        "Filesystem                                  Size  Used Avail Use% Mounted on\n"
        "/dev/sda1                                    50G   20G   28G  42% /\n"
        "mapper/vg_long_volume_name-lv_data_storage\n"
        "                                            200G  150G   50G  75% /mnt/data dir\n"
    )
    parsed = parse_output(df_out, "builtin:df")
    assert len(parsed) == 2
    assert parsed[0]["filesystem"] == "/dev/sda1"
    assert parsed[0]["percent_used"] == 42
    assert parsed[0]["use_percent"] == 42
    assert parsed[0]["mounted_on"] == "/"
    assert parsed[1]["filesystem"] == "mapper/vg_long_volume_name-lv_data_storage"
    assert parsed[1]["percent_used"] == 75
    assert parsed[1]["mounted_on"] == "/mnt/data dir"


def test_builtin_uptime_and_free_parsers() -> None:
    uptime_out = " 14:22:05 up 12 days,  4:18,  3 users,  load average: 0.42, 1.15, 0.98\n"
    up = parse_output(uptime_out, "builtin:uptime")
    assert up["users"] == 3
    assert up["load_1m"] == 0.42
    assert up["load_5m"] == 1.15
    assert up["load_15m"] == 0.98
    assert up["uptime"] == "12 days,  4:18"

    free_out = (
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:          15884        4120        6200         312        5564       11120\n"
        "Swap:          2047          12        2035\n"
    )
    fr = parse_output(free_out, "builtin:free")
    assert fr["total"] == 15884
    assert fr["used"] == 4120
    assert fr["available"] == 11120
    assert fr["swap_total"] == 2047
    assert fr["swap_free"] == 2035


def test_builtin_ps_ip_mount_ss_systemctl_parsers() -> None:
    ps_out = (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.1  0.4 168940 12400 ?        Ss   Nov01   0:14 /sbin/init --splash\n"
        "www-data  1042  2.5  1.2 245000 38000 ?        Sl   10:15   1:05 nginx: worker process\n"
    )
    procs = parse_output(ps_out, "builtin:ps")
    assert len(procs) == 2
    assert procs[0]["pid"] == 1
    assert procs[0]["command"] == "/sbin/init --splash"
    assert procs[1]["user"] == "www-data"
    assert procs[1]["cpu_percent"] == 2.5

    ip_route_out = (
        "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100\n"
        "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50 metric 100\n"
    )
    routes = parse_output(ip_route_out, "builtin:ip_route")
    assert routes[0]["destination"] == "default"
    assert routes[0]["gateway"] == "192.168.1.1"
    assert routes[0]["dev"] == "eth0"
    assert routes[0]["metric"] == 100

    ip_addr_out = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
        "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\n"
    )
    addrs = parse_output(ip_addr_out, "builtin:ip_addr")
    assert len(addrs) == 2
    assert addrs[1]["interface"] == "eth0"
    assert addrs[1]["mtu"] == 1500
    assert addrs[1]["state"] == "UP"
    assert addrs[1]["mac_address"] == "02:42:ac:11:00:02"
    assert addrs[1]["ipv4"][0]["address"] == "172.17.0.2"
    assert addrs[1]["ipv4"][0]["prefixlen"] == 16

    mount_out = "/dev/nvme0n1p2 on / type ext4 (rw,relatime,errors=remount-ro)\n"
    mounts = parse_output(mount_out, "builtin:mount")
    assert mounts == [
        {
            "filesystem": "/dev/nvme0n1p2",
            "mounted_on": "/",
            "type": "ext4",
            "options": ["rw", "relatime", "errors=remount-ro"],
        }
    ]

    ss_out = (
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        "tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:((\"sshd\",pid=812,fd=3))\n"
    )
    sockets = parse_output(ss_out, "builtin:ss")
    assert len(sockets) == 1
    assert sockets[0]["local_port"] == 22
    assert sockets[0]["state"] == "LISTEN"

    systemctl_out = (
        "● nginx.service - A high performance web server and a reverse proxy server\n"
        "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)\n"
        "     Active: active (running) since Mon 2026-11-08 12:00:00 UTC; 2h ago\n"
        "   Main PID: 4321 (nginx)\n"
        "     Memory: 12.4M\n"
    )
    svc = parse_output(systemctl_out, "builtin:systemctl_status")
    assert svc["unit"] == "nginx.service"
    assert svc["loaded"] == "loaded"
    assert svc["active"] == "active"
    assert svc["sub_state"] == "running"
    assert svc["main_pid"] == 4321
    assert svc["memory"] == "12.4M"


def test_builtin_cisco_network_parsers_and_generic_table_kv() -> None:
    cisco_int = (
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/0     10.10.1.1       YES NVRAM  up                    up\n"
        "GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down\n"
    )
    intfs = parse_output(cisco_int, "builtin:cisco_ios_show_ip_int_brief")
    assert len(intfs) == 2
    assert intfs[0]["intf"] == "GigabitEthernet0/0"
    assert intfs[0]["interface"] == "GigabitEthernet0/0"
    assert intfs[0]["ipaddr"] == "10.10.1.1"
    assert intfs[0]["proto"] == "up"
    assert intfs[1]["status"] == "administratively down"
    assert intfs[1]["proto"] == "down"

    kv_out = "net.ipv4.ip_forward = 1\nkernel.hostname = edge-router-01\n"
    kv = parse_output(kv_out, "kv")
    assert kv == {"net.ipv4.ip_forward": 1, "kernel.hostname": "edge-router-01"}

    table_out = (
        "NAME       STATUS    AGE\n"
        "---        ------    ---\n"
        "web-pod-1  Running   12d\n"
        "db-pod-0   Pending   5m\n"
    )
    tbl = parse_output(table_out, "table")
    assert tbl == [
        {"name": "web-pod-1", "status": "Running", "age": "12d"},
        {"name": "db-pod-0", "status": "Pending", "age": "5m"},
    ]


def test_optional_dependency_errors_inherit_import_error_and_uniconn_error() -> None:
    with patch("uniconn.parsing.engines.jc_engine._jc_mod", None):
        engine = JCEngine()
        assert not engine.can_parse("df")
        with pytest.raises(OptionalDependencyError, match=r"uniconn\[parsing\]") as exc_info:
            engine.parse("text", "df")
        assert isinstance(exc_info.value, ImportError)
        assert isinstance(exc_info.value, UniconnError)

    with patch("uniconn.parsing.engines.ttp_engine._ttp_cls", None):
        ttp_eng = TTPEngine()
        assert not ttp_eng.can_parse("tpl.ttp")
        with pytest.raises(OptionalDependencyError, match=r"uniconn\[parsing\]"):
            ttp_eng.parse("text", "<group>{{ item }}</group>")

    with patch("uniconn.parsing.engines.textfsm_engine._textfsm_mod", None):
        fsm_eng = TextFSMEngine()
        assert not fsm_eng.can_parse("tpl.textfsm")
        with pytest.raises(OptionalDependencyError, match=r"uniconn\[parsing\]"):
            fsm_eng.parse("text", "cisco_ios_show_ip_int_brief")


def test_jc_ttp_and_textfsm_engines_with_mocked_backends(tmp_path: Path) -> None:
    # 1. Mocked JC
    fake_jc = SimpleNamespace(
        parser_mod_list=lambda: ["df", "uptime"],
        parse=lambda spec, text, raw=False, quiet=True: (
            [{"filesystem": "/dev/sda1", "use_percent": 55, "mounted_on": "/"}]
            if spec == "df"
            else {"load_average_1m": 0.5, "load_average_5m": 0.4, "load_average_15m": 0.3}
        ),
    )
    with patch("uniconn.parsing.engines.jc_engine._jc_mod", fake_jc):
        jc_eng = JCEngine()
        assert jc_eng.can_parse("df")
        res_df = jc_eng.parse("raw df", "df")
        assert res_df[0]["percent_used"] == 55
        res_up = jc_eng.parse("raw uptime", "uptime")
        assert res_up["load_1m"] == 0.5

    # 2. Mocked TTP with template file
    ttp_file = tmp_path / "iface.ttp"
    ttp_file.write_text("interface {{ name }}\n ip address {{ ip }}", encoding="utf-8")

    class FakeTTPInstance:
        def __init__(self, data: str, template: str) -> None:
            self.data = data
            self.template = template

        def parse(self) -> None:
            pass

        def result(self, format: str = "raw") -> list[ Any]:
            return [[{"name": "Loopback0", "ip": "1.1.1.1"}]]

    with patch("uniconn.parsing.engines.ttp_engine._ttp_cls", FakeTTPInstance):
        ttp_eng = TTPEngine()
        assert ttp_eng.can_parse(str(ttp_file))
        parsed_ttp = ttp_eng.parse("interface Loopback0\n ip address 1.1.1.1", str(ttp_file))
        assert parsed_ttp == {"name": "Loopback0", "ip": "1.1.1.1"}

        with pytest.raises(ParserNotFoundError):
            ttp_eng.parse("data", str(tmp_path / "missing.ttp"))

    # 3. Mocked TextFSM + ntc-templates
    fsm_file = tmp_path / "sample.textfsm"
    fsm_file.write_text("Value INTF (\\S+)\n\nStart\n  ^${INTF} -> Record\n", encoding="utf-8")

    fake_fsm_obj = MagicMock()
    fake_fsm_obj.header = ["INTF", "IP_ADDRESS", "PROTOCOL"]
    fake_fsm_obj.ParseText.return_value = [["Gi0/1", "10.0.0.1", "up"]]
    fake_textfsm_mod = SimpleNamespace(TextFSM=lambda _io: fake_fsm_obj)
    fake_ntc_parse = MagicMock(
        return_value=[{"interface": "Gi0/2", "ip_address": "10.0.0.2", "protocol": "up"}]
    )

    with (
        patch("uniconn.parsing.engines.textfsm_engine._textfsm_mod", fake_textfsm_mod),
        patch("uniconn.parsing.engines.textfsm_engine._ntc_parse_output", fake_ntc_parse),
    ):
        fsm_eng = TextFSMEngine()
        assert fsm_eng.can_parse(str(fsm_file))
        direct_res = fsm_eng.parse("Gi0/1", str(fsm_file))
        assert direct_res == [{"intf": "Gi0/1", "ip_address": "10.0.0.1", "protocol": "up"}]

        ntc_res = fsm_eng.parse("show output", "cisco_ios_show_ip_int_brief")
        assert ntc_res[0]["intf"] == "Gi0/2"
        assert ntc_res[0]["ipaddr"] == "10.0.0.2"
        assert ntc_res[0]["proto"] == "up"

    # 4. BuiltinEngine unknown parser error
    with pytest.raises(ParserNotFoundError):
        BuiltinEngine().parse("data", "unknown_builtin")

    with pytest.raises(ParsingError):
        BuiltinEngine().parse("invalid uptime text", "uptime")


def test_builtin_df_7cols_uptime_pretty_and_aliases() -> None:
    # 1. df -T 7 columns
    df_t_out = (
        "Filesystem     Type     1K-blocks    Used Available Use% Mounted on\n"
        "/dev/sda1      ext4      20511312 8593452  10852788  45% /\n"
        "/dev/sdb1      ntfs-3g  104857600 4000000 100857600   4% /media/External Drive\n"
    )
    df_parsed = parse_output(df_t_out, "df")
    assert len(df_parsed) == 2
    assert df_parsed[0]["filesystem"] == "/dev/sda1"
    assert df_parsed[0]["type"] == "ext4"
    assert df_parsed[0]["size"] == 20511312
    assert df_parsed[0]["used"] == 8593452
    assert df_parsed[0]["available"] == 10852788
    assert df_parsed[0]["percent_used"] == 45
    assert df_parsed[0]["mounted_on"] == "/"
    assert df_parsed[1]["mounted_on"] == "/media/External Drive"
    assert df_parsed[1]["type"] == "ntfs-3g"

    # 2. uptime -p
    up_pretty = "up 2 weeks, 3 days, 14 hours, 5 minutes\n"
    up_res = parse_output(up_pretty, "uptime")
    assert up_res["uptime"] == "2 weeks, 3 days, 14 hours, 5 minutes"
    assert up_res["users"] == 0
    assert up_res["load_1m"] == 0.0

    # 3. ip addr with 'ip' and 'ip_address' alias
    ip_out = (
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
        "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\n"
    )
    ip_parsed = parse_output(ip_out, "ip_addr")
    assert ip_parsed[0]["ip"] == "172.17.0.2"
    assert ip_parsed[0]["ip_address"] == "172.17.0.2"

    # 4. systemctl status is_active boolean
    sys_out = (
        "● nginx.service - A high performance web server and a reverse proxy server\n"
        "   Loaded: loaded (/lib/systemd/system/nginx.service; enabled; vendor preset: enabled)\n"
        "   Active: active (running) since Sun 2026-11-08 10:00:00 UTC; 2h ago\n"
        " Main PID: 1234 (nginx)\n"
    )
    sys_parsed = parse_output(sys_out, "systemctl_status")
    assert sys_parsed["is_active"] is True
    assert sys_parsed["unit"] == "nginx.service"

