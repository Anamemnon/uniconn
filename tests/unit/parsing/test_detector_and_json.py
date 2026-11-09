# tests/unit/parsing/test_detector_and_json.py
"""Unit-тесты детектора команд, очистки ANSI и встроенного JSON/JSONL движка."""

from __future__ import annotations

import pytest

from uniconn import (
    NativeJsonEngine,
    ParserNotFoundError,
    ParsingError,
    default_registry,
    detect_parser_spec,
    parse_output,
    strip_ansi,
)


def test_strip_ansi_fast_path_and_escape_removal() -> None:
    plain = "Filesystem      Size  Used Avail Use% Mounted on"
    assert strip_ansi(plain) is plain

    colored = "\x1b[32mGigabitEthernet0/1\x1b[0m  \x1b[1;36m10.0.0.1\x1b[0m  up"
    assert strip_ansi(colored) == "GigabitEthernet0/1  10.0.0.1  up"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("df -h", "df"),
        ("/bin/df -P -k", "df"),
        ("sudo -n -u root -- sh -c 'LANG=C df -h'", "df"),
        ("env LC_ALL=C ps aux", "ps"),
        ("uptime", "uptime"),
        ("free -m", "free"),
        ("mount", "mount"),
        ("ip route show", "ip_route"),
        ("ip r", "ip_route"),
        ("ip addr show eth0", "ip_addr"),
        ("ip -j route", "json"),
        ("ip -json addr", "json"),
        ("kubectl get pods -o json", "json"),
        ("docker inspect web-01", "json"),
        ("ss -tulnp", "ss"),
        ("netstat -tulnp", "ss"),
        ("systemctl status nginx.service", "systemctl_status"),
        ("systemctl list-units --type=service", "table"),
        ("sysctl -a", "sysctl"),
        ("printenv", "kv"),
        ("docker ps -a", "table"),
        ("podman images", "table"),
        ("kubectl get pods -n kube-system", "table"),
        ("kubectl top nodes", "table"),
        ("show ip interface brief", "cisco_ios_show_ip_int_brief"),
        ("sh ip int br", "cisco_ios_show_ip_int_brief"),
        ("show interfaces status", "cisco_ios_show_interfaces_status"),
        ("show ip route", "cisco_ios_show_ip_route"),
        ("show version", "cisco_ios_show_version"),
    ],
)
def test_detect_parser_spec_from_commands(command: str, expected: str) -> None:
    assert detect_parser_spec(command) == expected


def test_detect_parser_spec_from_content_json_and_jsonl() -> None:
    assert detect_parser_spec("custom-tool", '{"status": "ok", "count": 3}') == "json"
    assert detect_parser_spec("custom-tool", '[{"id": 1}, {"id": 2}]') == "json"
    jsonl_text = '{"line": 1}\n{"line": 2}\n'
    assert detect_parser_spec("custom-tool", jsonl_text) == "jsonl"
    assert detect_parser_spec("unknown-cmd", "plain unstructured text") is None


def test_native_json_engine_standard_and_prefixed_logs() -> None:
    engine = NativeJsonEngine()
    assert engine.can_parse("json")
    assert engine.can_parse("jsonl")
    assert not engine.can_parse("df")

    data = engine.parse('{"host": "node-01", "ok": true}', "json")
    assert data == {"host": "node-01", "ok": True}

    noisy = "INFO: connecting to cluster...\nWARNING: slow response\n{\"items\": [1, 2, 3]}\n"
    assert engine.parse(noisy, "json") == {"items": [1, 2, 3]}

    # Trailing logs after JSON
    trailing_noisy = "{\"status\": \"ok\", \"count\": 42}\nConnection closed by foreign host.\n"
    assert engine.parse(trailing_noisy, "json") == {"status": "ok", "count": 42}

    jsonl_out = '{"ev": "start"}\n{"ev": "stop"}\n'
    assert engine.parse(jsonl_out, "jsonl") == [{"ev": "start"}, {"ev": "stop"}]
    assert engine.parse("   ", "jsonl") == []


def test_native_json_engine_errors() -> None:
    engine = NativeJsonEngine()
    with pytest.raises(ParsingError, match="Cannot parse empty stdout as JSON"):
        engine.parse("   ", "json")

    with pytest.raises(ParsingError, match="Failed to parse output as JSON"):
        engine.parse("{broken json", "json")

    with pytest.raises(ParsingError, match="Failed to parse JSONL at line 2"):
        engine.parse('{"ok": 1}\n{bad_line}\n', "jsonl")


def test_registry_unknown_engine_and_undetectable_command() -> None:
    with pytest.raises(ParserNotFoundError, match="is not registered"):
        parse_output("some text", "nonexistent_engine:spec")

    with pytest.raises(ParserNotFoundError, match="Could not auto-detect parser"):
        default_registry.parse("hello world", "auto", command="echo hello")
