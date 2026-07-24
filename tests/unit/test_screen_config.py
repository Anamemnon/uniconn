# tests/unit/test_screen_config.py
"""Тесты конфигурации ScreenPool: LogRule, LogConfig, ScreenPoolConfig."""

import json
from pathlib import Path

import pytest

from uniconn.background._config import LogConfig, LogRule, ScreenPoolConfig


class TestLogRule:
    """Тесты LogRule.matches."""

    def test_matches_true(self):
        """matches: True, если команда подходит под regex (search)."""
        rule = LogRule(pattern=r"stress-ng --cpu \d+")
        assert rule.matches("nice stress-ng --cpu 4 --timeout 60") is True

    def test_matches_false(self):
        """matches: False, если команда не подходит под regex."""
        rule = LogRule(pattern="sysbench")
        assert rule.matches("stress-ng --cpu 4") is False


class TestLogConfig:
    """Тесты LogConfig.match_rule."""

    def test_first_matching_rule_wins(self):
        """match_rule возвращает первое подходящее правило по порядку."""
        config = LogConfig(rules=[
            LogRule(pattern="stress", local_name="stress_{idx}.log"),
            LogRule(pattern=".*", collect=False),
        ])
        rule = config.match_rule("stress-ng --cpu 4")
        assert rule is not None
        assert rule.local_name == "stress_{idx}.log"

    def test_no_matching_rule_returns_none(self):
        """match_rule: None, если ни одно правило не подошло."""
        config = LogConfig(rules=[LogRule(pattern="sysbench")])
        assert config.match_rule("stress-ng --cpu 4") is None


class TestScreenPoolConfig:
    """Тесты ScreenPoolConfig: значения по умолчанию и from_file."""

    def test_defaults(self):
        """Значения по умолчанию: 16 screen, 4 монитора, poll 5.0, LogConfig."""
        config = ScreenPoolConfig(uri="ssh://host")
        assert config.max_screens == 16
        assert config.max_monitors == 4
        assert config.poll_interval == 5.0
        assert config.log_config.local_dir == "./logs"
        assert config.log_config.rules == []

    def test_from_file_json(self, tmp_path: Path):
        """from_file загружает конфигурацию из JSON."""
        path = tmp_path / "pool.json"
        path.write_text(
            json.dumps({
                "uri": "ssh://node1",
                "max_screens": 8,
                "log_config": {"local_dir": "/tmp/logs"},
            }),
            encoding="utf-8",
        )
        config = ScreenPoolConfig.from_file(path)
        assert config.uri == "ssh://node1"
        assert config.max_screens == 8
        assert config.log_config.local_dir == "/tmp/logs"

    def test_from_file_yaml(self, tmp_path: Path):
        """from_file загружает конфигурацию из YAML."""
        pytest.importorskip("yaml")
        path = tmp_path / "pool.yaml"
        path.write_text(
            "uri: ssh://node1\n"
            "max_monitors: 2\n"
            "log_config:\n"
            "  rules:\n"
            "    - pattern: sysbench\n"
            "      download_strategy: on_complete\n",
            encoding="utf-8",
        )
        config = ScreenPoolConfig.from_file(path)
        assert config.uri == "ssh://node1"
        assert config.max_monitors == 2
        assert config.log_config.rules[0].pattern == "sysbench"
        assert config.log_config.rules[0].download_strategy == "on_complete"

    def test_from_file_unsupported_extension(self, tmp_path: Path):
        """from_file с неподдерживаемым расширением падает с ValueError."""
        path = tmp_path / "pool.toml"
        path.write_text('uri = "ssh://node1"\n', encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported file format"):
            ScreenPoolConfig.from_file(path)
