# src/uniconn/background/_config.py
import json
import re
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field


class LogRule(BaseModel):
    """Правило обработки логов для команд, подходящих под regex."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    pattern: str
    local_name: str | None = None
    download: bool = True
    download_strategy: Literal["realtime", "periodic", "on_complete"] = "on_complete"
    forward_to: str | None = None
    delete_remote: bool = False
    collect: bool = True

    def matches(self, command: str) -> bool:
        """Проверить, подходит ли команда под regex правила."""
        return re.search(self.pattern, command) is not None


class LogConfig(BaseModel):
    """Конфигурация обработки логов screen-сессий."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    local_dir: str = "./logs"
    max_log_size_mb: int = 100
    rules: list[LogRule] = Field(default_factory=list)

    def match_rule(self, command: str) -> LogRule | None:
        """Найти первое правило, подходящее под команду (порядок важен)."""
        for rule in self.rules:
            if rule.matches(command):
                return rule
        return None


class ScreenPoolConfig(BaseModel):
    """Конфигурация пула screen-сессий."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    uri: str
    max_screens: int = 16
    max_monitors: int = 4
    poll_interval: float = 5.0
    log_config: LogConfig = Field(default_factory=LogConfig)

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        """Загрузить конфигурацию из JSON или YAML файла.

        Args:
            path: Путь к файлу (.json, .yaml, .yml)

        Returns:
            ScreenPoolConfig

        """
        filepath = Path(path)
        content = filepath.read_text(encoding="utf-8")

        if filepath.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                raise ImportError(
                    "PyYAML not installed. "
                    "Run: pip install pyyaml"
                ) from None
        elif filepath.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(
                f"Unsupported file format: {filepath.suffix}. "
                "Use .json, .yaml or .yml"
            )

        return cls(**data)
