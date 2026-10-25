# src/uniconn/transports/replay/models.py
"""Модели данных и сериализация кассет для контрактного тестирования (Replay / Cassette)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import BaseModel, Field

from ...exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    CapabilityNotSupportedError,
    CassetteError,
    ConnectionError,
    ExecutionError,
    TimeoutError,
    UniconnError,
)

_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
_YAML_DUMPER = getattr(yaml, "CSafeDumper", yaml.SafeDumper)

_TEMP_PATH_RE = re.compile(r"/tmp/uniconn_[A-Za-z0-9_]+")
_POSIX_MARKER_CMD_RE = re.compile(
    r"^(.*);\s*echo\s+\"\\n(__UNICONN_[0-9a-f]+__)\$\?\"\s*$",
    re.DOTALL,
)
_POSIX_MARKER_OUT_RE = re.compile(r"\r?\n?__UNICONN_[0-9a-f]+__(\d+)\r?\n?")
_SUDO_WRAPPER_RE = re.compile(r"^sudo\s+-[Sn]\b")

_ERROR_MAP: dict[str, type[Exception]] = {
    "ConnectionError": ConnectionError,
    "AuthenticationError": AuthenticationError,
    "ExecutionError": ExecutionError,
    "TimeoutError": TimeoutError,
    "BMCCapabilityError": BMCCapabilityError,
    "CapabilityNotSupportedError": CapabilityNotSupportedError,
    "FileNotFoundError": FileNotFoundError,
    "PermissionError": PermissionError,
    "OSError": OSError,
    "UniconnError": UniconnError,
}


def normalize_temp_paths(text: str) -> str:
    """Нормализовать динамические пути временных директорий ``/tmp/uniconn_XXXXXX``."""
    if not text:
        return text
    return _TEMP_PATH_RE.sub("/tmp/uniconn_<TEMP>", text)


class RecordMode(StrEnum):
    """Режим работы кассеты записи и воспроизведения."""

    ONCE = "once"
    NEW_EPISODES = "new_episodes"
    NONE = "none"
    ALL = "all"


InteractionKind = Literal["exec", "stream", "fs", "shell"]
MatchField = Literal["command", "cwd", "sudo"]
CapabilityKind = Literal["exec", "stream", "file", "shell", "tunnel"]
FsOperationName = Literal[
    "read_file",
    "write_file",
    "exists",
    "stat",
    "listdir",
    "mkdir",
    "remove_file",
    "chmod",
    "upload",
    "download",
]


class RecordedExecInteraction(BaseModel):
    """Записанный вызов ``run()``, ``run_bytes()`` или ``ping()``."""

    kind: Literal["exec"] = "exec"
    command: str
    cwd: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    sudo: bool = False
    stdin_redacted: bool = False
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    stdout_base64: str | None = None
    duration: float = 0.001
    error_class: str | None = None
    error_message: str | None = None


class RecordedStreamInteraction(BaseModel):
    """Записанный потоковый вызов ``stream()``."""

    kind: Literal["stream"] = "stream"
    command: str
    cwd: str | None = None
    lines: list[str] = Field(default_factory=list)
    chunk_delay_ms: float = 0.0
    error_class: str | None = None
    error_message: str | None = None


class RecordedFsInteraction(BaseModel):
    """Записанная файловая операция ``FileCapableTransport``."""

    kind: Literal["fs"] = "fs"
    operation: FsOperationName
    path: str
    target_path: str | None = None
    mode: int | None = None
    result_bool: bool | None = None
    result_stat: dict[str, Any] | None = None
    result_list: list[str] = Field(default_factory=list)
    content_utf8: str | None = None
    content_base64: str | None = None
    content_sha256: str | None = None
    error_class: str | None = None
    error_message: str | None = None


class ShellDialogStep(BaseModel):
    """Один шаг интерактивного обмена в PTY ``ShellSession`` или ``expect()``."""

    expect_input: str
    response_output: str
    exit_code: int = 0


class RecordedShellInteraction(BaseModel):
    """Записанная интерактивная сессия ``open_shell()`` / ``expect()``."""

    kind: Literal["shell"] = "shell"
    term_type: str = "xterm"
    term_size: tuple[int, int] = (80, 24)
    steps: list[ShellDialogStep] = Field(default_factory=list)


CassetteInteraction = Annotated[
    RecordedExecInteraction
    | RecordedStreamInteraction
    | RecordedFsInteraction
    | RecordedShellInteraction,
    Field(discriminator="kind"),
]


class Cassette(BaseModel):
    """Корневая модель кассеты взаимодействий (сериализуется в YAML или JSON)."""

    version: str = "1.0"
    recorded_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    transport: str = "ssh"
    host: str | None = None
    capabilities: list[CapabilityKind] = Field(
        default_factory=lambda: ["exec", "stream", "file", "shell"]
    )
    interactions: list[CassetteInteraction] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> Self:
        """Загрузить кассету из YAML или JSON файла."""
        file_path = Path(path)
        if not file_path.is_file():
            raise CassetteError(f"Cassette file not found: {file_path}")
        raw_text = file_path.read_text(encoding="utf-8")
        data = (
            json.loads(raw_text)
            if file_path.suffix.lower() == ".json"
            else (yaml.load(raw_text, Loader=_YAML_LOADER) or {})
        )
        if not isinstance(data, dict):
            raise CassetteError(f"Invalid cassette structure in {file_path}")
        return cls.model_validate(data)

    def save(self, path: str | Path) -> None:
        """Сохранить кассету в YAML или JSON файл."""
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.model_dump(mode="json", exclude_none=True)
        if file_path.suffix.lower() == ".json":
            text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        else:
            text = yaml.dump(
                payload,
                Dumper=_YAML_DUMPER,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
        file_path.write_text(text, encoding="utf-8")


__all__ = [
    "_ERROR_MAP",
    "_POSIX_MARKER_CMD_RE",
    "_POSIX_MARKER_OUT_RE",
    "_SUDO_WRAPPER_RE",
    "CapabilityKind",
    "Cassette",
    "CassetteInteraction",
    "FsOperationName",
    "InteractionKind",
    "MatchField",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "ShellDialogStep",
    "normalize_temp_paths",
]
