# src/uniconn/transports/replay/models.py
"""Модели данных и сериализация кассет для контрактного тестирования (Replay / Cassette)."""

from __future__ import annotations

import base64
import difflib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
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
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TOKEN_RE = re.compile(
    r"(?i)\b(?:bearer\s+[a-zA-Z0-9_\-\.]{8,}|(?:ghp|glpat|token|password|secret|api[_-]?key)[=:\s]+[a-zA-Z0-9_\-\.]{6,})"
)
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

    @property
    def total_interactions(self) -> int:
        """Общее количество записанных взаимодействий."""
        return len(self.interactions)

    @property
    def exec_count(self) -> int:
        """Количество вызовов команд (exec)."""
        return sum(1 for it in self.interactions if it.kind == "exec")

    @property
    def stream_count(self) -> int:
        """Количество потоковых вызовов (stream)."""
        return sum(1 for it in self.interactions if it.kind == "stream")

    @property
    def fs_count(self) -> int:
        """Количество файловых операций (fs)."""
        return sum(1 for it in self.interactions if it.kind == "fs")

    @property
    def shell_count(self) -> int:
        """Количество интерактивных shell-сессий."""
        return sum(1 for it in self.interactions if it.kind == "shell")

    def sanitize(
        self,
        *,
        redact_ips: bool = False,
        redact_tokens: bool = True,
        custom_patterns: Mapping[str | re.Pattern[str], str] | None = None,
    ) -> int:
        """Санитизировать конфиденциальные данные (IP, токены, секреты) во всех взаимодействиях кассеты.

        Возвращает суммарное количество произведённых замен.
        """
        rules: list[tuple[re.Pattern[str], str]] = []
        if redact_tokens:
            rules.append((_TOKEN_RE, "<REDACTED_SECRET>"))
        if redact_ips:
            rules.append((_IPV4_RE, "<IP_REDACTED>"))
        if custom_patterns:
            for pat, repl in custom_patterns.items():
                compiled = re.compile(pat) if isinstance(pat, str) else pat
                rules.append((compiled, repl))

        if not rules:
            return 0

        replacements = 0

        def _sub(text: str | None) -> str | None:
            nonlocal replacements
            if not text:
                return text
            res = text
            for pat, repl in rules:
                res, n = pat.subn(repl, res)
                replacements += n
            return res

        if self.host and redact_ips:
            self.host = _sub(self.host)

        for it in self.interactions:
            if isinstance(it, RecordedExecInteraction):
                it.command = _sub(it.command) or ""
                it.stdout = _sub(it.stdout) or ""
                it.stderr = _sub(it.stderr) or ""
                if it.cwd:
                    it.cwd = _sub(it.cwd)
                if it.env:
                    it.env = {k: (_sub(v) or "") for k, v in it.env.items()}
            elif isinstance(it, RecordedStreamInteraction):
                it.command = _sub(it.command) or ""
                if it.cwd:
                    it.cwd = _sub(it.cwd)
                it.lines = [(_sub(line) or "") for line in it.lines]
            elif isinstance(it, RecordedFsInteraction):
                it.path = _sub(it.path) or ""
                if it.target_path:
                    it.target_path = _sub(it.target_path)
                if it.content_utf8:
                    it.content_utf8 = _sub(it.content_utf8)
                if it.result_list:
                    it.result_list = [(_sub(item) or "") for item in it.result_list]
            elif isinstance(it, RecordedShellInteraction):
                for step in it.steps:
                    step.expect_input = _sub(step.expect_input) or ""
                    step.response_output = _sub(step.response_output) or ""

        return replacements

    def verify(self) -> list[str]:
        """Проверить целостность кассеты и соответствие схеме взаимодействий.

        Возвращает список ошибок (пустой, если кассета полностью корректна).
        """
        errors: list[str] = []
        if not self.transport:
            errors.append("Cassette has no transport specified.")
        for idx, it in enumerate(self.interactions):
            if isinstance(it, RecordedExecInteraction):
                if it.stdout_base64:
                    try:
                        base64.b64decode(it.stdout_base64)
                    except Exception as exc:
                        errors.append(f"Interaction #{idx} (exec): invalid stdout_base64 ({exc})")
            elif isinstance(it, RecordedFsInteraction):
                if it.content_base64:
                    try:
                        base64.b64decode(it.content_base64)
                    except Exception as exc:
                        errors.append(f"Interaction #{idx} (fs): invalid content_base64 ({exc})")
            elif isinstance(it, RecordedShellInteraction) and not isinstance(it.steps, list):
                errors.append(f"Interaction #{idx} (shell): steps must be a list")
        return errors

    def diff(self, other: Cassette) -> CassetteDiffReport:
        """Сравнить текущую кассету (baseline) с другой кассетой (candidate) и вернуть ``CassetteDiffReport``."""
        max_len = max(len(self.interactions), len(other.interactions))
        diffs: list[InteractionDiff] = []
        identical_count = 0
        modified_count = 0
        added_count = 0
        removed_count = 0

        for idx in range(max_len):
            if idx >= len(self.interactions):
                right_it = other.interactions[idx]
                added_count += 1
                diffs.append(
                    InteractionDiff(
                        index=idx,
                        status="added",
                        kind=right_it.kind,
                        left_command=None,
                        right_command=_interaction_summary(right_it),
                        command_changed=True,
                        exit_code_changed=False,
                        left_exit_code=None,
                        right_exit_code=_interaction_exit_code(right_it),
                        stdout_diff=None,
                        stderr_diff=None,
                        duration_delta=round(_interaction_duration(right_it), 6),
                    )
                )
            elif idx >= len(other.interactions):
                left_it = self.interactions[idx]
                removed_count += 1
                diffs.append(
                    InteractionDiff(
                        index=idx,
                        status="removed",
                        kind=left_it.kind,
                        left_command=_interaction_summary(left_it),
                        right_command=None,
                        command_changed=True,
                        exit_code_changed=False,
                        left_exit_code=_interaction_exit_code(left_it),
                        right_exit_code=None,
                        stdout_diff=None,
                        stderr_diff=None,
                        duration_delta=round(-_interaction_duration(left_it), 6),
                    )
                )
            else:
                left_it = self.interactions[idx]
                right_it = other.interactions[idx]
                left_cmd = _interaction_summary(left_it)
                right_cmd = _interaction_summary(right_it)
                cmd_changed = (left_it.kind != right_it.kind) or (left_cmd != right_cmd)

                left_ec = _interaction_exit_code(left_it)
                right_ec = _interaction_exit_code(right_it)
                ec_changed = left_ec != right_ec

                left_out = _interaction_stdout(left_it)
                right_out = _interaction_stdout(right_it)
                stdout_diff = _compute_unified_diff(
                    left_out,
                    right_out,
                    fromfile=f"a/step_{idx}/stdout",
                    tofile=f"b/step_{idx}/stdout",
                )

                left_err = _interaction_stderr(left_it)
                right_err = _interaction_stderr(right_it)
                stderr_diff = _compute_unified_diff(
                    left_err,
                    right_err,
                    fromfile=f"a/step_{idx}/stderr",
                    tofile=f"b/step_{idx}/stderr",
                )

                dur_delta = round(
                    _interaction_duration(right_it) - _interaction_duration(left_it),
                    6,
                )
                is_mod = (
                    cmd_changed
                    or ec_changed
                    or (stdout_diff is not None)
                    or (stderr_diff is not None)
                )
                status: Literal["identical", "modified"] = (
                    "modified" if is_mod else "identical"
                )
                if is_mod:
                    modified_count += 1
                else:
                    identical_count += 1

                diffs.append(
                    InteractionDiff(
                        index=idx,
                        status=status,
                        kind=right_it.kind,
                        left_command=left_cmd,
                        right_command=right_cmd,
                        command_changed=cmd_changed,
                        exit_code_changed=ec_changed,
                        left_exit_code=left_ec,
                        right_exit_code=right_ec,
                        stdout_diff=stdout_diff,
                        stderr_diff=stderr_diff,
                        duration_delta=dur_delta,
                    )
                )

        return CassetteDiffReport(
            left_host=self.host,
            right_host=other.host,
            left_transport=self.transport,
            right_transport=other.transport,
            left_count=len(self.interactions),
            right_count=len(other.interactions),
            identical_count=identical_count,
            modified_count=modified_count,
            added_count=added_count,
            removed_count=removed_count,
            interactions=diffs,
        )


def _compute_unified_diff(
    left_text: str,
    right_text: str,
    *,
    fromfile: str,
    tofile: str,
) -> str | None:
    """Построить unified diff для двух строк или вернуть ``None``, если они идентичны."""
    if left_text == right_text:
        return None
    left_lines = left_text.splitlines(keepends=True)
    right_lines = right_text.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(left_lines, right_lines, fromfile=fromfile, tofile=tofile)
    )


def _interaction_summary(it: CassetteInteraction) -> str:
    """Краткое строковое описание шага кассеты для сравнения."""
    if isinstance(it, RecordedExecInteraction):
        return it.command
    if isinstance(it, RecordedStreamInteraction):
        return f"stream: {it.command}"
    if isinstance(it, RecordedFsInteraction):
        return f"fs:{it.operation} {it.path}"
    return f"shell ({len(it.steps)} steps)"


def _interaction_stdout(it: CassetteInteraction) -> str:
    """Извлечь текстовое представление основного вывода шага."""
    if isinstance(it, RecordedExecInteraction):
        return it.stdout
    if isinstance(it, RecordedStreamInteraction):
        return "\n".join(it.lines)
    if isinstance(it, RecordedFsInteraction):
        if it.content_utf8 is not None:
            return it.content_utf8
        if it.result_stat is not None:
            return json.dumps(it.result_stat, sort_keys=True)
        if it.result_list:
            return "\n".join(it.result_list)
        if it.result_bool is not None:
            return str(it.result_bool)
        return ""
    return "\n".join(f"{s.expect_input} -> {s.response_output}" for s in it.steps)


def _interaction_stderr(it: CassetteInteraction) -> str:
    """Извлечь текстовое представление потока ошибок шага."""
    if isinstance(it, RecordedExecInteraction):
        return it.stderr
    if isinstance(it, RecordedStreamInteraction | RecordedFsInteraction):
        return it.error_message or ""
    return ""


def _interaction_exit_code(it: CassetteInteraction) -> int:
    """Извлечь числовой код возврата шага."""
    if isinstance(it, RecordedExecInteraction):
        return it.exit_code
    if isinstance(it, RecordedShellInteraction):
        return it.steps[-1].exit_code if it.steps else 0
    return 1 if it.error_class else 0


def _interaction_duration(it: CassetteInteraction) -> float:
    """Извлечь длительность выполнения шага в секундах."""
    if isinstance(it, RecordedExecInteraction):
        return it.duration
    return 0.0


@dataclass(slots=True)
class InteractionDiff:
    """Результат сравнения одного шага взаимодействия между двумя кассетами."""

    index: int
    status: Literal["identical", "modified", "added", "removed"]
    kind: InteractionKind
    left_command: str | None = None
    right_command: str | None = None
    command_changed: bool = False
    exit_code_changed: bool = False
    left_exit_code: int | None = None
    right_exit_code: int | None = None
    stdout_diff: str | None = None
    stderr_diff: str | None = None
    duration_delta: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать запись расхождения в сериализуемый словарь."""
        return {
            "index": self.index,
            "status": self.status,
            "kind": self.kind,
            "left_command": self.left_command,
            "right_command": self.right_command,
            "command_changed": self.command_changed,
            "exit_code_changed": self.exit_code_changed,
            "left_exit_code": self.left_exit_code,
            "right_exit_code": self.right_exit_code,
            "stdout_diff": self.stdout_diff,
            "stderr_diff": self.stderr_diff,
            "duration_delta": self.duration_delta,
        }


@dataclass(slots=True)
class CassetteDiffReport:
    """Сводный отчёт сравнения двух кассет (``Cassette.diff()``)."""

    left_host: str | None
    right_host: str | None
    left_transport: str
    right_transport: str
    left_count: int
    right_count: int
    identical_count: int
    modified_count: int
    added_count: int
    removed_count: int
    interactions: list[InteractionDiff] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Вернуть ``True``, если между кассетами обнаружены любые расхождения."""
        return (
            self.modified_count > 0
            or self.added_count > 0
            or self.removed_count > 0
        )

    @property
    def is_identical(self) -> bool:
        """Вернуть ``True``, если кассеты полностью идентичны."""
        return not self.has_changes

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать отчёт сравнения кассет в сериализуемый словарь."""
        return {
            "left_host": self.left_host,
            "right_host": self.right_host,
            "left_transport": self.left_transport,
            "right_transport": self.right_transport,
            "left_count": self.left_count,
            "right_count": self.right_count,
            "identical_count": self.identical_count,
            "modified_count": self.modified_count,
            "added_count": self.added_count,
            "removed_count": self.removed_count,
            "has_changes": self.has_changes,
            "is_identical": self.is_identical,
            "interactions": [it.to_dict() for it in self.interactions],
        }


__all__ = [
    "_ERROR_MAP",
    "_POSIX_MARKER_CMD_RE",
    "_POSIX_MARKER_OUT_RE",
    "_SUDO_WRAPPER_RE",
    "CapabilityKind",
    "Cassette",
    "CassetteDiffReport",
    "CassetteInteraction",
    "FsOperationName",
    "InteractionDiff",
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

