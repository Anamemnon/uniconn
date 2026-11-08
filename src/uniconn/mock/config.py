# src/uniconn/mock/config.py
"""Конфигурация, журнал событий и движок сопоставления кассет для Mock-серверов."""

from __future__ import annotations

import base64
import posixpath
import stat as stat_module
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..transports.replay.models import (
    _POSIX_MARKER_CMD_RE,
    _SUDO_WRAPPER_RE,
    Cassette,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    normalize_temp_paths,
)


@dataclass(slots=True)
class MockRequestEvent:
    """Событие обращения внешнего клиента к Mock SSH / Telnet серверу."""

    channel: Literal["exec", "shell", "sftp", "telnet", "auth"]
    command: str
    matched: bool
    exit_code: int | None = None
    details: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать событие в словарь."""
        return {
            "channel": self.channel,
            "command": self.command,
            "matched": self.matched,
            "exit_code": self.exit_code,
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class MockServerConfig:
    """Конфигурация сокетного Mock SSH / Telnet сервера."""

    cassette: Cassette | Path | str
    host: str = "127.0.0.1"
    port: int = 0
    server_type: Literal["ssh", "telnet"] = "ssh"

    # Аутентификация
    allow_any_auth: bool = True
    username: str | None = None
    password: str | None = None

    # Правила сопоставления
    strict_mode: bool = False
    normalize_temp: bool = True
    allow_repeats: bool = True
    default_exit_code: int = 127

    # Колбэк наблюдения за входящими запросами (для CLI и тестов)
    on_request: Callable[[MockRequestEvent], Any] | None = None

    def load_cassette(self) -> Cassette:
        """Загрузить или вернуть объект ``Cassette``."""
        if isinstance(self.cassette, Cassette):
            return self.cassette
        return Cassette.load(self.cassette)


class CassetteInteractionMatcher:
    """Потокобезопасный сопоставитель входящих запросов с записанной кассетой и сессионным FS-оверлеем."""

    def __init__(self, config: MockServerConfig, cassette: Cassette) -> None:
        """Инициализировать сопоставитель для заданной конфигурации и кассеты."""
        self.config = config
        self.cassette = cassette
        self.history: list[MockRequestEvent] = []
        self._consumed_exec: set[int] = set()
        self._consumed_fs: set[int] = set()
        self._consumed_shell: set[int] = set()

        # Сессионный оверлей файловой системы для SFTP-операций записи/модификации
        self.overlay_files: dict[str, bytes] = {}
        self.overlay_modes: dict[str, int] = {}
        self.overlay_dirs: set[str] = {"/", "."}
        self.deleted_paths: set[str] = set()
        self._seed_fs_hierarchy()

    def _seed_fs_hierarchy(self) -> None:
        """Построить начальное дерево известных директорий из записанных FS-взаимодействий."""
        for item in self.cassette.interactions:
            if not isinstance(item, RecordedFsInteraction):
                continue
            norm = self.normalize_path(item.path)
            if item.operation in ("mkdir", "listdir"):
                self.overlay_dirs.add(norm)
            parent = posixpath.dirname(norm)
            while parent and parent not in self.overlay_dirs:
                self.overlay_dirs.add(parent)
                nxt = posixpath.dirname(parent)
                if nxt == parent:
                    break
                parent = nxt

    def record_event(
        self,
        channel: Literal["exec", "shell", "sftp", "telnet", "auth"],
        command: str,
        *,
        matched: bool,
        exit_code: int | None = None,
        details: str = "",
    ) -> MockRequestEvent:
        """Зафиксировать обращение клиента в истории и вызвать ``on_request``."""
        event = MockRequestEvent(
            channel=channel,
            command=command,
            matched=matched,
            exit_code=exit_code,
            details=details,
        )
        self.history.append(event)
        if self.config.on_request is not None:
            self.config.on_request(event)
        return event

    def normalize_text(self, text: str) -> str:
        """Нормализовать временные пути ``/tmp/uniconn_XXXXXX`` при включённой опции."""
        if not text:
            return ""
        return normalize_temp_paths(text) if self.config.normalize_temp else text

    def normalize_path(self, path: str) -> str:
        """Нормализовать путь POSIX и временные директории."""
        raw = path.strip() or "."
        norm = posixpath.normpath(raw) if raw != "." else "."
        return self.normalize_text(norm)

    @staticmethod
    def unwrap_sudo(cmd: str) -> str:
        """Развернуть обёртку ``sudo -S -p '' -- sh -c '...'`` до исходной команды."""
        stripped = cmd.strip()
        if not _SUDO_WRAPPER_RE.match(stripped):
            return stripped
        marker = "-- sh -c "
        idx = stripped.find(marker)
        if idx == -1:
            return stripped
        inner = stripped[idx + len(marker) :].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in ("'", '"'):
            return inner[1:-1]
        return inner

    @staticmethod
    def unwrap_cd_env_prefix(cmd: str) -> str:
        """Извлечь основную команду, если клиент обернул её в ``cd ... && ...``."""
        stripped = cmd.strip()
        if stripped.startswith("cd ") and " && " in stripped:
            return stripped.split(" && ", 1)[1].strip()
        return stripped

    def match_exec(self, command: str) -> RecordedExecInteraction | None:
        """Найти подходящее ``RecordedExecInteraction`` (или синтезировать из ``stream``/``ping``)."""
        norm_cmd = self.normalize_text(command.strip())
        norm_unwrapped = self.normalize_text(self.unwrap_sudo(command))
        norm_bare = self.normalize_text(self.unwrap_cd_env_prefix(norm_unwrapped))
        candidates = {norm_cmd, norm_unwrapped, norm_bare}

        matched_repeat: RecordedExecInteraction | None = None

        for idx, item in enumerate(self.cassette.interactions):
            if not isinstance(item, RecordedExecInteraction):
                continue
            item_cmd = self.normalize_text(item.command.strip())
            item_unwrapped = self.normalize_text(self.unwrap_sudo(item.command))
            item_bare = self.normalize_text(self.unwrap_cd_env_prefix(item_unwrapped))
            if not candidates.intersection((item_cmd, item_unwrapped, item_bare)):
                continue

            if idx not in self._consumed_exec:
                self._consumed_exec.add(idx)
                return item
            matched_repeat = item

        if self.config.allow_repeats and matched_repeat is not None:
            return matched_repeat

        # Fallback на RecordedStreamInteraction, если команда записана как stream
        for item in self.cassette.interactions:
            if isinstance(item, RecordedStreamInteraction):
                item_cmd = self.normalize_text(item.command.strip())
                if item_cmd in candidates:
                    return RecordedExecInteraction(
                        command=item.command,
                        exit_code=1 if item.error_class else 0,
                        stdout="\n".join(item.lines) + ("\n" if item.lines else ""),
                        stderr=item.error_message or "",
                    )

        # Fallback для стандартного ping ("echo ping") в non-strict режиме
        if not self.config.strict_mode and norm_cmd == "echo ping":
            return RecordedExecInteraction(
                command="echo ping",
                exit_code=0,
                stdout="ping\n",
                stderr="",
            )

        return None

    def match_shell_session(self) -> RecordedShellInteraction | None:
        """Выбрать следующую интерактивную сессию ``RecordedShellInteraction`` из кассеты."""
        matched_repeat: RecordedShellInteraction | None = None
        for idx, item in enumerate(self.cassette.interactions):
            if not isinstance(item, RecordedShellInteraction):
                continue
            if idx not in self._consumed_shell:
                self._consumed_shell.add(idx)
                return item
            matched_repeat = item
        if self.config.allow_repeats and matched_repeat is not None:
            return matched_repeat
        return None

    def resolve_shell_input(
        self,
        raw_line: str,
        shell_interaction: RecordedShellInteraction | None,
        consumed_steps: set[int],
    ) -> tuple[str | None, int, bool]:
        """Сопоставить строку ввода в интерактивном шелле или Telnet-сессии.

        Поддерживает:
        1. Инициализацию ``PosixMarkerProtocol`` (``export PS1=''; stty -echo``).
        2. Команды с маркером ``__UNICONN_<hex>__$?``.
        3. Прямые шаги ``ShellDialogStep`` из ``RecordedShellInteraction``.
        4. Fallback на ``RecordedExecInteraction``.
        """
        stripped = raw_line.strip()
        if not stripped or stripped == "export PS1=''; stty -echo" or raw_line == "\x03":
            return None, 0, True

        marker_match = _POSIX_MARKER_CMD_RE.match(stripped)
        if marker_match is not None:
            inner_cmd = marker_match.group(1)
            marker_prefix = marker_match.group(2)
            out_text, code, matched = self._find_dialog_or_exec(
                inner_cmd, shell_interaction, consumed_steps
            )
            body = out_text if out_text.endswith("\n") or not out_text else f"{out_text}\n"
            payload = f"{body}{marker_prefix}{code}\n"
            self.record_event(
                "shell",
                inner_cmd,
                matched=matched,
                exit_code=code,
                details="posix-marker",
            )
            return payload, code, matched

        out_text, code, matched = self._find_dialog_or_exec(
            stripped, shell_interaction, consumed_steps
        )
        self.record_event("shell", stripped, matched=matched, exit_code=code)
        return out_text, code, matched

    def _find_dialog_or_exec(
        self,
        cmd: str,
        shell_interaction: RecordedShellInteraction | None,
        consumed_steps: set[int],
    ) -> tuple[str, int, bool]:
        norm_cmd = self.normalize_text(cmd.strip())
        if shell_interaction is not None:
            for idx, step in enumerate(shell_interaction.steps):
                if (
                    idx not in consumed_steps
                    and self.normalize_text(step.expect_input.strip()) == norm_cmd
                ):
                    consumed_steps.add(idx)
                    return step.response_output, step.exit_code, True
            if self.config.allow_repeats:
                for step in shell_interaction.steps:
                    if self.normalize_text(step.expect_input.strip()) == norm_cmd:
                        return step.response_output, step.exit_code, True

        # Поиск по всем RecordedShellInteraction кассеты
        for item in self.cassette.interactions:
            if isinstance(item, RecordedShellInteraction):
                for step in item.steps:
                    if self.normalize_text(step.expect_input.strip()) == norm_cmd:
                        return step.response_output, step.exit_code, True

        exec_match = self.match_exec(cmd)
        if exec_match is not None:
            out = exec_match.stdout
            if exec_match.stdout_base64 and not out:
                out = base64.b64decode(exec_match.stdout_base64).decode("utf-8", errors="replace")
            return out, exec_match.exit_code, True

        if self.config.strict_mode:
            return (
                f"uniconn mock: no matching interaction for: {cmd}\n",
                self.config.default_exit_code,
                False,
            )
        return "", self.config.default_exit_code, False

    def match_fs(
        self,
        operations: tuple[str, ...],
        path: str,
        *,
        consume: bool = True,
    ) -> RecordedFsInteraction | None:
        """Найти файловое взаимодействие ``RecordedFsInteraction`` по списку допустимых операций и пути."""
        norm_path = self.normalize_path(path)
        matched_repeat: RecordedFsInteraction | None = None

        for idx, item in enumerate(self.cassette.interactions):
            if not isinstance(item, RecordedFsInteraction):
                continue
            if item.operation not in operations:
                continue
            if self.normalize_path(item.path) != norm_path:
                continue
            if idx not in self._consumed_fs:
                if consume:
                    self._consumed_fs.add(idx)
                return item
            matched_repeat = item

        if (self.config.allow_repeats or not consume) and matched_repeat is not None:
            return matched_repeat
        return None

    def extract_fs_bytes(self, item: RecordedFsInteraction) -> bytes:
        """Извлечь байтовое содержимое файла из ``RecordedFsInteraction``."""
        if item.content_base64 is not None:
            return base64.b64decode(item.content_base64)
        if item.content_utf8 is not None:
            return item.content_utf8.encode("utf-8")
        return b""

    def resolve_sftp_stat(self, path: str) -> dict[str, int] | None:
        """Вычислить метаданные файла или директории (size, permissions) из сессионного оверлея или кассеты."""
        norm_path = self.normalize_path(path)
        if norm_path in self.deleted_paths:
            return None

        if norm_path in self.overlay_files:
            content = self.overlay_files[norm_path]
            mode = self.overlay_modes.get(norm_path, 0o644)
            perms = mode if stat_module.S_IFMT(mode) else (stat_module.S_IFREG | mode)
            return {"size": len(content), "permissions": perms}

        if norm_path in self.overlay_dirs:
            mode = self.overlay_modes.get(norm_path, 0o755)
            perms = mode if stat_module.S_IFMT(mode) else (stat_module.S_IFDIR | mode)
            return {"size": 4096, "permissions": perms}

        item = self.match_fs(("stat", "exists"), norm_path, consume=True)
        if item is None:
            item = self.match_fs(
                ("read_file", "download", "write_file", "upload"),
                norm_path,
                consume=False,
            )
        if item is not None:
            if item.operation == "exists" and item.result_bool is False:
                return None
            if item.result_stat:
                sz = int(item.result_stat.get("size") or 0)
                raw_perms = item.result_stat.get("permissions")
                if isinstance(raw_perms, str):
                    mode = int(raw_perms, 8)
                elif isinstance(raw_perms, int):
                    mode = raw_perms
                else:
                    mode = 0o755 if item.result_stat.get("is_dir") else 0o644
                if not stat_module.S_IFMT(mode):
                    flag = stat_module.S_IFDIR if item.result_stat.get("is_dir") else stat_module.S_IFREG
                    mode |= flag
                return {"size": sz, "permissions": mode}

            raw_bytes = self.extract_fs_bytes(item)
            base_mode = self.overlay_modes.get(norm_path, item.mode or 0o644)
            perms = base_mode if stat_module.S_IFMT(base_mode) else (stat_module.S_IFREG | base_mode)
            return {"size": len(raw_bytes), "permissions": perms}

        # Проверить, не упоминается ли файл внутри записанного listdir родительской папки
        parent = posixpath.dirname(norm_path) or "."
        basename = posixpath.basename(norm_path)
        listdir_item = self.match_fs(("listdir",), parent, consume=False)
        if listdir_item is not None and basename in listdir_item.result_list:
            return {"size": 0, "permissions": stat_module.S_IFREG | 0o644}

        return None


__all__ = [
    "CassetteInteractionMatcher",
    "MockRequestEvent",
    "MockServerConfig",
]
