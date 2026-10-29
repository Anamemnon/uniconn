# src/uniconn/shell/marker_protocol.py
"""Маркерный POSIX-протокол для определения границ вывода и кода возврата в PTY-потоке."""

from __future__ import annotations

import re
import uuid


class PosixMarkerProtocol:
    """Форматирует команды с маркером завершения и очищает вывод от терминального эха."""

    def __init__(self, session_uuid: str | None = None) -> None:
        """Инициализировать протокол с уникальным маркером сессии."""
        self.uuid = session_uuid or uuid.uuid4().hex[:12]
        self.pattern = re.compile(rf"(?:\\n)?__UNICONN_{re.escape(self.uuid)}__(\d+)")

    def wrap_command(self, cmd_str: str) -> str:
        """Обернуть команду в выражение с выводом маркера и кода возврата ``$?``."""
        return f'{cmd_str}; echo "\\n__UNICONN_{self.uuid}__$?"\n'

    def search(self, buffer: str) -> re.Match[str] | None:
        """Найти маркер завершения в накопленном буфере."""
        return self.pattern.search(buffer)

    @staticmethod
    def clean_output(raw_output: str, command: str, wrapped_cmd: str) -> str:
        """Очистить вывод от CRLF, возможного эха команды и лишнего перевода строки."""
        normalized = raw_output.replace("\r\n", "\n")

        lines = normalized.split("\n")
        if lines:
            first_line = lines[0].strip()
            wrapped_stripped = wrapped_cmd.strip()
            if (
                first_line == wrapped_stripped
                or first_line == command.strip()
                or (command.strip() and first_line.startswith(f"{command.strip()}; echo"))
            ):
                lines = lines[1:]
        cleaned = "\n".join(lines)

        if cleaned.endswith("\\n"):
            cleaned = cleaned[:-2]
        if cleaned.endswith("\n"):
            cleaned = cleaned[:-1]

        return cleaned
