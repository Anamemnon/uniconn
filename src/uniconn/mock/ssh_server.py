# src/uniconn/mock/ssh_server.py
"""Ядро сокетного Mock SSH-сервера на базе asyncssh (аутентификация, exec, pty/shell)."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

import asyncssh

from ..transports.replay.models import (
    Cassette,
    RecordedExecInteraction,
    RecordedShellInteraction,
)
from .config import CassetteInteractionMatcher, MockServerConfig


class MockSSHServerInterface(asyncssh.SSHServer):
    """Интерфейс сервера ``asyncssh``: управление аутентификацией и запросами каналов."""

    def __init__(
        self,
        config: MockServerConfig,
        cassette: Cassette,
        *,
        matcher: CassetteInteractionMatcher | None = None,
        active_connections: set[asyncssh.SSHServerConnection] | None = None,
    ) -> None:
        """Инициализировать серверный интерфейс для нового подключения."""
        self.config = config
        self.cassette = cassette
        self.matcher = matcher or CassetteInteractionMatcher(config, cassette)
        self._conn: asyncssh.SSHServerConnection | None = None
        self._active_connections = active_connections

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Сохранить ссылку на установленное серверное соединение."""
        self._conn = conn
        if self._active_connections is not None:
            self._active_connections.add(conn)

    def connection_lost(self, exc: Exception | None) -> None:
        """Удалить соединение из набора активных при отключении клиента."""
        if self._conn is not None and self._active_connections is not None:
            self._active_connections.discard(self._conn)
        self._conn = None

    def begin_auth(self, username: str) -> bool:
        """Определить, требуется ли проверка учётных данных для ``username``."""
        if (
            self.config.allow_any_auth
            and self.config.username is None
            and self.config.password is None
        ):
            self.matcher.record_event("auth", f"user={username}", matched=True, exit_code=0)
            return False
        return True

    def password_auth_supported(self) -> bool:
        """Разрешить аутентификацию по паролю."""
        return True

    def public_key_auth_supported(self) -> bool:
        """Разрешить аутентификацию по публичному ключу."""
        return True

    def password_auth_requested(self, username: str, password: str) -> bool:
        """Проверить логин и пароль клиента."""
        if (
            self.config.allow_any_auth
            and self.config.username is None
            and self.config.password is None
        ):
            self.matcher.record_event("auth", f"password:{username}", matched=True, exit_code=0)
            return True
        user_ok = self.config.username is None or username == self.config.username
        pass_ok = self.config.password is None or password == self.config.password
        ok = bool(user_ok and pass_ok)
        self.matcher.record_event(
            "auth",
            f"password:{username}",
            matched=ok,
            exit_code=0 if ok else 1,
        )
        return ok

    def validate_password(self, username: str, password: str) -> bool:
        """Стандартный хук ``asyncssh.SSHServer`` для проверки пароля."""
        return self.password_auth_requested(username, password)

    def public_key_auth_requested(self, username: str, key: Any) -> bool:
        """Проверить публичный ключ клиента."""
        if self.config.allow_any_auth and self.config.password is None:
            user_ok = self.config.username is None or username == self.config.username
            self.matcher.record_event(
                "auth",
                f"publickey:{username}",
                matched=user_ok,
                exit_code=0 if user_ok else 1,
            )
            return user_ok
        return False

    def validate_public_key(self, username: str, key: Any) -> bool:
        """Стандартный хук ``asyncssh.SSHServer`` для проверки публичного ключа."""
        return self.public_key_auth_requested(username, key)

    def session_requested(self) -> MockSSHServerSession:
        """Создать и вернуть ``MockSSHServerSession`` для нового SSH-канала."""
        from .sftp_server import MockSFTPServer

        return MockSSHServerSession(
            self.cassette,
            self.config,
            matcher=self.matcher,
            sftp_factory=lambda chan: MockSFTPServer(
                chan,
                self.cassette,
                matcher=self.matcher,
                config=self.config,
            ),
        )

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        """Разрешить запросы обратного проброса портов (remote port forwarding)."""
        return True

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        """Разрешить запросы прямого проброса портов (local port forwarding)."""
        return True


class MockSSHServerSession(asyncssh.SSHServerSession[Any]):
    """Обработчик сессии канала SSH: выполнение ``exec``, ``pty``, ``shell`` и подсистемы ``sftp``."""

    def __init__(
        self,
        cassette: Cassette,
        config: MockServerConfig,
        *,
        matcher: CassetteInteractionMatcher | None = None,
        sftp_factory: Any = None,
    ) -> None:
        """Инициализировать сессию канала SSH."""
        self.cassette = cassette
        self.config = config
        self.matcher = matcher or CassetteInteractionMatcher(config, cassette)
        self._sftp_factory = sftp_factory
        self._sftp_stream: Any = None
        self._chan: Any = None
        self._pending_exec: str | None = None
        self._in_shell: bool = False
        self._shell_interaction: RecordedShellInteraction | None = None
        self._consumed_steps: set[int] = set()
        self._line_buffer: str = ""
        self.term_type: str = "xterm"
        self.term_size: tuple[int, int] = (80, 24)
        self._env: dict[str, str] = {}

    def connection_made(self, chan: asyncssh.SSHServerChannel[Any]) -> None:
        """Привязать открытый канал SSH к сессии."""
        self._chan = chan

    def connection_lost(self, exc: Exception | None) -> None:
        """Обработать закрытие канала SSH."""
        if self._sftp_stream is not None:
            self._sftp_stream.connection_lost(exc)

    def env_requested(self, name: bytes | str, value: bytes | str) -> bool:
        """Принять переменные окружения, переданные клиентом по каналу SSH."""
        k = name.decode("utf-8", errors="replace") if isinstance(name, bytes) else str(name)
        v = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
        self._env[k] = v
        return True

    def pty_requested(
        self,
        term_type: str,
        term_size: tuple[int, int, int, int],
        term_modes: Mapping[int, int],
    ) -> bool:
        """Подтвердить выделение виртуального терминала PTY."""
        self.term_type = term_type or "xterm"
        if len(term_size) >= 2:
            self.term_size = (int(term_size[0]), int(term_size[1]))
        return True

    def terminal_size_changed(
        self,
        width: int,
        height: int,
        pixwidth: int = 0,
        pixheight: int = 0,
    ) -> None:
        """Обновить размеры терминала при получении сигнала ``window-change``."""
        self.term_size = (int(width), int(height))

    def _find_exec_interaction(self, command: str) -> RecordedExecInteraction | None:
        """Найти подходящее ``RecordedExecInteraction`` в кассете."""
        return self.matcher.match_exec(command)

    def _find_shell_interaction(self) -> RecordedShellInteraction | None:
        """Найти подходящее ``RecordedShellInteraction`` в кассете."""
        return self.matcher.match_shell_session()

    def subsystem_requested(self, subsystem: str) -> bool:
        """Обработать запрос запуска подсистемы (например, ``sftp``)."""
        if subsystem == "sftp" and self._sftp_factory is not None and self._chan is not None:
            from asyncssh.stream import SSHServerStreamSession

            self._sftp_stream = SSHServerStreamSession(
                None,
                sftp_factory=self._sftp_factory,
                sftp_version=3,
            )
            self._sftp_stream.connection_made(self._chan)
            return bool(self._sftp_stream.subsystem_requested(subsystem))
        return False

    def exec_requested(self, command: str) -> bool:
        """Обработать запрос удалённого выполнения команды (``ssh host 'cmd'``)."""
        self._pending_exec = command
        if self._chan is not None and not isinstance(self._chan, asyncssh.SSHServerChannel):
            self._run_pending_exec()
        return True

    def shell_requested(self) -> bool:
        """Обработать запрос открытия интерактивной оболочки ``shell``."""
        self._in_shell = True
        self._shell_interaction = self._find_shell_interaction()
        return True

    def session_started(self) -> None:
        """Выполнить отложенную команду ``exec`` или запустить SFTP-поток."""
        if self._sftp_stream is not None:
            self._sftp_stream.session_started()
            return
        if self._pending_exec is not None:
            self._run_pending_exec()

    def _write_out(self, data: str | bytes) -> None:
        if self._chan is None:
            return
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
            self._chan.write(text)
        else:
            self._chan.write(data)

    def _write_err(self, data: str) -> None:
        if self._chan is None or not data:
            return
        self._chan.write_stderr(data)

    def _run_pending_exec(self) -> None:
        command = self._pending_exec
        self._pending_exec = None
        if command is None or self._chan is None:
            return

        interaction = self._find_exec_interaction(command)
        if interaction is None:
            self.matcher.record_event(
                "exec",
                command,
                matched=False,
                exit_code=self.config.default_exit_code,
            )
            if self.config.strict_mode:
                self._write_err(f"uniconn mock: no matching interaction for: {command}\n")
            else:
                self._write_err(f"mock: command not found: {command}\n")
            self._chan.exit(self.config.default_exit_code)
            return

        if interaction.error_class:
            err_msg = interaction.error_message or interaction.error_class
            self.matcher.record_event("exec", command, matched=True, exit_code=1, details=err_msg)
            self._write_err(f"{interaction.error_class}: {err_msg}\n")
            self._chan.exit(interaction.exit_code or 1)
            return

        if interaction.stdout_base64 is not None and not interaction.stdout:
            raw_bytes = base64.b64decode(interaction.stdout_base64)
            self._write_out(raw_bytes)
        elif interaction.stdout:
            self._write_out(interaction.stdout)

        if interaction.stderr:
            self._write_err(interaction.stderr)

        self.matcher.record_event(
            "exec",
            command,
            matched=True,
            exit_code=interaction.exit_code,
        )
        self._chan.exit(interaction.exit_code)

    def data_received(self, data: str | bytes, datatype: asyncssh.DataType) -> None:
        """Обработать входящие данные в интерактивной PTY/shell или SFTP сессии."""
        if self._sftp_stream is not None:
            self._sftp_stream.data_received(data, datatype)
            return
        if not self._in_shell or self._chan is None:
            return

        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
        if text == "\x03":
            return

        self._line_buffer += text
        while "\n" in self._line_buffer or "\r" in self._line_buffer:
            sep_n = self._line_buffer.find("\n")
            sep_r = self._line_buffer.find("\r")
            if sep_n == -1:
                idx = sep_r
            elif sep_r == -1:
                idx = sep_n
            else:
                idx = min(sep_n, sep_r)

            line = self._line_buffer[:idx]
            rest = self._line_buffer[idx + 1 :]
            if rest.startswith("\n") and self._line_buffer[idx] == "\r":
                rest = rest[1:]
            self._line_buffer = rest
            self._handle_shell_line(line)

    def _handle_shell_line(self, line: str) -> None:
        if self._chan is None:
            return
        stripped = line.strip()
        if stripped in ("exit", "logout"):
            self._write_out("logout\n")
            self._chan.exit(0)
            return

        out_text, _code, _matched = self.matcher.resolve_shell_input(
            line,
            self._shell_interaction,
            self._consumed_steps,
        )
        if out_text:
            self._write_out(out_text)

    def eof_received(self) -> bool:
        """Обработать закрытие входного потока клиентом."""
        if self._sftp_stream is not None:
            return bool(self._sftp_stream.eof_received())
        if self._line_buffer.strip():
            rem = self._line_buffer
            self._line_buffer = ""
            self._handle_shell_line(rem)
        if self._in_shell and self._chan is not None:
            self._chan.exit(0)
        return False

    def pause_writing(self) -> None:
        """Приостановить запись при заполнении буфера канала."""
        if self._sftp_stream is not None:
            self._sftp_stream.pause_writing()

    def resume_writing(self) -> None:
        """Возобновить запись при освобождении буфера канала."""
        if self._sftp_stream is not None:
            self._sftp_stream.resume_writing()


__all__ = [
    "MockSSHServerInterface",
    "MockSSHServerSession",
]
