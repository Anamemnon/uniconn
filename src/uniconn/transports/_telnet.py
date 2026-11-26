# src/uniconn/transports/_telnet.py
"""Telnet транспорт на базе telnetlib3 с поддержкой POSIX/CLI режимов и OOB-консолей.

Поддерживает:
    - Аутентификацию по логину/паролю
    - Автоопределение режима оболочки (``shell_mode=auto|posix|cli``)
    - Режим ``posix`` на базе ``PosixMarkerProtocol`` с точным ``exit_code`` и границами вывода
    - Режим ``cli`` для сетевого оборудования и OOB-консолей:
      профили (``generic``, ``cisco``, ``junos``, ``linux``, ``uboot``),
      кастомный ``prompt_regex``, автоматическую пагинацию (``--More--``),
      очистку ANSI/CR-последовательностей и детекцию CLI-ошибок
    - Интерактивные сессии (``open_shell``) и потоковый вывод (``stream``)

Пример URI:
    telnet://user:pass@host:23
    telnet://host?timeout=30&term_type=vt100&shell_mode=posix
    telnet://admin:pass@sw01?shell_mode=cli&profile=cisco&pagination=true
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import re
import time
from collections.abc import AsyncIterator
from typing import Any

from .._utils import parse_bool
from ..exceptions import (
    AuthenticationError,
    ConfigurationError,
    ConnectionError,
    ExecutionError,
)
from ..exceptions import (
    TimeoutError as UniconnTimeoutError,
)
from ..result import Result
from ..shell.marker_protocol import PosixMarkerProtocol
from ._telnet_cli import (
    _CLI_PROFILES,
    _LEGACY_PROMPTS,
    _apply_cr_overwrite,
    _can_use_chunk_read,
    _compile_error_patterns,
    _detect_cli_errors,
    _has_cli_prompt_at_end,
    _is_echo_line,
    _is_prompt_line,
    _resolve_cli_options,
    _strip_cli_echo_and_prompt,
    _strip_terminal_noise,
    _TelnetCliOptions,
    _validate_shell_mode,
)
from .base import BaseTransport

# Импорт опциональный (extra dependency)
try:
    import telnetlib3
except ImportError:
    telnetlib3 = None  # type: ignore


class _TelnetShellProcess:
    """Адаптер Telnet reader/writer для работы с ``ShellSession``."""

    def __init__(
        self,
        reader: Any,
        writer: Any,
        term_size: tuple[int, int] = (80, 24),
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.stdin = writer
        self.stdout = reader
        self.term_size = term_size
        self.returncode: int | None = None
        self.terminated = False
        self.closed = False

    def change_terminal_size(self, cols: int, rows: int) -> None:
        self.term_size = (cols, rows)

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def close(self) -> None:
        self.closed = True
        self.returncode = 0


class TelnetTransport(BaseTransport):
    """Telnet транспорт для выполнения команд через Telnet протокол (POSIX и CLI/OOB)."""

    def __init__(self, config: Any) -> None:
        if telnetlib3 is None:
            raise ImportError(
                "telnetlib3 not installed. "
                "Run: pip install uniconn[telnet]"
            )
        super().__init__(config)
        opts = getattr(config, "options", {}) or {}

        shell_mode = _validate_shell_mode(opts.get("shell_mode", "auto"))
        profile_name = str(opts.get("profile", "generic")).strip().lower() or "generic"
        if profile_name not in _CLI_PROFILES:
            raise ConfigurationError(
                f"Unsupported telnet profile {profile_name!r}. "
                f"Supported: {', '.join(sorted(_CLI_PROFILES))}"
            )

        profile = _CLI_PROFILES[profile_name]
        self._shell_mode: str = shell_mode
        self._resolved_shell_mode: str | None = None if shell_mode == "auto" else shell_mode
        self._profile_name: str = profile_name
        self._cli_defaults = _TelnetCliOptions(
            prompt_regex=re.compile(str(opts.get("prompt_regex") or profile.prompt_regex)),
            pagination=parse_bool(opts.get("pagination"), default=True),
            pager_regex=re.compile(
                str(opts.get("pager_regex") or profile.pager_regex),
                re.IGNORECASE,
            ),
            pager_response=str(opts.get("pager_response", profile.pager_response)),
            error_patterns=_compile_error_patterns(
                opts.get("error_patterns"),
                profile.error_patterns,
            ),
            strip_ansi=parse_bool(opts.get("strip_ansi"), default=True),
        )
        self._probe_timeout: float = float(opts.get("probe_timeout", 2.0))

        self._reader: Any = None
        self._writer: Any = None
        self._rx_buffer: str = ""
        self._shell_procs: list[_TelnetShellProcess] = []
        self._shell_prompt: str = "$ "
        self._login_prompt: str = "login: "
        self._password_prompt: str = "Password: "
        self._marker_protocol = PosixMarkerProtocol()

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "telnet"

    @property
    def shell_mode(self) -> str:
        """Настроенный режим выполнения команд (``auto``, ``posix`` или ``cli``)."""
        return self._shell_mode

    @property
    def resolved_shell_mode(self) -> str | None:
        """Фактически определённый режим сессии (``posix`` или ``cli``; ``None`` до автоопределения)."""
        return self._resolved_shell_mode

    def _write_text(self, text: str) -> None:
        """Отправить текстовую строку в Telnet writer (поддерживает str и bytes writer)."""
        if self._writer is None:
            raise ConnectionError("Not connected", host=self.config.host)
        try:
            self._writer.write(text)
        except TypeError:
            self._writer.write(text.encode("utf-8"))

    async def _drain_writer(self) -> None:
        """Дождаться отправки буфера записи."""
        if self._writer is None:
            return
        drain_fn = getattr(self._writer, "drain", None)
        if callable(drain_fn):
            res = drain_fn()
            if inspect.isawaitable(res):
                await res

    @staticmethod
    def _decode_chunk(data: Any) -> str:
        if not data:
            return ""
        if isinstance(data, bytes | bytearray):
            return bytes(data).decode("utf-8", errors="replace")
        return str(data)

    async def _read_chunk(self, size: int, timeout: float) -> str:
        """Прочитать очередную порцию текста (сначала из остатка ``_rx_buffer``, затем из ``reader.read``)."""
        if self._rx_buffer:
            buffered = self._rx_buffer
            self._rx_buffer = ""
            return buffered
        if self._reader is None:
            raise ConnectionError("Not connected", host=self.config.host)
        raw = await asyncio.wait_for(self._reader.read(size), timeout=timeout)
        return self._decode_chunk(raw)

    def _stash_after_marker_line(self, tail: str) -> None:
        """Сохранить в ``_rx_buffer`` непрочитанные данные после строки с POSIX-маркером (кроме idle-промпта)."""
        if not tail:
            return
        nl_idx = tail.find("\n")
        remainder = tail[nl_idx + 1 :] if nl_idx != -1 else tail
        if not remainder or not remainder.strip():
            return
        cleaned = _strip_terminal_noise(remainder)
        if "\n" not in cleaned and _is_prompt_line(cleaned, self._cli_defaults.prompt_regex):
            return
        self._rx_buffer = remainder + self._rx_buffer

    async def connect(self) -> None:
        """Установить Telnet подключение и выполнить аутентификацию."""
        if telnetlib3 is None:
            raise ImportError(
                "telnetlib3 is required for TelnetTransport. Install with: pip install uniconn[telnet]"
            )
        port = self.config.port or 23
        try:
            host = self.config.host
            timeout = self.config.timeout

            logging.getLogger("uniconn").warning(
                "Telnet — незашифрованный протокол: трафик и учётные данные "
                "передаются в открытом виде. Рекомендуется использовать SSH."
            )

            self._reader, self._writer = await asyncio.wait_for(
                telnetlib3.open_connection(
                    host=host,
                    port=port,
                    term=self.config.options.get("term_type", "xterm-256color"),
                    cols=self.config.options.get("term_cols", 80),
                    rows=self.config.options.get("term_rows", 24),
                ),
                timeout=timeout,
            )

            if self.config.username:
                await self._authenticate()

            self._connected = True

        except AuthenticationError:
            await self.disconnect()
            raise
        except TimeoutError as e:
            await self.disconnect()
            raise ConnectionError(
                f"Telnet connection timeout to {self.config.host}:{port}",
                host=self.config.host,
            ) from e
        except Exception as e:
            await self.disconnect()
            raise ConnectionError(
                f"Telnet connection failed: {e}",
                host=self.config.host,
            ) from e

    async def _authenticate(self) -> None:
        """Выполнить аутентификацию через login/password prompts."""
        if not self._reader or not self._writer:
            return

        username = self.config.username or ""
        password = (
            self.config.password.get_secret_value()
            if self.config.password
            else ""
        )
        auth_fail_markers = (
            "login incorrect",
            "authentication failed",
            "access denied",
            "permission denied",
            "invalid password",
            "bad password",
            "invalid credentials",
        )

        try:
            data = await asyncio.wait_for(self._reader.read(4096), timeout=5.0)
            text_data = self._decode_chunk(data)

            if "login" in text_data.lower() or "username" in text_data.lower():
                self._write_text(username + "\n")
                await self._drain_writer()

                data = await asyncio.wait_for(self._reader.read(4096), timeout=5.0)
                text_data = self._decode_chunk(data)

            if "password" in text_data.lower():
                self._write_text(password + "\n")
                await self._drain_writer()

                post_data = await asyncio.wait_for(self._reader.read(4096), timeout=5.0)
                post_text = self._decode_chunk(post_data)
                post_lower = post_text.lower()
                if (
                    any(marker in post_lower for marker in auth_fail_markers)
                    or post_lower.rstrip().endswith(("login:", "username:", "password:"))
                ):
                    raise AuthenticationError(
                        f"Telnet authentication rejected by {self.config.host}",
                        host=self.config.host,
                    )

        except TimeoutError as e:
            raise AuthenticationError(
                "Telnet authentication timeout",
                host=self.config.host,
            ) from e

    async def disconnect(self) -> None:
        """Закрыть Telnet подключение и активные shell-сессии."""
        try:
            while self._shell_procs:
                proc = self._shell_procs.pop()
                with contextlib.suppress(Exception):
                    proc.terminate()
                    proc.close()
            if self._writer:
                with contextlib.suppress(Exception):
                    self._writer.close()
                with contextlib.suppress(Exception):
                    wait_closed = getattr(self._writer, "wait_closed", None)
                    if callable(wait_closed):
                        res = wait_closed()
                        if inspect.isawaitable(res):
                            await res
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            self._rx_buffer = ""
            if self._shell_mode == "auto":
                self._resolved_shell_mode = None

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> _TelnetShellProcess:
        """Открыть stateful shell-сессию поверх активного Telnet-потока."""
        if not self._connected or not self._reader or not self._writer:
            raise ConnectionError(
                "Telnet transport is not connected. Call connect() first",
                host=self.config.host,
            )
        proc = _TelnetShellProcess(
            self._reader,
            self._writer,
            term_size=term_size,
        )
        self._shell_procs.append(proc)
        return proc

    async def _resolve_shell_mode(
        self,
        requested_mode: str,
        cmd_timeout: float,
    ) -> str:
        """Определить режим работы (``posix`` или ``cli``), выполнив безопасный пробник при ``auto``."""
        if requested_mode in ("posix", "cli"):
            return requested_mode

        if self._resolved_shell_mode is not None:
            return self._resolved_shell_mode

        if not _can_use_chunk_read(self._reader):
            self._resolved_shell_mode = "cli"
            return "cli"

        probe_proto = PosixMarkerProtocol()
        probe_cmd = probe_proto.wrap_command(":")
        self._write_text(probe_cmd)
        await self._drain_writer()

        probe_limit = min(self._probe_timeout, max(0.2, cmd_timeout))
        deadline = time.monotonic() + probe_limit
        buf = ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._resolved_shell_mode = "cli"
                return "cli"
            try:
                chunk = await self._read_chunk(4096, remaining)
            except TimeoutError:
                self._resolved_shell_mode = "cli"
                return "cli"
            if not chunk:
                self._resolved_shell_mode = "cli"
                return "cli"

            buf += chunk
            match = probe_proto.search(buf)
            if match is not None:
                self._stash_after_marker_line(buf[match.end() :])
                self._resolved_shell_mode = "posix"
                return "posix"

            clean_buf = _strip_terminal_noise(buf)
            lines = clean_buf.split("\n")
            if len(lines) > 1:
                has_cli_err = any(
                    pat.search(line.strip())
                    for line in lines[1:]
                    for pat in self._cli_defaults.error_patterns
                    if line.strip()
                )
                if has_cli_err or _has_cli_prompt_at_end(
                    clean_buf,
                    probe_cmd.strip(),
                    self._cli_defaults.prompt_regex,
                    strip_ansi=False,
                ):
                    self._resolved_shell_mode = "cli"
                    return "cli"

    def _clean_posix_output(
        self,
        raw_output: str,
        command: str,
        wrapped_cmd: str,
        *,
        strip_ansi: bool,
    ) -> str:
        """Очистить вывод POSIX-команды от ANSI, ведущих пустых/промпт-строк и эха."""
        text = _strip_terminal_noise(raw_output) if strip_ansi else _apply_cr_overwrite(raw_output)
        lines = text.split("\n")

        cmd_stripped = command.strip()
        wrapped_stripped = wrapped_cmd.strip()
        prompt_regex = self._cli_defaults.prompt_regex

        # Пропускаем ведущие пустые строки или отдельно пришедший промпт от предыдущей команды
        idx = 0
        while idx < len(lines):
            cur = lines[idx]
            cur_stripped = cur.strip()
            if not cur_stripped:
                idx += 1
                continue
            if (
                cur_stripped in (wrapped_stripped, cmd_stripped)
                or (wrapped_stripped and wrapped_stripped in cur)
                or (cmd_stripped and f"{cmd_stripped}; echo" in cur)
            ):
                idx += 1
                break
            if _is_prompt_line(cur, prompt_regex):
                idx += 1
                continue
            break

        return PosixMarkerProtocol.clean_output("\n".join(lines[idx:]), command, wrapped_cmd)

    async def _run_posix(
        self,
        command: str,
        cmd_timeout: float,
        *,
        strip_ansi: bool,
        start_time: float,
    ) -> Result:
        """Выполнить команду в POSIX-режиме через ``PosixMarkerProtocol`` с реальным ``exit_code``."""
        proto = self._marker_protocol
        wrapped = proto.wrap_command(command)
        self._write_text(wrapped)
        await self._drain_writer()

        deadline = time.monotonic() + cmd_timeout
        buf = ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UniconnTimeoutError(
                    f"Telnet command timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                )
            try:
                chunk = await self._read_chunk(4096, remaining)
            except TimeoutError:
                raise UniconnTimeoutError(
                    f"Telnet command timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                ) from None

            if not chunk:
                break

            buf += chunk
            match = proto.search(buf)
            if match is not None:
                exit_code = int(match.group(1))
                raw_output = buf[: match.start()]
                self._stash_after_marker_line(buf[match.end() :])
                stdout = self._clean_posix_output(
                    raw_output,
                    command,
                    wrapped,
                    strip_ansi=strip_ansi,
                )
                return Result(
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr="",
                    duration=time.monotonic() - start_time,
                    command=command,
                    host=self.config.host,
                )

        raise ConnectionError(
            f"Telnet connection closed before command completion: {command!r}",
            command=command,
            host=self.config.host,
        )

    async def _handle_pager_if_present(
        self,
        buf: str,
        cli_opts: _TelnetCliOptions,
    ) -> tuple[str, bool]:
        """Распознать запрос пагинации в хвосте буфера, вырезать его и отправить отклик."""
        if not cli_opts.pagination:
            return buf, False
        tail_start = max(0, len(buf) - 256)
        tail = buf[tail_start:]
        pager_match = cli_opts.pager_regex.search(tail)
        if pager_match is None:
            return buf, False
        abs_start = tail_start + pager_match.start()
        abs_end = tail_start + pager_match.end()
        new_buf = buf[:abs_start] + buf[abs_end:]
        self._write_text(cli_opts.pager_response)
        await self._drain_writer()
        return new_buf, True

    async def _run_cli_chunked(
        self,
        command: str,
        cmd_timeout: float,
        cli_opts: _TelnetCliOptions,
        *,
        start_time: float,
    ) -> Result:
        """Выполнить команду в CLI/OOB режиме с почанковым чтением и обработкой пагинации."""
        self._write_text(command + "\n")
        await self._drain_writer()

        deadline = time.monotonic() + cmd_timeout
        buf = ""
        cmd_stripped = command.strip()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UniconnTimeoutError(
                    f"Telnet command timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                )
            try:
                chunk = await self._read_chunk(4096, remaining)
            except TimeoutError:
                raise UniconnTimeoutError(
                    f"Telnet command timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                ) from None

            if not chunk:
                break

            buf += chunk
            buf, paged = await self._handle_pager_if_present(buf, cli_opts)
            if paged:
                continue

            if _has_cli_prompt_at_end(
                buf,
                cmd_stripped,
                cli_opts.prompt_regex,
                strip_ansi=cli_opts.strip_ansi,
            ):
                break

        stdout_lines = _strip_cli_echo_and_prompt(
            buf,
            command,
            cli_opts.prompt_regex,
            strip_ansi=cli_opts.strip_ansi,
        )
        exit_code, stderr = _detect_cli_errors(stdout_lines, cli_opts.error_patterns)
        return Result(
            exit_code=exit_code,
            stdout="\n".join(stdout_lines),
            stderr=stderr,
            duration=time.monotonic() - start_time,
            command=command,
            host=self.config.host,
        )

    async def _run_cli_lines(
        self,
        command: str,
        cmd_timeout: float,
        cli_opts: _TelnetCliOptions,
        *,
        start_time: float,
    ) -> Result:
        """Построчный CLI-режим для совместимости с line-oriented моками ``reader.readline()``."""
        self._write_text(command + "\n")
        await self._drain_writer()

        output_lines: list[str] = []
        while True:
            try:
                line = await asyncio.wait_for(self._reader.readline(), timeout=cmd_timeout)
                if not line:
                    break

                raw_line = self._decode_chunk(line)
                if cli_opts.strip_ansi:
                    raw_line = _strip_terminal_noise(raw_line)
                decoded = raw_line.rstrip()
                output_lines.append(decoded)

                stripped_eol = raw_line.rstrip("\r\n")
                if _is_prompt_line(stripped_eol, cli_opts.prompt_regex) and len(output_lines) > 1:
                    break
            except TimeoutError:
                raise UniconnTimeoutError(
                    f"Telnet command timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                ) from None

        stdout_lines = [
            line
            for line in output_lines
            if line.strip() != command.strip() and not _is_prompt_line(line, cli_opts.prompt_regex)
        ]
        exit_code, stderr = _detect_cli_errors(stdout_lines, cli_opts.error_patterns)
        return Result(
            exit_code=exit_code,
            stdout="\n".join(stdout_lines),
            stderr=stderr,
            duration=time.monotonic() - start_time,
            command=command,
            host=self.config.host,
        )

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду через Telnet (в POSIX или CLI/OOB режиме)."""
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self.config.host)

        start_time = time.monotonic()
        cmd_timeout = float(timeout if timeout is not None else self.config.timeout)
        req_mode = _validate_shell_mode(kwargs.get("shell_mode", self._shell_mode))
        cli_opts = _resolve_cli_options(self._cli_defaults, kwargs)

        try:
            mode = await self._resolve_shell_mode(req_mode, cmd_timeout)
            use_chunks = _can_use_chunk_read(self._reader)

            if mode == "posix" and use_chunks:
                return await self._run_posix(
                    command,
                    cmd_timeout,
                    strip_ansi=cli_opts.strip_ansi,
                    start_time=start_time,
                )

            if use_chunks:
                return await self._run_cli_chunked(
                    command,
                    cmd_timeout,
                    cli_opts,
                    start_time=start_time,
                )

            return await self._run_cli_lines(
                command,
                cmd_timeout,
                cli_opts,
                start_time=start_time,
            )

        except (UniconnTimeoutError, ConnectionError, ConfigurationError):
            raise
        except Exception as e:
            raise ExecutionError(
                f"Telnet command execution failed: {e}",
                command=command,
                host=self.config.host,
            ) from e

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое выполнение команды через Telnet с поддержкой пагинации и ``prompt_regex``."""
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self.config.host)

        cmd_timeout = float(timeout if timeout is not None else self.config.timeout)
        cli_opts = _resolve_cli_options(self._cli_defaults, kwargs)

        self._write_text(command + "\n")
        await self._drain_writer()

        if not _can_use_chunk_read(self._reader):
            while True:
                try:
                    line = await asyncio.wait_for(self._reader.readline(), timeout=cmd_timeout)
                    if not line:
                        break
                    raw_line = self._decode_chunk(line)
                    if cli_opts.strip_ansi:
                        raw_line = _strip_terminal_noise(raw_line)
                    decoded = raw_line.rstrip()
                    if decoded.strip() == command.strip():
                        continue
                    if _is_prompt_line(raw_line.rstrip("\r\n"), cli_opts.prompt_regex):
                        break
                    yield decoded
                except TimeoutError:
                    raise UniconnTimeoutError(
                        f"Telnet stream timeout after {cmd_timeout}s: {command!r}",
                        command=command,
                        host=self.config.host,
                    ) from None
            return

        buf = ""
        echo_skipped = False
        cmd_stripped = command.strip()

        while True:
            try:
                chunk = await self._read_chunk(4096, cmd_timeout)
            except TimeoutError:
                raise UniconnTimeoutError(
                    f"Telnet stream timeout after {cmd_timeout}s: {command!r}",
                    command=command,
                    host=self.config.host,
                ) from None

            if not chunk:
                if buf.strip():
                    rem = _strip_terminal_noise(buf) if cli_opts.strip_ansi else _apply_cr_overwrite(buf)
                    rem_clean = rem.rstrip("\n")
                    if rem_clean and not _is_prompt_line(rem_clean, cli_opts.prompt_regex):
                        yield rem_clean.rstrip()
                break

            buf += chunk
            buf, _ = await self._handle_pager_if_present(buf, cli_opts)

            normalized = buf.replace("\r\n", "\n")
            while "\n" in normalized:
                raw_line, normalized = normalized.split("\n", 1)
                clean_line = (
                    _strip_terminal_noise(raw_line)
                    if cli_opts.strip_ansi
                    else _apply_cr_overwrite(raw_line)
                )
                decoded = clean_line.rstrip()
                if not echo_skipped and cmd_stripped:
                    if _is_echo_line(decoded, cmd_stripped, cli_opts.prompt_regex):
                        echo_skipped = True
                        continue
                    echo_skipped = True
                if decoded in ("$", "#", ">") or clean_line in _LEGACY_PROMPTS:
                    return
                yield decoded

            buf = normalized
            tail_clean = (
                _strip_terminal_noise(buf) if cli_opts.strip_ansi else _apply_cr_overwrite(buf)
            ).rstrip("\n")
            if tail_clean and _is_prompt_line(tail_clean, cli_opts.prompt_regex):
                break
