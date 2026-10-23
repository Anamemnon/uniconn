# src/uniconn/_shell.py
r"""Интерактивная stateful PTY shell-сессия поверх SSH-соединения.

Использует маркерный протокол для определения границ вывода и кода возврата
каждой команды внутри единого PTY-потока:
    {command}; echo "\n__UNICONN_{session_uuid}__$?"

Позволяет сохранять состояние между вызовами ``execute()`` (текущая директория
после ``cd``, переменные окружения после ``export``, алиасы и функции оболочки),
работая на одном SSH-соединении параллельно с ``Connection.run()``.
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import inspect
import re
import shlex
import time
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Self

from pydantic import SecretStr

from .exceptions import ConnectionError, TimeoutError
from .result import Result


class ShellSession:
    """Асинхронная stateful PTY shell-сессия.

    Оборачивает ``asyncssh.SSHClientProcess`` и предоставляет высокоуровневый
    метод ``execute()`` (с маркерным протоколом и возвратом ``Result``), а также
    низкоуровневые методы ``send()``, ``receive()`` и ``resize()``.

    Примечание:
        В режиме PTY стандартный вывод и поток ошибок объединяются на стороне
        терминала, поэтому ``Result.stderr`` всегда пустая строка ``""``, а весь
        вывод попадает в ``Result.stdout``.

    Пример:
        >>> async with Connection.from_uri("ssh://user@host") as conn:
        ...     async with await conn.open_shell() as shell:
        ...         await shell.execute("cd /tmp")
        ...         res = await shell.execute("pwd")
        ...         print(res.stdout)  # /tmp
    """

    def __init__(
        self,
        proc: Any,
        host: str | None = None,
        default_timeout: float = 30.0,
        session_uuid: str | None = None,
    ) -> None:
        """Инициализировать обёртку над PTY-процессом.

        Args:
            proc: Процесс оболочки (``asyncssh.SSHClientProcess``)
            host: Имя хоста для контекста ошибок и ``Result``
            default_timeout: Таймаут выполнения команд по умолчанию (в секундах)
            session_uuid: Фиксированный идентификатор маркера (для тестирования)

        """
        self._proc = proc
        self._host = host
        self._default_timeout = default_timeout
        self._uuid = session_uuid or uuid.uuid4().hex[:12]
        self._marker_pattern = re.compile(
            rf"__UNICONN_{re.escape(self._uuid)}__(\d+)"
        )
        self._buffer: str = ""
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialized = False

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен и не завершён."""
        if self._closed or self._proc is None:
            return False
        rc = getattr(self._proc, "returncode", None)
        if isinstance(rc, int):
            return False
        exit_status = getattr(self._proc, "exit_status", None)
        return not isinstance(exit_status, int)

    async def initialize(self) -> None:
        """Выполнить начальную настройку оболочки (отключить prompt и эхо ввода)."""
        await self.send("export PS1=''; stty -echo\n")
        self._initialized = True

    async def send(self, text: str) -> None:
        """Низкоуровневая отправка текста в stdin оболочки.

        Args:
            text: Строка для записи в stdin

        Raises:
            ConnectionError: Если сессия закрыта или процесс завершился

        """
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        try:
            self._proc.stdin.write(text)
            drain = getattr(self._proc.stdin, "drain", None)
            if callable(drain):
                res = drain()
                if inspect.isawaitable(res):
                    await res
        except Exception as e:
            self._closed = True
            raise ConnectionError(
                f"Failed to write to shell stdin: {e}",
                host=self._host,
            ) from e

    async def _read_chunk(self) -> str:
        """Прочитать очередную порцию данных из stdout процесса."""
        read_fn = self._proc.stdout.read
        try:
            res = read_fn(4096)
        except TypeError:
            res = read_fn()
        chunk = await res if inspect.isawaitable(res) else res
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        return chunk or ""

    async def receive(self, timeout: float | None = None) -> str:
        """Низкоуровневое чтение доступного вывода из stdout оболочки.

        Args:
            timeout: Таймаут чтения в секундах (по умолчанию ``default_timeout``)

        Returns:
            Прочитанный фрагмент вывода

        Raises:
            ConnectionError: Если сессия закрыта или процесс завершился
            TimeoutError: При превышении таймаута ожидания данных

        """
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        if self._buffer:
            data = self._buffer
            self._buffer = ""
            return data

        effective_timeout = (
            timeout if timeout is not None else self._default_timeout
        )
        try:
            chunk = await asyncio.wait_for(
                self._read_chunk(), timeout=effective_timeout
            )
        except builtins.TimeoutError:
            raise TimeoutError(
                f"Timed out waiting for shell output after {effective_timeout}s",
                host=self._host,
            ) from None

        if chunk == "":
            self._closed = True
            raise ConnectionError(
                "Shell process terminated unexpectedly (EOF)",
                host=self._host,
            )
        return chunk

    def _clean_output(self, raw_output: str, command: str, wrapped_cmd: str) -> str:
        """Очистить вывод от CRLF, возможного эха команды и лишнего перевода строки."""
        normalized = raw_output.replace("\r\n", "\n")

        # Fallback на случай, если stty -echo недоступен и терминал вернул эхо команды
        lines = normalized.split("\n")
        if lines:
            first_line = lines[0].strip()
            wrapped_stripped = wrapped_cmd.strip()
            if first_line == wrapped_stripped or first_line == command.strip() or (
                command.strip() and first_line.startswith(f"{command.strip()}; echo")
            ):
                lines = lines[1:]
        cleaned = "\n".join(lines)

        # Убираем перевод строки, добавленный перед маркером (`echo "\n__UNICONN_..."`)
        if cleaned.endswith("\n"):
            cleaned = cleaned[:-1]

        return cleaned

    async def execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        """Выполнить команду в stateful shell-сессии и дождаться её завершения.

        Команда оборачивается в маркерный протокол для получения кода возврата.
        Параллельные вызовы ``execute()`` на одной сессии сериализуются через lock.
        Поскольку PTY объединяет потоки вывода, ``Result.stderr`` всегда пуст.

        Args:
            command: Команда (строка или последовательность аргументов для ``shlex.join``)
            timeout: Таймаут в секундах (по умолчанию ``default_timeout``)

        Returns:
            ``Result`` с ``stdout``, ``exit_code`` и ``duration``

        Raises:
            ConnectionError: Если процесс оболочки мёртв или завершился до маркера
            TimeoutError: При превышении таймаута (отправляет Ctrl-C в stdin)

        """
        cmd_str = command if isinstance(command, str) else shlex.join(command)
        async with self._lock:
            if not self.is_alive:
                raise ConnectionError(
                    "Shell session is closed or terminated",
                    command=cmd_str,
                    host=self._host,
                )

            effective_timeout = (
                timeout if timeout is not None else self._default_timeout
            )
            start_time = time.monotonic()
            wrapped_cmd = f'{cmd_str}; echo "\\n__UNICONN_{self._uuid}__$?"\n'

            await self.send(wrapped_cmd)

            async def _read_until_marker() -> tuple[str, int]:
                while True:
                    match = self._marker_pattern.search(self._buffer)
                    if match is not None:
                        raw_out = self._buffer[: match.start()]
                        self._buffer = self._buffer[match.end() :].lstrip("\r\n")
                        code = int(match.group(1))
                        return raw_out, code

                    if not self.is_alive:
                        self._closed = True
                        raise ConnectionError(
                            "Shell process terminated during command execution",
                            command=cmd_str,
                            host=self._host,
                        )

                    chunk = await self._read_chunk()
                    if chunk == "":
                        self._closed = True
                        raise ConnectionError(
                            "Shell process closed stdout unexpectedly (EOF)",
                            command=cmd_str,
                            host=self._host,
                        )
                    self._buffer += chunk

            try:
                raw_output, exit_code = await asyncio.wait_for(
                    _read_until_marker(),
                    timeout=effective_timeout,
                )
            except builtins.TimeoutError:
                # Прерываем зависшую команду отправкой Ctrl-C
                with contextlib.suppress(Exception):
                    self._proc.stdin.write("\x03")
                self._buffer = ""
                raise TimeoutError(
                    f"Shell command timed out after {effective_timeout}s",
                    command=cmd_str,
                    host=self._host,
                ) from None

            duration = time.monotonic() - start_time
            stdout = self._clean_output(raw_output, cmd_str, wrapped_cmd)

            return Result(
                exit_code=exit_code,
                stdout=stdout,
                stderr="",
                duration=duration,
                command=cmd_str,
                host=self._host,
            )

    async def expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        r"""Выполнить интерактивный диалог по регулярным выражениям (``expect``).

        Подходит для сетевого оборудования (Cisco IOS, MikroTik), Serial/UART,
        Telnet и интерактивных CLI-утилит без POSIX-маркеров.

        Args:
            command: Начальная команда для отправки (или ``None``, если ждём промпт)
            patterns: Словарь ``{regex_pattern: response_str_or_SecretStr}``
            final_prompt: Регулярное выражение финального приглашения оболочки
            timeout: Таймаут ожидания диалога в секундах
            line_ending: Завершение строки для начальной команды (по умолчанию ``"\n"``)
            sensitive: Маскировать команду и вывод в ``Result`` и ошибках
            allow_eof: Считать закрытие потока (EOF) успешным завершением диалога

        Returns:
            ``Result`` с полным выводом диалога в ``stdout``

        """
        if command is None:
            cmd_str = ""
        elif isinstance(command, str):
            cmd_str = command
        else:
            cmd_str = shlex.join(command)

        async with self._lock:
            if not self.is_alive:
                raise ConnectionError(
                    "Shell session is closed or terminated",
                    command="***REDACTED***" if sensitive else cmd_str,
                    host=self._host,
                )

            effective_timeout = (
                timeout if timeout is not None else self._default_timeout
            )
            start_time = time.monotonic()

            compiled_patterns: list[tuple[re.Pattern[str], str]] = []
            for pat_str, raw_resp in (patterns or {}).items():
                secret_fn = getattr(raw_resp, "get_secret_value", None)
                resp_text = (
                    str(secret_fn()) if callable(secret_fn) else str(raw_resp)
                )
                compiled_patterns.append(
                    (re.compile(pat_str, re.MULTILINE), resp_text)
                )

            final_re = (
                re.compile(final_prompt, re.MULTILINE) if final_prompt else None
            )

            if command is not None:
                payload = (
                    cmd_str
                    if cmd_str.endswith(("\n", "\r"))
                    else f"{cmd_str}{line_ending}"
                )
                await self.send(payload)

            accumulated = self._buffer
            self._buffer = ""
            cursor = 0
            matched_indices: set[int] = set()

            async def _read_dialog() -> str:
                nonlocal accumulated, cursor
                while True:
                    tail = accumulated[cursor:]
                    candidates: list[
                        tuple[bool, int, int, int, re.Match[str], str]
                    ] = []
                    for idx, (pat_re, resp_text) in enumerate(compiled_patterns):
                        m = pat_re.search(tail)
                        if m is not None:
                            candidates.append(
                                (
                                    idx in matched_indices,
                                    m.start(),
                                    -len(m.group(0)),
                                    idx,
                                    m,
                                    resp_text,
                                )
                            )
                    if candidates:
                        candidates.sort(key=lambda item: item[:4])
                        _, _, _, win_idx, win_m, win_resp = candidates[0]
                        # Если все паттерны уже срабатывали, не зацикливаемся на том же хвосте
                        if win_idx not in matched_indices or final_re is not None:
                            cursor += win_m.end()
                            matched_indices.add(win_idx)
                            if win_resp:
                                await self.send(win_resp)
                            continue

                    if final_re is not None:
                        m_final = final_re.search(tail)
                        if m_final is not None:
                            out_end = cursor + m_final.end()
                            raw_out = accumulated[:out_end]
                            self._buffer = accumulated[out_end:]
                            return raw_out

                    all_patterns_done = bool(compiled_patterns) and len(
                        matched_indices
                    ) == len(compiled_patterns)

                    if not self.is_alive:
                        self._closed = True
                        if allow_eof or (
                            final_re is None
                            and (all_patterns_done or not compiled_patterns)
                        ):
                            return accumulated
                        raise ConnectionError(
                            "Shell process terminated during expect()",
                            command="***REDACTED***" if sensitive else cmd_str,
                            host=self._host,
                        )

                    if final_re is None and all_patterns_done:
                        try:
                            chunk = await asyncio.wait_for(
                                self._read_chunk(),
                                timeout=min(0.15, effective_timeout),
                            )
                        except builtins.TimeoutError:
                            return accumulated
                    else:
                        chunk = await self._read_chunk()

                    if chunk == "":
                        self._closed = True
                        if (
                            allow_eof
                            or (
                                final_re is None
                                and (all_patterns_done or not compiled_patterns)
                            )
                            or (
                                final_re is not None
                                and final_re.search(accumulated[cursor:])
                            )
                        ):
                            return accumulated
                        raise ConnectionError(
                            "Shell process closed stdout unexpectedly (EOF)",
                            command="***REDACTED***" if sensitive else cmd_str,
                            host=self._host,
                        )
                    accumulated += chunk

            try:
                raw_output = await asyncio.wait_for(
                    _read_dialog(),
                    timeout=effective_timeout,
                )
            except builtins.TimeoutError:
                with contextlib.suppress(Exception):
                    self._proc.stdin.write("\x03")
                self._buffer = ""
                raise TimeoutError(
                    f"Expect dialog timed out after {effective_timeout}s",
                    command="***REDACTED***" if sensitive else cmd_str,
                    host=self._host,
                ) from None

            duration = time.monotonic() - start_time
            cleaned = self._clean_output(raw_output, cmd_str, cmd_str)

            return Result(
                exit_code=0,
                stdout=cleaned,
                stderr="",
                duration=duration,
                command=cmd_str,
                host=self._host,
                sensitive=sensitive,
            )

    async def resize(self, cols: int, rows: int) -> None:
        """Изменить размер окна терминала PTY.

        Args:
            cols: Ширина терминала в символах
            rows: Высота терминала в строках

        Raises:
            ConnectionError: Если сессия закрыта

        """
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        res = self._proc.change_terminal_size(cols, rows)
        if inspect.isawaitable(res):
            await res

    async def close(self) -> None:
        """Закрыть shell-сессию: отправить Ctrl-C, exit и терминировать процесс."""
        if self._closed:
            return
        self._closed = True

        if self._proc is not None:
            with contextlib.suppress(Exception):
                self._proc.stdin.write("\x03")
                self._proc.stdin.write("exit\n")
            with contextlib.suppress(Exception):
                self._proc.terminate()
            with contextlib.suppress(Exception):
                close_fn = getattr(self._proc, "close", None)
                if callable(close_fn):
                    close_fn()
            with contextlib.suppress(Exception):
                wait_closed_fn = getattr(self._proc, "wait_closed", None)
                if callable(wait_closed_fn):
                    res = wait_closed_fn()
                    if inspect.isawaitable(res):
                        await res

    async def __aenter__(self) -> Self:
        """Войти в контекстный менеджер сессии."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Закрыть сессию при выходе из контекстного менеджера."""
        await self.close()
