# src/uniconn/transports/_winrm.py
"""WinRM / WS-Management транспорт (winrm:// и wsman://) на базе pywinrm."""

from __future__ import annotations

import asyncio
import base64
import builtins
import contextlib
import json
import posixpath
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Callable, Mapping
from pathlib import Path
from typing import Any, Literal

from ..config.models import ConnectionConfig
from ..exceptions import (
    AuthenticationError,
    ConnectionError,
    ExecutionError,
    FileTransferError,
    TimeoutError,
    UniconnError,
)
from ..result import Result
from .base import BaseTransport, FileStat

try:
    import winrm  # type: ignore[import-untyped]
    from winrm.exceptions import (  # type: ignore[import-untyped]
        InvalidCredentialsError,
        WinRMError,
        WinRMOperationTimeoutError,
        WinRMTransportError,
    )
    from winrm.protocol import Protocol as WinRMProtocol  # type: ignore[import-untyped]
except ImportError:
    winrm = None
    WinRMProtocol = None
    InvalidCredentialsError = None
    WinRMError = None
    WinRMOperationTimeoutError = None
    WinRMTransportError = None

WINRM_CHUNK_SIZE = 131072  # 128 КБ сырых байт на один WS-Man SOAP запрос
_CLIXML_PREFIX = "#< CLIXML"
_HEX_ESCAPE_SEQ_RE = re.compile(r"(?:_x[0-9a-fA-F]{4}_)+")
_HEX_UNIT_RE = re.compile(r"_x([0-9a-fA-F]{4})_")
_XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>", flags=re.IGNORECASE)


def _ps_quote(value: str) -> str:
    """Экранировать строку для безопасной подстановки в одинарные кавычки PowerShell."""
    return "'" + value.replace("'", "''") + "'"


def _unescape_clixml_text(text: str) -> str:
    """Декодировать escape-последовательности PowerShell CLIXML вида ``_x000D__x000A_``.

    Группирует смежные 16-битные кодовые единицы в буфер UTF-16LE, чтобы суррогатные
    пары (например, эмодзи ``_xD83D__xDE80_``) собирались в валидный символ Unicode
    и не оставляли одиночных суррогатов, ломающих UTF-8 сериализацию.
    """

    def _replace_seq(match: re.Match[str]) -> str:
        raw_units = [int(h, 16) for h in _HEX_UNIT_RE.findall(match.group(0))]
        raw_bytes = b"".join(u.to_bytes(2, "little") for u in raw_bytes_units(raw_units))
        return raw_bytes.decode("utf-16-le", errors="replace")

    def raw_bytes_units(units: list[int]) -> list[int]:
        return units

    return _HEX_ESCAPE_SEQ_RE.sub(_replace_seq, text)


def clean_clixml_stderr(raw_stderr: bytes | str) -> str:
    """Очистить поток ``stderr`` от служебных XML-конвертов PowerShell ``#< CLIXML``.

    Извлекает сообщения из элементов ``<S S="Error">`` и ``<S S="Warning">``,
    отбрасывая шумовые записи прогресс-баров (``<Obj>`` / ``ProgressRecord``).
    Поддерживает множественные блоки ``#< CLIXML`` и XML-декларации в одном потоке.
    """
    text = (
        raw_stderr.decode("utf-8", errors="replace")
        if isinstance(raw_stderr, bytes)
        else str(raw_stderr)
    )
    if _CLIXML_PREFIX not in text:
        return text

    prefix_idx = text.find(_CLIXML_PREFIX)
    leading = text[:prefix_idx].strip()
    xml_part = text[prefix_idx + len(_CLIXML_PREFIX) :]
    # Удаляем повторные заголовки #< CLIXML и декларации <?xml ...?> внутри потока
    xml_part = xml_part.replace(_CLIXML_PREFIX, "")
    xml_part = _XML_DECL_RE.sub("", xml_part).lstrip("\r\n")

    extracted_messages: list[str] = []
    if leading:
        extracted_messages.append(leading)

    try:
        wrapped_xml = f"<Root>{xml_part}</Root>"
        root = ET.fromstring(wrapped_xml)
        for elem in root.iter():
            tag_name = elem.tag.rsplit("}", 1)[-1]
            stream_attr = (elem.attrib.get("S") or "").lower()
            if tag_name == "S" and stream_attr in ("error", "warning", "verbose") and elem.text:
                msg_text = _unescape_clixml_text(elem.text)
                if stream_attr == "warning" and not msg_text.upper().startswith("WARNING:"):
                    msg_text = f"WARNING: {msg_text}\n"
                extracted_messages.append(msg_text)
    except ET.ParseError:
        matches = re.findall(
            r'<S\s+S="(?:Error|Warning|error|warning)"[^>]*>(.*?)</S>',
            xml_part,
            flags=re.DOTALL,
        )
        if matches:
            for m in matches:
                extracted_messages.append(_unescape_clixml_text(m))
        else:
            return text

    joined = "".join(extracted_messages).replace("\r\n", "\n")
    return joined.strip()


def build_powershell_encoded_command(
    script: str,
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    input_data: str | bytes | None = None,
) -> tuple[str, list[str]]:
    """Сформировать команду запуска PowerShell с ``-EncodedCommand`` (UTF-16LE Base64).

    Автоматически переключает входную и выходную кодировки консоли в UTF-8,
    отключает рендеринг прогресс-баров в CLIXML и применяет контексты ``cwd`` и ``env``.
    """
    prologue: list[str] = [
        "$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
        "$ProgressPreference = 'SilentlyContinue'",
    ]
    if env:
        for k, v in env.items():
            safe_key = re.sub(r"[^A-Za-z0-9_]", "_", str(k))
            prologue.append(f"$env:{safe_key} = {_ps_quote(str(v))}")
    if cwd:
        prologue.append(f"Set-Location -LiteralPath {_ps_quote(str(cwd))} -ErrorAction Stop")

    if input_data is not None:
        in_str = (
            input_data.decode("utf-8", errors="replace")
            if isinstance(input_data, bytes)
            else str(input_data)
        )
        prologue.append(f"$__uniconn_input = {_ps_quote(in_str)}")
        full_script = "; ".join(prologue) + f"\n$__uniconn_input | & {{\n{script}\n}}"
    else:
        full_script = "; ".join(prologue) + f"\n{script}"

    encoded = base64.b64encode(full_script.encode("utf-16-le")).decode("ascii")
    return "powershell", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def _join_win_or_posix(base: str, rel: str) -> str:
    """Аккуратно склеить базовый и относительный пути на удалённом Windows-хосте."""
    if "\\" in base or (len(base) >= 2 and base[1] == ":"):
        clean_base = base.rstrip("\\/")
        clean_rel = rel.lstrip("\\/").replace("/", "\\")
        return f"{clean_base}\\{clean_rel}" if clean_rel else clean_base
    clean_base = base.rstrip("/")
    clean_rel = rel.lstrip("/")
    return f"{clean_base}/{clean_rel}" if clean_rel else clean_base


class WinRMTransport(BaseTransport):
    """Асинхронный транспорт WinRM / PowerShell Remoting (``winrm://`` и ``wsman://``)."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать WinRM транспорт из ``ConnectionConfig``."""
        if winrm is None:
            raise ImportError(
                "Для WinRM транспорта требуется библиотека pywinrm: "
                "pip install uniconn[winrm]"
            )
        super().__init__(config)

        opts = config.options
        host = config.host or "localhost"
        raw_auth = str(opts.get("transport") or opts.get("auth") or "ntlm").lower()
        self.auth_transport: str = raw_auth

        domain = opts.get("domain")
        raw_user = config.username
        if domain and raw_user and "\\" not in raw_user and "@" not in raw_user:
            self.username: str | None = f"{domain}\\{raw_user}"
        else:
            self.username = raw_user

        use_ssl = (
            bool(opts.get("ssl", False))
            or str(opts.get("scheme", "")).lower() == "https"
            or raw_auth == "ssl"
            or config.port == 5986
        )
        self.use_ssl: bool = use_ssl
        scheme = "https" if use_ssl else "http"
        port = config.port or (5986 if use_ssl else 5985)
        wsman_path = str(opts.get("path", "/wsman")).lstrip("/")
        self.endpoint: str = f"{scheme}://{host}:{port}/{wsman_path}"

        if "server_cert_validation" in opts:
            raw_cert = opts["server_cert_validation"]
            if isinstance(raw_cert, bool):
                self.server_cert_validation = "validate" if raw_cert else "ignore"
            else:
                self.server_cert_validation = str(raw_cert).lower()
        elif "verify_ssl" in opts:
            self.server_cert_validation = "validate" if opts["verify_ssl"] else "ignore"
        else:
            self.server_cert_validation = "validate"

        raw_shell = str(opts.get("shell", "ps")).lower()
        self.default_shell: Literal["ps", "cmd"] = (
            "cmd" if raw_shell in ("cmd", "cmd.exe") else "ps"
        )
        self._protocol: Any = None
        self._session: Any = None

    @property
    def name(self) -> str:
        """Название транспорта (``winrm`` или ``wsman``)."""
        if self.config.transport in ("winrm", "wsman"):
            return self.config.transport
        return "winrm"

    def _compute_timeouts(self, timeout: float | None = None) -> tuple[int, int]:
        """Рассчитать ``(operation_timeout_sec, read_timeout_sec)`` для ``pywinrm``."""
        opts = self.config.options
        base_timeout = (
            timeout
            if timeout is not None
            else float(opts.get("operation_timeout_sec") or self.config.timeout or 20.0)
        )
        op_sec = max(1, int(base_timeout))
        explicit_read = opts.get("read_timeout_sec")
        if explicit_read is not None and int(explicit_read) > op_sec:
            read_sec = int(explicit_read)
        else:
            read_sec = op_sec + max(5, int(op_sec * 0.25))
        return op_sec, read_sec

    def _build_protocol(self, timeout: float | None = None) -> Any:
        """Создать экземпляр ``winrm.protocol.Protocol`` с текущими настройками."""
        if winrm is None:
            raise ImportError(
                "Для WinRM транспорта требуется библиотека pywinrm: "
                "pip install uniconn[winrm]"
            )
        proto_cls = getattr(winrm, "Protocol", None) or WinRMProtocol
        if proto_cls is None:
            raise ImportError(
                "Для WinRM транспорта требуется библиотека pywinrm: "
                "pip install uniconn[winrm]"
            )
        op_sec, read_sec = self._compute_timeouts(timeout)
        password_str = (
            self.config.password.get_secret_value()
            if self.config.password is not None
            else None
        )
        opts = self.config.options
        proto_kwargs: dict[str, Any] = {
            "endpoint": self.endpoint,
            "transport": self.auth_transport,
            "username": self.username,
            "password": password_str,
            "server_cert_validation": self.server_cert_validation,
            "operation_timeout_sec": op_sec,
            "read_timeout_sec": read_sec,
        }
        optional_keys = (
            "message_encryption",
            "ca_trust_path",
            "cert_pem",
            "cert_key_pem",
            "kerberos_delegation",
            "kerberos_hostname_override",
            "credssp_disable_tlsv1_2",
        )
        for key in optional_keys:
            if key in opts:
                proto_kwargs[key] = opts[key]

        return proto_cls(**proto_kwargs)

    def _map_exception(
        self,
        exc: BaseException,
        command: str | None = None,
    ) -> UniconnError:
        """Преобразовать исключения ``pywinrm`` и сокетов в иерархию ``UniconnError``."""
        if isinstance(exc, UniconnError):
            return exc

        msg = str(exc)
        msg_lower = msg.lower()
        auth_exc_types = tuple(
            t for t in (InvalidCredentialsError,) if t is not None
        )
        if (
            (auth_exc_types and isinstance(exc, auth_exc_types))
            or "401" in msg_lower
            or "403" in msg_lower
            or "credentials" in msg_lower
            or "unauthorized" in msg_lower
            or "authentication" in msg_lower
        ):
            return AuthenticationError(
                f"WinRM authentication failed on {self.config.host}: {msg}",
                command=command,
                host=self.config.host,
            )

        timeout_exc_types = tuple(
            t for t in (WinRMOperationTimeoutError, builtins.TimeoutError) if t is not None
        )
        if (
            (timeout_exc_types and isinstance(exc, timeout_exc_types))
            or "timed out" in msg_lower
            or "timeout" in msg_lower
        ):
            return TimeoutError(
                f"WinRM operation timed out on {self.config.host}: {msg}",
                command=command,
                host=self.config.host,
            )

        return ConnectionError(
            f"WinRM error on {self.config.host}: {msg}",
            command=command,
            host=self.config.host,
        )

    async def connect(self) -> None:
        """Инициализировать подключение WinRM."""
        if self._connected:
            return
        try:
            if self._protocol is None:
                self._protocol = self._build_protocol()
            if self.config.options.get("validate_on_connect", False):
                shell_id = await asyncio.to_thread(self._protocol.open_shell)
                await asyncio.to_thread(self._protocol.close_shell, shell_id)
            self._connected = True
        except Exception as exc:
            self._connected = False
            raise self._map_exception(exc) from exc

    async def disconnect(self) -> None:
        """Закрыть подключение WinRM."""
        self._protocol = None
        self._session = None
        self._connected = False

    def _get_protocol_for_call(self, timeout: float | None = None) -> Any:
        """Вернуть экземпляр ``Protocol`` для выполнения запроса."""
        if self._protocol is None:
            self._protocol = self._build_protocol(timeout=timeout)
        return self._protocol

    def _exec_sync(
        self,
        protocol: Any,
        exec_cmd: str,
        exec_args: list[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> tuple[bytes, bytes, int]:
        """Синхронный цикл открытия WS-Man оболочки, запуска команды и чтения результата."""
        open_kwargs: dict[str, Any] = {}
        if cwd:
            open_kwargs["working_directory"] = str(cwd)
        if env:
            open_kwargs["env_vars"] = {str(k): str(v) for k, v in env.items()}

        try:
            shell_id = (
                protocol.open_shell(**open_kwargs)
                if open_kwargs
                else protocol.open_shell()
            )
        except TypeError:
            shell_id = protocol.open_shell()

        command_id: str | None = None
        try:
            command_id = protocol.run_command(shell_id, exec_cmd, exec_args)
            std_out, std_err, status_code = protocol.get_command_output(
                shell_id, command_id
            )
            out_bytes = (
                std_out
                if isinstance(std_out, bytes)
                else str(std_out or "").encode("utf-8")
            )
            err_bytes = (
                std_err
                if isinstance(std_err, bytes)
                else str(std_err or "").encode("utf-8")
            )
            return out_bytes, err_bytes, int(status_code or 0)
        finally:
            if command_id is not None:
                with contextlib.suppress(Exception):
                    protocol.cleanup_command(shell_id, command_id)
            with contextlib.suppress(Exception):
                protocol.close_shell(shell_id)

    def _prepare_execution(
        self,
        command: str,
        *,
        shell_mode: str,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        input_data: str | bytes | None = None,
    ) -> tuple[str, list[str], str | None, Mapping[str, str] | None]:
        """Подготовить исполняемый бинарник и аргументы для ``ps`` или ``cmd`` режима."""
        if shell_mode in ("cmd", "cmd.exe"):
            cmd_str = command
            if cwd:
                safe_cwd = str(cwd).replace('"', "")
                cmd_str = f'cd /d "{safe_cwd}" && {cmd_str}'
            return cmd_str, [], cwd, env

        exec_bin, exec_args = build_powershell_encoded_command(
            command,
            cwd=cwd,
            env=env,
            input_data=input_data,
        )
        return exec_bin, exec_args, None, None

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду через WinRM (по умолчанию в PowerShell) и вернуть ``Result``."""
        if not self._connected:
            raise ConnectionError("WinRM transport is not connected", host=self.config.host)

        shell_mode = str(kwargs.get("shell") or self.default_shell).lower()
        cwd = kwargs.get("cwd")
        env = kwargs.get("env")
        input_data = kwargs.get("input")

        t0 = time.monotonic()
        try:
            if self._session is not None and cwd is None and env is None and input_data is None:
                if shell_mode in ("cmd", "cmd.exe") and hasattr(self._session, "run_cmd"):
                    resp = await asyncio.to_thread(self._session.run_cmd, command)
                elif hasattr(self._session, "run_ps"):
                    resp = await asyncio.to_thread(self._session.run_ps, command)
                else:
                    resp = None

                if resp is not None:
                    out_b = (
                        resp.std_out
                        if isinstance(resp.std_out, bytes)
                        else str(resp.std_out or "").encode("utf-8")
                    )
                    err_b = (
                        resp.std_err
                        if isinstance(resp.std_err, bytes)
                        else str(resp.std_err or "").encode("utf-8")
                    )
                    code = int(getattr(resp, "status_code", 0) or 0)
                    stdout_str = out_b.decode("utf-8", errors="replace")
                    stderr_str = clean_clixml_stderr(err_b)
                    return Result(
                        exit_code=code,
                        stdout=stdout_str,
                        stderr=stderr_str,
                        duration=time.monotonic() - t0,
                        command=command,
                        host=self.config.host,
                        raw_bytes=out_b,
                    )

            exec_cmd, exec_args, proto_cwd, proto_env = self._prepare_execution(
                command,
                shell_mode=shell_mode,
                cwd=cwd,
                env=env,
                input_data=input_data,
            )
            protocol = self._get_protocol_for_call(timeout=timeout)
            prev_op = getattr(protocol, "operation_timeout_sec", None)
            prev_read = getattr(protocol, "read_timeout_sec", None)
            if timeout is not None:
                op_sec, read_sec = self._compute_timeouts(timeout)
                with contextlib.suppress(Exception):
                    protocol.operation_timeout_sec = op_sec
                    protocol.read_timeout_sec = read_sec

            try:
                coro = asyncio.to_thread(
                    self._exec_sync,
                    protocol,
                    exec_cmd,
                    exec_args,
                    cwd=proto_cwd,
                    env=proto_env,
                )
                if timeout is not None:
                    out_bytes, err_bytes, status_code = await asyncio.wait_for(
                        coro, timeout=timeout + 2.0
                    )
                else:
                    out_bytes, err_bytes, status_code = await coro
            finally:
                if timeout is not None:
                    with contextlib.suppress(Exception):
                        if prev_op is not None:
                            protocol.operation_timeout_sec = prev_op
                        if prev_read is not None:
                            protocol.read_timeout_sec = prev_read

        except Exception as exc:
            raise self._map_exception(exc, command=command) from exc

        stdout_text = out_bytes.decode("utf-8", errors="replace")
        stderr_text = clean_clixml_stderr(err_bytes)
        return Result(
            exit_code=status_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration=time.monotonic() - t0,
            command=command,
            host=self.config.host,
            raw_bytes=out_bytes,
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду и вернуть сырые байты ``stdout``."""
        res = await self.run(command, timeout=timeout, **kwargs)
        if kwargs.get("raise_on_error"):
            res.raise_for_status()
        return res.raw_bytes if res.raw_bytes else res.stdout.encode("utf-8")

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Построчное потоковое чтение вывода команды через опрос WS-Man буфера."""
        if not self._connected:
            raise ConnectionError("WinRM transport is not connected", host=self.config.host)

        shell_mode = str(kwargs.get("shell") or self.default_shell).lower()
        cwd = kwargs.get("cwd")
        env = kwargs.get("env")
        input_data = kwargs.get("input")

        exec_cmd, exec_args, _, _ = self._prepare_execution(
            command,
            shell_mode=shell_mode,
            cwd=cwd,
            env=env,
            input_data=input_data,
        )
        protocol = self._get_protocol_for_call(timeout=timeout)

        if not hasattr(protocol, "_raw_get_command_output"):
            res = await self.run(command, timeout=timeout, **kwargs)
            for line in res.stdout.splitlines(keepends=True):
                yield line
            return

        shell_id: str | None = None
        command_id: str | None = None
        buffer = ""
        try:
            shell_id = await asyncio.to_thread(protocol.open_shell)
            command_id = await asyncio.to_thread(
                protocol.run_command, shell_id, exec_cmd, exec_args
            )
            command_done = False
            while not command_done:
                raw_out, _raw_err, _rc, command_done = await asyncio.to_thread(
                    protocol._raw_get_command_output, shell_id, command_id
                )
                if raw_out:
                    chunk_str = (
                        raw_out.decode("utf-8", errors="replace")
                        if isinstance(raw_out, bytes)
                        else str(raw_out)
                    )
                    buffer += chunk_str
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        yield line + "\n"
            if buffer:
                yield buffer
        except Exception as exc:
            raise self._map_exception(exc, command=command) from exc
        finally:
            if shell_id is not None and command_id is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(protocol.cleanup_command, shell_id, command_id)
            if shell_id is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(protocol.close_shell, shell_id)

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить живость WinRM-соединения."""
        if not self._connected:
            return False
        try:
            res = await self.run("Write-Output ping", timeout=timeout or 5.0)
            return res.ok
        except Exception:
            return False

    async def _run_ps_internal(
        self,
        ps_script: str,
        timeout: float | None = None,
    ) -> Result:
        """Внутренний вызов PowerShell-сниппета для файловых операций."""
        return await self.run(ps_script, timeout=timeout, shell="ps")

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории на удалённом Windows-хосте."""
        q_path = _ps_quote(remote_path)
        script = f"if (Test-Path -LiteralPath {q_path} -Force) {{ exit 0 }} else {{ exit 1 }}"
        res = await self._run_ps_internal(script)
        return res.ok

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла или директории (``FileStat``) через ``Get-Item``."""
        q_path = _ps_quote(remote_path)
        script = (
            f"$item = Get-Item -LiteralPath {q_path} -Force -ErrorAction SilentlyContinue; "
            "if ($null -eq $item) { exit 2 }; "
            "$isDir = [bool]$item.PSIsContainer; "
            "$isLink = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint); "
            "$size = if ($isDir) { 0 } else { [int64]$item.Length }; "
            "$ro = if (-not $isDir -and $item.IsReadOnly) { $true } else { $false }; "
            "$mtime = [DateTimeOffset]::new($item.LastWriteTimeUtc).ToUnixTimeMilliseconds() / 1000.0; "
            "$atime = [DateTimeOffset]::new($item.LastAccessTimeUtc).ToUnixTimeMilliseconds() / 1000.0; "
            "@{ size=$size; is_dir=$isDir; is_file=(-not $isDir); is_symlink=$isLink; "
            "readonly=$ro; mtime=$mtime; atime=$atime } | ConvertTo-Json -Compress"
        )
        res = await self._run_ps_internal(script)
        if not res.ok or not res.stdout.strip():
            raise FileNotFoundError(f"Remote path does not exist: {remote_path}")

        try:
            info = json.loads(res.stdout.strip())
        except ValueError as exc:
            raise FileTransferError(
                f"Failed to parse stat metadata for {remote_path}: {res.stdout!r}",
                host=self.config.host,
            ) from exc

        is_dir = bool(info.get("is_dir", False))
        is_ro = bool(info.get("readonly", False))
        mode = 0o755 if is_dir else (0o444 if is_ro else 0o644)
        return FileStat(
            size=int(info.get("size", 0)),
            uid=None,
            gid=None,
            permissions=oct(mode)[2:],
            mode=mode,
            atime=float(info.get("atime", 0.0)),
            mtime=float(info.get("mtime", 0.0)),
            is_file=bool(info.get("is_file", not is_dir)),
            is_dir=is_dir,
            is_symlink=bool(info.get("is_symlink", False)),
        )

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список имён файлов и папок в директории через ``Get-ChildItem``."""
        q_path = _ps_quote(remote_path)
        script = (
            f"if (-not (Test-Path -LiteralPath {q_path} -Force)) {{ exit 2 }}; "
            f"$items = @(Get-ChildItem -LiteralPath {q_path} -Force -Name -ErrorAction Stop); "
            "ConvertTo-Json -InputObject $items -Compress"
        )
        res = await self._run_ps_internal(script)
        if not res.ok:
            raise FileNotFoundError(f"Remote directory does not exist: {remote_path}")

        raw = res.stdout.strip()
        if not raw or raw == "null":
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x is not None]
            if isinstance(parsed, str):
                return [parsed]
        except ValueError:
            pass
        return [line.strip() for line in raw.splitlines() if line.strip()]

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на Windows-хосте через ``New-Item -ItemType Directory``."""
        del parents
        q_path = _ps_quote(remote_path)
        if not exist_ok:
            script = (
                f"if (Test-Path -LiteralPath {q_path} -Force) {{ exit 17 }}; "
                f"New-Item -ItemType Directory -Path {q_path} -Force -ErrorAction Stop | Out-Null"
            )
        else:
            script = (
                f"if (-not (Test-Path -LiteralPath {q_path} -Force)) {{ "
                f"New-Item -ItemType Directory -Path {q_path} -Force -ErrorAction Stop | Out-Null }}"
            )
        res = await self._run_ps_internal(script)
        if not res.ok:
            raise ExecutionError(
                res.stderr.strip() or f"Failed to create directory {remote_path}",
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                host=self.config.host,
            )
        if mode is not None:
            await self.chmod(remote_path, mode)

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл или директорию на Windows-хосте."""
        q_path = _ps_quote(remote_path)
        script = (
            f"if (Test-Path -LiteralPath {q_path} -Force) {{ "
            f"Remove-Item -LiteralPath {q_path} -Force -Recurse -ErrorAction Stop }}"
        )
        res = await self._run_ps_internal(script)
        if not res.ok:
            raise ExecutionError(
                res.stderr.strip() or f"Failed to remove {remote_path}",
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                host=self.config.host,
            )

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Установить или снять атрибут ``IsReadOnly`` в зависимости от бита записи владельца ``0o200``."""
        q_path = _ps_quote(remote_path)
        readonly_literal = "$false" if (mode & 0o200) else "$true"
        script = (
            f"$item = Get-Item -LiteralPath {q_path} -Force -ErrorAction Stop; "
            f"if (-not $item.PSIsContainer) {{ $item.IsReadOnly = {readonly_literal} }}"
        )
        res = await self._run_ps_internal(script)
        if not res.ok:
            raise ExecutionError(
                res.stderr.strip() or f"Failed to chmod {remote_path}",
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                host=self.config.host,
            )

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать бинарное содержимое файла с Windows-хоста через Base64."""
        q_path = _ps_quote(remote_path)
        script = (
            f"$item = Get-Item -LiteralPath {q_path} -Force -ErrorAction SilentlyContinue; "
            "if ($null -eq $item -or $item.PSIsContainer) { exit 2 }; "
            "$bytes = [System.IO.File]::ReadAllBytes($item.FullName); "
            "[Convert]::ToBase64String($bytes)"
        )
        res = await self._run_ps_internal(script)
        if not res.ok:
            if res.exit_code == 2:
                raise FileNotFoundError(f"Remote file not found: {remote_path}")
            raise FileTransferError(
                res.stderr.strip() or f"Failed to read remote file {remote_path}",
                command=res.command,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                host=self.config.host,
            )
        b64_str = "".join(res.stdout.split())
        if not b64_str:
            return b""
        try:
            return base64.b64decode(b64_str)
        except Exception as exc:
            raise FileTransferError(
                f"Failed to decode Base64 payload for {remote_path}: {exc}",
                host=self.config.host,
            ) from exc

    async def _write_bytes_chunked(
        self,
        remote_path: str,
        data: bytes,
        *,
        progress_callback: Callable[[int, int], None] | None = None,
        error_context: str = "",
    ) -> None:
        """Записать массив байтов в файл на Windows-хосте порциями Base64 по ``WINRM_CHUNK_SIZE``."""
        q_path = _ps_quote(remote_path)
        payload = bytes(data)
        total = len(payload)
        chunks = (
            [payload[i : i + WINRM_CHUNK_SIZE] for i in range(0, total, WINRM_CHUNK_SIZE)]
            if payload
            else [b""]
        )
        transferred = 0
        for idx, chunk in enumerate(chunks):
            b64_chunk = base64.b64encode(chunk).decode("ascii")
            resolve_expr = (
                f"$p = [System.IO.Path]::GetFullPath("
                f"[System.IO.Path]::Combine((Get-Location).Path, {q_path})); "
            )
            if idx == 0:
                script = (
                    resolve_expr
                    + "$parent = [System.IO.Path]::GetDirectoryName($p); "
                    "if ($parent -and -not [System.IO.Directory]::Exists($parent)) { "
                    "[System.IO.Directory]::CreateDirectory($parent) | Out-Null }; "
                    f"$bytes = [Convert]::FromBase64String('{b64_chunk}'); "
                    "[System.IO.File]::WriteAllBytes($p, $bytes)"
                )
            else:
                script = (
                    resolve_expr
                    + f"$bytes = [Convert]::FromBase64String('{b64_chunk}'); "
                    "$fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write); "
                    "try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }"
                )
            res = await self._run_ps_internal(script)
            if not res.ok:
                default_err = error_context or f"Failed to write chunk {idx} to {remote_path}"
                raise FileTransferError(
                    res.stderr.strip() or default_err,
                    command=res.command,
                    exit_code=res.exit_code,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    host=self.config.host,
                )
            transferred += len(chunk)
            if progress_callback is not None:
                progress_callback(transferred, total)

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл на Windows-хосте чанками Base64."""
        await self._write_bytes_chunked(remote_path, data)
        if mode is not None:
            await self.chmod(remote_path, mode)

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Загрузить локальный файл или директорию на Windows-хост."""
        recurse = bool(kwargs.get("recurse", False))
        progress_cb: Callable[[int, int], None] | None = kwargs.get("progress_callback")

        src = Path(local_path)
        if not src.exists():
            raise FileNotFoundError(f"Local path not found: {local_path}")

        if src.is_dir():
            if not recurse:
                raise FileTransferError(
                    f"Cannot upload directory {local_path} without recurse=True",
                    host=self.config.host,
                )
            await self.mkdir(remote_path, parents=True, exist_ok=True)
            for item in sorted(src.iterdir()):
                child_remote = _join_win_or_posix(remote_path, item.name)
                await self.upload(
                    str(item),
                    child_remote,
                    recurse=True,
                    progress_callback=progress_cb,
                )
            return

        data = src.read_bytes()
        await self._write_bytes_chunked(
            remote_path,
            data,
            progress_callback=progress_cb,
            error_context=f"Failed to upload {local_path} -> {remote_path}",
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с Windows-хоста."""
        recurse = bool(kwargs.get("recurse", False))
        progress_cb: Callable[[int, int], None] | None = kwargs.get("progress_callback")

        info = await self.stat(remote_path)
        dst = Path(local_path)

        if info.get("is_dir"):
            if not recurse:
                raise FileTransferError(
                    f"Cannot download remote directory {remote_path} without recurse=True",
                    host=self.config.host,
                )
            dst.mkdir(parents=True, exist_ok=True)
            entries = await self.listdir(remote_path)
            for name in entries:
                if name in (".", ".."):
                    continue
                child_remote = _join_win_or_posix(remote_path, name)
                child_local = dst / posixpath.basename(name.replace("\\", "/"))
                await self.download(
                    child_remote,
                    str(child_local),
                    recurse=True,
                    progress_callback=progress_cb,
                )
            return

        data = await self.read_file(remote_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        if progress_cb is not None:
            progress_cb(len(data), len(data))


__all__ = [
    "WINRM_CHUNK_SIZE",
    "WinRMTransport",
    "build_powershell_encoded_command",
    "clean_clixml_stderr",
]
