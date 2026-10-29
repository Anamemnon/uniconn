# src/uniconn/transports/_serial.py
"""Serial (UART) транспорт для работы с последовательными портами.

Поддерживает:
    - Схемы serial:// и uart://
    - Настройку параметров порта (baudrate, parity, stopbits, bytesize)
    - Flow control (xonxoff, rtscts, dsrdtr)
    - Аппаратные сигналы (DTR, RTS, BREAK, опрос CTS, DSR, CD, RI)
    - Адаптивное кадрирование (Smart Framing) и межсимвольные таймауты
    - Перечисление портов (Port Discovery) и выбор по USB VID/PID
    - Потоковый и бинарный ввод/вывод (run, run_bytes, stream, stream_bytes)
    - Пассивный режим мониторинга (listen mode)

Пример URI:
    serial:///dev/ttyUSB0?baudrate=9600&parity=N
    uart://COM3:115200?timeout=10
    serial://?vid=10c4&pid=ea60

Зависимости:
    pyserial-asyncio >= 0.6
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import re
import sys
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from ..exceptions import (
    ConfigurationError,
    ConnectionError,
    ExecutionError,
)
from ..exceptions import (
    TimeoutError as UniconnTimeoutError,
)
from ..result import Result
from .base import BaseTransport

# Импорт опциональный (extra dependency)
try:
    import serial_asyncio
except ImportError:
    serial_asyncio = None  # type: ignore


@dataclass(frozen=True)
class SerialPortInfo:
    """Информация об обнаруженном последовательном порте."""

    device: str
    name: str = ""
    description: str = ""
    hwid: str = ""
    vid: int | None = None
    pid: int | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    interface: str | None = None

    @property
    def vid_pid_hex(self) -> str | None:
        """Строковое представление VID:PID в формате '10C4:EA60'."""
        if self.vid is not None and self.pid is not None:
            return f"{self.vid:04X}:{self.pid:04X}"
        return None


def list_serial_ports() -> list[SerialPortInfo]:
    """Получить список доступных в системе последовательных портов."""
    try:
        import serial.tools.list_ports

        comports_iter = serial.tools.list_ports.comports()
    except Exception:
        return []

    results: list[SerialPortInfo] = []
    for p in comports_iter:
        results.append(
            SerialPortInfo(
                device=p.device or "",
                name=getattr(p, "name", "") or "",
                description=getattr(p, "description", "") or "",
                hwid=getattr(p, "hwid", "") or "",
                vid=getattr(p, "vid", None),
                pid=getattr(p, "pid", None),
                serial_number=getattr(p, "serial_number", None),
                manufacturer=getattr(p, "manufacturer", None),
                product=getattr(p, "product", None),
                interface=getattr(p, "interface", None),
            )
        )
    return results


def _parse_vid_pid(val: Any) -> int | None:
    """Безопасный парсинг VID/PID из строки (hex '10c4', '0x10c4' или dec '4292') или int."""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        with contextlib.suppress(ValueError):
            return int(s, 16)
    if any(c in "abcdefABCDEF" for c in s) or (len(s) == 4 and all(c in "0123456789abcdefABCDEF" for c in s)):
        with contextlib.suppress(ValueError):
            return int(s, 16)
    with contextlib.suppress(ValueError):
        return int(s, 10)
    with contextlib.suppress(ValueError):
        return int(s, 16)
    return None


class SerialTransport(BaseTransport):
    """Serial транспорт для работы с UART/последовательными портами.

    Поддерживает схемы serial:// и uart://, автоматическое определение устройства,
    управление линиями DTR/RTS/BREAK и адаптивное кадрирование.
    """

    # Значения по умолчанию
    DEFAULT_BAUDRATE = 9600
    DEFAULT_TIMEOUT = 30.0
    DEFAULT_INTER_BYTE_TIMEOUT = 0.05

    def __init__(self, config: Any) -> None:
        if serial_asyncio is None:
            raise ImportError(
                "pyserial-asyncio not installed. "
                "Run: pip install uniconn[serial]"
            )
        super().__init__(config)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._device: str = self._get_device()

    @property
    def name(self) -> str:
        """Название транспорта (serial или uart)."""
        cfg_transport = getattr(self.config, "transport", "serial")
        return cfg_transport if cfg_transport in ("serial", "uart") else "serial"

    @property
    def is_connected(self) -> bool:
        """Статус подключения (учитывает флаг и физическое состояние порта)."""
        if not self._connected or not self._writer:
            return False
        s = self.serial_instance
        if s is not None and hasattr(s, "is_open"):
            return bool(s.is_open)
        return True

    @property
    def serial_instance(self) -> Any | None:
        """Низкоуровневый экземпляр ``serial.Serial`` для аппаратного управления."""
        if self._writer is None:
            return None
        get_extra = getattr(self._writer, "get_extra_info", None)
        if callable(get_extra) and type(get_extra).__name__ != "AsyncMock":
            try:
                res = get_extra("serial")
                if res is not None and not asyncio.iscoroutine(res):
                    return res
            except Exception:
                pass
        transport = getattr(self._writer, "transport", None)
        if transport is not None and type(transport).__name__ != "AsyncMock":
            res = getattr(transport, "serial", None) or getattr(transport, "_serial", None)
            if res is not None and not asyncio.iscoroutine(res):
                return res
        return None

    def _get_device(self) -> str:
        """Получить путь к устройству из конфигурации или обнаружить по VID/PID."""
        opts = getattr(self.config, "options", {})

        # 1. Проверяем опцию device
        if opts.get("device"):
            return str(opts["device"])

        # 2. Проверяем host
        if getattr(self.config, "host", None):
            return str(self.config.host)

        # 3. Авто-поиск по USB VID/PID или паттерну
        target_vid_raw = opts.get("vid")
        target_pid_raw = opts.get("pid")
        if "vid_pid" in opts and ":" in str(opts["vid_pid"]):
            v_str, p_str = str(opts["vid_pid"]).split(":", 1)
            target_vid_raw = target_vid_raw or v_str
            target_pid_raw = target_pid_raw or p_str

        target_vid = _parse_vid_pid(target_vid_raw)
        target_pid = _parse_vid_pid(target_pid_raw)
        target_pattern = opts.get("pattern") or opts.get("vendor")

        has_filter = (target_vid_raw is not None) or (target_pid_raw is not None) or (target_pattern is not None)
        if has_filter:
            available = list_serial_ports()
            for port_info in available:
                if target_vid is not None and port_info.vid != target_vid:
                    continue
                if target_pid is not None and port_info.pid != target_pid:
                    continue
                if target_pattern is not None:
                    pat_str = str(target_pattern).lower()
                    haystack = f"{port_info.description} {port_info.manufacturer} {port_info.hwid}".lower()
                    if pat_str not in haystack:
                        continue
                return port_info.device

            raise ConnectionError(
                f"No serial port matching filter (vid={target_vid_raw}, pid={target_pid_raw}, "
                f"pattern={target_pattern}) found",
                host="serial",
            )

        # 4. Дефолтное устройство по платформе
        if sys.platform == "win32":
            return "COM1"
        return "/dev/ttyUSB0"

    def _get_serial_kwargs(self) -> dict[str, Any]:
        """Получить валидированные параметры для создания serial соединения."""
        opts = self.config.options

        baud_val = opts.get("baudrate", getattr(self.config, "port", None) or self.DEFAULT_BAUDRATE)
        try:
            baudrate = int(baud_val)
        except (ValueError, TypeError) as e:
            raise ConfigurationError(f"Invalid serial baudrate: {baud_val!r}") from e

        timeout_val = opts.get("timeout", getattr(self.config, "timeout", None) or self.DEFAULT_TIMEOUT)

        kwargs: dict[str, Any] = {
            "baudrate": baudrate,
            "timeout": float(timeout_val),
        }

        # Размер байта
        if "bytesize" in opts:
            try:
                kwargs["bytesize"] = int(opts["bytesize"])
            except (ValueError, TypeError) as e:
                raise ConfigurationError(f"Invalid serial bytesize: {opts['bytesize']!r}") from e

        # Четность
        if "parity" in opts:
            parity = opts["parity"]
            if isinstance(parity, str):
                import serial as pser

                parity_map = {
                    "N": pser.PARITY_NONE,
                    "NONE": pser.PARITY_NONE,
                    "E": pser.PARITY_EVEN,
                    "EVEN": pser.PARITY_EVEN,
                    "O": pser.PARITY_ODD,
                    "ODD": pser.PARITY_ODD,
                    "M": pser.PARITY_MARK,
                    "MARK": pser.PARITY_MARK,
                    "S": pser.PARITY_SPACE,
                    "SPACE": pser.PARITY_SPACE,
                }
                parity_key = parity.upper().strip()
                if parity_key not in parity_map:
                    raise ConfigurationError(
                        f"Unsupported serial parity '{parity}'. "
                        "Supported: N, E, O, M, S (or NONE, EVEN, ODD, MARK, SPACE)"
                    )
                kwargs["parity"] = parity_map[parity_key]
            else:
                kwargs["parity"] = parity

        # Стоп-биты
        if "stopbits" in opts:
            stopbits = opts["stopbits"]
            import serial as pser

            try:
                stopbits_val = float(stopbits)
            except (ValueError, TypeError) as e:
                raise ConfigurationError(f"Invalid serial stopbits value: {stopbits!r}") from e

            if stopbits_val in (1, 1.0):
                kwargs["stopbits"] = pser.STOPBITS_ONE
            elif stopbits_val == 1.5:
                kwargs["stopbits"] = pser.STOPBITS_ONE_POINT_FIVE
            elif stopbits_val in (2, 2.0):
                kwargs["stopbits"] = pser.STOPBITS_TWO
            else:
                raise ConfigurationError(
                    f"Unsupported serial stopbits '{stopbits}'. Supported: 1, 1.5, 2"
                )

        if "xonxoff" in opts:
            kwargs["xonxoff"] = bool(opts["xonxoff"])
        if "rtscts" in opts:
            kwargs["rtscts"] = bool(opts["rtscts"])
        if "dsrdtr" in opts:
            kwargs["dsrdtr"] = bool(opts["dsrdtr"])

        return kwargs

    def set_dtr(self, state: bool) -> None:
        """Установить состояние аппаратной линии DTR (Data Terminal Ready)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        try:
            s.dtr = bool(state)
        except Exception as e:
            raise ConnectionError(f"Failed to set DTR to {state}: {e}", host=self._device) from e

    def set_rts(self, state: bool) -> None:
        """Установить состояние аппаратной линии RTS (Request to Send)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        try:
            s.rts = bool(state)
        except Exception as e:
            raise ConnectionError(f"Failed to set RTS to {state}: {e}", host=self._device) from e

    def send_break(self, duration: float = 0.25) -> None:
        """Отправить аппаратный сигнал BREAK (удержание TX в нуле) для перехвата загрузчиков."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        try:
            s.send_break(duration=duration)
        except Exception as e:
            raise ConnectionError(f"Failed to send BREAK: {e}", host=self._device) from e

    def get_cts(self) -> bool:
        """Прочитать состояние аппаратной входной линии CTS (Clear to Send)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        return bool(getattr(s, "cts", False))

    def get_dsr(self) -> bool:
        """Прочитать состояние аппаратной входной линии DSR (Data Set Ready)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        return bool(getattr(s, "dsr", False))

    def get_ri(self) -> bool:
        """Прочитать состояние аппаратной входной линии RI (Ring Indicator)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        return bool(getattr(s, "ri", False))

    def get_cd(self) -> bool:
        """Прочитать состояние аппаратной входной линии CD (Carrier Detect / DCD)."""
        s = self.serial_instance
        if s is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)
        return bool(getattr(s, "cd", False))

    async def pulse_dtr_rts(
        self,
        dtr: bool = False,
        rts: bool = True,
        duration: float = 0.1,
    ) -> None:
        """Сформировать аппаратный импульс DTR/RTS для сброса целевой платы (ESP32/Arduino)."""
        self.set_dtr(dtr)
        self.set_rts(rts)
        await asyncio.sleep(duration)
        self.set_dtr(not dtr)
        self.set_rts(not rts)

    def _flush_input_buffer(self) -> None:
        """Очистить входной системный буфер от старых данных."""
        s = self.serial_instance
        if s is not None and hasattr(s, "reset_input_buffer"):
            with contextlib.suppress(Exception):
                s.reset_input_buffer()

    async def connect(self) -> None:
        """Открыть serial порт.

        Raises:
            ConnectionError: При ошибке открытия порта

        """
        try:
            self._device = self._get_device()
            kwargs = self._get_serial_kwargs()

            logging.getLogger("uniconn").warning(
                "Serial — незашифрованное соединение: данные передаются в открытом виде."
            )

            assert serial_asyncio is not None
            loop = asyncio.get_running_loop()
            self._reader, self._writer = await serial_asyncio.open_serial_connection(
                url=self._device,
                loop=loop,
                **kwargs,
            )

            self._connected = True

        except Exception as e:
            self._connected = False
            raise ConnectionError(
                f"Failed to open serial port {self._device}: {e}",
                host=self._device,
            ) from e

    async def disconnect(self) -> None:
        """Закрыть serial порт."""
        if self._writer:
            with contextlib.suppress(Exception):
                self._writer.close()
            with contextlib.suppress(Exception):
                wait_closed = getattr(self._writer, "wait_closed", None)
                if callable(wait_closed):
                    res = wait_closed()
                    if inspect.isawaitable(res):
                        await res
        s = self.serial_instance
        if s is not None and hasattr(s, "close") and hasattr(s, "is_open") and s.is_open:
            with contextlib.suppress(Exception):
                s.close()
        self._connected = False
        self._reader = None
        self._writer = None

    def _handle_comm_error(self, e: Exception, command: str) -> None:
        """Обработать коммуникационную ошибку и при разрыве соединения выставить _connected = False."""
        if isinstance(e, (ConnectionError, UniconnTimeoutError)):
            raise e
        err_msg = str(e).lower()
        if any(
            term in err_msg
            for term in (
                "disconnected",
                "input/output error",
                "port",
                "device",
                "clearcommerror",
                "not open",
                "closed",
                "permissionerror",
                "access is denied",
            )
        ):
            self._connected = False
            raise ConnectionError(
                f"Serial connection lost on {self._device}: {e}",
                command=command,
                host=self._device,
            ) from e
        raise ExecutionError(
            f"Serial communication failed: {e}",
            command=command,
            host=self._device,
        ) from e

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность serial порта без отправки мусорных команд."""
        if not self._connected or not self._writer:
            return False

        ping_cmd = self.config.options.get("ping_command")
        if ping_cmd:
            try:
                res = await self.run(str(ping_cmd), timeout=timeout or 2.0)
                return res.ok
            except Exception:
                return False

        s = self.serial_instance
        if s is not None and hasattr(s, "is_open"):
            return bool(s.is_open)
        return self._connected

    async def _read_response_bytes(
        self,
        cmd_timeout: float,
        read_until: bytes | None = None,
        prompt_regex: re.Pattern[str] | None = None,
        read_lines: int | None = None,
        inter_byte_timeout: float = 0.05,
        encoding: str = "utf-8",
    ) -> bytes:
        """Адаптивное почанковое чтение сырых байт из последовательного порта."""
        if not self._reader:
            raise ConnectionError("Not connected", host=self._device)

        accumulated = bytearray()
        read_start = time.monotonic()
        received_lines = 0

        while True:
            elapsed = time.monotonic() - read_start
            time_left = cmd_timeout - elapsed
            if time_left <= 0:
                if read_until is not None and read_until not in accumulated:
                    raise UniconnTimeoutError(
                        f"Serial command timeout after {cmd_timeout:.1f}s waiting for {read_until!r}",
                        host=self._device,
                    )
                if prompt_regex is not None:
                    decoded = accumulated.decode(encoding, errors="replace")
                    if not prompt_regex.search(decoded):
                        raise UniconnTimeoutError(
                            f"Serial command timeout after {cmd_timeout:.1f}s waiting for prompt pattern",
                            host=self._device,
                        )
                if read_lines is not None and received_lines < read_lines:
                    raise UniconnTimeoutError(
                        f"Serial command timeout after {cmd_timeout:.1f}s waiting for {read_lines} lines "
                        f"(received {received_lines})",
                        host=self._device,
                    )
                break

            # Если стоп-условие уже удовлетворено
            if read_until is not None and read_until in accumulated:
                break
            if prompt_regex is not None:
                decoded = accumulated.decode(encoding, errors="replace")
                if prompt_regex.search(decoded):
                    break
            if read_lines is not None and received_lines >= read_lines:
                break

            # Определение времени ожидания следующей порции
            waiting_for_specific = (
                read_until is not None
                or prompt_regex is not None
                or (read_lines is not None and received_lines < read_lines)
            )
            if waiting_for_specific:
                chunk_timeout = time_left
            elif accumulated:
                chunk_timeout = min(inter_byte_timeout, time_left)
            else:
                chunk_timeout = time_left

            try:
                chunk: bytes | None = None
                if isinstance(self._reader, asyncio.StreamReader):
                    res = await asyncio.wait_for(self._reader.read(4096), timeout=chunk_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                elif hasattr(self._reader, "readline"):
                    res = await asyncio.wait_for(self._reader.readline(), timeout=chunk_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                if chunk is None and hasattr(self._reader, "read"):
                    res = await asyncio.wait_for(self._reader.read(4096), timeout=chunk_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)

                if not chunk:
                    # EOF достигнут
                    break
                accumulated.extend(chunk)
                if read_lines is not None:
                    received_lines = accumulated.count(b"\n")
            except TimeoutError:
                # Если мы ждали специфичное условие, таймаут обрабатывается на следующей итерации
                if waiting_for_specific:
                    continue
                # Если данные уже поступали, пауза означает окончание пакета
                if accumulated:
                    break
                # Если данных еще не было вовсе, выходим по истечении общего времени
                if time.monotonic() - read_start >= cmd_timeout:
                    break

        return bytes(accumulated)

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        r"""Отправить данные в serial порт и прочитать ответ.

        Args:
            command: Данные для отправки
            timeout: Общий таймаут ожидания ответа
            **kwargs: Дополнительные аргументы:
                - line_ending: Перевод строки (\n, \r\n, \r, '')
                - read_until: Стоп-строка для остановки чтения
                - prompt_pattern: Regex-паттерн остановки чтения
                - read_lines: Количество строк для чтения
                - inter_byte_timeout: Межсимвольный таймаут (по умолчанию 0.05 с)
                - flush_before_write: Очистить буфер перед отправкой (по умолчанию True)
                - encoding: Кодировка текста (по умолчанию 'utf-8')

        Returns:
            Result объект с ответом от устройства

        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        start_time = time.monotonic()
        cmd_timeout = float(timeout or self.config.timeout or self.DEFAULT_TIMEOUT)

        line_ending: str = kwargs.get("line_ending", "\n")
        read_until_str: str | None = kwargs.get("read_until")
        prompt_pat = kwargs.get("prompt_pattern")
        prompt_regex = re.compile(prompt_pat) if isinstance(prompt_pat, str) else prompt_pat
        read_lines: int | None = kwargs.get("read_lines")
        inter_byte = float(
            kwargs.get(
                "inter_byte_timeout",
                self.config.options.get("inter_byte_timeout", self.DEFAULT_INTER_BYTE_TIMEOUT),
            )
        )
        flush_buf: bool = kwargs.get("flush_before_write", True)
        encoding: str = kwargs.get("encoding", self.config.options.get("encoding", "utf-8"))

        if flush_buf:
            self._flush_input_buffer()

        try:
            full_command = command + line_ending
            self._writer.write(full_command.encode(encoding, errors="replace"))
            await self._writer.drain()

            read_until_bytes = read_until_str.encode(encoding, errors="replace") if read_until_str else None

            raw_bytes = await self._read_response_bytes(
                cmd_timeout=cmd_timeout,
                read_until=read_until_bytes,
                prompt_regex=prompt_regex,
                read_lines=read_lines,
                inter_byte_timeout=inter_byte,
                encoding=encoding,
            )

            duration = time.monotonic() - start_time
            decoded = raw_bytes.decode(encoding, errors="replace")
            clean_lines = [line.rstrip("\r\n") for line in decoded.splitlines(keepends=True)]
            stdout_str = "\n".join(clean_lines)

            return Result(
                exit_code=0,
                stdout=stdout_str,
                stderr="",
                duration=duration,
                command=command,
                host=self._device,
                raw_bytes=raw_bytes,
            )

        except UniconnTimeoutError:
            raise
        except (OSError, Exception) as e:
            self._handle_comm_error(e, command)
            raise

    async def run_bytes(
        self,
        command: str | bytes,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить бинарную команду без UTF-8 перекодирования."""
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        cmd_timeout = float(timeout or self.config.timeout or self.DEFAULT_TIMEOUT)
        read_until: bytes | None = kwargs.get("read_until")
        inter_byte = float(
            kwargs.get(
                "inter_byte_timeout",
                self.config.options.get("inter_byte_timeout", self.DEFAULT_INTER_BYTE_TIMEOUT),
            )
        )
        if kwargs.get("flush_before_write", True):
            self._flush_input_buffer()

        try:
            data = command if isinstance(command, bytes) else command.encode("utf-8")
            self._writer.write(data)
            await self._writer.drain()

            return await self._read_response_bytes(
                cmd_timeout=cmd_timeout,
                read_until=read_until,
                inter_byte_timeout=inter_byte,
            )
        except UniconnTimeoutError:
            raise
        except (OSError, Exception) as e:
            self._handle_comm_error(e, str(command))
            raise

    async def stream(
        self,
        command: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковая отправка/получение данных через serial порт (включая режим мониторинга).

        Если command is None, транспорт работает в пассивном режиме прослушивания.
        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        cmd_timeout = timeout if command is None else (timeout or self.config.timeout)
        line_ending = kwargs.get("line_ending", "\n")
        encoding = kwargs.get("encoding", self.config.options.get("encoding", "utf-8"))

        if command is not None:
            full_command = command + line_ending
            try:
                self._writer.write(full_command.encode(encoding, errors="replace"))
                await self._writer.drain()
            except Exception as e:
                self._handle_comm_error(e, command)

        # Потоковое построчное чтение
        buffer = ""
        while True:
            try:
                chunk: bytes | None = None
                if isinstance(self._reader, asyncio.StreamReader):
                    res = await asyncio.wait_for(self._reader.read(4096), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                elif hasattr(self._reader, "readline"):
                    res = await asyncio.wait_for(self._reader.readline(), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                if chunk is None and hasattr(self._reader, "read"):
                    res = await asyncio.wait_for(self._reader.read(4096), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)

                if not chunk:
                    if buffer:
                        yield buffer.rstrip("\r\n")
                    break

                buffer += chunk.decode(encoding, errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    yield line.rstrip("\r\n")

            except TimeoutError:
                if buffer:
                    yield buffer.rstrip("\r\n")
                    buffer = ""
                break
            except Exception as e:
                self._handle_comm_error(e, command or "stream")

    async def stream_bytes(
        self,
        command: str | bytes | None = None,
        timeout: float | None = None,
        chunk_size: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[bytes]:
        """Потоковое чтение сырых байт из порта без декодирования."""
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        cmd_timeout = timeout if command is None else (timeout or self.config.timeout)
        if command is not None:
            try:
                data = command if isinstance(command, bytes) else command.encode("utf-8")
                self._writer.write(data)
                await self._writer.drain()
            except Exception as e:
                self._handle_comm_error(e, str(command))

        while True:
            try:
                chunk: bytes | None = None
                if isinstance(self._reader, asyncio.StreamReader):
                    res = await asyncio.wait_for(self._reader.read(chunk_size), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                elif hasattr(self._reader, "readline"):
                    res = await asyncio.wait_for(self._reader.readline(), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)
                if chunk is None and hasattr(self._reader, "read"):
                    res = await asyncio.wait_for(self._reader.read(chunk_size), timeout=cmd_timeout)
                    if isinstance(res, bytes | bytearray):
                        chunk = bytes(res)

                if not chunk:
                    break
                yield chunk
            except TimeoutError:
                break
            except Exception as e:
                self._handle_comm_error(e, str(command or "stream_bytes"))

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> _SerialShellProcess:
        """Открыть интерактивную сессию поверх Serial/UART для ``ShellSession`` и ``expect()``."""
        if not self._connected or not self._reader or not self._writer:
            raise ConnectionError(
                "Serial transport is not connected. Call connect() first",
                host=self._device,
            )
        return _SerialShellProcess(
            self._reader,
            self._writer,
            term_size=term_size,
        )


class _SerialShellStdin:
    """Адаптер текстовой записи поверх байтового StreamWriter для SerialTransport."""

    def __init__(self, writer: Any) -> None:
        self._writer = writer

    def write(self, text: str | bytes) -> None:
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        self._writer.write(data)

    async def drain(self) -> None:
        drain_fn = getattr(self._writer, "drain", None)
        if callable(drain_fn):
            res = drain_fn()
            if inspect.isawaitable(res):
                await res


class _SerialShellStdout:
    """Адаптер текстового чтения поверх байтового StreamReader для SerialTransport."""

    def __init__(self, reader: Any) -> None:
        self._reader = reader

    async def read(self, n: int = 4096) -> str:
        chunk = await self._reader.read(n)
        if isinstance(chunk, bytes):
            return chunk.decode("utf-8", errors="replace")
        return chunk or ""


class _SerialShellProcess:
    """Адаптер Serial reader/writer для работы с ``ShellSession`` и ``expect()``."""

    def __init__(
        self,
        reader: Any,
        writer: Any,
        term_size: tuple[int, int] = (80, 24),
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.stdin = _SerialShellStdin(writer)
        self.stdout = _SerialShellStdout(reader)
        self.term_size = term_size
        self.returncode: int | None = None
        self.terminated = False
        self.closed = False

    def change_terminal_size(self, width: int = 80, height: int = 24, **kwargs: Any) -> None:
        w = kwargs.get("cols", width)
        h = kwargs.get("rows", height)
        self.term_size = (w, h)

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def close(self) -> None:
        self.closed = True
        self.returncode = 0

    def is_closing(self) -> bool:
        """Проверить, закрывается ли процесс оболочки (ShellProcessProtocol)."""
        if self.closed or self.terminated:
            return True
        is_closing_fn = getattr(self._writer, "is_closing", None)
        if callable(is_closing_fn) and type(is_closing_fn).__name__ != "AsyncMock":
            try:
                res = is_closing_fn()
                if not inspect.isawaitable(res):
                    return bool(res)
            except Exception:
                pass
        return False


__all__ = [
    "SerialPortInfo",
    "SerialTransport",
    "list_serial_ports",
]
