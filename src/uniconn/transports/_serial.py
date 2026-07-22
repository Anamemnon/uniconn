# src/uniconn/transports/_serial.py
"""Serial (UART) транспорт для работы с последовательными портами.

Поддерживает:
    - Настройку параметров порта (baudrate, parity, stopbits, bytesize)
    - Flow control (xonxoff, rtscts, dsrdtr)
    - Таймауты чтения/записи
    - Потоковый ввод/вывод

Пример URI:
    serial:///dev/ttyUSB0?baudrate=9600&parity=N
    serial://COM3?baudrate=115200&timeout=10

Зависимости:
    pyserial-asyncio >= 0.6
"""

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from ..exceptions import ConnectionError, ExecutionError
from ..result import Result
from ._base import BaseTransport

# Импорт опциональный (extra dependency)
try:
    import serial_asyncio
except ImportError:
    serial_asyncio = None  # type: ignore


class SerialTransport(BaseTransport):
    """Serial транспорт для работы с UART/последовательными портами.

    Поддерживает автоматическое определение устройства из URI или опций.
    """

    # Значения по умолчанию
    DEFAULT_BAUDRATE = 9600
    DEFAULT_TIMEOUT = 30.0

    def __init__(self, config):
        if serial_asyncio is None:
            raise ImportError(
                "pyserial-asyncio not installed. "
                "Run: pip install uniconn[serial]"
            )
        super().__init__(config)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._device: str | None = None

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "serial"

    def _get_device(self) -> str:
        """Получить путь к устройству из конфигурации."""
        # Проверяем опции
        if 'device' in self.config.options:
            return self.config.options['device']

        # Проверяем host (для URI вида serial:///dev/ttyUSB0)
        if self.config.host:
            return self.config.host

        # Определяем дефолтное устройство по платформе
        import sys
        if sys.platform == 'win32':
            return 'COM1'
        return '/dev/ttyUSB0'

    def _get_serial_kwargs(self) -> dict[str, Any]:
        """Получить параметры для создания serial соединения."""
        opts = self.config.options

        kwargs = {
            'baudrate': opts.get('baudrate', self.DEFAULT_BAUDRATE),
            'timeout': opts.get('timeout', self.DEFAULT_TIMEOUT),
        }

        # Опциональные параметры
        if 'bytesize' in opts:
            kwargs['bytesize'] = opts['bytesize']
        if 'parity' in opts:
            parity = opts['parity']
            if isinstance(parity, str):
                import serial
                parity_map = {
                    'N': serial.PARITY_NONE,
                    'E': serial.PARITY_EVEN,
                    'O': serial.PARITY_ODD,
                    'M': serial.PARITY_MARK,
                    'S': serial.PARITY_SPACE,
                }
                kwargs['parity'] = parity_map.get(parity.upper(), serial.PARITY_NONE)
            else:
                kwargs['parity'] = parity

        if 'stopbits' in opts:
            stopbits = opts['stopbits']
            if isinstance(stopbits, int):
                import serial
                if stopbits == 1:
                    kwargs['stopbits'] = serial.STOPBITS_ONE
                elif stopbits == 2:
                    kwargs['stopbits'] = serial.STOPBITS_TWO

        if 'xonxoff' in opts:
            kwargs['xonxoff'] = bool(opts['xonxoff'])
        if 'rtscts' in opts:
            kwargs['rtscts'] = bool(opts['rtscts'])
        if 'dsrdtr' in opts:
            kwargs['dsrdtr'] = bool(opts['dsrdtr'])

        return kwargs

    async def connect(self) -> None:
        """Открыть serial порт.

        Raises:
            ConnectionError: При ошибке открытия порта

        """
        try:
            self._device = self._get_device()
            kwargs = self._get_serial_kwargs()

            logging.getLogger("uniconn").warning(
                "Serial — незашифрованное соединение: данные передаются "
                "в открытом виде."
            )

            self._reader, self._writer = await serial_asyncio.open_serial_connection(
                url=self._device,
                **kwargs
            )

            self._connected = True

        except Exception as e:
            raise ConnectionError(
                f"Failed to open serial port {self._device}: {e}",
                host=self._device
            ) from e

    async def disconnect(self) -> None:
        """Закрыть serial порт."""
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._connected = False
        self._reader = None
        self._writer = None

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        r"""Отправить данные в serial порт и прочитать ответ.

        Для serial портов команда обычно отправляется как есть,
        часто требуется добавить перенос строки (\r\n или \n)
        в зависимости от устройства.

        Args:
            command: Данные для отправки
            timeout: Таймаут ожидания ответа
            **kwargs: Дополнительные аргументы
                - line_ending: Строка окончания команды (\n, \r\n, \r)
                - read_until: Строка для остановки чтения
                - read_lines: Количество строк для чтения

        Returns:
            Result объект с ответом от устройства

        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        start_time = time.monotonic()
        cmd_timeout = timeout or self.config.timeout

        # Получаем параметры
        line_ending = kwargs.get('line_ending', '\n')
        read_until = kwargs.get('read_until')
        read_lines = kwargs.get('read_lines', 100)  # Ограничение по умолчанию

        try:
            # Отправляем команду
            full_command = command + line_ending
            self._writer.write(full_command.encode())
            await self._writer.drain()

            # Читаем ответ
            lines = []
            read_start = time.monotonic()

            for _ in range(read_lines):
                # Проверяем общий таймаут
                if time.monotonic() - read_start > cmd_timeout:
                    break

                try:
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=1.0  # Короткий таймаут для чтения построчно
                    )
                    if not line:
                        break

                    decoded = line.decode('utf-8', errors='replace').rstrip()
                    lines.append(decoded)

                    # Проверяем условие остановки
                    if read_until and read_until in decoded:
                        break

                except TimeoutError:
                    # Нет данных - возможно ответ закончен
                    if lines:  # Если уже что-то прочитали, выходим
                        break
                    # Иначе продолжаем ждать

            duration = time.monotonic() - start_time

            return Result(
                exit_code=0,  # Serial не имеет exit codes
                stdout="\n".join(lines),
                stderr="",
                duration=duration,
                command=command,
                host=self._device
            )

        except Exception as e:
            raise ExecutionError(
                f"Serial communication failed: {e}",
                command=command,
                host=self._device
            ) from e

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковая отправка/получение данных через serial порт.

        Args:
            command: Данные для отправки
            timeout: Таймаут между строками
            **kwargs: Дополнительные аргументы
                - line_ending: Строка окончания команды

        Yields:
            Строки ответа от устройства

        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self._device)

        cmd_timeout = timeout or self.config.timeout
        line_ending = kwargs.get('line_ending', '\n')

        # Отправляем команду
        full_command = command + line_ending
        self._writer.write(full_command.encode())
        await self._writer.drain()

        # Читаем потоком
        while True:
            try:
                line = await asyncio.wait_for(
                    self._reader.readline(),
                    timeout=cmd_timeout
                )
                if not line:
                    break

                decoded = line.decode('utf-8', errors='replace').rstrip()
                yield decoded

            except TimeoutError:
                break
