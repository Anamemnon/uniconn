# src/uniconn/transports/_telnet.py
"""
Telnet транспорт на базе telnetlib3.

Поддерживает:
    - Аутентификацию по логину/паролю
    - Настройку терминала (тип, размер)
    - Таймауты подключения и выполнения
    - Потоковый вывод команд

Пример URI:
    telnet://user:pass@host:23
    telnet://host?timeout=30&term_type=vt100
"""

import asyncio
import time
from typing import AsyncIterator, Optional, List, Callable
from ._base import BaseTransport
from ..result import Result
from ..exceptions import ConnectionError, AuthenticationError, ExecutionError

# Импорт опциональный (extra dependency)
try:
    import telnetlib3
except ImportError:
    telnetlib3 = None  # type: ignore


class TelnetTransport(BaseTransport):
    """Telnet транспорт для выполнения команд через Telnet протокол"""
    
    def __init__(self, config):
        if telnetlib3 is None:
            raise ImportError(
                "telnetlib3 not installed. "
                "Run: pip install uniconn[telnet]"
            )
        super().__init__(config)
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._shell_prompt: str = "$ "
        self._login_prompt: str = "login: "
        self._password_prompt: str = "Password: "
    
    @property
    def name(self) -> str:
        """Название транспорта"""
        return "telnet"
    
    async def connect(self) -> None:
        """
        Установить Telnet подключение и выполнить аутентификацию.
        
        Raises:
            ConnectionError: При ошибке подключения
            AuthenticationError: При ошибке аутентификации
        """
        try:
            host = self.config.host
            port = self.config.port or 23
            timeout = self.config.timeout
            
            # Подключаемся
            self._reader, self._writer = await asyncio.wait_for(
                telnetlib3.open_connection(
                    host=host,
                    port=port,
                    term=self.config.options.get('term_type', 'xterm-256color'),
                    cols=self.config.options.get('term_cols', 80),
                    rows=self.config.options.get('term_rows', 24),
                ),
                timeout=timeout
            )
            
            # Аутентификация если нужна
            if self.config.username:
                await self._authenticate()
            
            self._connected = True
            
        except asyncio.TimeoutError as e:
            raise ConnectionError(
                f"Telnet connection timeout to {self.config.host}:{port}",
                host=self.config.host
            ) from e
        except Exception as e:
            raise ConnectionError(
                f"Telnet connection failed: {e}",
                host=self.config.host
            ) from e
    
    async def _authenticate(self) -> None:
        """Выполнить аутентификацию через login/password prompts"""
        if not self._reader or not self._writer:
            return
        
        username = self.config.username or ""
        password = (
            self.config.password.get_secret_value()
            if self.config.password
            else ""
        )
        
        # Ждём и обрабатываем login/password prompts
        try:
            # Читаем начальные данные
            data = await asyncio.wait_for(
                self._reader.read(4096),
                timeout=5.0
            )
            
            # Ищем login prompt
            if b"login" in data.lower() or b"username" in data.lower():
                self._writer.write(username + "\n")
                await self._writer.drain()
                
                # Ждём password prompt
                data = await asyncio.wait_for(
                    self._reader.read(4096),
                    timeout=5.0
                )
            
            # Ищем password prompt
            if b"password" in data.lower():
                self._writer.write(password + "\n")
                await self._writer.drain()
                
                # Ждём приветствия/приглашения
                await asyncio.wait_for(
                    self._reader.read(4096),
                    timeout=5.0
                )
        
        except asyncio.TimeoutError as e:
            raise AuthenticationError(
                "Telnet authentication timeout",
                host=self.config.host
            ) from e
    
    async def disconnect(self) -> None:
        """Закрыть Telnet подключение"""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass  # Игнорируем ошибки при закрытии
        self._connected = False
        self._reader = None
        self._writer = None
    
    async def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> Result:
        """
        Выполнить команду через Telnet.
        
        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            **kwargs: Дополнительные аргументы
            
        Returns:
            Result объект с результатом выполнения
            
        Raises:
            ExecutionError: При ошибке выполнения
        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self.config.host)
        
        start_time = time.monotonic()
        cmd_timeout = timeout or self.config.timeout
        
        try:
            # Отправляем команду
            self._writer.write(command + "\n")
            await self._writer.drain()
            
            # Читаем вывод
            output_lines: List[str] = []
            
            while True:
                try:
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=cmd_timeout
                    )
                    if not line:
                        break
                    
                    decoded = line.decode('utf-8', errors='replace').rstrip()
                    output_lines.append(decoded)
                    
                    # Проверяем на приглашение оболочки (конец вывода)
                    if any(prompt in decoded for prompt in ['$ ', '# ', '> ']):
                        if len(output_lines) > 1:  # Пропускаем первую строку с самой командой
                            break
                            
                except asyncio.TimeoutError:
                    break
            
            duration = time.monotonic() - start_time
            
            # Фильтруем команду и приглашение из вывода
            stdout_lines = []
            for line in output_lines:
                # Пропускаем саму команду
                if line.strip() == command.strip():
                    continue
                # Пропускаем приглашение оболочки
                if any(line.endswith(prompt) for prompt in ['$ ', '# ', '> ']):
                    continue
                stdout_lines.append(line)
            
            return Result(
                exit_code=0,  # Telnet не возвращает exit code напрямую
                stdout="\n".join(stdout_lines),
                stderr="",
                duration=duration,
                command=command,
                host=self.config.host
            )
            
        except Exception as e:
            raise ExecutionError(
                f"Telnet command execution failed: {e}",
                command=command,
                host=self.config.host
            ) from e
    
    async def stream(
        self,
        command: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Потоковое выполнение команды через Telnet.
        
        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            **kwargs: Дополнительные аргументы
            
        Yields:
            Строки вывода команды
        """
        if not self._reader or not self._writer:
            raise ConnectionError("Not connected", host=self.config.host)
        
        cmd_timeout = timeout or self.config.timeout
        
        # Отправляем команду
        self._writer.write(command + "\n")
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
                
                # Пропускаем саму команду
                if decoded.strip() == command.strip():
                    continue
                
                # Проверяем конец вывода
                if any(decoded.endswith(prompt) for prompt in ['$ ', '# ', '> ']):
                    break
                
                yield decoded
                
            except asyncio.TimeoutError:
                break
