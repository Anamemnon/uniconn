# src/uniconn/_uri.py
"""Парсер URI для различных транспортов.

Поддерживаемые форматы:
    - ssh://[user[:password]@]host[:port][?option=value]
    - telnet://[user[:password]@]host[:port][?option=value]
    - serial:///dev/ttyUSB0?baudrate=9600&parity=N
    - local://[?option=value]
    - ipmi://[user[:password]@]host[:port]
    - redfish://[user[:password]@]host[:port][/path]
"""

from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ._config import ConnectionConfig


class URIParser:
    """Парсер URI строк в ConnectionConfig."""

    # Порты по умолчанию для различных транспортов
    DEFAULT_PORTS = {
        "ssh": 22,
        "telnet": 23,
        "ipmi": 623,
        "redfish": 443,
    }

    @classmethod
    def parse(cls, uri: str) -> "ConnectionConfig":
        """Распарсить URI в ConnectionConfig.

        Args:
            uri: URI строка (например, "ssh://user:pass@host:22")

        Returns:
            ConnectionConfig объект

        Raises:
            ValueError: Если URI некорректен

        """
        parsed = urlparse(uri)

        if not parsed.scheme:
            raise ValueError(f"URI должен содержать схему (transport://...): {uri}")

        transport = parsed.scheme.lower()

        # Специальная обработка для serial транспорта
        if transport == "serial":
            return cls._parse_serial(parsed, uri)

        # Специальная обработка для local транспорта
        if transport == "local":
            return cls._parse_local(parsed)

        # Стандартная обработка для сетевых транспортов
        return cls._parse_network(parsed, transport)

    @classmethod
    def _parse_network(cls, parsed, transport: str) -> "ConnectionConfig":
        """Парсинг сетевых транспортов (ssh, telnet, ipmi, redfish)."""
        from ._config import ConnectionConfig

        # Порт (с дефолтом для транспорта)
        port = parsed.port
        if port is None and transport in cls.DEFAULT_PORTS:
            port = cls.DEFAULT_PORTS[transport]

        # Парсим query параметры
        options = cls._parse_options(parsed.query)

        # Для redfish добавляем path в options
        if transport == "redfish" and parsed.path and parsed.path != "/":
            options["base_path"] = parsed.path

        return ConnectionConfig(
            transport=transport,
            host=parsed.hostname,
            port=port,
            username=parsed.username,
            password=parsed.password,
            options=options
        )

    @classmethod
    def _parse_serial(cls, parsed, uri: str) -> "ConnectionConfig":
        """Парсинг serial URI."""
        from ._config import ConnectionConfig

        # Для serial: serial:///dev/ttyUSB0?baudrate=9600
        # Или: serial://COM1?baudrate=9600 (Windows)

        options = cls._parse_options(parsed.query)

        # Путь устройства берём из netloc или path
        device = parsed.netloc or parsed.path
        if device.startswith("/"):
            device = device[1:]

        if device:
            options["device"] = device

        return ConnectionConfig(
            transport="serial",
            host=None,  # Для serial нет хоста
            port=None,
            username=None,
            password=None,
            options=options
        )

    @classmethod
    def _parse_local(cls, parsed) -> "ConnectionConfig":
        """Парсинг local URI."""
        from ._config import ConnectionConfig

        options = cls._parse_options(parsed.query)

        return ConnectionConfig(
            transport="local",
            host="localhost",
            port=None,
            username=None,
            password=None,
            options=options
        )

    @classmethod
    def _parse_options(cls, query: str) -> dict[str, Any]:
        """Парсинг query строки в словарь опций.

        Поддерживает типизацию:
            - Целые числа: timeout=30
            - Числа с плавающей точкой: timeout=30.5
            - Булевы значения: verify_ssl=true/false/1/0/yes/no
            - Строки: encoding=utf-8
        """
        if not query:
            return {}

        parsed = parse_qs(query, keep_blank_values=True)
        options: dict[str, Any] = {}

        for key, values in parsed.items():
            value = values[0] if len(values) == 1 else values
            options[key] = cls._convert_type(value)

        return options

    @classmethod
    def _convert_type(cls, value: str) -> Any:
        """Конвертация строкового значения в соответствующий тип."""
        # Попытка конвертации в int
        try:
            return int(value)
        except ValueError:
            pass

        # Попытка конвертации в float
        try:
            return float(value)
        except ValueError:
            pass

        # Булевы значения
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        # Строка
        return value

    @classmethod
    def build(
        cls,
        transport: str,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        options: dict[str, Any] | None = None
    ) -> str:
        """Собрать URI строку из компонентов.

        Args:
            transport: Тип транспорта (ssh, telnet, serial, etc.)
            host: Хост или устройство
            port: Порт
            username: Имя пользователя
            password: Пароль
            options: Дополнительные опции

        Returns:
            URI строка

        """
        # Специальные случаи
        if transport == "local":
            if options:
                query = "&".join(f"{k}={v}" for k, v in options.items())
                return f"local://?{query}"
            return "local://"

        if transport == "serial":
            device = host or ""
            if options:
                query = "&".join(f"{k}={v}" for k, v in options.items())
                return f"serial://{device}?{query}"
            return f"serial://{device}"

        # Сетевые транспорты
        auth = ""
        if username and password:
            auth = f"{username}:{password}@"
        elif username:
            auth = f"{username}@"

        port_str = f":{port}" if port else ""

        uri = f"{transport}://{auth}{host or ''}{port_str}"

        if options:
            query = "&".join(f"{k}={v}" for k, v in options.items())
            uri = f"{uri}?{query}"

        return uri
