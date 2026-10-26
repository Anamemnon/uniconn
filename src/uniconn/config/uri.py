# src/uniconn/config/uri.py
"""Парсер URI для различных транспортов.

Поддерживаемые форматы:
    - ssh://[user[:password]@]host[:port][?option=value]
    - telnet://[user[:password]@]host[:port][?option=value]
    - serial:///dev/ttyUSB0?baudrate=9600&parity=N
    - local://[?option=value]
    - ipmi://[user[:password]@]host[:port]
    - replay:///path/to/cassette.yaml

Логин и пароль при парсинге подвергаются percent-decoding (unquote),
а в ``build()`` — экранируются (quote), так что спецсимволы вроде
``@``, ``:``, ``/`` в креденшелах переживают round-trip parse → build.
Повторяющиеся query-параметры: побеждает последнее значение.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import ParseResult, parse_qs, quote, unquote, urlparse

from ..exceptions import ConfigurationError

if TYPE_CHECKING:
    from .models import ConnectionConfig


class URIParser:
    """Парсер URI строк в ConnectionConfig."""

    DEFAULT_PORTS = {
        "ssh": 22,
        "telnet": 23,
        "ipmi": 623,
    }

    @classmethod
    def parse(cls, uri: str) -> ConnectionConfig:
        """Распарсить URI в ConnectionConfig.

        Args:
            uri: URI строка (например, "ssh://user:pass@host:22")

        Returns:
            ConnectionConfig объект

        Raises:
            ConfigurationError: Если URI некорректен (наследуется от ValueError)

        """
        parsed = urlparse(uri)

        if not parsed.scheme:
            raise ConfigurationError(
                f"URI должен содержать схему (transport://...): {uri}"
            )

        transport = parsed.scheme.lower()

        if transport == "serial":
            return cls._parse_serial(parsed, uri)

        if transport == "local":
            return cls._parse_local(parsed)

        if transport == "replay":
            return cls._parse_replay(parsed)

        return cls._parse_network(parsed, transport)

    @classmethod
    def _parse_replay(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг replay URI."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        cassette_path = parsed.path or parsed.netloc
        if cassette_path and "cassette" not in options:
            options["cassette"] = cassette_path
        host = str(options.get("host", parsed.hostname or "replay"))
        return ConnectionConfig(
            transport="replay",
            host=host,
            port=None,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_network(cls, parsed: ParseResult, transport: str) -> ConnectionConfig:
        """Парсинг сетевых транспортов (ssh, telnet, ipmi)."""
        from pydantic import SecretStr

        from .models import ConnectionConfig

        port = parsed.port
        if port is None and transport in cls.DEFAULT_PORTS:
            port = cls.DEFAULT_PORTS[transport]

        options = cls._parse_options(parsed.query)
        key_file = str(options.pop("key_file")) if "key_file" in options else None
        raw_passphrase = options.pop("passphrase", None)
        passphrase = (
            SecretStr(str(raw_passphrase)) if raw_passphrase is not None else None
        )
        raw_query_password = options.pop("password", None)
        password_val = (
            SecretStr(unquote(parsed.password))
            if parsed.password
            else (
                SecretStr(str(raw_query_password))
                if raw_query_password is not None
                else None
            )
        )
        ssh_config: str | bool | None = None
        if "ssh_config" in options:
            raw_ssh_cfg = options["ssh_config"]
            ssh_config = (
                raw_ssh_cfg if isinstance(raw_ssh_cfg, bool) else str(raw_ssh_cfg)
            )

        return ConnectionConfig(
            transport=transport,
            host=parsed.hostname,
            port=port,
            username=unquote(parsed.username) if parsed.username else None,
            password=password_val,
            key_file=key_file,
            passphrase=passphrase,
            ssh_config=ssh_config,
            options=options,
        )

    @classmethod
    def _parse_serial(cls, parsed: ParseResult, uri: str) -> ConnectionConfig:
        """Парсинг serial URI."""
        from .models import ConnectionConfig

        _ = uri
        options = cls._parse_options(parsed.query)
        device = parsed.netloc or parsed.path

        if device:
            options["device"] = device

        return ConnectionConfig(
            transport="serial",
            host=None,
            port=None,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_local(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг local URI."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        host = (
            str(options["host"])
            if "host" in options
            else (parsed.hostname or "localhost")
        )

        return ConnectionConfig(
            transport="local",
            host=host,
            port=None,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_options(cls, query: str) -> dict[str, Any]:
        """Парсинг query строки в словарь опций."""
        if not query:
            return {}

        parsed = parse_qs(query, keep_blank_values=True)
        options: dict[str, Any] = {}

        for key, values in parsed.items():
            options[key] = cls._convert_type(values[-1])

        return options

    @classmethod
    def _convert_type(cls, value: str) -> int | float | bool | str:
        """Конвертация строкового значения в соответствующий тип."""
        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            pass

        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        return value

    @classmethod
    def build(
        cls,
        transport: str,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Собрать URI строку из компонентов."""
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

        auth = ""
        if username and password:
            auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
        elif username:
            auth = f"{quote(username, safe='')}@"

        port_str = f":{port}" if port else ""

        uri = f"{transport}://{auth}{host or ''}{port_str}"

        if options:
            query = "&".join(f"{k}={v}" for k, v in options.items())
            uri = f"{uri}?{query}"

        return uri


__all__ = ["URIParser"]
