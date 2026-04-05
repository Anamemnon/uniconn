# src/uniconn/_connection.py
import json
import logging
from pathlib import Path
from typing import Self

from pydantic import SecretStr
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from ._config import ConnectionConfig
from .exceptions import ConnectionError, TimeoutError
from .plugins._loader import TransportLoader
from .result import Result
from .transports._base import BaseTransport

logger = logging.getLogger(__name__)


class Connection:
    """Основной класс для работы с удалёнными хостами.

    Пример использования:
        async with Connection.from_uri("ssh://user@host") as conn:
            result = await conn.run("uptime")
            print(result.stdout)
    """

    def __init__(
        self,
        transport: BaseTransport,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ):
        self._transport = transport
        self._config = config
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)

    # ─── Фабричные методы ──────────────────────────────────────────

    @classmethod
    def from_uri(
        cls,
        uri: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать подключение из URI строки."""
        config = ConnectionConfig.from_uri(uri)
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry_attempts, logger)

    @classmethod
    def from_config(
        cls,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать подключение из конфигурации."""
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry_attempts, logger)

    @classmethod
    def from_dict(
        cls,
        data: dict,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать подключение из словаря.

        Args:
            data: Словарь с параметрами подключения.
                Поддерживаемые ключи: transport, host, port, username,
                password, key_file, timeout, options.
            retry_attempts: Количество попыток при ошибке
            logger: Кастомный логгер

        Returns:
            Connection

        Пример:
            >>> Connection.from_dict({
            ...     "transport": "ssh",
            ...     "host": "example.com",
            ...     "username": "admin",
            ...     "timeout": 60,
            ... })

        """
        # Извлекаем retry_attempts из данных если есть
        retry = data.get("retry_attempts", retry_attempts)
        config = ConnectionConfig(**{
            k: v for k, v in data.items()
            if k not in ("retry_attempts", "logger")
        })
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry, logger)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> list[Self]:
        """Создать подключения из JSON или YAML файла.

        Файл должен содержать список объектов конфигурации:
        ```json
        [
            {"transport": "ssh", "host": "node1"},
            {"transport": "ssh", "host": "node2", "username": "admin"}
        ]
        ```

        YAML формат:
        ```yaml
        - transport: ssh
          host: node1
        - transport: ssh
          host: node2
          username: admin
        ```

        Args:
            path: Путь к файлу (.json, .yaml, .yml)
            retry_attempts: Количество попыток при ошибке
            logger: Кастомный логгер

        Returns:
            Список Connection объектов

        """
        filepath = Path(path)
        content = filepath.read_text(encoding="utf-8")

        if filepath.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data_list = yaml.safe_load(content)
            except ImportError:
                raise ImportError(
                    "PyYAML not installed. "
                    "Run: pip install pyyaml"
                ) from None
        elif filepath.suffix == ".json":
            data_list = json.loads(content)
        else:
            raise ValueError(
                f"Unsupported file format: {filepath.suffix}. "
                "Use .json, .yaml or .yml"
            )

        if not isinstance(data_list, list):
            data_list = [data_list]

        return [
            cls.from_dict(data, retry_attempts, logger)
            for data in data_list
        ]

    # ─── Клонирование и модификация ────────────────────────────────

    def copy(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | SecretStr | None = None,
        key_file: str | None = None,
        timeout: float | None = None,
        options: dict | None = None,
        retry_attempts: int | None = None,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать копию подключения с возможностью изменения параметров.

        Все не указанные параметры наследуются из оригинала.
        Если пароль не указан, берётся из оригинала.

        Args:
            host: Новый хост
            port: Новый порт
            username: Новый пользователь
            password: Новый пароль
            key_file: Новый путь к ключу
            timeout: Новый таймаут
            options: Новые опции
            retry_attempts: Новое количество попыток
            logger: Новый логгер

        Returns:
            Новый Connection с изменёнными параметрами

        Пример:
            >>> conn = Connection.from_uri("ssh://admin@prod")
            >>> dev = conn.copy(host="dev", username="developer")

        """
        new_config = ConnectionConfig(
            transport=self._config.transport,
            host=host if host is not None else self._config.host,
            port=port if port is not None else self._config.port,
            username=username if username is not None else self._config.username,
            password=(
                SecretStr(password) if isinstance(password, str)
                else password if password is not None
                else self._config.password
            ),
            key_file=key_file if key_file is not None else self._config.key_file,
            timeout=timeout if timeout is not None else self._config.timeout,
            options=options if options is not None else self._config.options,
        )
        transport_class = TransportLoader.get(new_config.transport)
        transport = transport_class(new_config)
        return type(self)(
            transport,
            new_config,
            retry_attempts or self._retry_attempts,
            logger or self._logger,
        )

    def with_overrides(self, **overrides) -> Self:
        """Создать копию подключения с переопределёнными параметрами.

        Удобный метод для пакетного изменения множества параметров
        через словарь.

        Args:
            **overrides: Параметры для переопределения.
                Поддерживаются: host, port, username, password,
                key_file, timeout, options, retry_attempts, logger.

        Returns:
            Новый Connection с переопределёнными параметрами

        Пример:
            >>> prod = Connection.from_uri("ssh://admin@prod:22")
            >>> staging = prod.with_overrides(
            ...     host="staging",
            ...     timeout=60,
            ...     options={"compress": True}
            ... )

        """
        return self.copy(
            host=overrides.get("host"),
            port=overrides.get("port"),
            username=overrides.get("username"),
            password=overrides.get("password"),
            key_file=overrides.get("key_file"),
            timeout=overrides.get("timeout"),
            options=overrides.get("options"),
            retry_attempts=overrides.get("retry_attempts"),
            logger=overrides.get("logger"),
        )

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        raise_on_error: bool = False,
        **kwargs
    ) -> Result:
        """Выполнить команду на удалённом хосте.

        Автоматически повторяет попытку при ConnectionError/TimeoutError
        с экспоненциальным backoff (до retry_attempts раз).

        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            raise_on_error: Raise ExecutionError если exit_code != 0
            **kwargs: Дополнительные аргументы для транспорта

        Returns:
            Result объект с stdout, stderr, exit_code

        Raises:
            ConnectionError: При ошибке подключения после всех retry попыток
            TimeoutError: При таймауте после всех retry попыток

        """
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        self._logger.debug(
            f"Running command: {command!r} on {self._config.uri_safe}"
        )

        # Динамический retry с использованием self._retry_attempts
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._retry_attempts),
            wait=wait_exponential_jitter(initial=1, max=10),
            retry=retry_if_exception_type((ConnectionError, TimeoutError)),
            reraise=True,
        ):
            with attempt:
                result = await self._transport.run(
                    command, timeout=timeout, **kwargs
                )

        if raise_on_error:
            result.raise_for_status()

        return result

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ):
        """Потоковое получение вывода команды."""
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        async for line in self._transport.stream(command, timeout=timeout, **kwargs):
            yield line

    async def close(self) -> None:
        """Закрыть подключение."""
        await self._transport.disconnect()

    async def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения.

        Делегирует проверку транспорту через ``ping()``.
        Для SSH — выполняет ``true`` через `asyncssh.run()`.
        Для Redfish — GET запрос к корневому ресурсу.
        Для IPMI — ``get_power`` команда.
        Для Local — всегда True (если подключён).

        Args:
            timeout: Таймаут проверки в секундах

        Returns:
            True если подключение живо и отвечает

        Пример:
            >>> async with Connection.from_uri("ssh://user@host") as conn:
            ...     if await conn.is_alive():
            ...         print("Host is alive")
            ...     else:
            ...         print("Host is unreachable")
        """
        return await self._transport.ping(timeout=timeout)

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs
    ) -> None:
        """Загрузить файл или директорию на удалённый хост.

        Работает только для SSH транспорта (SFTP).
        Автоматически определяет рекурсию если local_path — директория.

        Args:
            local_path: Путь к локальному файлу или директории
            remote_path: Путь на удалённом хосте
            recurse: Принудительная рекурсивная загрузка
            **kwargs: Дополнительные аргументы для транспорта

        Пример:
            >>> await conn.upload("/local/file.txt", "/remote/file.txt")
            >>> await conn.upload("/local/dir", "/remote/dir", recurse=True)
        """
        await self._transport.upload(
            local_path, remote_path, recurse=recurse, **kwargs
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs
    ) -> None:
        """Скачать файл или директорию с удалённого хоста.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь на удалённом хосте
            local_path: Путь для сохранения локально
            recurse: Рекурсивная загрузка директории
            **kwargs: Дополнительные аргументы для транспорта

        Пример:
            >>> await conn.download("/remote/file.txt", "/local/file.txt")
            >>> await conn.download("/remote/dir", "/local/dir", recurse=True)
        """
        await self._transport.download(
            remote_path, local_path, recurse=recurse, **kwargs
        )

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к файлу на удалённом хосте
            mode: Права доступа (например, ``0o755``, ``0o644``)

        Пример:
            >>> await conn.chmod("/var/www/app.py", 0o755)
        """
        await self._transport.chmod(remote_path, mode)

    async def stat(
        self,
        remote_path: str,
    ) -> dict:
        """Получить информацию о файле на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к файлу на удалённом хосте

        Returns:
            Словарь: size, uid, gid, permissions, atime, mtime,
            is_file, is_dir, is_symlink

        Пример:
            >>> info = await conn.stat("/var/log/syslog")
            >>> print(info["size"], info["permissions"])
        """
        return await self._transport.stat(remote_path)

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов в директории на удалённом хосте.

        Работает только для SSH транспорта (SFTP).

        Args:
            remote_path: Путь к директории (по умолчанию ".")

        Returns:
            Список имён файлов и директорий

        Пример:
            >>> files = await conn.listdir("/var/log")
            >>> print(files)
        """
        return await self._transport.listdir(remote_path)

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> "SyncConnection":  # noqa: F821
        """Конвертировать в синхронную версию."""
        from ._sync import SyncConnection
        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        return self._config

    @property
    def transport_name(self) -> str:
        return self._transport.name
