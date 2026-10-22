# src/uniconn/transports/_base.py
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Self

from .._config import ConnectionConfig
from ..result import Result


class BaseTransport(ABC):
    """Базовый класс для всех транспортов."""

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._connected = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Название транспорта (ssh, uart, ipmi, etc.)."""
        pass

    @abstractmethod
    async def connect(self) -> None:
        """Установить подключение."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Закрыть подключение."""
        pass

    @abstractmethod
    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        """Выполнить команду и вернуть результат."""
        pass

    @abstractmethod
    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковое выполнение с yield строк вывода."""
        raise NotImplementedError
        yield ""  # pragma: no cover

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения.

        Базовая реализация: выполняет команду ``echo`` и проверяет ответ.
        Переопределяется в транспортах для более эффективной проверки.

        Args:
            timeout: Таймаут проверки в секундах

        Returns:
            True если подключение живо

        """
        if not self._connected:
            return False
        try:
            result = await self.run("echo ping", timeout=timeout or 5.0)
            return result.ok
        except Exception:
            return False

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs
    ) -> None:
        """Загрузить файл на удалённый хост.

        Базовая реализация вызывает NotImplementedError.
        Переопределяется в транспортах с поддержкой файловых операций.

        Raises:
            NotImplementedError: Если транспорт не поддерживает файловые операции

        """
        raise NotImplementedError(
            f"Upload not supported for {self.name} transport"
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs
    ) -> None:
        """Скачать файл с удалённого хоста.

        Базовая реализация вызывает NotImplementedError.
        Переопределяется в транспортах с поддержкой файловых операций.

        Raises:
            NotImplementedError: Если транспорт не поддерживает файловые операции

        """
        raise NotImplementedError(
            f"Download not supported for {self.name} transport"
        )

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу."""
        raise NotImplementedError(
            f"chmod not supported for {self.name} transport"
        )

    async def stat(
        self,
        remote_path: str,
    ) -> dict:
        """Получить информацию о файле."""
        raise NotImplementedError(
            f"stat not supported for {self.name} transport"
        )

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов в директории."""
        raise NotImplementedError(
            f"listdir not supported for {self.name} transport"
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs,
    ) -> bytes:
        """Выполнить команду и вернуть сырой байтовый вывод (stdout).

        Базовая реализация делегирует в ``run()`` и кодирует ``stdout`` в UTF-8.
        Переопределяется в ``LocalTransport`` и ``SSHTransport`` для чтения
        сырых байтов без промежуточного декодирования.
        """
        result = await self.run(command, timeout=timeout, **kwargs)
        return result.stdout.encode("utf-8")

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать содержимое файла в память (в виде ``bytes``)."""
        raise NotImplementedError(
            f"read_file not supported for {self.name} transport"
        )

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты из памяти в файл (с опциональной установкой прав ``mode``)."""
        raise NotImplementedError(
            f"write_file not supported for {self.name} transport"
        )

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории на хосте."""
        import shlex

        res = await self.run(f"test -e {shlex.quote(remote_path)}")
        return res.ok

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте."""
        import shlex

        flags = "-p " if (parents or exist_ok) else ""
        res = await self.run(f"mkdir {flags}{shlex.quote(remote_path)}")
        res.raise_for_status()
        if mode is not None:
            chmod_res = await self.run(
                f"chmod {oct(mode)[2:]} {shlex.quote(remote_path)}"
            )
            chmod_res.raise_for_status()

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs,
    ):
        """Открыть интерактивную PTY shell-сессию.

        Базовая реализация вызывает NotImplementedError.
        Переопределяется в транспортах с поддержкой PTY (SSH).

        Args:
            term_type: Тип терминала (например, "xterm", "vt100")
            term_size: Размер терминала (cols, rows)
            **kwargs: Дополнительные параметры

        Raises:
            NotImplementedError: Если транспорт не поддерживает интерактивный shell

        """
        raise NotImplementedError(
            f"open_shell not supported for {self.name} transport"
        )

