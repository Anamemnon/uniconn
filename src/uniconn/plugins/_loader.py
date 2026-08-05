# src/uniconn/plugins/_loader.py
import logging
from importlib.metadata import entry_points

from ..exceptions import TransportNotFoundError
from ..transports._base import BaseTransport

logger = logging.getLogger(__name__)

class TransportLoader:
    """Динамическая загрузка транспортов через entry-points."""

    _cache: dict[str, type[BaseTransport]] = {}

    @classmethod
    def get(cls, transport_name: str) -> type[BaseTransport]:
        """Получить класс транспорта по имени.

        Args:
            transport_name: Название транспорта (ssh, uart, ipmi, etc.)

        Returns:
            Класс транспорта

        Raises:
            TransportNotFoundError: Если транспорт не найден

        """
        if transport_name in cls._cache:
            return cls._cache[transport_name]

        # Python 3.10+ entry_points с group параметром
        eps = entry_points(group="uniconn.transports")

        # Транспорт не зарегистрирован — сразу осмысленная ошибка
        # (без повторного обёртывания TransportNotFoundError)
        if transport_name not in eps.names:
            raise TransportNotFoundError(
                f"Transport '{transport_name}' not found. "
                f"Available: {', '.join(sorted(eps.names))}. "
                f"Install with: pip install uniconn[{transport_name}]"
            )

        try:
            transport_class = eps[transport_name].load()
        except Exception as e:
            raise TransportNotFoundError(
                f"Failed to load transport '{transport_name}': {e}"
            ) from e

        cls._cache[transport_name] = transport_class
        logger.debug(f"Loaded transport: {transport_name} -> {transport_class}")
        return transport_class

    @classmethod
    def list_available(cls) -> list[str]:
        """Список доступных транспортов."""
        eps = entry_points(group="uniconn.transports")
        return list(eps.names)

    @classmethod
    def clear_cache(cls) -> None:
        """Очистить кэш (для тестирования)."""
        cls._cache.clear()
