# tests/unit/test_loader.py
"""Прямые тесты TransportLoader (get/list_available/clear_cache)."""

import pytest

from uniconn.exceptions import TransportNotFoundError
from uniconn.plugins._loader import TransportLoader


@pytest.fixture(autouse=True)
def clean_cache():
    """Кэш транспортов чист до и после каждого теста."""
    TransportLoader.clear_cache()
    yield
    TransportLoader.clear_cache()


class TestTransportLoaderGet:
    """Тесты TransportLoader.get()."""

    def test_get_local(self):
        """Встроенный транспорт local загружается."""
        cls = TransportLoader.get("local")
        from uniconn.transports._local import LocalTransport

        assert cls is LocalTransport

    def test_get_caches(self):
        """Повторный get возвращает закэшированный класс."""
        cls1 = TransportLoader.get("local")
        assert "local" in TransportLoader._cache
        cls2 = TransportLoader.get("local")
        assert cls2 is cls1

    def test_get_unknown_transport(self):
        """Несуществующий транспорт → TransportNotFoundError без двойного обёртывания.

        Сообщение сразу содержит имя транспорта и список доступных.
        """
        with pytest.raises(TransportNotFoundError) as exc_info:
            TransportLoader.get("no_such_transport_xyz")

        message = str(exc_info.value)
        assert "'no_such_transport_xyz' not found" in message
        assert "Available:" in message
        # Нет повторного обёртывания "Failed to load ... Transport ..."
        assert "Failed to load" not in message


class TestTransportLoaderList:
    """Тесты list_available/clear_cache."""

    def test_list_available(self):
        """Список содержит встроенные транспорты (redfish удалён)."""
        available = TransportLoader.list_available()
        for name in ("local", "ssh", "telnet", "serial", "ipmi"):
            assert name in available
        assert "redfish" not in available

    def test_clear_cache(self):
        """clear_cache очищает кэш."""
        TransportLoader.get("local")
        assert TransportLoader._cache
        TransportLoader.clear_cache()
        assert not TransportLoader._cache
