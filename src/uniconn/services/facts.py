# src/uniconn/services/facts.py
"""Доменный сервис сбора системных фактов (HostFacts) о целевом хосте."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._facts import (
    DEFAULT_DIFF_FIELDS,
    FACT_COLLECTION_SCRIPT,
    DiskInfo,
    FactsDiffReport,
    HostFacts,
    NetworkInterface,
    diff_facts,
    parse_facts_output,
)

if TYPE_CHECKING:
    from .._connection import Connection


class FactCollector:
    """Сервис инспекции хоста и кэширования ``HostFacts``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сборщик фактов для подключения."""
        self._conn = conn
        self.cached: HostFacts | None = None

    async def gather(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты за один батч-запрос (с кэшированием)."""
        if not refresh and self.cached is not None:
            return self.cached

        default_host = self._conn._config.host or "localhost"
        if self._conn._dry_run:
            facts = HostFacts(hostname=default_host)
            self.cached = facts
            return facts

        res = await self._conn.run(
            FACT_COLLECTION_SCRIPT,
            timeout=timeout,
            raise_on_error=False,
        )
        facts = parse_facts_output(res.stdout, default_host=default_host)
        self.cached = facts
        return facts


__all__ = [
    "DEFAULT_DIFF_FIELDS",
    "FACT_COLLECTION_SCRIPT",
    "DiskInfo",
    "FactCollector",
    "FactsDiffReport",
    "HostFacts",
    "NetworkInterface",
    "diff_facts",
    "parse_facts_output",
]
