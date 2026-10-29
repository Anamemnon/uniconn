# src/uniconn/_facts.py
"""Обратно-совместимый реэкспорт моделей и парсеров фактов из uniconn.services.facts_models."""

from .services.facts_models import (
    DEFAULT_DIFF_FIELDS,
    FACT_COLLECTION_SCRIPT,
    WINDOWS_FACT_POWERSHELL_SCRIPT,
    CustomCommandSpec,
    DiskInfo,
    ExternalToolSpec,
    FactsDiffReport,
    FactSpec,
    FileSourceSpec,
    HostFacts,
    NetworkInterface,
    diff_facts,
    parse_facts_output,
    parse_windows_facts_output,
)

__all__ = [
    "DEFAULT_DIFF_FIELDS",
    "FACT_COLLECTION_SCRIPT",
    "WINDOWS_FACT_POWERSHELL_SCRIPT",
    "CustomCommandSpec",
    "DiskInfo",
    "ExternalToolSpec",
    "FactSpec",
    "FactsDiffReport",
    "FileSourceSpec",
    "HostFacts",
    "NetworkInterface",
    "diff_facts",
    "parse_facts_output",
    "parse_windows_facts_output",
]
