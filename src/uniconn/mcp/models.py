# src/uniconn/mcp/models.py
"""Модели данных, политики безопасности и определения инструментов для MCP-сервера uniconn."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MCPSecurityPolicy(BaseModel):
    """Политика безопасности и guardrails для MCP-сервера ``uniconn mcp``.

    По умолчанию сервер запускается в безопасном режиме (Safe Mode):
    - Запись файлов (``allow_write=False``) и ``sudo`` (``allow_sudo=False``) отключены.
    - Произвольные динамические URI вне реестра (``allow_dynamic_uri=False``) запрещены.
    - Включён базовый ``blocklist_hook`` против деструктивных команд и маскирование секретов.
    """

    model_config = ConfigDict(frozen=True)

    allow_write: bool = False
    allow_sudo: bool = False
    allow_dynamic_uri: bool = False
    dry_run: bool = False
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] | None = None
    audit_log_path: str | None = None
    max_read_bytes: int = Field(default=65536, ge=1024, le=10_485_760)

    def to_summary_dict(self) -> dict[str, Any]:
        """Вернуть публичную сводку активной политики безопасности."""
        return {
            "allow_write": self.allow_write,
            "allow_sudo": self.allow_sudo,
            "allow_dynamic_uri": self.allow_dynamic_uri,
            "dry_run": self.dry_run,
            "allowlist": list(self.allowlist),
            "custom_blocklist": list(self.blocklist) if self.blocklist is not None else None,
            "audit_log_enabled": self.audit_log_path is not None,
            "max_read_bytes": self.max_read_bytes,
        }


class MCPHostEntry(BaseModel):
    """Запись о зарегистрированном хосте в реестре MCP-сервера."""

    model_config = ConfigDict(frozen=True)

    name: str
    uri: str
    masked_uri: str
    transport: str
    host: str | None = None
    groups: tuple[str, ...] = ()
    raw_config: dict[str, Any] = Field(default_factory=dict, repr=False, exclude=True)

    def to_public_dict(self) -> dict[str, Any]:
        """Сериализовать запись хоста без раскрытия секретов и паролей."""
        return {
            "name": self.name,
            "uri": self.masked_uri,
            "transport": self.transport,
            "host": self.host,
            "groups": list(self.groups),
        }


class MCPToolDefinition(BaseModel):
    """Описание MCP-инструмента (Tool) в формате JSON Schema."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать определение в формат ответа ``tools/list`` протокола MCP."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class MCPResourceDefinition(BaseModel):
    """Описание статического MCP-ресурса (Resource)."""

    model_config = ConfigDict(frozen=True)

    uri: str
    name: str
    description: str
    mime_type: str = "application/json"

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать ресурс в формат ответа ``resources/list`` протокола MCP."""
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


class MCPResourceTemplate(BaseModel):
    """Описание параметризованного шаблона MCP-ресурса (Resource Template)."""

    model_config = ConfigDict(frozen=True)

    uri_template: str
    name: str
    description: str
    mime_type: str = "application/json"

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать шаблон в формат ответа ``resources/templates/list``."""
        return {
            "uriTemplate": self.uri_template,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


__all__ = [
    "MCPHostEntry",
    "MCPResourceDefinition",
    "MCPResourceTemplate",
    "MCPSecurityPolicy",
    "MCPToolDefinition",
]
