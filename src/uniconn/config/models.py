# src/uniconn/config/models.py
"""Модель конфигурации подключения ConnectionConfig."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Self, cast

from pydantic import BaseModel, ConfigDict, Field, SecretStr, computed_field, model_validator

from .secrets import SecretResolver


class ConnectionConfig(BaseModel):
    """Конфигурация подключения с автоматическим разрешением секретов (``env://``, ``file://``)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    transport: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: SecretStr | None = None
    key_file: str | None = None
    passphrase: SecretStr | None = None
    ssh_config: str | bool | None = None
    timeout: float = 30.0
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _resolve_secret_references(cls, data: Any) -> Any:
        """Разрешить ссылки ``env://`` и ``file://`` во всех полях конфигурации."""
        if isinstance(data, Mapping):
            return SecretResolver.resolve_mapping(data)
        return data

    @computed_field
    @property
    def uri_safe(self) -> str:
        """URI без чувствительных данных (для логирования)."""
        if self.password:
            return f"{self.transport}://{self.username}@{self.host}:{self.port}"
        return f"{self.transport}://{self.host}:{self.port}"

    @classmethod
    def from_uri(cls, uri: str) -> Self:
        """Парсинг URI в конфигурацию."""
        from .uri import URIParser

        return cast(Self, URIParser.parse(uri))


__all__ = ["ConnectionConfig"]

