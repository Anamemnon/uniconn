# src/uniconn/_config.py
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, computed_field


class ConnectionConfig(BaseModel):
    """Конфигурация подключения."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    transport: str
    host: str | None = None
    port: int | None = None
    username: str | None = None
    password: SecretStr | None = None
    key_file: str | None = None
    timeout: float = 30.0
    options: dict[str, Any] = Field(default_factory=dict)

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
        from ._uri import URIParser
        return URIParser.parse(uri)
