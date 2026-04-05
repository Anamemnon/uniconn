# src/uniconn/_config.py
from pydantic import BaseModel, SecretStr, Field, computed_field, ConfigDict
from typing import Optional, Dict, Any, Self
from urllib.parse import urlparse, parse_qs

class ConnectionConfig(BaseModel):
    """Конфигурация подключения"""
    model_config = ConfigDict(frozen=True, extra="ignore")
    
    transport: str
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    key_file: Optional[str] = None
    timeout: float = 30.0
    options: Dict[str, Any] = Field(default_factory=dict)
    
    @computed_field
    @property
    def uri_safe(self) -> str:
        """URI без чувствительных данных (для логирования)"""
        if self.password:
            return f"{self.transport}://{self.username}@{self.host}:{self.port}"
        return f"{self.transport}://{self.host}:{self.port}"
    
    @classmethod
    def from_uri(cls, uri: str) -> Self:
        """Парсинг URI в конфигурацию"""
        from ._uri import URIParser
        return URIParser.parse(uri)