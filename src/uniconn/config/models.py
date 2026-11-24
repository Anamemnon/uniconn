# src/uniconn/config/models.py
"""Модель конфигурации подключения ConnectionConfig."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Self, cast

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationInfo, computed_field, model_validator

from .secrets import SecretResolver

_RESOLVE_SECRETS_VAR: ContextVar[bool] = ContextVar("_uniconn_resolve_secrets", default=True)
_SECRET_BASE_DIR_VAR: ContextVar[str | Path | None] = ContextVar("_uniconn_secret_base_dir", default=None)
_SECRET_TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"password", "passphrase"})
_SECRET_OPTION_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passphrase",
        "sudo_password",
        "enable_password",
        "token",
        "token_secret",
        "auth_token",
        "api_token",
        "api_key",
        "secret",
        "client_secret",
        "private_key",
        "key_passphrase",
        "proxy_password",
    }
)


def _is_secret_option_key(key: str) -> bool:
    norm = key.strip().lower()
    if norm in _SECRET_OPTION_KEYS:
        return True
    return norm.endswith(("_password", "_passphrase", "_secret", "_token", "_api_key"))


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
    def _resolve_secret_references(cls, data: Any, info: ValidationInfo) -> Any:
        """Разрешить ссылки ``env://`` и ``file://`` только в секретных полях конфигурации."""
        if not isinstance(data, Mapping):
            return data
        ctx = info.context if isinstance(info.context, Mapping) else {}
        if ctx.get("resolve_secrets", _RESOLVE_SECRETS_VAR.get()) is False:
            return data
        base_dir = ctx.get("secret_base_dir", _SECRET_BASE_DIR_VAR.get())
        resolved: dict[str, Any] = dict(data)
        for field_name in _SECRET_TOP_LEVEL_FIELDS:
            if field_name in resolved:
                resolved[field_name] = SecretResolver.resolve_value(
                    resolved[field_name],
                    base_dir=base_dir,
                )
        raw_opts = resolved.get("options")
        if isinstance(raw_opts, Mapping):
            new_opts: dict[str, Any] = {}
            for opt_key, opt_val in raw_opts.items():
                k_str = str(opt_key)
                if _is_secret_option_key(k_str):
                    new_opts[k_str] = SecretResolver.resolve_value(opt_val, base_dir=base_dir)
                else:
                    new_opts[k_str] = opt_val
            resolved["options"] = new_opts
        return resolved

    @computed_field
    @property
    def uri_safe(self) -> str:
        """URI без чувствительных данных (для логирования)."""
        if self.transport in ("serial", "uart"):
            dev = self.host or self.options.get("device") or ""
            baud = self.port or self.options.get("baudrate")
            suffix = f":{baud}" if baud else ""
            return f"{self.transport}://{dev}{suffix}"
        if self.transport in ("qga", "qemu-ga"):
            if self.host and self.host.startswith("/"):
                return f"{self.transport}://{self.host}"
            user_prefix = f"{self.username}@" if self.username else ""
            port_part = f":{self.port}" if self.port else ""
            vm_part = f"/{self.options['vm']}" if self.options.get("vm") else ""
            return f"{self.transport}://{user_prefix}{self.host or 'localhost'}{port_part}{vm_part}"
        if self.transport == "pve":
            user_prefix = f"{self.username}@" if self.username else ""
            port_part = f":{self.port}" if self.port else ""
            vmid_part = f"/{self.options['vmid']}" if self.options.get("vmid") is not None else ""
            return f"pve://{user_prefix}{self.host}:{self.port or 8006}{vmid_part}"
        user_prefix = f"{self.username}@" if self.username else ""
        port_suffix = f":{self.port}" if self.port is not None else ""
        return f"{self.transport}://{user_prefix}{self.host}{port_suffix}"

    @classmethod
    def from_uri(
        cls,
        uri: str,
        *,
        resolve_secrets: bool = True,
        base_dir: str | Path | None = None,
    ) -> Self:
        """Парсинг URI в конфигурацию."""
        from .uri import URIParser

        return cast(Self, URIParser.parse(uri, resolve_secrets=resolve_secrets, base_dir=base_dir))


__all__ = ["ConnectionConfig"]
