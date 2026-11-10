# src/uniconn/mcp/registry.py
"""Реестр хостов и фабрика защищённых подключений для MCP-сервера uniconn."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .._logging import SecretMaskingFilter
from ..config.inventory import InventoryLoader
from ..config.uri import URIParser
from ..core.connection import Connection
from ..exceptions import ConfigurationError
from ..hooks import (
    DEFAULT_BLOCKED_PATTERNS,
    allowlist_hook,
    audit_log_hook,
    blocklist_hook,
)
from .models import MCPHostEntry, MCPSecurityPolicy

_QUERY_SECRET_RE = re.compile(
    r"((?:password|passphrase|sudo_password|token_secret|token|secret|key)=)([^&\s]+)",
    re.IGNORECASE,
)


def mask_uri_secrets(uri: str) -> str:
    """Замаскировать учётные данные и секретные query-параметры в URI."""
    if not uri:
        return uri
    try:
        norm_uri = URIParser._normalize_inline_secret_in_userinfo(uri)
        parts = urlsplit(norm_uri)
        netloc = parts.netloc
        if "@" in netloc:
            userinfo, hostinfo = netloc.rsplit("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                netloc = f"{user}:***REDACTED***@{hostinfo}"
        query = _QUERY_SECRET_RE.sub(r"\1***REDACTED***", parts.query)
        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
    except Exception:
        return SecretMaskingFilter._mask_string(uri)


class MCPHostRegistry:
    """Реестр целевых хостов и групп с автоматическим применением политик безопасности."""

    def __init__(
        self,
        policy: MCPSecurityPolicy | None = None,
        *,
        entries: Sequence[MCPHostEntry] = (),
    ) -> None:
        """Инициализировать реестр хостов с заданной политикой безопасности."""
        self.policy = policy or MCPSecurityPolicy()
        self._entries: dict[str, MCPHostEntry] = {entry.name: entry for entry in entries}

    @classmethod
    def from_sources(
        cls,
        *,
        inventory: str | Path | None = None,
        uris: Sequence[str] = (),
        group: str | None = None,
        host: str | None = None,
        include_local: bool = False,
        default_to_local: bool = True,
        policy: MCPSecurityPolicy | None = None,
    ) -> MCPHostRegistry:
        """Собрать реестр хостов из файла инвентаря, списка URI и/или локального хоста."""
        entries: list[MCPHostEntry] = []
        seen_names: set[str] = set()

        if inventory is not None:
            raw_entries = InventoryLoader.load_file(inventory, host=host, group=group)
            for idx, item in enumerate(raw_entries, start=1):
                entry = cls._build_entry_from_dict(item, fallback_index=idx)
                entries.append(entry)
                seen_names.add(entry.name)

        for idx, raw_uri in enumerate(uris, start=1):
            uri_str = raw_uri.strip()
            if not uri_str:
                continue
            cfg = URIParser.parse(uri_str)
            candidate_name = cfg.host or f"{cfg.transport}-{idx}"
            if candidate_name in seen_names:
                candidate_name = f"{candidate_name}-{idx}"
            seen_names.add(candidate_name)
            entries.append(
                MCPHostEntry(
                    name=candidate_name,
                    uri=uri_str,
                    masked_uri=mask_uri_secrets(uri_str),
                    transport=cfg.transport,
                    host=cfg.host,
                    groups=(),
                    raw_config={"uri": uri_str, "name": candidate_name},
                )
            )

        if (include_local or (not entries and default_to_local)) and "local" not in seen_names:
            entries.append(
                MCPHostEntry(
                    name="local",
                    uri="local://",
                    masked_uri="local://",
                    transport="local",
                    host="localhost",
                    groups=("local",),
                    raw_config={"uri": "local://", "name": "local"},
                )
            )

        return cls(policy=policy, entries=entries)

    @staticmethod
    def _build_entry_from_dict(data: dict[str, Any], *, fallback_index: int) -> MCPHostEntry:
        """Преобразовать нормализованную запись ``InventoryLoader`` в ``MCPHostEntry``."""
        raw_copy = dict(data)
        raw_groups = raw_copy.get("groups") or ()
        if isinstance(raw_groups, str):
            groups = (raw_groups,)
        elif isinstance(raw_groups, Sequence):
            groups = tuple(str(g) for g in raw_groups)
        else:
            groups = ()

        uri_val = raw_copy.get("uri")
        if isinstance(uri_val, str) and uri_val.strip():
            cfg = URIParser.parse(uri_val)
            name = str(raw_copy.get("name") or cfg.host or f"{cfg.transport}-{fallback_index}")
            return MCPHostEntry(
                name=name,
                uri=uri_val,
                masked_uri=mask_uri_secrets(uri_val),
                transport=cfg.transport,
                host=cfg.host or name,
                groups=groups,
                raw_config=raw_copy,
            )

        transport = str(raw_copy.get("transport") or "ssh")
        host_val = raw_copy.get("host")
        name = str(raw_copy.get("name") or host_val or f"{transport}-{fallback_index}")
        user_val = raw_copy.get("username")
        pass_val = raw_copy.get("password")
        port_val = raw_copy.get("port")
        auth_prefix = ""
        if user_val:
            auth_prefix = f"{user_val}:secret@" if pass_val else f"{user_val}@"
        port_suffix = f":{port_val}" if port_val is not None else ""
        synthetic_uri = f"{transport}://{auth_prefix}{host_val or name}{port_suffix}"
        return MCPHostEntry(
            name=name,
            uri=synthetic_uri,
            masked_uri=mask_uri_secrets(synthetic_uri),
            transport=transport,
            host=str(host_val) if host_val is not None else name,
            groups=groups,
            raw_config=raw_copy,
        )

    def list_entries(self, *, group: str | None = None) -> list[MCPHostEntry]:
        """Вернуть список зарегистрированных хостов (опционально отфильтрованный по группе)."""
        all_entries = list(self._entries.values())
        if group is None:
            return all_entries
        return [e for e in all_entries if group in e.groups]

    def list_groups(self) -> dict[str, list[str]]:
        """Вернуть карту групп и входящих в них имён хостов."""
        groups_map: dict[str, list[str]] = {}
        for entry in self._entries.values():
            for grp in entry.groups:
                groups_map.setdefault(grp, []).append(entry.name)
        return groups_map

    def get_entry(self, target: str) -> MCPHostEntry:
        """Найти запись хоста по имени, адресу хоста или динамическому URI."""
        key = target.strip()
        if not key:
            raise ConfigurationError("Target host name or URI must not be empty")

        if key in self._entries:
            return self._entries[key]

        for entry in self._entries.values():
            if entry.host == key or entry.uri == key or entry.masked_uri == key:
                return entry

        if "://" in key:
            if not self.policy.allow_dynamic_uri:
                raise PermissionError(
                    f"Target URI {mask_uri_secrets(key)!r} is not registered in MCP host registry "
                    "and dynamic URIs are disabled (use --allow-dynamic-uri to permit)."
                )
            cfg = URIParser.parse(key)
            return MCPHostEntry(
                name=cfg.host or cfg.transport,
                uri=key,
                masked_uri=mask_uri_secrets(key),
                transport=cfg.transport,
                host=cfg.host,
                groups=(),
                raw_config={"uri": key},
            )

        available = ", ".join(sorted(self._entries.keys())) or "none"
        raise KeyError(f"Host {key!r} not found in MCP registry (available: {available})")

    def resolve_targets(
        self,
        targets: Sequence[str] | str | None = None,
        *,
        group: str | None = None,
    ) -> list[MCPHostEntry]:
        """Разрешить список имён хостов и/или имя группы в список ``MCPHostEntry``."""
        if group is not None:
            matched = self.list_entries(group=group)
            if not matched:
                raise KeyError(f"Group {group!r} not found or empty in MCP registry")
            if targets is None:
                return matched
            allowed_names = {e.name for e in matched}
            target_list = [targets] if isinstance(targets, str) else list(targets)
            resolved = [self.get_entry(t) for t in target_list if str(t).strip()]
            filtered = [e for e in resolved if e.name in allowed_names]
            if not filtered:
                raise KeyError(
                    f"None of the requested targets belong to group {group!r}"
                )
            return filtered

        if targets is None:
            all_entries = self.list_entries()
            if not all_entries:
                raise ConfigurationError("No hosts registered in MCP registry")
            return all_entries

        target_list = [targets] if isinstance(targets, str) else list(targets)
        resolved = [self.get_entry(t) for t in target_list if str(t).strip()]
        if not resolved:
            raise ConfigurationError("No valid targets specified")
        return resolved

    def create_connection(self, target: str | MCPHostEntry) -> Connection:
        """Создать ``Connection`` для целевого хоста с подключёнными хуками безопасности."""
        entry = target if isinstance(target, MCPHostEntry) else self.get_entry(target)
        raw = dict(entry.raw_config)
        raw["dry_run"] = self.policy.dry_run
        conn = Connection.from_dict(raw, dry_run=self.policy.dry_run)
        self._attach_security_hooks(conn)
        return conn

    def _attach_security_hooks(self, conn: Connection) -> None:
        """Навесить на ``Connection`` guardrails согласно ``MCPSecurityPolicy``."""
        patterns = list(DEFAULT_BLOCKED_PATTERNS)
        if self.policy.blocklist:
            patterns.extend(self.policy.blocklist)
        conn.add_hook("before_run", blocklist_hook(patterns))

        if self.policy.allowlist:
            conn.add_hook("before_run", allowlist_hook(self.policy.allowlist))

        if self.policy.audit_log_path:
            conn.add_hook(
                "after_run",
                audit_log_hook(
                    self.policy.audit_log_path,
                    include_output=True,
                    mask_secrets=True,
                ),
            )


__all__ = [
    "MCPHostRegistry",
    "mask_uri_secrets",
]
