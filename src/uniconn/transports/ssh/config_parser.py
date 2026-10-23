# src/uniconn/transports/ssh/config_parser.py
"""Парсер конфигурационных файлов OpenSSH (~/.ssh/config) и резолвер known_hosts."""

from __future__ import annotations

import contextlib
import fnmatch
from pathlib import Path
from typing import Any

from ..._config import ConnectionConfig
from ...exceptions import ConnectionError


class OpenSSHConfigParser:
    """Сервис разбора директив OpenSSH и подстановки токенов ``ProxyCommand``."""

    @staticmethod
    def expand_proxy_command(
        template: str,
        host: str | None,
        port: int | None,
        username: str | None,
    ) -> str:
        """Подставить токены OpenSSH (``%h``, ``%p``, ``%r``, ``%%``) в строку ProxyCommand."""
        sentinel = "\x00PERCENT\x00"
        expanded = template.replace("%%", sentinel)
        expanded = expanded.replace("%h", str(host or ""))
        expanded = expanded.replace("%p", str(port or 22))
        expanded = expanded.replace("%r", str(username or ""))
        return expanded.replace(sentinel, "%")

    @staticmethod
    def resolve_known_hosts(known_hosts_option: Any, host: str | None = None) -> str | None:
        """Определить политику проверки known_hosts."""
        mode = str(known_hosts_option).lower()

        if mode in ("no", "false", "none", ""):
            return None

        if mode in ("strict", "default"):
            known_hosts_path = Path.home() / ".ssh" / "known_hosts"
            if known_hosts_path.exists():
                return str(known_hosts_path)
            return None

        path = Path(str(known_hosts_option)).expanduser()
        if path.exists():
            return str(path)

        raise ConnectionError(
            f"known_hosts file not found: {path}",
            host=host,
        )

    @staticmethod
    def resolve_ssh_config_files(config: ConnectionConfig) -> list[str] | None:
        """Определить список файлов конфигурации OpenSSH (``ssh_config``)."""
        opt = (
            config.ssh_config
            if config.ssh_config is not None
            else config.options.get("ssh_config")
        )
        if opt is False or (
            opt is not None and str(opt).lower() in ("false", "no", "none", "0", "")
        ):
            return None

        if opt is None:
            default_cfg = Path.home() / ".ssh" / "config"
            return [str(default_cfg)] if default_cfg.exists() else None

        if opt is True or str(opt).lower() in ("true", "yes", "1", "default"):
            default_cfg = Path.home() / ".ssh" / "config"
            return [str(default_cfg)] if default_cfg.exists() else []

        cfg_path = Path(str(opt)).expanduser()
        if cfg_path.exists():
            return [str(cfg_path)]

        raise ConnectionError(
            f"ssh_config file not found: {cfg_path}",
            host=config.host,
        )

    @staticmethod
    def parse_file(
        config_path: str | Path,
        host: str | None,
    ) -> dict[str, Any]:
        """Распарсить директивы OpenSSH config для заданного хоста/алиаса (first-match-wins)."""
        if not host:
            return {}
        path = Path(config_path).expanduser()
        if not path.is_file():
            return {}

        matched_directives: dict[str, Any] = {}
        current_matches = False

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return {}

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and (" " not in line or line.index("=") < line.index(" ")):
                key, val = line.split("=", 1)
            else:
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                key, val = parts[0], parts[1]

            key_lower = key.strip().lower()
            val = val.strip().strip('"')

            if key_lower == "host":
                patterns = val.split()
                pos_match = False
                neg_match = False
                for pat in patterns:
                    if pat.startswith("!"):
                        if fnmatch.fnmatchcase(host, pat[1:]):
                            neg_match = True
                    elif fnmatch.fnmatchcase(host, pat):
                        pos_match = True
                current_matches = pos_match and not neg_match
                continue

            if not current_matches:
                continue

            if key_lower == "hostname" and "hostname" not in matched_directives:
                matched_directives["hostname"] = val
            elif key_lower == "user" and "user" not in matched_directives:
                matched_directives["user"] = val
            elif key_lower == "port" and "port" not in matched_directives:
                with contextlib.suppress(ValueError):
                    matched_directives["port"] = int(val)
            elif key_lower == "identityfile" and "identityfile" not in matched_directives:
                matched_directives["identityfile"] = str(Path(val).expanduser())
            elif key_lower == "proxyjump" and "proxyjump" not in matched_directives:
                matched_directives["proxyjump"] = val
            elif key_lower == "proxycommand" and "proxycommand" not in matched_directives:
                matched_directives["proxycommand"] = val

        return matched_directives
