# src/uniconn/config/uri.py
"""Парсер URI для различных транспортов.

Поддерживаемые форматы:
    - ssh://[user[:password]@]host[:port][?option=value]
    - telnet://[user[:password]@]host[:port][?option=value]
    - serial:///dev/ttyUSB0?baudrate=9600&parity=N
    - local://[?option=value]
    - ipmi://[user[:password]@]host[:port]
    - redfish://[user[:password]@]host[:port][?verify_ssl=false&system_id=1]
    - winrm://[user[:password]@]host[:5985][?transport=ntlm&server_cert_validation=ignore]
    - wsman://[user[:password]@]host[:5985][?transport=kerberos&ssl=true]
    - qga://[user[:password]@][host[:port]]/socket_or_vm[?backend=socket&socket=/path]
    - qemu-ga://[user[:password]@][host[:port]]/socket_or_vm[?backend=socket&socket=/path]
    - pve://[user[@realm][:password]@]host[:8006][/vmid][?node=pve1&token_id=id&secret=...]
    - replay:///path/to/cassette.yaml

Логин и пароль при парсинге подвергаются percent-decoding (unquote),
а в ``build()`` — экранируются (quote), так что спецсимволы вроде
``@``, ``:``, ``/`` в креденшелах переживают round-trip parse → build.
Повторяющиеся query-параметры: побеждает последнее значение.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import ParseResult, parse_qs, quote, unquote, urlparse

from .._utils import parse_bool
from ..exceptions import ConfigurationError

if TYPE_CHECKING:
    from .models import ConnectionConfig

_INLINE_SECRET_URI_RE = re.compile(
    r"^([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#:]*:)([a-zA-Z][a-zA-Z0-9+.-]*)://([^@#]+)(@[^/?#@]+(?:[/?#].*)?)$"
)
_WINDOWS_PIPE_PREFIXES = ("\\\\.\\pipe\\", "//./pipe/")
_LOCAL_QGA_HOSTS = ("localhost", "127.0.0.1", "::1")


def _is_windows_pipe_path(path: str | None) -> bool:
    return bool(path and path.strip().lower().startswith(_WINDOWS_PIPE_PREFIXES))


def _format_uri_host(host: str | None) -> str:
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


class URIParser:
    """Парсер URI строк в ConnectionConfig."""

    DEFAULT_PORTS = {
        "ssh": 22,
        "telnet": 23,
        "ipmi": 623,
        "redfish": 443,
        "winrm": 5985,
        "wsman": 5985,
        "pve": 8006,
        "qga": 22,
        "qemu-ga": 22,
        "netconf": 830,
        "restconf": 443,
        "gnmi": 9339,
    }

    @classmethod
    def _normalize_inline_secret_in_userinfo(cls, uri: str) -> str:
        """Экранировать встроенные секретные URI (``env://``, ``file://`` и плагины) внутри пароля в userinfo."""
        if uri.count("://") < 2:
            return uri
        match = _INLINE_SECRET_URI_RE.match(uri)
        if not match:
            return uri
        prefix, secret_scheme, secret_target, suffix = match.groups()
        from .secrets import SecretResolver

        if secret_scheme.lower() not in set(SecretResolver.list_schemes()):
            return uri
        encoded_secret = f"{secret_scheme}%3A%2F%2F{quote(secret_target, safe='')}"
        return f"{prefix}{encoded_secret}{suffix}"

    @classmethod
    def parse(
        cls,
        uri: str,
        *,
        resolve_secrets: bool = True,
        base_dir: str | Path | None = None,
    ) -> ConnectionConfig:
        """Распарсить URI в ConnectionConfig.

        Args:
            uri: URI строка (например, "ssh://user:pass@host:22")
            resolve_secrets: Разрешать ли ссылки ``env://`` и ``file://`` в секретных полях.
                Для недоверенного пользовательского ввода следует передавать ``False``.
            base_dir: Опциональная корневая директория для ограничения ``file://`` секретов.

        Returns:
            ConnectionConfig объект

        Raises:
            ConfigurationError: Если URI некорректен (наследуется от ValueError)

        """
        from pydantic import ValidationError

        from .models import _RESOLVE_SECRETS_VAR, _SECRET_BASE_DIR_VAR

        normalized_uri = cls._normalize_inline_secret_in_userinfo(uri)
        parsed = urlparse(normalized_uri)

        if not parsed.scheme:
            raise ConfigurationError(
                f"URI должен содержать схему (transport://...): {uri}"
            )

        transport = parsed.scheme.lower()
        token = _RESOLVE_SECRETS_VAR.set(resolve_secrets)
        base_dir_token = _SECRET_BASE_DIR_VAR.set(base_dir) if base_dir is not None else None
        try:
            if transport in ("serial", "uart"):
                return cls._parse_serial(parsed, uri, transport=transport)

            if transport == "local":
                return cls._parse_local(parsed)

            if transport == "replay":
                return cls._parse_replay(parsed)

            if transport in ("qga", "qemu-ga"):
                return cls._parse_qga(parsed, transport)

            if transport == "pve":
                return cls._parse_pve(parsed)

            return cls._parse_network(parsed, transport)
        except ValidationError as exc:
            for err in exc.errors():
                ctx = err.get("ctx")
                orig = ctx.get("error") if isinstance(ctx, dict) else None
                if isinstance(orig, ConfigurationError):
                    raise orig from exc
            raise
        finally:
            if base_dir_token is not None:
                _SECRET_BASE_DIR_VAR.reset(base_dir_token)
            _RESOLVE_SECRETS_VAR.reset(token)

    @classmethod
    def _parse_replay(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг replay URI."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        cassette_path = parsed.path or parsed.netloc
        if cassette_path and "cassette" not in options:
            options["cassette"] = cassette_path
        host = str(options.get("host", parsed.hostname or "replay"))
        return ConnectionConfig(
            transport="replay",
            host=host,
            port=None,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_network(cls, parsed: ParseResult, transport: str) -> ConnectionConfig:
        """Парсинг сетевых транспортов (ssh, telnet, ipmi, redfish)."""
        from pydantic import SecretStr

        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        port = parsed.port
        if port is None and transport in cls.DEFAULT_PORTS:
            if (
                transport in ("redfish", "restconf")
                and str(options.get("scheme", "https")).lower() == "http"
            ):
                port = 80
            elif transport in ("winrm", "wsman") and (
                parse_bool(options.get("ssl"), default=False)
                or str(options.get("scheme", "")).lower() == "https"
                or str(options.get("transport", "")).lower() == "ssl"
            ):
                port = 5986
            else:
                port = cls.DEFAULT_PORTS[transport]
        if transport == "restconf" and parsed.path and parsed.path != "/":
            clean_path = "/" + unquote(parsed.path).strip("/")
            if clean_path.endswith("/data"):
                clean_path = clean_path[: -len("/data")] or "/restconf"
            elif clean_path.endswith("/operations"):
                clean_path = clean_path[: -len("/operations")] or "/restconf"
            options.setdefault("root", clean_path)
        if transport == "netconf" and "version" in options:
            options["version"] = str(options["version"])
        key_file = str(options.pop("key_file")) if "key_file" in options else None
        raw_passphrase = options.pop("passphrase", None)
        passphrase = (
            SecretStr(str(raw_passphrase)) if raw_passphrase is not None else None
        )
        raw_query_password = options.pop("password", None)
        password_val = (
            SecretStr(unquote(parsed.password))
            if parsed.password
            else (
                SecretStr(str(raw_query_password))
                if raw_query_password is not None
                else None
            )
        )
        ssh_config: str | bool | None = None
        if "ssh_config" in options:
            raw_ssh_cfg = options["ssh_config"]
            ssh_config = (
                raw_ssh_cfg if isinstance(raw_ssh_cfg, bool) else str(raw_ssh_cfg)
            )

        return ConnectionConfig(
            transport=transport,
            host=parsed.hostname,
            port=port,
            username=unquote(parsed.username) if parsed.username else None,
            password=password_val,
            key_file=key_file,
            passphrase=passphrase,
            ssh_config=ssh_config,
            options=options,
        )

    @classmethod
    def _parse_serial(
        cls,
        parsed: ParseResult,
        uri: str,
        transport: str = "serial",
    ) -> ConnectionConfig:
        """Парсинг serial и uart URI."""
        from .models import ConnectionConfig

        _ = uri
        options = cls._parse_options(parsed.query)
        device = parsed.netloc or parsed.path

        if ":" in device:
            dev_candidate, _, baud_candidate = device.rpartition(":")
            if baud_candidate.isdigit():
                device = dev_candidate
                options.setdefault("baudrate", int(baud_candidate))

        if device.startswith("/"):
            trimmed = device.lstrip("/")
            if trimmed.upper().startswith("COM") and trimmed[3:].isdigit():
                device = trimmed

        if device:
            options["device"] = device
        elif "device" in options:
            device = str(options["device"])

        baud_val = options.get("baudrate")
        baud_int = (
            int(baud_val)
            if isinstance(baud_val, int | str) and str(baud_val).isdigit()
            else None
        )

        return ConnectionConfig(
            transport=transport,
            host=device or None,
            port=baud_int,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_local(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг local URI."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        host = (
            str(options["host"])
            if "host" in options
            else (parsed.hostname or "localhost")
        )

        return ConnectionConfig(
            transport="local",
            host=host,
            port=None,
            username=None,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_qga(cls, parsed: ParseResult, transport: str) -> ConnectionConfig:
        """Парсинг qga:// и qemu-ga:// URI (локальный сокет, SSH-туннель к сокету, virsh)."""
        from pydantic import SecretStr

        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        key_file = str(options.pop("key_file")) if "key_file" in options else None
        raw_passphrase = options.pop("passphrase", None)
        passphrase = (
            SecretStr(str(raw_passphrase)) if raw_passphrase is not None else None
        )
        raw_query_password = options.pop("password", None)
        password_val = (
            SecretStr(unquote(parsed.password))
            if parsed.password
            else (
                SecretStr(str(raw_query_password))
                if raw_query_password is not None
                else None
            )
        )
        ssh_config: str | bool | None = None
        if "ssh_config" in options:
            raw_ssh_cfg = options["ssh_config"]
            ssh_config = (
                raw_ssh_cfg if isinstance(raw_ssh_cfg, bool) else str(raw_ssh_cfg)
            )

        # Случай 1: qga:///path/to/socket.sock или qga://?backend=pipe&pipe=\\.\pipe\qga-vm1
        if not parsed.netloc:
            raw_path = unquote(parsed.path) if parsed.path else ""
            raw_pipe = str(options.get("pipe", "")) if "pipe" in options else ""
            raw_socket = raw_path or (str(options["socket"]) if "socket" in options else "")
            is_pipe_target = (
                bool(raw_pipe)
                or str(options.get("backend", "")).strip().lower() == "pipe"
                or _is_windows_pipe_path(raw_socket)
            )
            if is_pipe_target:
                pipe_val = raw_pipe or raw_socket
                if pipe_val:
                    options["pipe"] = pipe_val
                    if "socket" in options and str(options["socket"]) == pipe_val:
                        options.pop("socket", None)
                options["backend"] = "pipe"
                return ConnectionConfig(
                    transport=transport,
                    host=pipe_val or "localhost",
                    port=None,
                    username=None,
                    password=None,
                    options=options,
                )

            socket_path = raw_socket
            if socket_path:
                options.setdefault("socket", socket_path)
            options.setdefault("backend", "socket")
            return ConnectionConfig(
                transport=transport,
                host=socket_path or "localhost",
                port=None,
                username=None,
                password=None,
                options=options,
            )

        # Случай 2: qga://[user@]hypervisor[:port][/vm-name][?socket=...&backend=...]
        path_trimmed = unquote(parsed.path.strip("/")) if parsed.path else ""
        if path_trimmed:
            options.setdefault("vm", path_trimmed)
            options.setdefault("domain", path_trimmed)

        explicit_backend = str(options.get("backend", "")).strip().lower()
        port = parsed.port
        is_local_tcp = (
            not explicit_backend
            and parsed.hostname in _LOCAL_QGA_HOSTS
            and port is not None
            and not path_trimmed
            and "socket" not in options
        )
        if explicit_backend == "tcp" or is_local_tcp:
            options["backend"] = "tcp"
        elif port is None and parsed.hostname not in (None, "", *_LOCAL_QGA_HOSTS):
            port = cls.DEFAULT_PORTS.get(transport, 22)

        return ConnectionConfig(
            transport=transport,
            host=parsed.hostname,
            port=port,
            username=unquote(parsed.username) if parsed.username else None,
            password=password_val,
            key_file=key_file,
            passphrase=passphrase,
            ssh_config=ssh_config,
            options=options,
        )

    @classmethod
    def _parse_pve(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг pve://[user[@realm][!token_id][:password]@]host[:8006][/vmid][?node=...&token_id=...&secret=...]."""
        from pydantic import SecretStr

        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        port = parsed.port if parsed.port is not None else cls.DEFAULT_PORTS["pve"]

        raw_user = unquote(parsed.username) if parsed.username else None
        username: str | None = raw_user
        if raw_user and "!" in raw_user:
            user_part, token_part = raw_user.split("!", 1)
            username = user_part or None
            if token_part and "token_id" not in options:
                options["token_id"] = token_part

        if username and "@" in username:
            _, realm_part = username.rsplit("@", 1)
            if realm_part and "realm" not in options:
                options["realm"] = realm_part
        elif username and "realm" in options:
            username = f"{username}@{options['realm']}"

        raw_query_password = options.pop("password", None)
        password_str = (
            unquote(parsed.password)
            if parsed.password
            else (str(raw_query_password) if raw_query_password is not None else None)
        )
        if (
            password_str is not None
            and "token_id" in options
            and "secret" not in options
            and "token_secret" not in options
        ):
            options["secret"] = password_str

        password_val = SecretStr(password_str) if password_str is not None else None

        path_trimmed = unquote(parsed.path.strip("/")) if parsed.path else ""
        if path_trimmed:
            vmid_token = path_trimmed.split("/")[-1]
            if vmid_token and "vmid" not in options:
                options["vmid"] = int(vmid_token) if vmid_token.isdigit() else vmid_token

        return ConnectionConfig(
            transport="pve",
            host=parsed.hostname,
            port=port,
            username=username,
            password=password_val,
            options=options,
        )

    @classmethod
    def _parse_options(cls, query: str) -> dict[str, Any]:
        """Парсинг query строки в словарь опций."""
        if not query:
            return {}

        parsed = parse_qs(query, keep_blank_values=True)
        options: dict[str, Any] = {}

        for key, values in parsed.items():
            options[key] = cls._convert_type(values[-1])

        return options

    @classmethod
    def _convert_type(cls, value: str) -> int | float | bool | str:
        """Конвертация строкового значения в соответствующий тип."""
        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            pass

        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False

        return value

    @classmethod
    def _build_query_string(cls, opts: dict[str, Any]) -> str:
        """Собрать query-строку из словаря опций с безопасным экранированием значений."""
        safe_chars = "/:\\.,~-@"
        return "&".join(
            f"{quote(str(k), safe='')}={quote(str(v), safe=safe_chars)}"
            for k, v in opts.items()
        )

    @classmethod
    def build(
        cls,
        transport: str,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        options: dict[str, Any] | None = None,
        *,
        key_file: str | None = None,
        ssh_config: str | bool | None = None,
    ) -> str:
        """Собрать URI строку из компонентов."""
        merged_opts = dict(options) if options else {}
        if key_file is not None and "key_file" not in merged_opts:
            merged_opts["key_file"] = key_file
        if ssh_config is not None and "ssh_config" not in merged_opts:
            merged_opts["ssh_config"] = ssh_config

        if transport == "local":
            if merged_opts:
                return f"local://?{cls._build_query_string(merged_opts)}"
            return "local://"

        if transport in ("serial", "uart"):
            device = host or (merged_opts.get("device") if merged_opts else "") or ""
            opts = dict(merged_opts)
            opts.pop("device", None)
            if opts:
                return f"{transport}://{device}?{cls._build_query_string(opts)}"
            return f"{transport}://{device}"

        if transport in ("qga", "qemu-ga"):
            opts = dict(merged_opts)
            backend_val = str(opts.get("backend", "")).strip().lower()
            is_pipe_host = _is_windows_pipe_path(host)
            if backend_val == "pipe" or "pipe" in opts or is_pipe_host:
                if "pipe" not in opts and is_pipe_host and host:
                    opts["pipe"] = host
                opts["backend"] = "pipe"
                return f"{transport}://?{cls._build_query_string(opts)}"
            if (host and host.startswith("/")) or (not host and "socket" in opts):
                sock_path = host if (host and host.startswith("/")) else str(opts.pop("socket", ""))
                opts.pop("socket", None)
                if opts.get("backend") == "socket":
                    opts.pop("backend", None)
                if opts:
                    return f"{transport}://{sock_path}?{cls._build_query_string(opts)}"
                return f"{transport}://{sock_path}"
            vm_name = opts.pop("vm", None) or opts.pop("domain", None)
            opts.pop("domain", None)
            auth = ""
            if username and password:
                auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
            elif username:
                auth = f"{quote(username, safe='')}@"
            port_str = f":{port}" if port else ""
            vm_suffix = f"/{vm_name}" if vm_name else ""
            uri = f"{transport}://{auth}{_format_uri_host(host)}{port_str}{vm_suffix}"
            if opts:
                uri = f"{uri}?{cls._build_query_string(opts)}"
            return uri

        if transport == "pve":
            opts = dict(merged_opts)
            vmid = opts.pop("vmid", None)
            auth = ""
            if username and password:
                auth = f"{quote(username, safe='@!')}:{quote(password, safe='')}@"
            elif username:
                auth = f"{quote(username, safe='@!')}@"
            port_str = f":{port}" if port else ""
            vmid_suffix = f"/{vmid}" if vmid is not None else ""
            uri = f"pve://{auth}{host or ''}{port_str}{vmid_suffix}"
            if opts:
                uri = f"{uri}?{cls._build_query_string(opts)}"
            return uri

        opts = dict(merged_opts)
        path_suffix = ""
        if transport == "restconf" and "root" in opts:
            root_val = str(opts.pop("root")).strip()
            if root_val and root_val.lower() not in ("auto", "/auto"):
                path_suffix = "/" + root_val.strip("/")
            elif root_val:
                opts["root"] = "auto"

        auth = ""
        if username and password:
            auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
        elif username:
            auth = f"{quote(username, safe='')}@"

        port_str = f":{port}" if port else ""

        uri = f"{transport}://{auth}{host or ''}{port_str}{path_suffix}"

        if opts:
            uri = f"{uri}?{cls._build_query_string(opts)}"

        return uri

    @classmethod
    def from_config(cls, config: ConnectionConfig, *, include_secrets: bool = False) -> str:
        """Собрать URI строку напрямую из объекта ``ConnectionConfig`` с сохранением всех полей."""
        pwd: str | None = None
        if include_secrets and config.password is not None:
            pwd = config.password.get_secret_value()
        return cls.build(
            transport=config.transport,
            host=config.host,
            port=config.port,
            username=config.username,
            password=pwd,
            options=config.options,
            key_file=config.key_file,
            ssh_config=config.ssh_config,
        )


__all__ = ["URIParser"]

