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
    - docker://[user@]container[/workdir]
    - podman://[user@]container[/workdir]
    - kubectl://[namespace/]pod[?container=name&context=ctx]
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
from typing import TYPE_CHECKING, Any
from urllib.parse import ParseResult, parse_qs, quote, unquote, urlparse

from ..exceptions import ConfigurationError

if TYPE_CHECKING:
    from .models import ConnectionConfig

_INLINE_SECRET_URI_RE = re.compile(
    r"^([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#:]*:)(env|file)://([^@/?#]+)(@.*)$"
)


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
    }

    @classmethod
    def _normalize_inline_secret_in_userinfo(cls, uri: str) -> str:
        """Экранировать ``env://`` и ``file://`` внутри пароля в userinfo перед ``urlparse``."""
        match = _INLINE_SECRET_URI_RE.match(uri)
        if not match:
            return uri
        prefix, secret_scheme, secret_target, suffix = match.groups()
        encoded_secret = f"{secret_scheme}%3A%2F%2F{quote(secret_target, safe='')}"
        return f"{prefix}{encoded_secret}{suffix}"

    @classmethod
    def parse(cls, uri: str) -> ConnectionConfig:
        """Распарсить URI в ConnectionConfig.

        Args:
            uri: URI строка (например, "ssh://user:pass@host:22")

        Returns:
            ConnectionConfig объект

        Raises:
            ConfigurationError: Если URI некорректен (наследуется от ValueError)

        """
        normalized_uri = cls._normalize_inline_secret_in_userinfo(uri)
        parsed = urlparse(normalized_uri)

        if not parsed.scheme:
            raise ConfigurationError(
                f"URI должен содержать схему (transport://...): {uri}"
            )

        transport = parsed.scheme.lower()

        if transport in ("serial", "uart"):
            return cls._parse_serial(parsed, uri, transport=transport)

        if transport == "local":
            return cls._parse_local(parsed)

        if transport == "replay":
            return cls._parse_replay(parsed)

        if transport in ("docker", "podman"):
            return cls._parse_container(parsed, transport)

        if transport == "kubectl":
            return cls._parse_kubectl(parsed)

        if transport in ("qga", "qemu-ga"):
            return cls._parse_qga(parsed, transport)

        if transport == "pve":
            return cls._parse_pve(parsed)

        return cls._parse_network(parsed, transport)

    @classmethod
    def _parse_container(cls, parsed: ParseResult, transport: str) -> ConnectionConfig:
        """Парсинг docker:// и podman:// URI с сохранением регистра имени контейнера."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        if transport == "podman":
            options.setdefault("runtime", "podman")

        netloc = parsed.netloc
        username: str | None = None
        host_part = netloc
        if "@" in netloc:
            raw_user, host_part = netloc.rsplit("@", 1)
            if ":" in raw_user:
                raw_user, _ = raw_user.split(":", 1)
            username = unquote(raw_user) if raw_user else None

        port: int | None = None
        if ":" in host_part:
            maybe_host, maybe_port = host_part.rsplit(":", 1)
            if maybe_port.isdigit():
                host_part = maybe_host
                port = int(maybe_port)

        container_name = unquote(host_part) or unquote(parsed.path.strip("/"))
        if not container_name and "container" in options:
            container_name = str(options.pop("container"))

        if parsed.path and parsed.path != "/" and unquote(host_part):
            options.setdefault("workdir", unquote(parsed.path))

        return ConnectionConfig(
            transport=transport,
            host=container_name or None,
            port=port,
            username=username,
            password=None,
            options=options,
        )

    @classmethod
    def _parse_kubectl(cls, parsed: ParseResult) -> ConnectionConfig:
        """Парсинг kubectl://[namespace/]pod_name[?container=...&context=...&kubeconfig=...]."""
        from .models import ConnectionConfig

        options = cls._parse_options(parsed.query)
        netloc = unquote(parsed.netloc)
        path_trimmed = unquote(parsed.path.strip("/"))

        if path_trimmed:
            # Формат kubectl://namespace/pod_name
            if netloc and "namespace" not in options:
                options["namespace"] = netloc
            pod_name = path_trimmed.split("/", 1)[0]
        else:
            # Формат kubectl://pod_name?namespace=default
            pod_name = netloc

        if not pod_name and "pod" in options:
            pod_name = str(options.pop("pod"))

        return ConnectionConfig(
            transport="kubectl",
            host=pod_name or None,
            port=None,
            username=None,
            password=None,
            options=options,
        )

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
                transport == "redfish"
                and str(options.get("scheme", "https")).lower() == "http"
            ):
                port = 80
            elif transport in ("winrm", "wsman") and (
                bool(options.get("ssl", False))
                or str(options.get("scheme", "")).lower() == "https"
                or str(options.get("transport", "")).lower() == "ssl"
            ):
                port = 5986
            else:
                port = cls.DEFAULT_PORTS[transport]
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

        # Случай 1: qga:///path/to/socket.sock (без сетевого хоста гипервизора)
        if not parsed.netloc:
            socket_path = unquote(parsed.path) if parsed.path else ""
            if socket_path:
                options.setdefault("socket", socket_path)
            elif "socket" in options:
                socket_path = str(options["socket"])
            options.setdefault("backend", "socket")
            return ConnectionConfig(
                transport=transport,
                host=socket_path or "localhost",
                port=None,
                username=None,
                password=None,
                options=options,
            )

        # Случай 2: qga://[user@]hypervisor[:port]/vm-name[?socket=...&backend=...]
        path_trimmed = unquote(parsed.path.strip("/")) if parsed.path else ""
        if path_trimmed:
            options.setdefault("vm", path_trimmed)
            options.setdefault("domain", path_trimmed)

        port = parsed.port
        if port is None and parsed.hostname not in (None, "", "localhost", "127.0.0.1"):
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
    def build(
        cls,
        transport: str,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        """Собрать URI строку из компонентов."""
        if transport == "local":
            if options:
                query = "&".join(f"{k}={v}" for k, v in options.items())
                return f"local://?{query}"
            return "local://"

        if transport in ("serial", "uart"):
            device = host or (options.get("device") if options else "") or ""
            opts = dict(options) if options else {}
            opts.pop("device", None)
            if opts:
                query = "&".join(f"{k}={v}" for k, v in opts.items())
                return f"{transport}://{device}?{query}"
            return f"{transport}://{device}"

        if transport == "kubectl":
            opts = dict(options) if options else {}
            ns = opts.pop("namespace", None)
            target = f"{ns}/{host or ''}" if ns else (host or "")
            if opts:
                query = "&".join(f"{k}={v}" for k, v in opts.items())
                return f"kubectl://{target}?{query}"
            return f"kubectl://{target}"

        if transport in ("qga", "qemu-ga"):
            opts = dict(options) if options else {}
            if (host and host.startswith("/")) or (not host and "socket" in opts):
                sock_path = host if (host and host.startswith("/")) else str(opts.pop("socket", ""))
                opts.pop("socket", None)
                if opts.get("backend") == "socket":
                    opts.pop("backend", None)
                if opts:
                    query = "&".join(f"{k}={v}" for k, v in opts.items())
                    return f"{transport}://{sock_path}?{query}"
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
            uri = f"{transport}://{auth}{host or ''}{port_str}{vm_suffix}"
            if opts:
                query = "&".join(f"{k}={v}" for k, v in opts.items())
                uri = f"{uri}?{query}"
            return uri

        if transport == "pve":
            opts = dict(options) if options else {}
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
                query = "&".join(f"{k}={v}" for k, v in opts.items())
                uri = f"{uri}?{query}"
            return uri

        auth = ""
        if username and password:
            auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
        elif username:
            auth = f"{quote(username, safe='')}@"

        port_str = f":{port}" if port else ""

        uri = f"{transport}://{auth}{host or ''}{port_str}"

        if options:
            query = "&".join(f"{k}={v}" for k, v in options.items())
            uri = f"{uri}?{query}"

        return uri


__all__ = ["URIParser"]
