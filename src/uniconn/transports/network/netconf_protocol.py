# src/uniconn/transports/network/netconf_protocol.py
"""Протокольный кодек фреймов NETCONF (RFC 4742 v1.0 и RFC 6242 v1.1) и адаптеры вендоров."""

from __future__ import annotations

import asyncio
import html
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from typing import Any, Literal

from ...exceptions import ConnectionError as UniconnConnectionError
from ...exceptions import ExecutionError
from .base import safe_parse_xml, strip_xml_ns, xml_to_data

NETCONF_BASE_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
NETCONF_NOTIFICATION_NS = "urn:ietf:params:xml:ns:netconf:notification:1.0"
NETCONF_DELIM_10 = b"]]>]]>"
NETCONF_END_CHUNKS_11 = b"\n##\n"

BASE_10_CAP = "urn:ietf:params:netconf:base:1.0"
BASE_11_CAP = "urn:ietf:params:netconf:base:1.1"
CANDIDATE_CAP = "urn:ietf:params:netconf:capability:candidate:1.0"
CONFIRMED_COMMIT_10_CAP = "urn:ietf:params:netconf:capability:confirmed-commit:1.0"
CONFIRMED_COMMIT_11_CAP = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
VALIDATE_10_CAP = "urn:ietf:params:netconf:capability:validate:1.0"
VALIDATE_11_CAP = "urn:ietf:params:netconf:capability:validate:1.1"
WRITABLE_RUNNING_CAP = "urn:ietf:params:netconf:capability:writable-running:1.0"
XPATH_CAP = "urn:ietf:params:netconf:capability:xpath:1.0"
ROLLBACK_ON_ERROR_CAP = "urn:ietf:params:netconf:capability:rollback-on-error:1.0"
NOTIFICATION_CAP = "urn:ietf:params:netconf:capability:notification:1.0"

DEFAULT_CLIENT_CAPABILITIES: tuple[str, ...] = (
    BASE_10_CAP,
    BASE_11_CAP,
)


class NetconfFrameCodec:
    """Кодек сообщений NETCONF поверх SSH-подсистемы (RFC 4742 / RFC 6242)."""

    @staticmethod
    def encode_hello(
        capabilities: Sequence[str] = DEFAULT_CLIENT_CAPABILITIES,
        session_id: int | str | None = None,
    ) -> bytes:
        """Сформировать приветствие ``<hello>`` (по RFC 6242 всегда обрамляется разделителем ``]]>]]>``)."""
        caps_xml = "".join(
            f"<capability>{html.escape(str(cap), quote=False)}</capability>"
            for cap in capabilities
        )
        sid_xml = f"<session-id>{session_id}</session-id>" if session_id is not None else ""
        hello_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<hello xmlns="{NETCONF_BASE_NS}">'
            f"<capabilities>{caps_xml}</capabilities>"
            f"{sid_xml}"
            "</hello>"
        )
        return hello_xml.encode("utf-8") + NETCONF_DELIM_10

    @staticmethod
    def decode_hello(raw_frame: bytes | str) -> tuple[list[str], str | None]:
        """Распарсить ``<hello>`` и вернуть ``(capabilities, session_id)``."""
        root = safe_parse_xml(raw_frame)
        if strip_xml_ns(root.tag) != "hello":
            raise UniconnConnectionError(
                f"Expected NETCONF <hello>, got <{strip_xml_ns(root.tag)}>"
            )
        caps: list[str] = []
        session_id: str | None = None
        for elem in root.iter():
            tag = strip_xml_ns(elem.tag)
            if tag == "capability" and elem.text:
                caps.append(elem.text.strip())
            elif tag == "session-id" and elem.text:
                session_id = elem.text.strip()
        return caps, session_id

    @staticmethod
    def negotiate_version(
        client_caps: Sequence[str],
        server_caps: Sequence[str],
        requested_version: str = "auto",
    ) -> Literal["1.0", "1.1"]:
        """Определить версию кадрирования сессии после обмена ``<hello>`` (RFC 6242 Section 4.1)."""
        req = str(requested_version).strip().lower()
        if req in ("1.0", "1"):
            return "1.0"
        if BASE_11_CAP in client_caps and BASE_11_CAP in server_caps:
            return "1.1"
        return "1.0"

    @staticmethod
    def encode_frame(
        payload: str | bytes,
        version: Literal["1.0", "1.1"] = "1.1",
    ) -> bytes:
        r"""Закодировать полезную нагрузку XML в фрейм NETCONF 1.0 (``]]>]]>``) или 1.1 (``\n#<len>\n...\n##\n``)."""
        raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        if version == "1.0":
            return raw_bytes + NETCONF_DELIM_10
        octet_len = len(raw_bytes)
        header = f"\n#{octet_len}\n".encode("ascii")
        return header + raw_bytes + NETCONF_END_CHUNKS_11

    @staticmethod
    async def read_frame(
        reader: Any,
        buffer: bytearray,
        *,
        version: Literal["1.0", "1.1"] = "1.0",
        timeout: float | None = 30.0,
    ) -> bytes:
        """Вычитать ровно один фрейм NETCONF 1.0 или 1.1 из асинхронного байтового потока."""

        async def _read_more() -> bytes:
            chunk = await reader.read(65536)
            if not chunk:
                raise UniconnConnectionError("NETCONF channel closed by remote peer (EOF)")
            return chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)

        async def _read_until_10() -> bytes:
            while True:
                idx = buffer.find(NETCONF_DELIM_10)
                if idx != -1:
                    frame = bytes(buffer[:idx])
                    del buffer[: idx + len(NETCONF_DELIM_10)]
                    return frame.strip()
                buffer.extend(await _read_more())

        async def _read_chunked_11() -> bytes:
            assembled = bytearray()
            while True:
                # Допускаем fallback, если устройство ответило фреймом 1.0 (например, при ошибке до переключения)
                if not assembled:
                    idx_10 = buffer.find(NETCONF_DELIM_10)
                    idx_11 = buffer.find(b"\n#")
                    if idx_10 != -1 and (idx_11 == -1 or idx_10 < idx_11):
                        frame = bytes(buffer[:idx_10])
                        del buffer[: idx_10 + len(NETCONF_DELIM_10)]
                        return frame.strip()

                # Ищем заголовок чанка \n#<len>\n или конец сообщения \n##\n
                while len(buffer) < 4 or b"\n" not in buffer[2:]:
                    buffer.extend(await _read_more())

                # Пропускаем ведущие пробелы/CR перед \n#
                start_idx = buffer.find(b"\n#")
                if start_idx == -1:
                    if buffer.startswith(b"#"):
                        buffer[:0] = b"\n"
                        start_idx = 0
                    else:
                        buffer.extend(await _read_more())
                        continue
                if start_idx > 0:
                    del buffer[:start_idx]

                if buffer.startswith(NETCONF_END_CHUNKS_11):
                    del buffer[: len(NETCONF_END_CHUNKS_11)]
                    return bytes(assembled).strip()

                header_end = buffer.find(b"\n", 2)
                if header_end == -1:
                    buffer.extend(await _read_more())
                    continue

                header_token = bytes(buffer[2:header_end]).strip()
                if header_token == b"#":
                    del buffer[: header_end + 1]
                    return bytes(assembled).strip()

                try:
                    chunk_len = int(header_token.decode("ascii"))
                    if chunk_len <= 0:
                        raise ValueError("Chunk length must be positive")
                except ValueError as exc:
                    raise ExecutionError(
                        f"Invalid RFC 6242 NETCONF 1.1 chunk header: {header_token!r}",
                        command="netconf.read_frame",
                        exit_code=1,
                    ) from exc

                del buffer[: header_end + 1]
                while len(buffer) < chunk_len:
                    buffer.extend(await _read_more())

                assembled.extend(buffer[:chunk_len])
                del buffer[:chunk_len]

        coro = _read_until_10() if version == "1.0" else _read_chunked_11()
        if timeout is not None and timeout > 0:
            return await asyncio.wait_for(coro, timeout=timeout)
        return await coro


class NetconfVendorAdapter:
    """Адаптер диалектов сетевых вендоров (Cisco IOS-XE/XR, Juniper Junos, Arista EOS, Nokia, Huawei)."""

    @staticmethod
    def detect_vendor(capabilities: Sequence[str], hint: str = "auto") -> str:
        """Определить семейство сетевой ОС по списку capabilities ``<hello>``."""
        if hint and hint.lower() != "auto":
            return hint.lower()
        joined = " ".join(capabilities).lower()
        if "juniper.net" in joined or "junos" in joined:
            return "junos"
        if "cisco.com/ns/yang/cisco-ios-xr" in joined:
            return "ios-xr"
        if "cisco.com" in joined or "tailf-common" in joined:
            return "ios-xe"
        if "arista.com" in joined or ("openconfig" in joined and "eos" in joined):
            return "arista"
        if "nokia.com" in joined or "alcatel-lucent" in joined:
            return "nokia"
        if "huawei.com" in joined:
            return "huawei"
        return "ietf"

    @staticmethod
    def build_filter_xml(
        path_or_filter: str,
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        supports_xpath: bool = True,
    ) -> str:
        """Построить XML-элемент ``<filter>`` для ``<get>`` или ``<get-config>``."""
        cleaned = path_or_filter.strip()
        if not cleaned or cleaned == "/":
            return ""
        if cleaned.startswith("<"):
            if cleaned.startswith("<filter"):
                return cleaned
            return f'<filter type="subtree">{cleaned}</filter>'
        if filter_type == "xpath" and supports_xpath:
            escaped_select = cleaned.replace('"', "&quot;")
            return f'<filter type="xpath" select="{escaped_select}"/>'
        # Конвертация простого пути /a/b в subtree-фильтр <a><b/></a>
        from .base import parse_yang_path_steps

        steps = parse_yang_path_steps(cleaned)
        if not steps:
            return ""
        inner = ""
        for node_name, keys in reversed(steps):
            key_xml = "".join(f"<{k}>{v}</{k}>" for k, v in keys.items())
            inner = (
                f"<{node_name}>{key_xml}{inner}</{node_name}>"
                if (inner or key_xml)
                else f"<{node_name}/>"
            )
        return f'<filter type="subtree">{inner}</filter>'


def parse_rpc_reply(
    raw_xml: bytes | str,
    *,
    operation: str,
    datastore: str | None = None,
    duration: float = 0.0,
    host: str | None = None,
) -> tuple[bool, Any, str, list[dict[str, Any]], str | None]:
    """Распарсить ``<rpc-reply>`` и вернуть ``(ok, data, text, errors, message_id)``."""
    raw_bytes = raw_xml.encode("utf-8") if isinstance(raw_xml, str) else bytes(raw_xml)
    text = raw_bytes.decode("utf-8", errors="replace").strip()
    root = safe_parse_xml(raw_bytes)
    message_id = root.attrib.get("message-id")

    errors: list[dict[str, Any]] = []
    has_ok_tag = False
    data_elem: ET.Element | None = None

    for child in root:
        tag = strip_xml_ns(child.tag)
        if tag == "rpc-error":
            err_info: dict[str, Any] = {}
            for err_child in child:
                err_tag = strip_xml_ns(err_child.tag)
                err_info[err_tag] = (err_child.text or "").strip()
            errors.append(err_info)
        elif tag == "ok":
            has_ok_tag = True
        elif tag == "data":
            data_elem = child

    fatal_errors = [
        e for e in errors if e.get("error-severity", "error").lower() != "warning"
    ]
    ok = len(fatal_errors) == 0 and (has_ok_tag or data_elem is not None or not errors)

    parsed_data = xml_to_data(data_elem) if data_elem is not None else xml_to_data(root)
    return ok, parsed_data, text, errors, message_id


__all__ = [
    "BASE_10_CAP",
    "BASE_11_CAP",
    "CANDIDATE_CAP",
    "CONFIRMED_COMMIT_10_CAP",
    "CONFIRMED_COMMIT_11_CAP",
    "DEFAULT_CLIENT_CAPABILITIES",
    "NETCONF_BASE_NS",
    "NETCONF_DELIM_10",
    "NETCONF_END_CHUNKS_11",
    "NETCONF_NOTIFICATION_NS",
    "NOTIFICATION_CAP",
    "ROLLBACK_ON_ERROR_CAP",
    "VALIDATE_10_CAP",
    "VALIDATE_11_CAP",
    "WRITABLE_RUNNING_CAP",
    "XPATH_CAP",
    "NetconfFrameCodec",
    "NetconfVendorAdapter",
    "parse_rpc_reply",
]
