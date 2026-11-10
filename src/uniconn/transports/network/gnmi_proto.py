# src/uniconn/transports/network/gnmi_proto.py
"""Встроенный бинарный Protobuf / gRPC wire-кодек и AST путей для OpenConfig gNMI."""

from __future__ import annotations

import asyncio
import json
import re
import struct
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from ...exceptions import ConnectionError as UniconnConnectionError
from ...exceptions import ExecutionError

_PATH_KEY_RE = re.compile(r"\[([^=\[\]]+)=([^\[\]]+)\]")

ENCODING_NAME_TO_ENUM: dict[str, int] = {
    "json": 0,
    "bytes": 1,
    "proto": 2,
    "ascii": 3,
    "json_ietf": 4,
}
ENCODING_ENUM_TO_NAME: dict[int, str] = {v: k for k, v in ENCODING_NAME_TO_ENUM.items()}

SUB_MODE_TO_ENUM: dict[str, int] = {
    "target_defined": 0,
    "on_change": 1,
    "sample": 2,
}
SUB_LIST_MODE_TO_ENUM: dict[str, int] = {
    "stream": 0,
    "once": 1,
    "poll": 2,
}


@dataclass(slots=True)
class GnmiPathElem:
    """Элемент пути OpenConfig gNMI (``PathElem`` в ``gnmi.proto``)."""

    name: str
    key: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class GnmiPath:
    """Структурированный путь OpenConfig gNMI (``Path`` в ``gnmi.proto``)."""

    elem: list[GnmiPathElem] = field(default_factory=list)
    origin: str = ""
    target: str = ""


def parse_gnmi_path(
    path_str: str,
    *,
    origin: str = "",
    target: str = "",
) -> GnmiPath:
    """Распарсить строковый путь OpenConfig (например, ``/interfaces/interface[name=eth0]/state/counters``)."""
    cleaned = path_str.strip()
    detected_origin = origin
    if ":" in cleaned and not cleaned.startswith("/"):
        maybe_orig, rest = cleaned.split(":", 1)
        if "[" not in maybe_orig and "/" not in maybe_orig:
            detected_origin = detected_origin or maybe_orig
            cleaned = rest

    if not cleaned or cleaned == "/":
        return GnmiPath(elem=[], origin=detected_origin, target=target)

    segments: list[str] = []
    cur: list[str] = []
    bracket_depth = 0
    for ch in cleaned.strip("/"):
        if ch == "[":
            bracket_depth += 1
            cur.append(ch)
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            cur.append(ch)
        elif ch == "/" and bracket_depth == 0:
            if cur:
                segments.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        segments.append("".join(cur))

    elems: list[GnmiPathElem] = []
    for seg in segments:
        if not seg:
            continue
        if "[" in seg:
            name_part = seg[: seg.index("[")]
            if ":" in name_part and not detected_origin:
                detected_origin, name_part = name_part.split(":", 1)
            keys: dict[str, str] = {}
            for m in _PATH_KEY_RE.finditer(seg[seg.index("[") :]):
                k, v = m.groups()
                keys[k.strip()] = v.strip().strip("'\"")
            elems.append(GnmiPathElem(name=name_part.strip(), key=keys))
        else:
            name_part = seg
            if ":" in name_part and not detected_origin:
                detected_origin, name_part = name_part.split(":", 1)
            elems.append(GnmiPathElem(name=name_part.strip()))
    return GnmiPath(elem=elems, origin=detected_origin, target=target)


def format_gnmi_path(path: GnmiPath) -> str:
    """Преобразовать ``GnmiPath`` обратно в каноническую строку пути OpenConfig."""
    if not path.elem:
        return "/"
    parts: list[str] = []
    for el in path.elem:
        if el.key:
            kv = "".join(f"[{k}={v}]" for k, v in sorted(el.key.items()))
            parts.append(f"{el.name}{kv}")
        else:
            parts.append(el.name)
    res = "/" + "/".join(parts)
    if path.origin:
        return f"{path.origin}:{res}"
    return res


# ─── Низкоуровневые примитивы Protobuf Wire Format ─────────────────


def encode_varint(value: int) -> bytes:
    """Закодировать беззнаковое/знаковое целое в Protobuf Base-128 Varint."""
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value & 0x7F)
    return bytes(out)


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Декодировать Varint из ``buf`` начиная с ``offset``, вернув ``(value, new_offset)``."""
    result = 0
    shift = 0
    pos = offset
    n = len(buf)
    while pos < n:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            raise ExecutionError("Protobuf varint overflow", command="gnmi.decode", exit_code=1)
    raise ExecutionError("Truncated protobuf varint", command="gnmi.decode", exit_code=1)


def encode_tag(field_number: int, wire_type: int) -> bytes:
    """Сформировать тег поля Protobuf ``(field_number << 3) | wire_type``."""
    return encode_varint((field_number << 3) | wire_type)


def encode_varint_field(field_number: int, value: int) -> bytes:
    """Закодировать varint-поле Protobuf (wire_type = 0)."""
    return encode_tag(field_number, 0) + encode_varint(value)


def encode_bytes_field(field_number: int, data: bytes | str) -> bytes:
    """Закодировать length-delimited поле Protobuf (wire_type = 2)."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return encode_tag(field_number, 2) + encode_varint(len(raw)) + raw


def iter_proto_fields(buf: bytes) -> Iterator[tuple[int, int, int | bytes]]:
    """Итерироваться по полям Protobuf-сообщения ``(field_number, wire_type, value)``."""
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = decode_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            val, pos = decode_varint(buf, pos)
            yield field_num, wire_type, val
        elif wire_type == 1:
            if pos + 8 > n:
                raise ExecutionError("Truncated 64-bit protobuf field", command="gnmi.decode", exit_code=1)
            yield field_num, wire_type, buf[pos : pos + 8]
            pos += 8
        elif wire_type == 2:
            length, pos = decode_varint(buf, pos)
            if pos + length > n:
                raise ExecutionError("Truncated length-delimited protobuf field", command="gnmi.decode", exit_code=1)
            yield field_num, wire_type, buf[pos : pos + length]
            pos += length
        elif wire_type == 5:
            if pos + 4 > n:
                raise ExecutionError("Truncated 32-bit protobuf field", command="gnmi.decode", exit_code=1)
            yield field_num, wire_type, buf[pos : pos + 4]
            pos += 4
        else:
            raise ExecutionError(
                f"Unsupported protobuf wire_type={wire_type}",
                command="gnmi.decode",
                exit_code=1,
            )


def pack_grpc_frame(payload: bytes, *, compressed: bool = False) -> bytes:
    """Упаковать бинарное сообщение Protobuf в 5-байтовый gRPC Length-Prefixed Frame."""
    flag = 1 if compressed else 0
    return struct.pack(">BI", flag, len(payload)) + payload


async def read_grpc_frame(
    reader: asyncio.StreamReader,
    *,
    timeout: float | None = 30.0,
) -> bytes:
    """Прочитать один 5-байтовый gRPC Length-Prefixed Frame из ``StreamReader``."""

    async def _do_read() -> bytes:
        try:
            header = await reader.readexactly(5)
        except asyncio.IncompleteReadError as exc:
            raise UniconnConnectionError("gNMI stream closed by remote peer") from exc
        _compressed, msg_len = struct.unpack(">BI", header)
        if msg_len == 0:
            return b""
        try:
            return await reader.readexactly(msg_len)
        except asyncio.IncompleteReadError as exc:
            raise UniconnConnectionError("Truncated gNMI frame from remote peer") from exc

    if timeout is not None and timeout > 0:
        return await asyncio.wait_for(_do_read(), timeout=timeout)
    return await _do_read()


class GnmiWireCodec:
    """Кодек сообщений ``gnmi.proto`` (Path, TypedValue, Update, Notification, Get, Set, Subscribe)."""

    @staticmethod
    def encode_path_elem(elem: GnmiPathElem) -> bytes:
        """Закодировать ``PathElem`` (name=1, map<string,string> key=2)."""
        out = bytearray()
        if elem.name:
            out.extend(encode_bytes_field(1, elem.name))
        for k, v in elem.key.items():
            entry = encode_bytes_field(1, k) + encode_bytes_field(2, v)
            out.extend(encode_bytes_field(2, entry))
        return bytes(out)

    @staticmethod
    def decode_path_elem(buf: bytes) -> GnmiPathElem:
        """Декодировать ``PathElem``."""
        name = ""
        keys: dict[str, str] = {}
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                name = val.decode("utf-8", errors="replace")
            elif fnum == 2 and isinstance(val, bytes):
                mk = ""
                mv = ""
                for mf, _mw, mval in iter_proto_fields(val):
                    if mf == 1 and isinstance(mval, bytes):
                        mk = mval.decode("utf-8", errors="replace")
                    elif mf == 2 and isinstance(mval, bytes):
                        mv = mval.decode("utf-8", errors="replace")
                if mk:
                    keys[mk] = mv
        return GnmiPathElem(name=name, key=keys)

    @classmethod
    def encode_path(cls, path: GnmiPath | str) -> bytes:
        """Закодировать ``Path`` (origin=2, elem=3, target=4)."""
        p = parse_gnmi_path(path) if isinstance(path, str) else path
        out = bytearray()
        if p.origin:
            out.extend(encode_bytes_field(2, p.origin))
        for el in p.elem:
            out.extend(encode_bytes_field(3, cls.encode_path_elem(el)))
        if p.target:
            out.extend(encode_bytes_field(4, p.target))
        return bytes(out)

    @classmethod
    def decode_path(cls, buf: bytes) -> GnmiPath:
        """Декодировать ``Path``."""
        origin = ""
        target = ""
        elems: list[GnmiPathElem] = []
        deprecated_elements: list[str] = []
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                deprecated_elements.append(val.decode("utf-8", errors="replace"))
            elif fnum == 2 and isinstance(val, bytes):
                origin = val.decode("utf-8", errors="replace")
            elif fnum == 3 and isinstance(val, bytes):
                elems.append(cls.decode_path_elem(val))
            elif fnum == 4 and isinstance(val, bytes):
                target = val.decode("utf-8", errors="replace")
        if not elems and deprecated_elements:
            elems = [GnmiPathElem(name=e) for e in deprecated_elements]
        return GnmiPath(elem=elems, origin=origin, target=target)

    @staticmethod
    def encode_typed_value(value: Any, encoding: str = "json_ietf") -> bytes:
        """Закодировать Python-значение в ``TypedValue`` (``gnmi.proto``)."""
        enc = encoding.lower()
        if isinstance(value, bytes) and enc == "bytes":
            return encode_bytes_field(5, value)
        if enc in ("json_ietf", "json") or isinstance(value, Mapping | list):
            json_bytes = (
                value.encode("utf-8")
                if isinstance(value, str)
                else (value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8"))
            )
            field_no = 10 if enc == "json_ietf" else 11
            return encode_bytes_field(field_no, json_bytes)
        if isinstance(value, bool):
            return encode_varint_field(4, 1 if value else 0)
        if isinstance(value, int):
            if value >= 0:
                return encode_varint_field(3, value)
            return encode_varint_field(2, value)
        if enc == "ascii":
            return encode_bytes_field(12, str(value))
        return encode_bytes_field(1, str(value))

    @staticmethod
    def decode_typed_value(buf: bytes) -> Any:
        """Декодировать ``TypedValue`` в нативный тип Python."""
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            if fnum == 2 and isinstance(val, int):
                if val >= (1 << 63):
                    val -= 1 << 64
                return val
            if fnum == 3 and isinstance(val, int):
                return val
            if fnum == 4 and isinstance(val, int):
                return bool(val)
            if fnum == 5 and isinstance(val, bytes):
                return val
            if fnum in (10, 11) and isinstance(val, bytes):
                txt = val.decode("utf-8", errors="replace")
                try:
                    return json.loads(txt)
                except ValueError:
                    return txt
            if fnum == 12 and isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
        return None

    @classmethod
    def encode_update(cls, path: GnmiPath | str, value: Any, encoding: str = "json_ietf") -> bytes:
        """Закодировать ``Update`` (path=1, val=3)."""
        out = bytearray()
        out.extend(encode_bytes_field(1, cls.encode_path(path)))
        out.extend(encode_bytes_field(3, cls.encode_typed_value(value, encoding=encoding)))
        return bytes(out)

    @classmethod
    def decode_update(cls, buf: bytes) -> tuple[GnmiPath, Any]:
        """Декодировать ``Update`` -> ``(GnmiPath, value)``."""
        path = GnmiPath()
        value: Any = None
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                path = cls.decode_path(val)
            elif fnum == 3 and isinstance(val, bytes):
                value = cls.decode_typed_value(val)
        return path, value

    @classmethod
    def encode_notification(
        cls,
        *,
        timestamp: int,
        prefix: GnmiPath | str | None = None,
        updates: Sequence[tuple[GnmiPath | str, Any]] = (),
        deletes: Sequence[GnmiPath | str] = (),
        encoding: str = "json_ietf",
    ) -> bytes:
        """Закодировать ``Notification`` (timestamp=1, prefix=2, update=4, delete=5)."""
        out = bytearray()
        out.extend(encode_varint_field(1, timestamp))
        if prefix:
            out.extend(encode_bytes_field(2, cls.encode_path(prefix)))
        for up_path, up_val in updates:
            out.extend(encode_bytes_field(4, cls.encode_update(up_path, up_val, encoding=encoding)))
        for del_path in deletes:
            out.extend(encode_bytes_field(5, cls.encode_path(del_path)))
        return bytes(out)

    @classmethod
    def decode_notification(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``Notification``."""
        timestamp = 0
        prefix_str = ""
        updates: list[tuple[str, Any]] = []
        deletes: list[str] = []
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, int):
                timestamp = val
            elif fnum == 2 and isinstance(val, bytes):
                prefix_str = format_gnmi_path(cls.decode_path(val))
            elif fnum == 4 and isinstance(val, bytes):
                up_path, up_val = cls.decode_update(val)
                updates.append((format_gnmi_path(up_path), up_val))
            elif fnum == 5 and isinstance(val, bytes):
                deletes.append(format_gnmi_path(cls.decode_path(val)))
        return {
            "timestamp": timestamp,
            "prefix": prefix_str,
            "updates": updates,
            "deletes": deletes,
        }

    # ─── Запросы и ответы Get / Set / Subscribe / Capabilities ─────

    @classmethod
    def encode_get_request(
        cls,
        paths: Sequence[GnmiPath | str],
        *,
        prefix: GnmiPath | str | None = None,
        data_type: Literal["all", "config", "state", "operational"] = "all",
        encoding: str = "json_ietf",
    ) -> bytes:
        """Закодировать ``GetRequest`` (prefix=1, path=2, type=3, encoding=5)."""
        out = bytearray()
        if prefix:
            out.extend(encode_bytes_field(1, cls.encode_path(prefix)))
        for p in paths:
            out.extend(encode_bytes_field(2, cls.encode_path(p)))
        type_map = {"all": 0, "config": 1, "state": 2, "operational": 3}
        out.extend(encode_varint_field(3, type_map.get(data_type.lower(), 0)))
        enc_enum = ENCODING_NAME_TO_ENUM.get(encoding.lower(), 4)
        out.extend(encode_varint_field(5, enc_enum))
        return bytes(out)

    @classmethod
    def decode_get_request(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``GetRequest``."""
        prefix = ""
        paths: list[str] = []
        data_type_enum = 0
        encoding_enum = 4
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                prefix = format_gnmi_path(cls.decode_path(val))
            elif fnum == 2 and isinstance(val, bytes):
                paths.append(format_gnmi_path(cls.decode_path(val)))
            elif fnum == 3 and isinstance(val, int):
                data_type_enum = val
            elif fnum == 5 and isinstance(val, int):
                encoding_enum = val
        type_names = {0: "all", 1: "config", 2: "state", 3: "operational"}
        return {
            "prefix": prefix,
            "paths": paths,
            "data_type": type_names.get(data_type_enum, "all"),
            "encoding": ENCODING_ENUM_TO_NAME.get(encoding_enum, "json_ietf"),
        }

    @classmethod
    def encode_get_response(
        cls,
        notifications: Sequence[bytes],
    ) -> bytes:
        """Закодировать ``GetResponse`` (notification=1)."""
        out = bytearray()
        for notif in notifications:
            out.extend(encode_bytes_field(1, notif))
        return bytes(out)

    @classmethod
    def decode_get_response(cls, buf: bytes) -> list[dict[str, Any]]:
        """Декодировать ``GetResponse`` в список словарей ``Notification``."""
        notifs: list[dict[str, Any]] = []
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                notifs.append(cls.decode_notification(val))
        return notifs

    @classmethod
    def encode_set_request(
        cls,
        *,
        prefix: GnmiPath | str | None = None,
        deletes: Sequence[GnmiPath | str] = (),
        replaces: Sequence[tuple[GnmiPath | str, Any]] = (),
        updates: Sequence[tuple[GnmiPath | str, Any]] = (),
        encoding: str = "json_ietf",
    ) -> bytes:
        """Закодировать ``SetRequest`` (prefix=1, delete=2, replace=3, update=4)."""
        out = bytearray()
        if prefix:
            out.extend(encode_bytes_field(1, cls.encode_path(prefix)))
        for d in deletes:
            out.extend(encode_bytes_field(2, cls.encode_path(d)))
        for rp, rv in replaces:
            out.extend(encode_bytes_field(3, cls.encode_update(rp, rv, encoding=encoding)))
        for up, uv in updates:
            out.extend(encode_bytes_field(4, cls.encode_update(up, uv, encoding=encoding)))
        return bytes(out)

    @classmethod
    def decode_set_request(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``SetRequest``."""
        prefix = ""
        deletes: list[str] = []
        replaces: list[tuple[str, Any]] = []
        updates: list[tuple[str, Any]] = []
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                prefix = format_gnmi_path(cls.decode_path(val))
            elif fnum == 2 and isinstance(val, bytes):
                deletes.append(format_gnmi_path(cls.decode_path(val)))
            elif fnum == 3 and isinstance(val, bytes):
                p, v = cls.decode_update(val)
                replaces.append((format_gnmi_path(p), v))
            elif fnum == 4 and isinstance(val, bytes):
                p, v = cls.decode_update(val)
                updates.append((format_gnmi_path(p), v))
        return {
            "prefix": prefix,
            "deletes": deletes,
            "replaces": replaces,
            "updates": updates,
        }

    @classmethod
    def encode_set_response(
        cls,
        results: Sequence[tuple[GnmiPath | str, Literal["delete", "replace", "update"]]],
        *,
        timestamp: int = 0,
    ) -> bytes:
        """Закодировать ``SetResponse`` (response=2, timestamp=3)."""
        op_map = {"delete": 1, "replace": 2, "update": 3}
        out = bytearray()
        for path, op in results:
            ur = encode_bytes_field(2, cls.encode_path(path)) + encode_varint_field(3, op_map.get(op, 3))
            out.extend(encode_bytes_field(2, ur))
        if timestamp:
            out.extend(encode_varint_field(3, timestamp))
        return bytes(out)

    @classmethod
    def decode_set_response(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``SetResponse``."""
        op_names = {1: "DELETE", 2: "REPLACE", 3: "UPDATE"}
        responses: list[dict[str, str]] = []
        timestamp = 0
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 2 and isinstance(val, bytes):
                p_str = "/"
                op_str = "UPDATE"
                for uf, _uw, uval in iter_proto_fields(val):
                    if uf == 2 and isinstance(uval, bytes):
                        p_str = format_gnmi_path(cls.decode_path(uval))
                    elif uf == 3 and isinstance(uval, int):
                        op_str = op_names.get(uval, "UPDATE")
                responses.append({"path": p_str, "op": op_str})
            elif fnum == 3 and isinstance(val, int):
                timestamp = val
        return {"responses": responses, "timestamp": timestamp}

    @classmethod
    def encode_subscribe_request(
        cls,
        paths: Sequence[GnmiPath | str],
        *,
        mode: Literal["sample", "on_change", "target_defined"] = "sample",
        list_mode: Literal["stream", "once", "poll"] = "stream",
        sample_interval_ns: int = 5_000_000_000,
        suppress_redundant: bool = False,
        heartbeat_interval_ns: int = 0,
        encoding: str = "json_ietf",
        prefix: GnmiPath | str | None = None,
    ) -> bytes:
        """Закодировать ``SubscribeRequest`` (subscribe=1 -> SubscriptionList)."""
        sub_list = bytearray()
        if prefix:
            sub_list.extend(encode_bytes_field(1, cls.encode_path(prefix)))

        sub_mode_enum = SUB_MODE_TO_ENUM.get(mode.lower(), 2)
        for p in paths:
            sub_item = bytearray()
            sub_item.extend(encode_bytes_field(1, cls.encode_path(p)))
            sub_item.extend(encode_varint_field(2, sub_mode_enum))
            if sample_interval_ns > 0:
                sub_item.extend(encode_varint_field(3, sample_interval_ns))
            if suppress_redundant:
                sub_item.extend(encode_varint_field(4, 1))
            if heartbeat_interval_ns > 0:
                sub_item.extend(encode_varint_field(5, heartbeat_interval_ns))
            sub_list.extend(encode_bytes_field(2, bytes(sub_item)))

        list_mode_enum = SUB_LIST_MODE_TO_ENUM.get(list_mode.lower(), 0)
        sub_list.extend(encode_varint_field(5, list_mode_enum))
        enc_enum = ENCODING_NAME_TO_ENUM.get(encoding.lower(), 4)
        sub_list.extend(encode_varint_field(6, enc_enum))

        return encode_bytes_field(1, bytes(sub_list))

    @classmethod
    def decode_subscribe_request(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``SubscribeRequest``."""
        paths: list[str] = []
        mode = "sample"
        list_mode = "stream"
        sample_interval_ns = 0
        encoding = "json_ietf"
        rev_sub_mode = {v: k for k, v in SUB_MODE_TO_ENUM.items()}
        rev_list_mode = {v: k for k, v in SUB_LIST_MODE_TO_ENUM.items()}

        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                for sf, _sw, sval in iter_proto_fields(val):
                    if sf == 2 and isinstance(sval, bytes):
                        for item_f, _iw, item_v in iter_proto_fields(sval):
                            if item_f == 1 and isinstance(item_v, bytes):
                                paths.append(format_gnmi_path(cls.decode_path(item_v)))
                            elif item_f == 2 and isinstance(item_v, int):
                                mode = rev_sub_mode.get(item_v, "sample")
                            elif item_f == 3 and isinstance(item_v, int):
                                sample_interval_ns = item_v
                    elif sf == 5 and isinstance(sval, int):
                        list_mode = rev_list_mode.get(sval, "stream")
                    elif sf == 6 and isinstance(sval, int):
                        encoding = ENCODING_ENUM_TO_NAME.get(sval, "json_ietf")

        return {
            "paths": paths,
            "mode": mode,
            "list_mode": list_mode,
            "sample_interval_ns": sample_interval_ns,
            "encoding": encoding,
        }

    @classmethod
    def encode_subscribe_response(
        cls,
        *,
        notification: bytes | None = None,
        sync_response: bool = False,
    ) -> bytes:
        """Закодировать ``SubscribeResponse`` (update=1, sync_response=3)."""
        out = bytearray()
        if notification is not None:
            out.extend(encode_bytes_field(1, notification))
        if sync_response:
            out.extend(encode_varint_field(3, 1))
        return bytes(out)

    @classmethod
    def decode_subscribe_response(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``SubscribeResponse``."""
        notif: dict[str, Any] | None = None
        sync_resp = False
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                notif = cls.decode_notification(val)
            elif fnum == 3 and isinstance(val, int):
                sync_resp = bool(val)
        return {"notification": notif, "sync_response": sync_resp}

    @classmethod
    def encode_capabilities_response(
        cls,
        models: Sequence[Mapping[str, str]],
        encodings: Sequence[str] = ("json", "json_ietf", "proto"),
        gnmi_version: str = "0.10.0",
    ) -> bytes:
        """Закодировать ``CapabilitiesResponse`` (supported_models=1, supported_encodings=2, gNMI_version=3)."""
        out = bytearray()
        for m in models:
            m_bytes = bytearray()
            if m.get("name"):
                m_bytes.extend(encode_bytes_field(1, m["name"]))
            if m.get("organization"):
                m_bytes.extend(encode_bytes_field(2, m["organization"]))
            if m.get("version"):
                m_bytes.extend(encode_bytes_field(3, m["version"]))
            out.extend(encode_bytes_field(1, bytes(m_bytes)))
        for enc in encodings:
            out.extend(encode_varint_field(2, ENCODING_NAME_TO_ENUM.get(enc.lower(), 4)))
        out.extend(encode_bytes_field(3, gnmi_version))
        return bytes(out)

    @classmethod
    def decode_capabilities_response(cls, buf: bytes) -> dict[str, Any]:
        """Декодировать ``CapabilitiesResponse``."""
        models: list[dict[str, str]] = []
        encodings: list[str] = []
        gnmi_version = ""
        for fnum, _wtype, val in iter_proto_fields(buf):
            if fnum == 1 and isinstance(val, bytes):
                m_dict: dict[str, str] = {}
                for mf, _mw, mval in iter_proto_fields(val):
                    if mf == 1 and isinstance(mval, bytes):
                        m_dict["name"] = mval.decode("utf-8", errors="replace")
                    elif mf == 2 and isinstance(mval, bytes):
                        m_dict["organization"] = mval.decode("utf-8", errors="replace")
                    elif mf == 3 and isinstance(mval, bytes):
                        m_dict["version"] = mval.decode("utf-8", errors="replace")
                models.append(m_dict)
            elif fnum == 2 and isinstance(val, int):
                encodings.append(ENCODING_ENUM_TO_NAME.get(val, "json_ietf"))
            elif fnum == 3 and isinstance(val, bytes):
                gnmi_version = val.decode("utf-8", errors="replace")
        return {
            "supported_models": models,
            "supported_encodings": encodings,
            "gnmi_version": gnmi_version,
        }


__all__ = [
    "ENCODING_ENUM_TO_NAME",
    "ENCODING_NAME_TO_ENUM",
    "GnmiPath",
    "GnmiPathElem",
    "GnmiWireCodec",
    "decode_varint",
    "encode_bytes_field",
    "encode_tag",
    "encode_varint",
    "encode_varint_field",
    "format_gnmi_path",
    "iter_proto_fields",
    "pack_grpc_frame",
    "parse_gnmi_path",
    "read_grpc_frame",
]
