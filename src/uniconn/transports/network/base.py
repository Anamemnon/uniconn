# src/uniconn/transports/network/base.py
"""Базовый протокол возможностей и утилиты трансформации YANG/XML/JSON для сетевых транспортов."""

from __future__ import annotations

import copy
import difflib
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from ...exceptions import ExecutionError
from ...result import NetResult, TelemetrySample

_FORBIDDEN_XML_RE = re.compile(r"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XPATH_KEY_RE = re.compile(r"^([^\[\]=]+)(?:\[([^\[\]]+)\]|=(.+))?$")
_XPATH_PRED_RE = re.compile(r"([a-zA-Z0-9_.-]+)\s*=\s*['\"]?([^'\"\[\]]+)['\"]?")


@runtime_checkable
class StructuredNetworkTransport(Protocol):
    """Протокол транспорта со структурированными сетевыми операциями (NETCONF / RESTCONF / gNMI)."""

    async def net_get(
        self,
        path: str = "",
        *,
        datastore: str = "running",
        filter_type: Literal["xpath", "subtree"] = "xpath",
        depth: int | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Получить операционное состояние и конфигурацию по пути YANG/XPath."""
        ...

    async def net_get_config(
        self,
        datastore: str = "running",
        path: str = "",
        *,
        filter_type: Literal["xpath", "subtree"] = "xpath",
        timeout: float | None = None,
    ) -> NetResult:
        """Получить конфигурацию из указанного хранилища (``running``, ``candidate``, ``startup``)."""
        ...

    async def net_edit(
        self,
        config: Mapping[str, Any] | Sequence[Mapping[str, Any]] | str | bytes,
        *,
        path: str = "",
        datastore: str | None = None,
        operation: Literal["merge", "replace", "create", "delete", "remove", "patch"] = "merge",
        default_operation: str | None = None,
        test_option: str | None = None,
        error_option: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Применить конфигурационные изменения к целевому хранилищу."""
        ...

    async def net_commit(
        self,
        *,
        confirmed: bool = False,
        confirm_timeout: int = 60,
        persist: str | None = None,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Зафиксировать изменения из ``candidate`` в ``running`` (с поддержкой confirmed commit)."""
        ...

    async def net_commit_confirm(
        self,
        *,
        persist_id: str | None = None,
        timeout: float | None = None,
    ) -> NetResult:
        """Подтвердить активный ``confirmed commit``."""
        ...

    async def net_discard_changes(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Откатить незафиксированные изменения в хранилище ``candidate``."""
        ...

    async def net_validate(
        self,
        *,
        source: str = "candidate",
        timeout: float | None = None,
    ) -> NetResult:
        """Проверить валидность конфигурации в хранилище ``source``."""
        ...

    async def net_lock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Установить монопольную блокировку на хранилище конфигурации."""
        ...

    async def net_unlock(
        self,
        datastore: str = "candidate",
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Снять блокировку с хранилища конфигурации."""
        ...

    async def net_capabilities(
        self,
        *,
        timeout: float | None = None,
    ) -> NetResult:
        """Получить список поддерживаемых YANG-моделей и возможностей устройства."""
        ...

    async def net_rpc(
        self,
        payload: Mapping[str, Any] | str,
        *,
        path: str = "",
        timeout: float | None = None,
    ) -> NetResult:
        """Выполнить произвольный RPC-вызов или операцию YANG."""
        ...

    def net_subscribe(
        self,
        paths: Sequence[str],
        *,
        mode: Literal["sample", "on_change", "target_defined"] = "sample",
        sample_interval: float = 5.0,
        suppress_redundant: bool = False,
        heartbeat_interval: float | None = None,
        once: bool = False,
        encoding: str | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[TelemetrySample]:
        """Подписаться на потоковую телеметрию или поток уведомлений по путям YANG/OpenConfig."""
        ...


def strip_xml_ns(tag: str) -> str:
    """Удалить пространство имён ``{urn:...}`` или префикс модуля из тега XML/YANG."""
    if "}" in tag:
        tag = tag.split("}", 1)[1]
    return tag


def strip_yang_prefix(key: str) -> str:
    """Удалить префикс модуля YANG (например, ``ietf-interfaces:interfaces`` -> ``interfaces``)."""
    if ":" in key and not key.startswith("http"):
        return key.split(":", 1)[1]
    return key


def safe_parse_xml(raw_xml: str | bytes) -> ET.Element:
    """Безопасно распарсить XML-документ с защитой от XXE и DTD/ENTITY-атак."""
    text = raw_xml.decode("utf-8", errors="replace") if isinstance(raw_xml, bytes) else raw_xml
    if _FORBIDDEN_XML_RE.search(text):
        raise ExecutionError(
            "XML payload rejected: DOCTYPE and ENTITY declarations are forbidden (XXE protection)",
            command="xml.parse",
            exit_code=1,
            stderr="XXE/DOCTYPE forbidden",
        )
    try:
        return ET.fromstring(text.strip())
    except ET.ParseError as exc:
        raise ExecutionError(
            f"Malformed XML payload: {exc}",
            command="xml.parse",
            exit_code=1,
            stderr=str(exc),
        ) from exc


def _coerce_scalar(text: str) -> Any:
    """Преобразовать строковый литерал XML в булево или числовое значение, если это уместно."""
    stripped = text.strip()
    if stripped == "true":
        return True
    if stripped == "false":
        return False
    if stripped.isdigit() or (stripped.startswith("-") and stripped[1:].isdigit()):
        try:
            return int(stripped)
        except ValueError:
            pass
    return stripped


def xml_to_data(elem: ET.Element) -> Any:
    """Рекурсивно преобразовать ``ET.Element`` в Python-словарь/список без префиксов пространств имён."""
    children = list(elem)
    if not children:
        text = (elem.text or "").strip()
        if not text and elem.attrib:
            return {
                f"@{strip_xml_ns(k)}": v
                for k, v in elem.attrib.items()
                if strip_xml_ns(k) not in ("xmlns", "message-id")
            }
        if not text:
            return {}
        return _coerce_scalar(text)

    result: dict[str, Any] = {}
    for k, v in elem.attrib.items():
        clean_k = strip_xml_ns(k)
        if clean_k not in ("xmlns", "message-id"):
            result[f"@{clean_k}"] = v

    for child in children:
        tag = strip_xml_ns(child.tag)
        val = xml_to_data(child)
        if tag in result:
            existing = result[tag]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[tag] = [existing, val]
        else:
            result[tag] = val
    return result


def _dict_to_xml_elements(parent: ET.Element, data: Any) -> None:
    """Рекурсивно наполнить ``ET.Element`` дочерними элементами из словаря или списка."""
    if isinstance(data, Mapping):
        for key, val in data.items():
            key_str = str(key)
            if key_str.startswith("@"):
                parent.set(key_str[1:], str(val))
                continue
            tag = strip_yang_prefix(key_str)
            if isinstance(val, list | tuple):
                for item in val:
                    child = ET.SubElement(parent, tag)
                    _dict_to_xml_elements(child, item)
            elif isinstance(val, Mapping):
                child = ET.SubElement(parent, tag)
                _dict_to_xml_elements(child, val)
            elif val is None:
                ET.SubElement(parent, tag)
            elif isinstance(val, bool):
                child = ET.SubElement(parent, tag)
                child.text = "true" if val else "false"
            else:
                child = ET.SubElement(parent, tag)
                child.text = str(val)
    elif data is not None:
        if isinstance(data, bool):
            parent.text = "true" if data else "false"
        else:
            parent.text = str(data)


def data_to_xml(
    config: Mapping[str, Any] | str | bytes,
    *,
    root_tag: str = "config",
    default_ns: str | None = "urn:ietf:params:xml:ns:netconf:base:1.0",
) -> str:
    """Преобразовать словарь Python или XML-строку в XML-блок (например, ``<config>...</config>``)."""
    if isinstance(config, bytes):
        config = config.decode("utf-8", errors="replace")
    if isinstance(config, str):
        stripped = config.strip()
        if stripped.startswith("<"):
            elem = safe_parse_xml(stripped)
            if strip_xml_ns(elem.tag) == root_tag:
                return stripped
            ns_attr = f' xmlns="{default_ns}"' if default_ns else ""
            return f"<{root_tag}{ns_attr}>{stripped}</{root_tag}>"
        try:
            parsed_json = json.loads(stripped)
            if isinstance(parsed_json, Mapping):
                config = parsed_json
            else:
                ns_attr = f' xmlns="{default_ns}"' if default_ns else ""
                return f"<{root_tag}{ns_attr}>{stripped}</{root_tag}>"
        except ValueError:
            ns_attr = f' xmlns="{default_ns}"' if default_ns else ""
            return f"<{root_tag}{ns_attr}>{stripped}</{root_tag}>"

    root = ET.Element(root_tag)
    if default_ns:
        root.set("xmlns", default_ns)
    _dict_to_xml_elements(root, config)
    return ET.tostring(root, encoding="unicode")


def parse_yang_path_steps(path: str) -> list[tuple[str, dict[str, str]]]:
    """Разобрать путь YANG / RESTCONF / XPath / OpenConfig на шаги ``(node_name, keys_dict)``."""
    cleaned = path.strip()
    if not cleaned or cleaned == "/":
        return []
    steps: list[tuple[str, dict[str, str]]] = []
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

    for seg in segments:
        if not seg:
            continue
        node_part = seg
        keys: dict[str, str] = {}
        if "[" in seg:
            node_part = seg[: seg.index("[")]
            for pred_match in _XPATH_PRED_RE.finditer(seg[seg.index("[") :]):
                k, v = pred_match.groups()
                keys[strip_yang_prefix(k)] = v
        elif "=" in seg:
            node_part, eq_val = seg.split("=", 1)
            keys["name"] = eq_val.strip("'\"")
        steps.append((strip_yang_prefix(node_part), keys))
    return steps


def query_yang_tree(tree: Mapping[str, Any], path: str) -> Any:
    """Извлечь поддерево из словаря YANG/OpenConfig по XPath / RESTCONF / gNMI пути."""
    steps = parse_yang_path_steps(path)
    if not steps:
        return copy.deepcopy(dict(tree))

    cur: Any = tree
    for node_name, keys in steps:
        if not isinstance(cur, Mapping):
            return None
        matched_val: Any = None
        for k, v in cur.items():
            if strip_yang_prefix(str(k)) == node_name or str(k) == node_name:
                matched_val = v
                break
        if matched_val is None:
            # Если на верхнем уровне есть вложенный контейнер с этим узлом
            for v in cur.values():
                if isinstance(v, Mapping):
                    for sub_k, sub_v in v.items():
                        if strip_yang_prefix(str(sub_k)) == node_name:
                            matched_val = sub_v
                            break
                if matched_val is not None:
                    break
        if matched_val is None:
            return None
        if keys:
            if isinstance(matched_val, list):
                found_item = None
                for item in matched_val:
                    if isinstance(item, Mapping) and all(
                        str(item.get(pk) or item.get(f"config/{pk}") or "") == pv
                        for pk, pv in keys.items()
                    ):
                        found_item = item
                        break
                cur = found_item
            elif isinstance(matched_val, Mapping):
                if all(str(matched_val.get(pk, "")) == pv for pk, pv in keys.items()):
                    cur = matched_val
                elif len(keys) == 1 and next(iter(keys.values())) in matched_val:
                    cur = matched_val[next(iter(keys.values()))]
                else:
                    return None
            else:
                return None
        else:
            cur = matched_val
    return copy.deepcopy(cur)


def apply_yang_edit(
    tree: dict[str, Any],
    path: str,
    payload: Any,
    operation: str = "merge",
) -> dict[str, Any]:
    """Применить операцию ``merge``, ``replace``, ``create`` или ``delete`` к in-memory дереву YANG."""
    steps = parse_yang_path_steps(path)
    op = operation.lower()

    if not steps:
        if op in ("delete", "remove"):
            if isinstance(payload, Mapping):
                for k in list(payload.keys()):
                    norm_k = strip_yang_prefix(str(k))
                    for tk in list(tree.keys()):
                        if strip_yang_prefix(str(tk)) == norm_k:
                            tree.pop(tk, None)
            else:
                tree.clear()
            return tree
        if op == "replace":
            tree.clear()
            if isinstance(payload, Mapping):
                tree.update(copy.deepcopy(dict(payload)))
            return tree
        if isinstance(payload, Mapping):
            deep_merge_yang(tree, payload)
        return tree

    cur: Any = tree
    for idx, (node_name, keys) in enumerate(steps):
        if not isinstance(cur, dict):
            break
        is_last = idx == len(steps) - 1
        actual_key = node_name
        for k in cur:
            if strip_yang_prefix(str(k)) == node_name:
                actual_key = str(k)
                break

        if is_last:
            if op in ("delete", "remove"):
                if keys and isinstance(cur.get(actual_key), list):
                    cur[actual_key] = [
                        item
                        for item in cur[actual_key]
                        if not (
                            isinstance(item, Mapping)
                            and all(str(item.get(pk, "")) == pv for pk, pv in keys.items())
                        )
                    ]
                else:
                    cur.pop(actual_key, None)
                return tree

            unwrapped = payload
            if isinstance(payload, Mapping) and len(payload) == 1:
                only_k = next(iter(payload.keys()))
                if strip_yang_prefix(str(only_k)) == node_name:
                    unwrapped = payload[only_k]

            if keys:
                if isinstance(unwrapped, Mapping):
                    unwrapped = {**keys, **dict(unwrapped)}
                existing_list = cur.get(actual_key)
                if isinstance(existing_list, list):
                    for i, item in enumerate(existing_list):
                        if isinstance(item, dict) and all(
                            str(item.get(pk, "")) == pv for pk, pv in keys.items()
                        ):
                            if op == "replace":
                                existing_list[i] = copy.deepcopy(unwrapped)
                            elif isinstance(unwrapped, Mapping):
                                deep_merge_yang(existing_list[i], unwrapped)
                            else:
                                existing_list[i] = copy.deepcopy(unwrapped)
                            return tree
                    existing_list.append(copy.deepcopy(unwrapped))
                    return tree
                if isinstance(existing_list, dict):
                    if all(str(existing_list.get(pk, "")) == pv for pk, pv in keys.items()):
                        if op == "replace":
                            cur[actual_key] = copy.deepcopy(unwrapped)
                        elif isinstance(unwrapped, Mapping):
                            deep_merge_yang(existing_list, unwrapped)
                        return tree
                    cur[actual_key] = [existing_list, copy.deepcopy(unwrapped)]
                    return tree
                cur[actual_key] = [copy.deepcopy(unwrapped)]
                return tree

            existing_target_node = cur.get(actual_key)
            if op == "replace" or not isinstance(existing_target_node, dict):
                cur[actual_key] = copy.deepcopy(unwrapped)
            elif isinstance(unwrapped, Mapping):
                deep_merge_yang(existing_target_node, unwrapped)
            else:
                cur[actual_key] = copy.deepcopy(unwrapped)
            return tree

        # Промежуточный шаг
        if actual_key not in cur or cur[actual_key] is None:
            cur[actual_key] = [dict(keys)] if keys else {}
        nxt = cur[actual_key]
        if keys:
            if isinstance(nxt, list):
                matched_elem: dict[str, Any] | None = None
                for item in nxt:
                    if isinstance(item, dict) and all(
                        str(item.get(pk, "")) == pv for pk, pv in keys.items()
                    ):
                        matched_elem = item
                        break
                if matched_elem is None:
                    matched_elem = dict(keys)
                    nxt.append(matched_elem)
                cur = matched_elem
            elif isinstance(nxt, dict):
                for pk, pv in keys.items():
                    nxt.setdefault(pk, pv)
                cur = nxt
        else:
            if not isinstance(nxt, dict):
                cur[actual_key] = {}
            cur = cur[actual_key]

    return tree


def deep_merge_yang(target: dict[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    """Глубокое слияние YANG-словарей с сопоставлением ключей без учёта префикса модуля."""
    for src_k, src_v in source.items():
        norm_src = strip_yang_prefix(str(src_k))
        dest_k = str(src_k)
        for existing_k in target:
            if strip_yang_prefix(str(existing_k)) == norm_src:
                dest_k = str(existing_k)
                break
        if (
            dest_k in target
            and isinstance(target[dest_k], dict)
            and isinstance(src_v, Mapping)
        ):
            deep_merge_yang(target[dest_k], src_v)
        elif (
            dest_k in target
            and isinstance(target[dest_k], list)
            and isinstance(src_v, list)
        ):
            for new_item in src_v:
                if isinstance(new_item, Mapping) and "name" in new_item:
                    merged_in_list = False
                    for existing_item in target[dest_k]:
                        if (
                            isinstance(existing_item, dict)
                            and existing_item.get("name") == new_item.get("name")
                        ):
                            deep_merge_yang(existing_item, new_item)
                            merged_in_list = True
                            break
                    if not merged_in_list:
                        target[dest_k].append(copy.deepcopy(dict(new_item)))
                else:
                    target[dest_k].append(copy.deepcopy(new_item))
        else:
            target[dest_k] = copy.deepcopy(src_v)
    return target


def normalize_yang_structure(val: Any) -> Any:
    """Нормализовать ключи структуры YANG (удаляя префиксы модулей) для идемпотентного сравнения."""
    if isinstance(val, Mapping):
        out: dict[str, Any] = {}
        for k, v in val.items():
            clean_k = strip_yang_prefix(str(k))
            if clean_k.startswith("@"):
                continue
            out[clean_k] = normalize_yang_structure(v)
        return out
    if isinstance(val, list | tuple):
        return [normalize_yang_structure(x) for x in val]
    return val


def yang_subset_matches(current: Any, desired: Any) -> bool:
    """Проверить, что все поля и элементы ``desired`` уже присутствуют и совпадают в ``current``."""
    norm_cur = normalize_yang_structure(current)
    norm_des = normalize_yang_structure(desired)
    return _subset_check(norm_cur, norm_des)


def _subset_check(cur: Any, des: Any) -> bool:
    if isinstance(des, Mapping):
        if len(des) == 1 and isinstance(cur, Mapping):
            only_key = next(iter(des.keys()))
            if only_key not in cur and isinstance(des[only_key], Mapping):
                return _subset_check(cur, des[only_key])
        if not isinstance(cur, Mapping):
            return False
        return all(k in cur and _subset_check(cur[k], v) for k, v in des.items())
    if isinstance(des, list):
        if isinstance(cur, Mapping):
            cur = [cur]
        if not isinstance(cur, list):
            return False
        return all(
            any(_subset_check(cur_item, des_item) for cur_item in cur)
            for des_item in des
        )
    return str(cur) == str(des) if (cur is not None and des is not None) else (cur == des)


def compute_yang_diff(before: Any, after: Any, path: str = "/") -> str:
    """Вычислить текстовый unified diff между двумя состояниями поддерева YANG."""
    before_norm = normalize_yang_structure(before) if before is not None else {}
    after_norm = normalize_yang_structure(after) if after is not None else {}
    before_lines = json.dumps(before_norm, indent=2, sort_keys=True, ensure_ascii=False).splitlines(keepends=True)
    after_lines = json.dumps(after_norm, indent=2, sort_keys=True, ensure_ascii=False).splitlines(keepends=True)
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"current:{path}",
        tofile=f"desired:{path}",
    )
    return "".join(diff)


def extract_yang_interfaces_and_system(data: Any) -> dict[str, Any]:
    """Извлечь нормализованные факты (``hostname``, ``interfaces``) из YANG-деревьев IETF / OpenConfig."""
    norm = normalize_yang_structure(data)
    if not isinstance(norm, Mapping):
        return {"hostname": None, "interfaces": []}

    if "data" in norm and isinstance(norm["data"], Mapping):
        norm = norm["data"]

    hostname: str | None = None
    os_version: str | None = None
    sys_block = norm.get("system") or norm.get("system-state")
    if isinstance(sys_block, Mapping):
        raw_cfg = sys_block.get("config")
        cfg_block: Mapping[str, Any] = raw_cfg if isinstance(raw_cfg, Mapping) else {}
        raw_st = sys_block.get("state")
        state_block: Mapping[str, Any] = raw_st if isinstance(raw_st, Mapping) else {}
        hostname = str(
            sys_block.get("hostname")
            or cfg_block.get("hostname")
            or state_block.get("hostname")
            or ""
        ).strip() or None
        plat = sys_block.get("platform")
        if isinstance(plat, Mapping):
            os_version = str(plat.get("os-version") or plat.get("os-name") or "").strip() or None

    interfaces_out: list[dict[str, Any]] = []
    ifaces_container = norm.get("interfaces") or norm.get("interfaces-state")
    raw_list: list[Any] = []
    if isinstance(ifaces_container, Mapping):
        iface_entries = ifaces_container.get("interface")
        if isinstance(iface_entries, list):
            raw_list = iface_entries
        elif isinstance(iface_entries, Mapping):
            raw_list = [iface_entries]
    elif isinstance(norm.get("interface"), list):
        raw_list = norm["interface"]
    elif isinstance(norm.get("interface"), Mapping):
        raw_list = [norm["interface"]]

    for entry in raw_list:
        if not isinstance(entry, Mapping):
            continue
        raw_e_st = entry.get("state")
        state_sub: Mapping[str, Any] = raw_e_st if isinstance(raw_e_st, Mapping) else {}
        raw_e_cfg = entry.get("config")
        cfg_sub: Mapping[str, Any] = raw_e_cfg if isinstance(raw_e_cfg, Mapping) else {}
        name = str(
            entry.get("name")
            or state_sub.get("name")
            or cfg_sub.get("name")
            or ""
        ).strip()
        if not name:
            continue
        mac = str(
            entry.get("phys-address")
            or entry.get("mac-address")
            or state_sub.get("hardware-address")
            or state_sub.get("mac-address")
            or ""
        ).strip()
        mtu_raw = (
            entry.get("mtu")
            or state_sub.get("mtu")
            or cfg_sub.get("mtu")
            or 1500
        )
        try:
            mtu = int(mtu_raw)
        except (TypeError, ValueError):
            mtu = 1500

        oper_raw = (
            entry.get("oper-status")
            or state_sub.get("oper-status")
            or entry.get("admin-status")
            or state_sub.get("admin-status")
        )
        enabled_val = entry.get("enabled", cfg_sub.get("enabled", True))
        if oper_raw is not None:
            state_str = "UP" if str(oper_raw).upper() in ("UP", "TRUE", "1") else "DOWN"
        else:
            state_str = "UP" if bool(enabled_val) else "DOWN"

        ipv4_list: list[str] = []
        ipv6_list: list[str] = []

        # 1. IETF ietf-ip:ipv4 / ipv6
        for family, target_list in (("ipv4", ipv4_list), ("ipv6", ipv6_list)):
            ip_container = entry.get(family)
            if isinstance(ip_container, Mapping):
                addrs = ip_container.get("address")
                addr_items = (
                    addrs
                    if isinstance(addrs, list)
                    else ([addrs] if isinstance(addrs, Mapping) else [])
                )
                for addr_obj in addr_items:
                    if isinstance(addr_obj, Mapping) and addr_obj.get("ip"):
                        target_list.append(str(addr_obj["ip"]))

        # 2. OpenConfig subinterfaces -> subinterface -> ipv4/ipv6 -> addresses -> address
        subifaces = entry.get("subinterfaces")
        if isinstance(subifaces, Mapping):
            sub_items = subifaces.get("subinterface")
            sub_list = (
                sub_items
                if isinstance(sub_items, list)
                else ([sub_items] if isinstance(sub_items, Mapping) else [])
            )
            for sub in sub_list:
                if not isinstance(sub, Mapping):
                    continue
                for family, target_list in (("ipv4", ipv4_list), ("ipv6", ipv6_list)):
                    fam_block = sub.get(family)
                    if isinstance(fam_block, Mapping):
                        addrs_container = fam_block.get("addresses")
                        if isinstance(addrs_container, Mapping):
                            addr_entries = addrs_container.get("address")
                            a_list = (
                                addr_entries
                                if isinstance(addr_entries, list)
                                else ([addr_entries] if isinstance(addr_entries, Mapping) else [])
                            )
                            for a_item in a_list:
                                if isinstance(a_item, Mapping):
                                    raw_acfg = a_item.get("config")
                                    a_cfg: Mapping[str, Any] = (
                                        raw_acfg if isinstance(raw_acfg, Mapping) else {}
                                    )
                                    raw_ast = a_item.get("state")
                                    a_st: Mapping[str, Any] = (
                                        raw_ast if isinstance(raw_ast, Mapping) else {}
                                    )
                                    ip_val = a_item.get("ip") or a_cfg.get("ip") or a_st.get("ip")
                                    if ip_val and str(ip_val) not in target_list:
                                        target_list.append(str(ip_val))

        interfaces_out.append(
            {
                "name": name,
                "mac": mac,
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
                "state": state_str,
                "mtu": mtu,
            }
        )

    return {
        "hostname": hostname,
        "os_version": os_version,
        "interfaces": interfaces_out,
    }


__all__ = [
    "StructuredNetworkTransport",
    "apply_yang_edit",
    "compute_yang_diff",
    "data_to_xml",
    "deep_merge_yang",
    "extract_yang_interfaces_and_system",
    "normalize_yang_structure",
    "parse_yang_path_steps",
    "query_yang_tree",
    "safe_parse_xml",
    "strip_xml_ns",
    "strip_yang_prefix",
    "xml_to_data",
    "yang_subset_matches",
]
