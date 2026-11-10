# src/uniconn/services/provisioning/yang.py
"""Идемпотентное управление YANG-конфигурацией сетевых устройств (conn.state.ensure_yang)."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal

from ...result import EnsureResult
from ...transports.network.base import (
    apply_yang_edit,
    compute_yang_diff,
    normalize_yang_structure,
    query_yang_tree,
    safe_parse_xml,
    xml_to_data,
    yang_subset_matches,
)

if TYPE_CHECKING:
    from ...core.connection import Connection
    from .facade import StateManagementService


def _coerce_desired_data(data: Mapping[str, Any] | str | bytes | None) -> Any:
    if data is None:
        return {}
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    if isinstance(data, str):
        stripped = data.strip()
        if not stripped:
            return {}
        if stripped.startswith("<"):
            return xml_to_data(safe_parse_xml(stripped))
        try:
            return json.loads(stripped)
        except ValueError:
            return {"value": stripped}
    return dict(data)


async def _finalize_yang_mutation(
    conn: Connection,
    *,
    path: str,
    state: Literal["present", "absent"],
    datastore: str,
    validate: bool,
    auto_commit: bool,
    details: str,
    diff_str: str,
) -> EnsureResult:
    """Выполнить опциональную валидацию и коммит после успешного ``conn.net.edit``."""
    if validate:
        val_res = await conn.net.validate(source=datastore)
        if not val_res.ok:
            await conn.net.discard_changes()
            return EnsureResult(
                target=path,
                state=state,
                changed=False,
                ok=False,
                details=f"YANG validation failed: {val_res.text}",
                diff=diff_str,
            )

    if auto_commit and datastore == "candidate" and conn.transport_name == "netconf":
        com_res = await conn.net.commit()
        if not com_res.ok:
            return EnsureResult(
                target=path,
                state=state,
                changed=False,
                ok=False,
                details=f"YANG commit failed: {com_res.text}",
                diff=diff_str,
            )

    return EnsureResult(
        target=path,
        state=state,
        changed=True,
        ok=True,
        details=details,
        diff=diff_str,
    )


async def ensure_yang(
    service: StateManagementService,
    path: str,
    data: Mapping[str, Any] | str | bytes | None = None,
    *,
    datastore: str = "candidate",
    operation: Literal["merge", "replace"] = "merge",
    state: Literal["present", "absent"] = "present",
    auto_commit: bool = True,
    validate: bool = False,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно обеспечить целевое состояние YANG-узла по пути ``path``."""
    conn = service._conn
    effective_dry_run = conn.dry_run if dry_run is None else dry_run
    desired = _coerce_desired_data(data)

    # 1. Читаем текущее состояние узла (если возможно в текущем режиме)
    current_sub: Any = None
    if not effective_dry_run or service._can_inspect_in_dry_run():
        get_res = await conn.net.get(path=path, datastore="running")
        if get_res.ok and get_res.data is not None and get_res.data != {}:
            raw_cur = get_res.data
            if (
                isinstance(raw_cur, Mapping)
                and "data" in raw_cur
                and isinstance(raw_cur["data"], Mapping)
            ):
                raw_cur = raw_cur["data"]
            queried = query_yang_tree(raw_cur, path) if isinstance(raw_cur, Mapping) else None
            current_sub = queried if queried is not None else raw_cur

    if state == "absent":
        is_already_absent = current_sub is None or current_sub == {} or current_sub == []
        if is_already_absent and (not effective_dry_run or service._can_inspect_in_dry_run()):
            return EnsureResult(
                target=path,
                state="absent",
                changed=False,
                ok=True,
                details=f"YANG node {path} is already absent",
                dry_run=effective_dry_run,
            )
        diff_str = compute_yang_diff(current_sub, {}, path=path)
        if effective_dry_run:
            return EnsureResult(
                target=path,
                state="absent",
                changed=True,
                ok=True,
                details=f"Would delete YANG node {path}",
                dry_run=True,
                diff=diff_str,
            )
        del_res = await conn.net.edit(
            desired or {},
            path=path,
            datastore=datastore,
            operation="delete",
        )
        if not del_res.ok:
            return EnsureResult(
                target=path,
                state="absent",
                changed=False,
                ok=False,
                details="; ".join(str(e) for e in del_res.errors) or del_res.text,
            )
        return await _finalize_yang_mutation(
            conn,
            path=path,
            state="absent",
            datastore=datastore,
            validate=validate,
            auto_commit=auto_commit,
            details=f"Deleted YANG node {path}",
            diff_str=diff_str,
        )

    # state == "present"
    matches = False
    if current_sub is not None and current_sub != {}:
        if operation == "replace":
            norm_cur = normalize_yang_structure(current_sub)
            norm_des = normalize_yang_structure(desired)
            cur_map = norm_cur if isinstance(norm_cur, Mapping) else {}
            if (
                isinstance(norm_des, Mapping)
                and len(norm_des) == 1
                and next(iter(norm_des.keys())) not in cur_map
            ):
                norm_des = next(iter(norm_des.values()))
            matches = norm_cur == norm_des
        else:
            matches = yang_subset_matches(current_sub, desired)

    if matches:
        return EnsureResult(
            target=path,
            state="present",
            changed=False,
            ok=True,
            details=f"YANG node {path} already matches desired state",
            dry_run=effective_dry_run,
        )

    # Вычисляем целевое состояние для diff
    projected: dict[str, Any] = (
        copy.deepcopy(dict(current_sub)) if isinstance(current_sub, Mapping) else {}
    )
    if operation == "replace":
        projected = (
            copy.deepcopy(dict(desired))
            if isinstance(desired, Mapping)
            else {"value": desired}
        )
    elif isinstance(desired, Mapping):
        apply_yang_edit(projected, "", desired, operation="merge")
    diff_str = compute_yang_diff(current_sub, projected, path=path)

    if effective_dry_run:
        return EnsureResult(
            target=path,
            state="present",
            changed=True,
            ok=True,
            details=f"Would apply YANG {operation} at {path}",
            dry_run=True,
            diff=diff_str,
        )

    edit_res = await conn.net.edit(
        data if data is not None else desired,
        path=path,
        datastore=datastore,
        operation=operation,
    )
    if not edit_res.ok:
        return EnsureResult(
            target=path,
            state="present",
            changed=False,
            ok=False,
            details="; ".join(str(e) for e in edit_res.errors) or edit_res.text,
            diff=diff_str,
        )

    return await _finalize_yang_mutation(
        conn,
        path=path,
        state="present",
        datastore=datastore,
        validate=validate,
        auto_commit=auto_commit,
        details=f"Applied YANG {operation} at {path}",
        diff_str=diff_str,
    )


__all__ = ["ensure_yang"]
