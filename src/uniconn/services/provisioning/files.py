# src/uniconn/services/provisioning/files.py
"""Идемпотентное управление файлами, ссылками, директориями и строками (ensure_file, ensure_directory, ensure_line)."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import os
import re
import shlex
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ...result import EnsureResult
from ._plan import ChangePlan, _parse_mode

if TYPE_CHECKING:
    from .service import StateManagementService


# ─── Чистые функции трансформации строк (Pure Functional Core) ──────


def transform_lines_present(
    existing_lines: Sequence[str],
    clean_line: str,
    pattern: re.Pattern[str] | None,
    *,
    path_str: str,
    file_exists: bool,
) -> tuple[list[str], bool, str]:
    """Вычислить новое состояние списка строк для ``ensure_line(state='present')``."""
    if not file_exists:
        return [clean_line], True, f"Created {path_str} with target line"

    if pattern is None:
        if clean_line in existing_lines:
            return list(existing_lines), False, f"Line already present in {path_str}"
        return [*existing_lines, clean_line], True, f"Appended line to {path_str}"

    new_lines: list[str] = []
    matched_any = False
    changed = False
    details = "No changes needed"

    for existing in existing_lines:
        if not pattern.search(existing):
            new_lines.append(existing)
            continue
        if not matched_any:
            new_lines.append(clean_line)
            matched_any = True
            if existing != clean_line:
                changed = True
                details = f"Replaced matching line in {path_str}"
        else:
            changed = True
            details = f"Collapsed duplicate matching lines in {path_str}"

    if not matched_any:
        new_lines.append(clean_line)
        changed = True
        details = f"Appended line to {path_str}"

    return new_lines, changed, details


def transform_lines_absent(
    existing_lines: Sequence[str],
    clean_line: str,
    pattern: re.Pattern[str] | None,
    *,
    path_str: str,
) -> tuple[list[str], bool, str]:
    """Вычислить новое состояние списка строк для ``ensure_line(state='absent')``."""
    new_lines: list[str] = []
    changed = False
    for existing in existing_lines:
        matches = bool(pattern.search(existing)) if pattern is not None else (existing == clean_line)
        if matches:
            changed = True
        else:
            new_lines.append(existing)
    details = f"Removed matching line(s) from {path_str}" if changed else f"Line already absent in {path_str}"
    return new_lines, changed, details


async def ensure_line(
    svc: StateManagementService,
    remote_path: str | Path,
    line: str,
    state: Literal["present", "absent"] = "present",
    regex: str | None = None,
    create: bool = True,
    backup: bool = False,
    mode: int | None = None,
    encoding: str = "utf-8",
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно обеспечить наличие, замену или отсутствие строки в файле."""
    path_str = str(remote_path)
    clean_line = line.rstrip("\r\n")
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run

    if not svc._can_inspect_in_dry_run():
        synthetic_diff = (
            f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+{clean_line}\n"
            if state == "present"
            else f"--- a:{path_str}\n+++ b:{path_str}\n@@ -1 +0,0 @@\n-{clean_line}\n"
        )
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure line in {path_str} is {state}",
            dry_run=True,
            diff=synthetic_diff,
        )

    file_exists = await svc._conn.exists(path_str)
    if not file_exists and state == "absent":
        return EnsureResult(
            target=path_str,
            state=state,
            changed=False,
            ok=True,
            details=f"File {path_str} does not exist (already absent)",
            dry_run=is_dry_run,
            diff=None,
        )
    if not file_exists and not create:
        return EnsureResult(
            target=path_str,
            state=state,
            changed=False,
            ok=False,
            details=f"File {path_str} does not exist and create=False",
            dry_run=is_dry_run,
            diff=None,
        )

    original_text = ""
    existing_lines: list[str] = []
    if file_exists:
        raw_content = await svc._conn.read_file(path_str, encoding=encoding)
        original_text = raw_content if isinstance(raw_content, str) else raw_content.decode(encoding)
        existing_lines = original_text.splitlines()

    pattern = re.compile(regex) if regex is not None else None
    if state == "present":
        new_lines, changed, details = transform_lines_present(
            existing_lines, clean_line, pattern, path_str=path_str, file_exists=file_exists
        )
    else:
        new_lines, changed, details = transform_lines_absent(
            existing_lines, clean_line, pattern, path_str=path_str
        )

    if not changed:
        return EnsureResult(
            target=path_str,
            state=state,
            changed=False,
            ok=True,
            details=details,
            dry_run=is_dry_run,
            diff=None,
        )

    new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
    computed_diff = "".join(
        difflib.unified_diff(
            original_text.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a:{path_str}" if file_exists else "/dev/null",
            tofile=f"b:{path_str}",
        )
    )

    if is_dry_run:
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] {details}",
            dry_run=True,
            diff=computed_diff,
        )

    if backup and file_exists:
        await svc._conn.write_file(f"{path_str}.bak", original_text, encoding=encoding)
    await svc._conn.write_file(path_str, new_content, mode=mode, encoding=encoding)
    return EnsureResult(
        target=path_str,
        state=state,
        changed=True,
        ok=True,
        details=details,
        dry_run=False,
        diff=computed_diff,
    )


# ─── Общие хелперы планирования и применения метаданных FS ──────────


async def _plan_mode_change(
    svc: StateManagementService,
    plan: ChangePlan,
    path_str: str,
    *,
    exists: bool,
    parsed_mode: int | None,
    recurse: bool = False,
) -> bool:
    """Проверить необходимость изменения прав доступа и записать изменение в ``ChangePlan``."""
    if parsed_mode is None:
        return False
    if not exists:
        plan.record(f"mode {oct(parsed_mode)}")
        return True
    try:
        st = await svc._conn.stat(path_str)
        cur_mode = svc._extract_stat_mode(st)
    except Exception:
        cur_mode = -1
    if cur_mode == parsed_mode and not recurse:
        return False
    cur_oct = oct(cur_mode) if cur_mode >= 0 else "unknown"
    plan.record(
        f"mode {cur_oct} -> {oct(parsed_mode)}",
        f"--- a:{path_str} (mode)\n+++ b:{path_str} (mode)\n@@ -1 +1 @@\n-{cur_oct}\n+{oct(parsed_mode)}\n",
    )
    return True


async def _plan_owner_change(
    svc: StateManagementService,
    plan: ChangePlan,
    path_str: str,
    *,
    exists: bool,
    owner: str | None,
    group: str | None,
    recurse: bool = False,
    is_link: bool = False,
    sudo: bool = False,
) -> bool:
    """Проверить необходимость изменения владельца/группы и записать изменение в ``ChangePlan``."""
    if owner is None and group is None:
        return False
    if not exists and not is_link:
        ug_spec = f"{owner or ''}:{group or ''}".strip(":")
        plan.record(f"owner {ug_spec}")
        return True

    cur_u, cur_g = await svc._get_owner_group(path_str, sudo=sudo, is_link=is_link)
    needs_change = (
        (owner is not None and cur_u != owner)
        or (group is not None and cur_g != group)
        or recurse
    )
    if not needs_change:
        return False
    ug_spec = f"{owner or cur_u or ''}:{group or cur_g or ''}".strip(":")
    owner_diff = (
        f"--- a:{path_str} (owner)\n+++ b:{path_str} (owner)\n"
        f"@@ -1 +1 @@\n-{cur_u or '?'}:{cur_g or '?'}\n+{ug_spec}\n"
    )
    plan.record(f"owner {ug_spec}", owner_diff)
    return True


# ─── Обработчики состояний для ensure_file (State Dispatch) ─────────


async def _ensure_file_absent(
    svc: StateManagementService,
    path_str: str,
    *,
    encoding: str,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Обработать ``ensure_file(..., state='absent')``."""
    is_symlink = False
    if svc._conn.transport_name == "local" and not sudo:
        eff = Path(svc._conn.context.resolve_path(path_str))
        is_symlink = eff.is_symlink()
        exists = eff.exists() or is_symlink
    else:
        exists = await svc._conn.exists(path_str)
        if not exists:
            chk = await svc._conn.run(
                f"test -L {shlex.quote(path_str)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            is_symlink = chk.ok
            exists = is_symlink

    if not exists:
        return EnsureResult(
            target=path_str,
            state="absent",
            changed=False,
            ok=True,
            details=f"File {path_str} is already absent",
            dry_run=is_dry_run,
            diff=None,
        )

    old_text = ""
    if not is_symlink:
        with contextlib.suppress(Exception):
            raw = await svc._conn.read_file(path_str, encoding=encoding)
            old_text = raw if isinstance(raw, str) else raw.decode(encoding, errors="replace")

    diff_str = (
        "".join(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                [],
                fromfile=f"a:{path_str}",
                tofile="/dev/null",
            )
        )
        if old_text
        else f"--- a:{path_str}\n+++ /dev/null\n@@ -1 +0,0 @@\n-<removed>\n"
    )

    if is_dry_run:
        return EnsureResult(
            target=path_str,
            state="absent",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would remove {path_str}",
            dry_run=True,
            diff=diff_str,
        )

    if svc._conn.transport_name == "local" and not sudo:
        Path(svc._conn.context.resolve_path(path_str)).unlink(missing_ok=True)
    elif sudo or is_symlink:
        await svc._conn.run(
            f"rm -f {shlex.quote(path_str)}",
            sudo=sudo,
            raise_on_error=True,
            dry_run=False,
        )
    else:
        await svc._conn.remove_file(path_str)

    return EnsureResult(
        target=path_str,
        state="absent",
        changed=True,
        ok=True,
        details=f"Removed {path_str}",
        dry_run=False,
        diff=diff_str,
    )


async def _ensure_file_link(
    svc: StateManagementService,
    path_str: str,
    *,
    target_str: str,
    owner: str | None,
    group: str | None,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Обработать ``ensure_file(..., state='link')``."""
    current_target: str | None = None
    if svc._conn.transport_name == "local" and not sudo:
        eff = Path(svc._conn.context.resolve_path(path_str))
        if eff.is_symlink():
            current_target = os.readlink(eff)
    else:
        rl_res = await svc._conn.run(
            f"readlink {shlex.quote(path_str)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if rl_res.ok:
            current_target = rl_res.stdout.rstrip("\r\n")

    plan = ChangePlan(target=path_str, state="link", is_dry_run=is_dry_run)
    link_changed = current_target != target_str
    if link_changed:
        plan.record(
            f"symlink -> {target_str}",
            f"--- a:{path_str}\n+++ b:{path_str}\n@@ -1 +1 @@\n-{current_target or '<absent>'}\n+{target_str}\n",
        )

    owner_changed = await _plan_owner_change(
        svc,
        plan,
        path_str,
        exists=True,
        owner=owner,
        group=group,
        is_link=True,
        sudo=sudo,
    )

    if not plan.changed or is_dry_run:
        return plan.to_result(
            unchanged_details=f"Symlink {path_str} -> {target_str} already in place",
            changed_prefix=f"Symlink {path_str}",
            dry_run_prefix=f"[DRY-RUN] Would update symlink {path_str}",
        )

    if link_changed:
        if svc._conn.transport_name == "local" and not sudo:
            eff = Path(svc._conn.context.resolve_path(path_str))
            if eff.exists() or eff.is_symlink():
                eff.unlink()
            eff.parent.mkdir(parents=True, exist_ok=True)
            eff.symlink_to(target_str)
        else:
            await svc._conn.run(
                f"ln -sfn {shlex.quote(target_str)} {shlex.quote(path_str)}",
                sudo=sudo,
                raise_on_error=True,
                dry_run=False,
            )

    if owner_changed:
        await svc._apply_owner_group(
            path_str,
            owner=owner,
            group=group,
            is_link=True,
            sudo=sudo,
        )

    return plan.to_result(
        unchanged_details=f"Symlink {path_str} -> {target_str} already in place",
        changed_prefix=f"Symlink {path_str}",
        dry_run_prefix=f"[DRY-RUN] Would update symlink {path_str}",
    )


def _plan_content_change(
    plan: ChangePlan,
    path_str: str,
    *,
    file_exists: bool,
    old_bytes: bytes,
    content: str | bytes | None,
    encoding: str,
) -> bool:
    """Рассчитать расхождение содержимого файла и пополнить ``ChangePlan``."""
    if content is None:
        if not file_exists:
            plan.record("created empty file", f"--- /dev/null\n+++ b:{path_str}\n@@ -0,0 +1,0 @@\n")
            return True
        return False

    new_bytes = content.encode(encoding) if isinstance(content, str) else bytes(content)
    if file_exists and old_bytes == new_bytes:
        return False

    action_label = "created content" if not file_exists else "updated content"
    from_label = f"a:{path_str}" if file_exists else "/dev/null"
    if isinstance(content, str):
        old_text = old_bytes.decode(encoding, errors="replace") if file_exists else ""
        plan.add_text_diff(
            old_text,
            content,
            fromfile=from_label,
            tofile=f"b:{path_str}",
            action=action_label,
            fallback_diff=f"--- {from_label}\n+++ b:{path_str}\n@@ -1 +1 @@\n+{content}\n",
        )
    else:
        old_hash = hashlib.sha256(old_bytes).hexdigest()[:12] if file_exists else "none"
        new_hash = hashlib.sha256(new_bytes).hexdigest()[:12]
        plan.record(
            action_label,
            f"--- {from_label}\n+++ b:{path_str}\n@@ -1 +1 @@\n"
            f"-binary sha256={old_hash} ({len(old_bytes)} bytes)\n"
            f"+binary sha256={new_hash} ({len(new_bytes)} bytes)\n",
        )
    return True


async def _validate_candidate_file(
    svc: StateManagementService,
    path_str: str,
    *,
    validate: str,
    candidate_payload: str | bytes,
    parsed_mode: int | None,
    encoding: str,
    sudo: bool,
    full_diff: str | None,
) -> EnsureResult | None:
    """Записать временный файл-кандидат и проверить его через команду ``validate``."""
    async with svc._conn.temp_dir(prefix="uniconn_val_") as tmp_dir:
        tmp_candidate = f"{tmp_dir.rstrip('/')}/candidate"
        await svc._conn.write_file(
            tmp_candidate,
            candidate_payload,
            mode=parsed_mode,
            encoding=encoding,
        )
        val_cmd = (
            validate.replace("%s", shlex.quote(tmp_candidate))
            if "%s" in validate
            else f"{validate} {shlex.quote(tmp_candidate)}"
        )
        val_res = await svc._conn.run(
            val_cmd,
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if not val_res.ok:
            err_msg = val_res.stderr.strip() or val_res.stdout.strip()
            return EnsureResult(
                target=path_str,
                state="present",
                changed=False,
                ok=False,
                details=f"Validation command failed ({validate}): {err_msg}",
                dry_run=False,
                diff=full_diff,
            )
    return None


async def _ensure_file_present(
    svc: StateManagementService,
    path_str: str,
    *,
    content: str | bytes | None,
    parsed_mode: int | None,
    owner: str | None,
    group: str | None,
    validate: str | None,
    encoding: str,
    atomic: bool,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Обработать ``ensure_file(..., state='present')``."""
    file_exists = await svc._conn.exists(path_str)
    old_bytes = b""
    if file_exists:
        with contextlib.suppress(Exception):
            raw_existing = await svc._conn.read_file(path_str, encoding=None)
            old_bytes = raw_existing if isinstance(raw_existing, bytes) else raw_existing.encode(encoding)

    plan = ChangePlan(target=path_str, state="present", is_dry_run=is_dry_run)
    content_changed = _plan_content_change(
        plan,
        path_str,
        file_exists=file_exists,
        old_bytes=old_bytes,
        content=content,
        encoding=encoding,
    )
    mode_changed = await _plan_mode_change(
        svc, plan, path_str, exists=file_exists, parsed_mode=parsed_mode
    )
    owner_changed = await _plan_owner_change(
        svc, plan, path_str, exists=file_exists, owner=owner, group=group, sudo=sudo
    )

    if not plan.changed or is_dry_run:
        return plan.to_result(
            unchanged_details=f"File {path_str} already in desired state",
            changed_prefix=f"File {path_str}",
            dry_run_prefix=f"[DRY-RUN] Would update {path_str}",
        )

    if validate is not None:
        candidate: str | bytes = content if content is not None else (old_bytes if file_exists else "")
        val_failure = await _validate_candidate_file(
            svc,
            path_str,
            validate=validate,
            candidate_payload=candidate,
            parsed_mode=parsed_mode,
            encoding=encoding,
            sudo=sudo,
            full_diff=plan.full_diff,
        )
        if val_failure is not None:
            return val_failure

    if content_changed:
        write_payload: str | bytes = content if content is not None else ""
        if sudo and svc._conn.transport_name != "local":
            async with svc._conn.temp_dir(prefix="uniconn_stage_") as stage_dir:
                staged = f"{stage_dir.rstrip('/')}/staged"
                await svc._conn.write_file(staged, write_payload, mode=parsed_mode, encoding=encoding)
                await svc._conn.run(
                    f"mv -f {shlex.quote(staged)} {shlex.quote(path_str)}",
                    sudo=True,
                    raise_on_error=True,
                    dry_run=False,
                )
        else:
            await svc._conn.write_file(
                path_str, write_payload, mode=parsed_mode, encoding=encoding, atomic=atomic
            )

    if mode_changed and parsed_mode is not None:
        if sudo and svc._conn.transport_name != "local":
            await svc._conn.run(
                f"chmod {parsed_mode:o} {shlex.quote(path_str)}",
                sudo=sudo,
                raise_on_error=True,
                dry_run=False,
            )
        else:
            await svc._conn.chmod(path_str, parsed_mode)

    if owner_changed:
        await svc._apply_owner_group(path_str, owner=owner, group=group, sudo=sudo)

    return plan.to_result(
        unchanged_details=f"File {path_str} already in desired state",
        changed_prefix=f"File {path_str}",
        dry_run_prefix=f"[DRY-RUN] Would update {path_str}",
    )


async def ensure_file(
    svc: StateManagementService,
    remote_path: str | Path,
    *,
    state: Literal["present", "absent", "link"] = "present",
    content: str | bytes | None = None,
    target: str | Path | None = None,
    mode: int | str | None = None,
    owner: str | None = None,
    group: str | None = None,
    validate: str | None = None,
    encoding: str = "utf-8",
    atomic: bool = False,
    sudo: bool = False,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять файлом или символической ссылкой на хосте."""
    path_str = str(remote_path)
    parsed_mode = _parse_mode(mode)
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run

    if state == "link" and target is None:
        raise ValueError("Parameter 'target' is required when state='link'")

    if not svc._can_inspect_in_dry_run():
        synth_diff = f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+state={state}\n"
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure file {path_str} is {state}",
            dry_run=True,
            diff=synth_diff,
        )

    if state == "absent":
        return await _ensure_file_absent(
            svc, path_str, encoding=encoding, sudo=sudo, is_dry_run=is_dry_run
        )
    if state == "link":
        return await _ensure_file_link(
            svc,
            path_str,
            target_str=str(target),
            owner=owner,
            group=group,
            sudo=sudo,
            is_dry_run=is_dry_run,
        )
    return await _ensure_file_present(
        svc,
        path_str,
        content=content,
        parsed_mode=parsed_mode,
        owner=owner,
        group=group,
        validate=validate,
        encoding=encoding,
        atomic=atomic,
        sudo=sudo,
        is_dry_run=is_dry_run,
    )


# ─── Обработчики состояний для ensure_directory ─────────────────────


async def _ensure_directory_absent(
    svc: StateManagementService,
    path_str: str,
    *,
    dir_exists: bool,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Обработать ``ensure_directory(..., state='absent')``."""
    if not dir_exists:
        return EnsureResult(
            target=path_str,
            state="absent",
            changed=False,
            ok=True,
            details=f"Directory {path_str} is already absent",
            dry_run=is_dry_run,
            diff=None,
        )

    diff_str = f"--- a:{path_str}\n+++ /dev/null\n@@ -1 +0,0 @@\n-directory {path_str}\n"
    if is_dry_run:
        return EnsureResult(
            target=path_str,
            state="absent",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would remove directory {path_str}",
            dry_run=True,
            diff=diff_str,
        )

    if svc._conn.transport_name == "local" and not sudo:
        shutil.rmtree(Path(svc._conn.context.resolve_path(path_str)))
    else:
        rm_res = await svc._conn.run(
            f"rm -rf {shlex.quote(path_str)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if not rm_res.ok:
            return EnsureResult(
                target=path_str,
                state="absent",
                changed=False,
                ok=False,
                details=rm_res.stderr.strip() or f"Failed to remove directory {path_str}",
                dry_run=False,
                diff=diff_str,
            )

    return EnsureResult(
        target=path_str,
        state="absent",
        changed=True,
        ok=True,
        details=f"Removed directory {path_str}",
        dry_run=False,
        diff=diff_str,
    )


async def ensure_directory(
    svc: StateManagementService,
    remote_path: str | Path,
    *,
    state: Literal["present", "absent"] = "present",
    mode: int | str | None = None,
    owner: str | None = None,
    group: str | None = None,
    recurse: bool = False,
    sudo: bool = False,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно обеспечить наличие или отсутствие директории, её прав и владельца."""
    path_str = str(remote_path)
    parsed_mode = _parse_mode(mode)
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run

    if not svc._can_inspect_in_dry_run():
        synth_diff = f"--- a:{path_str}\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+directory state={state}\n"
        return EnsureResult(
            target=path_str,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure directory {path_str} is {state}",
            dry_run=True,
            diff=synth_diff,
        )

    dir_exists = await svc._conn.exists(path_str)
    if state == "absent":
        return await _ensure_directory_absent(
            svc, path_str, dir_exists=dir_exists, sudo=sudo, is_dry_run=is_dry_run
        )

    plan = ChangePlan(target=path_str, state="present", is_dry_run=is_dry_run)
    created_dir = not dir_exists
    if created_dir:
        plan.record(
            "created directory",
            f"--- /dev/null\n+++ b:{path_str}\n@@ -0,0 +1 @@\n+directory {path_str}\n",
        )

    mode_changed = await _plan_mode_change(
        svc, plan, path_str, exists=dir_exists, parsed_mode=parsed_mode, recurse=recurse
    )
    owner_changed = await _plan_owner_change(
        svc, plan, path_str, exists=dir_exists, owner=owner, group=group, recurse=recurse, sudo=sudo
    )

    if not plan.changed or is_dry_run:
        return plan.to_result(
            unchanged_details=f"Directory {path_str} already in desired state",
            changed_prefix=f"Directory {path_str}",
            dry_run_prefix=f"[DRY-RUN] Would update directory {path_str}",
        )

    if created_dir:
        if sudo and svc._conn.transport_name != "local":
            await svc._conn.run(
                f"mkdir -p {shlex.quote(path_str)}",
                sudo=True,
                raise_on_error=True,
                dry_run=False,
            )
        else:
            await svc._conn.mkdir(path_str, parents=True, exist_ok=True, mode=parsed_mode)

    if mode_changed and parsed_mode is not None:
        if (sudo and svc._conn.transport_name != "local") or recurse:
            rec_flag = "-R " if recurse else ""
            await svc._conn.run(
                f"chmod {rec_flag}{parsed_mode:o} {shlex.quote(path_str)}",
                sudo=sudo,
                raise_on_error=True,
                dry_run=False,
            )
        else:
            await svc._conn.chmod(path_str, parsed_mode)

    if owner_changed:
        await svc._apply_owner_group(
            path_str, owner=owner, group=group, recurse=recurse, sudo=sudo
        )

    return plan.to_result(
        unchanged_details=f"Directory {path_str} already in desired state",
        changed_prefix=f"Directory {path_str}",
        dry_run_prefix=f"[DRY-RUN] Would update directory {path_str}",
    )
