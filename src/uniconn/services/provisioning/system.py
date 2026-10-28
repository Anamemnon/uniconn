# src/uniconn/services/provisioning/system.py
"""Системные примитивы: управление пользователями, SSH-ключами, systemd-юнитами и параметрами sysctl."""

from __future__ import annotations

import contextlib
import difflib
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from ...result import EnsureResult
from .services import ServiceState

if TYPE_CHECKING:
    from .service import StateManagementService


# ─── Декларативная спецификация атрибутов пользователя (Pattern 4) ──


@dataclass(frozen=True, slots=True)
class UserAttributeSpec:
    """Спецификация атрибута пользователя для единообразной сборки флагов ``useradd``/``usermod``."""

    name: str
    cli_flag: str
    quote_value: bool = True

    def format_cli_arg(self, raw_value: str | int) -> str:
        """Сформировать аргумент командной строки для ``useradd`` или ``usermod``."""
        text = str(raw_value)
        return shlex.quote(text) if self.quote_value else text


_SCALAR_USER_SPECS: tuple[UserAttributeSpec, ...] = (
    UserAttributeSpec(name="uid", cli_flag="-u", quote_value=False),
    UserAttributeSpec(name="group", cli_flag="-g", quote_value=True),
    UserAttributeSpec(name="shell", cli_flag="-s", quote_value=True),
    UserAttributeSpec(name="home", cli_flag="-d", quote_value=True),
)


def build_useradd_command(
    username: str,
    *,
    uid: int | None,
    group: str | None,
    groups: Sequence[str] | None,
    shell: str | None,
    home: str | None,
    create_home: bool,
    system: bool,
) -> str:
    """Собрать команду ``useradd`` по декларативной таблице спецификаций."""
    cmd_parts = ["useradd"]
    if system:
        cmd_parts.append("-r")
    cmd_parts.append("-m" if create_home else "-M")

    desired_values: dict[str, str | int | None] = {
        "uid": uid,
        "group": group,
        "shell": shell,
        "home": home,
    }
    for spec in _SCALAR_USER_SPECS:
        val = desired_values.get(spec.name)
        if val is not None:
            cmd_parts.extend([spec.cli_flag, spec.format_cli_arg(val)])
            if spec.name == "group" and groups is not None:
                cmd_parts.extend(["-G", shlex.quote(",".join(groups))])

    if group is None and groups is not None:
        cmd_parts.extend(["-G", shlex.quote(",".join(groups))])

    cmd_parts.append(shlex.quote(username))
    return " ".join(cmd_parts)


async def _ensure_user_absent(
    svc: StateManagementService,
    username: str,
    *,
    user_exists: bool,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Обработать ``ensure_user(..., state='absent')``."""
    if not user_exists:
        return EnsureResult(
            target=username,
            state="absent",
            changed=False,
            ok=True,
            details=f"User {username} is already absent",
            dry_run=is_dry_run,
            diff=None,
        )
    diff_str = f"--- a:/etc/passwd ({username})\n+++ /dev/null\n@@ -1 +0,0 @@\n-user={username}\n"
    if is_dry_run:
        return EnsureResult(
            target=username,
            state="absent",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would remove user {username}",
            dry_run=True,
            diff=diff_str,
        )
    del_res = await svc._conn.run(
        f"userdel {shlex.quote(username)}",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    if not del_res.ok:
        return EnsureResult(
            target=username,
            state="absent",
            changed=False,
            ok=False,
            details=del_res.stderr.strip() or f"Failed to remove user {username}",
            dry_run=False,
            diff=diff_str,
        )
    return EnsureResult(
        target=username,
        state="absent",
        changed=True,
        ok=True,
        details=f"Removed user {username}",
        dry_run=False,
        diff=diff_str,
    )


async def _ensure_user_created(
    svc: StateManagementService,
    username: str,
    *,
    uid: int | None,
    group: str | None,
    groups: Sequence[str] | None,
    shell: str | None,
    home: str | None,
    create_home: bool,
    system: bool,
    sudo: bool,
    is_dry_run: bool,
) -> EnsureResult:
    """Создать отсутствующего пользователя через ``useradd``."""
    add_cmd = build_useradd_command(
        username,
        uid=uid,
        group=group,
        groups=groups,
        shell=shell,
        home=home,
        create_home=create_home,
        system=system,
    )
    spec_line = (
        f"+user={username} uid={uid if uid is not None else 'auto'} "
        f"group={group or 'default'} groups={','.join(groups or ())} "
        f"shell={shell or 'default'} home={home or 'default'}\n"
    )
    diff_str = f"--- /dev/null\n+++ b:/etc/passwd ({username})\n@@ -0,0 +1 @@\n{spec_line}"
    if is_dry_run:
        return EnsureResult(
            target=username,
            state="present",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would create user {username}",
            dry_run=True,
            diff=diff_str,
        )
    add_res = await svc._conn.run(add_cmd, sudo=sudo, raise_on_error=False, dry_run=False)
    if not add_res.ok:
        return EnsureResult(
            target=username,
            state="present",
            changed=False,
            ok=False,
            details=add_res.stderr.strip() or f"Failed to create user {username}",
            dry_run=False,
            diff=diff_str,
        )
    return EnsureResult(
        target=username,
        state="present",
        changed=True,
        ok=True,
        details=f"Created user {username}",
        dry_run=False,
        diff=diff_str,
    )


async def ensure_user(
    svc: StateManagementService,
    username: str,
    *,
    state: Literal["present", "absent"] = "present",
    uid: int | None = None,
    group: str | None = None,
    groups: Sequence[str] | None = None,
    shell: str | None = None,
    home: str | None = None,
    create_home: bool = True,
    system: bool = False,
    sudo: bool = True,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять системным пользователем и его группами."""
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run

    if not svc._can_inspect_in_dry_run():
        synth_diff = (
            f"--- a:/etc/passwd ({username})\n+++ b:/etc/passwd ({username})\n"
            f"@@ -0,0 +1 @@\n+user={username} state={state}\n"
        )
        return EnsureResult(
            target=username,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure user {username} is {state}",
            dry_run=True,
            diff=synth_diff,
        )

    pw_res = await svc._conn.run(
        f"getent passwd {shlex.quote(username)}",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    user_exists = pw_res.ok and bool(pw_res.stdout.strip())

    if state == "absent":
        return await _ensure_user_absent(
            svc, username, user_exists=user_exists, sudo=sudo, is_dry_run=is_dry_run
        )

    if not user_exists:
        return await _ensure_user_created(
            svc,
            username,
            uid=uid,
            group=group,
            groups=groups,
            shell=shell,
            home=home,
            create_home=create_home,
            system=system,
            sudo=sudo,
            is_dry_run=is_dry_run,
        )

    pw_fields = pw_res.stdout.strip().splitlines()[0].split(":")
    cur_uid = int(pw_fields[2]) if len(pw_fields) > 2 and pw_fields[2].isdigit() else None
    cur_home = pw_fields[5] if len(pw_fields) > 5 else ""
    cur_shell = pw_fields[6] if len(pw_fields) > 6 else ""

    cur_group = ""
    if group is not None:
        gn_res = await svc._conn.run(
            f"id -gn {shlex.quote(username)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        cur_group = gn_res.stdout.strip() if gn_res.ok else ""

    current_map: dict[str, str | int | None] = {
        "uid": cur_uid,
        "group": cur_group,
        "shell": cur_shell,
        "home": cur_home,
    }
    desired_map: dict[str, str | int | None] = {
        "uid": uid,
        "group": group,
        "shell": shell,
        "home": home,
    }

    mod_flags: list[str] = []
    changes_desc: list[str] = []
    old_tokens: list[str] = []
    new_tokens: list[str] = []

    for spec in _SCALAR_USER_SPECS:
        desired_val = desired_map[spec.name]
        current_val = current_map[spec.name]
        if desired_val is not None and current_val != desired_val:
            mod_flags.extend([spec.cli_flag, spec.format_cli_arg(desired_val)])
            changes_desc.append(f"{spec.name} {current_val} -> {desired_val}")
            old_tokens.append(f"{spec.name}={current_val}")
            new_tokens.append(f"{spec.name}={desired_val}")

        if spec.name == "group" and groups is not None:
            all_g_res = await svc._conn.run(
                f"id -Gn {shlex.quote(username)}",
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
            cur_all_groups = set(all_g_res.stdout.strip().split()) if all_g_res.ok else set()
            if not set(groups).issubset(cur_all_groups):
                joined_groups = ",".join(groups)
                mod_flags.extend(["-G", shlex.quote(joined_groups)])
                changes_desc.append(f"groups -> {joined_groups}")
                old_tokens.append(f"groups={','.join(sorted(cur_all_groups))}")
                new_tokens.append(f"groups={joined_groups}")

    if not mod_flags:
        return EnsureResult(
            target=username,
            state="present",
            changed=False,
            ok=True,
            details=f"User {username} already in desired state",
            dry_run=is_dry_run,
            diff=None,
        )

    diff_str = (
        f"--- a:/etc/passwd ({username})\n+++ b:/etc/passwd ({username})\n"
        f"@@ -1 +1 @@\n-{' '.join(old_tokens)}\n+{' '.join(new_tokens)}\n"
    )
    if is_dry_run:
        return EnsureResult(
            target=username,
            state="present",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would update user {username}: {', '.join(changes_desc)}",
            dry_run=True,
            diff=diff_str,
        )

    mod_res = await svc._conn.run(
        f"usermod {' '.join(mod_flags)} {shlex.quote(username)}",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    if not mod_res.ok:
        return EnsureResult(
            target=username,
            state="present",
            changed=False,
            ok=False,
            details=mod_res.stderr.strip() or f"Failed to modify user {username}",
            dry_run=False,
            diff=diff_str,
        )

    return EnsureResult(
        target=username,
        state="present",
        changed=True,
        ok=True,
        details=f"Updated user {username}: {', '.join(changes_desc)}",
        dry_run=False,
        diff=diff_str,
    )


# ─── Управление SSH-ключами (ensure_authorized_key) ─────────────────


async def resolve_user_home(svc: StateManagementService, user: str, *, sudo: bool = False) -> str:
    """Определить домашнюю директорию пользователя на целевом хосте."""
    pw_res = await svc._conn.run(
        f"getent passwd {shlex.quote(user)}",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    if pw_res.ok and pw_res.stdout.strip():
        fields = pw_res.stdout.strip().splitlines()[0].split(":")
        if len(fields) > 5 and fields[5]:
            return fields[5]
    return "/root" if user == "root" else f"/home/{user}"


def transform_authorized_keys(
    existing_lines: Sequence[str],
    desired_keys: Sequence[str],
    *,
    state: Literal["present", "absent"],
    exclusive: bool,
) -> list[str]:
    """Чистая функция расчёта нового списка строк ``authorized_keys``."""
    if state == "absent":
        remove_set = set(desired_keys)
        return [ln for ln in existing_lines if ln.strip() not in remove_set]
    if exclusive:
        return list(desired_keys)

    new_lines = list(existing_lines)
    existing_stripped = {ln.strip() for ln in existing_lines if ln.strip()}
    for key_line in desired_keys:
        if key_line not in existing_stripped:
            new_lines.append(key_line)
            existing_stripped.add(key_line)
    return new_lines


async def ensure_authorized_key(
    svc: StateManagementService,
    user: str,
    key: str,
    *,
    state: Literal["present", "absent"] = "present",
    exclusive: bool = False,
    sudo: bool = False,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять SSH-ключами в ``~/.ssh/authorized_keys``."""
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run
    clean_key = key.strip()
    if not clean_key:
        raise ValueError("SSH public key cannot be empty")

    if not svc._can_inspect_in_dry_run():
        target_hint = f"~{user}/.ssh/authorized_keys"
        synth_diff = f"--- a:{target_hint}\n+++ b:{target_hint}\n@@ -0,0 +1 @@\n+{clean_key}\n"
        return EnsureResult(
            target=target_hint,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would ensure authorized_key for {user} is {state}",
            dry_run=True,
            diff=synth_diff,
        )

    home_dir = await svc._resolve_user_home(user, sudo=sudo)
    ssh_dir = f"{home_dir.rstrip('/')}/.ssh"
    auth_file = f"{ssh_dir}/authorized_keys"

    file_exists = await svc._conn.exists(auth_file)
    old_text = ""
    if file_exists:
        with contextlib.suppress(Exception):
            raw = await svc._conn.read_file(auth_file, encoding="utf-8")
            old_text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")

    existing_lines = [ln.rstrip("\r") for ln in old_text.splitlines()]
    desired_keys = [ln.strip() for ln in clean_key.splitlines() if ln.strip()]
    new_lines = transform_authorized_keys(
        existing_lines, desired_keys, state=state, exclusive=exclusive
    )
    new_text = ("\n".join(new_lines) + "\n") if new_lines else ""

    if (not file_exists and state == "absent") or (file_exists and old_text == new_text):
        return EnsureResult(
            target=auth_file,
            state=state,
            changed=False,
            ok=True,
            details=f"Authorized key for {user} already {state}",
            dry_run=is_dry_run,
            diff=None,
        )

    u_diff = "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a:{auth_file}" if file_exists else "/dev/null",
            tofile=f"b:{auth_file}",
        )
    )

    if is_dry_run:
        return EnsureResult(
            target=auth_file,
            state=state,
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would update {auth_file} for user {user}",
            dry_run=True,
            diff=u_diff or None,
        )

    dir_res = await svc.ensure_directory(
        ssh_dir,
        state="present",
        mode=0o700,
        owner=user,
        sudo=sudo,
        dry_run=False,
    )
    if not dir_res.ok:
        return EnsureResult(
            target=auth_file,
            state=state,
            changed=False,
            ok=False,
            details=dir_res.details,
            dry_run=False,
            diff=u_diff or None,
        )

    file_res = await svc.ensure_file(
        auth_file,
        state="present",
        content=new_text,
        mode=0o600,
        owner=user,
        atomic=True,
        sudo=sudo,
        dry_run=False,
    )
    return EnsureResult(
        target=auth_file,
        state=state,
        changed=True,
        ok=file_res.ok,
        details=f"Updated {auth_file} for user {user}" if file_res.ok else file_res.details,
        dry_run=False,
        diff=u_diff or file_res.diff,
    )


# ─── Управление systemd-юнитами (ensure_systemd_unit) ───────────────


async def _run_daemon_reload(
    svc: StateManagementService,
    unit_name: str,
    *,
    state: str,
    changed: bool,
    sudo: bool,
    is_dry_run: bool,
    details_parts: list[str],
    diff_parts: list[str],
) -> EnsureResult | None:
    """Выполнить ``systemctl daemon-reload`` (или записать dry-run шаг) без дублирования кода."""
    if is_dry_run:
        details_parts.append("[DRY-RUN] systemctl daemon-reload")
        return None
    rl_res = await svc._conn.run(
        "systemctl daemon-reload",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    if not rl_res.ok:
        return EnsureResult(
            target=unit_name,
            state=state,
            changed=changed,
            ok=False,
            details=rl_res.stderr.strip() or "systemctl daemon-reload failed",
            dry_run=False,
            diff="\n".join(diff_parts) or None,
        )
    details_parts.append("systemctl daemon-reload")
    return None


async def ensure_systemd_unit(
    svc: StateManagementService,
    name: str,
    *,
    content: str | None = None,
    state: Literal["present", "absent", "started", "stopped", "restarted"] = "present",
    enabled: bool | None = None,
    unit_dir: str = "/etc/systemd/system",
    daemon_reload: bool = True,
    sudo: bool = True,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять unit-файлом systemd с вызовом ``daemon-reload`` при изменениях."""
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run
    unit_name = name if "." in name else f"{name}.service"
    unit_path = f"{unit_dir.rstrip('/')}/{unit_name}"

    changed = False
    details_parts: list[str] = []
    diff_parts: list[str] = []

    if state == "absent":
        if enabled is False:
            svc_stop = await svc.ensure_service(
                unit_name,
                state="stopped",
                enabled=False,
                sudo=sudo,
                dry_run=is_dry_run,
            )
            if svc_stop.changed:
                changed = True
                details_parts.append(svc_stop.details)
        file_res = await svc.ensure_file(
            unit_path,
            state="absent",
            sudo=sudo,
            dry_run=is_dry_run,
        )
        if not file_res.ok:
            return file_res
        if file_res.changed:
            changed = True
            details_parts.append(file_res.details)
            if file_res.diff:
                diff_parts.append(file_res.diff)
            if daemon_reload:
                err_res = await _run_daemon_reload(
                    svc,
                    unit_name,
                    state="absent",
                    changed=changed,
                    sudo=sudo,
                    is_dry_run=is_dry_run,
                    details_parts=details_parts,
                    diff_parts=diff_parts,
                )
                if err_res is not None:
                    return err_res
        return EnsureResult(
            target=unit_name,
            state="absent",
            changed=changed,
            ok=True,
            details="; ".join(details_parts) or f"Unit {unit_name} is already absent",
            dry_run=is_dry_run,
            diff="\n".join(p.rstrip("\n") for p in diff_parts) + "\n" if diff_parts else None,
        )

    if content is not None:
        file_res = await svc.ensure_file(
            unit_path,
            state="present",
            content=content,
            mode=0o644,
            atomic=True,
            sudo=sudo,
            dry_run=is_dry_run,
        )
        if not file_res.ok:
            return file_res
        if file_res.changed:
            changed = True
            details_parts.append(file_res.details)
            if file_res.diff:
                diff_parts.append(file_res.diff)
            if daemon_reload:
                err_res = await _run_daemon_reload(
                    svc,
                    unit_name,
                    state=state,
                    changed=changed,
                    sudo=sudo,
                    is_dry_run=is_dry_run,
                    details_parts=details_parts,
                    diff_parts=diff_parts,
                )
                if err_res is not None:
                    return err_res

    if state in ("started", "stopped", "restarted") or enabled is not None:
        svc_state: ServiceState = (
            state if state in ("started", "stopped", "restarted") else "started"
        )
        svc_res = await svc.ensure_service(
            unit_name,
            state=svc_state,
            enabled=enabled,
            sudo=sudo,
            dry_run=is_dry_run,
        )
        if not svc_res.ok:
            return EnsureResult(
                target=unit_name,
                state=state,
                changed=changed or svc_res.changed,
                ok=False,
                details=svc_res.details,
                dry_run=is_dry_run,
                diff="\n".join(diff_parts) or svc_res.diff,
            )
        if svc_res.changed:
            changed = True
            details_parts.append(svc_res.details)
            if svc_res.diff:
                diff_parts.append(svc_res.diff)

    return EnsureResult(
        target=unit_name,
        state=state,
        changed=changed,
        ok=True,
        details="; ".join(details_parts) or f"Unit {unit_name} already in desired state",
        dry_run=is_dry_run,
        diff="\n".join(p.rstrip("\n") for p in diff_parts) + "\n" if diff_parts else None,
    )


# ─── Управление параметрами ядра (ensure_sysctl) ────────────────────


async def ensure_sysctl(
    svc: StateManagementService,
    name: str,
    value: str | int,
    *,
    state: Literal["present", "absent"] = "present",
    config_file: str = "/etc/sysctl.d/99-uniconn.conf",
    reload: bool = True,
    sudo: bool = True,
    dry_run: bool | None = None,
) -> EnsureResult:
    """Идемпотентно управлять параметром ядра ``sysctl`` и применять его на лету."""
    is_dry_run = svc._conn.is_dry_run if dry_run is None else dry_run
    val_str = str(value).strip()
    line_str = f"{name} = {val_str}"
    regex_pat = rf"^\s*{re.escape(name)}\s*="

    if state == "absent":
        line_res = await svc.ensure_line(
            config_file,
            line=line_str,
            regex=regex_pat,
            state="absent",
            create=False,
            dry_run=is_dry_run,
        )
        return EnsureResult(
            target=name,
            state="absent",
            changed=line_res.changed,
            ok=line_res.ok,
            details=line_res.details,
            dry_run=is_dry_run,
            diff=line_res.diff,
        )

    line_res = await svc.ensure_line(
        config_file,
        line=line_str,
        regex=regex_pat,
        state="present",
        create=True,
        dry_run=is_dry_run,
    )
    if not line_res.ok:
        return EnsureResult(
            target=name,
            state="present",
            changed=False,
            ok=False,
            details=line_res.details,
            dry_run=is_dry_run,
            diff=line_res.diff,
        )

    runtime_changed = False
    rt_val: str | None = None
    if reload and svc._can_inspect_in_dry_run():
        rt_res = await svc._conn.run(
            f"sysctl -n {shlex.quote(name)}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if rt_res.ok:
            rt_val = " ".join(rt_res.stdout.strip().split())
            desired_norm = " ".join(val_str.split())
            runtime_changed = rt_val != desired_norm

    changed = line_res.changed or runtime_changed
    diff_str = line_res.diff
    if runtime_changed and not diff_str:
        diff_str = (
            f"--- a:sysctl:{name}\n+++ b:sysctl:{name}\n"
            f"@@ -1 +1 @@\n-{rt_val or '<unset>'}\n+{val_str}\n"
        )

    if not changed:
        return EnsureResult(
            target=name,
            state="present",
            changed=False,
            ok=True,
            details=f"sysctl {name} = {val_str} already in desired state",
            dry_run=is_dry_run,
            diff=None,
        )

    if is_dry_run:
        return EnsureResult(
            target=name,
            state="present",
            changed=True,
            ok=True,
            details=f"[DRY-RUN] Would set sysctl {name} = {val_str}",
            dry_run=True,
            diff=diff_str,
        )

    if reload:
        apply_res = await svc._conn.run(
            f"sysctl -w {shlex.quote(f'{name}={val_str}')}",
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if not apply_res.ok:
            return EnsureResult(
                target=name,
                state="present",
                changed=line_res.changed,
                ok=False,
                details=apply_res.stderr.strip() or f"Failed to apply sysctl {name}={val_str}",
                dry_run=False,
                diff=diff_str,
            )

    return EnsureResult(
        target=name,
        state="present",
        changed=True,
        ok=True,
        details=f"Set sysctl {name} = {val_str}",
        dry_run=False,
        diff=diff_str,
    )
