# src/uniconn/services/provisioning/_plan.py
"""Аккумулятор изменений (ChangePlan) и базовые POSIX/FS-утилиты для идемпотентного провижининга."""

from __future__ import annotations

import difflib
import shlex
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...result import EnsureResult

if TYPE_CHECKING:
    from ...core.connection import Connection


def _parse_mode(mode: int | str | None) -> int | None:
    """Нормализовать права доступа (``int`` вроде ``0o644`` или восьмеричную строку ``'0644'``/``'644'``)."""
    if mode is None:
        return None
    if isinstance(mode, int) and not isinstance(mode, bool):
        return mode & 0o7777
    if isinstance(mode, str):
        cleaned = mode.strip()
        try:
            return int(cleaned, 8) & 0o7777
        except ValueError as exc:
            raise ValueError(f"Invalid octal file mode: {mode!r}") from exc
    raise ValueError(f"Unsupported file mode type: {type(mode).__name__}")


def extract_stat_mode(st: Mapping[str, Any]) -> int:
    """Извлечь числовые права доступа (0o7777) из словаря FileStat."""
    for key in ("mode", "permissions"):
        raw = st.get(key)
        if raw is not None:
            return (int(raw, 0) if isinstance(raw, str) else int(raw)) & 0o7777
    return -1


@dataclass(slots=True)
class ChangePlan:
    """Аккумулятор запланированных действий и unified diff для операций ``ensure_*``.

    Устраняет дублирование списков ``actions``, ``diff_parts``, вычисления ``difflib.unified_diff``
    и формирования ``EnsureResult`` для обычного и ``dry_run`` режимов.
    """

    target: str
    state: str
    is_dry_run: bool
    actions: list[str] = field(default_factory=list)
    diff_parts: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """Вернуть ``True``, если зарегистрировано хотя бы одно изменение."""
        return bool(self.actions)

    @property
    def full_diff(self) -> str | None:
        """Собрать итоговый unified diff из всех накопленных фрагментов."""
        if not self.diff_parts:
            return None
        return "\n".join(part.rstrip("\n") for part in self.diff_parts if part) + "\n"

    def record(self, action: str, diff_entry: str | None = None) -> None:
        """Зарегистрировать выполненное/запланированное действие и опциональный фрагмент diff."""
        self.actions.append(action)
        if diff_entry:
            self.diff_parts.append(diff_entry)

    def add_text_diff(
        self,
        before: str,
        after: str,
        *,
        fromfile: str,
        tofile: str,
        action: str | None = None,
        fallback_diff: str | None = None,
    ) -> None:
        """Вычислить unified diff между двумя текстами и добавить его в план."""
        computed = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=fromfile,
                tofile=tofile,
            )
        )
        diff_entry = computed or fallback_diff
        if action is not None:
            self.record(action, diff_entry)
        elif diff_entry:
            self.diff_parts.append(diff_entry)

    def to_result(
        self,
        *,
        ok: bool = True,
        unchanged_details: str,
        changed_prefix: str,
        dry_run_prefix: str,
    ) -> EnsureResult:
        """Сформировать ``EnsureResult`` на основе накопленных изменений."""
        if not self.changed:
            return EnsureResult(
                target=self.target,
                state=self.state,
                changed=False,
                ok=ok,
                details=unchanged_details,
                dry_run=self.is_dry_run,
                diff=None,
            )
        actions_summary = ", ".join(self.actions)
        if self.is_dry_run:
            return EnsureResult(
                target=self.target,
                state=self.state,
                changed=True,
                ok=ok,
                details=f"{dry_run_prefix}: {actions_summary}",
                dry_run=True,
                diff=self.full_diff,
            )
        return EnsureResult(
            target=self.target,
            state=self.state,
            changed=True,
            ok=ok,
            details=f"{changed_prefix}: {actions_summary}",
            dry_run=False,
            diff=self.full_diff,
        )


def can_inspect_in_dry_run(conn: Connection) -> bool:
    """Проверить, можно ли безопасно выполнить read-only чтение с хоста при dry_run."""
    if not conn.dry_run:
        return True
    return conn.transport.is_connected or conn.transport_name in ("local", "replay")


async def get_owner_group(
    conn: Connection,
    path_str: str,
    *,
    sudo: bool = False,
    is_link: bool = False,
) -> tuple[str | None, str | None]:
    """Получить текущие имя владельца и группы файла или директории."""
    if conn.transport_name == "local":
        if sys.platform == "win32":
            return None, None
        if not sudo:
            eff_path = Path(conn.context.resolve_path(path_str))
            try:
                import grp
                import pwd

                st = eff_path.lstat() if is_link else eff_path.stat()
                return pwd.getpwuid(st.st_uid).pw_name, grp.getgrgid(st.st_gid).gr_name
            except Exception:
                return None, None

    deref_flag = "" if is_link else "-L "
    res = await conn.run(
        f"stat {deref_flag}-c '%U:%G' {shlex.quote(path_str)}",
        sudo=sudo,
        raise_on_error=False,
        dry_run=False,
    )
    if res.ok and ":" in res.text:
        u_str, g_str = res.text.split(":", 1)
        return u_str.strip(), g_str.strip()
    return None, None


async def apply_owner_group(
    conn: Connection,
    path_str: str,
    *,
    owner: str | None,
    group: str | None,
    recurse: bool = False,
    is_link: bool = False,
    sudo: bool = False,
) -> None:
    """Применить владельца и/или группу к пути."""
    if owner is None and group is None:
        return
    if conn.transport_name == "local":
        if sys.platform == "win32":
            return
        if not sudo and not recurse and not is_link:
            eff_path = Path(conn.context.resolve_path(path_str))
            shutil.chown(eff_path, user=owner, group=group)  # type: ignore[arg-type]
            return

    flags: list[str] = []
    if is_link:
        flags.append("-h")
    if recurse:
        flags.append("-R")
    flag_str = (" ".join(flags) + " ") if flags else ""
    if owner is not None and group is not None:
        cmd = f"chown {flag_str}{shlex.quote(f'{owner}:{group}')} {shlex.quote(path_str)}"
    elif owner is not None:
        cmd = f"chown {flag_str}{shlex.quote(owner)} {shlex.quote(path_str)}"
    else:
        assert group is not None
        cmd = f"chgrp {flag_str}{shlex.quote(group)} {shlex.quote(path_str)}"
    await conn.run(cmd, sudo=sudo, raise_on_error=True, dry_run=False)

