# src/uniconn/services/_dir_sync.py
"""Инкрементальная синхронизация дерева директорий и расчёт контрольных сумм."""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import logging
import os
import re
import shlex
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import CapabilityNotSupportedError, ExecutionError, FileTransferError
from ..result import SyncResult
from ..transports.base import FileStat

if TYPE_CHECKING:
    from ..core.connection import Connection

_logger = logging.getLogger("uniconn.services.files")

STREAM_UPLOAD_THRESHOLD = 4 * 1024 * 1024  # 4 МБ
ChecksumAlgorithm = Literal["sha256", "sha1", "md5"]
_SUPPORTED_CHECKSUMS: frozenset[str] = frozenset(("sha256", "sha1", "md5"))
_CHECKSUM_HEX_LENGTHS: dict[str, int] = {
    "sha256": 64,
    "sha1": 40,
    "md5": 32,
}


def _build_checksum_command(
    path: str,
    algo: ChecksumAlgorithm = "sha256",
    os_family: str | None = None,
) -> str:
    """Построить кроссплатформенную команду расчёта хеша (Linux/macOS/BSD/OpenSSL/Windows)."""
    q_path = shlex.quote(path)
    if os_family and os_family.lower() == "windows":
        win_algo = algo.upper()
        ps_q = "'" + path.replace("'", "''") + "'"
        return f"certutil -hashfile {ps_q} {win_algo}"

    if algo == "sha256":
        return (
            f"if command -v sha256sum >/dev/null 2>&1; then sha256sum {q_path}; "
            f"elif command -v shasum >/dev/null 2>&1; then shasum -a 256 {q_path}; "
            f"elif command -v sha256 >/dev/null 2>&1; then sha256 -q {q_path}; "
            f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r {q_path}; "
            f"else certutil -hashfile {q_path} SHA256; fi"
        )
    if algo == "sha1":
        return (
            f"if command -v sha1sum >/dev/null 2>&1; then sha1sum {q_path}; "
            f"elif command -v shasum >/dev/null 2>&1; then shasum -a 1 {q_path}; "
            f"elif command -v sha1 >/dev/null 2>&1; then sha1 -q {q_path}; "
            f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha1 -r {q_path}; "
            f"else certutil -hashfile {q_path} SHA1; fi"
        )
    return (
        f"if command -v md5sum >/dev/null 2>&1; then md5sum {q_path}; "
        f"elif command -v md5 >/dev/null 2>&1; then md5 -q {q_path}; "
        f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -md5 -r {q_path}; "
        f"else certutil -hashfile {q_path} MD5; fi"
    )


def _extract_checksum_digest(stdout: str, algo: ChecksumAlgorithm = "sha256") -> str | None:
    """Извлечь hex-дайджест из вывода GNU coreutils, shasum, BSD md5/sha256, openssl или certutil."""
    expected_len = _CHECKSUM_HEX_LENGTHS.get(algo, 64)
    hex_re = re.compile(rf"\b([0-9a-fA-F]{{{expected_len}}})\b")
    for line in stdout.strip().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = hex_re.search(stripped)
        if match:
            return match.group(1).lower()
        compact = re.sub(r"\s+", "", stripped)
        if len(compact) == expected_len and all(c in "0123456789abcdefABCDEF" for c in compact):
            return compact.lower()
    return None


def _local_file_digest(path: str | Path, algorithm: ChecksumAlgorithm = "sha256") -> str:
    """Потоково вычислить контрольную сумму локального файла."""
    if algorithm not in _SUPPORTED_CHECKSUMS:
        raise ValueError(f"Unsupported checksum algorithm: {algorithm!r}")
    hasher = hashlib.new(algorithm)
    with Path(path).open("rb") as fp:
        while chunk := fp.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _is_permission_error(exc: BaseException) -> bool:
    """Определить, вызвана ли ошибка отсутствием прав доступа (включая вложенную цепочку)."""
    cur: BaseException | None = exc
    seen: set[int] = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, PermissionError):
            return True
        if "PermissionDenied" in type(cur).__name__:
            return True
        msg = str(cur).lower()
        stderr = str(getattr(cur, "stderr", "") or "").lower()
        combined = f"{msg}\n{stderr}"
        if "permission denied" in combined or "operation not permitted" in combined:
            return True
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return False


def _compile_exclude_regex(patterns: Sequence[str]) -> re.Pattern[str] | None:
    """Скомпилировать список glob-паттернов в единое регулярное выражение (O(1) поиск)."""
    if not patterns:
        return None
    translated: list[str] = []
    for pat in patterns:
        if not pat:
            continue
        regex_str = fnmatch.translate(pat)
        translated.append(f"(?:{regex_str})")
    if not translated:
        return None
    return re.compile("|".join(translated))


def _join_sync_path(base: str, rel: str) -> str:
    """Соединить базовый путь и относительный сегмент с учётом стиля разделителей (POSIX/Windows)."""
    if not rel:
        return base
    if "\\" in base or (len(base) >= 2 and base[1] == ":"):
        clean_b = base.rstrip("\\/")
        clean_r = rel.lstrip("\\/").replace("/", "\\")
        return f"{clean_b}\\{clean_r}"
    return f"{base.rstrip('/')}/{rel.lstrip('/')}"


class DirectorySynchronizer:
    """Алгоритм инкрементальной синхронизации локального дерева директорий с удалённым хостом."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать синхронизатор директорий."""
        self._conn = conn

    _compile_exclude_regex = staticmethod(_compile_exclude_regex)

    @staticmethod
    def is_excluded(
        rel_posix: str,
        name: str,
        patterns: Sequence[str],
        compiled_re: re.Pattern[str] | None = None,
    ) -> bool:
        """Проверить, подпадает ли относительный путь или имя файла под glob-исключения."""
        if not patterns:
            return False
        regex = compiled_re or _compile_exclude_regex(patterns)
        if regex is None:
            return False
        if regex.match(name) or regex.match(rel_posix):
            return True
        return any(regex.match(part) for part in rel_posix.split("/"))

    async def _try_batch_inspect_remote(
        self,
        effective_remote: str,
        rel_dirs: Sequence[str],
        *,
        is_dry: bool,
        checksum_check: bool,
        exclude: Sequence[str] = (),
    ) -> dict[str, Any] | None:
        """Попытаться выполнить пакетное создание директорий и сканирование дерева за 1 RPC-запрос."""
        worker = getattr(self._conn, "_python_worker", None)
        if worker is None:
            return None
        use_worker = worker.is_active or (
            self._conn.transport_name != "local" and worker.can_auto_accelerate()
        )
        if not use_worker:
            return None
        try:
            res = await worker.request(
                "sync_scan",
                allow_oneshot_fallback=(self._conn.transport_name != "local"),
                path=effective_remote,
                mkdirs=[] if is_dry else list(rel_dirs),
                checksum=checksum_check,
                exclude=list(exclude),
                scan=True,
            )
            if isinstance(res, dict) and "entries" in res:
                return res
        except (OSError, ExecutionError, CapabilityNotSupportedError, TimeoutError) as exc:
            _logger.debug(
                "Batch remote sync_scan fallback to transport stat/mkdir: %s", exc
            )
        return None

    async def _needs_file_upload(
        self,
        full_local: Path,
        l_size: int,
        l_mtime: float,
        rel_path: str,
        target_file: str,
        *,
        checksum_check: bool,
        mtime_tolerance: float,
        batch_entries: dict[str, dict[str, Any]] | None,
        can_inspect_remote: bool,
    ) -> tuple[bool, FileStat | dict[str, Any]]:
        """Определить необходимость загрузки файла и вернуть метаданные удалённого файла."""
        r_stat: FileStat | dict[str, Any] = {}
        r_hash: str | None = None

        if batch_entries is not None:
            entry_info = batch_entries.get(rel_path)
            if not isinstance(entry_info, dict) or entry_info.get("is_dir"):
                return True, r_stat
            r_stat = entry_info
            raw_hash = r_stat.get("sha256")
            if isinstance(raw_hash, str) and raw_hash:
                r_hash = raw_hash
        elif can_inspect_remote:
            transport = self._conn.transport
            try:
                if not await transport.exists(target_file):
                    return True, r_stat
                r_stat = await transport.stat(target_file)
            except (OSError, ExecutionError):
                return True, r_stat
        else:
            return True, r_stat

        r_size = int(r_stat.get("size", -1))
        if r_size != l_size:
            return True, r_stat

        if checksum_check:
            l_hash = _local_file_digest(full_local, "sha256")
            if r_hash is None:
                r_hash = await self._conn.files.checksum(target_file, "sha256")
            return (l_hash != r_hash), r_stat

        r_mtime = float(r_stat.get("mtime") or 0.0)
        if r_mtime > 0 and (r_mtime + mtime_tolerance) >= l_mtime:
            return False, r_stat
        return True, r_stat

    def _scan_local_tree(
        self,
        src_root: Path,
        patterns: list[str],
        compiled_exclude: re.Pattern[str] | None,
    ) -> tuple[dict[str, tuple[Path, int, float, int]], set[str]]:
        local_files: dict[str, tuple[Path, int, float, int]] = {}
        local_rel_dirs: set[str] = {""}
        for root, dirs, files in os.walk(src_root):
            rel_dir_path = Path(root).relative_to(src_root)
            rel_dir = "" if str(rel_dir_path) == "." else rel_dir_path.as_posix()

            kept_dirs: list[str] = []
            for d in dirs:
                d_rel = f"{rel_dir}/{d}" if rel_dir else d
                if not self.is_excluded(d_rel, d, patterns, compiled_exclude):
                    kept_dirs.append(d)
                    local_rel_dirs.add(d_rel)
            dirs[:] = kept_dirs

            for fname in files:
                f_rel = f"{rel_dir}/{fname}" if rel_dir else fname
                if self.is_excluded(f_rel, fname, patterns, compiled_exclude):
                    continue
                full_local = Path(root) / fname
                st = full_local.stat()
                local_files[f_rel] = (
                    full_local,
                    int(st.st_size),
                    float(st.st_mtime),
                    int(st.st_mode) & 0o777,
                )
        return local_files, local_rel_dirs

    async def _delete_stale_from_batch(
        self,
        effective_remote: str,
        batch_entries: dict[str, dict[str, Any]],
        local_files: dict[str, tuple[Path, int, float, int]],
        local_rel_dirs: set[str],
        patterns: list[str],
        compiled_exclude: re.Pattern[str] | None,
        *,
        is_dry: bool,
    ) -> list[str]:
        deleted: list[str] = []
        stale_rels: list[str] = []
        stale_dirs: list[str] = []
        for entry_rel, info in sorted(batch_entries.items()):
            entry_name = entry_rel.rsplit("/", 1)[-1]
            if self.is_excluded(entry_rel, entry_name, patterns, compiled_exclude):
                continue
            if info.get("is_dir"):
                if entry_rel not in local_rel_dirs:
                    stale_dirs.append(entry_rel)
                continue
            if entry_rel not in local_files:
                stale_rels.append(entry_rel)

        transport = self._conn.transport
        if stale_rels:
            if not is_dry:
                worker = getattr(self._conn, "_python_worker", None)
                batch_del_ok = False
                if worker is not None:
                    try:
                        await worker.request(
                            "sync_scan",
                            allow_oneshot_fallback=(self._conn.transport_name != "local"),
                            path=effective_remote,
                            delete_paths=stale_rels,
                            scan=False,
                        )
                        batch_del_ok = True
                    except (OSError, ExecutionError, CapabilityNotSupportedError, TimeoutError) as exc:
                        _logger.debug(
                            "Batch delete fallback to transport remove_file: %s", exc
                        )
                if not batch_del_ok:
                    for rel_del in stale_rels:
                        await transport.remove_file(_join_sync_path(effective_remote, rel_del))
            deleted.extend(stale_rels)

        if stale_dirs and not is_dry:
            for rel_d in sorted(stale_dirs, key=lambda p: p.count("/"), reverse=True):
                try:
                    await self._conn.files.path(_join_sync_path(effective_remote, rel_d)).rmdir()
                except (OSError, ExecutionError, FileTransferError, CapabilityNotSupportedError) as exc:
                    _logger.debug("Skipping stale dir rmdir %r: %s", rel_d, exc)
        return deleted

    async def _delete_stale_via_walk(
        self,
        effective_remote: str,
        local_files: dict[str, tuple[Path, int, float, int]],
        local_rel_dirs: set[str],
        patterns: list[str],
        compiled_exclude: re.Pattern[str] | None,
        *,
        is_dry: bool,
    ) -> list[str]:
        deleted: list[str] = []
        transport = self._conn.transport

        async def _walk_remote(rel_prefix: str) -> None:
            cur_remote = _join_sync_path(effective_remote, rel_prefix)
            try:
                entries = await transport.listdir(cur_remote)
            except (OSError, ExecutionError):
                return

            for entry in entries:
                if entry in (".", ".."):
                    continue
                entry_rel = f"{rel_prefix}/{entry}" if rel_prefix else entry
                if self.is_excluded(entry_rel, entry, patterns, compiled_exclude):
                    continue
                entry_full = _join_sync_path(effective_remote, entry_rel)
                try:
                    info = await transport.stat(entry_full)
                except (OSError, ExecutionError):
                    continue
                if info.get("is_symlink"):
                    if entry_rel not in local_files:
                        if not is_dry:
                            await transport.remove_file(entry_full)
                        deleted.append(entry_rel)
                elif info.get("is_dir"):
                    await _walk_remote(entry_rel)
                    if entry_rel not in local_rel_dirs and not is_dry:
                        try:
                            await self._conn.files.path(entry_full).rmdir()
                        except (OSError, ExecutionError, FileTransferError, CapabilityNotSupportedError) as exc:
                            _logger.debug("Skipping stale dir rmdir %r: %s", entry_full, exc)
                elif entry_rel not in local_files:
                    if not is_dry:
                        await transport.remove_file(entry_full)
                    deleted.append(entry_rel)

        if await transport.exists(effective_remote):
            await _walk_remote("")
        return deleted

    async def sync(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
        *,
        checksum_check: bool = False,
        preserve_permissions: bool = False,
    ) -> SyncResult:
        """Выполнить инкрементальную синхронизацию ``local_dir -> remote_dir``."""
        start_time = time.monotonic()
        is_dry = self._conn.dry_run if dry_run is None else dry_run
        patterns = list(exclude or [])
        compiled_exclude = _compile_exclude_regex(patterns)

        src_root = Path(local_dir)
        if not src_root.is_dir():
            raise FileNotFoundError(f"Local directory does not exist: {local_dir}")

        transport = self._conn.transport
        if not transport.is_connected and not is_dry:
            await transport.connect()

        effective_remote = self._conn.context.resolve_path(remote_dir)
        local_files, local_rel_dirs = self._scan_local_tree(src_root, patterns, compiled_exclude)

        uploaded: list[str] = []
        skipped: list[str] = []
        deleted: list[str] = []
        bytes_transferred = 0

        sorted_rel_dirs = sorted(local_rel_dirs)
        can_inspect_remote = not is_dry or transport.is_connected
        batch_manifest: dict[str, Any] | None = None
        if can_inspect_remote:
            batch_manifest = await self._try_batch_inspect_remote(
                effective_remote,
                sorted_rel_dirs,
                is_dry=is_dry,
                checksum_check=checksum_check,
                exclude=patterns,
            )

        if not is_dry and batch_manifest is None:
            for rel_d in sorted_rel_dirs:
                target_d = _join_sync_path(effective_remote, rel_d)
                await transport.mkdir(target_d, parents=True, exist_ok=True)

        batch_entries: dict[str, dict[str, Any]] | None = (
            batch_manifest.get("entries") if isinstance(batch_manifest, dict) else None
        )

        for rel_path, (full_local, l_size, l_mtime, mode) in sorted(local_files.items()):
            target_file = _join_sync_path(effective_remote, rel_path)
            needs_upload, r_stat = await self._needs_file_upload(
                full_local,
                l_size,
                l_mtime,
                rel_path,
                target_file,
                checksum_check=checksum_check,
                mtime_tolerance=mtime_tolerance,
                batch_entries=batch_entries,
                can_inspect_remote=can_inspect_remote,
            )

            if needs_upload:
                if not is_dry:
                    if l_size > STREAM_UPLOAD_THRESHOLD:
                        await transport.upload(str(full_local), target_file)
                        with contextlib.suppress(OSError, ExecutionError):
                            await transport.chmod(target_file, mode)
                    else:
                        data = full_local.read_bytes()
                        await transport.write_file(target_file, data, mode=mode)
                uploaded.append(rel_path)
                bytes_transferred += l_size
            else:
                if preserve_permissions and not is_dry:
                    r_perms_raw = r_stat.get("permissions")
                    raw_mode = r_stat.get("mode")
                    r_mode: int | None = None
                    if isinstance(r_perms_raw, str):
                        with contextlib.suppress(ValueError):
                            r_mode = int(r_perms_raw, 8) & 0o777
                    elif isinstance(raw_mode, int):
                        r_mode = raw_mode & 0o777
                    if r_mode != mode:
                        with contextlib.suppress(OSError, ExecutionError):
                            await transport.chmod(target_file, mode)
                skipped.append(rel_path)

        if delete and (not is_dry or transport.is_connected):
            if batch_entries is not None:
                deleted = await self._delete_stale_from_batch(
                    effective_remote,
                    batch_entries,
                    local_files,
                    local_rel_dirs,
                    patterns,
                    compiled_exclude,
                    is_dry=is_dry,
                )
            else:
                deleted = await self._delete_stale_via_walk(
                    effective_remote,
                    local_files,
                    local_rel_dirs,
                    patterns,
                    compiled_exclude,
                    is_dry=is_dry,
                )

        duration = time.monotonic() - start_time
        return SyncResult(
            uploaded=uploaded,
            skipped=skipped,
            deleted=deleted,
            bytes_transferred=bytes_transferred,
            duration=duration,
            dry_run=is_dry,
        )
