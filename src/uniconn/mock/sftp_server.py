# src/uniconn/mock/sftp_server.py
"""Mock SFTP-сервер поверх кассет Replay с сессионным in-memory оверлеем записи."""

from __future__ import annotations

import errno
import os
import posixpath
import stat as stat_module
import time
from typing import Any

import asyncssh

from ..transports.replay.models import Cassette, RecordedFsInteraction
from .config import CassetteInteractionMatcher, MockServerConfig

_FXF_WRITE = 0x00000002
_FXF_APPEND = 0x00000004
_FXF_CREAT = 0x00000008
_FXF_TRUNC = 0x00000010


def _decode_sftp_path(path: bytes | str) -> str:
    """Преобразовать путь SFTP (``bytes`` или ``str``) в строку UTF-8."""
    if isinstance(path, bytes):
        return path.decode("utf-8", errors="replace")
    return str(path)


class MockSFTPFile:
    """Виртуальный файловый дескриптор в памяти для чтения и записи по SFTP."""

    def __init__(
        self,
        path: str,
        initial_bytes: bytes = b"",
        *,
        matcher: CassetteInteractionMatcher | None = None,
        writable: bool = False,
        append: bool = False,
        mode: int = 0o644,
    ) -> None:
        """Инициализировать файловый буфер."""
        self.path = path
        self._buffer = bytearray(initial_bytes)
        self._matcher = matcher
        self._writable = writable
        self._append = append
        self.mode = mode
        self._pos = len(self._buffer) if append else 0
        self.closed = False

    @property
    def content(self) -> bytes:
        """Текущее байтовое содержимое файла."""
        return bytes(self._buffer)

    def seek(self, offset: int, whence: int = 0) -> int:
        """Переместить указатель чтения/записи (включая ``SEEK_DATA`` и ``SEEK_HOLE`` для ``asyncssh``)."""
        seek_data = getattr(os, "SEEK_DATA", 3)
        seek_hole = getattr(os, "SEEK_HOLE", 4)
        if whence == os.SEEK_SET:
            self._pos = max(0, offset)
        elif whence == os.SEEK_CUR:
            self._pos = max(0, self._pos + offset)
        elif whence == os.SEEK_END:
            self._pos = max(0, len(self._buffer) + offset)
        elif whence == seek_data:
            if offset >= len(self._buffer):
                raise OSError(errno.ENXIO, "No such device or address")
            self._pos = max(0, offset)
        elif whence == seek_hole:
            if offset >= len(self._buffer):
                raise OSError(errno.ENXIO, "No such device or address")
            self._pos = len(self._buffer)
        else:
            raise OSError(errno.EINVAL, f"Invalid whence: {whence}")
        return self._pos

    def read(self, size: int = -1, offset: int | None = None) -> bytes:
        """Прочитать срез байтов из виртуального файла."""
        if offset is not None:
            self._pos = max(0, offset)
        if self._pos >= len(self._buffer):
            return b""
        end = len(self._buffer) if size < 0 else min(len(self._buffer), self._pos + size)
        chunk = bytes(self._buffer[self._pos : end])
        self._pos = end
        return chunk

    def write(self, data: bytes | str, offset: int | None = None) -> int:
        """Записать байты в буфер файла и синхронизировать с сессионным оверлеем."""
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        pos = len(self._buffer) if self._append else (self._pos if offset is None else max(0, offset))
        if pos > len(self._buffer):
            self._buffer.extend(b"\x00" * (pos - len(self._buffer)))
        end = pos + len(raw)
        self._buffer[pos:end] = raw
        self._pos = end
        self._sync_to_overlay()
        return len(raw)

    def _sync_to_overlay(self) -> None:
        if self._matcher is not None and self._writable:
            norm = self._matcher.normalize_path(self.path)
            self._matcher.overlay_files[norm] = bytes(self._buffer)
            self._matcher.overlay_modes.setdefault(norm, self.mode)
            self._matcher.deleted_paths.discard(norm)
            parent = posixpath.dirname(norm)
            while parent and parent not in self._matcher.overlay_dirs:
                self._matcher.overlay_dirs.add(parent)
                nxt = posixpath.dirname(parent)
                if nxt == parent:
                    break
                parent = nxt

    def close(self) -> None:
        """Закрыть виртуальный файл и зафиксировать записанные данные в оверлее."""
        if not self.closed:
            self._sync_to_overlay()
            self.closed = True


class MockSFTPServer(asyncssh.SFTPServer):
    """Подсистема SFTP для ``MockSSHServer``, воспроизводящая ``RecordedFsInteraction`` из кассеты."""

    def __init__(
        self,
        chan: asyncssh.SSHServerChannel[Any],
        cassette: Cassette,
        *,
        matcher: CassetteInteractionMatcher | None = None,
        config: MockServerConfig | None = None,
    ) -> None:
        """Инициализировать Mock SFTP сервер для открытого канала."""
        super().__init__(chan)
        self.cassette = cassette
        effective_cfg = config or MockServerConfig(cassette=cassette)
        self.matcher = matcher or CassetteInteractionMatcher(effective_cfg, cassette)

    def _build_attrs(self, size: int, permissions: int) -> asyncssh.SFTPAttrs:
        now = int(time.time())
        return asyncssh.SFTPAttrs(
            size=size,
            uid=0,
            gid=0,
            permissions=permissions,
            atime=now,
            mtime=now,
        )

    def realpath(self, path: bytes) -> bytes:
        """Канонизировать путь SFTP."""
        decoded = _decode_sftp_path(path)
        if not decoded or decoded == ".":
            return b"/"
        norm = posixpath.normpath(decoded)
        if not norm.startswith("/"):
            norm = "/" + norm
        return norm.encode("utf-8")

    def stat(self, path: bytes | str) -> asyncssh.SFTPAttrs:
        """Вернуть ``SFTPAttrs`` файла или директории из оверлея или кассеты."""
        str_path = _decode_sftp_path(path)
        info = self.matcher.resolve_sftp_stat(str_path)
        if info is None:
            self.matcher.record_event("sftp", f"stat {str_path}", matched=False)
            raise asyncssh.SFTPNoSuchFile(f"No such file in cassette: {str_path}")
        self.matcher.record_event("sftp", f"stat {str_path}", matched=True, exit_code=0)
        return self._build_attrs(info["size"], info["permissions"])

    def lstat(self, path: bytes | str) -> asyncssh.SFTPAttrs:
        """Вернуть ``SFTPAttrs`` без разыменования симлинков."""
        return self.stat(path)

    def fstat(self, file_obj: Any) -> asyncssh.SFTPAttrs:
        """Вернуть ``SFTPAttrs`` для открытого ``MockSFTPFile``."""
        if isinstance(file_obj, MockSFTPFile):
            perms = file_obj.mode
            if not stat_module.S_IFMT(perms):
                perms |= stat_module.S_IFREG
            return self._build_attrs(len(file_obj.content), perms)
        raise asyncssh.SFTPFailure("Invalid file handle")

    def setstat(self, path: bytes | str, attrs: asyncssh.SFTPAttrs) -> None:
        """Обновить атрибуты (права доступа) файла со сверкой по кассете."""
        str_path = _decode_sftp_path(path)
        norm_path = self.matcher.normalize_path(str_path)
        matched_chmod = self.matcher.match_fs(("chmod",), norm_path, consume=True)
        if matched_chmod is None:
            matched_chmod = self.matcher.match_fs(
                ("write_file", "upload", "mkdir"),
                norm_path,
                consume=False,
            )
        if (
            matched_chmod is None
            and norm_path not in self.matcher.overlay_files
            and self.matcher.config.strict_mode
        ):
            self.matcher.record_event("sftp", f"chmod {str_path}", matched=False)
            raise asyncssh.SFTPPermissionDenied(
                f"chmod not permitted by cassette in strict mode: {str_path}"
            )
        if matched_chmod is not None and matched_chmod.error_class:
            self.matcher.record_event("sftp", f"chmod {str_path}", matched=True, exit_code=1)
            raise asyncssh.SFTPPermissionDenied(
                matched_chmod.error_message or matched_chmod.error_class
            )

        if attrs.permissions is not None:
            self.matcher.overlay_modes[norm_path] = int(attrs.permissions)
        self.matcher.record_event("sftp", f"chmod {str_path}", matched=True, exit_code=0)

    def fsetstat(self, file_obj: Any, attrs: asyncssh.SFTPAttrs) -> None:
        """Обновить атрибуты открытого дескриптора ``MockSFTPFile``."""
        if isinstance(file_obj, MockSFTPFile):
            if attrs.permissions is not None:
                file_obj.mode = int(attrs.permissions)
            self.setstat(file_obj.path, attrs)

    def open(
        self,
        path: bytes | str,
        pflags: int,
        attrs: asyncssh.SFTPAttrs,
    ) -> MockSFTPFile:
        """Открыть файл для чтения или записи со сверкой по кассете и поддержкой сессионного оверлея."""
        str_path = _decode_sftp_path(path)
        norm_path = self.matcher.normalize_path(str_path)
        write_mask = (
            _FXF_WRITE
            | _FXF_CREAT
            | _FXF_TRUNC
            | _FXF_APPEND
        )
        is_write = bool(pflags & write_mask)
        is_append = bool(pflags & _FXF_APPEND)
        is_trunc = bool(pflags & _FXF_TRUNC)

        if is_write:
            matched_write = self.matcher.match_fs(("write_file", "upload"), norm_path)
            if matched_write is None and self.matcher.config.strict_mode:
                self.matcher.record_event("sftp", f"write {str_path}", matched=False)
                raise asyncssh.SFTPPermissionDenied(
                    f"Write operation not found in cassette (strict mode): {str_path}"
                )
            if matched_write is not None and matched_write.error_class:
                self.matcher.record_event("sftp", f"write {str_path}", matched=True, exit_code=1)
                raise asyncssh.SFTPPermissionDenied(
                    matched_write.error_message or matched_write.error_class
                )

            existing_bytes = (
                b""
                if is_trunc
                else self.matcher.overlay_files.get(norm_path, b"")
            )
            mode = (
                int(attrs.permissions)
                if attrs.permissions is not None
                else (matched_write.mode if matched_write and matched_write.mode else 0o644)
            )
            f_obj = MockSFTPFile(
                norm_path,
                existing_bytes,
                matcher=self.matcher,
                writable=True,
                append=is_append,
                mode=mode,
            )
            f_obj._sync_to_overlay()
            self.matcher.record_event("sftp", f"open(write) {str_path}", matched=True, exit_code=0)
            return f_obj

        # Режим чтения
        if norm_path in self.matcher.deleted_paths:
            self.matcher.record_event("sftp", f"open(read) {str_path}", matched=False)
            raise asyncssh.SFTPNoSuchFile(f"File was deleted in session: {str_path}")

        if norm_path in self.matcher.overlay_files:
            self.matcher.record_event("sftp", f"open(read) {str_path}", matched=True, exit_code=0)
            return MockSFTPFile(
                norm_path,
                self.matcher.overlay_files[norm_path],
                matcher=self.matcher,
                writable=False,
                mode=self.matcher.overlay_modes.get(norm_path, 0o644),
            )

        matched_read = self.matcher.match_fs(
            ("read_file", "download", "write_file", "upload"),
            norm_path,
        )
        if matched_read is None:
            self.matcher.record_event("sftp", f"open(read) {str_path}", matched=False)
            raise asyncssh.SFTPNoSuchFile(f"File not found in cassette: {str_path}")

        if matched_read.error_class:
            self.matcher.record_event("sftp", f"open(read) {str_path}", matched=True, exit_code=1)
            raise asyncssh.SFTPNoSuchFile(
                matched_read.error_message or matched_read.error_class
            )

        content = self.matcher.extract_fs_bytes(matched_read)
        self.matcher.record_event("sftp", f"open(read) {str_path}", matched=True, exit_code=0)
        return MockSFTPFile(
            norm_path,
            content,
            matcher=self.matcher,
            writable=False,
            mode=matched_read.mode or 0o644,
        )

    def read(self, file_obj: Any, offset: int, size: int) -> bytes:
        """Прочитать блок данных из ``MockSFTPFile`` по смещению."""
        if isinstance(file_obj, MockSFTPFile):
            return file_obj.read(size, offset=offset)
        raise asyncssh.SFTPFailure("Invalid file handle")

    def write(self, file_obj: Any, offset: int, data: bytes) -> int:
        """Записать блок данных в ``MockSFTPFile`` по смещению."""
        if isinstance(file_obj, MockSFTPFile):
            return file_obj.write(data, offset=offset)
        raise asyncssh.SFTPFailure("Invalid file handle")

    def close(self, file_obj: Any) -> None:
        """Закрыть дескриптор ``MockSFTPFile``."""
        if isinstance(file_obj, MockSFTPFile):
            file_obj.close()

    def listdir(self, path: bytes | str) -> list[Any]:
        """Вернуть список элементов директории из кассеты и сессионного оверлея.

        Если ``path`` передан как ``bytes`` (внутренний вызов протокола ``asyncssh``),
        возвращает ``list[bytes]``. Если ``path`` передан как ``str`` (прямой вызов в тестах),
        возвращает ``list[asyncssh.SFTPName]``.
        """
        str_path = _decode_sftp_path(path)
        norm_dir = self.matcher.normalize_path(str_path)
        names: list[str] = []

        matched = self.matcher.match_fs(("listdir",), norm_dir)
        if matched is not None:
            if matched.error_class:
                self.matcher.record_event("sftp", f"listdir {str_path}", matched=True, exit_code=1)
                raise asyncssh.SFTPNoSuchFile(matched.error_message or matched.error_class)
            for entry in matched.result_list:
                full = posixpath.normpath(posixpath.join(norm_dir, entry))
                if full not in self.matcher.deleted_paths and entry not in names:
                    names.append(entry)

        # Добавить файлы, записанные в сессионный оверлей внутри этой директории
        for ov_path in sorted(self.matcher.overlay_files):
            if ov_path in self.matcher.deleted_paths:
                continue
            if posixpath.dirname(ov_path) == norm_dir:
                base = posixpath.basename(ov_path)
                if base and base not in names:
                    names.append(base)

        # Также подтянуть файлы из кассеты, лежащие в этой директории
        for item in self.cassette.interactions:
            if isinstance(item, RecordedFsInteraction) and item.operation in (
                "read_file",
                "download",
                "write_file",
                "upload",
            ):
                item_norm = self.matcher.normalize_path(item.path)
                if item_norm not in self.matcher.deleted_paths and posixpath.dirname(item_norm) == norm_dir:
                    base = posixpath.basename(item_norm)
                    if base and base not in names:
                        names.append(base)

        if (
            matched is None
            and not names
            and norm_dir not in self.matcher.overlay_dirs
            and self.matcher.config.strict_mode
        ):
            self.matcher.record_event("sftp", f"listdir {str_path}", matched=False)
            raise asyncssh.SFTPNoSuchFile(f"Directory not found in cassette: {str_path}")

        self.matcher.record_event(
            "sftp",
            f"listdir {str_path}",
            matched=bool(matched is not None or names or norm_dir in self.matcher.overlay_dirs),
            exit_code=0,
        )
        if isinstance(path, bytes):
            return [name.encode("utf-8") for name in names]
        return [asyncssh.SFTPName(name) for name in names]

    def mkdir(self, path: bytes | str, attrs: asyncssh.SFTPAttrs) -> None:
        """Создать директорию в сессионном оверлее со сверкой по кассете."""
        str_path = _decode_sftp_path(path)
        norm_path = self.matcher.normalize_path(str_path)
        matched = self.matcher.match_fs(("mkdir",), norm_path)
        if matched is None and self.matcher.config.strict_mode:
            self.matcher.record_event("sftp", f"mkdir {str_path}", matched=False)
            raise asyncssh.SFTPPermissionDenied(
                f"mkdir not permitted by cassette in strict mode: {str_path}"
            )
        if matched is not None and matched.error_class:
            self.matcher.record_event("sftp", f"mkdir {str_path}", matched=True, exit_code=1)
            raise asyncssh.SFTPPermissionDenied(matched.error_message or matched.error_class)

        self.matcher.overlay_dirs.add(norm_path)
        self.matcher.deleted_paths.discard(norm_path)
        if attrs.permissions is not None:
            self.matcher.overlay_modes[norm_path] = int(attrs.permissions)
        self.matcher.record_event("sftp", f"mkdir {str_path}", matched=True, exit_code=0)

    def rmdir(self, path: bytes | str) -> None:
        """Удалить директорию из сессионного оверлея."""
        str_path = _decode_sftp_path(path)
        norm_path = self.matcher.normalize_path(str_path)
        self.matcher.overlay_dirs.discard(norm_path)
        self.matcher.deleted_paths.add(norm_path)
        self.matcher.record_event("sftp", f"rmdir {str_path}", matched=True, exit_code=0)

    def remove(self, path: bytes | str) -> None:
        """Удалить файл из сессионного оверлея со сверкой по кассете."""
        str_path = _decode_sftp_path(path)
        norm_path = self.matcher.normalize_path(str_path)
        matched = self.matcher.match_fs(("remove_file",), norm_path)
        if (
            matched is None
            and norm_path not in self.matcher.overlay_files
            and self.matcher.config.strict_mode
        ):
            self.matcher.record_event("sftp", f"remove {str_path}", matched=False)
            raise asyncssh.SFTPPermissionDenied(
                f"remove_file not permitted by cassette in strict mode: {str_path}"
            )
        if matched is not None and matched.error_class:
            self.matcher.record_event("sftp", f"remove {str_path}", matched=True, exit_code=1)
            raise asyncssh.SFTPPermissionDenied(matched.error_message or matched.error_class)

        self.matcher.overlay_files.pop(norm_path, None)
        self.matcher.deleted_paths.add(norm_path)
        self.matcher.record_event("sftp", f"remove {str_path}", matched=True, exit_code=0)

    def rename(self, oldpath: bytes | str, newpath: bytes | str) -> None:
        """Переименовать файл в сессионном оверлее (используется при атомарной записи)."""
        old_str = _decode_sftp_path(oldpath)
        new_str = _decode_sftp_path(newpath)
        old_norm = self.matcher.normalize_path(old_str)
        new_norm = self.matcher.normalize_path(new_str)
        if old_norm in self.matcher.overlay_files:
            self.matcher.overlay_files[new_norm] = self.matcher.overlay_files.pop(old_norm)
        if old_norm in self.matcher.overlay_modes:
            self.matcher.overlay_modes[new_norm] = self.matcher.overlay_modes.pop(old_norm)
        self.matcher.deleted_paths.add(old_norm)
        self.matcher.deleted_paths.discard(new_norm)
        self.matcher.record_event(
            "sftp", f"rename {old_str} -> {new_str}", matched=True, exit_code=0
        )

    def posix_rename(self, oldpath: bytes | str, newpath: bytes | str) -> None:
        """Переименовать файл с семантикой POSIX (перезапись целевого пути)."""
        self.rename(oldpath, newpath)


__all__ = [
    "MockSFTPFile",
    "MockSFTPServer",
]
