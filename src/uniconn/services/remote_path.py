# src/uniconn/services/remote_path.py
"""Объектно-ориентированная модель удалённой файловой системы (RemotePath и SyncRemotePath).

Предоставляет интуитивный интерфейс, полностью совместимый по семантике с ``pathlib.Path``,
поддерживающий оператор ``/``, предзагрузку и кэширование метаданных ``stat`` при пакетном
обходе директорий (``glob``, ``rglob``, ``iterdir``) и автоматическую инвалидацию кэша при записи.
"""

from __future__ import annotations

import contextlib
import fnmatch
import os
import shlex
import stat as stat_mod
from collections.abc import AsyncIterator, Iterator, Mapping
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Any, Literal, Self

from ..core.bridge import EventLoopPortal, sync_method
from ..exceptions import UniconnError

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..sync.connection import SyncConnection

ChecksumAlgorithm = Literal["sha256", "sha1", "md5"]


class RemoteStatResult(dict[str, Any]):
    """Гибридный объект метаданных файла, совместимый и с ``FileStat`` (dict), и с ``os.stat_result``.

    Позволяет обращаться к полям как по ключу словаря (``st["size"]``, ``st["is_dir"]``),
    так и через стандартные атрибуты ``pathlib.Path.stat()`` (``st.st_size``, ``st.st_mtime``,
    ``st.st_mode``, ``st.st_atime``, ``st.st_uid``, ``st.st_gid``, ``st.is_dir``, ``st.is_file``,
    ``st.is_symlink``).
    """

    @classmethod
    def coerce(cls, data: Mapping[str, Any] | RemoteStatResult) -> RemoteStatResult:
        """Преобразовать произвольный словарь FileStat в ``RemoteStatResult``."""
        if isinstance(data, RemoteStatResult):
            return data
        return cls(data)

    @property
    def st_size(self) -> int:
        """Размер файла в байтах (совместимо с ``os.stat_result.st_size``)."""
        return int(self.get("size", 0))

    @property
    def size(self) -> int:
        """Размер файла в байтах."""
        return int(self.get("size", 0))

    @property
    def st_mtime(self) -> float:
        """Время последней модификации в секундах (UNIX timestamp)."""
        return float(self.get("mtime") or 0.0)

    @property
    def mtime(self) -> float:
        """Время последней модификации в секундах."""
        return float(self.get("mtime") or 0.0)

    @property
    def st_atime(self) -> float:
        """Время последнего доступа в секундах (UNIX timestamp)."""
        return float(self.get("atime") or self.get("mtime") or 0.0)

    @property
    def atime(self) -> float:
        """Время последнего доступа в секундах."""
        return float(self.get("atime") or self.get("mtime") or 0.0)

    @property
    def st_ctime(self) -> float:
        """Время изменения метаданных / создания в секундах (UNIX timestamp)."""
        return float(self.get("ctime") or self.get("mtime") or 0.0)

    @property
    def st_uid(self) -> int:
        """Числовой идентификатор владельца файла (UID)."""
        return int(self.get("uid") or 0)

    @property
    def uid(self) -> int:
        """Числовой идентификатор владельца файла (UID)."""
        return int(self.get("uid") or 0)

    @property
    def st_gid(self) -> int:
        """Числовой идентификатор группы файла (GID)."""
        return int(self.get("gid") or 0)

    @property
    def gid(self) -> int:
        """Числовой идентификатор группы файла (GID)."""
        return int(self.get("gid") or 0)

    @property
    def st_mode(self) -> int:
        """Числовой режим файла ``st_mode`` (включая флаги типа файла и права доступа)."""
        raw_mode = self.get("mode")
        if isinstance(raw_mode, int) and raw_mode > 0:
            mode_val = raw_mode
        else:
            perms_str = self.get("permissions")
            mode_val = 0o644
            if isinstance(perms_str, str):
                with contextlib.suppress(ValueError):
                    mode_val = int(perms_str, 8)
        if not stat_mod.S_IFMT(mode_val):
            if self.get("is_symlink"):
                mode_val |= stat_mod.S_IFLNK
            elif self.get("is_dir"):
                mode_val |= stat_mod.S_IFDIR
            else:
                mode_val |= stat_mod.S_IFREG
        return mode_val

    @property
    def mode(self) -> int:
        """Числовой режим доступа."""
        raw_mode = self.get("mode")
        if isinstance(raw_mode, int):
            return raw_mode
        return self.st_mode

    @property
    def permissions(self) -> str:
        """Восьмеричное строковое представление прав доступа (например, ``'0o644'``)."""
        perms = self.get("permissions")
        if isinstance(perms, str):
            return perms
        return oct(stat_mod.S_IMODE(self.st_mode))

    @property
    def is_dir(self) -> bool:
        """Является ли путь директорией."""
        return bool(self.get("is_dir", False))

    @property
    def is_file(self) -> bool:
        """Является ли путь обычным файлом."""
        if "is_file" in self:
            return bool(self["is_file"])
        return not bool(self.get("is_dir", False)) and not bool(self.get("is_symlink", False))

    @property
    def is_symlink(self) -> bool:
        """Является ли путь символической ссылкой."""
        return bool(self.get("is_symlink", False))


def _is_windows_flavour(conn: Any, raw_path: str) -> bool:
    """Определить, нужно ли использовать семантику путей Windows для данного подключения."""
    tr_name = getattr(conn, "transport_name", "")
    if tr_name in ("winrm", "wsman"):
        return True
    if tr_name == "local" and os.name == "nt":
        return True
    return len(raw_path) >= 2 and raw_path[1] == ":" and ("\\" in raw_path or "/" in raw_path)


def _make_pure_path(raw_path: str, *, is_windows: bool) -> PurePath:
    """Создать объект PurePosixPath или PureWindowsPath без обращения к локальной ОС."""
    if is_windows:
        return PureWindowsPath(raw_path or ".")
    return PurePosixPath(raw_path or ".")


def _glob_parts_match(rel_parts: tuple[str, ...], pat_parts: tuple[str, ...]) -> bool:
    """Рекурсивно сопоставить сегменты относительного пути с сегментами glob-паттерна (включая ``**``)."""
    if not pat_parts:
        return not rel_parts
    if pat_parts[0] == "**":
        # '**' может поглотить 0 или более сегментов директорий
        if _glob_parts_match(rel_parts, pat_parts[1:]):
            return True
        if rel_parts:
            return _glob_parts_match(rel_parts[1:], pat_parts)
        return False
    if not rel_parts:
        return False
    if not fnmatch.fnmatchcase(rel_parts[0], pat_parts[0]):
        return False
    return _glob_parts_match(rel_parts[1:], pat_parts[1:])


class RemotePath(os.PathLike[str]):
    """Асинхронная объектная модель пути на удалённом или локальном хосте (аналог ``pathlib.Path``).

    Создаётся через ``conn.path("/var/log/nginx")`` или ``conn.files.path(...)``.
    """

    def __init__(
        self,
        conn: Connection,
        *pathsegments: str | os.PathLike[str],
        cached_stat: Mapping[str, Any] | RemoteStatResult | None = None,
    ) -> None:
        """Инициализировать удалённый путь с привязкой к ``Connection``."""
        self._conn = conn
        str_segments = [os.fspath(s) for s in pathsegments if s is not None]
        joined_hint = "/".join(str_segments) if str_segments else "."
        self._is_windows = _is_windows_flavour(conn, joined_hint)
        self._pure: PurePath = (
            PureWindowsPath(*str_segments)
            if self._is_windows
            else PurePosixPath(*str_segments)
        )
        self._raw_path = str(self._pure)
        self._cached_stat: RemoteStatResult | None = (
            RemoteStatResult.coerce(cached_stat) if cached_stat is not None else None
        )

    def _spawn(
        self,
        new_pure: PurePath | str,
        *,
        cached_stat: Mapping[str, Any] | RemoteStatResult | None = None,
    ) -> RemotePath:
        """Создать новый экземпляр ``RemotePath`` на том же подключении."""
        return RemotePath(self._conn, str(new_pure), cached_stat=cached_stat)

    # ─── Протокол PathLike, сравнение и чистые свойства пути ─────────

    @property
    def connection(self) -> Connection:
        """Привязанный экземпляр ``Connection``."""
        return self._conn

    @property
    def cached_stat(self) -> RemoteStatResult | None:
        """Предзагруженный кэш метаданных ``RemoteStatResult`` (или ``None``)."""
        return self._cached_stat

    def invalidate_cache(self) -> None:
        """Сбросить закэшированные метаданные ``stat`` для данного пути."""
        self._cached_stat = None

    def __fspath__(self) -> str:
        return self._raw_path

    def __str__(self) -> str:
        return self._raw_path

    def __repr__(self) -> str:
        return f"RemotePath({self._raw_path!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RemotePath):
            return self._pure == other._pure and self._conn is other._conn
        if isinstance(other, SyncRemotePath):
            return self._pure == other._async_path._pure and self._conn is other._async_path._conn
        if isinstance(other, PurePath):
            return str(self._pure) == str(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((id(self._conn), self._pure))

    def __lt__(self, other: RemotePath | PurePath | str) -> bool:
        other_str = os.fspath(other) if isinstance(other, os.PathLike) else str(other)
        return str(self._pure) < other_str

    def __le__(self, other: RemotePath | PurePath | str) -> bool:
        other_str = os.fspath(other) if isinstance(other, os.PathLike) else str(other)
        return str(self._pure) <= other_str

    def __gt__(self, other: RemotePath | PurePath | str) -> bool:
        other_str = os.fspath(other) if isinstance(other, os.PathLike) else str(other)
        return str(self._pure) > other_str

    def __ge__(self, other: RemotePath | PurePath | str) -> bool:
        other_str = os.fspath(other) if isinstance(other, os.PathLike) else str(other)
        return str(self._pure) >= other_str

    def __truediv__(self, key: str | os.PathLike[str]) -> RemotePath:
        return self._spawn(self._pure / os.fspath(key))

    def __rtruediv__(self, key: str | os.PathLike[str]) -> RemotePath:
        return self._spawn(_make_pure_path(os.fspath(key), is_windows=self._is_windows) / self._pure)

    def joinpath(self, *other: str | os.PathLike[str]) -> RemotePath:
        """Объединить путь с одним или несколькими сегментами."""
        return self._spawn(self._pure.joinpath(*(os.fspath(o) for o in other)))

    @property
    def parts(self) -> tuple[str, ...]:
        """Кортеж отдельных компонентов пути."""
        return self._pure.parts

    @property
    def drive(self) -> str:
        """Буква диска или UNC-префикс (для Windows-путей)."""
        return self._pure.drive

    @property
    def root(self) -> str:
        r"""Корневой разделитель пути (``'/'`` или ``'\\'``)."""
        return self._pure.root

    @property
    def anchor(self) -> str:
        """Объединение ``drive`` и ``root``."""
        return self._pure.anchor

    @property
    def name(self) -> str:
        """Конечное имя файла или директории."""
        return self._pure.name

    @property
    def suffix(self) -> str:
        """Расширение файла с точкой (например, ``'.log'``)."""
        return self._pure.suffix

    @property
    def suffixes(self) -> list[str]:
        """Список всех расширений файла (например, ``['.tar', '.gz']``)."""
        return self._pure.suffixes

    @property
    def stem(self) -> str:
        """Имя файла без последнего расширения."""
        return self._pure.stem

    @property
    def parent(self) -> RemotePath:
        """Родительская директория как ``RemotePath``."""
        return self._spawn(self._pure.parent)

    @property
    def parents(self) -> tuple[RemotePath, ...]:
        """Кортеж всех родительских директорий вверх до корня."""
        return tuple(self._spawn(p) for p in self._pure.parents)

    def as_posix(self) -> str:
        """Строковое представление пути с прямыми слэшами ``/``."""
        return self._pure.as_posix()

    def is_absolute(self) -> bool:
        """Проверить, является ли путь абсолютным."""
        return self._pure.is_absolute()

    def is_relative_to(self, other: str | os.PathLike[str]) -> bool:
        """Проверить, находится ли путь внутри указанного базового пути."""
        return self._pure.is_relative_to(os.fspath(other))

    def relative_to(self, other: str | os.PathLike[str]) -> PurePath:
        """Вычислить относительный путь относительно ``other``."""
        return self._pure.relative_to(os.fspath(other))

    def with_name(self, name: str) -> RemotePath:
        """Вернуть новый ``RemotePath`` с заменённым именем файла."""
        return self._spawn(self._pure.with_name(name))

    def with_stem(self, stem: str) -> RemotePath:
        """Вернуть новый ``RemotePath`` с заменённой основой имени (без расширения)."""
        return self._spawn(self._pure.with_stem(stem))

    def with_suffix(self, suffix: str) -> RemotePath:
        """Вернуть новый ``RemotePath`` с заменённым расширением файла."""
        return self._spawn(self._pure.with_suffix(suffix))

    def match(self, path_pattern: str) -> bool:
        """Проверить соответствие пути glob-шаблону."""
        return self._pure.match(path_pattern)

    def _effective_path(self) -> str:
        """Разрешить путь с учётом активного контекста ``conn.cd(...)``."""
        return self._conn.context.resolve_path(self._raw_path)

    # ─── Асинхронные операции инспекции и чтения/записи ──────────────

    async def stat(self, *, refresh: bool = False) -> RemoteStatResult:
        """Получить метаданные файла (из предзагруженного кэша или через транспорт)."""
        if self._cached_stat is not None and not refresh:
            return self._cached_stat
        raw_st = await self._conn.files.stat(self._raw_path)
        self._cached_stat = RemoteStatResult.coerce(raw_st)
        return self._cached_stat

    async def lstat(self, *, refresh: bool = False) -> RemoteStatResult:
        """Получить метаданные файла или самой символической ссылки."""
        return await self.stat(refresh=refresh)

    async def exists(self) -> bool:
        """Проверить существование пути на удалённом хосте."""
        if self._cached_stat is not None:
            return True
        return await self._conn.files.exists(self._raw_path)

    async def is_dir(self) -> bool:
        """Проверить, существует ли путь и является ли он директорией."""
        if self._cached_stat is not None:
            return self._cached_stat.is_dir
        try:
            st = await self.stat()
            return st.is_dir
        except (OSError, UniconnError):
            return False

    async def is_file(self) -> bool:
        """Проверить, существует ли путь и является ли он обычным файлом."""
        if self._cached_stat is not None:
            return self._cached_stat.is_file
        try:
            st = await self.stat()
            return st.is_file
        except (OSError, UniconnError):
            return False

    async def is_symlink(self) -> bool:
        """Проверить, является ли путь символической ссылкой."""
        if self._cached_stat is not None and "is_symlink" in self._cached_stat:
            return self._cached_stat.is_symlink
        try:
            st = await self.stat()
            if "is_symlink" in st:
                return st.is_symlink
        except (OSError, UniconnError):
            return False
        return False

    async def read_text(self, encoding: str = "utf-8") -> str:
        """Прочитать текстовое содержимое файла в указанной кодировке."""
        res = await self._conn.files.read_file(self._raw_path, encoding=encoding)
        if isinstance(res, bytes):
            return res.decode(encoding)
        return res

    async def read_bytes(self) -> bytes:
        """Прочитать сырое бинарное содержимое файла."""
        res = await self._conn.files.read_file(self._raw_path, encoding=None)
        if isinstance(res, str):
            return res.encode("utf-8")
        return bytes(res)

    async def write_text(
        self,
        data: str,
        encoding: str = "utf-8",
        *,
        mode: int | None = None,
        atomic: bool = False,
    ) -> int:
        """Записать строку в файл (с автоматическим сбросом кэша ``stat``)."""
        if not isinstance(data, str):
            raise TypeError(f"data must be str, not {type(data).__name__}")
        self.invalidate_cache()
        await self._conn.files.write_file(
            self._raw_path,
            data,
            mode=mode,
            encoding=encoding,
            atomic=atomic,
        )
        return len(data)

    async def write_bytes(
        self,
        data: bytes | bytearray | memoryview,
        *,
        mode: int | None = None,
        atomic: bool = False,
    ) -> int:
        """Записать байты в файл (с автоматическим сбросом кэша ``stat``)."""
        raw = bytes(data)
        self.invalidate_cache()
        await self._conn.files.write_file(
            self._raw_path,
            raw,
            mode=mode,
            atomic=atomic,
        )
        return len(raw)

    async def mkdir(
        self,
        mode: int | None = None,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        """Создать директорию на удалённом хосте."""
        self.invalidate_cache()
        await self._conn.files.mkdir(
            self._raw_path,
            parents=parents,
            exist_ok=exist_ok,
            mode=mode,
        )

    async def chmod(self, mode: int) -> None:
        """Изменить права доступа к файлу или директории."""
        self.invalidate_cache()
        await self._conn.files.chmod(self._raw_path, mode)

    async def unlink(self, missing_ok: bool = False) -> None:
        """Удалить файл или символическую ссылку."""
        self.invalidate_cache()
        try:
            await self._conn.files.remove_file(self._raw_path)
        except (OSError, UniconnError):
            if not missing_ok or await self._conn.files.exists(self._raw_path):
                raise

    async def rmdir(self) -> None:
        """Удалить пустую директорию на хосте."""
        self.invalidate_cache()
        if self._conn.dry_run:
            return
        eff = self._effective_path()
        if self._conn.transport_name == "local":
            Path(eff).rmdir()
            return
        if self._is_windows:
            ps_q = "'" + eff.replace("'", "''") + "'"
            await self._conn.run(
                f"Remove-Item -LiteralPath {ps_q} -Force -ErrorAction Stop",
                raise_on_error=True,
            )
            return
        await self._conn.run(f"rmdir {shlex.quote(eff)}", raise_on_error=True)

    async def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        """Создать пустой файл или обновить время модификации существующего."""
        self.invalidate_cache()
        already_exists = await self._conn.files.exists(self._raw_path)
        if already_exists:
            if not exist_ok:
                raise FileExistsError(f"File already exists: {self._raw_path}")
            if self._conn.transport_name == "local" and not self._conn.dry_run:
                Path(self._effective_path()).touch(mode=mode, exist_ok=True)
            elif not self._is_windows and not self._conn.dry_run:
                await self._conn.run(
                    f"touch {shlex.quote(self._effective_path())}",
                    raise_on_error=False,
                )
            return
        await self._conn.files.write_file(self._raw_path, b"", mode=mode if mode != 0o666 else None)

    async def rename(self, target: str | os.PathLike[str]) -> RemotePath:
        """Переместить или переименовать файл/директорию в ``target`` и вернуть новый ``RemotePath``."""
        self.invalidate_cache()
        target_str = os.fspath(target)
        new_path = self._spawn(target_str)
        new_path.invalidate_cache()
        if self._conn.dry_run:
            return new_path

        src_eff = self._effective_path()
        dst_eff = self._conn.context.resolve_path(target_str)
        if self._conn.transport_name == "local":
            Path(src_eff).rename(dst_eff)
            return new_path
        if self._is_windows:
            q_src = "'" + src_eff.replace("'", "''") + "'"
            q_dst = "'" + dst_eff.replace("'", "''") + "'"
            await self._conn.run(
                f"Move-Item -LiteralPath {q_src} -Destination {q_dst} -Force -ErrorAction Stop",
                raise_on_error=True,
            )
            return new_path
        await self._conn.run(
            f"mv -f {shlex.quote(src_eff)} {shlex.quote(dst_eff)}",
            raise_on_error=True,
        )
        return new_path

    async def replace(self, target: str | os.PathLike[str]) -> RemotePath:
        """Атомарно заменить ``target`` текущим путём и вернуть новый ``RemotePath``."""
        return await self.rename(target)

    async def checksum(
        self,
        algorithm: ChecksumAlgorithm = "sha256",
        *,
        sudo: bool = False,
    ) -> str:
        """Вычислить контрольную сумму файла (``sha256``, ``sha1`` или ``md5``)."""
        return await self._conn.files.checksum(
            self._raw_path,
            algorithm=algorithm,
            sudo=sudo,
        )

    async def upload_from(
        self,
        local_path: str | Path,
        *,
        recurse: bool = False,
        verify: bool = False,
    ) -> Self:
        """Загрузить локальный файл или директорию по текущему удалённому пути."""
        self.invalidate_cache()
        await self._conn.files.upload(
            local_path,
            self._raw_path,
            recurse=recurse,
            verify=verify,
        )
        return self

    async def download_to(
        self,
        local_path: str | Path,
        *,
        recurse: bool = False,
        verify: bool = False,
    ) -> Path:
        """Скачать текущий удалённый файл или директорию на локальную машину."""
        await self._conn.files.download(
            self._raw_path,
            local_path,
            recurse=recurse,
            verify=verify,
        )
        return Path(local_path)

    # ─── Пакетный обход директорий с предзагрузкой метаданных stat ───

    async def _scan_via_worker_or_fs(
        self,
        *,
        pattern: str = "*",
        recursive: bool = False,
        iterdir_only: bool = False,
    ) -> list[RemotePath]:
        """Собрать список элементов директории с предзаполненным ``_cached_stat``."""
        eff_base = self._effective_path()

        # 1. Быстрый путь через активный или авто-активируемый Python-воркер
        worker = getattr(self._conn, "_python_worker", None)
        if worker is not None and worker.can_auto_accelerate():
            with contextlib.suppress(Exception):
                entries = await worker.glob_with_stat(
                    eff_base,
                    pattern=pattern,
                    recursive=recursive,
                    iterdir_only=iterdir_only,
                )
                return [
                    self._spawn(
                        self._pure / item["rel_path"] if "rel_path" in item else item["path"],
                        cached_stat=item.get("stat"),
                    )
                    for item in entries
                ]

        # 2. Универсальный путь через FileOperationsService (поддерживает SFTP, Local, WinRM, Replay/Cassette)
        results: list[RemotePath] = []
        norm_pat = pattern.replace("\\", "/").lstrip("/")
        if norm_pat.startswith("./"):
            norm_pat = norm_pat[2:]
        pat_parts = tuple(p for p in norm_pat.split("/") if p and p != ".")

        async def _walk_fs(cur_dir: RemotePath, rel_parts: tuple[str, ...]) -> None:
            try:
                names = await self._conn.files.listdir(cur_dir._raw_path)
            except (OSError, UniconnError):
                return

            for name in sorted(names):
                if name in (".", ".."):
                    continue
                child = cur_dir / name
                child_rel = (*rel_parts, name)

                if iterdir_only:
                    st: RemoteStatResult | None = None
                    with contextlib.suppress(OSError, UniconnError):
                        st = RemoteStatResult.coerce(await self._conn.files.stat(child._raw_path))
                    child._cached_stat = st
                    results.append(child)
                    continue

                is_deep = recursive or ("**" in pat_parts) or (len(pat_parts) > 1)
                if not is_deep:
                    # Простой одноуровневый паттерн вроде "*.log" — проверяем имя ДО вызова stat!
                    if fnmatch.fnmatchcase(name, norm_pat):
                        st_single: RemoteStatResult | None = None
                        with contextlib.suppress(OSError, UniconnError):
                            st_single = RemoteStatResult.coerce(
                                await self._conn.files.stat(child._raw_path)
                            )
                        child._cached_stat = st_single
                        results.append(child)
                    continue

                # Многоуровневый или рекурсивный паттерн
                st_deep: RemoteStatResult | None = None
                with contextlib.suppress(OSError, UniconnError):
                    st_deep = RemoteStatResult.coerce(await self._conn.files.stat(child._raw_path))
                child._cached_stat = st_deep

                effective_pat_parts = (
                    ("**", *pat_parts)
                    if recursive and (not pat_parts or pat_parts[0] != "**")
                    else pat_parts
                )
                if _glob_parts_match(child_rel, effective_pat_parts):
                    results.append(child)

                if (
                    st_deep is not None
                    and st_deep.is_dir
                    and (
                        recursive
                        or "**" in effective_pat_parts
                        or len(child_rel) < len(effective_pat_parts)
                    )
                ):
                    await _walk_fs(child, child_rel)

        await _walk_fs(self, ())
        return results

    async def iterdir(self) -> AsyncIterator[RemotePath]:
        """Асинхронно итерироваться по содержимому директории с предзагрузкой ``stat``."""
        items = await self._scan_via_worker_or_fs(iterdir_only=True)
        for item in items:
            yield item

    async def glob(self, pattern: str) -> AsyncIterator[RemotePath]:
        """Найти пути в директории по glob-шаблону с предзагрузкой ``stat`` для каждого файла."""
        if not pattern:
            raise ValueError("Unacceptable pattern: ''")
        is_rec = "**" in pattern
        items = await self._scan_via_worker_or_fs(pattern=pattern, recursive=is_rec)
        for item in items:
            yield item

    async def rglob(self, pattern: str) -> AsyncIterator[RemotePath]:
        """Рекурсивно найти все пути в дереве директорий по glob-шаблону с предзагрузкой ``stat``."""
        if not pattern:
            raise ValueError("Unacceptable pattern: ''")
        items = await self._scan_via_worker_or_fs(pattern=pattern, recursive=True)
        for item in items:
            yield item


class SyncRemotePath(os.PathLike[str]):
    """Синхронная объектная модель удалённого пути на базе ``EventLoopPortal`` (``sync_conn.path(...)``)."""

    def __init__(
        self,
        async_path: RemotePath,
        sync_conn: SyncConnection,
    ) -> None:
        """Инициализировать синхронную обёртку над ``RemotePath``."""
        self._async_path = async_path
        self._async_target = async_path
        self._sync_conn = sync_conn

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    def _wrap(self, async_p: RemotePath) -> SyncRemotePath:
        return SyncRemotePath(async_p, self._sync_conn)

    # ─── Протокол PathLike, сравнение и чистые свойства пути ─────────

    @property
    def connection(self) -> SyncConnection:
        """Привязанный экземпляр ``SyncConnection``."""
        return self._sync_conn

    @property
    def cached_stat(self) -> RemoteStatResult | None:
        """Предзагруженный кэш метаданных ``RemoteStatResult`` (или ``None``)."""
        return self._async_path.cached_stat

    def invalidate_cache(self) -> None:
        """Сбросить закэшированные метаданные ``stat``."""
        self._async_path.invalidate_cache()

    def __fspath__(self) -> str:
        return self._async_path.__fspath__()

    def __str__(self) -> str:
        return str(self._async_path)

    def __repr__(self) -> str:
        return f"SyncRemotePath({str(self._async_path)!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SyncRemotePath):
            return self._async_path == other._async_path
        return self._async_path == other

    def __hash__(self) -> int:
        return hash(self._async_path)

    def __lt__(self, other: SyncRemotePath | RemotePath | PurePath | str) -> bool:
        return self._async_path < other

    def __le__(self, other: SyncRemotePath | RemotePath | PurePath | str) -> bool:
        return self._async_path <= other

    def __gt__(self, other: SyncRemotePath | RemotePath | PurePath | str) -> bool:
        return self._async_path > other

    def __ge__(self, other: SyncRemotePath | RemotePath | PurePath | str) -> bool:
        return self._async_path >= other

    def __truediv__(self, key: str | os.PathLike[str]) -> SyncRemotePath:
        return self._wrap(self._async_path / os.fspath(key))

    def __rtruediv__(self, key: str | os.PathLike[str]) -> SyncRemotePath:
        return self._wrap(os.fspath(key) / self._async_path)

    def joinpath(self, *other: str | os.PathLike[str]) -> SyncRemotePath:
        """Объединить путь с одним или несколькими сегментами."""
        return self._wrap(self._async_path.joinpath(*other))

    @property
    def parts(self) -> tuple[str, ...]:
        return self._async_path.parts

    @property
    def drive(self) -> str:
        return self._async_path.drive

    @property
    def root(self) -> str:
        return self._async_path.root

    @property
    def anchor(self) -> str:
        return self._async_path.anchor

    @property
    def name(self) -> str:
        return self._async_path.name

    @property
    def suffix(self) -> str:
        return self._async_path.suffix

    @property
    def suffixes(self) -> list[str]:
        return self._async_path.suffixes

    @property
    def stem(self) -> str:
        return self._async_path.stem

    @property
    def parent(self) -> SyncRemotePath:
        return self._wrap(self._async_path.parent)

    @property
    def parents(self) -> tuple[SyncRemotePath, ...]:
        return tuple(self._wrap(p) for p in self._async_path.parents)

    def as_posix(self) -> str:
        return self._async_path.as_posix()

    def is_absolute(self) -> bool:
        return self._async_path.is_absolute()

    def is_relative_to(self, other: str | os.PathLike[str]) -> bool:
        return self._async_path.is_relative_to(other)

    def relative_to(self, other: str | os.PathLike[str]) -> PurePath:
        return self._async_path.relative_to(other)

    def with_name(self, name: str) -> SyncRemotePath:
        return self._wrap(self._async_path.with_name(name))

    def with_stem(self, stem: str) -> SyncRemotePath:
        return self._wrap(self._async_path.with_stem(stem))

    def with_suffix(self, suffix: str) -> SyncRemotePath:
        return self._wrap(self._async_path.with_suffix(suffix))

    def match(self, path_pattern: str) -> bool:
        return self._async_path.match(path_pattern)

    # ─── Синхронные файловые операции (ParamSpec-дескрипторы) ────────

    stat = sync_method(RemotePath.stat)
    lstat = sync_method(RemotePath.lstat)
    exists = sync_method(RemotePath.exists)
    is_dir = sync_method(RemotePath.is_dir)
    is_file = sync_method(RemotePath.is_file)
    is_symlink = sync_method(RemotePath.is_symlink)
    read_text = sync_method(RemotePath.read_text)
    read_bytes = sync_method(RemotePath.read_bytes)
    write_text = sync_method(RemotePath.write_text)
    write_bytes = sync_method(RemotePath.write_bytes)
    mkdir = sync_method(RemotePath.mkdir)
    chmod = sync_method(RemotePath.chmod)
    unlink = sync_method(RemotePath.unlink)
    rmdir = sync_method(RemotePath.rmdir)
    touch = sync_method(RemotePath.touch)
    checksum = sync_method(RemotePath.checksum)
    download_to = sync_method(RemotePath.download_to)

    def upload_from(
        self,
        local_path: str | Path,
        *,
        recurse: bool = False,
        verify: bool = False,
    ) -> Self:
        """Загрузить локальный файл или директорию по текущему удалённому пути (синхронно)."""
        self._portal.call(
            self._async_path.upload_from(local_path, recurse=recurse, verify=verify)
        )
        return self

    def rename(self, target: str | os.PathLike[str]) -> SyncRemotePath:
        """Переименовать или переместить путь в ``target`` и вернуть новый ``SyncRemotePath``."""
        new_async = self._portal.call(self._async_path.rename(target))
        return self._wrap(new_async)

    def replace(self, target: str | os.PathLike[str]) -> SyncRemotePath:
        """Атомарно заменить ``target`` текущим путём и вернуть новый ``SyncRemotePath``."""
        new_async = self._portal.call(self._async_path.replace(target))
        return self._wrap(new_async)

    def iterdir(self) -> Iterator[SyncRemotePath]:
        """Синхронно итерироваться по содержимому директории с предзагрузкой ``stat``."""
        items = self._portal.call(self._async_path._scan_via_worker_or_fs(iterdir_only=True))
        for item in items:
            yield self._wrap(item)

    def glob(self, pattern: str) -> Iterator[SyncRemotePath]:
        """Синхронно найти пути по glob-шаблону с предзагрузкой ``stat``."""
        if not pattern:
            raise ValueError("Unacceptable pattern: ''")
        is_rec = "**" in pattern
        items = self._portal.call(
            self._async_path._scan_via_worker_or_fs(pattern=pattern, recursive=is_rec)
        )
        for item in items:
            yield self._wrap(item)

    def rglob(self, pattern: str) -> Iterator[SyncRemotePath]:
        """Синхронно рекурсивно найти все пути по glob-шаблону с предзагрузкой ``stat``."""
        if not pattern:
            raise ValueError("Unacceptable pattern: ''")
        items = self._portal.call(
            self._async_path._scan_via_worker_or_fs(pattern=pattern, recursive=True)
        )
        for item in items:
            yield self._wrap(item)


__all__ = [
    "RemotePath",
    "RemoteStatResult",
    "SyncRemotePath",
]
