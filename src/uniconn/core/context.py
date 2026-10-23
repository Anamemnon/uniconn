# src/uniconn/core/context.py
"""Управление контекстом выполнения команд (стеки рабочей директории, окружения и временных папок)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .._connection import Connection


class CwdContext:
    """Универсальный (sync + async) контекстный менеджер смены рабочей директории."""

    def __init__(self, stack: list[str], new_cwd: str) -> None:
        """Инициализировать контекст рабочей директории."""
        self._stack = stack
        self._new_cwd = new_cwd

    def __enter__(self) -> None:
        """Добавить директорию в стек."""
        if self._stack and not Path(self._new_cwd).is_absolute():
            resolved = str(Path(self._stack[-1]) / self._new_cwd)
        else:
            resolved = self._new_cwd
        self._stack.append(resolved)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Удалить директорию из стека."""
        if self._stack:
            self._stack.pop()

    async def __aenter__(self) -> None:
        """Асинхронный вход в контекст директории."""
        self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Асинхронный выход из контекста директории."""
        self.__exit__(exc_type, exc_val, exc_tb)


class EnvContext:
    """Универсальный (sync + async) контекстный менеджер переменных окружения."""

    def __init__(self, stack: list[dict[str, str]], env_vars: dict[str, str]) -> None:
        """Инициализировать контекст переменных окружения."""
        self._stack = stack
        self._env_vars = env_vars

    def __enter__(self) -> None:
        """Добавить фрейм переменных окружения в стек."""
        self._stack.append(self._env_vars)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Удалить фрейм переменных окружения из стека."""
        if self._stack:
            self._stack.pop()

    async def __aenter__(self) -> None:
        """Асинхронный вход в контекст окружения."""
        self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Асинхронный выход из контекста окружения."""
        self.__exit__(exc_type, exc_val, exc_tb)


class TempDirContext:
    """Асинхронный контекстный менеджер временной директории на хосте."""

    def __init__(
        self,
        conn: Connection,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> None:
        """Инициализировать контекстный менеджер временной директории."""
        self._conn = conn
        self._prefix = prefix
        self._suffix = suffix
        self._dir = str(dir) if dir is not None else None
        self._path: str | None = None

    async def __aenter__(self) -> str:
        """Создать временную директорию на хосте."""
        self._path = await self._conn._create_temp_dir(
            prefix=self._prefix,
            suffix=self._suffix,
            dir=self._dir,
        )
        return self._path

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Удалить временную директорию на хосте."""
        if self._path:
            await self._conn._remove_temp_dir(self._path)
            self._path = None


class ExecutionContext:
    """Инкапсулирует состояние контекстных стеков ``cd()`` и ``env()`` для подключения."""

    def __init__(self) -> None:
        """Инициализировать пустые стеки рабочей директории и окружения."""
        self.cwd_stack: list[str] = []
        self.env_stack: list[dict[str, str]] = []

    def cd(self, path: str | Path) -> CwdContext:
        """Создать контекстный менеджер временной смены директории."""
        return CwdContext(self.cwd_stack, str(path))

    def env(self, mapping: dict[str, str] | None = None, **env_vars: str) -> EnvContext:
        """Создать контекстный менеджер временных переменных окружения."""
        merged: dict[str, str] = {}
        if mapping:
            merged.update({str(k): str(v) for k, v in mapping.items()})
        if env_vars:
            merged.update({str(k): str(v) for k, v in env_vars.items()})
        return EnvContext(self.env_stack, merged)

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека."""
        return self.cwd_stack[-1] if self.cwd_stack else None

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения."""
        merged: dict[str, str] = {}
        for frame in self.env_stack:
            merged.update(frame)
        return merged

    def resolve_path(self, remote_path: str | Path) -> str:
        """Разрешить путь с учётом активного ``current_cwd`` (для относительных путей)."""
        path_str = str(remote_path)
        active_cwd = self.current_cwd
        if active_cwd and not Path(path_str).is_absolute():
            return str(Path(active_cwd) / path_str)
        return path_str

    def apply_to_kwargs(self, kwargs: dict[str, Any]) -> None:
        """Применить активные контексты ``cd()`` и ``env()`` к аргументам вызова транспорта."""
        active_cwd = self.current_cwd
        if active_cwd is not None:
            explicit_cwd = kwargs.get("cwd")
            if explicit_cwd is None:
                kwargs["cwd"] = active_cwd
            elif not Path(str(explicit_cwd)).is_absolute():
                kwargs["cwd"] = str(Path(active_cwd) / str(explicit_cwd))

        active_env = self.current_env
        if active_env:
            explicit_env = kwargs.get("env")
            if explicit_env:
                kwargs["env"] = {**active_env, **explicit_env}
            else:
                kwargs["env"] = active_env
