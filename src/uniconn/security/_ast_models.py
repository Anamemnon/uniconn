# src/uniconn/security/_ast_models.py
"""Модели данных синтаксического дерева команд (AtomicCommand и ParsedCommandAST)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

CommandDialect = Literal["posix", "powershell"]


@dataclass(frozen=True, slots=True)
class AtomicCommand:
    """Атомарная команда внутри конвейера, цепочки или косвенной обёртки."""

    executable: str
    raw_executable: str = ""
    subcommand: str | None = None
    arguments: tuple[str, ...] = ()
    flags: dict[str, str | bool] = field(default_factory=dict)
    env_assignments: dict[str, str] = field(default_factory=dict)
    redirects: tuple[str, ...] = ()
    wrappers: tuple[str, ...] = ()
    is_sudo: bool = False
    is_obfuscated: bool = False
    subshell_depth: int = 0

    @property
    def args(self) -> tuple[str, ...]:
        """Алиас позиционных аргументов команды."""
        return self.arguments

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать атомарную команду в JSON-совместимый словарь."""
        return {
            "executable": self.executable,
            "raw_executable": self.raw_executable or self.executable,
            "subcommand": self.subcommand,
            "arguments": list(self.arguments),
            "args": list(self.arguments),
            "flags": dict(self.flags),
            "env_assignments": dict(self.env_assignments),
            "redirects": list(self.redirects),
            "wrappers": list(self.wrappers),
            "is_sudo": self.is_sudo,
            "is_obfuscated": self.is_obfuscated,
            "subshell_depth": self.subshell_depth,
        }


@dataclass(frozen=True, slots=True)
class ParsedCommandAST:
    """Синтаксическое дерево (AST) разобранной shell- или PowerShell-команды."""

    raw_command: str
    atomic_commands: tuple[AtomicCommand, ...] = ()
    executables: tuple[str, ...] = ()
    subcommands: tuple[str, ...] = ()
    target_paths: tuple[str, ...] = ()
    has_pipes: bool = False
    has_subshells: bool = False
    has_background_ops: bool = False
    has_inline_script: bool = False
    has_destructive_verbs: bool = False
    is_obfuscated: bool = False
    obfuscation_reasons: tuple[str, ...] = ()
    complexity_exceeded: bool = False
    max_depth: int = 0
    dialect: CommandDialect = "posix"
    parser_backend: str = "builtin"
    syntax_errors: tuple[str, ...] = ()

    @property
    def commands(self) -> tuple[AtomicCommand, ...]:
        """Алиас списка атомарных команд ``atomic_commands``."""
        return self.atomic_commands

    @property
    def verbs(self) -> tuple[str, ...]:
        """Алиас списка исполняемых бинарников ``executables``."""
        return self.executables

    @property
    def pipeline_length(self) -> int:
        """Общее число атомарных команд в цепочке или пайплайне."""
        return len(self.atomic_commands)

    @property
    def has_syntax_errors(self) -> bool:
        """Признак наличия синтаксических аномалий или ошибок грамматики (fail-closed)."""
        return bool(self.syntax_errors)

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать дерево команды в формат контекстного документа авторизации."""
        serialized_cmds = [cmd.to_dict() for cmd in self.atomic_commands]
        return {
            "raw_command": self.raw_command,
            "dialect": self.dialect,
            "parser_backend": self.parser_backend,
            "syntax_errors": list(self.syntax_errors),
            "has_syntax_errors": bool(self.syntax_errors),
            "executables": list(self.executables),
            "verbs": list(self.executables),
            "subcommands": list(self.subcommands),
            "targets": list(self.target_paths),
            "target_paths": list(self.target_paths),
            "has_pipes": self.has_pipes,
            "has_subshells": self.has_subshells,
            "has_background_ops": self.has_background_ops,
            "has_inline_script": self.has_inline_script,
            "has_destructive_verbs": self.has_destructive_verbs,
            "is_obfuscated": self.is_obfuscated,
            "obfuscation_reasons": list(self.obfuscation_reasons),
            "complexity_exceeded": self.complexity_exceeded,
            "pipeline_length": len(self.atomic_commands),
            "max_depth": self.max_depth,
            "atomic_commands": serialized_cmds,
            "commands": serialized_cmds,
        }


__all__ = [
    "AtomicCommand",
    "CommandDialect",
    "ParsedCommandAST",
]
