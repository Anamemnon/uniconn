# src/uniconn/security/_ast_treesitter.py
"""Опциональный грамматический бэкенд разбора POSIX/Bash на базе tree-sitter-bash.

Подключается автоматически при установленном extra ``uniconn[security]``
(``tree-sitter`` + ``tree-sitter-bash``). При отсутствии библиотек возвращает
``None``, обеспечивая бесшовный fallback на встроенный детерминированный парсер.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


@dataclass(frozen=True, slots=True)
class TreeSitterExtraction:
    """Результат грамматического разбора Bash-команды через ``tree-sitter-bash``."""

    segments: tuple[tuple[str, tuple[str, ...], int], ...]
    subshell_commands: tuple[tuple[str, int], ...]
    heredoc_payloads: tuple[str, ...]
    syntax_errors: tuple[str, ...]
    has_pipes: bool = False
    has_subshells: bool = False
    has_background_ops: bool = False


_THREAD_LOCAL = threading.local()


@lru_cache(maxsize=1)
def _load_bash_language() -> tuple[Any, Any] | None:
    """Лениво загрузить и закэшировать потокобезопасный ``tree_sitter.Language`` для Bash."""
    try:
        import tree_sitter
        import tree_sitter_bash
    except ImportError:
        return None

    try:
        language = tree_sitter.Language(tree_sitter_bash.language())
        return tree_sitter.Parser, language
    except Exception:
        return None


def _get_thread_bash_parser() -> Any | None:
    """Получить потокобезопасный (thread-local) экземпляр ``tree_sitter.Parser`` для Bash."""
    loaded = _load_bash_language()
    if loaded is None:
        return None
    parser = getattr(_THREAD_LOCAL, "bash_parser", None)
    if parser is None:
        parser_cls, language = loaded
        parser = parser_cls(language)
        _THREAD_LOCAL.bash_parser = parser
    return parser


def is_treesitter_available() -> bool:
    """Проверить, установлен и инициализирован ли грамматический бэкенд ``tree-sitter-bash``."""
    return _load_bash_language() is not None


def _decode_node(source_bytes: bytes, node: Any) -> str:
    """Извлечь исходный UTF-8 фрагмент узла CST."""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace").strip()


def _node_has_background_op(source_bytes: bytes, node: Any) -> bool:
    """Определить, содержит ли узел оператор фонового запуска ``&`` (но не ``&&`` / редирект)."""
    for child in node.children:
        if not child.is_named:
            tok = _decode_node(source_bytes, child)
            if tok == "&":
                return True
    return False


def _strip_inner_delimiters(text: str, prefix: str, suffix: str) -> str:
    """Снять внешние ограничители конструкции вроде ``$(...)`` или `` `...` ``."""
    cleaned = text.strip()
    if cleaned.startswith(prefix) and cleaned.endswith(suffix) and len(cleaned) >= len(prefix) + len(suffix):
        return cleaned[len(prefix) : len(cleaned) - len(suffix)].strip()
    return cleaned


def extract_bash_grammar(
    command: str,
    *,
    max_depth: int = 6,
) -> TreeSitterExtraction | None:
    """Разобрать POSIX/Bash строку через ``tree-sitter-bash`` и извлечь команды и ошибки грамматики.

    Возвращает ``None``, если ``tree-sitter-bash`` не установлен.
    """
    parser = _get_thread_bash_parser()
    if parser is None:
        return None

    source_bytes = command.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    root = tree.root_node

    segments: list[tuple[str, tuple[str, ...], int]] = []
    subshell_cmds: list[tuple[str, int]] = []
    seen_subshells: set[str] = set()
    heredocs: list[str] = []
    syntax_errors: list[str] = []
    has_pipes = False
    has_subshells = False
    has_background_ops = False

    def _record_error(node: Any) -> None:
        snippet = _decode_node(source_bytes, node)[:80]
        if node.is_missing:
            msg = f"Missing grammar token {node.type!r} at byte {node.start_byte}"
        else:
            msg = f"Bash syntax error at byte {node.start_byte} ({snippet!r})"
        if msg not in syntax_errors:
            syntax_errors.append(msg)

    def _walk(node: Any, wrappers: tuple[str, ...], depth: int, inside_command: bool = False) -> None:
        nonlocal has_pipes, has_subshells, has_background_ops

        if node.is_missing or node.type == "ERROR":
            _record_error(node)
            if node.type == "ERROR" and not inside_command:
                err_txt = _decode_node(source_bytes, node)
                if err_txt:
                    segments.append((err_txt, wrappers, depth))
            return

        if depth > max_depth + 2:
            return

        ntype = node.type

        if ntype == "pipeline":
            named_cmds = [c for c in node.children if c.is_named]
            if len(named_cmds) >= 2:
                has_pipes = True
            for child in node.children:
                _walk(child, wrappers, depth, inside_command=inside_command)
            return

        if ntype == "list":
            if _node_has_background_op(source_bytes, node):
                has_background_ops = True
            for child in node.children:
                _walk(child, wrappers, depth, inside_command=inside_command)
            return

        if ntype == "subshell":
            has_subshells = True
            next_wrappers = (*wrappers, "subshell")
            for child in node.children:
                _walk(child, next_wrappers, depth + 1, inside_command=False)
            return

        if ntype == "compound_statement":
            next_wrappers = (*wrappers, "group")
            for child in node.children:
                _walk(child, next_wrappers, depth, inside_command=False)
            return

        if ntype == "command_substitution":
            has_subshells = True
            raw_txt = _decode_node(source_bytes, node)
            if raw_txt.startswith("$("):
                inner = _strip_inner_delimiters(raw_txt, "$(", ")")
            elif raw_txt.startswith("`"):
                inner = _strip_inner_delimiters(raw_txt, "`", "`")
            else:
                inner = raw_txt
            if inner and inner not in seen_subshells:
                seen_subshells.add(inner)
                subshell_cmds.append((inner, depth + 1))
            for child in node.children:
                if child.has_error or child.is_missing or child.type == "ERROR":
                    _walk(child, (*wrappers, "subshell"), depth + 1, inside_command=True)
            return

        if ntype == "process_substitution":
            has_subshells = True
            raw_txt = _decode_node(source_bytes, node)
            inner = raw_txt[2:-1].strip() if len(raw_txt) >= 3 and raw_txt[1] == "(" and raw_txt[-1] == ")" else raw_txt
            if inner and inner not in seen_subshells:
                seen_subshells.add(inner)
                subshell_cmds.append((inner, depth + 1))
            return

        if ntype == "heredoc_body":
            body_text = _decode_node(source_bytes, node)
            if body_text:
                heredocs.append(body_text)
            return

        if ntype == "redirected_statement":
            body_node = node.child_by_field_name("body")
            # Если body — простая command, обрабатываем целиком вместе с редиректами
            if body_node is not None and body_node.type in ("command", "declaration_command"):
                full_text = _decode_node(source_bytes, node)
                if full_text:
                    segments.append((full_text, wrappers, depth))
                for child in node.children:
                    _walk(child, wrappers, depth, inside_command=True)
                return
            for child in node.children:
                _walk(child, wrappers, depth, inside_command=inside_command)
            return

        if ntype in ("command", "declaration_command"):
            if not inside_command:
                cmd_text = _decode_node(source_bytes, node)
                if cmd_text:
                    segments.append((cmd_text, wrappers, depth))
            # Продолжаем спуск, чтобы собрать вложенные command_substitution / process_substitution / ERROR
            for child in node.children:
                _walk(child, wrappers, depth, inside_command=True)
            return

        if ntype == "variable_assignment" and not inside_command:
            assign_text = _decode_node(source_bytes, node)
            if assign_text:
                segments.append((assign_text, wrappers, depth))
            for child in node.children:
                _walk(child, wrappers, depth, inside_command=True)
            return

        if ntype == "function_definition":
            next_wrappers = (*wrappers, "function")
            for child in node.children:
                _walk(child, next_wrappers, depth + 1, inside_command=False)
            return

        # Для управляющих конструкций (if/for/while/until/case/test_command) и прочих контейнеров
        for child in node.children:
            _walk(child, wrappers, depth, inside_command=inside_command)

    _walk(root, (), 0, inside_command=False)

    # Проверяем случай «команда с незакрытой кавычкой внутри ERROR-дерева»
    if root.has_error and not syntax_errors:
        syntax_errors.append("Bash grammar parser detected malformed syntax tree")

    return TreeSitterExtraction(
        segments=tuple(segments),
        subshell_commands=tuple(subshell_cmds),
        heredoc_payloads=tuple(heredocs),
        syntax_errors=tuple(syntax_errors),
        has_pipes=has_pipes,
        has_subshells=has_subshells,
        has_background_ops=has_background_ops,
    )


__all__ = [
    "TreeSitterExtraction",
    "extract_bash_grammar",
    "is_treesitter_available",
]
