# src/uniconn/cli/renderers.py
"""Унифицированный рендеринг вывода CLI (Rich Panel / Table / JSON / Plain), сборка пула и тестовый раннер."""

from __future__ import annotations

import contextlib
import io
import json
import sys
from dataclasses import dataclass
from typing import Any

try:
    import cyclopts
    from cyclopts import Parameter
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    HAVE_CLI_DEPS = True
except ImportError:
    cyclopts: Any = None
    Parameter: Any = None
    box: Any = None
    Console: Any = None
    Panel: Any = None
    Table: Any = None
    HAVE_CLI_DEPS = False


def check_cli_deps() -> None:
    """Проверить наличие CLI зависимостей (``cyclopts`` и ``rich``)."""
    if not HAVE_CLI_DEPS:
        print(
            "CLI dependencies not installed. Install: pip install uniconn[cli]",
            file=sys.stderr,
        )
        sys.exit(1)


@dataclass(slots=True)
class CliResult:
    """Результат вызова CLI-приложения через ``CliRunner``."""

    exit_code: int
    stdout: str
    stderr: str
    exception: BaseException | None = None

    @property
    def output(self) -> str:
        """Объединённый вывод (stdout + stderr)."""
        return self.stdout + self.stderr


class CliRunner:
    """Тестовый раннер для вызова ``cyclopts.App`` с перехватом потоков ввода-вывода."""

    def invoke(
        self,
        app: Any,
        args: list[str] | tuple[str, ...] | str | None = None,
        *,
        input: str | None = None,
    ) -> CliResult:
        """Выполнить команду CLI-приложения и вернуть ``CliResult``."""
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        old_stdin = sys.stdin
        if input is not None:
            sys.stdin = io.StringIO(input)
        exit_code = 0
        exc_caught: BaseException | None = None
        try:
            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                target = app.meta if getattr(app, "_meta", None) is not None else app
                target(args)
        except SystemExit as exc:
            if exc.code is None:
                exit_code = 0
            elif isinstance(exc.code, int):
                exit_code = exc.code
            else:
                exit_code = 1
        except BaseException as exc:
            exit_code = 1
            exc_caught = exc
        finally:
            sys.stdin = old_stdin

        return CliResult(
            exit_code=exit_code,
            stdout=stdout_buf.getvalue(),
            stderr=stderr_buf.getvalue(),
            exception=exc_caught,
        )


class CLIOutputRenderer:
    """Отвечает за форматирование результатов команд и ошибок в CLI."""

    def __init__(self, console: Any) -> None:
        """Инициализировать рендерер с экземпляром Rich Console."""
        self.console = console

    def print_error_and_exit(self, error: BaseException, title: str = "Exception") -> None:
        """Вывести панель с ошибкой и завершить процесс с кодом 1."""
        self.console.print(
            Panel(
                f"[red]ERROR:[/red] {error}",
                title=title,
                border_style="red",
            )
        )
        sys.exit(1)

    def render_single_result(self, result: Any, output_format: str = "panel") -> None:
        """Вывести результат одиночной команды в формате ``json``, ``plain`` или ``panel``."""
        if output_format == "json":
            self.console.print(json.dumps(result.to_dict(), indent=2))
            if not result.ok:
                sys.exit(result.exit_code)
            return

        if output_format == "plain":
            if result.stdout:
                self.console.print(result.stdout.rstrip())
            if result.stderr:
                self.console.print(result.stderr.rstrip(), style="red")
            if not result.ok:
                sys.exit(result.exit_code)
            return

        if result.ok:
            self.console.print(
                Panel(
                    f"[green]OK[/green] Command executed successfully\n"
                    f"[dim]Time:[/dim] {result.duration:.2f}s | "
                    f"[dim]Exit code:[/dim] {result.exit_code}",
                    title="Result",
                    border_style="green",
                )
            )
            if result.stdout:
                self.console.print("[bold]stdout:[/bold]")
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print("[bold red]stderr:[/bold red]")
                self.console.print(result.stderr)
        else:
            self.console.print(
                Panel(
                    f"[red]FAILED[/red] Command failed\n"
                    f"[dim]Time:[/dim] {result.duration:.2f}s | "
                    f"[dim]Exit code:[/dim] {result.exit_code}",
                    title="Error",
                    border_style="red",
                )
            )
            if result.stdout:
                self.console.print("[bold]stdout:[/bold]")
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print("[bold red]stderr:[/bold red]")
                self.console.print(result.stderr)
            sys.exit(result.exit_code)


def build_cli_pool(
    cli_pkg: Any,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    max_concurrent: int,
    logger: Any,
) -> Any:
    """Создать экземпляр ``ConnectionPool`` из списка URI или файла инвентаря."""
    if inventory:
        return cli_pkg.ConnectionPool.from_file(
            inventory,
            group=group,
            max_concurrent=max_concurrent,
            logger=logger,
        )
    return cli_pkg.ConnectionPool(
        host_uris,
        max_concurrent=max_concurrent,
        logger=logger,
    )
