# tests/unit/transports/test_windows_polyfills.py
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from uniconn.config.models import ConnectionConfig
from uniconn.transports._local import LocalTransport, _apply_windows_polyfills


def _run_cmd(cmd: list[str], input_data: str | None = None) -> subprocess.CompletedProcess[str]:
    """Вспомогательный запуск команды через subprocess для прямой проверки полифиллов."""
    return subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
    )


def test_apply_windows_polyfills_empty():
    """Пустой список аргументов возвращает None."""
    assert _apply_windows_polyfills([]) is None


def test_python3_polyfill_immutability(monkeypatch: pytest.MonkeyPatch):
    """Полифилл python3 возвращает новый список и не мутирует входные parts."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)
    parts = ["python3", "-c", "import sys; sys.stdout.write('ok')"]
    parts_copy = list(parts)

    cmd = _apply_windows_polyfills(parts)
    assert parts == parts_copy  # Входной список не изменился!
    assert cmd is not None
    assert cmd[0] == sys.executable
    assert cmd[1:] == parts[1:]

    proc = _run_cmd(cmd)
    assert proc.returncode == 0
    assert proc.stdout == "ok"


def test_pwd_polyfill(monkeypatch: pytest.MonkeyPatch):
    """Полифилл pwd завершается переводом строки \\n и выводит текущую директорию."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)
    cmd = _apply_windows_polyfills(["pwd"])
    assert cmd is not None

    proc = _run_cmd(cmd)
    assert proc.returncode == 0
    assert proc.stdout.endswith("\n")
    assert Path(proc.stdout.strip()).resolve() == Path.cwd().resolve()


def test_echo_polyfill_basic_and_flags():
    """Полифилл echo поддерживает -n (без \\n), -e (escape-последовательности) и обычный вывод."""
    # Обычный вывод с переводом строки
    cmd1 = _apply_windows_polyfills(["echo", "hello", "world"])
    assert cmd1 is not None
    proc1 = _run_cmd(cmd1)
    assert proc1.returncode == 0
    assert proc1.stdout == "hello world\n"

    # Флаг -n: без перевода строки
    cmd2 = _apply_windows_polyfills(["echo", "-n", "no-newline"])
    assert cmd2 is not None
    proc2 = _run_cmd(cmd2)
    assert proc2.returncode == 0
    assert proc2.stdout == "no-newline"

    # Флаг -e: интерпретация \n и \t
    cmd3 = _apply_windows_polyfills(["echo", "-e", r"line1\nline2\ttab"])
    assert cmd3 is not None
    proc3 = _run_cmd(cmd3)
    assert proc3.returncode == 0
    assert proc3.stdout == "line1\nline2\ttab\n"


def test_echo_polyfill_safety_against_injection():
    """Полифилл echo защищает от инъекций спецсимволов &, |, >, <."""
    dangerous_arg = "foo & dir | echo injected > should_not_exist.txt"
    cmd = _apply_windows_polyfills(["echo", dangerous_arg])
    assert cmd is not None

    proc = _run_cmd(cmd)
    assert proc.returncode == 0
    assert dangerous_arg in proc.stdout
    assert not Path("should_not_exist.txt").exists()


def test_touch_polyfill_no_args_error(monkeypatch: pytest.MonkeyPatch):
    """touch без аргументов возвращает ненулевой код и пишет ошибку в stderr."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)
    cmd = _apply_windows_polyfills(["touch"])
    assert cmd is not None

    proc = _run_cmd(cmd)
    assert proc.returncode == 1
    assert "touch: missing file operand" in proc.stderr


def test_touch_polyfill_creates_file_and_ignores_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """touch создает файлы, не создает артефактов от флагов вроде -a, и уважает -c/--no-create."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)

    # 1. touch -a file.txt
    target1 = tmp_path / "sub" / "file1.txt"
    cmd1 = _apply_windows_polyfills(["touch", "-a", str(target1)])
    assert cmd1 is not None
    proc1 = _run_cmd(cmd1)
    assert proc1.returncode == 0
    assert target1.exists()
    assert not Path("-a").exists()

    # 2. touch -c nonexistent.txt не должен создавать отсутствующий файл
    target2 = tmp_path / "nonexistent.txt"
    cmd2 = _apply_windows_polyfills(["touch", "-c", str(target2)])
    assert cmd2 is not None
    proc2 = _run_cmd(cmd2)
    assert proc2.returncode == 0
    assert not target2.exists()


def test_cat_polyfill_files_and_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """cat читает файлы, потоки stdin через '-' и сообщает об ошибках."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)

    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f1.write_text("Hello ", encoding="utf-8")
    f2.write_text("World!", encoding="utf-8")

    # Чтение двух файлов
    cmd1 = _apply_windows_polyfills(["cat", str(f1), str(f2)])
    assert cmd1 is not None
    proc1 = _run_cmd(cmd1)
    assert proc1.returncode == 0
    assert proc1.stdout == "Hello World!"

    # Чтение из stdin через '-'
    cmd2 = _apply_windows_polyfills(["cat", "-"])
    assert cmd2 is not None
    proc2 = _run_cmd(cmd2, input_data="piped data")
    assert proc2.returncode == 0
    assert proc2.stdout == "piped data"

    # Несуществующий файл
    cmd3 = _apply_windows_polyfills(["cat", str(tmp_path / "absent.txt")])
    assert cmd3 is not None
    proc3 = _run_cmd(cmd3)
    assert proc3.returncode == 1
    assert "No such file or directory" in proc3.stderr


def test_tail_polyfill_options_and_safety(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """tail корректно парсит -n N, не путает число с файлом, читает stdin и файлы."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)

    sample = tmp_path / "lines.txt"
    sample.write_text("\n".join(f"line_{i}" for i in range(1, 21)) + "\n", encoding="utf-8")

    # 1. tail -n 5 lines.txt (не должен пытаться открыть файл с именем '5')
    cmd1 = _apply_windows_polyfills(["tail", "-n", "5", str(sample)])
    assert cmd1 is not None
    proc1 = _run_cmd(cmd1)
    assert proc1.returncode == 0
    assert proc1.stdout.strip().splitlines() == [f"line_{i}" for i in range(16, 21)]

    # 2. tail -3 lines.txt
    cmd2 = _apply_windows_polyfills(["tail", "-3", str(sample)])
    assert cmd2 is not None
    proc2 = _run_cmd(cmd2)
    assert proc2.returncode == 0
    assert proc2.stdout.strip().splitlines() == ["line_18", "line_19", "line_20"]

    # 3. tail из stdin без аргументов (последние 10 строк)
    cmd3 = _apply_windows_polyfills(["tail"])
    assert cmd3 is not None
    proc3 = _run_cmd(cmd3, input_data="\n".join(f"in_{i}" for i in range(1, 16)) + "\n")
    assert proc3.returncode == 0
    assert proc3.stdout.strip().splitlines() == [f"in_{i}" for i in range(6, 16)]


def test_printf_polyfill_formatting_and_escapes(monkeypatch: pytest.MonkeyPatch):
    """printf поддерживает спецификаторы формата, escape-символы и устойчив к кавычкам."""
    monkeypatch.setattr("uniconn.transports._local._safe_which", lambda binary: None)

    # 1. Без аргументов -> usage error
    cmd0 = _apply_windows_polyfills(["printf"])
    assert cmd0 is not None
    proc0 = _run_cmd(cmd0)
    assert proc0.returncode == 1
    assert "usage: printf format" in proc0.stderr

    # 2. Форматирование %s, %d, %.2f, %%
    cmd1 = _apply_windows_polyfills(["printf", "%s: %d, rate: %.2f%%\n", "Alice", "42", "99.5"])
    assert cmd1 is not None
    proc1 = _run_cmd(cmd1)
    assert proc1.returncode == 0
    assert proc1.stdout == "Alice: 42, rate: 99.50%\n"

    # 3. Escape-символы \n и \t
    cmd2 = _apply_windows_polyfills(["printf", "Row1\nRow2\tCol2\n"])
    assert cmd2 is not None
    proc2 = _run_cmd(cmd2)
    assert proc2.returncode == 0
    assert proc2.stdout == "Row1\nRow2\tCol2\n"

    # 4. Аргументы с одинарными и двойными кавычками (it's "quoted")
    tricky_str = 'it\'s a "tricky" test & arg'
    cmd3 = _apply_windows_polyfills(["printf", "Result: %s\n", tricky_str])
    assert cmd3 is not None
    proc3 = _run_cmd(cmd3)
    assert proc3.returncode == 0
    assert proc3.stdout == f"Result: {tricky_str}\n"


@pytest.mark.asyncio
async def test_local_transport_integration_with_polyfills(tmp_path: Path):
    """Интеграционная проверка вызова команд через LocalTransport.run."""
    cfg = ConnectionConfig(transport="local", host="localhost")
    transport = LocalTransport(cfg)
    await transport.connect()

    try:
        # 1. echo как список с амперсандом
        r1 = await transport.run(["echo", "safe & sound"])
        assert r1.exit_code == 0
        assert r1.stdout.strip() == "safe & sound"

        # 2. touch и cat через transport
        f = tmp_path / "test_run.txt"
        r2 = await transport.run(["touch", str(f)])
        assert r2.exit_code == 0
        assert f.exists()

        f.write_text("line A\nline B\nline C\n", encoding="utf-8")
        r3 = await transport.run(["cat", str(f)])
        assert r3.exit_code == 0
        assert "line B" in r3.stdout

        # 3. tail через transport
        r4 = await transport.run(["tail", "-n", "2", str(f)])
        assert r4.exit_code == 0
        assert r4.stdout.strip().splitlines() == ["line B", "line C"]

        # 4. printf через transport
        r5 = await transport.run(["printf", "Item: %s, Qty: %04d\n", "Widget", "7"])
        assert r5.exit_code == 0
        assert r5.stdout == "Item: Widget, Qty: 0007\n"
    finally:
        await transport.disconnect()
