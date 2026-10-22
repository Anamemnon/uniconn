# AGENTS.md — Архитектура и руководство для разработки uniconn

## Обзор проекта

`uniconn` — универсальная async-first Python-библиотека (Python 3.11+) для выполнения команд на удалённых и локальных хостах через единый интерфейс `Connection`. Управление зависимостями осуществляется через `uv`.

## Структура модулей (`src/uniconn/`)

- `_connection.py` — `Connection`: основной класс (фабрики `from_uri`, `from_config`, `from_dict`, `from_file`, `copy`, `with_overrides`, методы `run`, `run_bytes`, `run_commands`, `stream`, `open_shell`, `is_alive`, контекстные менеджеры `cd`, `env`, lifecycle-хуки `add_hook` (`before_run`, `after_run`, `on_error`), режим `dry_run`, безопасное повышение привилегий `sudo`/`sudo_user`/`sudo_password`, режим `sensitive`, файловые операции в памяти `read_file`, `write_file` и SFTP-методы `upload`, `download`, `chmod`, `stat`, `listdir`).
- `_shell.py` — `ShellSession`: stateful PTY shell-сессия поверх SSH (`execute` с поддержкой `str | Sequence[str]` и маркерным протоколом `__UNICONN_{uuid}__{exit_code}`, `send`, `receive`, `resize`, `close`).
- `_sync.py` — `SyncConnection` и `SyncShellSession`: синхронные обёртки на базе постоянного event loop в daemon-потоке (`asyncio.run_coroutine_threadsafe`), включая `cd`, `env`, `add_hook`, `run_bytes`, `read_file`, `write_file`.
- `_pool.py` — `ConnectionPool`: параллельное выполнение команд на группе хостов (`map`, `map_safe`, `map_with_callback`).
- `_session_pool.py` — `SSHSessionPool`: мультиплексинг SSH-каналов к одному хосту.
- `background/` — `ScreenPool`, `ScreenSession`, `LogPipeline`: управление фоновыми задачами в GNU screen.
- `transports/` — реализации транспортов (`_base.py`, `_ssh.py`, `_telnet.py`, `_serial.py`, `_local.py`, `bmc/_ipmi.py`).
- `cli.py` — CLI на базе `typer` и `rich` (`run`, `run-multi`, `bmc`, `shell`, `transports`, `screen-*`, `version`).

## Команды разработки (uv)

```bash
# Установка всех зависимостей (включая транспорты, CLI и dev-зависимости)
uv sync

# Запуск unit-тестов
uv run pytest -m "not integration"

# Линтинг и проверка типов
uv run ruff check src/
uv run pyright
```
