# AGENTS.md — Архитектура и руководство для разработки uniconn

## Обзор проекта

`uniconn` (`v0.6.0`) — универсальная async-first Python-библиотека (Python 3.11+) для выполнения команд на удалённых и локальных хостах через единый интерфейс `Connection`. Управление зависимостями осуществляется через `uv`.

Для быстрого ознакомления с сигнатурами публичного API и URI-схемами используйте файл `llms.txt` в корне репозитория.

## Структура модулей (`src/uniconn/`)

- `_connection.py` — `Connection`: основной класс (фабрики `from_uri`, `from_config`, `from_dict`, `from_file` с поддержкой групп и хостов, `from_inventory`, `copy`, `with_overrides`, методы `run`, `run_bytes`, `run_commands`, `stream`, `open_shell`, `is_alive`, контекстные менеджеры `cd`, `env`, `temp_dir`, lifecycle-хуки `add_hook` (`before_run`, `after_run`, `on_error`), режим `dry_run`, безопасное повышение привилегий `sudo`/`sudo_user`/`sudo_password`, режим `sensitive`, файловые операции `read_file`, `write_file`, `exists`, `mkdir` и SFTP-методы `upload`, `download`, `chmod`, `stat`, `listdir`).
- `result.py` — `Result`: результат выполнения команды (`ok`, `__bool__`, `text`, `lines`, `json()`, `to_dict()`, `raise_for_status()`).
- `hooks.py` — готовые пресеты lifecycle-хуков (`audit_log_hook`, `allowlist_hook`, `blocklist_hook`, `MetricsCollector`, `metrics_collector_hook`).
- `_shell.py` — `ShellSession`: stateful PTY shell-сессия поверх SSH, Local и Telnet (`execute` с поддержкой `str | Sequence[str]` и маркерным протоколом `__UNICONN_{uuid}__{exit_code}`, `send`, `receive`, `resize`, `close`).
- `_sync.py` — `SyncConnection` и `SyncShellSession`: синхронные обёртки на базе постоянного event loop в daemon-потоке (`asyncio.run_coroutine_threadsafe`), включая `cd`, `env`, `temp_dir`, `add_hook`, `run_bytes`, `read_file`, `write_file`, `exists`, `mkdir`.
- `_pool.py` — `ConnectionPool`: параллельное выполнение команд и групповых операций на группе хостов (`async with pool:`, `from_file`, `map`, `map_safe`, `map_with_callback`, `upload`, `download`, `apply`).
- `_session_pool.py` — `SSHSessionPool`: мультиплексинг SSH-каналов к одному хосту с поддержкой `health_check` и `check_health()`.
- `background/` — `ScreenPool`, `ScreenSession`, `LogPipeline`: управление фоновыми задачами в GNU screen.
- `transports/` — реализации транспортов (`_base.py`, `_ssh.py` с парсером `~/.ssh/config`, Jump-хостами и `ProxyCommand`/`proxy_command`, `_telnet.py`, `_serial.py`, `_local.py`, `bmc/_ipmi.py`).
- `cli.py` — CLI на базе `typer` и `rich` (`run`, `run-multi` с `--inventory`/`--group`, `upload`, `download`, `bmc`, `shell`, `transports`, `screen-*`, `version`).
- `py.typed` — маркер типизации пакета (PEP 561).

## Точка входа и веб-панель (`main.py` и `examples/dashboard/`)

- `main.py` — точка входа: без аргументов запускает CLI-демонстрацию, с флагом `--serve` запускает HTTP-сервер предпросмотра на `0.0.0.0:3000`.
- `examples/dashboard/server.py` и `examples/dashboard/index.html` — веб-интерфейс и API для интерактивного тестирования `uniconn`.

## Архитектурные инварианты для ИИ-агентов

1. **Async + Sync паритет**: Любой новый публичный метод или контекстный менеджер в `Connection` обязан иметь синхронное отражение в `SyncConnection`.
2. **Экспорт API**: Все публичные классы и функции должны быть экспортированы в `src/uniconn/__init__.py` (`__all__`) и отражены в `llms.txt`.
3. **Качество кода**: Ограничение длины строки — 100 символов (`ruff`), типизация — `pyright` в режиме `standard` (0 ошибок).

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
