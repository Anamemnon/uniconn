# AGENTS.md — Архитектура и руководство для разработки uniconn

## Обзор проекта

`uniconn` (`v0.9.0`) — универсальная async-first Python-библиотека (Python 3.11+) для выполнения команд, инспекции хостов, идемпотентного управления состоянием и синхронизации файлов через единый фасад `Connection`. Управление зависимостями осуществляется через `uv`.

Для быстрого ознакомления с сигнатурами публичного API и URI-схемами используйте файл `llms.txt` в корне репозитория.

## Структура модулей (`src/uniconn/`)

- `_connection.py` / `core/connection.py` — `Connection`: тонкий фасад, предоставляющий фабрики (`from_uri`, `from_config`, `from_dict`, `from_file`, `from_inventory`), доменные сервисы (`conn.files`, `conn.state`, `conn.tunnels`), конвейер выполнения (`conn.pipeline`) и удобные методы верхнего уровня (`run`, `run_bytes`, `run_commands`, `run_script`, `ping`, `stream`, `expect`, `open_shell`, `gather_facts`, `ensure_package`, `ensure_service`, `ensure_line`, `sync_dir`, `write_template`, `forward_local_port`, `forward_remote_port` и др.).
- `core/` — ядро выполнения:
  - `pipeline.py` — `CommandRequest`, `CommandPipeline` и цепочка `CommandMiddleware` (`ContextMiddleware`, `SudoMiddleware`, `HookMiddleware`, `DryRunMiddleware`, `ObservabilityMiddleware`, `CircuitBreakerMiddleware`, `RateLimitMiddleware`, `RetryMiddleware`).
  - `resilience.py` — `CircuitBreaker`, `CircuitState` (`CLOSED` / `OPEN` / `HALF_OPEN`) и `RateLimiter` (async Token Bucket).
  - `context.py` — `ExecutionContext` и контекстные менеджеры `CwdContext`, `EnvContext`, `TempDirContext`.
  - `bridge.py` — `EventLoopPortal` (единый синглтон фонового event loop для синхронных вызовов) и `SyncContextBridge`.
- `services/` — выделенные доменные сервисы:
  - `files.py` — `FileOperationsService` и `DirectorySynchronizer` (файловые операции, SFTP и дельта-синхронизация `sync_dir`).
  - `templates.py` — `TemplateEngine` и `render_template` (`string.Template` и `jinja2`).
  - `facts.py` — `FactCollector`, `HostFacts`, `FactsDiffReport` и `diff_facts()` (сбор фактов и поиск расхождений между хостами).
  - `provisioning.py` — `StateManagementService`, паттерн «Стратегия» для пакетных менеджеров (`PackageManagerStrategy`: `AptStrategy`, `ApkStrategy`, `DnfYumStrategy`, `PacmanStrategy`, `ZypperStrategy`) и менеджеров сервисов (`ServiceManagerStrategy`: `SystemdStrategy`, `OpenRCStrategy`, `SysVStrategy`).
  - `tunnels.py` — `TunnelService` (`forward_local_port`, `forward_remote_port`).
- `config/` — `ConnectionConfig` и `InventoryLoader` (`config/inventory.py` — парсинг YAML/TOML/JSON инвентарей).
- `transports/` — протоколы возможностей ISP (`CommandTransport`, `FileCapableTransport`, `ShellCapableTransport`, `TunnelCapableTransport`, `require_capability` в `_base.py`/`base.py`), декомпозированный пакет `transports/ssh/` (`OpenSSHConfigParser`, `SSHJumpChainManager`, `SFTPClientAdapter`) и реализации `_ssh.py`, `_telnet.py`, `_serial.py`, `_local.py`, `bmc/_ipmi.py`.
- `shell/` и `_shell.py` — `ShellSession` (`shell/session.py`), `PosixMarkerProtocol` (`shell/marker_protocol.py`), `ExpectStateMachine` (`shell/expect_engine.py`).
- `sync/` и `_sync.py` — `SyncConnection`, `SyncShellSession`, `SyncConnectionPool` и синхронные обёртки доменных сервисов (`SyncFileOperationsService`, `SyncStateManagementService`, `SyncTunnelService`) на базе `EventLoopPortal`.
- `pool/` и `_pool.py` — `ConnectionPool` с единым движком конкурентного выполнения (`_fan_out_list`, `_fan_out_dict`), встроенными `RateLimiter` / пер-хостовыми `CircuitBreaker` и `PoolStreamMultiplexer` (`pool/stream_mux.py`).
- `_session_pool.py` — `SSHSessionPool`: мультиплексинг SSH-каналов к одному хосту с поддержкой `health_check`, `check_health()`, `rate_limit` и `circuit_breaker`.
- `background/` — `ScreenPool`, `ScreenSession`, `LogPipeline`: управление фоновыми задачами в GNU screen.
- `cli/` — модульный CLI на базе `cyclopts` и `rich` (`app.py`, `renderers.py`, `cmd_exec.py`, `cmd_files.py`, `cmd_ops.py`, `cmd_screen.py`).
- `result.py` (`Result`, `PingResult`, `SyncResult`, `EnsureResult`), `facts.py`, `hooks.py`, `_logging.py`, `exceptions.py` (`CircuitOpenError`), `py.typed`.

## Точка входа и веб-панель (`main.py` и `examples/dashboard/`)

- `main.py` — точка входа: без аргументов запускает CLI-демонстрацию, с флагом `--serve` запускает HTTP-сервер предпросмотра на `0.0.0.0:3000`.
- `examples/dashboard/server.py` и `examples/dashboard/index.html` — веб-интерфейс и API для интерактивного тестирования `uniconn`.

## Структура тестов (`tests/`)

Unit-тесты (`tests/unit/`, 34 модуля, 470 тестов) сгруппированы по тематическим пакетам:
- `tests/unit/core/` — базовые абстракции (`Connection`, `SyncConnection`, `Result`, `ShellSession`, URI, конфиги, плагины, исключения, `structlog`-логирование).
- `tests/unit/transports/` — тесты транспортов (`SSH`, `Telnet`, `Serial`, `Local`, `IPMI`, `BaseTransport`) и SFTP.
- `tests/unit/pools/` — `ConnectionPool` и `SSHSessionPool`.
- `tests/unit/screen/` — `ScreenPool`, `ScreenSession`, `LogPipeline`, `ScreenConfig`, cleanup.
- `tests/unit/cli/` — CLI-команды (`cyclopts` + `rich`), фоновые screen-команды и интерактивная веб-панель (`examples/dashboard/`).
- `tests/unit/releases/` — приёмочные наборы тестов по релизам (`v0.3.0` – `v0.9.0`).
- `tests/integration/` — интеграционные тесты с Docker/testcontainers.

## Архитектурные инварианты и правила тестирования для ИИ-агентов

Подробный навык тестирования и обеспечения стабильности описан в `.claude/skills/testing-and-stability/SKILL.md` и `.cursor/rules/testing-and-stability.mdc`.

1. **Async + Sync паритет**: Любой новый публичный метод или контекстный менеджер в `Connection` обязан иметь синхронное отражение в `SyncConnection`.
2. **Экспорт API**: Все публичные классы и функции должны быть экспортированы в `src/uniconn/__init__.py` (`__all__`) и отражены в `llms.txt`.
3. **Экономия контекста (`FEATURES.md`)**: Файл `FEATURES.md` содержит полный каталог реализованных возможностей и архитектурных решений библиотеки. **Не нужно читать `FEATURES.md` в начале каждой задачи** (чтобы не засорять контекстное окно ИИ-агента) — используйте `llms.txt` для быстрого обзора API, а к `FEATURES.md` обращайтесь только тогда, когда нужно точечно сверить статус реализации конкретной возможности или дополнить список после нового этапа.
4. **Качество кода**: Ограничение длины строки — **120 символов** (`ruff`), типизация — `pyright` в режиме `standard` (0 ошибок).
5. **Обязательный запуск и написание тестов**:
   - После любых изменений кода обязательно запускайте `uv run pytest -m "not integration" -q --tb=short | tail -n 5` (для экономии контекстного окна выводится только итоговая сводка; при наличии упавших тестов используйте `uv run pytest -m "not integration" -q --tb=short --lf | tail -n 30`).
   - Каждая новая фича, метод, хук или исправление бага должны сопровождаться новыми unit-тестами в соответствующей поддиректории `tests/unit/<domain>/` для поддержания покрытия и стабильности проекта.
   - В `pytest` включено правило `error::RuntimeWarning`: не допускайте неожидаемых корутин (`coroutine was never awaited`). При мокировании `StreamWriter` синхронные методы (`write`, `close`) задавайте через `MagicMock()`, а не `AsyncMock()`.

## Команды разработки (uv)

```bash
# Установка всех зависимостей (включая транспорты, CLI и dev-зависимости)
uv sync

# Запуск unit-тестов с кратким выводом для экономии контекста (0 RuntimeWarning)
uv run pytest -m "not integration" -q --tb=short | tail -n 5

# Повторный запуск только упавших тестов с трейсбеком (при отладке)
uv run pytest -m "not integration" -q --tb=short --lf | tail -n 30

# Линтинг (лимит строки 120 символов) и проверка типов
uv run ruff check src/
uv run pyright
```
