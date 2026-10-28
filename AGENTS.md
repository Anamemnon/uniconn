# AGENTS.md — Архитектура и руководство для разработки uniconn

## Обзор проекта

`uniconn` — универсальная async-first Python-библиотека (Python 3.11+) для выполнения команд, инспекции хостов, идемпотентного управления состоянием и синхронизации файлов через единый фасад `Connection`. Управление зависимостями осуществляется через `uv`.

Для быстрого ознакомления с сигнатурами публичного API и URI-схемами используйте файл `llms.txt` в корне репозитория.

## Структура модулей (`src/uniconn/`)

- `core/connection.py` (реэкспорт в `_connection.py`) — `Connection` и `OperationObserver`: тонкий фасад, предоставляющий фабрики (`from_uri`, `from_config`, `from_dict`, `from_file`, `from_inventory`), доменные сервисы (`conn.files`, `conn.state`, `conn.tunnels`), конвейер выполнения (`conn.pipeline`) и удобные методы верхнего уровня (`run`, `run_bytes`, `run_commands`, `run_script`, `ping`, `wait_for_connection`, `wait_for_port`, `wait_for_path`, `stream`, `expect`, `open_shell`, `gather_facts`, `checksum`, `ensure_package`, `ensure_service`, `ensure_line`, `ensure_file`, `ensure_directory`, `ensure_user`, `ensure_authorized_key`, `ensure_systemd_unit`, `ensure_sysctl`, `sync_dir`, `write_template`, `forward_local_port`, `forward_remote_port`, `use_cassette` и др.).
- `core/` — ядро выполнения:
  - `pipeline.py` — `CommandRequest`, `CommandPipeline`, типизированные хуки (`BeforeRunHook`, `AfterRunHook`, `OnErrorHook`) и цепочка `CommandMiddleware` (`ContextMiddleware`, `SudoMiddleware`, `HookMiddleware`, `DryRunMiddleware`, `ObservabilityMiddleware`, `CircuitBreakerMiddleware`, `RateLimitMiddleware`, `RetryMiddleware`).
  - `resilience.py` — `CircuitBreaker`, `CircuitState` (`CLOSED` / `OPEN` / `HALF_OPEN`) и `RateLimiter` (async Token Bucket).
  - `context.py` — `ExecutionContext` и контекстные менеджеры `CwdContext`, `EnvContext`, `TempDirContext`.
  - `bridge.py` — `EventLoopPortal` (единый синглтон фонового event loop для синхронных вызовов) и `SyncContextBridge`.
- `services/` — выделенные доменные сервисы:
  - `files.py` — `FileOperationsService` и `DirectorySynchronizer` (файловые операции, атомарная запись `atomic=True`, контроль хешей `checksum()` / `verify=True`, SFTP и дельта-синхронизация `sync_dir`).
  - `templates.py` — `TemplateEngine` и `render_template` (`string.Template` и `jinja2`).
  - `facts.py` и `facts_models.py` (реэкспорт в `_facts.py`) — `FactCollector`, `HostFacts`, `FactsDiffReport` и `diff_facts()` (сбор фактов и поиск расхождений между хостами).
  - `provisioning.py` — `StateManagementService` (`ensure_package`, `ensure_service`, `ensure_line`, `ensure_file`, `ensure_directory`, `ensure_user`, `ensure_authorized_key`, `ensure_systemd_unit`, `ensure_sysctl` с расчётом unified diff при `dry_run=True`), паттерн «Стратегия» для пакетных менеджеров (`PackageManagerStrategy`: `AptStrategy`, `ApkStrategy`, `DnfYumStrategy`, `PacmanStrategy`, `ZypperStrategy`) и менеджеров сервисов (`ServiceManagerStrategy`: `SystemdStrategy`, `OpenRCStrategy`, `SysVStrategy`).
  - `tunnels.py` — `TunnelService` (`forward_local_port`, `forward_remote_port`).
- `config/` — `models.py` (`ConnectionConfig`), `secrets.py` (`SecretResolver` для `env://` и `file://` с `?default=`), `uri.py` (`URIParser`) и `inventory.py` (`InventoryLoader` — парсинг YAML/TOML/JSON инвентарей).
- `transports/` — протоколы возможностей ISP (`CommandTransport`, `FileCapableTransport`, `FileStat`, `ShellCapableTransport`, `ShellProcessProtocol`, `TunnelCapableTransport`, `require_capability` в `base.py`), декомпозированный пакет `transports/replay/` (`ReplayTransport`, `Cassette`, `CassetteDiffReport`, `InteractionDiff`, `CassetteContext`, `CassetteTransportProxy`), декомпозированный пакет `transports/ssh/` (`OpenSSHConfigParser`, `SSHJumpChainManager`, `SFTPClientAdapter`) и реализации `_ssh.py`, `_telnet.py`, `_serial.py`, `_local.py`, `_docker.py` (`DockerTransport`, `PodmanTransport`), `_kubectl.py` (`KubectlTransport`), `bmc/_ipmi.py` (`IPMITransport`), `bmc/_redfish.py` (`RedfishTransport` на базе `niquests`).
- `shell/` (реэкспорт в `_shell.py`) — `ShellSession` (`shell/session.py`), `PosixMarkerProtocol` (`shell/marker_protocol.py`), `ExpectStateMachine` (`shell/expect_engine.py`).
- `sync/` (реэкспорт в `_sync.py`) — `connection.py` (`SyncConnection`), `shell.py` (`SyncShellSession`), `pool.py` (`SyncConnectionPool`) и `services.py` (`SyncFileOperationsService`, `SyncStateManagementService`, `SyncTunnelService`, `SyncDiagnosticSession`) на базе `EventLoopPortal`.
- `pool/` (реэкспорты в `_pool.py` и `_session_pool.py`) — `connection_pool.py` (`ConnectionPool` с `_fan_out_list` / `_fan_out_dict`, батчевой раскаткой `batch_size` / `max_fail_ratio`, `select()` и `use_cassette`), `session_pool.py` (`SSHSessionPool` с адаптивным авто-понижением лимитов и `resize()`) и `stream_mux.py` (`PoolStreamMultiplexer`).
- `background/` — `ScreenPool`, `ScreenSession`, `LogPipeline`, `DiagnosticSession`: управление фоновыми задачами и диагностическими сессиями.
- `cli/` — модульный CLI на базе `cyclopts` и `rich` (`app.py`, `renderers.py`, `cmd_exec.py`, `cmd_files.py`, `cmd_ops.py`, `cmd_screen.py`, `cmd_cassette.py`).
- `result.py` (`Result`, `PingResult`, `SyncResult`, `EnsureResult`), `hooks.py`, `telemetry.py`, `pytest_plugin.py`, `_logging.py`, `exceptions.py` (`ConfigurationError`, `CircuitOpenError`, `BatchAbortedError`, `CassetteError`), `py.typed`.

## Точка входа и веб-панель (`main.py` и `examples/dashboard/`)

- `main.py` — точка входа: без аргументов запускает CLI-демонстрацию, с флагом `--serve` запускает HTTP-сервер предпросмотра на `0.0.0.0:3000`.
- `examples/dashboard/server.py` и `examples/dashboard/index.html` — веб-интерфейс и API для интерактивного тестирования `uniconn`.

## Структура тестов (`tests/`)

Unit-тесты (`tests/unit/`, 40 модулей, 607 тестов) сгруппированы строго по доменным пакетам (зеркало `src/uniconn/`):
- `tests/unit/core/` — базовые абстракции (`Connection`, `SyncConnection`, `Result`, `ShellSession`, `ExpectStateMachine`, `PosixMarkerProtocol`, `wait_for_*`, `CircuitBreaker`, `RateLimiter`, `SecretResolver`, URI, конфиги, хуки, плагины, исключения, `structlog`-логирование и OpenTelemetry).
- `tests/unit/services/` — доменные сервисы (`FileOperationsService`, `checksum`, `atomic=True`, `sync_dir`, `write_template`, `FactCollector`, `diff_facts`, `StateManagementService` и системные примитивы `ensure_*`).
- `tests/unit/transports/` — тесты транспортов (`SSH`, `Telnet`, `Serial`, `Local`, `IPMI`, `Redfish`, `Docker`, `Podman`, `Kubectl`, `Replay`/`Cassette`, `BaseTransport`), SFTP и `pytest_plugin`.
- `tests/unit/pools/` — `ConnectionPool` (включая батчинг `batch_size`/`max_fail_ratio`, `BatchAbortedError` и `select()`) и `SSHSessionPool`.
- `tests/unit/screen/` — `ScreenPool`, `ScreenSession`, `LogPipeline`, `DiagnosticSession`, `ScreenConfig`, cleanup.
- `tests/unit/cli/` — CLI-команды (`cyclopts` + `rich`), фоновые screen-команды и интерактивная веб-панель (`examples/dashboard/`).
- `tests/unit/architecture/` — архитектурные инварианты и чистота публичного API (`__all__`).
- `tests/integration/` — интеграционные тесты с Docker/testcontainers.

## Архитектурные инварианты и правила тестирования для ИИ-агентов

Подробный навык тестирования и обеспечения стабильности описан в `.claude/skills/testing-and-stability/SKILL.md` и `.cursor/rules/testing-and-stability.mdc`, а принципы чистого и минималистичного проектирования (`ub-mode`) — в `.claude/skills/ub-mode/SKILL.md` и `.cursor/rules/ub-mode.mdc`.

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

# Замер задержек и накладных расходов ядра (CommandPipeline, EventLoopPortal, DirectorySynchronizer)
uv run python -m benchmarks.overhead_bench --check-thresholds

# Линтинг (лимит строки 120 символов) и проверка типов
uv run ruff check src/ benchmarks/
uv run pyright

# Быстрый запуск задач разработки через poethepoet
uv run poe check      # Комплексная проверка: lint + typecheck + test-arch
uv run poe lint       # Проверка стиля и качества кода (ruff)
uv run poe typecheck  # Проверка статической типизации (pyright)
uv run poe bench      # Замер накладных расходов ядра (SLA)
uv run poe test       # Запуск всех unit-тестов
```

