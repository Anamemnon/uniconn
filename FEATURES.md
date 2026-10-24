# Реализованные возможности и архитектура библиотеки uniconn

> **Версия**: v0.9.0 | **470 unit-тестов** | 34 файла тестов (6 пакетов в `tests/unit/`) | 5 транспортов | Модульный CLI (`cyclopts` + `rich`) | Интерактивная веб-панель (`examples/dashboard/`) | PEP 561 (`py.typed`)
>
> **Для ИИ-агентов**: этот файл (`FEATURES.md`) является полным каталогом реализованных фич и архитектурных решений библиотеки `uniconn`. **Не загружайте его в контекст при каждом запросе** — используйте `llms.txt` для быстрого обзора сигнатур API, а к `FEATURES.md` обращайтесь только по требованию (on-demand), когда нужно сверить наличие конкретной функциональности или обновить список возможностей после релиза.
>
> Обозначения: ✅ реализовано | ⚠️ частично | ❌ не реализовано (осознанно исключено)

## Сводка реализованных возможностей

| Область | Статус | Детали |
|---------|--------|--------|
| Транспорты | ✅ 5/5 | SSH (`~/.ssh/config`, цепочки Jump-хостов `SSHJumpChainManager`, `ProxyCommand`), Telnet, Serial/UART, Local, IPMI |
| Протоколы ISP | ✅ `transports.base` | `CommandTransport`, `FileCapableTransport`, `ShellCapableTransport`, `TunnelCapableTransport`, `require_capability()` |
| Конвейер команд | ✅ `CommandPipeline` | Цепочка `CommandMiddleware`: `Context`, `Sudo`, `Hook`, `DryRun`, `Observability`, `CircuitBreaker`, `RateLimit`, `Retry` (`conn.pipeline`) |
| Отказоустойчивость (`v0.9.0`) | ✅ `CircuitBreaker` + `RateLimiter` | Состояния `CLOSED` → `OPEN` → `HALF_OPEN` (`CircuitOpenError`), Token Bucket `RateLimiter` на уровне `Connection`, `ConnectionPool` и `SSHSessionPool` |
| Доменные сервисы | ✅ `conn.files` / `state` / `tunnels` | `FileOperationsService`, `DirectorySynchronizer`, `StateManagementService`, `FactCollector`, `TunnelService`, `TemplateEngine` |
| SSH мультиплексинг | ✅ `SSHSessionPool` | До N каналов на соединение, авто-создание новых, `health_check`, `check_health()`, `rate_limit`, `circuit_breaker` |
| Screen-сессии | ✅ `ScreenPool` | Долгоживущие команды в GNU screen, `LogPipeline`, `ScreenSession`, многоуровневый cleanup |
| PTY Shell & Expect | ✅ `ShellSession` + `expect()` | Stateful сессии (`open_shell`, `execute`, `SyncShellSession`) для SSH, Local, Telnet, Serial + декларативный `expect()` (`ExpectStateMachine`) |
| Инспекция и сравнение | ✅ `gather_facts()` + `diff_facts()` | `FactCollector` → `HostFacts` + детектор конфигурационного дрейфа `diff_facts()` (`FactsDiffReport`, `uniconn facts --diff`) |
| Идемпотентность | ✅ `ensure_*` (`EnsureResult`) | `ensure_package` (`apt`/`apk`/`dnf`/`yum`/`pacman`/`zypper`), `ensure_service` (`systemd`/`openrc`/`sysv`), `ensure_line` |
| Синхронизация и шаблоны | ✅ `sync_dir` & `write_template` | Дельта-синхронизация директорий (`SyncResult`, `delete`, `exclude`) и рендеринг шаблонов (`jinja2` / `string.Template`) |
| Выполнение скриптов | ✅ `run_script()` / `exec-script` | Автозагрузка локального скрипта в `temp_dir`, `chmod 0o700`, запуск с аргументами/интерпретатором и гарантированная очистка |
| SSH-туннелирование | ✅ `TunnelService` | Контекстные менеджеры `forward_local_port` (`-L`) и `forward_remote_port` (`-R`) в async и sync режимах |
| API (Async + Sync) | ✅ Полный паритет | `Connection` ↔ `SyncConnection`, `ConnectionPool` ↔ `SyncConnectionPool`, `ShellSession` ↔ `SyncShellSession` на базе `EventLoopPortal` |
| Фабрики и инвентарь | ✅ 5 методов + `InventoryLoader` | `from_uri`, `from_config`, `from_dict`, `from_file` (YAML/TOML/JSON с `host=`, `group=`, `defaults`), `from_inventory` |
| Клонирование | ✅ 2 метода | `copy()`, `with_overrides()` |
| Пул подключений | ✅ `ConnectionPool` | `async with pool:`, `to_sync()`, `from_file`, `map`, `map_safe`, `map_with_callback`, `ping`, `run_script`, `stream` (`PoolStreamMultiplexer`), `upload`, `download`, `sync_dir`, `write_template`, `gather_facts`, `diff_facts`, `ensure_line`, `apply` |
| Health check & Latency | ✅ `is_alive()` + `ping()` | `is_alive() -> bool` и `ping() -> PingResult` (замер `latency_ms`) для всех транспортов и пулов + `uniconn ping` |
| Retry & Hooks | ✅ `tenacity` + `uniconn.hooks` | Exponential backoff + jitter, `before_run`/`after_run`/`on_error`, `audit_log_hook`, `structured_log_hook`, `allowlist_hook`, `blocklist_hook`, `metrics_collector_hook`, `dry_run` |
| Логирование | ✅ `structlog` + `stdlib` | JSONL/Console (`configure_logging`), `contextvars` (`log_context`), метрики для Grafana/ClickHouse/InfluxDB, `SecretMaskingFilter` |
| Security | ✅ `SecretStr` + `sudo` | `passphrase`, `sudo` через `stdin`, `sensitive=True`, `shlex.join`/`quote`, `allowlist_hook`/`blocklist_hook` |
| CLI | ✅ `cyclopts` + `rich` | Модульный CLI (`src/uniconn/cli/`): `run`, `run-multi`, `stream-multi`, `exec-script`, `ping`, `expect`, `upload`, `download`, `sync-dir`, `template`, `facts` (`--diff`), `ensure-package`, `ensure-service`, `ensure-line`, `tunnel`, `bmc`, `shell`, `transports`, `screen-*`, `version` |
| Веб-панель (Dashboard) | ✅ `examples/dashboard/` | Интерактивный веб-интерфейс и HTTP API (`python3 main.py --serve` на порту `3000`) с 5 рабочими вкладками и песочницами (`v0.7.0`–`v0.9.0`) |
| Тесты | ✅ 470 unit | 34 тестовых модуля в `tests/unit/`, 0 failed, 0 warnings (`error::RuntimeWarning`) |
| Linting & Types | ✅ `ruff` + `pyright` | Лимит строки 120 символов (0 ошибок `ruff`), `pyright` в режиме `standard` (0 ошибок) + `py.typed` (PEP 561) |
| AI Agent Docs | ✅ Настроено | `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.claude/skills/`, `.cursor/rules/`, `llms.txt`, `FEATURES.md` |
| CI/CD | ❌ | GitHub Actions не настроены (осознанно исключено) |

---

## P0 — Базовое ядро и транспорты

### 1. Абстракция подключения и фабрики
- ✅ Единый фасад `Connection` (`src/uniconn/_connection.py`), объединяющий конвейер `CommandPipeline` и доменные сервисы (`conn.files`, `conn.state`, `conn.tunnels`)
- ✅ Фабрики: `from_uri()`, `from_config()`, `from_dict()`, `from_file()`, `from_inventory()`
- ✅ URI-схемы: `ssh://`, `telnet://`, `serial://`, `local://`, `ipmi://`
- ✅ Загрузчик инвентаря `InventoryLoader` (`src/uniconn/config/inventory.py`): парсинг dict / JSON / YAML / TOML с поддержкой секций `hosts`, `groups` и `defaults` (с сохранением URI query-опций)

### 2. Async + Sync API и `EventLoopPortal`
- ✅ Async-first архитектура на базе `asyncio`
- ✅ Полный синхронный паритет через `SyncConnection` (`conn.to_sync()`), `SyncShellSession`, `SyncConnectionPool` (`pool.to_sync()`) и синхронные сервисы (`SyncFileOperationsService`, `SyncStateManagementService`, `SyncTunnelService`)
- ✅ Единый фоновый портал цикла событий `EventLoopPortal` (`src/uniconn/core/bridge.py`) в daemon-потоке (`asyncio.run_coroutine_threadsafe`) и универсальный мост контекстных менеджеров `SyncContextBridge`

### 3. Управление жизненным циклом
- ✅ `close()` — явное закрытие соединения
- ✅ `async with` / `with` — асинхронный и синхронный контекстные менеджеры
- ✅ Ленивое подключение (автоматический `connect()` при первом вызове операции или явно при входе в `async with`)
- ❌ `__del__` — намеренно не реализован (антипаттерн в `asyncio`)

### 4. Структурированное логирование и наблюдаемость
- ✅ Структурированное логирование на базе `structlog` (`configure_logging(fmt="json" | "console")`, `get_struct_logger()`)
- ✅ Сквозной асинхронный контекст через `contextvars` (`log_context()`, `bind_log_context()`, `unbind_log_context()`, `clear_log_context()`, `get_log_context()`)
- ✅ События жизненного цикла (`command.start`, `command.retry`, `command.finish`, `command.error`, `command.executed`) через `ObservabilityMiddleware` с метриками (`duration_ms`, `exit_code`, `ok`, `host`, `transport`, `stdout_bytes`) для Grafana Loki / ClickHouse / InfluxDB
- ✅ Совместимость со стандартным `logging` и инъекция кастомного логгера (`logger=` параметр)
- ✅ Централизованное маскирование секретов (`redact_event_dict` и `SecretMaskingFilter`)
- ✅ Логирование в файл с ротацией (`setup_file_logging(..., structured=True)`)

### 5. Транспорты и протоколы возможностей (ISP)
- ✅ Протоколы возможностей в `src/uniconn/transports/base.py`: `CommandTransport`, `FileCapableTransport`, `ShellCapableTransport`, `TunnelCapableTransport`, проверка `require_capability()` и `supports_capability()`, исключение `CapabilityNotSupportedError`
- ✅ SSH (`SSHTransport`) — `asyncssh`, декомпозированный пакет `src/uniconn/transports/ssh/` (`OpenSSHConfigParser`, `SSHJumpChainManager`, `SFTPClientAdapter`), поддержка `~/.ssh/config`, многоступенчатых цепочек Jump-хостов (`proxy=jump1,jump2`), `ProxyCommand`
- ✅ Serial/UART (`SerialTransport`) — `pyserial-asyncio`, `baudrate`, `parity`, `stopbits`, `xonxoff`, `rtscts`
- ✅ Telnet (`TelnetTransport`) — `telnetlib3`, аутентификация login/password, настройка `term_type`
- ✅ Local (`LocalTransport`) — `asyncio.subprocess`, слияние `env`, поддержка `cwd`, PTY-сессии
- ✅ IPMI (`IPMITransport`) — `pyghmi`, управление питанием (`power status/on/off/cycle`), `sensors`, `boot device`
- ✅ Плагинная система динамической загрузки транспортов через `entry-points` (`uniconn.transports`)

### 6. Аутентификация и повышение привилегий
- ✅ По паролю (`pydantic.SecretStr`)
- ✅ По ключу (`key_file` — RSA, ECDSA, Ed25519) + поддержка зашифрованных ключей (`passphrase: SecretStr`)
- ✅ SSH-агент (`use_agent`, `agent_path`) и сертификаты OpenSSH (`client_cert`)
- ✅ Безопасное повышение привилегий `sudo=True` (`SudoMiddleware`: `sudo_user`, передача `sudo_password` через закрытый `stdin` без засветки в аргументах процесса)
- ⚠️ Telnet/Serial — базовый интерактивный login/password

### 7. Конвейер выполнения команд (`CommandPipeline`) и контекст
- ✅ `run(command, **kwargs)` → `Result(exit_code, stdout, stderr, text, lines, json(), to_dict(), raise_for_status())`
- ✅ Конвейер `CommandPipeline` (`src/uniconn/core/pipeline.py`) с расширяемой цепочкой `CommandMiddleware` (`ContextMiddleware` → `SudoMiddleware` → `HookMiddleware` → `DryRunMiddleware` → `ObservabilityMiddleware` → `RetryMiddleware`)
- ✅ Поддержка `command: str | Sequence[str]` (безопасное автоэкранирование списков аргументов через `shlex.join`)
- ✅ Передача данных в стандартный ввод `input: str | bytes | None` (`stdin`) в `run()` и `run_bytes()`
- ✅ Режим `sensitive=True` (маскировка вывода `***REDACTED***` в `repr(Result)`, `to_dict()`, `ExecutionError` и логах)
- ✅ Контекстные менеджеры `conn.cd(path)`, `conn.env(**vars)` и `conn.temp_dir(prefix=...)` (`ExecutionContext` с поддержкой вложенности в async и sync режимах)
- ✅ `stream(command)` → `AsyncIterator[str]` (построчное потоковое чтение вывода)
- ✅ Таймауты выполнения с корректным завершением процесса (`SIGTERM`/`kill`)

### 8. Повторные попытки (`RetryMiddleware`)
- ✅ Автоматические повторы с exponential backoff + jitter (`tenacity.AsyncRetrying`)
- ✅ Настраиваемое число попыток `retry_attempts`
- ✅ Повтор при сетевых сбоях и таймаутах (`ConnectionError`, `TimeoutError`) с автоматическим переподключением (`disconnect` + `connect`)

### 9. Проверка доступности
- ✅ `is_alive()` / `ping()` для всех транспортов

### 10. Пул подключений (`ConnectionPool` и `SyncConnectionPool`)
- ✅ `ConnectionPool` (`src/uniconn/_pool.py`) на базе `asyncio.TaskGroup` с единым движком распределения задач (`_fan_out_list`, `_fan_out_dict`) и ограничением параллелизма `max_concurrent` (`asyncio.Semaphore`)
- ✅ Контекстный менеджер `async with pool:` для удержания открытых соединений между групповыми операциями
- ✅ Синхронная обёртка `SyncConnectionPool` (`with pool.to_sync() as sync_pool:`)
- ✅ Загрузка из инвентаря `ConnectionPool.from_file()` с фильтрацией по `group` и `host`
- ✅ Групповые операции: `map()`, `map_safe()`, `map_with_callback()`, `stream()` (`PoolStreamMultiplexer`), `upload()`, `download()`, `sync_dir()`, `write_template()`, `gather_facts()`, `ensure_line()`, `apply()`

### 10a. SSH Session Pool (мультиплексинг каналов к одному хосту)
- ✅ `SSHSessionPool` (`src/uniconn/_session_pool.py`) — пул SSH-сессий к одному хосту
- ✅ Настройка `max_sessions_per_conn` и `max_connections` с авто-созданием соединений при пиковой нагрузке
- ✅ Проверка живости `health_check=True` и метод `check_health()` для отбраковки оборванных соединений
- ✅ Методы `run()`, `map()`, `close()` и контекстный менеджер `async with`

### 11. Иерархия исключений
- ✅ `UniconnError` → `ConnectionError`, `ExecutionError`, `TimeoutError`, `AuthenticationError`, `TransportNotFoundError`, `CapabilityNotSupportedError`, `BMCCapabilityError`, `ScreenError` (`ScreenNotFoundError`, `ScreenSessionExistsError`, `ScreenPoolFullError`)
- ✅ Полный контекст в `ExecutionError`: `command`, `exit_code`, `stdout`, `stderr`, `host` (с маскированием при `sensitive=True`)

### 12. Безопасность
- ✅ `pydantic.SecretStr` для паролей, парольных фраз (`passphrase`) и секретных ответов в `expect()`
- ✅ Автоматическая фильтрация секретов в логах (`SecretMaskingFilter` и `redact_event_dict`)
- ✅ Управление политикой SSH `known_hosts` (`strict`, `default`, путь к файлу, `no`)

### 13. Модульный CLI интерфейс (`cyclopts` + `rich`)
- ✅ Построен на `cyclopts>=5.0` и `rich>=15.0` (`src/uniconn/cli/`: `app.py`, `renderers.py`, `cmd_exec.py`, `cmd_files.py`, `cmd_ops.py`, `cmd_screen.py`)
- ✅ Команды выполнения и интерактивности: `run`, `run-multi` (`--inventory`, `--group`), `stream-multi`, `expect`, `shell`, `bmc`, `tunnel` (`-L` / `-R`)
- ✅ Команды файлов и шаблонов: `upload`, `download`, `sync-dir` (`--delete`, `--exclude`), `template` (`--var`, `--engine`)
- ✅ Команды инспекции и идемпотентного состояния: `facts`, `ensure-package`, `ensure-service`, `ensure-line`
- ✅ Команды фоновых задач и метаданных: `screen-run`, `screen-logs`, `screen-status`, `screen-kill`, `transports`, `version`
- ✅ Глобальные флаги логирования `--log-level` и `--log-format (console | json)` и форматы вывода результатов (`table`/`panel`, `json`, `plain`)

### 14. Клонирование подключений
- ✅ `copy(host=..., timeout=..., ...)` — создание независимой копии подключения с переопределением параметров
- ✅ `with_overrides(**overrides)` — клонирование с обновлением полей конфигурации и `options`

---

## P1 — Расширенные операции, интерактивность и автоматизация

### 15. Файловые операции, дельта-синхронизация и шаблоны (`FileOperationsService` & `TemplateEngine`)
- ✅ Чтение и запись файлов в памяти: `read_file()`, `write_file()`, удаление `remove_file()` (SSH SFTP и Local)
- ✅ Передача файлов и директорий: `upload()`, `download()` с поддержкой `recurse=True`
- ✅ Метаданные и файловая система: `chmod()`, `stat()`, `listdir()`, `exists()`, `mkdir(parents=True, exist_ok=True, mode=...)`
- ✅ Умная дельта-синхронизация директорий `sync_dir(local_dir, remote_dir, delete=False, exclude=None)` (`DirectorySynchronizer` → `SyncResult` со списками `uploaded`, `skipped`, `deleted`, счётчиком `bytes_transferred`)
- ✅ Шаблонизация конфигураций `write_template()` и `render_template()` (`TemplateEngine`: автовыбор `jinja2` или `string.Template`, установка прав `mode`, поддержка `dry_run`)

### 16. Интерактивный PTY Shell и декларативный `expect()`
- ✅ `open_shell(term_type, term_size, init_posix=None)` в `Connection` и `SyncConnection` для **всех интерактивных транспортов**: SSH, Local, Telnet и Serial/UART
- ✅ Stateful сессия `ShellSession` (`src/uniconn/shell/session.py`): сохранение `cd`, `export` и состояния оболочки между вызовами `execute()`, динамический `resize(cols, rows)`
- ✅ Маркерный протокол синхронизации `PosixMarkerProtocol` (`__UNICONN_{uuid}__{exit_code}`)
- ✅ Декларативный конечный автомат `ExpectStateMachine` (`conn.expect()` и `shell.expect()`): автоматический ответ на интерактивные запросы (`patterns: Mapping[str, str | SecretStr]`, ожидание `final_prompt`, защита `SecretStr` от попадания в логи)

### 17. Инспекция хостов и идемпотентное управление состоянием (`v0.8.0`)
- ✅ Сбор фактов о системе `gather_facts(refresh=False)` (`FactCollector` → `HostFacts`): семейство ОС (`os_family`), дистрибутив (`distro`), версия ядра (`kernel`), архитектура (`arch`), `hostname`, `uptime_seconds`, `cpu_count`, объём оперативной памяти (`memory_total_bytes`, `memory_available_bytes`), смонтированные диски (`DiskInfo`) и сетевые интерфейсы (`NetworkInterface`)
- ✅ Идемпотентное управление пакетами `ensure_package()` (`StateManagementService` → `EnsureResult`): стратегии `AptStrategy` (`apt-get`), `ApkStrategy` (`apk`), `DnfYumStrategy` (`dnf`/`yum`), `PacmanStrategy` (`pacman`), `ZypperStrategy` (`zypper`), состояния `present` / `absent` / `latest`, `update_cache=True`
- ✅ Идемпотентное управление сервисами `ensure_service()`: стратегии `SystemdStrategy` (`systemctl`), `OpenRCStrategy` (`rc-service`/`rc-update`), `SysVStrategy` (`service`/`chkconfig`), состояния `started` / `stopped` / `restarted` / `reloaded` и автозагрузка `enabled=True | False`
- ✅ Идемпотентное управление строками в файлах `ensure_line()`: добавление, замена по регулярному выражению (`regex=`) или удаление (`state="absent"`), создание файла (`create=True`), резервная копия (`backup=True`) и права доступа (`mode=`)

### 18. Проброс портов (SSH Port Forwarding — `TunnelService`)
- ✅ Локальный проброс порта `conn.forward_local_port(remote_host, remote_port, local_host="127.0.0.1", local_port=0)` (`ssh -L`) в async и sync режимах
- ✅ Удалённый проброс порта `conn.forward_remote_port(remote_host, remote_port, local_host="127.0.0.1", local_port=8000)` (`ssh -R`) в async и sync режимах

### 19. Пакетное выполнение и фоновые screen-сессии (`ScreenPool`)
- ✅ `run_commands(commands, stop_on_error=True)` — последовательное пакетное выполнение списка команд (async и sync)
- ✅ `ScreenPool` — запуск долгоживущих фоновых задач в detached GNU screen сессиях через SSH
- ✅ Управление квотами `max_screens` (`ScreenPoolFullError`) и `max_monitors`
- ✅ `LogPipeline` и `ScreenLogCollector` со стратегиями сбора логов (`realtime`, `periodic`, `on_finish`), санитизацией путей и фильтрацией по регулярным выражениям
- ✅ Многоуровневый cleanup: обработчики `atexit`/сигналов, sentinel-файл, фоновый cleanup-скрипт и загрузка из YAML/JSON (`ScreenPoolConfig.from_file`)

### 20. Документация, примеры и интерактивная веб-панель (`examples/dashboard/`)
- ✅ Документация Sphinx с RTD theme (`docs/index.rst`, `docs/api.rst`, `docs/transports.rst`, `docs/examples.rst`)
- ✅ Примеры использования в `examples/` и точка входа `main.py` (CLI-демонстрация и флаг `--serve`)
- ✅ Интерактивная веб-панель `examples/dashboard/` (`server.py` + `index.html`) на порту `3000`:
  - Вкладка **Shell & Local Runner**: интерактивный запуск в `ShellSession` и `LocalTransport` с визуальным инспектором `Result`
  - Вкладка **Hooks, Security & Telemetry**: песочница `CommandPipeline`, `allowlist_hook`, `blocklist_hook`, `audit_log_hook`, `structured_log_hook`, `MetricsCollector`, `sudo`, `sensitive`, `dry_run` и просмотр `structlog` JSONL
  - Вкладка **Pool, Inventory & Screen**: оркестратор `ConnectionPool` с YAML-инвентарём, пресетами `Fleet Presets`, групповыми операциями (`map_safe`, `apply`, `gather_facts`, `ensure_line`, `sync_dir`, `write_template`, `stream`), симулятором `ScreenPool` и песочницами релизов `v0.7.0` / `v0.8.0`
  - Вкладка **URI Builder & Codegen**: конструктор и валидатор URI с маскированием паролей и генератором кода (Async Python, Sync Python, CLI)
  - Вкладка **Unit Test Runner**: запуск тестовых пакетов `pytest` из веб-интерфейса
- ✅ Полный комплект документации для ИИ-агентов (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.claude/skills/`, `.cursor/rules/`, `llms.txt`, `FEATURES.md`)

---

## P2 & P3 — Middleware, прокси и защита выполнения

### 21. Lifecycle Hooks и пресеты `uniconn.hooks`
- ✅ Хуки `before_run`, `after_run`, `on_error` (`conn.add_hook()`, `HookMiddleware`)
- ✅ Готовые пресеты в `uniconn.hooks`:
  - `audit_log_hook` — запись аудита команд в JSONL с маскированием секретов
  - `structured_log_hook` — генерация событий `command.executed` для коллекторов метрик
  - `allowlist_hook` и `blocklist_hook` — превентивная блокировка запрещённых команд (`PermissionError`)
  - `MetricsCollector` / `metrics_collector_hook` — агрегация метрик выполнения по хостам
- ✅ Режим `dry_run=True` (`DryRunMiddleware` на уровне подключения и отдельного вызова)

### 22. Автореконнект, Keepalive, Jump-цепочки и `ProxyCommand`
- ✅ Auto-reconnect с backoff при сбоях `run()`
- ✅ SSH Keepalive (`options={"keepalive": 30, "keepalive_count_max": 3}`)
- ✅ Цепочки Jump / Bastion хостов (`SSHJumpChainManager`: `options={"proxy": "ssh://jump1,ssh://jump2"}`)
- ✅ Интеграция с `~/.ssh/config` (`OpenSSHConfigParser`: `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, `ProxyCommand` с поддержкой паттернов `*`, `?`, `!`)
- ✅ SOCKS5/HTTP прокси через `proxy_command` с раскрытием токенов `%h`, `%p`, `%r`, `%%`

### 23. Экранирование команд, бинарный вывод и предупреждения безопасности
- ✅ Автоэкранирование списков аргументов (`Sequence[str]`) через `shlex.join` и экспорт `uniconn.quote`
- ✅ Метод `run_bytes()` для получения сырого бинарного потока (`bytes`)
- ✅ Предупреждение в логах (`logger.warning`) при использовании незашифрованных транспортов (`TelnetTransport`, `SerialTransport`)

---

## Реализованные архитектурные решения

| Решение | Описание |
|---------|----------|
| Тонкий фасад `Connection` + доменные сервисы | Делегирование файловых операций в `FileOperationsService`, идемпотентных проверок в `StateManagementService`, туннелей в `TunnelService` и фактов в `FactCollector` |
| Конвейер `CommandPipeline` (`core/pipeline.py`) | Декомпозиция `run()` на изолированные слои `CommandMiddleware` (`Context`, `Sudo`, `Hook`, `DryRun`, `Observability`, `Retry`) |
| `EventLoopPortal` и `SyncContextBridge` (`core/bridge.py`) | Единый потокобезопасный синглтон фонового event loop для `SyncConnection`, `SyncConnectionPool` и `SyncShellSession` без дублирования кода |
| Протоколы возможностей ISP (`transports/base.py`) | Разделение интерфейсов транспорта на `CommandTransport`, `FileCapableTransport`, `ShellCapableTransport`, `TunnelCapableTransport` |
| Паттерн «Стратегия» (`services/provisioning.py`) | Изолированные стратегии пакетных менеджеров (`Apt`, `Apk`, `DnfYum`, `Pacman`, `Zypper`) и сервис-менеджеров (`Systemd`, `OpenRC`, `SysV`) |
| `PoolStreamMultiplexer` (`pool/stream_mux.py`) | Асинхронный мультиплексор потоков `stdout` со множества хостов через `asyncio.Queue` для `pool.stream()` |
| `PosixMarkerProtocol` и `ExpectStateMachine` (`shell/`) | Разделение маркерной синхронизации команд `__UNICONN_{uuid}__{exit_code}` и автомата интерактивных диалогов `expect()` |
| Модульный CLI на `cyclopts` (`src/uniconn/cli/`) | Декларативный CLI на стандартных аннотациях `typing.Annotated` без избыточных зависимостей |
| Структурированные логи (`structlog` + `contextvars`) | Единый пайплайн `ProcessorFormatter` для `structlog` и `stdlib logging`, JSONL/Console и авто-редакция секретов |
| Модульная группировка `tests/unit/` | 34 тестовых модуля (470 тестов) в 6 пакетах: `core/`, `transports/`, `pools/`, `screen/`, `cli/`, `releases/` |
| `CircuitBreaker` и `RateLimiter` (`core/resilience.py`) | Защита инфраструктуры на уровне `CommandPipeline` (`CircuitBreakerMiddleware`, `RateLimitMiddleware`) и пулов (`ConnectionPool`, `SSHSessionPool`) |

---

## Осознанно исключённые из библиотеки пункты

| Пункт | Причина исключения |
|-------|-------------------|
| `__del__` для закрытия соединений | Антипаттерн в `asyncio`, сборщик мусора не гарантирует порядок и наличие активного цикла событий |
| `arun()` с префиксом `a` | Выбрана async-first архитектура: базовый `run()` уже асинхронный, синхронный доступ — через `.to_sync()` |
| `paramiko` | Используется нативный асинхронный `asyncssh` |
| `typing_extensions` | Не требуется на Python 3.11+ (`Self` и современные типы доступны в стандартном `typing`) |
| Redfish-транспорт | Исключён из проекта для сохранения компактного ядра (управление BMC реализовано через `IPMITransport`) |
| CI/CD (GitHub Actions, PyPI) | Не входит в контур репозитория |
| Прямая зависимость от `prometheus_client` | Решается без утяжеления ядра через встроенный `MetricsCollector` и `structured_log_hook` в `uniconn.hooks` |
| Интерактивный GUI OS Keyring | Серверные и контейнерные окружения автоматизации не используют десктопный Keyring |
| OpenSSH `ControlMaster` | Заменён кроссплатформенным нативным мультиплексором `SSHSessionPool` |
| Парсеры вывода в `Result` (`Result.parse()`, `Result.table()`) | Осознанно исключены в `v0.9.0`: системные данные собираются через типизированный `FactCollector` (`gather_facts()`), а JSON-вывод разбирается через `Result.json()` |

---

## Технологический стек (`pyproject.toml`)

| Компонент | Зависимость |
|-----------|-------------|
| Core & Config | `pydantic>=2.14`, `tenacity>=9.2`, `pyyaml>=6.0`, `jinja2>=3.1`, `structlog>=26.1` |
| SSH & SFTP | `asyncssh>=2.24` |
| Telnet | `telnetlib3>=5.0` |
| Serial / UART | `pyserial-asyncio>=0.6` |
| BMC / IPMI | `pyghmi>=1.6` |
| CLI | `cyclopts>=5.0`, `rich>=15.0` |
| Dev & QA | `pytest>=8.0`, `pytest-asyncio>=1.0`, `pytest-mock>=3.14`, `pytest-cov>=6.0`, `pyright>=1.1.400`, `ruff>=0.15`, `testcontainers>=4.10` |
