# Реализованные возможности и архитектура библиотеки uniconn

> **Версия**: v0.20.0 | **915+ unit-тестов** | 16+ транспортов (`ssh`, `winrm`/`wsman`, `netconf`, `restconf`, `gnmi`, `qga`/`qemu-ga`, `pve`, `docker`, `podman`, `kubectl`, `telnet`, `serial`/`uart`, `ipmi`, `redfish`, `replay`, `local`) | Модульный CLI (`cyclopts` + `rich`) | Встроенный MCP-сервер (`uniconn mcp`) | Интерактивная веб-панель (`examples/dashboard/`) | PEP 561 (`py.typed`) + PEP 562 Lazy Exports
>
> **Для ИИ-агентов**: этот файл (`FEATURES.md`) является полным каталогом реализованных фич и архитектурных решений библиотеки `uniconn`. **Не загружайте его в контекст при каждом запросе** — используйте `llms.txt` для быстрого обзора сигнатур API, а к `FEATURES.md` обращайтесь только по требованию (on-demand), когда нужно сверить наличие конкретной функциональности или обновить список возможностей после релиза.
>
> Обозначения: ✅ реализовано | ⚠️ частично | ❌ не реализовано (осознанно исключено)

## Сводка реализованных возможностей

| Область | Статус | Детали |
|---------|--------|--------|
| Транспорты | ✅ 16+ | SSH (`~/.ssh/config`, `SSHJumpChainManager`, `ProxyCommand`), WinRM/WSMan (`winrm://`, `pywinrm`), NETCONF (`netconf://`), RESTCONF (`restconf://`), gNMI (`gnmi://`), QEMU Guest Agent (`qga://`), Proxmox VE (`pve://`), Docker (`docker://`), Podman (`podman://`), Kubernetes (`kubectl://`), Telnet, Serial/UART (X/Y/ZMODEM), Local, IPMI (`ipmi://`), Redfish BMC (`redfish://` на `niquests`), Replay (`replay://`) |
| Протоколы ISP | ✅ `transports.base` | `CommandTransport`, `FileCapableTransport`, `ShellCapableTransport`, `TunnelCapableTransport`, `StructuredNetworkTransport`, `require_capability()` |
| Конвейер команд | ✅ `CommandPipeline` | Цепочка `CommandMiddleware`: `Context`, `HITLApproval`, `PolicyGuardrail`, `Sudo`, `Hook`, `DryRun`, `Observability`, `AutoDiagnostic`, `CircuitBreaker`, `RateLimit`, `Retry` (`conn.pipeline`) |
| Отказоустойчивость и раскатка | ✅ `CircuitBreaker` + `RateLimiter` + Waves | Состояния `CLOSED` → `OPEN` → `HALF_OPEN` (`CircuitOpenError`), Token Bucket `RateLimiter`, волновая раскатка `batch_size` / `max_fail_ratio` (`BatchAbortedError`) |
| Доменные сервисы | ✅ `conn.files` / `path` / `state` / `tunnels` / `net` | `FileOperationsService`, `RemotePath` (`pathlib.Path` API), `DirectorySynchronizer`, `StateManagementService`, `NetworkOperationsService`, `FactCollector`, `TunnelService`, `TemplateEngine` |
| Zero-Fork Python RPC (`v0.18.0`) | ✅ `RemotePythonWorker` | `conn.run_python()` / `pool.run_python()` — постоянный Python-воркер по `stdin`/`stdout` с временем вызова `< 2 мс` |
| DAG-оркестрация задач (`v0.18.0`) | ✅ `uniconn.orchestration` | Декларативные графы `@task(depends_on=..., post=..., when=...)`, `Flow` / `SyncFlow`, режимы `barrier` и `independent`, экспорт `Flow` как MCP Tool |
| Семантический парсинг (`v0.17.0`) | ✅ `uniconn.parsing` | `conn.run(..., parse="auto" | "df" | "jc:..." | "textfsm:..." | "ttp:...")`, `Result.parse()`, `Result.parsed`, валидация через Pydantic-модели |
| Policy-as-Code & AST (`v0.19.0`) | ✅ `uniconn.security` | Глубокий AST-анализ команд (`CommandASTParser`, детектор обфускации `base64`/`eval`) и оценка политик (`EmbeddedPolicyEngine`, `OPAPolicyEngine`) |
| MCP Server & HITL (`v0.16.0`–`v0.19.0`) | ✅ `uniconn.mcp` | JSON-RPC 2.0 `stdio` сервер (`uniconn mcp`), классификатор риска (`ActionRiskClassifier`), криптографически подписанные HITL-аппрувы (`uniconn approval *`) |
| Фоновые сессии и диагностика | ✅ `BackgroundPool` + `DiagnosticSession` | Бэкенды `TmuxBackend`, `ScreenBackend`, `NohupBackend`, `WindowsJobBackend`, реактивный `LogPipeline` с `LogWatchRule` и `AutoDiagnosticMiddleware` |
| PTY Shell & Expect | ✅ `ShellSession` + `expect()` | Stateful сессии (`open_shell`, `execute`, `SyncShellSession`) и декларативный `expect()` на уровне `Connection`, `ShellSession` и `ConnectionPool` |
| Инспекция и сравнение | ✅ `gather_facts()` + `diff_facts()` | `FactCollector` → `HostFacts` (Linux + Windows PowerShell) + детектор конфигурационного дрейфа `diff_facts()` (`FactsDiffReport`) |
| Идемпотентность (`v0.12.0`–`v0.18.0`) | ✅ `ensure_*` (`EnsureResult` + `notify`) | Пакеты (`apt`/`apk`/`dnf`/`yum`/`pacman`/`zypper`/`winget`/`choco`/`scoop`), сервисы (`systemd`/`openrc`/`sysv`/Windows Services), `ensure_file`, `ensure_directory`, `ensure_line`, `ensure_user`, `ensure_authorized_key`, `ensure_systemd_unit`, `ensure_sysctl`, `ensure_registry_key`, `ensure_windows_feature`, `ensure_yang`, дедупликация `batch_notifications()` |
| Запись/реплей кассет и Mock-серверы | ✅ `Cassette` + `uniconn.mock` | `conn.use_cassette()`, `pool.use_cassette()`, `Cassette.diff()`, `uniconn.pytest_plugin`, сокетные серверы `MockSSHServer`, `MockNetconfServer`, `MockRestconfServer`, `MockGnmiServer`, `MockQgaServer`, `MockPveServer` |
| API (Async + Sync) и Lazy Loading | ✅ Полный паритет + PEP 562 | `Connection` ↔ `SyncConnection`, `ConnectionPool` ↔ `SyncConnectionPool`, `Flow` ↔ `SyncFlow` на базе `EventLoopPortal` и ленивая загрузка `__getattr__` в `uniconn/__init__.py` |
| Пул подключений (`v0.20.0`) | ✅ `ConnectionPool` | `from_file(..., dry_run, auto_diagnostics)`, `select()`, `use_cassette`, `map`, `map_safe`, `ping`, `wait_for_*`, `run_script`, `run_python`, `expect`, `run_flow`, `stream`, `.files`, `.state`, `.net`, `apply` |
| Тесты и качество кода | ✅ 915+ unit-тестов | `tests/unit/`, 0 failed, 0 warnings (`error::RuntimeWarning`), `ruff` (120 символов, 0 ошибок), `pyright` (`standard`, 0 ошибок), CI матрица в `.github/workflows/ci.yml` |

---

## P0 — Базовое ядро и транспорты

### 1. Абстракция подключения и фабрики
- ✅ Единый фасад `Connection` (`src/uniconn/core/connection.py`), объединяющий конвейер `CommandPipeline` и доменные сервисы (`conn.files`, `conn.state`, `conn.tunnels`, `conn.net`)
- ✅ Фабрики: `from_uri()`, `from_config()`, `from_dict()`, `from_file()`, `from_inventory()`, `local()`
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
- ✅ Serial/UART (`SerialTransport`, схемы `serial://` и `uart://`) — `pyserial-asyncio`, `baudrate` (включая `:baudrate`), `parity` (N/E/O/M/S, even/odd), `stopbits` (1/1.5/2), `xonxoff`, `rtscts`, аппаратные сигналы `DTR`/`RTS`/`send_break()`, опрос `CTS`/`DSR`/`CD`/`RI`, Smart Framing с `inter_byte_timeout`, безопасный `ping()`, Port Discovery (`list_serial_ports`, CLI `uniconn serial-ports`), бинарный ввод-вывод `run_bytes()`, пассивный режим `stream(command=None)`, передача файлов и прошивок по протоколам **XMODEM** (`checksum`, `crc`, `1k`), **YMODEM** (`Packet 0` с именем и точным размером, `Batch`-режим) и **ZMODEM** (`lrzsz` адаптер) с поддержкой `trigger_command` (`upload_xmodem`, `upload_ymodem`, `download_xmodem`, `download_ymodem`)
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
- ✅ `ConnectionPool` (`src/uniconn/pool/connection_pool.py`) на базе `asyncio.TaskGroup` с единым движком распределения задач (`_fan_out_list`, `_fan_out_dict`) и ограничением параллелизма `max_concurrent` (`asyncio.Semaphore`)
- ✅ Контекстный менеджер `async with pool:` для удержания открытых соединений между групповыми операциями
- ✅ Синхронная обёртка `SyncConnectionPool` (`with pool.to_sync() as sync_pool:`)
- ✅ Загрузка из инвентаря `ConnectionPool.from_file()` с фильтрацией по `group` и `host`, а также пробросом `dry_run` и `auto_diagnostics`
- ✅ Групповые операции: `map()`, `map_safe()`, `map_with_callback()`, `expect()`, `stream()` (`PoolStreamMultiplexer`), `upload()`, `download()`, `sync_dir()`, `write_template()`, `gather_facts()`, `ensure_line()`, `apply()`

### 10a. SSH Session Pool (мультиплексинг каналов к одному хосту)
- ✅ `SSHSessionPool` (`src/uniconn/pool/session_pool.py`) — пул SSH-сессий к одному хосту
- ✅ Настройка `max_sessions_per_conn` и `max_connections` с авто-созданием соединений при пиковой нагрузке
- ✅ Адаптивный режим по умолчанию (`adaptive=True`): автоматическое снижение `max_sessions_per_conn` (при отказе открытия каналов `MaxSessions`) и `max_connections` (при отказе новых подключений `MaxStartups`) с фиксацией найденного потолка и прозрачным повтором команд
- ✅ Динамическое изменение лимитов `await pool.resize(max_sessions_per_conn=..., max_connections=...)` с мягким дренажем (`graceful drain`) избыточных соединений и телеметрией `pool.stats()`
- ✅ Проверка живости `health_check=True` и метод `check_health()` для отбраковки оборванных соединений
- ✅ Методы `run()`, `map()`, `resize()`, `stats()`, `close()` и контекстный менеджер `async with`

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
| Модульная группировка `tests/unit/` | 34 тестовых модуля (475 тестов) в 6 пакетах: `core/`, `transports/`, `pools/`, `screen/`, `cli/`, `releases/` |
| `CircuitBreaker` и `RateLimiter` (`core/resilience.py`) | Защита инфраструктуры на уровне `CommandPipeline` (`CircuitBreakerMiddleware`, `RateLimitMiddleware`) и пулов (`ConnectionPool`, `SSHSessionPool`) |

---

## Осознанно исключённые из библиотеки пункты

| Пункт | Причина исключения |
|-------|-------------------|
| `__del__` для закрытия соединений | Антипаттерн в `asyncio`, сборщик мусора не гарантирует порядок и наличие активного цикла событий |
| `arun()` с префиксом `a` | Выбрана async-first архитектура: базовый `run()` уже асинхронный, синхронный доступ — через `.to_sync()` |
| `paramiko` | Используется нативный асинхронный `asyncssh` |
| `typing_extensions` | Не требуется на Python 3.11+ (`Self` и современные типы доступны в стандартном `typing`) |
| Интерактивный GUI OS Keyring | Серверные и контейнерные окружения автоматизации не используют десктопный Keyring |
| OpenSSH `ControlMaster` | Заменён кроссплатформенным нативным мультиплексором `SSHSessionPool` |
| Приватные модули-заглушки `_*.py` и `is_dry_run` | Полностью удалены в `v0.20.0` в пользу канонических подпакетов и свойства `.dry_run` |

---

## Технологический стек (`pyproject.toml`)

| Компонент | Зависимость |
|-----------|-------------|
| Core & Config | `pydantic>=2.14`, `tenacity>=9.2`, `pyyaml>=6.0`, `jinja2>=3.1`, `structlog>=26.1` |
| SSH & SFTP | `asyncssh>=2.24` |
| Telnet | `telnetlib3>=5.0` |
| Serial / UART | `pyserial-asyncio>=0.6` |
| BMC (IPMI & Redfish) | `pyghmi>=1.6`, `niquests>=3.10` |
| CLI | `cyclopts>=5.0`, `rich>=15.0` |
| Dev & QA | `pytest>=8.0`, `pytest-asyncio>=1.0`, `pytest-mock>=3.14`, `pytest-cov>=6.0`, `pyright>=1.1.400`, `ruff>=0.15`, `testcontainers>=4.10` |
