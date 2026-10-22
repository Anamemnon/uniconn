# Требования к универсальной Python-библиотеке для выполнения команд на удалённых хостах

> **Статус**: v0.6.0 | **410 unit-тестов** | 30 файлов тестов (6 пакетов в `tests/unit/`) | 5 транспортов | CLI | Плагинная система | PEP 561 (`py.typed`)
>
> **Для ИИ-агентов**: этот файл является справочной матрицей реализованных фич. **Не загружайте его в контекст при каждом запросе** — обращайтесь к нему только по требованию (on-demand), когда нужно быстро проверить статус конкретной функциональности или обновить чек-лист после релиза.
>
> Обозначения: ✅ реализовано | ⚠️ частично | ❌ не реализовано

## Сводка покрытия

| Область | Статус | Детали |
|---------|--------|--------|
| Транспорты | ✅ 5/5 | SSH (`~/.ssh/config`, Jump-хосты, `ProxyCommand`), Telnet, Serial, Local, IPMI |
| SSH мультиплексинг | ✅ SSHSessionPool | До N каналов на соединение, авто-создание новых, `health_check` и `check_health()` |
| Screen-сессии | ✅ ScreenPool | Долгоживущие команды в GNU screen, LogPipeline, cleanup |
| PTY Shell | ✅ ShellSession | Stateful интерактивные сессии для SSH, Local и Telnet (`open_shell`, `execute`, `SyncShellSession`) |
| API | ✅ async + sync | `Connection` + `SyncConnection` (`cd`, `env`, `temp_dir`, `run_bytes`, `read_file`, `write_file`, `exists`, `mkdir`) |
| Фабрики | ✅ 5 методов | `from_uri`, `from_config`, `from_dict`, `from_file` (с `host=` и `group=`), `from_inventory` |
| Клонирование | ✅ 2 метода | `copy()`, `with_overrides()` |
| Пул | ✅ `ConnectionPool` | `async with pool:`, `from_file`, `map`, `map_safe`, `map_with_callback`, `upload`, `download`, `apply` |
| Health check | ✅ `is_alive()` / `ping()` | Для всех транспортов + SSH keepalive + `SSHSessionPool.check_health()` |
| Retry & Hooks | ✅ tenacity + `uniconn.hooks` | Exponential backoff + jitter, `before_run`/`after_run`/`on_error`, `audit_log_hook`, `structured_log_hook`, `allowlist_hook`, `blocklist_hook`, `metrics_collector_hook`, `dry_run` |
| Логирование | ✅ `structlog` + `stdlib` | JSONL/Console (`configure_logging`), `contextvars` (`log_context`), метрики для Grafana/ClickHouse/InfluxDB, `SecretMaskingFilter` |
| Security | ✅ SecretStr + sudo | `passphrase`, `sudo` через `stdin`, `sensitive=True`, `shlex.join`/`quote`, `allowlist_hook`/`blocklist_hook` |
| CLI | ✅ typer + rich | `--log-level`, `--log-format`, `run`, `run-multi` (`--inventory`/`--group`), `upload`, `download`, `bmc`, `shell`, `transports`, `screen-*`, `version` |
| Тесты | ✅ 410 unit | Все green, 0 failed, 0 warnings (`error::RuntimeWarning`) |
| Linting | ✅ ruff | 120 char line (0 errors) |
| Types | ✅ pyright | Standard mode (0 errors) + `py.typed` (PEP 561) |
| AI Agent Docs | ✅ Настроено | `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.claude/skills/`, `.cursor/rules/`, `llms.txt`, `src/uniconn/py.typed` |
| CI/CD | ❌ | GitHub Actions не настроены (осознанно исключено) |

---

## P0 — Must have

### 1. Абстракция подключения
- ✅ Единый интерфейс `Connection`, скрывающий детали протокола
- ✅ Фабрики: `from_uri()`, `from_config()`, `from_dict()`, `from_file()`, `from_inventory()`
- ✅ URI-схемы: `ssh://`, `telnet://`, `serial://`, `local://`, `ipmi://`
- ✅ Конфигурация через dict / JSON / YAML (включая группы хостов и `defaults`)

### 2. Async + Sync API
- ✅ Async-first на базе `asyncio`
- ✅ Sync wrapper через `SyncConnection` (`to_sync()`) и `SyncShellSession`
- ✅ Постоянный event loop в daemon-потоке (`asyncio.run_coroutine_threadsafe`)

### 3. Управление жизненным циклом
- ✅ `close()` — явное закрытие
- ✅ `async with` / `with` — контекстный менеджер
- ✅ Ленивое подключение (при первом `run()` или `async with`)
- ❌ `__del__` — намеренно не реализован (asyncio антипаттерн)

### 4. Логирование
- ✅ Структурированное логирование на базе `structlog` (`configure_logging(fmt="json" | "console")`, `get_struct_logger()`)
- ✅ Асинхронный контекст через `contextvars` (`log_context()`, `bind_log_context()`, `clear_log_context()`)
- ✅ События жизненного цикла (`command.start`, `command.retry`, `command.finish`, `command.error`, `command.executed`) с метриками (`duration_ms`, `exit_code`, `ok`, `host`, `transport`) для Grafana Loki / ClickHouse / InfluxDB
- ✅ Встроенное через `logging` модуль и инъекция кастомного логгера (`logger=` параметр)
- ✅ Централизованное маскирование секретов (`redact_event_dict` и `SecretMaskingFilter`)
- ✅ Логирование в файл с ротацией (`setup_file_logging(..., structured=True)`)

### 5. Транспорты
- ✅ SSH — `asyncssh`, порт, таймаут, `known_hosts`, proxy/jump hosts, `ProxyCommand`
- ✅ Serial/UART — `pyserial-asyncio`, `baudrate`, `parity`, `stopbits`
- ✅ Telnet — `telnetlib3`, login/password auth
- ✅ Local — `asyncio.subprocess`, env merging
- ✅ IPMI — `pyghmi`, RMCP+
- ✅ Плагинная система (`entry-points`)

### 6. Аутентификация
- ✅ По паролю (`Pydantic SecretStr`)
- ✅ По ключу (`key_file` — RSA, ECDSA, Ed25519) + поддержка зашифрованных ключей (`passphrase: SecretStr`)
- ✅ SSH-агент (`use_agent`, `agent_path`) и сертификаты OpenSSH (`client_cert`)
- ✅ Повышение привилегий `sudo=True` (`sudo_user`, `sudo_password` через закрытый `stdin`)
- ⚠️ Telnet/Serial — базовый login/password

### 7. Выполнение команд
- ✅ `run(command, **kwargs)` → `Result(exit_code, stdout, stderr, text, lines, json(), to_dict())`
- ✅ Поддержка `command: str | Sequence[str]` (автоэкранирование через `shlex.join`)
- ✅ Передача данных в стандартный ввод `input: str | bytes | None` (`stdin`)
- ✅ Режим `sensitive=True` (маскировка вывода в `repr(Result)`, `to_dict()`, `ExecutionError` и логах)
- ✅ Контекстные менеджеры `conn.cd(path)`, `conn.env(**vars)` и `conn.temp_dir()`
- ✅ `stream(command)` → `AsyncIterator[str]`
- ✅ `raise_on_error=True` → `ExecutionError`
- ✅ Env vars (`env=`), рабочая директория (`cwd=` в Local и SSH)
- ✅ Таймауты с прерыванием (`SIGTERM`/`kill`)

### 8. Повторные попытки
- ✅ Авто-ретры с exponential backoff + jitter (`tenacity` `AsyncRetrying`)
- ✅ Конфигурируемое `retry_attempts`
- ✅ Retry по исключениям: `ConnectionError`, `TimeoutError` (включая builtin)
- ✅ Reconnect (`disconnect` + `connect`) между попытками

### 9. Проверка доступности
- ✅ `is_alive()` / `ping()` для всех транспортов

### 10. Пул соединений
- ✅ `ConnectionPool` с `asyncio.TaskGroup` и контекстным менеджером `async with pool:`
- ✅ `from_file()` с фильтрацией по `group` и `host`
- ✅ `map()`, `map_safe()`, `map_with_callback()`, `upload()`, `download()`, `apply()`
- ✅ Semaphore-based concurrency limit (`max_concurrent`)

### 10a. SSH Session Pool (один хост, много каналов)
- ✅ `SSHSessionPool` — пул SSH-соединений для одного хоста
- ✅ `max_sessions_per_conn` и `max_connections`
- ✅ Авто-создание нового соединения при переполнении
- ✅ Проверка здоровья `health_check=True` и `check_health()`
- ✅ `run()`, `map()`, `close()` + `async with` контекстный менеджер

### 11. Обработка ошибок
- ✅ Иерархия: `UniconnError` → `ConnectionError`, `ExecutionError`, `TimeoutError`, `AuthenticationError`, `BMCCapabilityError`, `TransportNotFoundError`, `ScreenError`
- ✅ Контекст ошибки: `command`, `exit_code`, `stdout`, `stderr`, `host`

### 12. Безопасность
- ✅ `Pydantic SecretStr` для паролей и парольных фраз
- ✅ `SecretMaskingFilter` в логах
- ✅ SSH `known_hosts` (`strict` / `default` / `file` / `no`)

### 13. CLI интерфейс
- ✅ `typer` + `rich`: `run`, `run-multi` (`--inventory`, `--group`), `upload`, `download`, `bmc`, `shell`, `transports`, `screen-run`, `screen-logs`, `screen-status`, `screen-kill`, `version`
- ✅ Глобальные флаги логирования: `--log-level` и `--log-format (console | json)`
- ✅ Форматы вывода команд: `table`/`panel`, `json`, `plain`

### 14. Клонирование подключений
- ✅ `copy(host=..., timeout=...)` — immutable clone с override
- ✅ `with_overrides({...})` — dict-based override

---

## P1 — Should have

### 15. Передача и операции с файлами (SFTP / Local)
- ✅ Upload/download через `upload()`, `download()` (SSH SFTP)
- ✅ Recursive transfer (`recurse=True` + автоопределение директорий)
- ✅ Permissions — `chmod(remote_path, 0o755)` через SFTP
- ✅ Метаданные и списки файлов: `stat()`, `listdir()`, `exists()`, `mkdir()`

### 16. Полноценный PTY shell
- ✅ `open_shell(term_type, term_size)` в `Connection` и `SyncConnection` (для SSH, Local и Telnet)
- ✅ Stateful сессия `ShellSession` (`cd`, `export` сохраняются между вызовами `execute()`)
- ✅ Маркерный протокол синхронизации `__UNICONN_{uuid}__{exit_code}`
- ✅ Переключение `run` ↔ `shell` без реконнекта на одном SSH-подключении
- ✅ CLI `shell` на базе `ShellSession.execute()`

### 17. CI/CD (Не реализовывать)
- ❌ GitHub Actions (test, lint, type check)
- ❌ PyPI publishing
- ❌ Integration tests в CI

### 18. Документация и примеры
- ✅ Sphinx с RTD theme (`docs/index.rst`, `docs/api.rst`, `docs/transports.rst`)
- ✅ Примеры в `examples/` и веб-панель интерактивного тестирования `examples/dashboard/`
- ✅ Документация для ИИ-агентов (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `llms.txt`)

### 19. `run_commands(commands)` — батч
- ✅ Последовательное выполнение списка команд
- ✅ `stop_on_error=True` — прерывание на первой ошибке
- ✅ Синхронная обёртка в `SyncConnection`

### 19a. Фоновые screen-сессии (`ScreenPool`)
- ✅ `ScreenPool` — запуск долгоживущих команд в detached GNU screen через SSH
- ✅ Лимиты `max_screens` (`ScreenPoolFullError`) и `max_monitors`
- ✅ `LogPipeline` и сбор логов порциями (`ScreenLogCollector`)
- ✅ Многоуровневый cleanup: `atexit`/signal, sentinel-файл, cleanup-скрипт
- ✅ CLI: `screen-run`, `screen-logs`, `screen-status`, `screen-kill`
- ✅ Конфигурация из YAML/JSON (`ScreenPoolConfig.from_file`)

---

## P2 — Nice to have

### 20. Middleware / цепочки обработчиков
- ✅ Hooks / callbacks (`before_run`, `after_run`, `on_error`, метод `add_hook`)
- ✅ Готовые пресеты в `uniconn.hooks`: `audit_log_hook`, `structured_log_hook` (JSONL-телеметрия `command.executed` для ClickHouse / InfluxDB / Grafana Loki), `allowlist_hook`, `blocklist_hook`, `MetricsCollector` / `metrics_collector_hook`
- ✅ Режим `dry_run=True` (на уровне `Connection` и отдельного вызова `run()`)

### 22. Автореконнект и Heartbeat
- ✅ Auto-reconnect с backoff при ошибках `run()`
- ✅ SSH Heartbeat / Keepalive (`options={"keepalive": 30, "keepalive_count_max": 3}`)

### 23. Продвинутая аутентификация и привилегии
- ✅ Управление SSH-агентом (`options={"use_agent": True, "agent_path": "..."}`)
- ✅ Сертификаты OpenSSH (`options={"client_cert": "/path/to/id-cert.pub"}`)
- ✅ Парольная фраза для приватных ключей (`passphrase: SecretStr`)
- ✅ Безопасный `sudo=True` (`sudo_user`, `sudo_password` через `stdin`)

### 24. Прокси и SSH Config
- ✅ Jump / Bastion хосты (`options={"proxy": "ssh://jump"}`)
- ✅ Интеграция с `~/.ssh/config` (`options={"ssh_config": True}` или путь к файлу)
- ✅ SOCKS5/HTTP прокси (`proxy_command` в `options` и `ProxyCommand` из `~/.ssh/config` с подстановкой `%h`, `%p`, `%r`)

---

## P3 — Future

### 26. Shell escaping
- ✅ List-based command args (`command: str | Sequence[str]`) с автоэкранированием через `shlex.join`
- ✅ Экспорт `uniconn.quote` (`shlex.quote`)

### 29. Warnings для незашифрованных транспортов
- ✅ Предупреждение (`logger.warning`) при подключении через Telnet/Serial

### 30. Стандартный ввод (`stdin`), файловые операции в памяти и байтовый режим
- ✅ Поддержка `input: str | bytes | None = None` (`stdin`) в `run()` и `run_bytes()`
- ✅ `run_bytes()` → сырые `bytes` вместо `str`
- ✅ `read_file()` и `write_file()` → чтение и запись файлов напрямую из памяти (SSH SFTP и Local)

---

## Реализованные архитектурные решения

| Решение | Описание |
|---------|----------|
| `AsyncRetrying` вместо `@retry` | Динамический `retry_attempts` из экземпляра |
| Постоянный event loop в daemon-потоке (`SyncConnection`) | `run_coroutine_threadsafe`, инкрементальный `stream()` через `asyncio.Queue` |
| `pyright standard` + `py.typed` | 0 ошибок типизации по всему `src/`, поддержка PEP 561 |
| `dependency-groups.dev` | Стандарт управления dev-зависимостями в `uv` |
| `type(self)` и `SecretStr` в `copy()` | Корректная работа с наследниками `Connection` и автообёртка паролей |
| Lazy connect | Подключение при первом `run()` или явно через `async with` |
| `SSHSessionPool` | Мультиплексинг SSH-каналов + `check_health()` |
| `ShellSession` (PTY) | Маркерный протокол `__UNICONN_{uuid}__{exit_code}` для SSH, Local и Telnet |
| `shlex.join` для `Sequence[str]` | Безопасное экранирование списков аргументов в `Connection` и `ShellSession` |
| Структурированные логи (`structlog` + `contextvars`) | Единый пайплайн `ProcessorFormatter` для `structlog` и `stdlib logging`, JSONL/Console, авто-редакция секретов (`redact_event_dict`) и телеметрия для Grafana Loki / ClickHouse / InfluxDB |
| Модульная группировка `tests/unit/` | 30 тестовых модулей сгруппированы по доменам: `core/`, `transports/`, `pools/`, `screen/`, `cli/`, `releases/` |

---

## Исключённые из требований пункты

| Было | Причина исключения |
|------|-------------------|
| `__del__` для закрытия | asyncio антипаттерн, GC не гарантирует порядок |
| `arun()` с префиксом `a` | Выбран async-first: `run()` уже async |
| `paramiko` в рекомендациях | Используем `asyncssh` — нативный async |
| `typing_extensions` | Не нужен на Python 3.11+ (`Self` в `typing`) |
| Redfish-транспорт | Удалён из проекта (вместе с зависимостью `aiohttp`) |
| CI/CD (GitHub Actions, PyPI) | Осознанно не реализуется |
| Мониторинг (`prometheus_client`) | Избыточная зависимость в ядре; решается через `uniconn.hooks` |
| MFA / OTP / Keyboard-interactive | Противоречит автоматизированному (non-interactive) сценарию |
| OpenSSH `ControlMaster` (§25) | Заменён нативным `SSHSessionPool` (§10a) |
| OS Keyring integration (§27) | Серверные и контейнерные окружения не имеют GUI keyring |
| SemVer deprecation cycle (§28) | Процессное правило поддержки после `v1.0.0`, не функциональная фича |

---

## Технологический стек

| Компонент | Зависимость |
|-----------|-------------|
| Core | `pydantic>=2.0`, `tenacity>=8.0`, `pyyaml>=6.0`, `structlog>=23.1` |
| SSH | `asyncssh>=2.13` |
| Telnet | `telnetlib3>=2.0` |
| Serial | `pyserial-asyncio>=0.6` |
| BMC | `pyghmi>=1.5` |
| CLI | `typer>=0.9`, `rich>=13.0` |
| Dev | `pytest`, `pyright`, `ruff`, `testcontainers` |
