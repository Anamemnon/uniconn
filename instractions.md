# Требования к универсальной Python-библиотеке для выполнения команд на удалённых хостах

> **Статус**: v0.3.0 | **367 unit-тестов** | 27 файлов тестов | 5 транспортов | CLI | Плагинная система
>
> Обозначения: ✅ реализовано | ⚠️ частично | ❌ не реализовано

## Сводка покрытия

| Область | Статус | Детали |
|---------|--------|--------|
| Транспорты | ✅ 5/5 | SSH, Telnet, Serial, Local, IPMI |
| SSH мультиплексинг | ✅ SSHSessionPool | До N каналов на соединение, авто-создание новых |
| Screen-сессии | ✅ ScreenPool | Долгоживущие команды в GNU screen, LogPipeline, cleanup |
| PTY Shell | ✅ ShellSession | Stateful интерактивные сессии (`open_shell`, `execute`, `SyncShellSession`) |
| API | ✅ async + sync | `Connection` + `SyncConnection` |
| Фабрики | ✅ 4 метода | `from_uri`, `from_config`, `from_dict`, `from_file` |
| Клонирование | ✅ 2 метода | `copy()`, `with_overrides()` |
| Пул | ✅ `ConnectionPool` | `map`, `map_safe`, `map_with_callback` |
| Health check | ✅ `is_alive()` / `ping()` | Для всех транспортов + SSH keepalive |
| Retry | ✅ tenacity | Exponential backoff + jitter + auto-reconnect |
| Security | ✅ SecretStr + masking | known_hosts, `shlex.join` / `quote` |
| CLI | ✅ typer + rich | run, run-multi, bmc, shell, transports, screen-* |
| Тесты | ✅ 367 unit | Все green, 0 failed |
| Linting | ✅ ruff | 100 char line (0 errors) |
| Types | ✅ pyright | Standard mode (0 errors) |
| CI/CD | ❌ | GitHub Actions не настроены (осознанно исключено) |

---

## Приоритеты

### P0 — Must have (реализовано)
Ядро библиотеки: транспорты, run/stream, retry, pool, security, CLI.

### P1 — Should have (реализовано)
PTY shell, file transfer (SFTP/SCP), docs, examples, `run_commands`, `ScreenPool`.

### P2 — Nice to have (частично реализовано в v0.3.0)
SSH keepalive/heartbeat, `~/.ssh/config`, SSH-агент, сертификаты OpenSSH, middleware (запланировано на v0.4.0).

### P3 — Future (частично реализовано в v0.3.0)
Shell escaping (`shlex.join`, `quote`), `stdin` (`input=`), предупреждения для незашифрованных транспортов.

---

## P0 — Must have

### 1. Абстракция подключения
- ✅ Единый интерфейс `Connection`, скрывающий детали протокола
- ✅ Фабрики: `from_uri()`, `from_config()`, `from_dict()`, `from_file()`
- ✅ URI-схемы: `ssh://`, `telnet://`, `serial://`, `local://`, `ipmi://`
- ✅ Конфигурация через dict / JSON / YAML

### 2. Async + Sync API
- ✅ Async-first на базе `asyncio`
- ✅ Sync wrapper через `SyncConnection` (`to_sync()`)
- ✅ Постоянный event loop в daemon-потоке (`asyncio.run_coroutine_threadsafe`)

### 3. Управление жизненным циклом
- ✅ `close()` — явное закрытие
- ✅ `async with` / `with` — контекстный менеджер
- ✅ Ленивое подключение (при первом `run()` или `async with`)
- ❌ `__del__` — намеренно не реализован (asyncio антипаттерн)

### 4. Логирование
- ✅ Встроенное через `logging` модуль
- ✅ Инъекция кастомного логгера (`logger=` параметр)
- ✅ Маскирование секретов (`SecretMaskingFilter`)
- ✅ Логирование в файл с ротацией

### 5. Транспорты
- ✅ SSH — asyncssh, порт, таймаут, known_hosts, proxy/jump hosts
- ✅ Serial/UART — pyserial-asyncio, baudrate, parity, stopbits
- ✅ Telnet — telnetlib3, login/password auth
- ✅ Local — asyncio.subprocess, env merging
- ✅ IPMI — pyghmi, RMCP+
- ✅ Плагинная система (entry-points)

### 6. Аутентификация
- ✅ По паролю (Pydantic SecretStr)
- ✅ По ключу (`key_file` — RSA, ECDSA, Ed25519)
- ✅ SSH-агент (`use_agent`, `agent_path`) и сертификаты OpenSSH (`client_cert`)
- ⚠️ Telnet/Serial — базовый login/password

### 7. Выполнение команд
- ✅ `run(command, **kwargs)` → `Result(exit_code, stdout, stderr)`
- ✅ Поддержка `command: str | Sequence[str]` (автоэкранирование через `shlex.join`)
- ✅ Передача данных в стандартный ввод `input: str | bytes | None` (`stdin`)
- ✅ `stream(command)` → `AsyncIterator[str]`
- ✅ `raise_on_error=True` → ExecutionError
- ✅ Env vars (`env=`), рабочая директория (`cwd=` в Local и SSH)
- ✅ Таймауты с прерыванием (SIGTERM/kill)

### 8. Повторные попытки
- ✅ Авто-ретры с exponential backoff + jitter (tenacity `AsyncRetrying`)
- ✅ Конфигурируемое `retry_attempts` (динамическое, не захардкожено)
- ✅ Retry по исключениям: `ConnectionError`, `TimeoutError` (включая builtin)
- ✅ Reconnect (disconnect + connect) между попытками

### 9. Проверка доступности
- ✅ `is_alive()` / `ping()` для всех транспортов
  - SSH: `asyncssh.run("true")` — лёгкая, без PTY
  - IPMI: `power status`
  - Local: возвращает `_connected`
  - Base: fallback через `echo ping`

### 10. Пул соединений
- ✅ `ConnectionPool` с `asyncio.TaskGroup`
- ✅ `map()`, `map_safe()`, `map_with_callback()`
- ✅ Semaphore-based concurrency limit (`max_concurrent`)

### 10a. SSH Session Pool (один хост, много каналов)
- ✅ `SSHSessionPool` — пул SSH-соединений для одного хоста
- ✅ `max_sessions_per_conn` — лимит каналов на одно соединение
- ✅ `max_connections` — лимит соединений к хосту (default: 6)
- ✅ Авто-создание нового соединения при переполнении
- ✅ `run()`, `map()`, `close()` + `async with` контекстный менеджер

### 11. Обработка ошибок
- ✅ Иерархия: `UniconnError` → `ConnectionError`, `ExecutionError`, `TimeoutError`, `AuthenticationError`, `BMCCapabilityError`, `TransportNotFoundError`, `ScreenError`
- ✅ Контекст ошибки: command, exit_code, stdout, stderr, host

### 12. Безопасность
- ✅ Pydantic SecretStr для паролей
- ✅ `SecretMaskingFilter` в логах (на handlers — работает для дочерних логгеров)
- ✅ SSH known_hosts (strict / default / file / no)

### 13. CLI интерфейс
- ✅ typer + rich: `run`, `run-multi`, `bmc`, `shell`, `transports`, `screen-run`, `screen-logs`, `screen-status`, `screen-kill`, `version`
- ✅ Форматы вывода: table, json, plain

### 14. Клонирование подключений
- ✅ `copy(host=..., timeout=...)` — immutable clone с override
- ✅ `with_overrides({...})` — dict-based override

---

## P1 — Should have

### 15. Передача файлов (SFTP/SCP)
- ✅ Upload/download через `upload()`, `download()` (SSH SFTP)
- ✅ Recursive transfer — параметр `recurse=True` + автоопределение директорий
- ✅ Permissions — `chmod(remote_path, 0o755)` через SFTP
- ✅ Дополнительно: `stat()` (метаданные файла), `listdir()` (список файлов)

> Реализовано для SSH через asyncssh SFTP. Остальные транспорты не поддерживают файловые операции.

### 16. Полноценный PTY shell
- ✅ CLI `shell` переведён на `ShellSession.execute()` (stateful REPL)
- ✅ `open_shell(term_type, term_size)` (`Connection` и `SyncConnection`)
- ✅ Stateful сессия (`cd`, `export` сохраняются между вызовами `execute()`)
- ✅ Переключение `run` ↔ `shell` без реконнекта на одном SSH-подключении

> asyncssh поддерживает PTY через `create_process(term_type="xterm")`.

#### План реализации PTY shell

**Цель**: stateful shell-сессия поверх одного SSH-подключения: `cd`, `export`,
переменные окружения и текущая директория сохраняются между командами;
`run()` и shell работают на одном подключении без реконнекта (мультиплексинг
каналов SSH — shell это просто ещё один channel на том же `_conn`).

**Объём v1**: только SSH. Остальные транспорты — `NotImplementedError`
(тот же паттерн, что и у файловых операций в `_base.py`). Telnet — кандидат
на v2 (его поток по природе shell-like).

**Дизайн: маркерный протокол.** PTY объединяет stdout/stderr и не возвращает
exit code по команде, поэтому `execute()` оборачивает каждую команду:

```
{command}; echo "\n__UNICONN_{session_uuid}__$?"
```

Чтение идёт до regex-маркера `__UNICONN_{uuid}__(\d+)`. UUID в маркере —
защита от коллизии с пользовательским выводом. После открытия сессии
выполняется инициализация: `export PS1=''` (убрать prompt из вывода) и
`stty -echo` (убрать эхо команды; fallback — срезать первую строку вывода,
если `stty` недоступен).

##### Этап 1. Транспортный уровень
- `transports/_base.py`: `async def open_shell(term_type="xterm", term_size=(80, 24), **kwargs)`
  — базовая реализация бросает `NotImplementedError` (как `upload()` и др.)
- `transports/_ssh.py`: реализация через
  `self._conn.create_process(term_type=..., term_size=..., encoding="utf-8")`
  без аргумента command (открывает login shell пользователя с PTY).
  Проверка `is_connected` (как в `run()`/`stream()`), возврат живого
  `asyncssh.SSHClientProcess` — управление им на уровне `ShellSession`
- Закрытие процесса при `disconnect()` транспорта (список активных
  shell-процессов, terminate при закрытии — иначе канал повиснет)

##### Этап 2. `ShellSession` (`src/uniconn/_shell.py`, новый модуль)
- Класс `ShellSession` (async): обёртка над PTY-процессом + маркерный протокол
- API:
  - `execute(command, timeout=None) -> Result` — отправка команды, чтение до
    маркера, сбор вывода в `Result` (stderr пуст — PTY сливает потоки, задокументировать)
  - `send(text)` — низкоуровневая запись в stdin (для интерактивных сценариев)
  - `receive(timeout) -> str` — низкоуровневое чтение доступного вывода
  - `resize(cols, rows)` — `proc.change_terminal_size()`
  - `close()` — Ctrl-C (`\x03`) на случай зависшей команды, затем `exit\n`,
    terminate процесса
  - `async with` контекстный менеджер
  - свойство `is_alive` — процесс не завершён
- Таймаут `execute()`: `asyncio.wait_for` на чтении; при таймауте — Ctrl-C в
  stdin + `uniconn.TimeoutError` (ловится retry на уровне Connection)
- Смерть shell-процесса (exit по `exit`/kill) → `ConnectionError` при
  следующем `execute()`
- Внутреннее состояние: буфер чтения, UUID маркера, lock на `execute()`
  (параллельные execute в одной сессии запрещены — данные перемешаются)

##### Этап 3. Интеграция в `Connection`
- `Connection.open_shell(term_type="xterm", term_size=(80, 24)) -> ShellSession`:
  lazy connect (как `run()`), делегирует транспорту, оборачивает процесс
  в `ShellSession`, выполняет инициализацию (PS1, stty)
- Несколько одновременных shell-сессий на одном Connection — допустимо
  (отдельные SSH-каналы), оформить тестом
- Экспорт `ShellSession` в `src/uniconn/__init__.py` (`__all__`)

##### Этап 4. Sync-обёртка
- `SyncConnection.open_shell() -> SyncShellSession` — тонкая обёртка над
  async-сессией через `run_coroutine_threadsafe` (паттерн существующих
  методов `_sync.py`); методы `execute/send/receive/resize/close`, `with`

##### Этап 5. CLI `shell`
- Перевести команду `shell` (`cli.py:331`) с цикла `run()` на
  `ShellSession.execute()` — REPL станет stateful (cd/export сохраняются),
  интерфейс команды без изменений
- Полноценный raw-mode passthrough терминала (как `ssh` в интерактиве) —
  НЕ входит в v1: сложно и ненадёжно на Windows; отдельной задачей при запросе

##### Этап 6. Тесты (`tests/unit/test_shell.py`, новый файл)
- Мок asyncssh-процесса (fake stdin/stdout как в `test_ssh_transport.py`):
  - `execute()` → корректный Result, парсинг exit code из маркера
  - statefulness: `cd /tmp` затем `pwd` → `/tmp`; `export X=1` затем `echo $X`
  - маркер с UUID не ломается на выводе, содержащем похожий текст
  - таймаут execute → Ctrl-C отправлен, брошен `uniconn.TimeoutError`
  - смерть процесса → `ConnectionError` на следующем execute
  - параллельный execute → блокируется/ошибка (lock)
  - `open_shell` на Local/Telnet/Serial/IPMI → `NotImplementedError`
  - `open_shell` без connect → lazy connect сработал
  - закрытие транспорта с активной сессией → процесс терминирован
- `tests/unit/test_sync.py`: `SyncShellSession.execute/close`, контекстный менеджер
- `tests/unit/test_cli.py`: CLI `shell` использует ShellSession (мок)
- Integration (docker sshd, опционально): реальный PTY против
  `linuxserver/openssh-server`

##### Этап 7. Документация
- `examples/interactive_shell.py` — stateful-сессия: cd/export, execute, resize
- `docs/api.rst` — `ShellSession`, `Connection.open_shell()`
- `README.md`, `AGENTS.md` — новый API в соответствующие разделы
- `instractions.md` — статусы §16 на ✅ после завершения

##### Порядок работ и оценка
1. Этапы 1–3 — ядро (~основная часть работы)
2. Этап 6 (unit) — параллельно с ядром, тесты на каждый этап
3. Этап 4 (sync) — малая обёртка
4. Этап 5 (CLI) — точечная замена
5. Этап 7 — финал

**Риски и решения:**
- *Шум в выводе* (motd, prompt, echo) → `PS1=''` + `stty -echo` при инициализации
- *Коллизия маркера с выводом* → UUID в маркере
- *Зависшая команда без таймаута* → обязательный timeout в execute, Ctrl-C
- *Windows-совместимость CLI* → v1 без raw-mode passthrough
- *Локальные транспорты* → явный `NotImplementedError`, не молчаливый fallback

### 17. CI/CD (Не реализовывать)
- ❌ GitHub Actions (test, lint, type check)
- ❌ PyPI publishing
- ❌ Integration tests в CI

### 18. Документация
- ✅ Sphinx с RTD theme — `docs/index.rst`, `docs/api.rst`, `docs/transports.rst`
- ✅ examples/ директория с 7 примерами + YAML-конфигом:
  - `basic_usage.py` — async/sync API, from_dict, from_file, copy, with_overrides
  - `parallel_execution.py` — ConnectionPool с map/map_safe/callback
  - `file_transfer.py` — SFTP upload/download, chmod, stat, listdir
  - `health_check.py` — is_alive(), массовая проверка хостов
  - `bmc_management.py` — IPMI операции
  - `custom_transport.py` — создание кастомного транспорта
  - `screen_monitoring.py` — ScreenPool: screen-сессии, poll_logs/poll_status
  - `screen_pool_config.yaml` — пример конфигурации ScreenPool

### 19. `run_commands(commands)` — батч
- ✅ Последовательное выполнение списка команд
- ✅ `stop_on_error=True` — прерывание на первой ошибке (по умолчанию)
- ✅ Синхронная обёртка в `SyncConnection`

### 19a. Фоновые screen-сессии (ScreenPool)
- ✅ `ScreenPool` — запуск долгоживущих команд в detached GNU screen через SSH
- ✅ Лимиты: `max_screens` (→ `ScreenPoolFullError`), `max_monitors` (семафор на SSH-запросы)
- ✅ `LogPipeline` — правила из `LogConfig`: local file (шаблоны имён), forward, null
- ✅ Сбор логов порциями (`ScreenLogCollector`, байтовый offset + `tail -c`)
- ✅ Многоуровневый cleanup: atexit/signal, sentinel-файл, cleanup-скрипт на сервере
- ✅ CLI: `screen-run`, `screen-logs`, `screen-status`, `screen-kill`
- ✅ Конфигурация из YAML/JSON (`ScreenPoolConfig.from_file`)

> Примеры: `examples/screen_monitoring.py`, `examples/screen_pool_config.yaml`.

---

## P2 — Nice to have

### 20. Middleware / цепочки обработчиков
- ❌ Hooks / callbacks (`before_run`, `after_run`, `on_error`) для логирования, метрик и трассировки (кандидат на v0.4.0)

### 22. Автореконнект и Heartbeat
- ✅ Auto-reconnect с backoff при ошибках `run()` (через `tenacity` + `disconnect()`/`connect()`)
- ✅ SSH Heartbeat / Keepalive для долгоживущих соединений (`options={"keepalive": 30, "keepalive_count_max": 3}`)

### 23. Продвинутая аутентификация
- ✅ Управление SSH-агентом (`options={"use_agent": True, "agent_path": "..."}`)
- ✅ Сертификаты OpenSSH (`options={"client_cert": "/path/to/id-cert.pub"}`)

### 24. Прокси и SSH Config
- ✅ Jump / Bastion хосты (`options={"proxy": "ssh://jump"}`)
- ✅ Интеграция с `~/.ssh/config` (`options={"ssh_config": True}` или путь к файлу)
- ❌ SOCKS5/HTTP прокси (`proxy_command`)

---

## P3 — Future

### 26. Shell escaping
- ✅ List-based command args (`command: str | Sequence[str]`) с автоэкранированием через `shlex.join` во всех методах (`run`, `run_commands`, `stream`, `ShellSession.execute`)
- ✅ Экспорт `uniconn.quote` (`shlex.quote`) для безопасной подстановки в строковые команды

### 29. Warnings для незашифрованных транспортов
- ✅ Предупреждение (`logger.warning`) при подключении через Telnet/Serial

### 30. Стандартный ввод (`stdin`) и байтовый режим
- ✅ Поддержка `input: str | bytes | None = None` (`stdin`) в `run()` для SSH и Local транспортов
- ❌ `run_bytes()` → raw bytes вместо str

---

## Реализованные архитектурные решения

| Решение | Описание |
|---------|----------|
| `AsyncRetrying` вместо `@retry` | Динамический `retry_attempts` из экземпляра, не захардкожен |
| Постоянный event loop в daemon-потоке (`SyncConnection`) | `run_coroutine_threadsafe`, инкрементальный `stream()` через `asyncio.Queue`, `close()` без зависаний |
| `pyright standard` вместо `mypy strict` | Меньше шума от optional dependencies, 0 ошибок типизации по всему `src/` |
| `dependency-groups.dev` | Замена deprecated `tool.uv.dev-dependencies` |
| `type(self)` в `copy()` | Корректная работа с наследниками Connection |
| `SecretStr` конвертация в `copy()` | Принимает str и SecretStr, автоматически оборачивает |
| Lazy connect | Подключение при первом `run()` или явно через `async with` |
| `SSHSessionPool` | Мультиплексинг SSH-каналов: ленивое создание соединений при переполнении |
| `ShellSession` (PTY) | Маркерный протокол `__UNICONN_{uuid}__{exit_code}` для сохранения состояния (`cd`, `export`) |
| `shlex.join` для `Sequence[str]` | Единообразное безопасное экранирование списков аргументов в `Connection` и `ShellSession` |

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
| Мониторинг (`prometheus_client`) | Избыточная зависимость в ядре библиотеки; решается через кастомный логгер/хуки |
| MFA / OTP / Keyboard-interactive | Противоречит автоматизированному (non-interactive) сценарию и `BatchMode` |
| OpenSSH `ControlMaster` (§25) | Специфичен для CLI `ssh`; в `uniconn` уже реализован нативный `SSHSessionPool` (§10a) |
| OS Keyring integration (§27) | Серверные и контейнерные окружения не имеют системного GUI keyring |
| SemVer deprecation cycle (§28) | Процессное правило поддержки после `v1.0.0`, не функциональная фича |

---

## Технологический стек

| Компонент | Зависимость |
|-----------|-------------|
| Core | `pydantic>=2.0`, `tenacity>=8.0` |
| SSH | `asyncssh>=2.13` |
| Telnet | `telnetlib3>=2.0` |
| Serial | `pyserial-asyncio>=0.6` |
| BMC | `pyghmi>=1.5` |
| CLI | `typer>=0.9`, `rich>=13.0` |
| Dev | `pytest`, `pyright`, `ruff`, `testcontainers`, `pyyaml` |
