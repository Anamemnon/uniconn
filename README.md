# uniconn

Универсальная Python библиотека для выполнения команд на удалённых хостах через различные транспорты: SSH, Telnet, Serial/UART, IPMI и локальное выполнение.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Особенности

- 🚀 **Множественные транспорты**: SSH, Telnet, Serial/UART, IPMI, локальное выполнение
- ⚡ **Async-first архитектура**: Построена на `asyncio` с синхронной обёрткой
- 🔌 **Плагинная система**: Транспорты загружаются динамически через entry-points
- 🔒 **Безопасность**: `SecretStr` для паролей и `passphrase`, безопасный `sudo` через `stdin`, режим `sensitive=True`, автоэкранирование списков аргументов (`shlex.join`)
- 🪝 **Lifecycle Hooks и `uniconn.hooks`**: Перехватчики `before_run`, `after_run`, `on_error` и готовые пресеты (`audit_log_hook`, `structured_log_hook`, `allowlist_hook`, `blocklist_hook`, `metrics_collector_hook`) + режим `dry_run`
- 📈 **Структурированные логи (`structlog`)**: JSONL и консольный вывод (`configure_logging`), сквозной контекст (`log_context` / `contextvars`) и готовые метрики для **Grafana Loki, ClickHouse, InfluxDB**
- 📂 **Контекстные менеджеры `cd()`, `env()`, `temp_dir()`**: Удобная работа с директориями, переменными окружения и временными папками
- 🔄 **Повторные попытки**: Встроенный retry с экспоненциальным backoff и автореконнектом
- 📊 **Пул соединений**: Параллельное выполнение на множестве хостов (`ConnectionPool` и `SyncConnectionPool` со стримингом `pool.stream()`, а также `SSHSessionPool` с `check_health()`)
- 🔎 **Инспекция хостов и идемпотентность**: Автосбор фактов `gather_facts()` (`HostFacts`) и идемпотентные проверки `ensure_package()`, `ensure_service()`, `ensure_line()` (`EnsureResult`)
- 📁 **Файловые операции, SFTP и шаблоны**: `read_file`/`write_file`, `remove_file`, `exists`, `mkdir`, `upload`/`download`, дельта-синхронизация директорий `sync_dir()` (`SyncResult`) и рендеринг шаблонов `write_template()` (`jinja2` / `string.Template`)
- 💻 **Stateful PTY Shell, Expect и Туннели**: Интерактивные сессии `ShellSession` (SSH, Local, Telnet, Serial), декларативный автомат диалогов `expect()` и проброс портов `forward_local_port()` / `forward_remote_port()`
- 🖥️ **ScreenPool**: Долгоживущие команды в detached GNU screen сессиях с `LogPipeline`
- 🛠️ **Модульный CLI (`cyclopts` + `rich`)**: Командная строка с поддержкой инвентаря (`--inventory`, `--group`), `facts`, `ensure-*`, `sync-dir`, `template`, `expect`, `tunnel`, `stream-multi`, `--sudo` и `--log-format json`
- 🌐 **Интерактивная веб-панель**: Встроенный веб-интерфейс (`python3 main.py --serve`) для интерактивного тестирования команд, хуков, `structlog`-телеметрии, пулов хостов, конструктора URI и запуска unit-тестов

## Установка

Легковесная установка ядра (SSH, Local, устойчивый конвейер команд, структурированное логирование и YAML/JSON инвентари):

```bash
pip install uniconn
# или через uv:
uv add uniconn
```

Полная установка со всеми специализированными транспортами (Telnet, Serial, BMC/IPMI/Redfish), шаблонизатором Jinja2 и CLI:

```bash
pip install "uniconn[all]"
# или выборочные extras:
pip install "uniconn[cli]"          # CLI интерфейс (cyclopts, rich)
pip install "uniconn[bmc]"          # IPMI (pyghmi) и Redfish (niquests)
pip install "uniconn[serial]"       # Serial/UART (pyserial-asyncio)
pip install "uniconn[telnet]"       # Telnet (telnetlib3)
pip install "uniconn[templates]"    # Jinja2 шаблонизатор
```

### Разработка

```bash
git clone https://github.com/yourusername/uniconn.git
cd uniconn
uv sync
```

## Быстрый старт

### Базовое использование (Async)

```python
import asyncio
from uniconn import Connection

async def main():
    # SSH подключение
    async with Connection.from_uri("ssh://user:password@host") as conn:
        result = await conn.run("uptime")
        print(f"Exit code: {result.exit_code}")
        print(f"Output: {result.stdout}")

asyncio.run(main())
```

### Синхронное использование

```python
from uniconn import Connection

# Синхронная обёртка
with Connection.from_uri("ssh://user:password@host").to_sync() as conn:
    result = conn.run("uptime")
    print(result.stdout)
```

### Параллельное выполнение

```python
import asyncio
from uniconn import ConnectionPool

async def main():
    hosts = [
        "ssh://user:pass@host1",
        "ssh://user:pass@host2",
        "ssh://user:pass@host3",
    ]
    
    pool = ConnectionPool(hosts, max_concurrent=5)
    results = await pool.map("uptime")
    
    for host, result in zip(hosts, results):
        print(f"{host}: {result.stdout.strip()}")

asyncio.run(main())
```

## Интерактивная веб-панель (Web Dashboard)

В состав репозитория входит интерактивная веб-панель (`examples/dashboard/server.py` и `examples/dashboard/index.html`), позволяющая тестировать возможности `uniconn` в браузере без необходимости поднимать внешние серверы.

### Запуск веб-страницы

```bash
# Запуск HTTP-сервера предпросмотра на http://0.0.0.0:3000 (требуется Python 3.11+)
uv run python main.py --serve

# Или напрямую (скрипт автоматически активирует .venv с Python 3.12+ при наличии):
python3 main.py --serve
```

После запуска откройте в браузере адрес **http://localhost:3000**.

> При запуске `python3 main.py` без флага `--serve` в терминале выполняется консольная демонстрация основных возможностей библиотеки.

### Возможности веб-интерфейса

Веб-панель разделена на 5 интерактивных рабочих областей:

1. **Shell & Local Runner (`ShellSession` / `LocalTransport`)** — интерактивный запуск команд в stateful PTY-сессии `ShellSession.execute()` (с сохранением рабочей директории `cd`, переменных окружения `export` и размера терминала `cols × rows`) или через `Connection("local://").run()`, с детальным инспектором объекта `Result` (`stdout`, `stderr`, `.lines`, `.json()`, `.to_dict()`, время выполнения).
2. **Hooks, Security & Telemetry (`CommandPipeline` & `structlog`)** — песочница конвейера middleware и хуков (`allowlist_hook`, `blocklist_hook`, `audit_log_hook`, `structured_log_hook`, `metrics_collector_hook`), тестирование флагов `sudo`, `sensitive=True`, `dry_run=True`, контекстных менеджеров `conn.cd()` и `conn.temp_dir()`, а также просмотр `structlog` JSONL и консольных логов с маскированием секретов в реальном времени.
3. **Pool, Inventory & Screen (`ConnectionPool` & `ScreenPool`)** — оркестратор мульти-хостового пула с редактируемым YAML-инвентарём, фильтрацией по группам (`all`, `web`, `backend`), готовыми пресетами (`Fleet Presets`) и групповыми операциями (`map_safe`, `apply`, `gather_facts`, `ensure_line`, `sync_dir`, `write_template`, `stream`), плюс симулятор `ScreenPool` / `LogPipeline` и интерактивные песочницы функций релизов `v0.7.0` и `v0.8.0`.
4. **URI Builder & Codegen (`URIParser` & `ConnectionConfig`)** — визуальный конструктор и валидатор URI для всех транспортов (`ssh://`, `telnet://`, `serial://`, `ipmi://`, `local://`) с безопасным представлением `uri_safe` и автоматической генерацией готовых сниппетов кода (Async Python, Sync Python и CLI).
5. **Unit Test Runner (`pytest`)** — запуск всех 458 unit-тестов или отдельных тематических пакетов (`core`, `transports`, `pools`, `screen`, `cli`, `releases`) прямо из браузера с отображением статуса и консольного вывода.

## Документация API

### Connection

Основной класс для работы с удалёнными хостами.

#### Создание подключения

```python
from uniconn import Connection, ConnectionConfig

# Из URI
conn = Connection.from_uri("ssh://user:pass@host:22")

# Из конфигурации
config = ConnectionConfig(
    transport="ssh",
    host="example.com",
    port=22,
    username="admin",
    password="secret",  # SecretStr
    key_file="/path/to/key",
    timeout=60.0,
)
conn = Connection.from_config(config)
```

#### Методы

##### `run(command, timeout=None, raise_on_error=False, input=None, sudo=False, sudo_user=None, sudo_password=None, sensitive=False, dry_run=None, **kwargs) -> Result`

Выполнить команду на удалённом хосте (строкой или списком аргументов с автоэкранированием через `shlex.join`).

**Параметры:**
- `command` (`str | Sequence[str]`): Команда для выполнения (строка или список аргументов)
- `timeout` (`float`, optional): Таймаут в секундах
- `raise_on_error` (`bool`): Выбросить `ExecutionError` при ненулевом exit code
- `input` (`str | bytes`, optional): Данные для передачи в `stdin` процесса
- `sudo` (`bool`): Выполнить команду через `sudo` (пароль передаётся через закрытый `stdin`)
- `sudo_user` (`str`, optional): Пользователь для `sudo -u <user>`
- `sudo_password` (`str | SecretStr`, optional): Пароль для `sudo` (по умолчанию берётся из `config.password`)
- `sensitive` (`bool`): Скрыть вывод в логах, `repr(Result)` и `ExecutionError` (`***REDACTED***`)
- `dry_run` (`bool`, optional): Пропустить реальное выполнение команды
- `**kwargs`: Дополнительные аргументы для транспорта (`cwd`, `env`)

**Возвращает:**
- `Result`: Объект результата выполнения

**Пример:**
```python
# Строковая команда или безопасный список аргументов
result = await conn.run(["ls", "-la", "/var/log"], timeout=30, raise_on_error=True)

# Безопасное повышение привилегий через sudo и передача stdin
await conn.run(["systemctl", "restart", "nginx"], sudo=True)

# Скрытие чувствительного вывода в логах и исключениях
token_res = await conn.run("cat /etc/app/token", sudo=True, sensitive=True)
```

##### `run_bytes(command, timeout=None, raise_on_error=False, input=None, sudo=False, **kwargs) -> bytes`

Выполнить команду и получить сырой бинарный вывод (`bytes`) без декодирования в UTF-8.

```python
archive_bytes = await conn.run_bytes(["tar", "-czf", "-", "/etc/nginx"], sudo=True)
```

##### Контекстные менеджеры `cd(path)` и `env(**vars)`

Позволяют задать рабочую директорию и переменные окружения для группы команд (поддерживают вложенность и работают как с `async with`, так и с `with`):

```python
async with conn.cd("/srv/myapp"), conn.env(APP_ENV="production"):
    await conn.run(["git", "pull"])
    async with conn.cd("migrations"):
        await conn.run(["uv", "run", "alembic", "upgrade", "head"])
```

##### Lifecycle Hooks (`before_run`, `after_run`, `on_error`) и пресеты `uniconn.hooks`

```python
from uniconn.hooks import (
    allowlist_hook,
    audit_log_hook,
    blocklist_hook,
    metrics_collector_hook,
    structured_log_hook,
)

# Белый и чёрный списки команд (выбрасывают PermissionError до выполнения)
conn.add_hook("before_run", allowlist_hook(["uptime", "df", "ls", "systemctl status"]))
conn.add_hook("before_run", blocklist_hook())

# Запись JSONL-аудита и отправка структурированных метрик в structlog
conn.add_hook("after_run", audit_log_hook("/var/log/uniconn_audit.jsonl"))
conn.add_hook("after_run", structured_log_hook(tags={"env": "prod", "dc": "eu-1"}))

# Сбор агрегированной статистики по хостам
metrics = metrics_collector_hook().attach(conn)
# После выполнения команд: metrics.to_dict() -> total_runs, avg_duration, by_host
```

##### `run_commands(commands, stop_on_error=True, **kwargs) -> List[Result]`

Последовательно выполнить список команд на хосте.

**Пример:**
```python
results = await conn.run_commands(["uptime", "df -h", "free -m"])
for r in results:
    print(r.command, r.exit_code)
```

##### `stream(command, timeout=None, **kwargs) -> AsyncIterator[str]`

Потоковое выполнение команды с построчным выводом.

**Пример:**
```python
async for line in conn.stream("tail -f /var/log/syslog"):
    print(line)
```

##### `is_alive(timeout=None) -> bool`

Проверить живость подключения (лёгкая проверка через транспорт).

**Пример:**
```python
if await conn.is_alive():
    print("Host is alive")
```

##### `close() -> None`

Закрыть подключение.

##### `open_shell(term_type="xterm", term_size=(80, 24), **kwargs) -> ShellSession`

Открыть интерактивную stateful PTY shell-сессию (для SSH). Между вызовами
`execute()` сохраняются рабочая директория (`cd`), переменные окружения
(`export`) и состояние оболочки; сессия работает поверх того же SSH-подключения
параллельно с `run()` без переподключения.

**Пример:**
```python
async with await conn.open_shell() as shell:
    await shell.execute("cd /var/log")
    res = await shell.execute("pwd")
    print(res.stdout)  # /var/log

    await shell.execute("export MY_VAR=42")
    res = await shell.execute("echo $MY_VAR")
    print(res.stdout)  # 42

    await shell.resize(120, 40)
```

#### Файловые операции (SFTP и работа в памяти)

```python
# Чтение и запись файлов напрямую из памяти (работает для SSH SFTP и Local)
await conn.write_file("/etc/myapp/config.yaml", "port: 8080\n", mode=0o600)
text = await conn.read_file("/etc/myapp/config.yaml")
raw_bytes = await conn.read_file("/etc/myapp/config.yaml", encoding=None)

# Загрузка файла/директории на хост (SFTP)
await conn.upload("/local/file.txt", "/remote/file.txt")
await conn.upload("/local/dir", "/remote/dir", recurse=True)

# Скачивание файла/директории с хоста (SFTP)
await conn.download("/remote/file.txt", "/local/file.txt")

# Права доступа, информация о файле, список директории (SFTP)
await conn.chmod("/remote/script.sh", 0o755)
info = await conn.stat("/remote/file.txt")   # size, mtime, is_dir, ...
files = await conn.listdir("/var/log")
```

##### `to_sync() -> SyncConnection`

Получить синхронную обёртку.

**Пример:**
```python
sync_conn = conn.to_sync()
result = sync_conn.run("uptime")
```

#### Контекстный менеджер

```python
async with Connection.from_uri("ssh://user@host") as conn:
    result = await conn.run("uptime")
# Подключение автоматически закрывается
```

### ConnectionConfig

Pydantic модель для конфигурации подключения.

```python
from uniconn import ConnectionConfig
from pydantic import SecretStr

config = ConnectionConfig(
    transport="ssh",           # Тип транспорта
    host="example.com",        # Хост или IP
    port=22,                   # Порт (опционально)
    username="admin",          # Имя пользователя
    password=SecretStr("pass"), # Пароль
    key_file="/path/to/key",   # Путь к SSH ключу
    timeout=30.0,              # Таймаут по умолчанию
    options={                  # Дополнительные опции
        "compress": True,
    }
)
```

**Поля:**
- `transport` (str): Тип транспорта (ssh, telnet, serial, local, ipmi)
- `host` (str | None): Хост, IP или устройство
- `port` (int | None): Порт подключения
- `username` (str | None): Имя пользователя
- `password` (SecretStr | None): Пароль
- `key_file` (str | None): Путь к файлу ключа
- `timeout` (float): Таймаут операций (по умолчанию 30.0)
- `options` (dict): Дополнительные опции транспорта

### ConnectionPool

Пул подключений для параллельного выполнения команд и групповых операций. Поддерживает как одноразовые вызовы, так и удержание открытых соединений через `async with`:

```python
from uniconn import ConnectionPool

hosts = ["ssh://host1", "ssh://host2", "ssh://host3"]

# Или из инвентарного YAML/JSON файла (с фильтрацией по группе):
# pool = ConnectionPool.from_file("inventory.yaml", group="production")

async with ConnectionPool(hosts, max_concurrent=10, retry_attempts=3) as pool:
    # Соединения открываются один раз и переиспользуются
    await pool.map("apt-get update", sudo=True)
    await pool.upload("./app.conf", "/etc/app/app.conf")
    saved = await pool.download("/var/log/syslog", "/tmp/logs/{host}.log")
    custom = await pool.apply(lambda conn: conn.run("hostname"))
```

#### Методы

##### `map(command, timeout=None, raise_on_error=False, **kwargs) -> List[Result]`

Выполнить команду на всех хостах пула (пробрасывает `sudo`, `sensitive`, `dry_run`, `cwd`, `env`).

**Пример:**
```python
results = await pool.map("uptime", timeout=30)
for result in results:
    print(result.text)
```

##### `map_safe(command, timeout=None, **kwargs) -> Dict[str, Result | Exception]`

Безопасное выполнение с возвратом исключений вместо выброса.

**Пример:**
```python
results = await pool.map_safe("uptime")
for uri, result in results.items():
    if isinstance(result, Exception):
        print(f"{uri}: Ошибка - {result}")
    else:
        print(f"{uri}: {result.text}")
```

##### `map_with_callback(command, callback, timeout=None, **kwargs) -> None`

Выполнение с callback по мере готовности результатов.

##### `upload(local_path, remote_path, recurse=False, **kwargs) -> None` и `download(remote_path, local_path, recurse=False, **kwargs) -> Dict[str, str]`

Параллельная загрузка и скачивание файлов со всех хостов пула.

##### `apply(func: Callable[[Connection], Awaitable[T]]) -> List[T]`

Параллельный запуск произвольной асинхронной функции `func(conn)` на всех хостах пула.

### Result

Результат выполнения команды.

```python
from uniconn import Result

result: Result = await conn.run("uptime")

# Использование в условиях (делегирует в result.ok)
if result:
    print(result.text)

# Свойства
result.exit_code     # Код возврата (int)
result.stdout        # Стандартный вывод (str)
result.stderr        # Ошибки (str)
result.text          # Очищенный stdout.strip() (str)
result.lines         # Список строк stdout.strip().splitlines() (list[str])
result.duration      # Время выполнения в секундах (float)
result.command       # Выполненная команда (str)
result.timestamp     # Время выполнения (datetime)
result.host          # Хост (str | None)
result.ok            # True если exit_code == 0 (bool)

# Методы
result.json()              # Распарсить stdout как JSON
result.to_dict()           # Сериализовать в dict (с маскированием при sensitive=True)
result.raise_for_status()  # Выбросить ExecutionError если exit_code != 0
```

### SyncConnection

Синхронная обёртка над async Connection.

```python
from uniconn import Connection

with Connection.from_uri("ssh://user@host").to_sync() as conn:
    # Все методы синхронные
    result = conn.run("uptime")
    print(result.stdout)
```

**Методы:**
- `run(command, timeout=None, raise_on_error=False, **kwargs) -> Result`
- `run_commands(commands, stop_on_error=True, **kwargs) -> List[Result]`
- `stream(command, timeout=None, **kwargs) -> Iterator[str]` — инкрементальный стриминг
- `open_shell(term_type="xterm", term_size=(80, 24), **kwargs) -> SyncShellSession` — синхронная stateful PTY-сессия
- `is_alive(timeout=None) -> bool`
- `close() -> None`

### SSHSessionPool

Пул SSH-сессий для одного хоста: мультиплексинг нескольких каналов по одному
подключению (с дополнительными подключениями при превышении лимита).

```python
from uniconn import SSHSessionPool

# До 6 параллельных каналов на одно SSH-подключение с автопроверкой живости
async with SSHSessionPool("ssh://user@host", max_sessions_per_conn=6, health_check=True) as pool:
    results = await pool.map(["lshw", "dmidecode", "nvme list", "sensors"])
    alive_conns = await pool.check_health()
```

### ScreenPool

Долгоживущие команды в detached GNU screen сессиях через SSH: сессии
переживают обрыв SSH, логи собираются периодическим опросом.

```python
from uniconn import ScreenPool

async with ScreenPool("ssh://admin@server", max_screens=8, max_monitors=2) as pool:
    await pool.start("stress-ng --cpu 4")
    await pool.start("sysbench --test=cpu run")

    async for event in pool.poll_logs(interval=2.0):
        print(f"[{event.session_id}] {event.line.rstrip()}")

    results = await pool.wait_all(timeout=3600.0)
```

Также из конфигурационного файла (см. `examples/screen_pool_config.yaml`):

```python
pool = ScreenPool.from_file("screen_pool_config.yaml")
```

## Поддерживаемые транспорты

### SSH

```python
# Базовая аутентификация
conn = Connection.from_uri("ssh://user:pass@host")

# По ключу
conn = Connection.from_uri("ssh://user@host?key_file=/path/to/key")

# С кастомным портом
conn = Connection.from_uri("ssh://user:pass@host:2222")
```

**Зависимости:** `pip install uniconn[ssh]` (asyncssh)

### Telnet

```python
conn = Connection.from_uri("telnet://user:pass@host:23")

# С опциями терминала
conn = Connection.from_uri("telnet://host?term_type=vt100&timeout=60")
```

**Зависимости:** `pip install uniconn[telnet]` (telnetlib3)

### Serial/UART

Поддерживает схемы `serial://` и `uart://`, автоматический поиск по USB VID:PID, аппаратные сигналы (DTR/RTS/BREAK), бинарный ввод-вывод и потоковый пассивный мониторинг.

```python
# Linux / macOS (схема serial:// или uart://)
conn = Connection.from_uri("serial:///dev/ttyUSB0?baudrate=9600")
conn = Connection.from_uri("uart:///dev/ttyUSB0:115200")

# Windows (COM-порты, краткая запись скорости через двоеточие)
conn = Connection.from_uri("uart://COM3:115200?parity=even&stopbits=1.5")

# Авто-поиск по USB VID:PID (например, Silicon Labs CP2102 или FTDI)
conn = Connection.from_uri("uart://?vid=10c4&pid=ea60")

# Бинарный ввод-вывод Modbus RTU без перекодирования в UTF-8
response: bytes = await conn.run_bytes(
    b"\x01\x03\x00\x00\x00\x02\xC4\x0B",
    inter_byte_timeout=0.02,
)

# Пассивный мониторинг датчиков и GPS/GNSS (NMEA-0183)
async for line in conn.stream():
    print("NMEA:", line)

# Аппаратный сброс платы (ESP32, Arduino, STM32) импульсом DTR/RTS
await conn.transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.1)

# Перехват загрузчика (U-Boot, ROMMON) аппаратным сигналом BREAK
conn.transport.send_break(duration=0.25)
cts_ready: bool = conn.transport.get_cts()

# Перечисление доступных в системе портов
from uniconn import list_serial_ports
for port in list_serial_ports():
    print(port.device, port.description, port.vid_pid_hex)
```

**Параметры:**
- `baudrate` / `:baudrate`: Скорость (115200, 9600, 57600 и др., по умолчанию 9600)
- `parity`: Чётность (`N` / `NONE`, `E` / `EVEN`, `O` / `ODD`, `M` / `MARK`, `S` / `SPACE`)
- `stopbits`: Стоп-биты (1, 1.5, 2)
- `bytesize`: Длина байта (5, 6, 7, 8; по умолчанию 8)
- `xonxoff`: Программный flow control (`true`/`false`)
- `rtscts`: Аппаратный flow control RTS/CTS (`true`/`false`)
- `dsrdtr`: Аппаратный flow control DSR/DTR (`true`/`false`)
- `inter_byte_timeout`: Межсимвольный таймаут кадрирования пакетов (по умолчанию 0.05 с)
- `vid`, `pid`, `vid_pid`: Фильтрация USB-устройства по VID/PID (например, `10c4:ea60`)

**Зависимости:** `pip install "uniconn[serial]"` или `pip install "uniconn[uart]"` (`pyserial-asyncio`)

### IPMI (BMC)

```python
conn = Connection.from_uri("ipmi://admin:password@bmc.local")

# С кастомным портом
conn = Connection.from_uri("ipmi://admin:password@bmc.local:623")

# Команды
result = await conn.run("power status")  # Статус питания
result = await conn.run("power on")      # Включить
result = await conn.run("power off")     # Выключить
result = await conn.run("sensors")       # Сенсоры
```

**Доступные команды:**
- `power status` - Статус питания
- `power on` - Включить сервер
- `power off` - Выключить сервер
- `power cycle` - Цикл питания
- `sensors` - Данные сенсоров
- `boot device` - Boot устройство

**Зависимости:** `pip install uniconn[bmc]` (pyghmi, niquests)

### Локальное выполнение

```python
conn = Connection.from_uri("local://")

# Или
from uniconn import Connection
conn = Connection.from_uri("local://?timeout=60")
```

Используется для единообразия API при локальном выполнении команд.

## CLI Интерфейс

### Установка

```bash
pip install uniconn[cli]
```

### Команды

#### Выполнение команды и передача файлов

```bash
# SSH (с sudo и JSON-форматом результата)
uniconn run "ssh://user:pass@host" "systemctl status nginx" --sudo --format json

# Со структурированными JSON-логами в stderr (для пайплайнов и коллекторов)
uniconn --log-level DEBUG --log-format json run "ssh://user@host" "uptime"

# Загрузка и скачивание файлов (SFTP / Local)
uniconn upload "ssh://user@host" ./app.conf /etc/app/app.conf
uniconn download "ssh://user@host" /var/log/syslog ./syslog.log
```

#### Параллельное выполнение и инвентарь

```bash
# На нескольких хостах
uniconn run-multi "ssh://host1" "ssh://host2" -c "uptime"

# По группе хостов из YAML/JSON инвентаря с sudo и JSON-выводом
uniconn run-multi --inventory inventory.yaml --group web -c "nginx -t" --sudo -f json
```

#### BMC управление

```bash
# Статус питания
uniconn bmc "ipmi://admin:pass@bmc" "power status"

# Включить сервер
uniconn bmc "ipmi://admin:pass@bmc" "power on"

# Данные сенсоров
uniconn bmc "ipmi://admin:pass@bmc" sensors
```

#### Фоновые screen-сессии

```bash
# Запустить команду в detached screen-сессии (переживает отключение)
uniconn screen-run "ssh://user@host" -c "stress-ng --cpu 4"

# Несколько экземпляров со стримингом логов
uniconn screen-run "ssh://user@host" --instances 4 -c "sysbench cpu run" --logs

# Логи и статус сессии
uniconn screen-logs "ssh://user@host" --session-id uniconn_x_0 --follow
uniconn screen-status "ssh://user@host"

# Остановить сессию
uniconn screen-kill "ssh://user@host" --session-id uniconn_x_0
```

#### Интерактивная оболочка

```bash
uniconn shell "ssh://user:pass@host"
```

#### Список транспортов

```bash
uniconn transports
```

#### Перечисление Serial / COM портов

```bash
# Табличный вывод обнаруженных USB/UART устройств
uniconn serial-ports

# Машиночитаемый JSON-формат
uniconn serial-ports --format json
```

#### Версия

```bash
uniconn version
```

## Исключения

```python
from uniconn.exceptions import (
    UniconnError,        # Базовое исключение
    ConnectionError,     # Ошибки подключения
    AuthenticationError, # Ошибки аутентификации
    ExecutionError,      # Ошибки выполнения команды
    TimeoutError,        # Таймаут операции
    TransportNotFoundError,  # Транспорт не найден
    BMCCapabilityError,  # BMC не поддерживает операцию
)

try:
    result = await conn.run("command")
except AuthenticationError as e:
    print(f"Auth failed: {e}")
except TimeoutError as e:
    print(f"Timeout: {e}")
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

## Структурированное логирование (`structlog`) и наблюдаемость

`uniconn` использует `structlog` с поддержкой `contextvars` и автоматическим маскированием секретов (`SecretStr`, паролей в URI, `sudo_password` и вывода `sensitive=True`). Логи в формате `json` содержат типизированные метрики (`duration_ms`, `exit_code`, `ok`, `host`, `transport`, `stdout_bytes`), готовые для **Grafana Loki**, **ClickHouse** и **InfluxDB**.

```python
from uniconn import (
    Connection,
    configure_logging,
    get_struct_logger,
    log_context,
    structured_log_hook,
)

# 1. Включаем JSONL-формат (в stderr и/или файл)
configure_logging(level="INFO", fmt="json", log_file="uniconn_telemetry.jsonl")
log = get_struct_logger("deploy")

async with Connection.from_uri("ssh://admin@node-01") as conn:
    # 2. Подключаем хук телеметрии для ClickHouse / InfluxDB / Grafana
    conn.add_hook("after_run", structured_log_hook(tags={"env": "prod", "cluster": "eu-1"}))

    # 3. Привязываем сквозной контекст (автоматически добавляется во все логи внутри блока)
    async with log_context(release_id="v2026.10"):
        log.info("deploy.started")
        await conn.run(["systemctl", "restart", "app"], sudo=True)
```

## Расширяемость

### Создание кастомного транспорта

```python
from uniconn.transports import BaseTransport
from uniconn import Result

class MyTransport(BaseTransport):
    @property
    def name(self) -> str:
        return "mytransport"
    
    async def connect(self) -> None:
        # Установить подключение
        self._connected = True
    
    async def disconnect(self) -> None:
        # Закрыть подключение
        self._connected = False
    
    async def run(self, command, timeout=None, **kwargs) -> Result:
        # Выполнить команду
        return Result(
            exit_code=0,
            stdout="result",
            stderr="",
            duration=1.0,
            command=command,
            host=self.config.host
        )
    
    async def stream(self, command, timeout=None, **kwargs):
        # Потоковое выполнение
        yield "line1"
        yield "line2"
```

### Регистрация через entry-points

В `pyproject.toml`:

```toml
[project.entry-points."uniconn.transports"]
mytransport = "my_package.transports:MyTransport"
```

## Тестирование

```bash
# Запуск unit-тестов с кратким выводом для экономии контекста
uv run pytest -m "not integration" -q --tb=short | tail -n 5

# Повторный запуск только упавших тестов с трейсбеком
uv run pytest -m "not integration" -q --tb=short --lf | tail -n 30

# Интеграционные тесты (требуется Docker)
uv run pytest -m integration

# С покрытием
uv run pytest --cov=uniconn
```

## Лицензия

MIT License. См. [LICENSE](LICENSE) файл.

## Вклад в проект

1. Форкните репозиторий
2. Создайте ветку (`git checkout -b feature/amazing-feature`)
3. Закоммитьте изменения (`git commit -m 'Add amazing feature'`)
4. Запушьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## Благодарности

- [asyncssh](https://github.com/ronf/asyncssh) - SSH реализация
- [telnetlib3](https://github.com/jquast/telnetlib3) - Telnet протокол
- [pyserial-asyncio](https://github.com/pyserial/pyserial-asyncio) - Serial порты
- [pyghmi](https://github.com/openstack/pyghmi) - IPMI реализация
- [Pydantic](https://github.com/pydantic/pydantic) - Валидация данных
- [Tenacity](https://github.com/jd/tenacity) - Retry логика
- [Cyclopts](https://github.com/BrianPugh/cyclopts) - CLI интерфейс
- [Rich](https://github.com/Textualize/rich) - Форматирование вывода в терминале
- [structlog](https://github.com/hynek/structlog) - Структурированное логирование
