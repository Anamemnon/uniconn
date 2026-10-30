# uniconn

Универсальная async-first Python-библиотека (Python 3.11+) и CLI для выполнения команд, инспекции хостов, идемпотентного управления состоянием, передачи файлов и контрактного тестирования через единый фасад `Connection`: **SSH, Telnet, Serial/UART, IPMI BMC, Redfish BMC, Docker, Podman, Kubernetes (`kubectl`), Replay и Local**.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Особенности

- 🚀 **10 встроенных транспортов**: `ssh://` (с Jump-цепочками и `~/.ssh/config`), `telnet://`, `serial://` / `uart://`, `ipmi://`, `redfish://` (`niquests` HTTP/2), `docker://`, `podman://`, `kubectl://`, `replay://` и `local://`
- ⚡ **Прагматичный Async + Sync паритет**: Асинхронное ядро на `asyncio` и полная синхронная обёртка (`SyncConnection`, `SyncConnectionPool`, `SyncShellSession`) через единый фоновый `EventLoopPortal`
- 🧩 **Доменные сервисы (`conn.files`, `conn.state`, `conn.tunnels`)**: Чистое разделение файловых операций, идемпотентной конфигурации и SSH-туннелирования как для одиночного хоста, так и для пула (`pool.files`, `pool.state`)
- 🔒 **Безопасность и `SecretResolver`**: Автоматическое разрешение секретов из `env://VAR?default=...` и `file:///path`, `SecretStr`, безопасный `sudo` через `stdin`, маскирование при `sensitive=True` и автоэкранирование списков аргументов (`shlex.join`)
- 🛡️ **Отказоустойчивость и волновой роллаут**: Встроенные `CircuitBreaker`, `RateLimiter` (Token Bucket), экспоненциальный retry, каскадная раскатка в `ConnectionPool` (`batch_size`, `max_fail_ratio`, `BatchAbortedError`) и выборка подмножеств `pool.select()`
- ⏳ **Примитивы ожидания и проверки доступности**: `ping()` (`PingResult` с измерением RTT), `wait_for_connection()`, `wait_for_port()` (проверка с удалённого или локального хоста) и `wait_for_path()` (с проверкой `content_regex`)
- 🔎 **Инспекция хостов, поиск дрейфа и диагностика**: Автосбор фактов `gather_facts()` (с расширяемым `FactSpec`), сравнение кластера `pool.diff_facts()` (`FactsDiffReport`) и контекстный менеджер `conn.diagnostic_session()`
- 🧱 **Идемпотентное управление состоянием (`conn.state`)**: `ensure_package`, `ensure_service`, `ensure_file` (`atomic=True`, `validate`), `ensure_directory`, `ensure_line`, `ensure_user`, `ensure_authorized_key`, `ensure_systemd_unit`, `ensure_sysctl` с генерацией unified diff (`EnsureResult.diff`)
- 📁 **Файловый сервис (`conn.files`)**: Чтение/запись в памяти, атомарная замена `atomic=True`, проверка контрольных сумм `checksum()` и `verify=True`, рекурсивный SFTP, дельта-синхронизация `sync_dir()` (`SyncResult`) и шаблоны `write_template()` (`jinja2` / `string.Template`)
- 📼 **Контрактное тестирование и кассеты (`use_cassette`)**: Запись и детерминированное воспроизведение команд, потоков, SFTP и PTY-сессий в YAML/JSON-кассетах, `cassette.diff()`, `ReplayTransport` и `pytest`-плагин `@pytest.mark.uniconn_cassette`
- 💻 **Stateful PTY Shell, Expect и Туннели**: Интерактивные сессии `ShellSession`, декларативный автомат диалогов `expect()` и проброс портов `conn.tunnels.forward_local_port()` / `forward_remote_port()`
- 🖥️ **BackgroundPool**: Долгоживущие фоновые задачи в `tmux`, `screen`, `nohup` или `WindowsJobBackend` с потоковым сбором логов `LogPipeline`
- 📈 **Наблюдаемость (`structlog` + OpenTelemetry)**: JSONL/консольное логирование (`configure_logging`, `log_context`) и распределённая трассировка `otel_tracing_hook`
- 🛠️ **Модульный CLI (`cyclopts` + `rich`) и Веб-панель**: Богатый CLI (`run`, `run-multi`, `ping`, `wait-for`, `facts`, `tail`, `upload`, `download`, `sync`, `template`, `checksum`, `ensure-*`, `bg-*`, `record`, `replay`, `cassette`) и интерактивный дашборд (`python3 main.py --serve`)

## Установка

Легковесная установка ядра (SSH, Local, Docker, Podman, Kubectl, Replay, конвейер команд, структурированное логирование и YAML/TOML/JSON инвентари):

```bash
pip install uniconn
# или через uv:
uv add uniconn
```

Полная установка со всеми специализированными транспортами (Telnet, Serial/UART, BMC IPMI/Redfish), шаблонизатором Jinja2 и CLI:

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

async def main() -> None:
    # SSH подключение (поддерживает env:// и file:// ссылки на секреты)
    async with Connection.from_uri("ssh://admin:env://SSH_PASS@node-01.internal") as conn:
        ping = await conn.ping()
        print(f"Host alive: {ping.alive} ({ping.latency_ms:.1f} ms)")

        result = await conn.run(["uptime"])
        print(f"Exit code: {result.exit_code}, output: {result.text}")

        # Работа с файлами через доменный сервис conn.files
        await conn.files.write_file("/etc/myapp.conf", "port = 8080\n", atomic=True)

        # Идемпотентное управление состоянием через conn.state
        ens = await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)
        print(f"Service nginx changed: {ens.changed}")

asyncio.run(main())
```

### Синхронное использование (`SyncConnection`)

```python
from uniconn import Connection, SyncConnection

# Напрямую через SyncConnection или метод .to_sync()
with SyncConnection.local() as conn:
    result = conn.run(["uname", "-s"])
    print(result.text)
```

### Параллельное выполнение и волновой роллаут (`ConnectionPool`)

```python
import asyncio
from uniconn import ConnectionPool

async def main() -> None:
    hosts = [
        "ssh://admin@node-01",
        "ssh://admin@node-02",
        "ssh://admin@node-03",
        "ssh://admin@node-04",
    ]

    # Каскадная раскатка батчами по 2 хоста с остановкой при ошибках (max_fail_ratio=0.0)
    async with ConnectionPool(hosts, max_concurrent=4, batch_size=2, max_fail_ratio=0.0) as pool:
        results = await pool.map("uptime")
        for res in results:
            print(f"{res.host}: {res.text}")

        # Сравнение системных фактов и поиск дрейфа конфигураций
        drift = await pool.diff_facts()
        print(f"Cluster has drift: {drift.has_drift}")

asyncio.run(main())
```

## Интерактивная веб-панель (Web Dashboard)

В состав репозитория входит интерактивная веб-панель (`examples/dashboard/server.py` и `examples/dashboard/index.html`), позволяющая тестировать возможности `uniconn` в браузере без необходимости поднимать внешние серверы.

### Запуск веб-страницы

```bash
# Запуск HTTP-сервера предпросмотра на http://0.0.0.0:3000 (требуется Python 3.11+)
uv run python main.py --serve

# Или напрямую:
python3 main.py --serve
```

После запуска откройте в браузере адрес **http://localhost:3000**.

> При запуске `python3 main.py` без флага `--serve` в терминале выполняется консольная демонстрация основных возможностей библиотеки.

### Возможности веб-интерфейса

Веб-панель разделена на 5 интерактивных рабочих областей:

1. **Shell & Local Runner (`ShellSession` / `LocalTransport`)** — интерактивный запуск команд в stateful PTY-сессии `ShellSession.execute()` (с сохранением рабочей директории `cd`, переменных окружения `export` и размера терминала `cols × rows`) или через `Connection.local().run()`, с детальным инспектором объекта `Result` (`stdout`, `stderr`, `.lines`, `.json()`, `.to_dict()`, время выполнения).
2. **Hooks, Security & Telemetry (`CommandPipeline` & `structlog`)** — песочница конвейера middleware и хуков (`allowlist_hook`, `blocklist_hook`, `audit_log_hook`, `structured_log_hook`, `metrics_collector_hook`, `otel_tracing_hook`), тестирование флагов `sudo`, `sensitive=True`, `dry_run=True`, контекстных менеджеров `conn.cd()` и `conn.temp_dir()`, а также просмотр `structlog` JSONL и консольных логов с маскированием секретов.
3. **Pool, Inventory & Background (`ConnectionPool` & `BackgroundPool`)** — оркестратор мульти-хостового пула с редактируемым YAML-инвентарём, фильтрацией по группам (`all`, `web`, `backend`), готовыми пресетами (`Fleet Presets`) и групповыми операциями (`map_safe`, `apply`, `gather_facts`, `diff_facts`, `state.ensure_*`, `files.sync_dir`, `files.write_template`, `stream`), плюс симулятор `BackgroundPool` / `LogPipeline`.
4. **URI Builder & Codegen (`URIParser` & `ConnectionConfig`)** — визуальный конструктор и валидатор URI для всех транспортов (`ssh://`, `docker://`, `kubectl://`, `redfish://`, `ipmi://`, `telnet://`, `serial://`, `replay://`, `local://`) с безопасным представлением `uri_safe` и генерацией готовых сниппетов кода.
5. **Unit Test Runner (`pytest`)** — запуск unit-тестов или отдельных доменных пакетов (`core`, `services`, `transports`, `pools`, `background`, `cli`, `architecture`) прямо из браузера.

---

## Документация API

### `Connection` и `SyncConnection`

Единый фасад для работы с локальными и удалёнными хостами, контейнерами и контроллерами BMC.

#### Фабрики и разрешение секретов (`SecretResolver`)

```python
from uniconn import Connection, ConnectionConfig, RateLimiter

# 1. Из URI (с автоматическим разрешением секретов env:// и file://)
conn = Connection.from_uri(
    "ssh://admin:env://PROD_SSH_PASS?default=fallback@node-01:22"
    "?key_file=file:///run/secrets/id_ed25519&ssh_config=true&proxy=bastion-01"
)

# 2. Локальное подключение
local_conn = Connection.local(timeout=30.0)

# 3. Из типизированной модели ConnectionConfig или словаря
config = ConnectionConfig(
    transport="ssh",
    host="example.com",
    port=22,
    username="admin",
    password="env://SSH_PASSWORD",
    timeout=60.0,
)
conn = Connection.from_config(config, rate_limit=RateLimiter(rate=20.0, burst=40), circuit_breaker=True)

# 4. Из YAML/TOML/JSON инвентаря
web1 = Connection.from_inventory("inventory.yaml", host="web-1")
web_conns = Connection.from_file("inventory.yaml", group="web")

# 5. Клонирование с переопределением параметров
staging_conn = conn.copy(host="staging.example.com", dry_run=True)
```

#### Выполнение команд и скриптов

- **`run(command, timeout=None, raise_on_error=False, input=None, sudo=False, sudo_user=None, sudo_password=None, sensitive=False, dry_run=None, **kwargs) -> Result`** — выполнить команду (строкой или безопасным списком аргументов с автоэкранированием через `shlex.join`).
- **`run_bytes(command, ...) -> bytes`** — выполнить команду и получить сырой бинарный поток (`bytes`) без декодирования в UTF-8.
- **`run_commands(commands, stop_on_error=True, **kwargs) -> list[Result]`** — последовательное выполнение списка команд.
- **`run_script(script_path, args=(), *, interpreter=None, sudo=False, timeout=None, raise_on_error=False, **kwargs) -> Result`** — загрузить локальный скрипт во временную директорию хоста, исполнить с аргументами и автоматически очистить артефакты.
- **`stream(command=None, timeout=None, **kwargs) -> AsyncIterator[str]`** — построчный потоковый вывод в реальном времени.

```python
# Безопасная передача аргументов списком и повышение привилегий
res = await conn.run(["systemctl", "restart", "nginx"], sudo=True, raise_on_error=True)

# Защита чувствительного вывода (маскируется в логах, repr(Result), to_dict() и исключениях)
token_res = await conn.run("cat /etc/app/api.token", sudo=True, sensitive=True)

# Выполнение локального скрипта на удалённом хосте
script_res = await conn.run_script("./scripts/health_audit.sh", args=["--strict"], sudo=True)
```

#### Примитивы ожидания и проверки доступности (`ping`, `wait_for_*`)

```python
# Измерение доступности и задержки (PingResult: alive, latency_ms, transport, error)
ping_res = await conn.ping(timeout=5.0)
if ping_res:
    print(f"Host {ping_res.host} responded in {ping_res.latency_ms:.2f} ms")

# Ожидание восстановления хоста (например, после перезагрузки)
await conn.wait_for_connection(timeout=120.0, interval=2.0)

# Ожидание открытия/закрытия TCP-порта (проверка с удалённого хоста или локально)
elapsed_port = await conn.wait_for_port(5432, state="open", check_from="remote", timeout=60.0)

# Ожидание появления файла и совпадения его содержимого с регулярным выражением
elapsed_path = await conn.wait_for_path(
    "/var/run/myapp/ready.status",
    state="present",
    content_regex=r"STATUS=READY",
    timeout=30.0,
)
```

#### Контекстные менеджеры `cd()`, `env()` и `temp_dir()`

```python
async with conn.cd("/srv/myapp"), conn.env(APP_ENV="production"):
    await conn.run(["git", "pull"])
    async with conn.temp_dir(prefix="build_") as tmp_dir:
        await conn.files.write_file(f"{tmp_dir}/manifest.json", '{"ok": true}')
```

---

### Доменные сервисы `Connection` и `ConnectionPool`

#### 1. Файловый сервис (`conn.files` и `pool.files`)

Предоставляет единый интерфейс поверх SFTP, контейнеров и локальной ФС с поддержкой атомарной записи, криптографической верификации, дельта-синхронизации и шаблонов:

```python
# Чтение и атомарная запись файлов в памяти (через временный файл + rename)
await conn.files.write_file("/etc/myapp/config.yaml", "port: 8080\n", mode=0o600, atomic=True)
text = await conn.files.read_file("/etc/myapp/config.yaml")
raw_bytes = await conn.files.read_file("/etc/myapp/config.yaml", encoding=None)

# Загрузка и скачивание с автоматической проверкой SHA-256 (verify=True)
await conn.files.upload("./build/app.tar.gz", "/opt/releases/app.tar.gz", verify=True)
await conn.files.download("/var/log/syslog", "./logs/syslog.log", verify=True)

# Вычисление контрольной суммы (sha256, sha1, md5)
digest = await conn.files.checksum("/opt/releases/app.tar.gz", algorithm="sha256")

# Инкрементальная дельта-синхронизация директорий (SyncResult)
sync_res = await conn.files.sync_dir(
    "./dist",
    "/var/www/app",
    delete=True,
    exclude=["*.pyc", ".git"],
    checksum_check=True,
    preserve_permissions=True,
)
print(f"Uploaded: {len(sync_res.uploaded)}, skipped: {len(sync_res.skipped)}")

# Рендеринг шаблонов (Jinja2 или string.Template) с атомарной записью
await conn.files.write_template(
    "/etc/nginx/conf.d/app.conf",
    "./templates/nginx.conf.j2",
    context={"server_name": "api.example.com", "port": 8080},
    mode=0o644,
    atomic=True,
)

# Метаданные и управление ФС
exists = await conn.files.exists("/var/www/app")
await conn.files.mkdir("/var/www/app/releases", parents=True, mode=0o755)
await conn.files.chmod("/opt/scripts/run.sh", 0o755)
info = await conn.files.stat("/etc/myapp/config.yaml")
entries = await conn.files.listdir("/var/log")
```

#### 2. Идемпотентное управление состоянием (`conn.state` и `pool.state`)

Все методы возвращают `EnsureResult` (`target`, `state`, `changed`, `ok`, `details`, `dry_run`, `diff`) и поддерживают режим `dry_run=True` с построением unified diff до внесения изменений:

```python
# Пакеты (auto: apt, apk, dnf/yum, pacman, zypper) и системные сервисы (systemd, openrc, sysv)
await conn.state.ensure_package(["nginx", "curl"], state="present", update_cache=True, sudo=True)
await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

# Файлы, директории и строки в конфигах (с unified diff и валидацией перед заменой)
file_res = await conn.state.ensure_file(
    "/etc/nginx/nginx.conf",
    content=new_nginx_conf,
    mode=0o644,
    atomic=True,
    validate="nginx -t -c %s",
    sudo=True,
)
if file_res.changed and file_res.diff:
    print(file_res.diff)

await conn.state.ensure_directory("/var/lib/myapp", mode=0o750, owner="deploy", group="deploy", sudo=True)
await conn.state.ensure_line("/etc/hosts", "10.0.0.10 db.internal", regex=r".*\bdb\.internal$")

# Пользователи, SSH-ключи, юниты systemd и параметры ядра sysctl
await conn.state.ensure_user("deploy", uid=1050, groups=["docker"], shell="/bin/bash", sudo=True)
await conn.state.ensure_authorized_key("deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...", sudo=True)
await conn.state.ensure_systemd_unit(
    "myapp.service",
    content="[Unit]\nDescription=MyApp\n[Service]\nExecStart=/usr/bin/myapp\n[Install]\nWantedBy=multi-user.target\n",
    state="started",
    enabled=True,
    sudo=True,
)
await conn.state.ensure_sysctl("net.ipv4.ip_forward", 1, reload=True, sudo=True)
```

#### 3. Инспекция фактов, дрейф конфигураций и диагностические сессии

```python
from uniconn import CustomCommandSpec, FactSpec

# Сбор стандартных и пользовательских фактов (OS, ядро, CPU, RAM, диски, сеть)
spec = FactSpec(
    commands=[CustomCommandSpec(name="openssl_ver", command="openssl version")],
)
facts = await conn.gather_facts(spec=spec)
print(facts.os_family, facts.distro, facts.cpu_count, facts.custom.get("openssl_ver"))

# Диагностическая сессия: снимки фактов + потоковый сбор логов в tar.gz архив
async with conn.diagnostic_session(
    local_dir="./diagnostics",
    archive_path="./diagnostics/incident_bundle.tar.gz",
) as diag:
    await diag.emit_custom_log("workload", "Running stress test")
    await diag.snapshot("peak_load")
```

#### 4. Проброс портов (`conn.tunnels`) и интерактивные сессии (`open_shell`, `expect`)

```python
# Локальный и удалённый проброс портов через SSH (работает в async with и в sync with)
async with conn.tunnels.forward_local_port(remote_host="127.0.0.1", remote_port=5432) as local_port:
    print(f"PostgreSQL доступен на 127.0.0.1:{local_port}")

# Декларативный диалог expect() с маскированием секретов
await conn.expect(
    "passwd deploy",
    patterns={r"New password:": "S3cretPass!", r"Retype new password:": "S3cretPass!"},
    sensitive=True,
)

# Stateful PTY-сессия (сохраняет cd, export и состояние оболочки между вызовами)
async with await conn.open_shell(term_type="xterm", term_size=(120, 40)) as shell:
    await shell.execute("cd /var/log && export LOG_FILTER=error")
    res = await shell.execute("pwd && echo $LOG_FILTER")
```

---

### Пулы соединений и фоновые задачи

#### `ConnectionPool` и `SyncConnectionPool`

Поддерживает групповое выполнение команд, доменные сервисы `pool.files` и `pool.state`, потоковый мультиплексор `pool.stream()`, выборку подмножеств `pool.select()` и волновой роллаут (`batch_size`, `max_fail_ratio`):

```python
from uniconn import BatchAbortedError, ConnectionPool

async with ConnectionPool.from_file(
    "inventory.yaml",
    group="production",
    max_concurrent=10,
    rate_limit=25.0,
    circuit_breaker=True,
    batch_size=2,
    max_fail_ratio=0.0,
) as pool:
    # 1. Канареечная проверка на подмножестве хостов (переиспользует открытые соединения)
    canary = pool.select(["web-1"])
    await canary.ping()

    # 2. Волновая раскатка на весь пул (выбросит BatchAbortedError при сбое первой волны)
    try:
        await pool.files.sync_dir("./dist", "/var/www/app", delete=True)
        await pool.state.ensure_service("nginx", state="restarted", sudo=True)
    except BatchAbortedError as err:
        print(f"Rollout aborted at batch {err.batch_index}: {err}")

    # 3. Мультиплексированный стриминг логов со всех хостов
    async for host, line in pool.stream("journalctl -u nginx -f -n 5"):
        print(f"[{host}] {line}")
```

#### `SSHSessionPool`

Мультиплексирование нескольких параллельных каналов поверх одного или нескольких SSH-соединений к одному хосту с адаптивным понижением лимитов (`adaptive=True`) при ошибках `MaxSessions`:

```python
from uniconn import SSHSessionPool

async with SSHSessionPool(
    "ssh://admin@heavy-node",
    max_sessions_per_conn=6,
    max_connections=4,
    adaptive=True,
    health_check=True,
) as ssh_pool:
    results = await ssh_pool.map(["lshw -short", "df -h", "free -m", "sensors"])
    await ssh_pool.resize(max_sessions_per_conn=4, max_connections=2)
```

#### `BackgroundPool`

Управление долгоживущими задачами в отсоединяемых сессиях (`tmux`, `screen`, `nohup`, `WindowsJobBackend`), которые переживают разрыв соединения:

```python
from uniconn import BackgroundPool

async with BackgroundPool("ssh://admin@server", backend="auto", max_sessions=8) as bg_pool:
    await bg_pool.start("stress-ng --cpu 4 --timeout 60s")
    await bg_pool.start("sysbench cpu run")

    async for event in bg_pool.poll_logs(interval=2.0):
        print(f"[{event.session_id}] {event.line.rstrip()}")

    results = await bg_pool.wait_all(timeout=120.0)
```

---

## Контрактное тестирование и кассеты (`use_cassette` и `pytest`-плагин)

`uniconn` позволяет записывать реальные сессии (команды, потоки, файловые операции и PTY-оболочку) в YAML/JSON-кассеты и воспроизводить их в тестах без доступа к сети, а также сравнивать кассеты между версиями (`cassette.diff()`):

```python
# 1. Контекстный менеджер на уровне Connection или ConnectionPool
async with conn.use_cassette(
    "tests/cassettes/deploy_flow.yaml",
    mode="once",                 # "once" | "new_episodes" | "none" | "all"
    normalize_temp=True,
    mask_secrets=True,
) as cassette:
    facts = await conn.gather_facts()
    await conn.state.ensure_line("/etc/hosts", "10.0.0.5 internal.api")

# Сравнение двух кассет (CassetteDiffReport)
diff_report = cassette.diff("tests/cassettes/baseline_deploy.yaml")
print("Identical:", diff_report.is_identical)
```

Использование встроенного `pytest`-плагина (`uniconn.pytest_plugin`):

```python
import pytest
from uniconn import Connection

@pytest.mark.uniconn_cassette(mode="once")
async def test_node_provisioning():
    async with Connection.from_uri("ssh://admin@node-01") as conn:
        res = await conn.run("hostname")
        assert res.ok
```

---

## Поддерживаемые транспорты и схемы URI

| Транспорт | Схема URI | Примеры и ключевые параметры |
| :--- | :--- | :--- |
| **SSH** | `ssh://` | `ssh://user:env://PASS@host:22?key_file=/path/id_ed25519&ssh_config=true&proxy=jump1,jump2&keepalive=30` |
| **Docker** | `docker://` | `docker://root@app-container?workdir=/app&shell=/bin/sh&context=prod` |
| **Podman** | `podman://` | `podman://web-container?workdir=/srv` |
| **Kubernetes** | `kubectl://` | `kubectl://prod-ns/api-pod-7f8b?container=api&context=eu-cluster&workdir=/app` |
| **Redfish BMC** | `redfish://` | `redfish://admin:env://BMC_PASS@bmc.local:443?verify_ssl=false&system_id=1` |
| **IPMI BMC** | `ipmi://` | `ipmi://admin:password@bmc.local:623` (`power status`, `power on/off/cycle`, `sensors`, `boot device`) |
| **Serial / UART** | `serial://`, `uart://` | `uart:///dev/ttyUSB0:115200?parity=N&stopbits=1` или `uart://?vid=10c4&pid=ea60` |
| **Telnet** | `telnet://` | `telnet://admin:pass@router.local:23?term_type=vt100` |
| **Replay** | `replay://` | `replay://node-01?cassette=tests/cassettes/node.yaml&mode=none` |
| **Local** | `local://` | `local://?timeout=30&rate_limit=50` (или `Connection.local()`) |

### Пример работы с Redfish и IPMI BMC

```python
# Redfish BMC (HTTP/2 клиент на базе niquests с автообнаружением System/Chassis/Manager)
async with Connection.from_uri("redfish://admin:env://BMC_PASS@bmc.local?verify_ssl=false") as bmc:
    status = await bmc.run("power status")
    sensors = await bmc.run("sensors")
    info = await bmc.run("system info")
```

### Пример работы с контейнерами Docker / Podman и Kubernetes

```python
async with Connection.from_uri("kubectl://production/backend-pod-0?container=app") as pod:
    res = await pod.run(["python3", "manage.py", "check"])
    await pod.files.write_file("/tmp/maintenance.flag", "1\n", atomic=True)
```

---

## CLI Интерфейс

```bash
# Выполнение команд (одиночное и групповое с волновым роллаутом)
uniconn run "ssh://user@host" "systemctl status nginx" --sudo --format json
uniconn run-multi --inventory inventory.yaml --group web -c "nginx -t" --sudo --batch-size 2 --max-fail-ratio 0.0

# Проверка доступности (ping) и примитивы ожидания (wait-for)
uniconn ping "ssh://node-01" "ssh://node-02"
uniconn wait-for connection "ssh://node-01" --timeout 120 --interval 2
uniconn wait-for port 5432 "ssh://node-01" --state open --check-from remote
uniconn wait-for path /tmp/ready.flag "ssh://node-01" --regex "READY"

# Сбор фактов, поиск дрейфа конфигураций и мультиплексированный стриминг логов
uniconn facts --inventory inventory.yaml --group prod --diff --baseline web-1
uniconn tail /var/log/nginx/error.log "ssh://web-1" "ssh://web-2" --follow

# Файловые операции, контрольные суммы, дельта-синхронизация и шаблоны
uniconn upload ./app.conf /etc/app/app.conf "ssh://web-1" --verify
uniconn download /var/log/syslog ./logs/{host}.log "ssh://web-1" "ssh://web-2" --verify
uniconn checksum /etc/app/app.conf "ssh://web-1" "ssh://web-2" --algorithm sha256
uniconn sync ./dist /var/www/app --inventory inventory.yaml --group web --delete --checksum
uniconn template ./nginx.conf.j2 /etc/nginx/conf.d/app.conf "ssh://web-1" -D port=8080 --atomic

# Идемпотентное управление состоянием (с поддержкой --dry-run и --batch-size)
uniconn ensure-user deploy "ssh://node-01" --uid 1050 --groups docker,sudo --shell /bin/bash --sudo
uniconn ensure-authorized-key deploy "ssh-ed25519 AAAA..." "ssh://node-01" --sudo
uniconn ensure-unit myapp.service "ssh://node-01" --file ./myapp.service --state started --enabled --sudo
uniconn ensure-sysctl net.ipv4.ip_forward 1 "ssh://node-01" --sudo

# Фоновые сессии BackgroundPool (auto / tmux / screen / nohup)
uniconn bg-run "ssh://user@host" --backend auto --instances 2 -c "stress-ng --cpu 4" --logs
uniconn bg-status "ssh://user@host"
uniconn bg-logs "ssh://user@host" --session-id uniconn_pool_0 --follow
uniconn bg-kill "ssh://user@host" --session-id uniconn_pool_0

# Запись, воспроизведение и аудит кассет контрактного тестирования
uniconn record "ssh://user@host" -c ./cassettes/node.yaml --sanitize-ip -- uptime
uniconn replay ./cassettes/node.yaml -- uptime
uniconn cassette info ./cassettes/node.yaml
uniconn cassette sanitize ./cassettes/node.yaml --redact-ip --redact-tokens
uniconn cassette verify ./cassettes/node.yaml
uniconn cassette diff ./cassettes/baseline.yaml ./cassettes/candidate.yaml --fail-on-diff

# BMC, интерактивный shell и утилиты
uniconn bmc "redfish://admin:pass@bmc?verify_ssl=false" "power status"
uniconn shell "ssh://user@host"
uniconn serial-ports --format json
uniconn transports
```

---

## Структурированное логирование (`structlog`), хуки и OpenTelemetry

`uniconn` предоставляет готовые lifecycle-хуки (`allowlist_hook`, `blocklist_hook`, `audit_log_hook`, `structured_log_hook`, `metrics_collector_hook`, `otel_tracing_hook`) и маскирование секретов во всех логах и спанах:

```python
from uniconn import (
    Connection,
    configure_logging,
    log_context,
    metrics_collector_hook,
    otel_tracing_hook,
    structured_log_hook,
)

configure_logging(level="INFO", fmt="json", log_file="uniconn_telemetry.jsonl")

async with Connection.local() as conn:
    conn.add_hook("after_run", structured_log_hook(tags={"env": "prod", "dc": "eu-1"}))
    metrics = metrics_collector_hook().attach(conn)
    otel = otel_tracing_hook(service_name="fleet-deployer", mask_secrets=True).attach(conn)

    async with log_context(release_id="v2026.10"):
        await conn.run(["echo", "deploying release"])
```

---

## Исключения

```python
from uniconn.exceptions import (
    UniconnError,                 # Базовое исключение библиотеки
    ConfigurationError,           # Ошибки конфигурации и разрешения секретов (env://, file://)
    ConnectionError,              # Ошибки установки соединения
    CircuitOpenError,             # Разомкнутый предохранитель CircuitBreaker
    BatchAbortedError,            # Прерывание волнового роллаута при превышении max_fail_ratio
    CassetteError,                # Ошибки работы с кассетами записи/воспроизведения
    CassetteMissError,            # Отсутствие подходящего эпизода в кассете при mode="none"
    AuthenticationError,          # Ошибки аутентификации
    ExecutionError,               # Ненулевой код возврата при raise_on_error=True
    FileTransferError,            # Ошибки передачи файлов и несовпадения контрольных сумм
    TimeoutError,                 # Превышение времени ожидания команды или wait_for_*
    TransportNotFoundError,       # Неизвестный транспорт
    CapabilityNotSupportedError,  # Транспорт не поддерживает требуемую возможность (ISP)
    BMCCapabilityError,           # BMC не поддерживает запрошенную операцию
    BackgroundError,              # Базовое исключение фоновых задач BackgroundPool
)
```

---

## Примеры использования (`examples/`)

Все примеры в директории `examples/` снабжены как готовыми сниппетами для боевых серверов (`ssh://`, `redfish://`, `docker://`, `kubectl://`), так и самодостаточным локальным сценарием в блоке `__main__`, который можно сразу запустить без внешних хостов:

- `examples/basic_usage.py` — создание подключений, `SecretResolver` (`env://`), `run`, `run_script`, клонирование и синхронный API.
- `examples/file_transfer.py` — `conn.files`: атомарная запись `atomic=True`, SFTP с `verify=True`, `checksum()`, дельта-синхронизация `sync_dir()` и шаблоны `write_template()`.
- `examples/provisioning_and_facts.py` — идемпотентное управление состоянием `conn.state.ensure_*` с выводом unified diff, сбор фактов `gather_facts()`, поиск дрейфа `pool.diff_facts()` и `diagnostic_session()`.
- `examples/parallel_execution.py` — `ConnectionPool`: волновой роллаут (`batch_size`, `max_fail_ratio`), выборка `pool.select()`, `pool.files`, `pool.state` и потоковый мультиплексор `pool.stream()`.
- `examples/resilience_rollout_and_waiters.py` — `CircuitBreaker`, `RateLimiter`, примитивы `ping()` и `wait_for_*`, адаптивный `SSHSessionPool` и проброс портов `conn.tunnels`.
- `examples/contract_testing_cassettes.py` — запись и воспроизведение кассет `use_cassette()`, `pool.use_cassette()`, сравнение `cassette.diff()` и `pytest`-плагин.
- `examples/containers_and_k8s.py` — работа с контейнерами `Docker`, `Podman` и подами `Kubernetes` (`kubectl://`).
- `examples/bmc_management.py` — управление серверами через `Redfish` (`redfish://`) и `IPMI` (`ipmi://`).
- `examples/health_check.py` — проверка доступности через `ping()`, `is_alive()` и `wait_for_*`.
- `examples/interactive_shell.py` — stateful PTY-сессии `open_shell()` и автомат диалогов `expect()`.
- `examples/screen_monitoring.py` — фоновые задачи `BackgroundPool` (`tmux`, `screen`, `nohup`) и `LogPipeline`.
- `examples/security_and_hooks.py` — хуки `before_run`/`after_run`, `sensitive=True`, `dry_run=True`, `cd()`, `env()` и `otel_tracing_hook`.
- `examples/structured_logging_telemetry.py` — `structlog` JSONL-логирование, `log_context` и сбор метрик.
- `examples/ergonomics_and_inventory.py` — эргономика `Result` (`.text`, `.lines`, `.json()`), `temp_dir()` и YAML-инвентари.
- `examples/custom_transport.py` — создание собственного транспорта на базе `BaseTransport`.

## Тестирование и качество кода

```bash
# Запуск unit-тестов с кратким выводом (0 RuntimeWarning)
uv run pytest -m "not integration" -q --tb=short | tail -n 5

# Линтинг (лимит строки 120 символов) и статическая проверка типов
uv run ruff check src/ examples/ benchmarks/
uv run pyright
```

## Лицензия

MIT License. См. [LICENSE](LICENSE) файл.
