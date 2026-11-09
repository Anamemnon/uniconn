# uniconn

**Универсальный Async/Sync движок и CLI для автоматизации инфраструктуры на Python**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type Checker: Pyright](https://img.shields.io/badge/type%20checking-pyright-brightgreen.svg)](https://github.com/microsoft/pyright)
[![Tests Passing](https://img.shields.io/badge/tests-607%20passed-brightgreen.svg)](tests/)
[![Poe Tasks](https://img.shields.io/badge/tasks-poethepoet-blueviolet.svg)](https://github.com/nat-n/poethepoet)

---

### Язык: **[ 🇬🇧 English ](README.md)** &nbsp;|&nbsp; **[ 🇷🇺 Русский ]**

---

`uniconn` устраняет необходимость в разрозненном инфраструктурном коде, предоставляя единый отказоустойчивый фасад `Connection` для выполнения команд, дельта-синхронизации файлов, идемпотентного управления состоянием, DAG-оркестрации задач и аппаратной диагностики поверх **SSH, WinRM, Docker, Podman, Kubernetes, Serial/UART, IPMI, Redfish BMC и Local** — со **100% паритетом Async + Sync** и нулевым оверхедом.

<p align="center">
  <img src="./docs/assets/terminal_demo.svg" alt="uniconn interactive terminal demo" width="100%" />
</p>

---

## ⚡ Быстрый старт за 5 строк

### 🚀 Асинхронное использование (`Connection`)
Выполнение команд, автопарсинг вывода, атомарная запись файлов и запуск системных служб через `sudo`:

```python
from uniconn import Connection

async with Connection.from_uri("ssh://admin:env://SSH_PASS@node-01") as conn:
    disks = (await conn.run("df -h", parse="auto")).parsed
    await conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
    await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)
```

### ⏱️ Синхронное использование (`SyncConnection`)
Без ручного управления `asyncio.run()` для скриптов, утилит и синхронных тестовых сценариев:

```python
from uniconn import SyncConnection

with SyncConnection.from_uri("docker://root@app-container") as conn:
    print(conn.run(["uname", "-s"]).text)
    print("ОС:", conn.gather_facts().os_family)
```

---

## 💡 Почему uniconn?

Современная инфраструктура разнородна: серверы Linux работают рядом с узлами Windows, микросервисы в контейнерах соседствуют с подами Kubernetes, а серверы bare-metal требуют удалённого управления через BMC или перепрошивки загрузчиков по Serial/UART.

Традиционно командам приходится комбинировать зоопарк несовместимых библиотек: `AsyncSSH` или `Paramiko` для SSH, `pywinrm` для Windows, `docker-py` и клиент `kubernetes` для контейнеров, `Pyinfra` или тяжеловесный `Ansible` для конфигурации, `pyserial` для плат и `Testinfra` для проверок.

`uniconn` объединяет все эти задачи в **единый легковесный движок с субмиллисекундным оверхедом ядра**:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              ПОЛЬЗОВАТЕЛЬСКИЙ КОД / CLI / ВЕБ-ПАНЕЛЬ                   │
│       Async API: Connection / ConnectionPool / Flow / ShellSession / RemotePath        │
│       Sync API:  SyncConnection / SyncConnectionPool / SyncFlow (через EventLoopPortal)│
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                  ┌─────────────────────────▼──────────────────────────┐
                  │               ДОМЕННЫЕ СЕРВИСЫ ЯДРА                │
                  │  • conn.files / conn.path (SFTP, дельта-синхр, хеш)│
                  │  • conn.state (Идемпотентность, unified diff)      │
                  │  • conn.gather_facts / diff_facts / диагностика    │
                  │  • conn.run_python (Zero-Fork RPC без форков)      │
                  └─────────────────────────┬──────────────────────────┘
                                            │
                  ┌─────────────────────────▼──────────────────────────┐
                  │             КОНВЕЙЕР ОТКАЗОУСТОЙЧИВОСТИ            │
                  │  [Context] ──► [Sudo/Секреты] ──► [Hooks/OTel] ──► │
                  │  [DryRun]  ──► [CircuitBreaker] ──► [RateLimiter]  │
                  │  ──► [Retry] ──► [Кассеты Replay / Запись]         │
                  └─────────────────────────┬──────────────────────────┘
                                            │
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                    ПОДКЛЮЧАЕМЫЕ ТРАНСПОРТЫ (ПРОТОКОЛЫ ISP)                             │
├───────────┬───────────┬───────────┬───────────┬───────────┬────────────┬───────────────┤
│  ssh://   │  winrm:// │ docker:// │ kubectl://│  uart://  │ redfish:// │   replay://   │
│  telnet://│  wsman:// │ podman:// │           │  serial://│   ipmi://  │   local://    │
└───────────┴───────────┴───────────┴───────────┴───────────┴────────────┴───────────────┘
```

### 📊 Сравнительная матрица возможностей

| Возможность | `uniconn` | `Ansible` | `Fabric` | `Pyinfra` | `Nornir` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Основная парадигма** | **Python SDK** | YAML Playbooks | CLI Runner | Python Deploy | Network SDK |
| **Async + Sync паритет** | **✅ 100%** | ❌ Process | ❌ Только Sync | ❌ Threads | ⚠️ Только Scrapli |
| **10+ схем URI транспортов** | **✅ Unified** | ⚠️ Плагины | ❌ Только SSH | ⚠️ Linux/SSH | ❌ Network CLI |
| **Идемпотентный стейт (`ensure_*`)** | **✅ Встроено** | ✅ YAML | ❌ Нет | ✅ Python ops | ❌ Нет |
| **DAG-оркестрация задач (`@task`)** | **✅ Встроено** | ✅ Playbooks | ❌ Нет | ⚠️ Линейная | ⚠️ Раннеры |
| **Zero-Fork RPC (`run_python`)** | **✅ &lt; 2 мс** | ⚠️ Плагин Mitogen | ❌ Нет | ⚠️ Коннектор | ❌ Нет |
| **Автопарсинг вывода (`auto`)** | **✅ Встроено** | ⚠️ Фильтры | ❌ Нет | ❌ Нет | ✅ TextFSM |
| **Аппаратные BMC и UART** | **✅ Из коробки** | ⚠️ Роли | ❌ Нет | ❌ Нет | ⚠️ Только Serial |
| **Офлайн кассеты и контрактные тесты** | **✅ Встроено** | ❌ Нет | ❌ Нет | ❌ Нет | ❌ Нет |
| **Отказоустойчивость (CircuitBreaker)** | **✅ Встроено** | ⚠️ `max_fail` | ❌ Нет | ❌ Нет | ❌ Нет |
| **Накладные расходы ядра** | **⚡ &lt; 0.3 мс** | ~ 500–2000 мс | ~ 3–8 мс | ~ 5–15 мс | ~ 1–5 мс |

> 💡 *Примечание: Ассерты Testinfra и сетевые коннекторы Scrapli бесшовно подключаются к uniconn через адаптеры транспортов и плагин pytest.*

---

## 📦 Установка

Базовая легковесная установка (SSH, Local, Docker, Podman, Kubectl, Replay-транспорт, пайплайн отказоустойчивости и структурированные логи):

```bash
# Через uv (рекомендуется):
uv add uniconn

# Через pip:
pip install uniconn
```

### Дополнительные компоненты (Extras)

Установка всех дополнительных транспортов, BMC-драйверов, протоколов Serial-модемов и CLI одной командой:

```bash
uv add "uniconn[all]"
```

Или точечно:

| Extra | Команда | Назначение |
| :--- | :--- | :--- |
| **CLI** | `uv add "uniconn[cli]"` | Полнофункциональный CLI (`cyclopts`, `rich`) |
| **WinRM** | `uv add "uniconn[winrm]"` | Windows Remote Management (`pywinrm`) |
| **BMC** | `uv add "uniconn[bmc]"` | IPMI (`pyghmi`) и Redfish HTTP/2 (`niquests`) |
| **Serial** | `uv add "uniconn[serial]"` | Serial/UART консоль (`pyserial-asyncio`) и X/Y/ZMODEM |
| **Telnet** | `uv add "uniconn[telnet]"` | Telnet транспорт (`telnetlib3`) |
| **Templates** | `uv add "uniconn[templates]"` | Шаблонизатор Jinja2 для `write_template()` |
| **Parsing** | `uv add "uniconn[parsing]"` | Семантические парсеры (`jc`, `ttp`, `textfsm`, `ntc-templates`) |
| **Telemetry**| `uv add "uniconn[otel]"` | Трассировка OpenTelemetry |

---

## 🌐 Поддерживаемые транспорты и схемы URI

Каждый транспорт описывается стандартизированным URI с авторазрешением секретов:

| Транспорт | Схема URI | Пример использования |
| :--- | :--- | :--- |
| **SSH** | `ssh://` | `ssh://admin:env://SSH_PASS@node-01:22?key_file=/path/id_ed25519&proxy=bastion&keepalive=30` |
| **Windows Remote**| `winrm://` | `winrm://Administrator:env://WIN_PASS@win-server:5986?ssl=true&shell=ps&transport=ntlm` |
| **Docker** | `docker://` | `docker://root@app-container?workdir=/app&shell=/bin/sh` |
| **Podman** | `podman://` | `podman://web-container?workdir=/srv` |
| **Kubernetes** | `kubectl://` | `kubectl://production/backend-pod-0?container=api&context=eu-cluster` |
| **Redfish BMC** | `redfish://` | `redfish://admin:env://BMC_PASS@bmc.local?verify_ssl=false&system_id=1` |
| **IPMI BMC** | `ipmi://` | `ipmi://admin:password@bmc.local:623` (`power status`, `sensors`, `boot device`) |
| **Serial / UART** | `serial://`, `uart://` | `uart:///dev/ttyUSB0:115200?parity=N&stopbits=1` или `uart://COM3?vid=10c4&pid=ea60` |
| **Telnet** | `telnet://` | `telnet://admin:pass@switch.local:23?term_type=vt100` |
| **Replay (Кассеты)**| `replay://` | `replay://node-01?cassette=tests/cassettes/node.yaml&mode=none` |
| **Local** | `local://` | `local://?timeout=30&rate_limit=50` (или `Connection.local()`) |

> 🔒 **Динамические ссылки на секреты**: Пароли, токены sudo и пути к ключам поддерживают синтаксис `env://VAR_NAME[?default=fallback]` и `file:///path/to/secret[?default=fallback]`. Отсутствие обязательного секрета вызывает `ConfigurationError` до попытки сетевого подключения.

---

## 🛠️ Практические сценарии и боевые примеры

### 1. Декларативная DAG-оркестрация задач (`uniconn.orchestration`)
Построение графов зависимостей задач с предусловиями (`depends_on`), гарантированной очисткой (`post`), предикатами выполнения (`when`) и барьерной волновой раскаткой по кластеру (`mode="barrier"`):

```python
from uniconn import Connection, ConnectionPool, Flow, FlowContext, task

@task(name="check_environment", tags=["preflight"])
async def check_environment(conn: Connection, ctx: FlowContext):
    facts = await conn.gather_facts()
    ctx.host_set(conn, "os_family", facts.os_family)
    return await conn.run("uname -a")

@task(name="cleanup_artifacts", always_run=True)
async def cleanup_artifacts(conn: Connection):
    await conn.files.remove_file("/tmp/release.tar.gz")

@task(
    name="deploy_application",
    depends_on=[check_environment],
    post=[cleanup_artifacts],
    when=lambda conn, ctx: ctx.host_get(conn, "os_family") == "Linux",
    retries=2,
    retry_delay=1.0,
)
async def deploy_application(conn: Connection):
    return await conn.state.ensure_file(
        "/etc/app.conf",
        content="PORT=8080\nWORKERS=4\n",
        mode=0o644,
        atomic=True,
        notify=("reload_app", lambda c: c.state.ensure_service("app", state="reloaded", sudo=True)),
    )

# Раскатка графа задач волнами по 2 узла с дедупликацией нотификаций перезапуска
flow = Flow(
    name="production_release",
    tasks=[deploy_application],  # Автоматически подтягивает check_environment и cleanup_artifacts
    mode="barrier",              # Все хосты завершают волну текущей задачи до перехода к следующей
    batch_size=2,                # Волна из двух хостов
    max_fail_ratio=0.0,          # Остановка роллаута при ошибке
    batch_notifications=True,    # Запуск 'reload_app' строго ОДИН РАЗ на хост в конце всего графа
)

async with ConnectionPool.from_file("fleet.yaml", group="prod") as pool:
    report = await pool.run_flow(flow, vars={"release": "v2.5.0"})
    report.raise_for_status()
```

---

### 2. Удалённый Python RPC без форков (`conn.run_python`)
Выполнение произвольных Python-функций напрямую внутри постоянного фонового Python-воркера через двунаправленный pipe (в стиле Mitogen). Устраняет оверхед шелла SSH, задержки заливки скриптов и потери времени на fork процессов:

```python
import os
from uniconn import Connection

async with Connection.from_uri("ssh://admin@remote-node") as conn:
    # 1. Выполнение анонимной lambda прямо на удалённом хосте (задержка < 2 мс)
    kernel_release = await conn.run_python(lambda: os.uname().release)
    print("Ядро удалённого хоста:", kernel_release)

    # 2. Выполнение параметризованной функции с импортом сторонних библиотек на удалённой стороне
    def inspect_system(threshold_pct: float) -> dict:
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        return {
            "cpu_percent": cpu_usage,
            "is_stressed": cpu_usage > threshold_pct,
            "memory_free_gb": psutil.virtual_memory().available / (1024 ** 3),
        }

    stats = await conn.run_python(inspect_system, 85.0, sudo=False, timeout=15.0)
    print("Отчёт по нагрузке:", stats["cpu_percent"], stats["is_stressed"])
```

---

### 3. Аппаратное управление bare-metal серверами (Redfish HTTP/2 и IPMI)
Управление серверными стойками через контроллеры BMC по протоколам DMTF Redfish HTTP/2 (на базе `niquests`) и IPMI:

```python
from uniconn import Connection

# 1. Redfish BMC: чтение сенсоров, здоровья узла и управление питанием
async with Connection.from_uri("redfish://admin:env://BMC_PASS@192.168.1.100?verify_ssl=false") as bmc:
    power_res = await bmc.run("power status")
    print("Питание сервера:", power_res.text)  # "On"

    # Опрос датчиков температур и вентиляторов
    thermal = await bmc.run("sensors")
    print(thermal.text)

    # Холодная перезагрузка bare-metal хоста
    await bmc.run("power cycle")

# 2. IPMI BMC: низкоуровневые raw-команды netfn и переключение порядка загрузки
async with Connection.from_uri("ipmi://admin:env://IPMI_PASS@192.168.1.100:623") as ipmi:
    # Однократная сетевая загрузка PXE для автоматической установки ОС
    await ipmi.run("boot pxe once")
    await ipmi.run("power reset")
```

---

### 4. Управление Serial/UART и перепрошивка микроконтроллеров (X/Y/ZMODEM)
Прямая работа с COM-портами и адаптерами `/dev/ttyUSB0` для сетевого оборудования, встраиваемых систем и IoT:

```python
from uniconn import Connection

async with Connection.from_uri("uart:///dev/ttyUSB0:115200?parity=N&stopbits=1") as board:
    # 1. Аппаратный сброс платы кратковременным импульсом DTR/RTS
    await board.transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.1)

    # 2. Отправка сигнала BREAK для перехвата загрузки U-Boot / ROMMON
    board.transport.send_break(duration=0.25)

    # 3. Передача файла прошивки в ОЗУ по протоколу YMODEM
    bytes_sent = await board.files.upload_ymodem(
        "build/u-boot-custom.bin",
        trigger_command="loady 0x82000000\r",
        progress_callback=lambda current, total: print(f"Прошивка: {current}/{total} байт"),
    )
    print(f"Прошивка завершена: {bytes_sent} байт передано")

    # 4. Потоковый вывод консоли UART в реальном времени
    async for line in board.stream():
        print("[UART]:", line)
        if "Kernel panic" in line:
            break
```

---

### 5. Сессии Stateful PTY Shell и автоматизация диалогов `expect`
Сохранение состояния сессии (директория `cd`, переменные `export`, размер терминала) и декларативный автомат ответов на интерактивные запросы:

```python
from uniconn import Connection

async with Connection.from_uri("ssh://admin@node-01") as conn:
    # 1. Stateful PTY Shell: директория и окружение сохраняются между вызовами
    async with await conn.open_shell(term_type="xterm-256color", term_size=(120, 40)) as shell:
        await shell.execute("cd /var/log/nginx && export LOG_LEVEL=debug")
        res = await shell.execute("pwd && echo $LOG_LEVEL")
        assert "/var/log/nginx" in res.text
        assert "debug" in res.text

    # 2. Декларативный Expect: интерактивная смена пароля с маскированием в логах
    await conn.expect(
        "passwd deployer",
        patterns={
            r"New password:": "SecureP@ssw0rd!123",
            r"Retype new password:": "SecureP@ssw0rd!123",
        },
        final_prompt=r"password updated successfully",
        sensitive=True,  # Пароли автоматически скрываются в логах, спанах OTel и ошибках
    )
```

---

### 6. Оркестрация кластера и волновой роллаут (`ConnectionPool`)
Выкатка изменений на сотни серверов с ограничением параллелизма, предохранителями `CircuitBreaker` и автоматической остановкой при превышении порога ошибок:

```python
import asyncio
from uniconn import ConnectionPool, BatchAbortedError

async def deploy_fleet():
    hosts = ["ssh://admin@web-01", "ssh://admin@web-02", "ssh://admin@web-03", "ssh://admin@web-04"]

    async with ConnectionPool(hosts, max_concurrent=10, batch_size=2, max_fail_ratio=0.0) as pool:
        # 1. Канареечная проверка на подмножестве хостов (переиспользует открытые сессии)
        canary = pool.select(["web-01"])
        assert (await canary.ping()).all_alive

        # 2. Волновая раскатка с прерыванием при сбое (выбрасывает BatchAbortedError)
        try:
            await pool.files.sync_dir("./dist", "/var/www/app", delete=True)
            await pool.state.ensure_service("nginx", state="restarted", sudo=True)
        except BatchAbortedError as err:
            print(f"Роллаут остановлен на волне {err.batch_index}: {err}")

        # 3. Поиск дрейфа фактов между узлами кластера
        drift = await pool.diff_facts()
        if drift.has_drift:
            print("Обнаружен дрейф конфигураций:", drift.mismatches)

asyncio.run(deploy_fleet())
```

---

### 7. Объектно-ориентированная файловая система (`conn.path` и `conn.files`)
Работа с удалёнными файлами в стиле `pathlib.Path` без лишних сетевых запросов:

```python
# Навигация по удалённой ФС в стиле Pathlib
log_dir = conn.path("/var/log/nginx")
if await log_dir.exists():
    async for log_file in log_dir.glob("*.log"):
        st = await log_file.stat()  # Метаданные предзагружены во время glob, 0 лишних RTT
        print(log_file.name, st.st_size)

# Высокопроизводительная дельта-синхронизация директорий (альтернатива rsync)
sync_res = await conn.files.sync_dir(
    "./build",
    "/var/www/app",
    delete=True,
    checksum_check=True,
    exclude=["*.pyc", ".git"],
)
```

---

### 8. Детерминированное контрактное тестирование (`use_cassette` и плагин Pytest)
Запись реальных сессий инфраструктуры (команды, SFTP, потоки, PTY-сессии) в YAML-кассеты с автоматическим маскированием секретов и воспроизведение в тестах CI без сетевого доступа:

```python
import pytest
from uniconn import Connection

# В наборе тестов:
@pytest.mark.uniconn_cassette(mode="once")
async def test_server_provisioning():
    # Автоматически оборачивается в ReplayTransport при наличии кассеты
    async with Connection.from_uri("ssh://admin@production-host") as conn:
        res = await conn.run("hostname")
        assert res.ok
        assert res.text == "prod-web-01"
```

---

## 🖥️ Интерактивная веб-панель (Web Dashboard)

В репозиторий встроен интерактивный веб-дашборд для проверки подключений, конструирования URI, тестирования конвейера хуков и запуска тестов прямо из браузера:

```bash
# Запуск сервера предпросмотра на http://0.0.0.0:3000
python main.py --serve
```

После запуска перейдите по адресу **http://localhost:3000**:
1. **Shell & Local Runner**: Интерактивные stateful PTY-сессии с сохранением состояния `cd`, переменных `export` и размеров терминала.
2. **Hooks & Telemetry Sandbox**: Тестирование `CircuitBreaker`, `RateLimiter` и маскирования секретов.
3. **Pool & Fleet Orchestrator**: Визуальное управление YAML-инвентарём и волновым роллаутом.
4. **Visual URI Builder**: Конструктор и валидатор URI с автогенерацией кода на Python.
5. **Interactive Test Runner**: Запуск unit-тестов отдельных пакетов из интерфейса.

---

## 🛠️ Модульный CLI

`uniconn` предоставляет эргономичный CLI на базе `cyclopts` и `rich`:

```bash
# Выполнение команд с правами sudo и выводом в JSON
uniconn run "ssh://user@host" "systemctl status nginx" --sudo --format json

# Волновой роллаут по инвентарю
uniconn run-multi --inventory fleet.yaml --group web -c "nginx -t" --batch-size 2 --max-fail-ratio 0.0

# Проверка доступности и задержки (ping)
uniconn ping "ssh://node-01" "winrm://win-01" "kubectl://prod/api-pod"

# Примитивы ожидания (доступность хоста, открытие TCP-порта, regex в файле)
uniconn wait-for connection "ssh://node-01" --timeout 120
uniconn wait-for port 5432 "ssh://node-01" --state open --check-from remote
uniconn wait-for path /var/run/app.pid "ssh://node-01" --regex "READY"

# Проверка контрольных сумм и дельта-синхронизация
uniconn checksum /etc/app.conf "ssh://node-01" "ssh://node-02" --algorithm sha256
uniconn sync ./dist /var/www/app --inventory fleet.yaml --group web --delete --checksum

# Идемпотентные команды с предпросмотром diff
uniconn ensure-user deploy "ssh://node-01" --uid 1050 --groups docker,sudo --sudo
uniconn ensure-unit myapp.service "ssh://node-01" --file ./myapp.service --state started --enabled

# Запись и детерминированное воспроизведение кассет
uniconn record "ssh://user@host" -c ./cassettes/node.yaml --sanitize-ip -- uptime
uniconn replay ./cassettes/node.yaml -- uptime
uniconn cassette diff ./cassettes/v1.yaml ./cassettes/v2.yaml --fail-on-diff
```

---

## 🤝 Сообщество и разработка

Мы стремимся к созданию открытой, дружелюбной и безопасной экосистемы:

- **[Руководство контрибьютора (CONTRIBUTING.md)](CONTRIBUTING.md)**: Настройка среды (`uv`, `poe`), стандарты кода, архитектурные инварианты и правила Pull Request.
- **[Кодекс поведения (CODE_OF_CONDUCT.md)](CODE_OF_CONDUCT.md)**: Наши обязательства и стандарты на базе Contributor Covenant v2.1.
- **[Политика безопасности (SECURITY.md)](SECURITY.md)**: Регламент ответственного раскрытия уязвимостей и сроки реагирования.

---

## 📄 Лицензия

Библиотека `uniconn` распространяется под лицензией **MIT**. Подробности в файле [LICENSE](LICENSE).
