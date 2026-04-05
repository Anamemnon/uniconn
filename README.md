# uniconn

Универсальная Python библиотека для выполнения команд на удалённых хостах через различные транспорты: SSH, Telnet, Serial/UART, IPMI, Redfish и локальное выполнение.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Особенности

- 🚀 **Множественные транспорты**: SSH, Telnet, Serial/UART, IPMI, Redfish, локальное выполнение
- ⚡ **Async-first архитектура**: Построена на `asyncio` с синхронной обёрткой
- 🔌 **Плагинная система**: Транспорты загружаются динамически через entry-points
- 🔒 **Безопасность**: Маскирование секретов в логах, Pydantic SecretStr для паролей
- 🔄 **Повторные попытки**: Встроенный retry с экспоненциальным backoff
- 📊 **Пул соединений**: Параллельное выполнение на множестве хостов
- 🛠️ **CLI инструмент**: Удобная командная строка для быстрых операций

## Установка

### Базовая установка

```bash
pip install uniconn
```

### С дополнительными транспортами

```bash
# SSH поддержка
pip install uniconn[ssh]

# Telnet
pip install uniconn[telnet]

# Serial/UART
pip install uniconn[serial]

# BMC (IPMI + Redfish)
pip install uniconn[bmc]

# CLI интерфейс
pip install uniconn[cli]

# Всё вместе
pip install uniconn[ssh,telnet,serial,bmc,cli]
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

##### `run(command, timeout=None, raise_on_error=False, **kwargs) -> Result`

Выполнить команду на удалённом хосте.

**Параметры:**
- `command` (str): Команда для выполнения
- `timeout` (float, optional): Таймаут в секундах
- `raise_on_error` (bool): Выбросить исключение при ненулевом exit code
- `**kwargs`: Дополнительные аргументы для транспорта

**Возвращает:**
- `Result`: Объект результата выполнения

**Пример:**
```python
result = await conn.run("ls -la", timeout=30, raise_on_error=True)
print(result.stdout)
```

##### `stream(command, timeout=None, **kwargs) -> AsyncIterator[str]`

Потоковое выполнение команды с построчным выводом.

**Пример:**
```python
async for line in conn.stream("tail -f /var/log/syslog"):
    print(line)
```

##### `close() -> None`

Закрыть подключение.

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
- `transport` (str): Тип транспорта (ssh, telnet, serial, local, ipmi, redfish)
- `host` (str | None): Хост, IP или устройство
- `port` (int | None): Порт подключения
- `username` (str | None): Имя пользователя
- `password` (SecretStr | None): Пароль
- `key_file` (str | None): Путь к файлу ключа
- `timeout` (float): Таймаут операций (по умолчанию 30.0)
- `options` (dict): Дополнительные опции транспорта

### ConnectionPool

Пул подключений для параллельного выполнения команд.

```python
from uniconn import ConnectionPool

hosts = ["ssh://host1", "ssh://host2", "ssh://host3"]
pool = ConnectionPool(
    uris=hosts,
    max_concurrent=10,  # Максимум параллельных подключений
    retry_attempts=3,   # Попыток переподключения
)
```

#### Методы

##### `map(command, timeout=None, raise_on_error=False) -> List[Result]`

Выполнить команду на всех хостах пула.

**Пример:**
```python
results = await pool.map("uptime", timeout=30)
for result in results:
    print(result.stdout)
```

##### `map_safe(command, timeout=None) -> Dict[str, Result | Exception]`

Безопасное выполнение с возвратом исключений вместо выброса.

**Пример:**
```python
results = await pool.map_safe("uptime")
for uri, result in results.items():
    if isinstance(result, Exception):
        print(f"{uri}: Ошибка - {result}")
    else:
        print(f"{uri}: {result.stdout}")
```

##### `map_with_callback(command, callback, timeout=None) -> None`

Выполнение с callback по мере готовности результатов.

**Пример:**
```python
def on_result(uri: str, result: Result):
    print(f"{uri}: {result.stdout}")

await pool.map_with_callback("uptime", on_result)
```

### Result

Результат выполнения команды.

```python
from uniconn import Result

result: Result = await conn.run("uptime")

# Свойства
result.exit_code     # Код возврата (int)
result.stdout        # Стандартный вывод (str)
result.stderr        # Ошибки (str)
result.duration      # Время выполнения в секундах (float)
result.command       # Выполненная команда (str)
result.timestamp     # Время выполнения (datetime)
result.host          # Хост (str | None)
result.ok            # True если exit_code == 0 (bool)

# Методы
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
- `close() -> None`

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

```python
# Linux
conn = Connection.from_uri("serial:///dev/ttyUSB0?baudrate=9600")

# Windows
conn = Connection.from_uri("serial://COM3?baudrate=115200")

# С полными настройками
conn = Connection.from_uri(
    "serial:///dev/ttyUSB0?baudrate=9600&parity=N&stopbits=1"
)
```

**Параметры:**
- `baudrate`: Скорость (по умолчанию 9600)
- `parity`: Чётность (N, E, O)
- `stopbits`: Стоп-биты (1, 2)
- `xonxoff`: Программный flow control (true/false)
- `rtscts`: Аппаратный flow control (true/false)

**Зависимости:** `pip install uniconn[serial]` (pyserial-asyncio)

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

**Зависимости:** `pip install uniconn[bmc]` (pyghmi)

### Redfish (BMC)

```python
conn = Connection.from_uri("redfish://admin:password@bmc.local")

# Отключить проверку SSL (для self-signed)
conn = Connection.from_uri(
    "redfish://admin:password@bmc.local?verify_ssl=false"
)

# Команды
result = await conn.run("power status")
result = await conn.run("power on")
result = await conn.run("info")
result = await conn.run("sensors")
```

**Доступные команды:**
- `power status`, `power on`, `power off`, `power forceoff`
- `power cycle`, `power restart`
- `boot device` - Текущее boot устройство
- `sensors` - Информация с сенсоров
- `info` - Общая информация о системе
- `get /path` - Произвольный GET запрос
- `post /path data` - Произвольный POST запрос

**Зависимости:** `pip install uniconn[bmc]` (aiohttp)

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

#### Выполнение команды

```bash
# SSH
uniconn run "ssh://user:pass@host" "uptime"

# С таймаутом и подробным выводом
uniconn run "ssh://user:pass@host" "apt update" -t 120 -v
```

#### Параллельное выполнение

```bash
# На нескольких хостах
uniconn run-multi "ssh://host1" "ssh://host2" -c "uptime"

# С ограничением параллелизма
uniconn run-multi "ssh://host1" "ssh://host2" "ssh://host3" \
    -c "apt update" -j 2

# JSON вывод
uniconn run-multi "ssh://host1" "ssh://host2" -c "whoami" -f json
```

#### BMC управление

```bash
# Статус питания
uniconn bmc "redfish://admin:pass@idrac" "power status"

# Включить сервер
uniconn bmc "ipmi://admin:pass@bmc" "power on"

# Информация о системе
uniconn bmc "redfish://admin:pass@idrac" info
```

#### Интерактивная оболочка

```bash
uniconn shell "ssh://user:pass@host"
```

#### Список транспортов

```bash
uniconn transports
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

## Логирование

```python
import logging
from uniconn import Connection, get_logger

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)

# С кастомным логгером
logger = get_logger("myapp", level=logging.DEBUG)
conn = Connection.from_uri("ssh://user@host", logger=logger)

# Логгер маскирует секреты автоматически
logger.info("Connecting with password: secret")  # -> "password: ***"
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
# Запуск всех тестов
pytest

# Только unit тесты
pytest -m "not integration"

# Интеграционные тесты (требуется Docker)
pytest -m integration

# С покрытием
pytest --cov=uniconn
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
