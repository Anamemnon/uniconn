# План реализации: ScreenPool для управления фоновыми screen-сессиями

> **Статус**: Планирование  
> **Цель**: Универсальная подсистема для запуска долгоживущих команд в GNU screen через SSH с гибкой обработкой логов  
> **Приоритет**: P1 (Should have)

---

## 1. Желаемый результат

### Что мы получим

Подсистема `ScreenPool` внутри `uniconn`, которая позволяет:

1. **Запускать** множество долгоживущих команд (стресс-тесты, сборщики логов, бенчмарки, задачи мониторинга) в изолированных GNU screen сессиях на удалённом хосте через SSH.
2. **Отключаться** от SSH сразу после запуска — screen сессии продолжают работать на сервере автономно.
3. **Ограничивать** число параллельных мониторов: если запущено 16 screen сессий, опрашивать их статус и собирать логи могут всего 2–4 параллельных SSH-запроса.
4. **Гибко управлять логами** — собирать в реальном времени, скачивать по окончании, пересылать на другой хост или игнорировать. Имена логов на локальной машине задаются шаблонами.
5. **Корректно завершать** все сессии при ошибке, `KeyboardInterrupt` (`Ctrl+C`) или обрыве SSH — многоуровневая защита от зомби-процессов и утечки диска.
6. **Конфигурировать** поведение через YAML/JSON файл — команды, правила логов, лимиты сессий.

### Чего мы НЕ делаем в рамках этого плана

- Не реализуем поддержку `tmux` (только GNU screen).
- Не реализуем постоянный SSH-канал для real-time streaming (используем polling + tail).
- Не реализуем сбор системных метрик (CPU, memory, bandwidth) — только stdout/stderr команд.
- Не добавляем WebSocket / HTTP API для мониторинга.

---

## 2. Архитектура

### 2.1 Компоненты

```
ScreenPool (оркестратор)
│
├─► ScreenSession × N          — одна screen сессия на хосте
│   ├─ создаётся через screen -dmS
│   ├─ хранит путь к удалённому лог-файлу
│   ├─ знает свой PID и exit code
│   └─ умеет принимать Ctrl+C и cleanup
│
├─► LogPipeline                  — pipeline обработки логов
│   ├─ RemoteFileHandler         — источник на хосте (screen -L)
│   ├─ LocalFileHandler          — скачивание на локальную машину
│   ├─ ForwardHandler            — отправка на logserver / другой хост
│   ├─ StreamHandler             — real-time stream в Python-код
│   └─ NullHandler               — silent mode
│
├─► ScreenLogCollector           — чтение порций через tail -c +{offset}
│
└─► ScreenCleanupManager         — менеджер очистки
    ├─ atexit + signal handler (клиент)
    ├─ cleanup-скрипт на сервере
    └─ sentinel-файл (fail-safe)
```

### 2.2 Модули и файлы

| Файл | Назначение |
|------|-----------|
| `src/uniconn/background/__init__.py` | Публичные экспорты подсистемы |
| `src/uniconn/background/_models.py` | `LogEvent`, `StatusEvent`, `ScreenResult`, `LogConfig`, `LogRule` |
| `src/uniconn/background/_session.py` | `ScreenSession` — управление одной сессией |
| `src/uniconn/background/_pool.py` | `ScreenPool` — оркестрация множества сессий |
| `src/uniconn/background/_log_pipeline.py` | `LogPipeline`, `LogHandler` и реализации |
| `src/uniconn/background/_log_collector.py` | `ScreenLogCollector` — чтение порций логов |
| `src/uniconn/background/_cleanup.py` | `ScreenCleanupManager` — очистка ресурсов |
| `src/uniconn/background/_config.py` | `ScreenPoolConfig` (Pydantic) — загрузка из YAML/JSON |
| `tests/unit/test_screen_session.py` | Unit-тесты `ScreenSession` |
| `tests/unit/test_screen_pool.py` | Unit-тесты `ScreenPool` |
| `tests/unit/test_screen_log_pipeline.py` | Unit-тесты логов |
| `tests/unit/test_screen_cleanup.py` | Unit-тесты cleanup |
| `tests/unit/test_screen_config.py` | Unit-тесты конфигурации |

### 2.3 Интеграция в существующий проект

- `src/uniconn/__init__.py` — добавить `ScreenPool`, `ScreenSession`, `ScreenResult`, `LogConfig` в `__all__`.
- `src/uniconn/cli.py` — добавить команды `screen-run`, `screen-logs`, `screen-kill`.
- `AGENTS.md` — обновить архитектуру и примеры.
- `instractions.md` — отметить статус реализации.

---

## 3. Модели и конфигурация (`_models.py`, `_config.py`)

### 3.1 Data-классы событий

```python
@dataclass(frozen=True)
class LogEvent:
    session_id: str
    line: str
    timestamp: datetime

@dataclass(frozen=True)
class StatusEvent:
    session_id: str
    alive: bool
    pid: int | None
    exit_code: int | None

@dataclass(frozen=True)
class ScreenResult:
    session_id: str
    exit_code: int
    remote_log_path: str
    local_log_path: str | None
    duration: float
```

### 3.2 LogConfig (Pydantic)

```python
class LogRule(BaseModel):
    pattern: str                       # regex для matching команды
    local_name: str | None             # шаблон имени локального файла
    download: bool = True              # скачивать ли на локальную машину
    download_strategy: str = "on_complete"  # realtime | periodic | on_complete
    forward_to: str | None = None      # URI куда отправить (sftp://host/path)
    delete_remote: bool = False        # удалять remote лог после скачивания
    collect: bool = True               # собирать ли логи вообще

class LogConfig(BaseModel):
    local_dir: str = "./logs"
    max_log_size_mb: int = 100
    rules: list[LogRule] = []

class ScreenPoolConfig(BaseModel):
    uri: str
    max_screens: int = 16
    max_monitors: int = 4
    poll_interval: float = 5.0
    log_config: LogConfig = LogConfig()
    
    @classmethod
    def from_file(cls, path: str | Path) -> Self: ...
```

**Шаблоны для `local_name`:**
- `{pool_id}`, `{session_id}`, `{idx}`, `{timestamp}`, `{host}`, `{command}`
- Пример: `"stress/{command}_{idx}_{timestamp:%Y%m%d_%H%M%S}.log"`

**Критерий приёмки**: Pyright проходит, ruff проходит, YAML/JSON парсинг покрыт тестами.

---

## 4. Детальный план по этапам

### Этап 1: ScreenSession — низкоуровневый драйвер (`_session.py`)

**Цель**: Уметь создавать, мониторить и убивать одну screen сессию.

**Конструктор**:
```python
def __init__(
    self,
    connection: Connection,
    session_id: str,
    remote_log_path: str,
    logger: logging.Logger | None = None,
)
```

**Методы**:

| Метод | Описание | Реализация |
|-------|----------|------------|
| `async create(command: str) -> None` | Создаёт detached screen сессию с логированием | `screen -dmS {id} -L -Logfile {log} bash -c '{cmd}; echo __UNICONN_EXIT__=$? >> {log}'` |
| `async is_alive() -> bool` | Проверяет, существует ли сессия | `screen -ls \| grep {id}` |
| `async get_pid() -> int \| None` | PID основного процесса внутри screen | `ps aux \| grep {id}` или парсинг `screen -ls` |
| `async get_exit_code() -> int \| None` | Exit code завершившейся команды | Парсинг `__UNICONN_EXIT__={code}` из лога |
| `async send_ctrl_c() -> None` | Отправка Ctrl+C в сессию | `screen -S {id} -X stuff $'\\003'` |
| `async send_signal(sig: int) -> None` | Отправка сигнала по PID | `kill -{sig} {pid}` |
| `async kill(graceful: bool = True) -> None` | Graceful (Ctrl+C + wait) или force (kill) | Комбинация `send_ctrl_c` / `screen -X kill` |
| `async cleanup() -> None` | Удаление лог-файла и очистка | `rm -f {log}` |

**Edge cases**:
- Screen не установлен на хосте → `ScreenNotFoundError`.
- Имя сессии уже существует → генерировать новое имя или падать с `ScreenSessionExistsError`.
- Команда завершилась раньше первого `is_alive()` — `is_alive` возвращает `False`, `get_exit_code` парсит лог.
- Лог-файл не создался — retry через `AsyncRetrying`.

**Критерий приёмки**: Unit-тесты с моком `Connection.run()` покрывают все методы.

---

### Этап 2: LogPipeline — гибкая обработка логов (`_log_pipeline.py`)

**Цель**: Логи — это поток данных, который можно направлять в разные приёмники (sinks).

**Абстракция**:
```python
class LogHandler(ABC):
    @abstractmethod
    async def handle(self, session_id: str, chunk: list[str]) -> None: ...
```

**Реализации**:

| Handler | Назначение | Когда срабатывает |
|---------|-----------|-------------------|
| `RemoteFileHandler` | Источник — screen -L пишет на хост | Неявно, при создании сессии |
| `LocalFileHandler` | Скачать/дописать лог на локальную машину | При `poll_logs` или `on_complete` |
| `ForwardHandler` | Отправить на другой хост (SFTP) | `on_complete` или periodic batch |
| `StreamHandler` | Отдать в `AsyncIterator[LogEvent]` | При `poll_logs` |
| `NullHandler` | Ничего не делать | Когда `collect=False` |

**LogPipeline**:
```python
class LogPipeline:
    def __init__(self, handlers: Sequence[LogHandler]):
        self._handlers = handlers
    
    async def emit(self, session_id: str, chunk: list[str]) -> None:
        await asyncio.gather(
            *(h.handle(session_id, chunk) for h in self._handlers)
        )
```

**Стратегии скачивания (download_strategy)**:
- `realtime` — каждый chunk сразу пишется локально (высокая нагрузка на сеть).
- `periodic` — скачиваем chunk'ами каждые N секунд (компромисс).
- `on_complete` — скачиваем после завершения сессии (минимальная нагрузка, рекомендуется для нагрузочных тестов).

**Edge cases**:
- Forward на logserver не удался — лог остаётся локально, ошибка логируется, тест не падает.
- Лог превышает `max_log_size_mb` — остановить сбор, уведомить через `logger.warning`.
- Кодировка UTF-8 с мультибайтовыми символами — `tail -c +{offset}` (байты) вместо `-n`.

**Критерий приёмки**: Unit-тесты проверяют все handlers, стратегии и обработку ошибок.

---

### Этап 3: ScreenLogCollector — чтение порций (`_log_collector.py`)

**Цель**: Получать stdout/stderr из screen сессий порциями, не держа постоянное SSH-соединение.

**Принцип**:
- При создании сессии offset = 0.
- Каждый `tail` запрос: `tail -c +{offset} {log_path}`.
- После получения данных: `offset += len(data.encode())`.
- Если `collect=False` — offset не обновляется.

**Методы**:

| Метод | Описание |
|-------|----------|
| `async read_chunk(session: ScreenSession) -> tuple[list[str], int]` | Прочитать новые строки с текущего offset |
| `async stream(session: ScreenSession, interval: float = 1.0) -> AsyncIterator[str]` | Бесконечный async iterator строк |
| `async stream_all(sessions: Sequence[ScreenSession], interval: float = 1.0) -> AsyncIterator[LogEvent]` | Мультиплексированный поток |

**Критерий приёмки**: Unit-тесты проверяют корректность offset и порядок строк.

---

### Этап 4: ScreenCleanupManager — очистка ресурсов (`_cleanup.py`)

**Цель**: Гарантировать удаление screen сессий и логов даже при падении клиента.

**Client-side (Python процесс)**:
- `atexit.register(self._cleanup_local)` — нормальный выход.
- `signal.signal(SIGINT, self._on_signal)` — `Ctrl+C` → graceful shutdown.
- `signal.signal(SIGTERM, self._on_signal)` — `kill` → graceful shutdown.
- `asyncio.CancelledError` → `stop_all()`.

**Server-side (fail-safe)**:
- **Sentinel-файл**: `/tmp/uniconn_{pool_id}.active` (JSON со списком сессий).
- **Cleanup-скрипт**: `/tmp/uniconn_cleanup_{pool_id}.sh`:
  ```bash
  #!/bin/bash
  POOL_ID="{pool_id}"
  for s in $(screen -ls | grep "uniconn_${POOL_ID}_" | awk '{print $1}'); do
      screen -S "$s" -X kill 2>/dev/null
  done
  rm -f /tmp/uniconn_${POOL_ID}_*.log
  rm -f /tmp/uniconn_${POOL_ID}.active
  rm -f "$0"
  ```

**Edge cases**:
- `Ctrl+C` дважды → второй раз `force kill`.
- SSH оборван — cleanup-скрипт можно запустить вручную позже.
- Сервер перезагружен — при запуске нового пула чистим старые логи по паттерну.

**Критерий приёмки**: Unit-тесты проверяют вызов cleanup при `KeyboardInterrupt`.

---

### Этап 5: ScreenPool — оркестратор (`_pool.py`)

**Цель**: Управлять множеством сессий с ограничением на число мониторов.

**Конструктор**:
```python
def __init__(
    self,
    uri: str,
    max_screens: int = 16,
    max_monitors: int = 4,
    poll_interval: float = 5.0,
    log_config: LogConfig | None = None,
    logger: logging.Logger | None = None,
)
```

**Фабричные методы**:
- `from_config(config: ScreenPoolConfig) -> ScreenPool`
- `from_file(path: str | Path) -> ScreenPool`

**Методы**:

| Метод | Описание |
|-------|----------|
| `async start(command: str, name: str \| None = None) -> ScreenSession` | Создать сессию, применить правила логов из `LogConfig` |
| `async stop(session_id: str, graceful: bool = True)` | Остановить конкретную сессию |
| `async stop_all(graceful: bool = True)` | Остановить все сессии |
| `async wait_all(timeout: float \| None = None) -> dict[str, ScreenResult]` | Дождаться завершения |
| `async poll_logs(interval: float = 2.0) -> AsyncIterator[LogEvent]` | Периодический опрос логов |
| `async poll_status(interval: float = 5.0) -> AsyncIterator[StatusEvent]` | Периодический опрос статуса |
| `async cleanup() -> None` | Остановить всё + удалить артефакты |

**Внутренняя логика**:
- `_sessions: dict[str, ScreenSession]`
- `_monitor_sem: asyncio.Semaphore(max_monitors)`
- `_pool_id: str` — UUID пула
- `_session_prefix: str` — `uniconn_{pool_id}`
- `_log_pipeline: LogPipeline` — строится из `LogConfig`

**Мониторинг (N воркеров, M сессий)**:
```python
async def _monitor_loop(self, interval: float, callback):
    while self._sessions:
        async with self._monitor_sem:
            for session in list(self._sessions.values()):
                await callback(session)
        await asyncio.sleep(interval)
```

**Edge cases**:
- Превышение `max_screens` → `ScreenPoolFullError`.
- Обрыв SSH во время `poll_logs` — retry, при неудаче → `dead`.
- `wait_all` с `timeout` → после таймаута `force kill`.

**Критерий приёмки**: Unit-тесты с моками проверяют создание N сессий, ограничение мониторов, сбор логов, остановку.

---

### Этап 6: CLI команды (`cli.py`)

**Цель**: Управление screen сессиями из командной строки.

```bash
# Запуск из конфига
uniconn screen-run --config stress_config.yaml

# Запуск ad-hoc
uniconn screen-run ssh://host --instances 4 --command "stress-ng --cpu 4" --logs

# Мониторинг логов
uniconn screen-logs ssh://host --session-id uniconn_abc123_0 --follow

# Статус
uniconn screen-status ssh://host --pool-id abc123

# Убить сессию или весь пул
uniconn screen-kill ssh://host --session-id uniconn_abc123_0 --force
uniconn screen-kill ssh://host --pool-id abc123 --all
```

**Критерий приёмки**: Unit-тесты CLI с `typer.CliRunner`.

---

### Этап 7: Тесты

| Файл теста | Что проверяем | Кол-во тестов (план) |
|------------|---------------|----------------------|
| `test_screen_session.py` | Создание, is_alive, get_exit_code, send_ctrl_c, kill, cleanup | 10 |
| `test_screen_pool.py` | start, stop_all, wait_all, poll_logs, max_screens, max_monitors, KeyboardInterrupt | 12 |
| `test_screen_log_pipeline.py` | handlers, strategies, templates, forward | 10 |
| `test_screen_config.py` | YAML/JSON парсинг, LogConfig, LogRule matching | 6 |
| `test_screen_cleanup.py` | atexit, signal handler, cleanup-скрипт, sentinel | 6 |
| `test_cli_screen.py` | screen-run, screen-logs, screen-kill | 8 |

**Итого**: ~52 новых unit-теста.

---

### Этап 8: Документация

- `AGENTS.md` — добавить раздел `ScreenPool` с описанием архитектуры, LogPipeline, конфигурации.
- `instractions.md` — отметить статус реализации screen-сессий.
- `examples/screen_pool_config.yaml` — пример конфига.
- `examples/screen_monitoring.py` — пример мониторинга уже запущенных процессов.

---

## 5. Технические решения и обоснование

### 5.1 Почему GNU screen, а не tmux / nohup

| Критерий | Screen | Tmux | Nohup |
|----------|--------|------|-------|
| Установлен по умолчанию | ✅ Да (99% Linux) | ⚠️ Часто нет | ✅ Да |
| Отправка Ctrl+C без SSH | ✅ `screen -X stuff` | ✅ `tmux send-keys` | ❌ Нет |
| Detached запуск | ✅ `-dmS` | ✅ `new-session -d` | ✅ `&` |
| Логирование в файл | ✅ `-L -Logfile` | ⚠️ Сложнее | ✅ Перенаправление |
| Получение вывода | ✅ `tail` лога | ✅ `capture-pane` | ✅ `tail` лога |

**Вывод**: Screen — наиболее универсальный выбор для серверного окружения.

### 5.2 Именование сессий и файлов

```
Session name: uniconn_{pool_uuid}_{idx}
Remote log:   /tmp/uniconn_{pool_uuid}_{idx}.log
Sentinel:     /tmp/uniconn_{pool_uuid}.active
Cleanup:      /tmp/uniconn_cleanup_{pool_uuid}.sh
```

- `pool_uuid` — UUID4, генерируется при создании `ScreenPool`.
- `idx` — порядковый номер сессии в пуле.
- Паттерн `uniconn_*` защищает пользовательские screen от cleanup.

### 5.3 Шаблоны имён локальных логов

```python
local_name = "stress/{command}_{idx}_{timestamp:%Y%m%d_%H%M%S}.log"
```

Доступные переменные: `{pool_id}`, `{session_id}`, `{idx}`, `{timestamp}`, `{host}`, `{command}`.

### 5.4 Получение exit code

```bash
bash -c 'my_command; echo __UNICONN_EXIT__=$? >> /tmp/uniconn_xxx.log'
```

`ScreenSession.get_exit_code()` парсит `__UNICONN_EXIT__=\d+`.

### 5.5 Ограничение числа мониторов

Каждый `poll_logs` или `poll_status` — это SSH-запрос.
Решение: `asyncio.Semaphore(max_monitors)` + round-robin.

### 5.6 Многоуровневая защита от зомби

```
Уровень 1 (клиент):  atexit + signal → stop_all()
Уровень 2 (клиент):  asyncio.CancelledError → cleanup()
Уровень 3 (сервер):  cleanup-скрипт
Уровень 4 (сервер):  sentinel-файл (ручной запуск)
Уровень 5 (сервер):  /tmp чистится при reboot (tmpfs)
```

---

## 6. Пример использования (целевой API)

### 6.1 Через конфигурационный файл

```yaml
# monitoring_config.yaml
uri: "ssh://admin@web-server"
max_screens: 8
max_monitors: 2
poll_interval: 5.0
log_config:
  local_dir: "./logs"
  rules:
    - pattern: "tail -f /var/log/nginx"
      local_name: "nginx_{idx}.log"
      download: true
      forward_to: "sftp://backup-server/logs/"
    - pattern: "sysbench"
      local_name: "sysbench_{timestamp}.log"
      download: true
      download_strategy: "on_complete"
    - pattern: ".*"
      collect: false
```

```python
import asyncio
from uniconn import ScreenPool

async def main():
    pool = ScreenPool.from_file("monitoring_config.yaml")
    async with pool:
        s1 = await pool.start("tail -f /var/log/nginx/access.log")
        s2 = await pool.start("sysbench --test=cpu --cpu-max-prime=20000 run")
        
        async for event in pool.poll_logs(interval=2.0):
            print(f"[{event.session_id}] {event.line.rstrip()}")
        
        results = await pool.wait_all(timeout=3600.0)

asyncio.run(main())
```

### 6.2 Ad-hoc запуск

```python
async with ScreenPool("ssh://admin@server", max_screens=4) as pool:
    sessions = [
        await pool.start(f"long_running_task.py --worker {i}")
        for i in range(4)
    ]
    results = await pool.wait_all()
```

---

## 7. Риски и ограничения

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| Screen не установлен | Низкая | Высокое | Проверка `which screen`, понятная ошибка |
| Лог-файлы занимают диск | Средняя | Среднее | `max_log_size_mb`, ротация |
| Обрыв SSH — зомби | Средняя | Среднее | Cleanup-скрипт + sentinel |
| Разные версии screen | Низкая | Среднее | Fallback синтаксиса `-logfile` |
| Forward на logserver падает | Средняя | Низкое | Best-effort, retry 3 раза, fallback local |
| Конфликт имён с пользовательскими screen | Низкая | Низкое | Префикс `uniconn_{uuid}` |

---

## 8. Оценка трудозатрат

| Этап | Сложность | Оценка |
|------|-----------|--------|
| 1. Модели + Config | Низкая | 1 ч |
| 2. ScreenSession | Средняя | 2–3 ч |
| 3. LogPipeline | Средняя | 3 ч |
| 4. ScreenLogCollector | Низкая | 1 ч |
| 5. ScreenCleanupManager | Средняя | 2 ч |
| 6. ScreenPool | Высокая | 3–4 ч |
| 7. CLI | Средняя | 2 ч |
| 8. Тесты | Средняя | 4–5 ч |
| 9. Документация | Низкая | 1 ч |
| **Итого** | | **19–24 ч** |

---

*Файл обновлён: 2026-05-07*  
*Версия плана: 2.0*
