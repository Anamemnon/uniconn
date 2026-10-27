---
name: testing-and-stability
description: Обязательные правила запуска тестов, написания новых unit-тестов для покрытия, предотвращения утечек корутин (RuntimeWarning) и проверки качества кода (ruff 120 chars + pyright) в проекте uniconn. Используйте при любых изменениях кода в src/ или tests/.
---

# Навык: Тестирование и стабильность проекта `uniconn`

Этот навык определяет обязательный рабочий процесс верификации и написания тестов при разработке `uniconn`.

## 1. Золотые правила тестирования

1. **Никаких изменений без запуска тестов**: После любого изменения в `src/uniconn/` или `tests/` агент **обязан** выполнить полный прогон unit-тестов с кратким выводом для экономии контекста:
   ```bash
   uv run pytest -m "not integration" -q --tb=short | tail -n 5
   ```
   При обнаружении ошибок для детального просмотра упавших тестов запускайте:
   ```bash
   uv run pytest -m "not integration" -q --tb=short --lf | tail -n 30
   ```
2. **Каждая новая фича или багфикс требует новых тестов**:
   - Размещайте новые тесты строго по доменным пакетам внутри `tests/unit/` (зеркало `src/uniconn/`, не создавайте версионные файлы вида `test_v0*_features.py`):
     - `tests/unit/core/` — `Connection`, `SyncConnection`, `Result`, `ShellSession`, `wait_for_*`, `CircuitBreaker`, `RateLimiter`, `SecretResolver`, URI/конфиги, `structlog`-логирование и хуки.
     - `tests/unit/services/` — `FileOperationsService`, `checksum`, `sync_dir`, `write_template`, `FactCollector`, `StateManagementService` и примитивы `ensure_*`.
     - `tests/unit/transports/` — `SSH`, `Telnet`, `Serial`, `Local`, `IPMI`, `Redfish`, `Docker`, `Podman`, `Kubectl`, `Replay`/`Cassette`, SFTP.
     - `tests/unit/pools/` — `ConnectionPool` (включая батчинг и `select()`), `SSHSessionPool`.
     - `tests/unit/screen/` — `ScreenPool`, `ScreenSession`, `LogPipeline`, `DiagnosticSession`, cleanup.
     - `tests/unit/cli/` — команды CLI (`cyclopts` + `rich`) и веб-дашборд.
     - `tests/unit/architecture/` — архитектурные инварианты и публичный контракт API.
   - При добавлении метода/контекстного менеджера в `Connection` необходимо добавить unit-тесты как для асинхронного `Connection`, так и для синхронного `SyncConnection`.
   - Покрывайте не только «счастливый путь» (happy path), но и граничные случаи: ошибки сети/таймауты, `dry_run=True`, `sensitive=True` (проверка отсутствия утечки секретов в `repr`, `to_dict()` и логах).
3. **Нулевая терпимость к `RuntimeWarning` (утечкам корутин)**:
   - В `pyproject.toml` установлено правило `filterwarnings = ["error::RuntimeWarning"]`. Любая неожиданная корутина (`coroutine '...' was never awaited`) приводит к падению тестов.
   - **Правило мокирования потоков (`StreamWriter`, `serial_asyncio`, `telnetlib3`)**:
     Если объект `writer` создаётся через `AsyncMock()`, его **синхронные** методы (`writer.write`, `writer.close`) обязательно нужно явно переопределять через `MagicMock()`:
     ```python
     writer = mocker.AsyncMock()
     writer.write = MagicMock()       # write() — синхронный метод!
     writer.drain = mocker.AsyncMock() # drain() — асинхронный метод!
     writer.close = MagicMock()       # close() — синхронный метод!
     writer.wait_closed = mocker.AsyncMock()
     ```
   - При раннем выходе из синхронных обёрток (например, `SyncConnection._run_coro` при `self._closed == True`) переданная корутина должна явно закрываться через `coro.close()`.

## 2. Чек-лист перед завершением задачи

Перед тем как сообщить пользователю о готовности задачи, выполните последовательно:

```bash
# 1. Прогон всех unit-тестов с выводом последних строк для экономии контекста (0 failed, 0 RuntimeWarning)
uv run pytest -m "not integration" -q --tb=short | tail -n 5

# 2. Проверка стиля и докстрингов (лимит длины строки — 120 символов)
uv run ruff check src/

# 3. Статическая проверка типов (pyright standard mode — 0 errors)
uv run pyright
```
