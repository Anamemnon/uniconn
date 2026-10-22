---
name: testing-and-stability
description: Обязательные правила запуска тестов, написания новых unit-тестов для покрытия, предотвращения утечек корутин (RuntimeWarning) и проверки качества кода (ruff 120 chars + pyright) в проекте uniconn. Используйте при любых изменениях кода в src/ или tests/.
---

# Навык: Тестирование и стабильность проекта `uniconn`

Этот навык определяет обязательный рабочий процесс верификации и написания тестов при разработке `uniconn`.

## 1. Золотые правила тестирования

1. **Никаких изменений без запуска тестов**: После любого изменения в `src/uniconn/` или `tests/` агент **обязан** выполнить полный прогон unit-тестов:
   ```bash
   uv run pytest -m "not integration"
   ```
2. **Каждая новая фича или багфикс требует новых тестов**:
   - Размещайте новые тесты в соответствующем тематическом пакете внутри `tests/unit/`:
     - `tests/unit/core/` — `Connection`, `SyncConnection`, `Result`, `ShellSession`, URI/конфиги, `structlog`-логирование и хуки.
     - `tests/unit/transports/` — `SSHTransport`, `TelnetTransport`, `SerialTransport`, `LocalTransport`, `IPMITransport`, SFTP.
     - `tests/unit/pools/` — `ConnectionPool`, `SSHSessionPool`.
     - `tests/unit/screen/` — `ScreenPool`, `ScreenSession`, `LogPipeline`, cleanup.
     - `tests/unit/cli/` — команды CLI (`typer` + `rich`).
     - `tests/unit/releases/` — сквозные тесты функциональности конкретных релизов (`test_v0*_features.py`).
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
# 1. Прогон всех unit-тестов (410+ тестов, 0 failed, 0 RuntimeWarning)
uv run pytest -m "not integration"

# 2. Проверка стиля и докстрингов (лимит длины строки — 120 символов)
uv run ruff check src/

# 3. Статическая проверка типов (pyright standard mode — 0 errors)
uv run pyright
```
