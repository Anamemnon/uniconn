# CLAUDE.md — Руководство для ИИ-агентов (uniconn)

Перед внесением изменений ознакомьтесь с:
- `AGENTS.md` — архитектура модулей и инварианты разработки.
- `llms.txt` — краткий справочник всех публичных классов, сигнатур и URI-схем.
- `instractions.md` — матрица возможностей и статус реализации.

## Основные команды (uv)

```bash
# Запуск unit-тестов (все тесты должны проходить без Docker)
uv run pytest -m "not integration"

# Линтинг и проверка форматирования (лимит строки — 100 символов)
uv run ruff check src/

# Статическая проверка типов (pyright standard mode, 0 errors)
uv run pyright

# Запуск веб-дашборда предпросмотра на порту 3000
python3 main.py --serve
```

## Инварианты проекта
1. **Async + Sync паритет**: Любой новый публичный метод или контекстный менеджер в `Connection` (`src/uniconn/_connection.py`) должен иметь синхронный аналог в `SyncConnection` (`src/uniconn/_sync.py`).
2. **Безопасность**: Пароли и парольные фразы хранятся в `pydantic.SecretStr`. При `sensitive=True` вывод маскируется в `Result.__repr__`, `ExecutionError` и логах аудита.
3. **Точка входа**: `main.py` запускает либо CLI-демонстрацию, либо (с флагом `--serve`) веб-панель из `examples/dashboard/server.py` на порту `3000`.
