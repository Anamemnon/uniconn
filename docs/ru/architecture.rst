Архитектура ядра, конвейер Middleware и жизненный цикл вызова
=============================================================

**Язык:** `English <../architecture.rst>`_ | **[ Русский ]**

В этом руководстве подробно разобрано внутреннее устройство ``uniconn``: как обеспечивается 100% паритет между ``Connection`` и ``SyncConnection`` с накладными расходами менее ``0.3 мс``, в каком порядке запрос проходит через 11 звеньев ``CommandPipeline``, как устроен постоянный RPC-воркер ``conn.run_python()`` и как написать собственный Middleware или транспорт.

1. Многоуровневая архитектура библиотеки
----------------------------------------

Ядро ``uniconn`` разделено на четыре независимых слоя:

1. **Фасад и синхронный портал**: ``Connection``, ``ConnectionPool``, ``Flow``, ``ShellSession`` и их синхронные двойники (``SyncConnection``, ``SyncConnectionPool``, ``SyncFlow``, ``SyncShellSession``).
2. **Доменные сервисы**: ``conn.files`` (``FileOperationsService``), ``conn.path`` (``RemotePath``), ``conn.state`` (``StateManagementService``), ``conn.net`` (``NetworkOperationsService``), ``conn.tunnels`` (``TunnelService``) и сборщик фактов ``FactCollector``.
3. **Конвейер отказоустойчивости и безопасности (``CommandPipeline``)**: Цепочка ответственности (Chain of Responsibility), через которую проходит каждый ``CommandRequest`` (применение ``cd``/``env``, двухфазное согласование HITL, AST-политики безопасности, оборачивание в ``sudo``, пользовательские хуки, ``dry_run``, структурное логирование, автодиагностика сбоев, ``CircuitBreaker``, ``RateLimiter`` и экспоненциальный ``Retry``).
4. **Слой транспортов на базе протоколов возможностей (ISP)**: Плагинные драйверы, реализующие чётко разграниченные протоколы (``CommandTransport``, ``FileCapableTransport``, ``ShellCapableTransport``, ``TunnelCapableTransport``, ``StructuredNetworkTransport``).

.. code-block:: text

   ┌────────────────────────────────────────────────────────────────────────────────────────┐
   │                   СЛОЙ ФАСАДА И ПАРАДИГМ ВЫПОЛНЕНИЯ (ASYNC + SYNC)                     │
   │   Async: Connection / ConnectionPool / Flow / ShellSession / BackgroundPool            │
   │   Sync:  SyncConnection / SyncConnectionPool / SyncFlow (через EventLoopPortal <0.3мс) │
   └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                               │
                     ┌─────────────────────────▼──────────────────────────┐
                     │               СЛОЙ ДОМЕННЫХ СЕРВИСОВ               │
                     │  • conn.files / conn.path (SFTP, дельта-синхр, хеш)│
                     │  • conn.state (Идемпотентные ensure_*, Diff, Notify)│
                     │  • conn.net   (NETCONF / RESTCONF / gNMI операции) │
                     │  • conn.run_python (Zero-Fork RPC воркер < 2 мс)   │
                     └─────────────────────────┬──────────────────────────┘
                                               │
                     ┌─────────────────────────▼──────────────────────────┐
                     │          КОНВЕЙЕР КОМАНД (COMMAND PIPELINE)        │
                     │  1. ContextMiddleware (стек cd / переменные env)   │
                     │  2. HITLApprovalMiddleware (двухфазные аппрувы)    │
                     │  3. PolicyGuardrailMiddleware (AST-разбор и ABAC)  │
                     │  4. SudoMiddleware (sudo -S / -n и ввод пароля)    │
                     │  5. HookMiddleware (хуки before_run / after_run)   │
                     │  6. DryRunMiddleware (короткое замыкание dry_run)  │
                     │  7. ObservabilityMiddleware (логи, raise_on_error) │
                     │  8. AutoDiagnosticMiddleware (зонды самодиагностики)│
                     │  9. CircuitBreakerMiddleware (предохранитель сети) │
                     │ 10. RateLimitMiddleware (асинхронный Token Bucket) │
                     │ 11. RetryMiddleware (Exponential Backoff + Jitter) │
                     └─────────────────────────┬──────────────────────────┘
                                               │
   ┌───────────────────────────────────────────▼────────────────────────────────────────────┐
   │                     ПРОТОКОЛЫ ВОЗМОЖНОСТЕЙ ТРАНСПОРТОВ (ISP)                           │
   ├──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
   │ Command      │ FileCapable  │ ShellCapable │ TunnelCapable│ StructuredNet│ ReplayProxy │
   │ (run/stream) │ (SFTP/Modem) │ (PTY/Expect) │ (PortFwd)    │ (YANG/gNMI)  │ (Кассеты)   │
   └──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘

2. Механика паритета Async + Sync (``EventLoopPortal``)
-------------------------------------------------------

Вместо дублирования кода для синхронного и асинхронного режимов все операции ввода-вывода в ``uniconn`` написаны на ``asyncio``, а синхронные классы работают через ``EventLoopPortal`` и ``SyncProxyMixin`` (модуль ``uniconn.core.bridge``):

- **Фоновый синглтон цикла событий**: ``EventLoopPortal`` запускает выделенный daemon-поток с постоянно активным ``asyncio`` event loop.
- **Типизированные дескрипторы без копирования кода**: Методы ``SyncConnection``, ``SyncConnectionPool`` и синхронных сервисов (``.files``, ``.state``, ``.net``, ``.tunnels``) объявляются однострочными ``ParamSpec``-дескрипторами (``sync_method``, ``sync_context``, ``sync_iter``).
- **Безопасность в любой среде**: Вызов ``sync_conn.run("uptime")`` передаёт корутину в фоновый поток через ``asyncio.run_coroutine_threadsafe()`` и ожидает результат. Благодаря этому ``SyncConnection`` работает даже внутри уже запущенного event loop (например, в Jupyter Notebook или гибридных веб-воркерах) без ошибки ``RuntimeError: This event loop is already running``.

.. tip::

   Любое асинхронное соединение ``Connection`` или пул ``ConnectionPool`` можно в любой момент обернуть в синхронный интерфейс методом ``conn.to_sync()`` или ``pool.to_sync()``.

3. Пошаговый жизненный цикл вызова ``conn.run()``
-------------------------------------------------

При вызове ``await conn.run("systemctl restart nginx", sudo=True, parse="auto", diagnose=True)`` создаётся объект ``CommandRequest``, который последовательно проходит через цепочку ``CommandMiddleware`` внутри ``conn.pipeline.execute(request)``.

Строгий порядок выполнения Middleware
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 6 26 68
   :header-rows: 1

   * - Шаг
     - Класс Middleware
     - Назначение и трансформация ``CommandRequest`` / ``Result``
   * - **1**
     - ``ContextMiddleware``
     - Считывает текущую рабочую директорию из стека ``conn.cd()`` и переменные окружения из ``conn.env()``, записывая их в ``request.transport_kwargs`` (``cwd`` и ``env``).
   * - **2**
     - ``HITLApprovalMiddleware`` *(опционально)*
     - Если подключён, оценивает уровень риска команды через ``ActionRiskClassifier``. Блокирует ``TIER_3_FORBIDDEN``; для рискованных операций проверяет криптографический токен ``approval_id`` или создаёт заявку на одобрение оператором (выбрасывая ``ApprovalRequiredError`` или ожидая решения).
   * - **3**
     - ``PolicyGuardrailMiddleware`` *(опционально)*
     - Если подключён, строит синтаксическое дерево команды через ``CommandASTParser`` (раскрывая вложенные обёртки ``sudo``, ``sh -c``, ``find -exec``, ``base64``) и проверяет правила ``EmbeddedPolicyEngine`` или ``OPAPolicyEngine``.
   * - **4**
     - ``SudoMiddleware``
     - При ``request.sudo=True`` преобразует команду в ``sudo -S -p '' [-u user] -- sh -c '...'`` (если задан пароль ``sudo_password`` или пароль подключения) и безопасно подставляет пароль в ``stdin`` транспорта, либо использует ``sudo -n`` для беспарольного sudo.
   * - **5**
     - ``HookMiddleware``
     - Вызывает все пользовательские хуки ``before_run(command, host, transport_kwargs)`` до выполнения и ``after_run(result)`` после получения результата.
   * - **6**
     - ``DryRunMiddleware``
     - Если активен ``dry_run=True``, логирует событие ``command.dry_run`` и мгновенно возвращает синтетический ``Result(exit_code=0, stdout="", _dry_run=True)`` без обращения к сети и без срабатывания ``CircuitBreaker``.
   * - **7**
     - ``ObservabilityMiddleware``
     - Привязывает ``host``, ``transport`` и ``uri_safe`` к контексту ``structlog``, пишет события ``command.start`` и ``command.finish`` (маскируя секреты при ``sensitive=True``), вызывает хуки ``on_error`` при исключениях и проверяет ``result.raise_for_status()`` при ``raise_on_error=True``.
   * - **8**
     - ``AutoDiagnosticMiddleware``
     - Если команда завершилась с ``exit_code != 0`` и включён ``diagnose=True`` (или ``conn.auto_diagnostics=True``), запускает изолированные диагностические зонды в рамках тайм-бюджета (по умолчанию ``2.0 с``) и прикрепляет ``DiagnosticSummary`` к ``result.diagnostic``.
   * - **9**
     - ``CircuitBreakerMiddleware``
     - Проверяет состояние ``conn.circuit_breaker``. Если цепь разомкнута (``OPEN``), мгновенно выбрасывает ``CircuitOpenError``. Фиксирует успех или сетевой сбой (``ConnectionError``, ``TimeoutError``).
   * - **10**
     - ``RateLimitMiddleware``
     - Запрашивает токен у ``conn.rate_limiter`` (асинхронный алгоритм Token Bucket) для соблюдения лимита запросов в секунду.
   * - **11**
     - ``RetryMiddleware``
     - Выполняет повторные попытки (Exponential Backoff + Jitter) до ``conn.retry_attempts`` раз при ``ConnectionError`` и ``TimeoutError``, автоматически переподключая транспорт между попытками.
   * - **12**
     - ``_terminal_dispatch`` и Парсинг
     - Вызывает ``transport.run()`` (или ``transport.run_bytes()``). На обратном пути прикрепляет спецификацию парсинга ``parse_spec`` (и валидирует Pydantic-схему).

.. important::

   Почему порядок слоёв в ``CommandPipeline`` критически важен:

   - ``HookMiddleware`` (шаг 5) расположен **до** ``DryRunMiddleware`` (шаг 6), поэтому ваши аудит-хуки ``before_run`` и ``after_run`` гарантированно вызываются даже в режиме симуляции ``dry_run=True``.
   - ``ObservabilityMiddleware`` (шаг 7) оборачивает ``AutoDiagnosticMiddleware`` (шаг 8) снаружи: благодаря этому при ``raise_on_error=True`` выброшенное исключение ``ExecutionError`` **уже содержит** готовый отчёт ``err.diagnostic``!
   - ``CircuitBreakerMiddleware`` (шаг 9) расположен **снаружи** ``RetryMiddleware`` (шаг 11), поэтому счётчик аварийного размыкателя увеличивается только тогда, когда исчерпаны все попытки ретрая.

4. Внутреннее устройство ключевых подсистем
-------------------------------------------

Постоянный Python RPC без форков (``RemotePythonWorker``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Обычный вызов ``conn.run("python3 -c ...")`` на каждую команду создаёт новый канал SSH, запускает shell и инициализирует интерпретатор Python (от ``40`` до ``150 мс``). Метод ``conn.run_python(fn, *args, **kwargs)`` устраняет эти накладные расходы:

1. **Ленивый старт воркера**: При первом вызове ``conn.run_python()`` открывается один постоянный фоновый процесс ``python3 -u -c <bootstrap>`` с двунаправленным каналом ``stdin/stdout``.
2. **Сериализация вызовов (``CallableSerializer``)**: Функция или ``lambda`` вместе с аргументами упаковывается в компактный JSON-кадр.
3. **Мультиплексированный обмен**: Вызовы и результаты передаются по уже открытому пайпу за ``< 2 мс`` без создания новых процессов на целевом хосте. При обрыве или таймауте воркер автоматически перезапускается.

Интерактивные PTY-сессии (``PosixMarkerProtocol`` и ``ExpectStateMachine``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

При открытии сессии ``async with await conn.open_shell() as shell:`` все команды выполняются внутри одного псевдотерминала (PTY), где сохраняются ``cd``, ``export`` и история:

- **Детерминированная разметка границ (``PosixMarkerProtocol``)**: Поскольку в непрерывном потоке PTY нет отдельного канала для кода возврата каждой команды, ``shell.execute()`` автоматически добавляет маркер ``printf "\n__UNICONN_EOF_<uuid>:%d__\n" $?``. Парсер отсекает эхо ввода, ANSI-последовательности и приглашение командной строки, возвращая чистый ``stdout`` и точный ``exit_code``.
- **Автомат интерактивных диалогов (``ExpectStateMachine``)**: Метод ``conn.expect()`` сопоставляет поток вывода с регулярными выражениями промптов и отправляет ответы, автоматически скрывая пароли из логов при ``sensitive=True``.

Разделение интерфейсов транспортов (ISP Protocols)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Разные транспорты обладают разными возможностями (например, ``ipmi://`` не поддерживает SFTP или проброс портов). В ``uniconn.transports.base`` возможности разделены на независимые протоколы:

- ``BaseTransport``: Базовый жизненный цикл (``connect()``, ``disconnect()``, ``is_connected``, ``ping()``).
- ``CommandTransport``: Выполнение команд и потоков (``run()``, ``run_bytes()``, ``stream()``).
- ``FileCapableTransport``: Файловые операции (``read_file()``, ``write_file()``, ``stat()``, ``listdir()``, ``mkdir()``, ``remove_file()``, ``chmod()``).
- ``ShellCapableTransport``: Интерактивные PTY-сессии (``open_shell()``).
- ``TunnelCapableTransport``: Проброс портов (``forward_local_port()``, ``forward_remote_port()``).
- ``StructuredNetworkTransport``: Структурированные сетевые операции (``net_get()``, ``net_edit_config()``, ``net_rpc()``, ``net_subscribe()`` для ``netconf://``, ``restconf://``, ``gnmi://``).

Если сервис вызывает операцию, которую транспорт не поддерживает, функция ``require_capability()`` немедленно выбрасывает ``CapabilityNotSupportedError`` (наследник ``UniconnError`` и ``NotImplementedError``).

5. Добавление собственного Middleware в конвейер
------------------------------------------------

Вы можете встроить собственную логику (метрики, проверку тикетов, модификацию команд) в любой экземпляр ``Connection`` через ``conn.pipeline.add_middleware()`` или ``conn.pipeline.insert_middleware(index, mw)``:

.. code-block:: python

   import time
   from uniconn import Connection, Result
   from uniconn.core.pipeline import CommandRequest, NextHandler

   class SlowCommandAlertMiddleware:
       def __init__(self, threshold_sec: float = 5.0) -> None:
           self.threshold_sec = threshold_sec

       async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
           t0 = time.monotonic()
           result = await call_next(request)
           elapsed = time.monotonic() - t0
           if elapsed > self.threshold_sec:
               print(f"[МЕДЛЕННАЯ КОМАНДА] {request.command!r} выполнялась {elapsed:.2f} с")
           return result

   async with Connection.local() as conn:
       # Вставка на позицию 0 оборачивает весь пайплайн, включая ретраи
       conn.pipeline.insert_middleware(0, SlowCommandAlertMiddleware(threshold_sec=1.0))
       res = await conn.run("echo hello")
       assert res.ok
