Руководство по отладке, иерархии исключений и решению частых проблем
====================================================================

**Язык:** `English <../troubleshooting.rst>`_ | **[ Русский ]**

Это руководство поможет быстро локализовать и устранить любую ошибку при работе с ``uniconn``: от разбора атрибутов исключений ``UniconnError`` и включения автодиагностики ``diagnose=True`` до решения проблем с ``sudo``, SSH jump-хостами, ``RemotePythonWorker`` и контрактными кассетами.

1. Полная иерархия исключений (``UniconnError``)
------------------------------------------------

Все собственные исключения библиотеки наследуются от ``UniconnError`` и одновременно от профильных встроенных исключений Python (``builtins.ConnectionError``, ``builtins.TimeoutError``, ``ValueError``, ``PermissionError``, ``NotImplementedError``), что позволяет перехватывать их как доменными, так и стандартными блоками ``except``.

Дерево наследования исключений
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   Exception
    └── UniconnError (базовый класс: .command, .exit_code, .stdout, .stderr, .host, .diagnostic)
         ├── ConfigurationError (также ValueError)
         │    └── CyclicDependencyError (.cycle)
         ├── ConnectionError (также builtins.ConnectionError)
         │    ├── AuthenticationError
         │    ├── CircuitOpenError (.remaining_seconds)
         │    └── PolicyEngineUnavailableError (.engine_name, .endpoint)
         ├── TimeoutError (также builtins.TimeoutError)
         │    └── ApprovalExpiredError (.approval_id, .approval_request)
         ├── ExecutionError
         │    └── FlowExecutionError (.report, .failed_hosts)
         ├── FileTransferError
         │    └── ModemTransferError
         │         ├── ModemHandshakeTimeoutError
         │         ├── ModemCancelledError
         │         ├── ModemMaxRetriesError
         │         ├── ModemProtocolError
         │         └── ModemChecksumMismatchError
         ├── ParsingError (также ValueError)
         │    ├── ParserNotFoundError (также LookupError)
         │    └── OptionalDependencyError (также ImportError)
         ├── ApprovalError (также PermissionError: .approval_id, .approval_request)
         │    ├── ApprovalRequiredError
         │    ├── ApprovalRejectedError (.decided_by, .decision_reason)
         │    ├── ApprovalExpiredError (также TimeoutError)
         │    ├── ApprovalTamperingError
         │    └── ApprovalAlreadyConsumedError
         ├── PolicyError (также PermissionError)
         │    ├── PolicyViolationError (.decision, .violations, .rule_names, .remediation_hint)
         │    └── PolicyEngineUnavailableError (также ConnectionError)
         ├── BackgroundError
         │    ├── BackgroundBackendError
         │    ├── BackgroundSessionExistsError
         │    ├── BackgroundPoolFullError
         │    └── HardwareFaultDetectedError (.match, .matches)
         ├── CassetteError
         │    └── CassetteMissError (.kind, .command, .host, .candidates)
         ├── BatchAbortedError (.batch_index, .fail_ratio, .max_fail_ratio, .completed_results, .failed_hosts)
         ├── CapabilityNotSupportedError (также NotImplementedError)
         ├── BMCCapabilityError
         └── TransportNotFoundError

Справочник атрибутов исключений
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 28 32 40
   :header-rows: 1

   * - Класс исключения
     - Полезные атрибуты объекта
     - Когда возникает и как обрабатывать
   * - ``UniconnError`` / ``ExecutionError``
     - ``.command``, ``.exit_code``, ``.stdout``, ``.stderr``, ``.host``, ``.diagnostic``
     - Выбрасывается при ``conn.run(..., raise_on_error=True)`` или ``result.raise_for_status()``, когда ``exit_code != 0``. Проверьте ``err.stderr`` и ``err.diagnostic``.
   * - ``ConfigurationError``
     - ``.message``
     - Некорректный URI, отсутствующий секрет ``env://`` / ``file://`` без ``?default=`` или неподдерживаемое расширение инвентаря.
   * - ``CyclicDependencyError``
     - ``.cycle`` (``list[str]``)
     - Цикл в графе зависимостей ``@task(depends_on=...)`` внутри ``Flow`` (например, ``['a', 'b', 'a']``).
   * - ``CircuitOpenError``
     - ``.host``, ``.remaining_seconds``, ``.command``
     - Предохранитель ``CircuitBreaker`` разомкнут (``OPEN``) после серии сетевых сбоев. Подождите ``err.remaining_seconds`` или вызовите ``conn.circuit_breaker.reset()``.
   * - ``BatchAbortedError``
     - ``.batch_index``, ``.fail_ratio``, ``.max_fail_ratio``, ``.completed_results``, ``.failed_hosts``
     - Волновой роллаут в ``ConnectionPool`` превысил порог ошибок ``max_fail_ratio``. В ``err.failed_hosts`` доступны упавшие узлы текущей волны.
   * - ``FlowExecutionError``
     - ``.report`` (``FlowReport``), ``.failed_hosts``
     - Выбрасывается методом ``flow_report.raise_for_status()``, если хотя бы одна задача в ``Flow`` завершилась с ошибкой.
   * - ``CassetteMissError``
     - ``.kind``, ``.command``, ``.host``, ``.candidates``
     - При воспроизведении кассеты не найдена подходящая запись. В списке ``err.candidates`` перечислены наиболее похожие записанные команды.
   * - ``ApprovalRequiredError``
     - ``.approval_id``, ``.approval_request``
     - Политика HITL приостановила выполнение до подтверждения оператором (``uniconn approval approve <id>``).
   * - ``PolicyViolationError``
     - ``.decision``, ``.violations``, ``.rule_names``, ``.remediation_hint``
     - ``CommandASTParser`` или движок политик заблокировал опасную команду. Рекомендация по исправлению находится в ``err.remediation_hint``.
   * - ``CapabilityNotSupportedError``
     - ``.message``
     - Запрошенная операция (например, SFTP или туннелирование) не поддерживается выбранным транспортом.

2. Автоматическая диагностика первопричин сбоев (``diagnose=True``)
-------------------------------------------------------------------

По умолчанию при ненулевом коде возврата ``conn.run()`` возвращает объект ``Result`` (``res.ok == False``). Если передать ``diagnose=True`` (или включить ``auto_diagnostics=True`` на уровне ``Connection`` / ``ConnectionPool``), ``AutoDiagnosticMiddleware`` автоматически запустит легковесные зонды в пределах тайм-бюджета (по умолчанию ``2.0 с``) и заполнит ``res.diagnostic`` (``DiagnosticSummary``):

.. list-table::
   :widths: 28 32 40
   :header-rows: 1

   * - ``ErrorCategory``
     - Что распознаёт ``ErrorClassifier``
     - Какие зонды запускаются и что попадает в ``res.diagnostic``
   * - ``PORT_CONFLICT``
     - ``EADDRINUSE``, ``Address already in use``, ``bind() failed``
     - Выполняет ``ss -tlpn`` / ``netstat`` (или ``Get-NetTCPConnection`` на Windows) и заполняет ``diag.port_conflict`` (порт, ``conflicting_pid``, имя процесса).
   * - ``DISK_FULL``
     - ``No space left on device``, ``ENOSPC``, нехватка inodes
     - Запрашивает ``df -Pm / /tmp`` и ``df -Pi /``, заполняя ``diag.vitals`` (``disk_root_free_mb``, ``disk_root_inodes_free``).
   * - ``OUT_OF_MEMORY``
     - ``exit_code == 137`` (SIGKILL), ``Out of memory``, ``oom-killer``
     - Читает ``/proc/meminfo``, счётчик ``oom_kill`` в cgroup v1/v2 контейнера и хвост ``dmesg`` в ``diag.dmesg_tail``.
   * - ``PACKAGE_LOCK_CONFLICT``
     - ``Could not get lock /var/lib/dpkg/lock-frontend`` или ``yum.pid``
     - Извлекает PID блокирующего процесса и формирует команды разблокировки (``fuser -v``, ``dpkg --configure -a``).
   * - ``SERVICE_CRASH``
     - ``Job for <unit>.service failed``, ``status=1/FAILURE``
     - Запрашивает ``journalctl -u <unit> -n 25`` и выполняет **каскадную реклассификацию** (например, автоматически уточняет категорию до ``PORT_CONFLICT`` или ``CONFIG_SYNTAX_ERROR`` по логам юнита!).
   * - ``CONFIG_SYNTAX_ERROR``
     - ``syntax error on line``, ``configtest failed``, ``nginx: [emerg]``
     - Извлекает путь к конфигурационному файлу с ошибкой и предлагает команду проверки синтаксиса.
   * - ``PERMISSION_DENIED``
     - ``Permission denied``, ``EACCES``, ``sudo: a password is required``
     - Проверяет текущего пользователя ``id -un``, права ``ls -ld <path>`` и статус SELinux ``getenforce``.
   * - ``COMMAND_NOT_FOUND``
     - ``exit_code == 127``, ``command not found``
     - Определяет имя отсутствующего бинарника и рекомендует установку через ``conn.state.ensure_package()``.
   * - ``NETWORK_UNREACHABLE``
     - ``Connection refused``, ``Name or service not known``, ``No route to host``
     - Предлагает команды проверки DNS (``/etc/resolv.conf``) и таблицы маршрутизации.

.. code-block:: python

   from uniconn import Connection

   async with Connection.from_uri("ssh://admin@node-01", auto_diagnostics=True) as conn:
       res = await conn.run("systemctl start nginx", sudo=True)
       if not res.ok and res.diagnostic:
           print("Категория сбоя:", res.diagnostic.category.value)
           print("Первопричина:", res.diagnostic.root_cause_hint)
           for step in res.diagnostic.suggested_actions:
               print(" -> Рекомендация:", step)

3. Включение отладочных логов и трассировки OpenTelemetry
---------------------------------------------------------

1. **Структурированное DEBUG-логирование (``structlog``)**:

   .. code-block:: python

      from uniconn import configure_logging, setup_file_logging

      # Включить подробный вывод всех событий пайплайна (command.start, command.retry, command.finish)
      configure_logging(level="DEBUG", json_format=False)

      # Или записать отладочный журнал в файл с автоматическим маскированием секретов
      setup_file_logging("/var/log/uniconn-debug.log", level="DEBUG")

2. **Сбор спанов трассировки в памяти (``InMemoryTracer`` и ``otel_tracing_hook``)**:

   .. code-block:: python

      from uniconn import Connection, InMemoryTracer, otel_tracing_hook

      tracer = InMemoryTracer()
      async with Connection.local() as conn:
          otel_tracing_hook(conn, tracer=tracer)
          await conn.run("uname -a")

      for span in tracer.spans:
          print(span.name, span.attributes, span.duration_ms)

4. Матрица решения частых проблем (Симптом → Причина → Решение)
---------------------------------------------------------------

4.1. Команда ``cd /some/dir`` не сохраняет директорию для следующего ``conn.run()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: Вызов ``await conn.run("cd /var/www")``, а затем ``await conn.run("pwd")`` выводит домашнюю директорию.
- **Причина**: Каждый ``conn.run()`` запускается в изолированном подпроцессе/канале, чтобы параллельные вызовы ``asyncio.gather()`` не ломали рабочую директорию друг друга.
- **Решение**: Используйте контекстный менеджер ``with conn.cd("/var/www"):`` (безопасен для корутин через ``ContextVar``) или откройте интерактивную PTY-сессию ``async with await conn.open_shell() as shell:``, где ``await shell.execute("cd /var/www")`` сохраняет состояние между вызовами.

4.2. Ошибка ``sudo: a password is required`` или зависание при запросе пароля
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: Команда с ``sudo=True`` завершается с кодом 1 и текстом ``sudo: a password is required``.
- **Причина**: На удалённом хосте для пользователя не настроен ``NOPASSWD: ALL``, а в ``uniconn`` не был передан пароль sudo, поэтому ``SudoMiddleware`` использовал неинтерактивный флаг ``sudo -n``.
- **Решение**: Передайте ``sudo_password="env://SUDO_PASS"`` в параметрах URI (``ssh://user@host?sudo_password=env://SUDO_PASS``), в секции ``options`` инвентаря или напрямую в ``conn.run("...", sudo=True, sudo_password=...)``. ``SudoMiddleware`` автоматически переключится на ``sudo -S -p ''`` и безопасно передаст пароль через ``stdin``.

4.3. Ошибка проверки SSH-ключа хоста (Host Key Verification) в CI или контейнерах
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: ``ConnectionError`` при установке SSH-соединения с новым облачным сервером или тестовым контейнером.
- **Причина**: Политика проверки ``known_hosts`` отклонила неизвестный или изменившийся ключ хоста.
- **Решение**: Укажите ``?known_hosts=accept_new`` (по умолчанию) или ``?known_hosts=none`` для временных тестовых окружений: ``ssh://root@172.17.0.2?known_hosts=none``.

4.4. ``CassetteMissError`` при воспроизведении кассет с атомарной записью файлов
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: При офлайн-тестировании ``conn.files.write_file(..., atomic=True)`` или ``conn.run_script()`` выбрасывается ``CassetteMissError`` из-за случайного суффикса временного файла ``/tmp/.uniconn-tmp-...``.
- **Причина**: Временные имена файлов генерируются случайно при каждом запуске.
- **Решение**: Убедитесь, что включена нормализация временных путей ``normalize_temp=True`` (включена по умолчанию в ``use_cassette()`` и ``replay://...?normalize_temp=true``). Посмотрите атрибут ``err.candidates`` у ``CassetteMissError``, чтобы увидеть список записанных в кассету команд.

4.5. ``BatchAbortedError`` и ``CircuitOpenError`` при раскатке по кластеру
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: ``ConnectionPool.map()`` прерывается с исключением ``BatchAbortedError``, либо повторные вызовы к узлу мгновенно падают с ``CircuitOpenError``.
- **Причина**: Доля упавших хостов в текущей волне превысила ``max_fail_ratio`` (или число подряд идущих сбоев сети достигло ``circuit_breaker_threshold``).
- **Решение**:
  - Перехватите ``BatchAbortedError`` и проверьте словари ``err.completed_results`` (успешные узлы) и ``err.failed_hosts`` (узлы, вызвавшие остановку на волне ``err.batch_index``).
  - Если нужно выполнить команду на всех узлах без прерывания и получить ошибки как значения словаря, используйте ``await pool.map_safe("cmd")``.
  - Для ручного сброса разомкнутого предохранителя вызовите ``conn.circuit_breaker.reset()``.

4.6. ``TransportNotFoundError`` или ``OptionalDependencyError``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Симптом**: При обращении к ``winrm://``, ``redfish://``, ``ipmi://``, ``uart://``, ``telnet://`` или парсерам ``jc``/``textfsm`` выбрасывается ``TransportNotFoundError`` или ``OptionalDependencyError``.
- **Причина**: Ядро ``uniconn`` не тянет тяжёлые специфичные библиотеки по умолчанию.
- **Решение**: Установите соответствующий extra-пакет:

  - ``winrm://`` / ``wsman://``: ``uv add "uniconn[winrm]"``
  - ``redfish://`` / ``ipmi://``: ``uv add "uniconn[bmc]"``
  - ``serial://`` / ``uart://``: ``uv add "uniconn[serial]"``
  - ``telnet://``: ``uv add "uniconn[telnet]"``
  - Парсеры ``jc`` / ``textfsm`` / ``ttp``: ``uv add "uniconn[parsing]"``
  - Все пакеты сразу: ``uv add "uniconn[all]"``
