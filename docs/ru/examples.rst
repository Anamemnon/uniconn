Каталог готовых сценариев (``examples/``)
==========================================

**Язык:** :doc:`English </examples>` | **[ Русский ]**

Все скрипты в директории ``examples/`` самодостаточны, не требуют живого внешнего оборудования для демонстрационного прогона ``main()`` и автоматически проверяются в наборе тестов CI (``uv run python examples/<script>.py``). Для пошаговых рецептов см. :doc:`cookbook`.

Сводная таблица сценариев
-------------------------

.. list-table::
   :widths: 28 36 36
   :header-rows: 1

   * - Сценарий
     - Ключевые возможности и API
     - Файл и страница
   * - Базовый старт (Async и Sync)
     - ``Connection.from_uri``, ``SyncConnection``, ``SecretResolver``, ``run``, ``stream``, ``copy``
     - :doc:`/examples/basic` (``basic_usage.py``)
   * - Инвентарь и эргономика ``Result``
     - ``from_file``, группы ``ConnectionPool``, ``Result`` хелперы
     - :doc:`/examples/inventory` (``ergonomics_and_inventory.py``)
   * - Файлы и дельта-синхронизация
     - ``conn.files``, ``conn.path``, ``atomic=True``, ``checksum``, ``sync_dir``, ``write_template``
     - :doc:`/examples/file_transfer` (``file_transfer.py``)
   * - Интерактивный PTY Shell и ``expect``
     - ``conn.open_shell``, ``shell.execute``, ``conn.expect``, ``SyncShellSession``
     - :doc:`/examples/shell` (``interactive_shell.py``)
   * - Проверки доступности и ожидания
     - ``ping``, ``is_alive``, ``wait_for_connection``, ``wait_for_port``, ``wait_for_path``
     - :doc:`/examples/health_check` (``health_check.py``)
   * - Параллелизм и волновой роллаут
     - ``ConnectionPool.map``, ``batch_size``, ``max_fail_ratio``, ``select``, ``pool.stream``
     - :doc:`/examples/parallel` (``parallel_execution.py``)
   * - Идемпотентный стейт, факты и стресс-диагностика
     - ``conn.state.ensure_*``, ``gather_facts``, ``diff_facts``, ``diagnostic_session``
     - :doc:`/examples/provisioning` (``provisioning_and_facts.py``, ``stress_test_diagnostics.py``, ``stress_test_diagnostics.yaml``)
   * - Отказоустойчивость, пулы и туннели
     - ``CircuitBreaker``, ``RateLimiter``, ``SSHSessionPool``, ``conn.tunnels``
     - :doc:`/examples/resilience` (``resilience_rollout_and_waiters.py``)
   * - Фоновый мониторинг и реактивный Watchdog
     - ``BackgroundPool``, ``tmux``/``screen``/``nohup``, ``PatternTriggerHandler``, ``LogWatchRule``
     - :doc:`/examples/background` (``screen_monitoring.py``, ``screen_pool_config.yaml``, ``reactive_log_watchdog_sct.py``, ``telecom_bs_sct_diagnostics.yaml``)
   * - Windows (``winrm://``) и Windows Provisioning
     - ``ensure_windows_service``, ``ensure_registry_key``, ``ensure_windows_feature``, ``SyncConnection``
     - :doc:`/examples/winrm` (``windows_winrm_management.py``)
   * - QEMU Guest Agent (``qga://``)
     - ``MockQgaServer``, ``backend=tcp`` (``127.0.0.1:port``), Named Pipe и UNIX-сокеты
     - :doc:`/examples/qemu_qga` (``qemu_guest_agent.py``)
   * - Сетевая автоматизация YANG
     - ``netconf://``, ``restconf://`` (SSE), ``gnmi://`` (HTTP/2 gRPC), ``conn.net``
     - :doc:`/examples/network_yang` (``network_yang_telemetry.py``)
   * - Bare-Metal BMC (Redfish и IPMI)
     - ``redfish://``, ``ipmi://``, питание, сенсоры, ``VirtualMedia``, ``SecureBoot``, ``raw``
     - :doc:`/examples/bmc` (``bmc_management.py``)
   * - Последовательный порт Serial / UART
     - ``serial://``, ``uart://``, Windows ``io_backend=threaded``, DTR/RTS/BREAK, XMODEM
     - :doc:`/examples/serial_uart` (``serial_uart_hardware.py``)
   * - Безопасность, хуки и OpenTelemetry
     - ``allowlist_hook``, ``blocklist_hook``, ``otel_tracing_hook``, ``configure_logging``
     - :doc:`/examples/security_telemetry` (``security_and_hooks.py``, ``structured_logging_telemetry.py``)
   * - Офлайн-кассеты и контрактные тесты
     - ``use_cassette``, ``pool.use_cassette``, ``cassette.diff``, pytest-плагин
     - :doc:`/examples/cassettes` (``contract_testing_cassettes.py``)
   * - Написание собственного транспорта
     - Наследование ``BaseTransport``, регистрация через ``entry_points``
     - :doc:`/examples/custom_transport` (``custom_transport.py``)
