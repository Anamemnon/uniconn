Быстрый старт за 5 минут
========================

**Язык:** `English <../quickstart.rst>`_ | **[ Русский ]**

Это руководство поможет за 5 минут установить ``uniconn``, выбрать между **Async**, **Sync** и **CLI** режимами, выполнить первые команды (даже без внешнего сервера) и безопасно подключить секреты из окружения или инвентаря.

1. Установка и опциональные пакеты (Extras)
-------------------------------------------

Базовая установка включает ядро библиотеки (транспорты SSH, Local, Docker, Podman, Kubernetes ``kubectl``, NETCONF, RESTCONF, gNMI, Proxmox VE, QEMU Guest Agent, Replay-кассеты, конвейер отказоустойчивости и структурированное логирование):

.. code-block:: bash

   # Рекомендуемый способ через uv
   uv add uniconn

   # Или через pip
   pip install uniconn

Матрица дополнительных зависимостей (Extras)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Установите все возможности одной командой ``uv add "uniconn[all]"`` или выберите только нужные модули:

.. list-table::
   :widths: 18 35 47
   :header-rows: 1

   * - Extra
     - Команда установки
     - Что входит в состав
   * - **all**
     - ``uv add "uniconn[all]"``
     - Все транспорты, парсеры, шаблонизатор, телеметрия и CLI
   * - **cli**
     - ``uv add "uniconn[cli]"``
     - Модульный CLI (``cyclopts``, ``rich``): ``uniconn run``, ``flow``, ``mcp``, ``policy``
   * - **winrm**
     - ``uv add "uniconn[winrm]"``
     - Управление Windows (``winrm://``, ``wsman://`` на базе ``pywinrm``)
   * - **bmc**
     - ``uv add "uniconn[bmc]"``
     - Контроллеры IPMI (``pyghmi``) и DMTF Redfish HTTP/2 (``niquests``)
   * - **serial**
     - ``uv add "uniconn[serial]"``
     - Консоли Serial/UART (``pyserial-asyncio``) и прошивка по XMODEM/YMODEM/ZMODEM
   * - **telnet**
     - ``uv add "uniconn[telnet]"``
     - Транспорт RFC 854 Telnet с поддержкой IAC NAWS (``telnetlib3``)
   * - **parsing**
     - ``uv add "uniconn[parsing]"``
     - Семантические парсеры вывода (``jc``, ``textfsm``, ``ttp``, ``ntc-templates``)
   * - **templates**
     - ``uv add "uniconn[templates]"``
     - Движок шаблонов Jinja2 для ``conn.files.write_template()``
   * - **otel**
     - ``uv add "uniconn[otel]"``
     - Распределённая трассировка OpenTelemetry через ``otel_tracing_hook``

2. Песочница без настройки: пробуем ``uniconn`` на локальном хосте
------------------------------------------------------------------

Для знакомства с ``uniconn`` не нужен удалённый сервер — все доменные сервисы работают поверх ``Connection.local()`` (или встроенного ``MockSSHServer``):

.. code-block:: python

   import asyncio
   import os
   from uniconn import Connection

   async def main():
       async with Connection.local() as conn:
           # 1. Выполнение команды
           res = await conn.run("uname -a")
           print("Система:", res.text)

           # 2. Выполнение Python-функции через Zero-Fork RPC (< 2 мс)
           cpus = await conn.run_python(lambda: os.cpu_count())
           print("Ядер CPU:", cpus)

           # 3. Сбор структурированных фактов о хосте
           facts = await conn.gather_facts()
           print(f"ОС: {facts.os_family} ({facts.arch}), Ядро: {facts.kernel}")

   asyncio.run(main())

3. Выбор парадигмы: Async против Sync против CLI
------------------------------------------------

``uniconn`` обеспечивает **100% паритет API** между асинхронными и синхронными классами:

- **Асинхронный API (``Connection``, ``ConnectionPool``, ``Flow``)** — идеален для FastAPI/aiohttp сервисов, параллельного опроса десятков хостов и потокового чтения логов.
- **Синхронный API (``SyncConnection``, ``SyncConnectionPool``, ``SyncFlow``)** — идеален для административных скриптов, CLI-утилит и синхронных тестов ``pytest`` без ``asyncio.run()``.
- **Командная строка (``uniconn ...``)** — для быстрой диагностики из терминала, раскатки по инвентарю и запуска MCP-сервера для ИИ.

Асинхронный Python
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from uniconn import Connection

   async with Connection.from_uri("ssh://admin:env://SSH_PASS@web-01") as conn:
       disks = (await conn.run("df -h", parse="auto")).parsed
       await conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
       await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

Синхронный Python
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from uniconn import SyncConnection

   with SyncConnection.from_uri("ssh://admin:env://SSH_PASS@web-01") as conn:
       disks = conn.run("df -h", parse="auto").parsed
       conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
       conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

Интерфейс командной строки (CLI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Выполнение команды с автопарсингом и выводом в JSON
   uniconn run "ssh://admin:env://SSH_PASS@web-01" "df -h" --format json

   # Идемпотентная настройка systemd-службы
   uniconn ensure-unit nginx.service "ssh://admin@web-01" --state started --enabled --sudo

4. Динамические секреты и файлы инвентаря
-----------------------------------------

Не храните пароли в коде. ``uniconn`` автоматически разрешает ссылки ``env://`` и ``file://`` в URI и инвентарях (подробнее см. :doc:`inventory_and_uris`):

.. code-block:: python

   from uniconn import ConnectionPool

   # Чтение переменной окружения SSH_PASS с резервным значением 'devpass'
   uri = "ssh://deploy:env://SSH_PASS?default=devpass@10.0.0.10?key_file=file:///run/secrets/ssh_key"

   # Загрузка группы хостов из YAML-инвентаря с волновой раскаткой по 2 узла
   async with ConnectionPool.from_file("inventory.yaml", group="web", batch_size=2) as pool:
       pings = await pool.ping()
       for host, status in pings.items():
           print(f"{host}: alive={status.alive} ({status.latency_ms:.1f} мс)")
