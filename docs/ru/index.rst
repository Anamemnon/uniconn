Документация uniconn (На русском языке)
=======================================

**Язык:** `English <../index.rst>`_ | **[ Русский ]**

**uniconn** — универсальная async-first Python-библиотека (Python 3.11+) и модульный CLI для выполнения команд, сбора фактов о хостах, идемпотентного управления состоянием, DAG-оркестрации задач и дельта-синхронизации файлов поверх **16+ транспортных схем** со **100% паритетом Async + Sync API** и субмиллисекундным оверхедом ядра.

Почему uniconn?
---------------

Современная инфраструктура охватывает серверы Linux и Windows, контейнеры, поды Kubernetes, маршрутизаторы, гипервизоры и контроллеры BMC/UART. Вместо склеивания несовместимых библиотек (``Paramiko``, ``pywinrm``, ``docker-py``, ``Netmiko``, ``Ansible``) ``uniconn`` предоставляет единый отказоустойчивый фасад:

- **16+ схем транспортов**: ``ssh://``, ``winrm://`` (``wsman://``), ``docker://``, ``podman://``, ``kubectl://``, ``netconf://``, ``restconf://``, ``gnmi://``, ``pve://`` (Proxmox VE), ``qga://`` (QEMU Guest Agent), ``redfish://``, ``ipmi://``, ``serial://`` (``uart://``), ``telnet://``, ``replay://`` и ``local://``.
- **100% паритет Async + Sync**: Используйте ``Connection`` / ``ConnectionPool`` / ``Flow`` для высококонкурентных асинхронных сервисов или ``SyncConnection`` / ``SyncConnectionPool`` / ``SyncFlow`` для синхронных скриптов и тестов (через фоновый синглтон ``EventLoopPortal``).
- **Семантический автопарсинг и автодиагностика сбоев**: Превращайте вывод команд в словари или Pydantic-модели через ``conn.run("df -h", parse="auto")`` и автоматически находите первопричины сбоев (конфликты портов, переполнение диска, OOM killer) с флагом ``diagnose=True``.
- **Удалённый Python RPC без форков (Zero-Fork RPC)**: Выполняйте функции и ``lambda`` внутри постоянного фонового воркера на удалённом хосте за ``< 2 мс`` через ``conn.run_python(fn)``.
- **Объектно-ориентированная удалённая ФС и дельта-синхронизация**: Работайте с путями через ``conn.path("/var/log")`` (в стиле ``pathlib.Path`` с предзагрузкой ``stat()`` при ``glob()``) и синхронизируйте директории по хешам через ``conn.files.sync_dir()``.
- **Идемпотентное состояние и дедупликация обработчиков**: Управляйте пакетами, службами, файлами, пользователями, ``sysctl``, реестром/компонентами Windows и YANG-деревьями через ``conn.state.ensure_*`` с unified diff и ``batch_notifications()``.
- **Декларативная DAG-оркестрация задач**: Стройте графы зависимостей с помощью ``@task`` и ``Flow`` с поддержкой ``depends_on``, ``post``-очистки, условий ``when`` и барьерной раскатки ``mode="barrier"``.
- **Контрактное тестирование и встроенные Mock-серверы**: Записывайте и воспроизводите YAML-кассеты через ``use_cassette()`` или ``@pytest.mark.uniconn_cassette``, либо поднимайте ``MockSSHServer`` / ``MockNetconfServer`` в памяти без доступа к сети.
- **Встроенный MCP-сервер для ИИ-агентов, HITL и AST Policy Guardrails**: Безопасно подключайте инвентарь к ИИ-агентам через ``uniconn mcp`` с проверкой AST дерева команд (``CommandASTParser``), движком политик и подтверждениями оператора (HITL).

Шпаргалка «Задача → Решение за 10 секунд»
-----------------------------------------

.. list-table::
   :widths: 34 26 40
   :header-rows: 1

   * - Что нужно сделать?
     - API / Инструмент uniconn
     - Минимальный пример
   * - Выполнить команду и распарсить вывод в JSON/dict
     - ``conn.run(..., parse="auto")``
     - ``(await conn.run("df -h", parse="auto")).parsed``
   * - Написать синхронный скрипт без ``async/await``
     - ``SyncConnection``
     - ``with SyncConnection.from_uri("ssh://host") as c:``
   * - Выполнить Python-функцию на хосте за < 2 мс
     - ``conn.run_python(fn)``
     - ``await conn.run_python(lambda: os.uname().release)``
   * - Работать с удалёнными файлами как с ``pathlib.Path``
     - ``conn.path(remote_path)``
     - ``await conn.path("/etc/app.conf").write_text(cfg, atomic=True)``
   * - Синхронизировать директорию по дельте хешей (как ``rsync``)
     - ``conn.files.sync_dir()``
     - ``await conn.files.sync_dir("./dist", "/var/www", delete=True)``
   * - Идемпотентно настроить пакеты, службы, файлы или ключи
     - ``conn.state.ensure_*``
     - ``await conn.state.ensure_service("nginx", state="started", sudo=True)``
   * - Перезагрузить службу строго один раз после серии правок
     - ``conn.state.batch_notifications()``
     - ``async with conn.state.batch_notifications(): ...``
   * - Автоматически узнать причину падения команды или сервиса
     - ``conn.run(..., diagnose=True)``
     - ``res = await conn.run("systemctl start app", diagnose=True)``
   * - Выкатить изменения волнами с авто-остановкой при ошибке
     - ``ConnectionPool(..., batch_size=2)``
     - ``await pool.map("deploy.sh", batch_size=2, max_fail_ratio=0.0)``
   * - Запустить многошаговый DAG-пайплайн с зависимостями
     - ``@task`` + ``Flow``
     - ``await pool.run_flow(deploy_flow, vars={"version": "1.4.2"})``
   * - Сравнить характеристики серверов кластера и найти дрейф
     - ``pool.diff_facts()``
     - ``drift = await pool.diff_facts()``
   * - Протестировать код офлайн в CI по записанным кассетам
     - ``@pytest.mark.uniconn_cassette``
     - Декоратор теста или ``async with conn.use_cassette(...)``
   * - Проверить команду против обфускации и политик безопасности
     - ``CommandASTParser`` & ``PolicyEngine``
     - ``uniconn policy eval "systemctl restart db" --preset prod-guard``

Выберите точку старта по вашей роли
-----------------------------------

- **Системный администратор Linux / Windows и DevOps**: Начните с :doc:`quickstart`, изучите рецепты в :doc:`cookbook` и полный справочник инвентаря в :doc:`inventory_and_uris`.
- **Разработчик Python и Архитектор**: Изучите внутреннее устройство ``CommandPipeline``, порядок мидлварей и ``EventLoopPortal`` в :doc:`architecture`.
- **Сетевой инженер (NETCONF / RESTCONF / gNMI)**: Посмотрите примеры ``conn.net.get``, ``conn.state.ensure_yang`` и парсинга ``textfsm`` / ``ttp`` в :doc:`cookbook` и параметры схем в :doc:`inventory_and_uris`.
- **Инженер по отладке, QA / SDET**: Изучите дерево исключений ``UniconnError``, автодиагностику ``diagnose=True`` и решение частых проблем в :doc:`troubleshooting`.

Содержание русскоязычной документации
-------------------------------------

.. toctree::
   :maxdepth: 2
   :caption: Руководства и архитектура (RU):

   quickstart
   architecture
   inventory_and_uris
   cookbook
   troubleshooting

.. toctree::
   :maxdepth: 1
   :caption: Справочники на английском (EN):

   English Documentation Hub <../index>
   Migration Guides (Ansible/Fabric/Paramiko) <../migration>
   CLI, MCP Server & Security Guardrails <../cli_and_mcp>
   API Reference <../api>
