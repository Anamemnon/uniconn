Полный справочник схем инвентаря (YAML/TOML/JSON) и параметров URI
==================================================================

**Язык:** `English <../inventory_and_uris.rst>`_ | **[ Русский ]**

Этот справочник содержит полное описание всех поддерживаемых форматов инвентаря (``.yaml`` / ``.yml``, ``.toml``, ``.json``), правил приоритета при слиянии полей в ``InventoryLoader``, динамических ссылок на секреты (``env://`` и ``file://``), глобальных параметров ``ConnectionConfig`` и всех **16+ схем транспортных URI**.

1. Форматы и схемы файлов инвентаря
-----------------------------------

Методы ``Connection.from_file()``, ``Connection.from_inventory()``, ``ConnectionPool.from_file()``, ``SyncConnectionPool.from_file()`` и флаги CLI ``--inventory`` используют единый парсер ``InventoryLoader``.

4 поддерживаемые структуры инвентаря
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``InventoryLoader.parse_data()`` поддерживает четыре формата записи в YAML, TOML и JSON:

1. **Каноническая структурированная схема (Рекомендуется)**: Словарь с секциями ``defaults`` (общие настройки по умолчанию), ``groups`` (словарь групп со списками хостов) и ``hosts`` (словарь алиасов хостов или список).
2. **Короткая карта алиасов**: Словарь верхнего уровня ``{алиас: "uri://..."}`` или ``{алиас: {transport: ...}}`` без обёртки ``hosts:``.
3. **Плоский список хостов**: Список URI-строк или словарей ``["ssh://node-01", {"uri": "ssh://node-02", "groups": ["web"]}]``.
4. **Одиночный объект подключения**: Одиночный словарь с ключом ``transport`` или ``uri``.

Примеры одного и того же инвентаря в YAML, TOML и JSON
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**YAML (``inventory.yaml``)**:

.. code-block:: yaml

   defaults:
     timeout: 30.0
     retry_attempts: 3
     auto_diagnostics: true
     options:
       keepalive: 30
       known_hosts: accept_new

   groups:
     web:
       - web-01
       - web-02
     prod:
       - web-01
       - web-02
       - db-01

   hosts:
     # 1. Короткая запись через URI (наследует defaults, получает name="web-01")
     web-01: "ssh://deploy:env://SSH_PASS?default=devpass@10.0.1.10:22"

     # 2. Полная словарная запись с переопределением опций и групп
     web-02:
       transport: ssh
       host: 10.0.1.11
       port: 22
       username: deploy
       key_file: "file:///run/secrets/id_ed25519_path?default=~/.ssh/id_ed25519"
       groups: ["web", "canary"]
       options:
         rate_limit: 20
         circuit_breaker_threshold: 5

     # 3. Узел базы данных с отдельным паролем sudo
     db-01:
       uri: "ssh://postgres@10.0.2.50:22?sudo_password=env://DB_SUDO_PASS"
       groups: ["db"]

**TOML (``inventory.toml``)**:

.. code-block:: toml

   [defaults]
   timeout = 30.0
   retry_attempts = 3
   auto_diagnostics = true

   [defaults.options]
   keepalive = 30
   known_hosts = "accept_new"

   [groups]
   web = ["web-01", "web-02"]
   prod = ["web-01", "web-02", "db-01"]

   [hosts]
   web-01 = "ssh://deploy:env://SSH_PASS?default=devpass@10.0.1.10:22"

   [hosts.web-02]
   transport = "ssh"
   host = "10.0.1.11"
   port = 22
   username = "deploy"
   groups = ["web", "canary"]

   [hosts.db-01]
   uri = "ssh://postgres@10.0.2.50:22"
   groups = ["db"]

**JSON (``inventory.json``)**:

.. code-block:: json

   {
     "defaults": {
       "timeout": 30.0,
       "retry_attempts": 3,
       "auto_diagnostics": true
     },
     "groups": {
       "web": ["web-01", "web-02"]
     },
     "hosts": {
       "web-01": "ssh://deploy:env://SSH_PASS?default=devpass@10.0.1.10:22",
       "web-02": {
         "transport": "ssh",
         "host": "10.0.1.11",
         "username": "deploy",
         "groups": ["web", "canary"]
       }
     }
   }

Правила приоритета слияния и разрешения групп
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   ┌────────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
   │  1. Секция defaults    │ ──► │   2. Поля хоста hosts  │ ──► │ 3. Аргументы вызова    │
   │  (defaults: {...})     │     │ (hosts.<alias>: {...}) │     │ (from_file(dry_run=..))│
   └────────────────────────┘     └────────────────────────┘     └────────────────────────┘
                                               │
                                               ▼
                        ┌──────────────────────────────────────────────┐
                        │ 4. SecretResolver (env:// и file://)         │
                        │    Разрешает секреты во всех строках и полях │
                        └──────────────────────────────────────────────┘

1. **Наследование ``defaults``**: Каждая запись в ``hosts`` получает копию полей из ``defaults``, после чего индивидуальные поля хоста перекрывают значения по умолчанию. Если в словарной записи не указаны ``name`` или ``host``, им автоматически присваивается имя ключа (алиаса).
2. **Двустороннее объединение групп**: Хост считается участником группы ``G``, если он перечислен в верхней секции ``groups: {G: [...]}`` **ИЛИ** если внутри самого хоста указано поле ``groups: ["G"]`` (оба списка объединяются без дубликатов).
3. **Фильтрация по ``group=`` и ``host=``**:
   - При передаче ``group="web"`` отбираются только участники группы ``web`` (если группа не найдена — выбрасывается ``KeyError``).
   - При передаче ``host="web-01"`` выбирается конкретный узел по совпадению ``name`` или ``host``.

2. Динамическое разрешение секретов (``SecretResolver``)
--------------------------------------------------------

``uniconn`` автоматически разрешает ссылки ``env://`` и ``file://`` во всех строках URI и словарях инвентаря **до** открытия сетевых сокетов:

.. list-table::
   :widths: 35 65
   :header-rows: 1

   * - Синтаксис секрета
     - Поведение и гарантии безопасности
   * - ``env://VAR_NAME``
     - Считывает ``os.environ["VAR_NAME"]``. Если переменная не задана или пуста — выбрасывает ``ConfigurationError``.
   * - ``env://VAR_NAME?default=fallback``
     - Считывает ``os.environ["VAR_NAME"]`` или подставляет ``"fallback"``, если переменная отсутствует.
   * - ``file:///abs/path/to/secret``
     - Читает содержимое файла и обрезает завершающие переводы строк ``\r\n``. При отсутствии файла выбрасывает ``ConfigurationError``.
   * - ``file://relative/secret?default=val``
     - Читает относительный путь (при указании ``base_dir`` блокирует выход за пределы директории через ``../``) или возвращает ``"val"``.

.. note::

   Все разрешённые пароли сохраняются внутри ``ConnectionConfig`` как ``pydantic.SecretStr``. В свойстве ``conn.config.uri_safe``, в структурных логах (``SecretMaskingFilter``) и кассетах они автоматически заменяются на ``***REDACTED***``.

3. Глобальные параметры ``ConnectionConfig`` и пайплайна
--------------------------------------------------------

Следующие параметры можно передать в query-строке **любого** URI (например, ``?timeout=60&auto_diagnostics=true``), в словаре инвентаря или в аргументах ``Connection.from_uri()``:

.. list-table::
   :widths: 26 16 14 44
   :header-rows: 1

   * - Параметр
     - Тип
     - По умолч.
     - Описание
   * - ``timeout``
     - ``float``
     - ``30.0``
     - Таймаут подключения и выполнения команд в секундах.
   * - ``retry_attempts``
     - ``int``
     - ``3``
     - Число попыток в ``RetryMiddleware`` при сетевых ошибках и таймаутах (``1`` отключает повторы).
   * - ``rate_limit``
     - ``float``
     - ``None``
     - Максимальное число команд в секунду на соединение (Token Bucket ``RateLimiter``).
   * - ``circuit_breaker_threshold``
     - ``int``
     - ``None``
     - Число подряд идущих сбоев сети до размыкания цепи ``CircuitBreaker`` в состояние ``OPEN``.
   * - ``circuit_breaker_timeout``
     - ``float``
     - ``30.0``
     - Время ожидания в секундах перед переходом размыкателя из ``OPEN`` в ``HALF_OPEN``.
   * - ``auto_diagnostics``
     - ``bool``
     - ``False``
     - Автоматический запуск зондов самодиагностики при ненулевом коде возврата любой команды.
   * - ``dry_run``
     - ``bool``
     - ``False``
     - Симуляция выполнения команд в ``DryRunMiddleware`` и расчёт unified diff без модификации хоста.
   * - ``sudo_password``
     - ``SecretStr | str``
     - ``None``
     - Пароль для ``sudo -S`` при ``sudo=True`` (по умолчанию берётся основной ``password`` подключения).
   * - ``is_production``
     - ``bool``
     - ``False``
     - Помечает узел как продакшен-окружение для ``HITLApprovalMiddleware`` и ``PolicyGuardrailMiddleware``.

4. Справочник параметров всех 16+ схем транспортов
--------------------------------------------------

4.1. SSH (``ssh://``)
~~~~~~~~~~~~~~~~~~~~~

- **Формат URI**: ``ssh://[user[:password]@]host[:22][?option=value]``
- **Зависимости**: Входит в базовое ядро ``uniconn``.

.. list-table::
   :widths: 25 18 57
   :header-rows: 1

   * - Параметр URI / опция
     - По умолч.
     - Описание
   * - ``key_file``
     - ``None``
     - Путь к приватному ключу SSH (поддерживает ``~/.ssh/...`` и ``file://``).
   * - ``passphrase``
     - ``None``
     - Парольная фраза приватного ключа (поддерживает ``env://`` и ``file://``).
   * - ``known_hosts``
     - ``"accept_new"``
     - Политика проверки ключей хоста: ``strict``, ``accept_new``, ``none`` (или путь к файлу).
   * - ``keepalive``
     - ``30``
     - Интервал отправки SSH keepalive-пакетов в секундах.
   * - ``ssh_config``
     - ``None``
     - ``true`` для чтения ``~/.ssh/config`` или путь к кастомному файлу конфигурации OpenSSH.
   * - ``use_agent``
     - ``True``
     - Использовать ли локальный ``ssh-agent`` при аутентификации.
   * - ``proxy``
     - ``None``
     - Цепочка jump-хостов через запятую (например, ``proxy=bastion1,bastion2``).
   * - ``proxy_command``
     - ``None``
     - Команда проксирования ``ProxyCommand`` (например, ``ssh -W %h:%p bastion``).
   * - ``system_ssh``
     - ``False``
     - Использовать системный бинарник ``ssh`` / ``scp`` вместо ``asyncssh``.

4.2. Windows Remote Management (``winrm://``, ``wsman://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Формат URI**: ``winrm://[user[:password]@]host[:5985|5986][?option=value]``
- **Установка**: ``uv add "uniconn[winrm]"``

.. list-table::
   :widths: 28 18 54
   :header-rows: 1

   * - Параметр URI / опция
     - По умолч.
     - Описание
   * - ``transport``
     - ``"ntlm"``
     - Протокол аутентификации: ``ntlm``, ``kerberos``, ``credssp``, ``basic`` или ``ssl``.
   * - ``ssl``
     - ``False``
     - Использовать HTTPS (автоматически переключает порт по умолчанию с ``5985`` на ``5986``).
   * - ``server_cert_validation``
     - ``"ignore"``
     - Проверка TLS-сертификата сервера: ``ignore`` или ``validate``.
   * - ``shell``
     - ``"ps"``
     - Оболочка по умолчанию: ``ps`` (PowerShell) или ``cmd`` (классический ``cmd.exe``).
   * - ``domain``
     - ``None``
     - Домен Active Directory / NTLM (например, ``CORP``).
   * - ``read_timeout_sec``
     - ``40``
     - Таймаут чтения HTTP-ответа WinRM в секундах.
   * - ``operation_timeout_sec``
     - ``30``
     - Таймаут операции WS-Management в секундах.

4.3. Сетевые протоколы YANG (``netconf://``, ``restconf://``, ``gnmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **NETCONF**: ``netconf://[user[:password]@]host[:830][?vendor=default&version=1.1]``
- **RESTCONF**: ``restconf://[user[:password]@]host[:443][/restconf][?scheme=https&format=json]``
- **gNMI**: ``gnmi://[user[:password]@]host[:9339][?encoding=json_ietf&origin=openconfig]``

.. list-table::
   :widths: 22 18 16 44
   :header-rows: 1

   * - Параметр
     - Транспорт
     - По умолч.
     - Описание
   * - ``vendor``
     - ``netconf``
     - ``"default"``
     - Профиль оборудования: ``default``, ``junos``, ``iosxr``, ``iosxe``, ``eos``, ``sros``, ``huawei``.
   * - ``version``
     - ``netconf``
     - ``"1.1"``
     - Версия фрейминга NETCONF: ``"1.1"`` (chunked) или ``"1.0"`` (``]]>]]>``).
   * - ``verify_host_key``
     - ``netconf``
     - ``False``
     - Строгая проверка SSH-ключа маршрутизатора на порту 830.
   * - ``root``
     - ``restconf``
     - ``"/restconf"``
     - Корневой путь RESTCONF API (или ``auto`` для автообнаружения через ``host-meta``).
   * - ``format``
     - ``restconf``
     - ``"json"``
     - Формат обмена данными YANG: ``json`` или ``xml``.
   * - ``verify_tls``
     - ``restconf``
     - ``False``
     - Проверять ли TLS-сертификат HTTPS-устройства.
   * - ``encoding``
     - ``gnmi``
     - ``"json_ietf"``
     - Кодировка gNMI: ``json_ietf``, ``json``, ``bytes``, ``proto``, ``ascii``.
   * - ``origin``
     - ``gnmi``
     - ``None``
     - Префикс YANG-модели по умолчанию (например, ``openconfig``, ``ietf``).
   * - ``insecure``
     - ``gnmi``
     - ``False``
     - Использовать незашифрованный канал gRPC или отключить валидацию сертификата.

4.4. Виртуализация и гипервизоры (``pve://``, ``qga://``, ``qemu-ga://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Proxmox VE**: ``pve://[user[@realm][!token_id][:secret]@]host[:8006]/<vmid>[?node=pve1&verify_ssl=false]``
- **QEMU Guest Agent**: ``qga:///path/to/qga.sock`` или ``qga://[user@]kvm-host[:22]/<vm_name>[?backend=socket|virsh]``

.. list-table::
   :widths: 24 16 16 44
   :header-rows: 1

   * - Параметр
     - Транспорт
     - По умолч.
     - Описание
   * - ``vmid``
     - ``pve``
     - Из пути ``/<vmid>``
     - Числовой идентификатор ВМ в Proxmox (например, ``105``).
   * - ``node``
     - ``pve``
     - Автопоиск
     - Имя ноды кластера Proxmox (например, ``pve1``); определяется автоматически, если не задано.
   * - ``realm``
     - ``pve``
     - ``"pam"``
     - Домен аутентификации (``pam``, ``pve`` или корпоративный LDAP/OIDC).
   * - ``token_id`` и ``secret``
     - ``pve``
     - ``None``
     - Имя API-токена и его секретный UUID (рекомендуется для автоматизации вместо пароля).
   * - ``backend``
     - ``qga``
     - ``"socket"``
     - Канал связи с агентом: ``socket`` (Unix-сокет локально или по SSH) или ``virsh`` (``virsh qemu-agent-command``).
   * - ``socket``
     - ``qga``
     - ``None``
     - Явный путь к Unix-сокету гостевого агента.
   * - ``libvirt_uri``
     - ``qga``
     - ``"qemu:///system"``
     - URI гипервизора для вызова ``virsh -c`` при ``backend=virsh``.

4.5. Контейнеры и Kubernetes (``docker://``, ``podman://``, ``kubectl://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Docker / Podman**: ``docker://[user@]container_name[/workdir][?shell=/bin/sh]``
- **Kubernetes**: ``kubectl://[namespace/]pod_name[?container=app&context=prod&kubeconfig=/path]``

.. list-table::
   :widths: 24 20 16 40
   :header-rows: 1

   * - Параметр
     - Транспорт
     - По умолч.
     - Описание
   * - ``workdir``
     - ``docker``, ``podman``, ``kubectl``
     - Дефолт образа
     - Рабочая директория внутри контейнера или пода.
   * - ``shell``
     - ``docker``, ``podman``, ``kubectl``
     - ``"/bin/sh"``
     - Оболочка для запуска строковых команд.
   * - ``namespace``
     - ``kubectl``
     - ``"default"``
     - Пространство имён Kubernetes (также задаётся в пути ``kubectl://ns/pod``).
   * - ``container``
     - ``kubectl``
     - Основной контейнер
     - Имя целевого контейнера внутри мультиконтейнерного пода (``kubectl exec -c``).
   * - ``context``
     - ``docker``, ``kubectl``
     - Текущий контекст
     - Имя контекста Docker CLI или кластера в ``kubeconfig``.
   * - ``kubeconfig``
     - ``kubectl``
     - ``~/.kube/config``
     - Путь к файлу конфигурации Kubernetes.

4.6. Контроллеры BMC, Serial/UART, Telnet, Replay и Local
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 20 34 46
   :header-rows: 1

   * - Схема
     - Пример URI
     - Ключевые query-параметры
   * - ``redfish://``
     - ``redfish://admin:env://PASS@bmc:443``
     - ``verify_ssl=false``, ``system_id=1``, ``chassis_id=1``, ``manager_id=1``, ``multiplexed=true`` (HTTP/2). Требует ``uniconn[bmc]``.
   * - ``ipmi://``
     - ``ipmi://admin:env://PASS@bmc:623``
     - Команды: ``power on|off|cycle|reset|status``, ``sensors``, ``sel list|clear``, ``boot pxe|disk|bios``, ``raw``. Требует ``uniconn[bmc]``.
   * - ``serial://`` / ``uart://``
     - ``uart:///dev/ttyUSB0:115200``
     - ``baudrate=115200``, ``parity=N|E|O``, ``stopbits=1|2``, ``bytesize=8``, ``vid=10c4``, ``pid=ea60``. Требует ``uniconn[serial]``.
   * - ``telnet://``
     - ``telnet://admin:pass@switch:23``
     - ``term_type=vt100``, ``login_prompt=login:``, ``password_prompt=Password:``, ``prompt=#``. Требует ``uniconn[telnet]``.
   * - ``replay://``
     - ``replay://node-01?cassette=test.yaml``
     - ``cassette=/path.yaml``, ``mode=none|once|new_episodes|all``, ``normalize_temp=true``.
   * - ``local://``
     - ``local://?timeout=30&rate_limit=50``
     - Локальное выполнение команд (эквивалентно ``Connection.local()``).
