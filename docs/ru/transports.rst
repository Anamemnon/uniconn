Обзор транспортов и разрешение секретов (13+ схем)
===================================================

**Язык:** :doc:`English </transports>` | **[ Русский ]**

Каждое подключение в ``uniconn`` задаётся единой URI-схемой или объектом ``ConnectionConfig``. Все транспорты поддерживают динамическое разрешение секретов через ``SecretResolver``. Полные схемы YAML/TOML/JSON инвентаря и таблицы параметров приведены в :doc:`inventory_and_uris`, а запускаемые скрипты — в :doc:`examples`.

Динамическое разрешение секретов (``env://`` и ``file://``)
-----------------------------------------------------------

Пароли, пути к SSH-ключам, парольные фразы, токены Proxmox API и пароли ``sudo`` в URI и инвентарях поддерживают ``env://VAR_NAME[?default=fallback]`` и ``file:///path/to/secret[?default=fallback]``. Отсутствующие секреты без ``?default=`` вызывают ``ConfigurationError`` до открытия сетевого сокета:

.. code-block:: python

   from uniconn import Connection

   conn = Connection.from_uri(
       "ssh://admin:env://SSH_PASS?default=fallback@node-01:22"
       "?key_file=file:///run/secrets/id_ed25519"
   )

Матрица транспортных схем
-------------------------

1. SSH (``ssh://``)
~~~~~~~~~~~~~~~~~~~

Полнофункциональный SSHv2-транспорт (``asyncssh``) с SFTP, интерактивным PTY, цепочками jump-хостов, парсингом ``~/.ssh/config`` и пробросом портов.

- **Формат URI**: ``ssh://[user[:password]@]host[:22][?option=value]``
- **Основные опции**: ``key_file``, ``passphrase``, ``known_hosts=strict|accept_new|none``, ``keepalive=30``, ``ssh_config=true``, ``use_agent=true``, ``proxy=bastion1,bastion2``, ``proxy_command=...``, ``rate_limit=10``, ``circuit_breaker_threshold=5``, ``auto_diagnostics=true``.

.. code-block:: python

   conn = Connection.from_uri("ssh://deploy@prod-web-01?key_file=~/.ssh/id_ed25519&proxy=bastion.internal")

2. Windows Remote Management (``winrm://`` / ``wsman://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Безагентное управление узлами Windows через PowerShell Remoting и CMD, передача файлов, сбор фактов и нативные примитивы состояния Windows.

- **Формат URI**: ``winrm://[user[:password]@]windows-host[:5985|5986][?option=value]``
- **Основные опции**: ``transport=ntlm|kerberos|credssp|basic|ssl``, ``ssl=true|false``, ``server_cert_validation=ignore|validate``, ``shell=ps|cmd``, ``domain=CORP``.

.. code-block:: python

   conn = Connection.from_uri("winrm://Administrator:env://WIN_PASS@win-srv-01:5986?ssl=true&transport=ntlm&shell=ps")

См. готовый сценарий :doc:`/examples/winrm` (``windows_winrm_management.py``).

3. Сетевые YANG-протоколы (``netconf://``, ``restconf://``, ``gnmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Модельное управление сетевым оборудованием через ``conn.net.get()``, ``conn.net.edit()``, ``conn.net.rpc()``, ``conn.net.subscribe()`` и идемпотентный ``conn.state.ensure_yang()`` с блокировками candidate и unified diff:

- **NETCONF (RFC 6241 поверх SSH)**: ``netconf://[user[:password]@]host[:830][?vendor=default|junos|iosxr|iosxe|eos|sros|huawei&version=1.1|1.0&verify_host_key=false]``
- **RESTCONF (RFC 8040 HTTP/HTTPS + SSE)**: ``restconf://[user[:password]@]host[:443][/restconf][?scheme=https|http&root=auto|/restconf&verify_tls=false&format=json|xml&subscribe_mode=auto|polling]``
- **gNMI (HTTP/2 gRPC поверх ``jh2``)**: ``gnmi://[user[:password]@]host[:9339][?tls=true|false&insecure=true|false&encoding=json_ietf|json|proto&origin=openconfig&target=...]``

См. запускаемый сценарий :doc:`/examples/network_yang` (``network_yang_telemetry.py``).

4. Виртуализация и эмуляторы (``pve://``, ``qga://`` / ``qemu-ga://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Выполнение команд и работа с файлами внутри ВМ и локальных эмуляторов QEMU без сети внутри гостевой ОС:

- **Proxmox VE API + Guest Agent (``pve://``)**: ``pve://[user[@realm][!token_id][:password]@]pve-host[:8006]/<vmid>[?node=pve1&verify_ssl=false&chunk_size=49152]``
- **QEMU Guest Agent (``qga://`` / ``qemu-ga://``)**: поддержка POSIX UNIX-сокетов (``qga:///var/lib/libvirt/.../org.qemu.guest_agent.0``), каналов SSH/``virsh``, TCP-сокетов (``qga://127.0.0.1:4444?backend=tcp``) и Windows Named Pipe (``qga://?backend=pipe&pipe=\\.\pipe\qga-vm1``).

См. запускаемый сценарий :doc:`/examples/qemu_qga` (``qemu_guest_agent.py``).

5. Контроллеры Bare-Metal BMC (``redfish://``, ``ipmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Внеполосное управление питанием, чтение сенсоров, аудит журнала событий (SEL), Virtual Media, UEFI SecureBoot и настройка загрузки PXE:

- **DMTF Redfish HTTP/2**: ``redfish://[user[:password]@]bmc-host[:443][?verify_ssl=false&system_id=1&multiplexed=true&sse_uri=...]``
- **IPMI v2.0 LAN+**: ``ipmi://[user[:password]@]bmc-host[:623][?reuse_session=true|false]``
- **Команды**: ``power on|off|cycle|reset|shutdown|status``, ``sensors`` / ``health``, ``sel list|clear``, ``events``, ``boot pxe|disk|bios|cdrom [once|continuous] [uefi|legacy]``, ``virtual_media status|mount|unmount``, ``boot secureboot status|on|off``, ``raw <netfn> <cmd>``.

См. запускаемый сценарий :doc:`/examples/bmc` (``bmc_management.py``).

6. Последовательные порты Serial / UART (``serial://``, ``uart://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Кроссплатформенная работа с RS-232 / UART (``pyserial-asyncio`` на POSIX и thread-backed адаптер ``io_backend=auto|threaded`` для ``ProactorEventLoop`` на Windows): управление DTR/RTS/BREAK, автопоиск по VID/PID, двоичный обмен и загрузка прошивок по XMODEM/YMODEM/ZMODEM.

- **Формат URI**: ``uart:///dev/ttyUSB0:115200[?parity=N&stopbits=1]`` или ``uart://COM3:115200[?vid=10c4&pid=ea60&io_backend=auto]``

См. запускаемый сценарий :doc:`/examples/serial_uart` (``serial_uart_hardware.py``).

7. Telnet (``telnet://``), Replay-кассеты (``replay://``) и Local (``local://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Telnet**: ``telnet://[user[:password]@]switch.local[:23][?term_type=vt100&shell_mode=auto|posix|cli&profile=generic|cisco|junos|linux|uboot&pagination=true]``
- **Replay (контрактное тестирование)**: ``replay://node-01[?cassette=tests/cassettes/node.yaml&mode=none&normalize_temp=true]`` (см. :doc:`/examples/cassettes`)
- **Local Subprocess / PTY**: ``local://[?timeout=30&rate_limit=50]`` (или ``Connection.local()``)

Для разработки сторонних транспортных плагинов (подключаемых через ``entry_points`` группы ``uniconn.transports``) см. :doc:`/examples/custom_transport`.
