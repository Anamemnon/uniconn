uniconn documentation
=====================

**uniconn** — универсальная async-first Python-библиотека (Python 3.11+) и CLI для
выполнения команд, инспекции хостов, идемпотентного управления состоянием, передачи
файлов и контрактного тестирования через различные транспорты: **SSH, Telnet,
Serial/UART, IPMI BMC, Redfish BMC, Docker, Podman, Kubernetes (kubectl), Replay и Local**.

.. image:: https://img.shields.io/badge/python-3.11+-blue.svg
   :target: https://www.python.org/downloads/
   :alt: Python 3.11+

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
   :alt: MIT License

Features
--------

- 🚀 **10 транспортов**: SSH, Telnet, Serial/UART, IPMI, Redfish, Docker, Podman, Kubectl, Replay, Local
- ⚡ **Async-first + Sync паритет**: ``Connection`` и ``SyncConnection`` через единый ``EventLoopPortal``
- 🧩 **Доменные сервисы**: ``conn.files``, ``conn.state``, ``conn.tunnels`` (и ``pool.files``, ``pool.state``)
- 🔒 **Безопасность**: ``SecretResolver`` (``env://``, ``file://``), ``SecretStr``, безопасный ``sudo``, ``sensitive=True``
- 🛡️ **Отказоустойчивость**: ``CircuitBreaker``, ``RateLimiter``, retry и волновой роллаут ``ConnectionPool`` (``batch_size``, ``max_fail_ratio``)
- 🔎 **Факты и идемпотентность**: ``gather_facts()``, ``diff_facts()`` и примитивы ``conn.state.ensure_*`` с unified diff
- 📁 **Файловый сервис**: ``atomic=True``, ``verify=True``, ``checksum()``, ``sync_dir()``, ``write_template()``
- 📼 **Кассеты и контрактные тесты**: ``use_cassette()``, ``cassette.diff()`` и ``pytest``-плагин ``@pytest.mark.uniconn_cassette``
- 🏥 **Ожидание и диагностика**: ``ping()``, ``is_alive()``, ``wait_for_connection()``, ``wait_for_port()``, ``wait_for_path()``

Quick Start
-----------

Установка::

    pip install uniconn
    # или полная установка со всеми транспортами и CLI:
    pip install "uniconn[all]"

Базовое использование::

    import asyncio
    from uniconn import Connection

    async def main():
        async with Connection.from_uri("ssh://admin:env://SSH_PASS@host") as conn:
            # Проверка доступности и измерение RTT
            ping = await conn.ping()
            if ping.alive:
                print(f"Host is alive ({ping.latency_ms:.1f} ms)")

            # Выполнение команды
            result = await conn.run(["uptime"])
            print(result.text)

            # Передача файла и смена прав через сервис conn.files
            await conn.files.upload("/local/config.yaml", "/etc/app/config.yaml", verify=True)
            await conn.files.chmod("/etc/app/config.yaml", 0o600)

            # Метаданные и контрольная сумма
            info = await conn.files.stat("/etc/app/config.yaml")
            digest = await conn.files.checksum("/etc/app/config.yaml")
            print(f"Size: {info['size']} bytes, SHA-256: {digest}")

            # Идемпотентное управление сервисом через conn.state
            await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

    asyncio.run(main())

Синхронный API::

    from uniconn import SyncConnection

    with SyncConnection.from_uri("ssh://user@host") as conn:
        result = conn.run("whoami")
        print(result.text)

Параллельное выполнение и батч-роллаут::

    import asyncio
    from uniconn import ConnectionPool

    async def main():
        hosts = ["ssh://node1", "ssh://node2", "ssh://node3"]
        async with ConnectionPool(hosts, max_concurrent=5, batch_size=2, max_fail_ratio=0.0) as pool:
            results = await pool.map("uptime")
            for res in results:
                print(f"{res.host}: {res.text}")

    asyncio.run(main())

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Documentation:

   api
   examples
   transports

.. toctree::
   :maxdepth: 1
   :caption: Links:

   GitHub <https://github.com/yourusername/uniconn>
   PyPI <https://pypi.org/project/uniconn>

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
