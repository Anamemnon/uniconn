uniconn documentation
=====================

**uniconn** — универсальная Python-библиотека для выполнения команд на удалённых
хостах через различные транспорты: SSH, Telnet, Serial, IPMI и локальное
выполнение.

.. image:: https://img.shields.io/badge/python-3.11+-blue.svg
   :target: https://www.python.org/downloads/
   :alt: Python 3.11+

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
   :alt: MIT License

Features
--------

- 🚀 **5 транспортов**: SSH, Telnet, Serial, Local, IPMI
- ⚡ **Async-first**: asyncio с синхронной обёрткой
- 🔌 **Плагины**: динамическая загрузка через entry-points
- 🔒 **Безопасность**: маскирование секретов, known_hosts
- 🔄 **Retry**: exponential backoff с настраиваемыми попытками
- 📊 **ConnectionPool**: параллельное выполнение на множестве хостов
- 📁 **SFTP**: upload/download, chmod, stat, listdir, recursive transfer
- 🏥 **Health check**: ``is_alive()`` / ``ping()`` для всех транспортов

Quick Start
-----------

Установка::

    pip install uniconn[ssh]

Базовое использование::

    import asyncio
    from uniconn import Connection

    async def main():
        async with Connection.from_uri("ssh://user:pass@host") as conn:
            # Проверка подключения
            if await conn.is_alive():
                print("Host is alive!")

            # Выполнение команды
            result = await conn.run("uptime")
            print(result.stdout)

            # Передача файла
            await conn.upload("/local/config.yaml", "/etc/app/config.yaml")

            # Смена прав
            await conn.chmod("/etc/app/config.yaml", 0o600)

            # Информация о файле
            info = await conn.stat("/etc/app/config.yaml")
            print(f"Size: {info['size']} bytes")

    asyncio.run(main())

Синхронный API::

    from uniconn import Connection

    with Connection.from_uri("ssh://user@host").to_sync() as conn:
        result = conn.run("whoami")
        print(result.stdout)

Параллельное выполнение::

    import asyncio
    from uniconn import ConnectionPool

    async def main():
        hosts = ["ssh://node1", "ssh://node2", "ssh://node3"]
        pool = ConnectionPool(hosts, max_concurrent=5)
        results = await pool.map("uptime")

        for host, result in zip(hosts, results):
            print(f"{host}: {result.stdout.strip()}")

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
