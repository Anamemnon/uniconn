Пошаговая кулинарная книга (Рецепты по задачам)
===============================================

**Язык:** `English <../cookbook.rst>`_ | **[ Русский ]**

В этом разделе собраны готовые к копированию боевые рецепты, сгруппированные по инженерным задачам. Каждый рецепт одинаково работает как с асинхронным ``Connection``, так и с синхронным ``SyncConnection``.

1. Выполнение команд, автопарсинг и автодиагностика сбоев
---------------------------------------------------------

Семантический парсинг вывода в JSON или Pydantic-модели
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Передайте ``parse="auto"`` (или явный движок ``"jc:df"``, ``"textfsm:..."``, ``"ttp:..."``, либо класс ``pydantic.BaseModel``), чтобы превратить сырой вывод терминала в типизированные структуры данных:

.. code-block:: python

   from pydantic import BaseModel
   from uniconn import Connection

   class MountEntry(BaseModel):
       filesystem: str
       mounted_on: str
       use_percent: int | None = None

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       # 1. Автоматическое распознавание формата (builtin / JSON / JC)
       res = await conn.run("df -h", parse="auto")
       for row in res.parsed:
           print(row)

       # 2. Прямая валидация вывода в список Pydantic-моделей
       typed = await conn.run("df -h", parse=list[MountEntry])
       print(typed.parsed[0].mounted_on)

Автодиагностика причин падения команд (``diagnose=True``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Если команда завершилась с ненулевым кодом, флаг ``diagnose=True`` (или ``auto_diagnostics=True`` на соединении) автоматически проверит конфликты портов, место на диске, OOM killer и логи ``journalctl``:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01", auto_diagnostics=True) as conn:
       res = await conn.run("systemctl start nginx", sudo=True, diagnose=True)
       if not res.ok and res.diagnostic:
           diag = res.diagnostic
           print(f"Категория: {diag.category.value}")
           print(f"Первопричина: {diag.root_cause_hint}")
           print(f"Рекомендации: {diag.suggested_actions}")
           if diag.port_conflict:
               print(f"Порт {diag.port_conflict.port} занят PID {diag.port_conflict.conflicting_pid}")

2. Удалённый Python RPC без форков (``conn.run_python``)
--------------------------------------------------------

Выполняйте функции и ``lambda`` напрямую внутри постоянного Python-воркера на удалённом хосте по двунаправленному pipe (время отклика ``< 2 мс``):

.. code-block:: python

   import os
   from uniconn import Connection

   def check_disk_pressure(path: str = "/") -> dict:
       st = os.statvfs(path)
       free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
       total_gb = (st.f_blocks * st.f_frsize) / (1024 ** 3)
       return {"path": path, "free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)}

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       kernel = await conn.run_python(lambda: os.uname().release)
       disk_info = await conn.run_python(check_disk_pressure, "/var")
       print(f"Ядро: {kernel}, свободно на /var: {disk_info['free_gb']} ГБ")

3. Объектно-ориентированная ФС (``conn.path``) и дельта-синхронизация
---------------------------------------------------------------------

Навигация в стиле ``pathlib.Path`` без лишних сетевых запросов
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``conn.path()`` возвращает ``RemotePath`` (или ``SyncRemotePath`` в ``SyncConnection``), который предзагружает метаданные файлов во время ``glob()`` и ``iterdir()``:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       log_dir = conn.path("/var/log/nginx")
       if await log_dir.exists():
           async for log_file in log_dir.glob("*.log"):
               st = await log_file.stat()  # Предзагружено при glob — 0 дополнительных RTT!
               print(f"{log_file.name}: {st.st_size} байт")

       # Атомарная запись конфигурационного файла через временный файл и rename
       conf = conn.path("/etc/nginx/conf.d/app.conf")
       await conf.write_text("server { listen 8080; }\n", atomic=True)

Дельта-синхронизация директорий (в стиле ``rsync``) и шаблоны Jinja2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       # Передача только изменившихся файлов по сверке SHA-256 хешей
       sync_res = await conn.files.sync_dir(
           "./build",
           "/var/www/app",
           delete=True,
           checksum_check=True,
           exclude=["*.pyc", ".git", "__pycache__"],
       )
       print(f"Загружено: {len(sync_res.uploaded)}, Пропущено: {len(sync_res.skipped)}")

       # Рендеринг Jinja2-шаблона с атомарной записью на целевой хост
       await conn.files.write_template(
           "/etc/app/config.yaml",
           "templates/config.yaml.j2",
           context={"env": "production", "workers": 8},
           mode=0o640,
           atomic=True,
       )

4. Идемпотентное управление состоянием и дедупликация уведомлений
-----------------------------------------------------------------

Конфигурация Linux с unified diff и ``batch_notifications()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Все методы ``conn.state.ensure_*`` проверяют текущее состояние перед внесением изменений, возвращают ``EnsureResult.diff`` и вызывают ``notify``-обработчики только при реальном изменении:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       reload_nginx = ("reload_nginx", lambda: conn.state.ensure_service("nginx", state="reloaded", sudo=True))

       # Дедупликация перезапуска службы при множественных правках конфигов
       async with conn.state.batch_notifications() as batch:
           await conn.state.ensure_package("nginx", state="present", sudo=True)
           r1 = await conn.state.ensure_file(
               "/etc/nginx/nginx.conf",
               content="worker_processes auto;\n",
               validate="nginx -t -c %s",
               atomic=True,
               sudo=True,
               notify=reload_nginx,
           )
           r2 = await conn.state.ensure_file(
               "/etc/nginx/conf.d/upstream.conf",
               content="upstream backend { server 127.0.0.1:8000; }\n",
               atomic=True,
               sudo=True,
               notify=reload_nginx,
           )
       # Даже если изменились оба файла, 'reload_nginx' выполнится строго ОДИН РАЗ!
       print(f"Сработало триггеров: {batch.triggered_count}, Выполнено: {batch.executed_count}")

5. Декларативная DAG-оркестрация задач (``@task`` и ``Flow``)
-------------------------------------------------------------

Определяйте графы задач с зависимостями ``depends_on``, гарантированной очисткой ``post``, условиями ``when`` и барьерной раскаткой ``mode="barrier"`` по пулу хостов:

.. code-block:: python

   from uniconn import Connection, ConnectionPool, Flow, FlowContext, task

   @task(name="preflight_check", tags=["preflight"])
   async def preflight_check(conn: Connection, ctx: FlowContext):
       facts = await conn.gather_facts()
       ctx.host_set(conn, "os_family", facts.os_family)
       return await conn.run("uname -a")

   @task(name="cleanup_temp", always_run=True)
   async def cleanup_temp(conn: Connection):
       await conn.files.remove_file("/tmp/release.tar.gz")

   @task(
       name="deploy_release",
       depends_on=[preflight_check],
       post=[cleanup_temp],
       when=lambda conn, ctx: ctx.host_get(conn, "os_family") == "Linux",
       retries=2,
   )
   async def deploy_release(conn: Connection, version: str, port: int = 8080):
       return await conn.state.ensure_file(
           "/etc/app.conf",
           content=f"VERSION={version}\nPORT={port}\n",
           atomic=True,
           notify=("restart_app", lambda c: c.state.ensure_service("app", state="restarted", sudo=True)),
       )

   flow = Flow(
       name="canary_rollout",
       tasks=[deploy_release],
       mode="barrier",            # Синхронизация волны между узлами на каждом шаге DAG
       batch_size=2,              # Раскатка волнами по 2 хоста
       max_fail_ratio=0.0,        # Мгновенная остановка при ошибке
       batch_notifications=True,  # Дедупликация 'restart_app' в конце сценария
   )

   async with ConnectionPool.from_file("inventory.yaml", group="web") as pool:
       report = await pool.run_flow(flow, vars={"version": "2.4.0", "port": 9000})
       report.raise_for_status()
