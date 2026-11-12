uniconn Documentation
=====================

**Language:** **[ English ]** | `Русский <ru/index.rst>`_

**uniconn** is a universal async-first Python library (Python 3.11+) and CLI for executing commands, inspecting host facts, enforcing idempotent states, orchestrating multi-host task DAGs, and synchronizing files across **16+ transport schemes** with **100% Async + Sync API parity** and sub-millisecond core overhead.

.. image:: https://img.shields.io/badge/python-3.11+-blue.svg
   :target: https://www.python.org/downloads/
   :alt: Python 3.11+

.. image:: https://img.shields.io/badge/License-MIT-yellow.svg
   :target: https://opensource.org/licenses/MIT
   :alt: MIT License

Why uniconn?
------------

Modern infrastructure spans Linux and Windows servers, containers, Kubernetes pods, network routers, hypervisors, and bare-metal BMC/UART controllers. Instead of stitching together incompatible libraries (`Paramiko`, `pywinrm`, `docker-py`, `Netmiko`, `Ansible`), ``uniconn`` provides a single resilient facade:

- **16+ Unified Transport Schemes**: ``ssh://``, ``winrm://`` (``wsman://``), ``docker://``, ``podman://``, ``kubectl://``, ``netconf://``, ``restconf://``, ``gnmi://``, ``pve://`` (Proxmox VE), ``qga://`` (QEMU Guest Agent), ``redfish://``, ``ipmi://``, ``serial://`` (``uart://``), ``telnet://``, ``replay://``, and ``local://``.
- **100% Async + Sync Parity**: Use ``Connection`` / ``ConnectionPool`` / ``Flow`` for high-concurrency async workloads, or ``SyncConnection`` / ``SyncConnectionPool`` / ``SyncFlow`` for synchronous scripts and tests—powered by a shared background ``EventLoopPortal``.
- **Semantic Output Parsing & Auto-Diagnostics**: Parse CLI output directly into dicts or Pydantic models via ``conn.run("df -h", parse="auto")``, and automatically diagnose failed commands (port conflicts, disk full, OOM kills) with ``diagnose=True``.
- **Zero-Fork Remote Python RPC**: Execute Python functions or lambdas directly inside a persistent remote worker over stdio pipe in ``< 2 ms`` via ``conn.run_python(fn)``.
- **Object-Oriented Remote Filesystem & Delta Sync**: Navigate remote paths with ``conn.path("/var/log")`` (``pathlib.Path`` ergonomics with preloaded ``glob()`` metadata) and perform rsync-style delta transfers via ``conn.files.sync_dir()``.
- **Idempotent State & Deduplicated Handlers**: Enforce packages, services, files, users, sysctl, Windows registry/features, and YANG trees via ``conn.state.ensure_*`` with unified diffs and ``batch_notifications()``.
- **Declarative Task DAG Orchestration**: Build dependency graphs with ``@task`` and ``Flow``, complete with ``depends_on``, ``post`` cleanup, ``when`` predicates, and wave-based ``mode="barrier"`` fleet rollouts.
- **Deterministic Contract Testing & In-Process Mocks**: Record and replay YAML cassettes via ``use_cassette()`` or ``@pytest.mark.uniconn_cassette``, or spin up in-memory ``MockSSHServer`` / ``MockNetconfServer`` instances in CI without network access.
- **AI-Ready MCP Server, HITL & AST Policy Guardrails**: Expose your inventory safely to AI agents via ``uniconn mcp`` with ``CommandASTParser`` obfuscation detection, ``EmbeddedPolicyEngine`` / OPA rules, and Human-in-the-Loop (HITL) approvals.

Task-to-Solution Cheat Sheet (Find Your Tool in 10 Seconds)
-----------------------------------------------------------

.. list-table::
   :widths: 32 28 40
   :header-rows: 1

   * - What do you want to achieve?
     - uniconn API / Tool
     - Minimal Example
   * - Run a command and parse output into structured JSON/dict
     - ``conn.run(..., parse="auto")``
     - ``(await conn.run("df -h", parse="auto")).parsed``
   * - Write a simple synchronous script without ``async/await``
     - ``SyncConnection``
     - ``with SyncConnection.from_uri("ssh://host") as c:``
   * - Execute a Python function on a remote host in < 2 ms
     - ``conn.run_python(fn)``
     - ``await conn.run_python(lambda: os.uname().release)``
   * - Work with remote files like ``pathlib.Path``
     - ``conn.path(remote_path)``
     - ``await conn.path("/etc/app.conf").write_text(cfg, atomic=True)``
   * - Synchronize a local directory to remote hosts (like ``rsync``)
     - ``conn.files.sync_dir()``
     - ``await conn.files.sync_dir("./dist", "/var/www", delete=True)``
   * - Configure packages, services, users, or files idempotently
     - ``conn.state.ensure_*``
     - ``await conn.state.ensure_service("nginx", state="started", sudo=True)``
   * - Reload a service only once after multiple config file edits
     - ``conn.state.batch_notifications()``
     - ``async with conn.state.batch_notifications(): ...``
   * - Automatically diagnose why a remote command failed
     - ``conn.run(..., diagnose=True)``
     - ``res = await conn.run("systemctl start app", diagnose=True)``
   * - Roll out changes across a fleet in waves with auto-abort
     - ``ConnectionPool(..., batch_size=2)``
     - ``await pool.map("deploy.sh", batch_size=2, max_fail_ratio=0.0)``
   * - Orchestrate a multi-step DAG pipeline with dependencies
     - ``@task`` + ``Flow``
     - ``await pool.run_flow(deploy_flow, vars={"version": "1.4.2"})``
   * - Compare OS/hardware facts across a cluster to find drift
     - ``pool.diff_facts()``
     - ``drift = await pool.diff_facts()``
   * - Test infrastructure code offline in CI without real servers
     - ``@pytest.mark.uniconn_cassette``
     - Decorate pytest test or use ``async with conn.use_cassette(...)``
   * - Verify shell commands against obfuscation and RBAC policies
     - ``CommandASTParser`` & ``PolicyEngine``
     - ``uniconn policy eval "systemctl restart db" --preset prod-guard``

Choose Your Starting Path by Role
---------------------------------

- **Linux / Windows SysAdmin & DevOps**: Start with :doc:`quickstart`, explore ``conn.files`` and ``conn.state.ensure_*`` in :doc:`cookbook`, check YAML/TOML/JSON schemas in :doc:`inventory_and_uris`, or compare patterns in :doc:`migration`.
- **Python Developer & Software Architect**: Dive into ``CommandPipeline``, middleware execution order, ``EventLoopPortal``, and custom extensions in :doc:`architecture`.
- **Network Engineer (NETCONF / RESTCONF / gNMI)**: Check structured YANG operations (``conn.net.get``, ``conn.state.ensure_yang``) and ``textfsm`` / ``ttp`` parsing in :doc:`transports`, :doc:`inventory_and_uris`, and :doc:`cookbook`.
- **Bare-Metal & Embedded Hardware Engineer**: See Redfish HTTP/2, IPMI, Serial/UART DTR/RTS pulsing, X/Y/ZMODEM flashing, and reactive ``diagnostic_session`` watchdogs in :doc:`cookbook`.
- **QA / SDET & Troubleshooting Engineer**: Learn how to inspect the ``UniconnError`` hierarchy, enable ``diagnose=True``, record YAML cassettes, and resolve common errors in :doc:`troubleshooting` and :doc:`cookbook`.
- **AI / Platform Engineer**: Configure ``uniconn mcp``, Human-in-the-Loop (HITL) approvals, and AST Policy-as-Code guardrails in :doc:`cli_and_mcp`.

Documentation Contents
----------------------

.. toctree::
   :maxdepth: 2
   :caption: User Guides & Deep Dives (EN):

   quickstart
   architecture
   inventory_and_uris
   cookbook
   troubleshooting
   migration
   transports
   cli_and_mcp

.. toctree::
   :maxdepth: 2
   :caption: Документация на русском (RU):

   ru/index

.. toctree::
   :maxdepth: 2
   :caption: Reference & Examples:

   api
   examples

.. toctree::
   :maxdepth: 1
   :caption: Project Links:

   GitHub <https://github.com/yourusername/uniconn>
   PyPI <https://pypi.org/project/uniconn>

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
