5-Minute Quickstart Guide
=========================

This guide walks you through installing ``uniconn``, choosing between the **Async** and **Sync** APIs, running your first commands (even without a remote server), and using the built-in interactive web console.

1. Installation
---------------

Install the lightweight core package (includes SSH, Local, Docker, Podman, Kubernetes ``kubectl``, NETCONF, RESTCONF, gNMI, Proxmox VE, QEMU Guest Agent, Replay cassettes, resilience pipeline, and structured logging):

.. code-block:: bash

   # Using uv (recommended)
   uv add uniconn

   # Or using pip
   pip install uniconn

Optional Extras Matrix
~~~~~~~~~~~~~~~~~~~~~~

Install everything at once with ``uv add "uniconn[all]"``, or pick only the extras your environment requires:

.. list-table::
   :widths: 18 35 47
   :header-rows: 1

   * - Extra
     - Install Command
     - Included Capabilities
   * - **all**
     - ``uv add "uniconn[all]"``
     - All optional transports, parsers, templates, telemetry, and CLI
   * - **cli**
     - ``uv add "uniconn[cli]"``
     - Full CLI (``cyclopts``, ``rich``) including ``uniconn run``, ``flow``, ``mcp``, ``policy``
   * - **winrm**
     - ``uv add "uniconn[winrm]"``
     - Windows Remote Management (``winrm://``, ``wsman://`` via ``pywinrm``)
   * - **bmc**
     - ``uv add "uniconn[bmc]"``
     - IPMI (``pyghmi``) and DMTF Redfish HTTP/2 (``niquests``)
   * - **serial**
     - ``uv add "uniconn[serial]"``
     - Serial/UART console (``pyserial-asyncio``) and XMODEM/YMODEM/ZMODEM flashing
   * - **telnet**
     - ``uv add "uniconn[telnet]"``
     - RFC 854 Telnet transport with IAC NAWS resize (``telnetlib3``)
   * - **parsing**
     - ``uv add "uniconn[parsing]"``
     - Semantic CLI parsers (``jc``, ``textfsm``, ``ttp``, ``ntc-templates``)
   * - **templates**
     - ``uv add "uniconn[templates]"``
     - Jinja2 template engine for ``conn.files.write_template()``
   * - **otel**
     - ``uv add "uniconn[otel]"``
     - OpenTelemetry distributed tracing via ``otel_tracing_hook``

2. Zero-Setup Sandbox: Try ``uniconn`` Without a Remote Server
--------------------------------------------------------------

You do not need an external SSH server to test ``uniconn``. Every feature works out of the box against ``local://`` or the built-in ``MockSSHServer``:

.. code-block:: python

   import asyncio
   from uniconn import Connection

   async def main():
       # Connect to the local machine using the unified Connection facade
       async with Connection.local() as conn:
           # 1. Run a command and automatically parse its output
           res = await conn.run("uname -a")
           print("System:", res.text)

           # 2. Execute a Python function directly via Zero-Fork RPC (< 2 ms)
           import os
           cpu_count = await conn.run_python(lambda: os.cpu_count())
           print("CPUs:", cpu_count)

           # 3. Collect structured host facts
           facts = await conn.gather_facts()
           print(f"OS: {facts.os_family} ({facts.arch}), Kernel: {facts.kernel}")

   asyncio.run(main())

3. Choosing Your Paradigm: Async vs. Sync vs. CLI
-------------------------------------------------

``uniconn`` provides **100% API parity** between asynchronous and synchronous classes:

- **Use Async (``Connection``, ``ConnectionPool``, ``Flow``)** when building FastAPI/aiohttp services, orchestrating dozens of hosts concurrently, or streaming logs in real time.
- **Use Sync (``SyncConnection``, ``SyncConnectionPool``, ``SyncFlow``)** when writing CLI scripts, maintenance utilities, or synchronous ``pytest`` checks without managing ``asyncio.run()``.
- **Use the CLI (``uniconn ...``)** for ad-hoc terminal inspection, wave rollouts, cassette recording, and starting the AI MCP server.

Async Python
~~~~~~~~~~~~

.. code-block:: python

   from uniconn import Connection

   async with Connection.from_uri("ssh://admin:env://SSH_PASS@web-01") as conn:
       disks = (await conn.run("df -h", parse="auto")).parsed
       await conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
       await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

Sync Python
~~~~~~~~~~~

.. code-block:: python

   from uniconn import SyncConnection

   with SyncConnection.from_uri("ssh://admin:env://SSH_PASS@web-01") as conn:
       disks = conn.run("df -h", parse="auto").parsed
       conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
       conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)

Command-Line Interface (CLI)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Run command with automatic semantic parsing and JSON output
   uniconn run "ssh://admin:env://SSH_PASS@web-01" "df -h" --format json

   # Enforce idempotent systemd unit state
   uniconn ensure-unit nginx.service "ssh://admin@web-01" --state started --enabled --sudo

4. Secret Resolution & Inventories
----------------------------------

Never hardcode credentials in scripts. ``uniconn`` resolves ``env://`` and ``file://`` references automatically in URIs and YAML/TOML/JSON inventories:

.. code-block:: python

   from uniconn import ConnectionPool

   # Resolves SSH_PASS from environment (or falls back to 'devpass' if unset)
   uri = "ssh://deploy:env://SSH_PASS?default=devpass@10.0.0.10?key_file=file:///run/secrets/ssh_key"

   # Or load an entire group of hosts from a YAML inventory
   async with ConnectionPool.from_file("inventory.yaml", group="web", batch_size=2) as pool:
       ping_results = await pool.ping()
       for host, status in ping_results.items():
           print(f"{host}: alive={status.alive} ({status.latency_ms:.1f} ms)")

5. Interactive Web Console & Recipe Wizard
------------------------------------------

``uniconn`` includes a built-in web dashboard with an interactive **Quickstart & Recipe Wizard**, **Visual URI Builder**, **Fleet Simulator**, and **AST Policy Inspector**:

.. code-block:: bash

   python main.py --serve

Open ``http://localhost:3000`` in your browser to:

1. Pick your target transport and engineering task in the **Quickstart & Recipes** tab.
2. Generate ready-to-copy **Async Python**, **Sync Python**, and **CLI** code.
3. Click **Run Recipe in Live Sandbox** to execute the workflow in-process and inspect real ``Result``, ``EnsureResult``, ``FlowReport``, and ``PolicyDecision`` objects.
