Step-by-Step Cookbook (Recipes by Use Case)
===========================================

This cookbook provides copy-pasteable, production-ready recipes organized by engineering task. Every recipe works with both ``Connection`` (async) and ``SyncConnection`` (sync).

1. Command Execution, Auto-Parsing & Failure Diagnostics
--------------------------------------------------------

Parse CLI Output into Structured JSON or Pydantic Models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pass ``parse="auto"`` (or an explicit engine like ``"jc:df"``, ``"textfsm:..."``, ``"ttp:..."``, or a ``pydantic.BaseModel``) to convert raw terminal text into structured Python data:

.. code-block:: python

   from pydantic import BaseModel
   from uniconn import Connection

   class MountEntry(BaseModel):
       filesystem: str
       mounted_on: str
       use_percent: int | None = None

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       # 1. Automatic semantic detection (builtin / JSON / JC)
       res = await conn.run("df -h", parse="auto")
       for row in res.parsed:
           print(row)

       # 2. Validate parsed rows directly into Pydantic models
       typed = await conn.run("df -h", parse=list[MountEntry])
       print(typed.parsed[0].mounted_on)

Automatic Root-Cause Diagnostics on Command Failure (``diagnose=True``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a command exits with a non-zero code, ``diagnose=True`` (or connection-wide ``auto_diagnostics=True``) inspects system vitals, port conflicts, OOM kills, and journal logs to build a ``DiagnosticSummary``:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01", auto_diagnostics=True) as conn:
       res = await conn.run("systemctl start nginx", sudo=True, diagnose=True)
       if not res.ok and res.diagnostic:
           diag = res.diagnostic
           print(f"Category: {diag.category.value}")
           print(f"Root cause hint: {diag.root_cause_hint}")
           print(f"Suggested actions: {diag.suggested_actions}")
           if diag.port_conflict:
               print(f"Port {diag.port_conflict.port} held by PID {diag.port_conflict.conflicting_pid}")

2. Zero-Fork Remote Python RPC (``conn.run_python``)
----------------------------------------------------

Execute arbitrary Python functions or lambdas inside a persistent background Python worker on the remote host over a bidirectional stdio pipe. This eliminates SSH process fork overhead and script upload delays (typical latency ``< 2 ms``):

.. code-block:: python

   import os
   from uniconn import Connection

   def check_disk_pressure(path: str = "/") -> dict:
       st = os.statvfs(path)
       free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
       total_gb = (st.f_blocks * st.f_frsize) / (1024 ** 3)
       return {"path": path, "free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)}

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       # Execute lambda or top-level function remotely
       kernel = await conn.run_python(lambda: os.uname().release)
       disk_info = await conn.run_python(check_disk_pressure, "/var")
       print(f"Kernel: {kernel}, /var free: {disk_info['free_gb']} GB")

3. Object-Oriented Filesystem (``conn.path``) & Delta Sync
----------------------------------------------------------

Navigate Remote Paths Like ``pathlib.Path`` with Zero Extra RTTs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``conn.path()`` returns a ``RemotePath`` (or ``SyncRemotePath`` on ``SyncConnection``) that preloads file metadata during ``glob()`` and ``iterdir()``:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       log_dir = conn.path("/var/log/nginx")
       if await log_dir.exists():
           async for log_file in log_dir.glob("*.log"):
               st = await log_file.stat()  # Preloaded during glob — 0 extra network round-trips!
               print(f"{log_file.name}: {st.st_size} bytes")

       # Atomic file write with automatic temp-file rename
       conf = conn.path("/etc/nginx/conf.d/app.conf")
       await conf.write_text("server { listen 8080; }\n", atomic=True)

Rsync-Style Delta Directory Synchronization & Jinja2 Templates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       # Upload only modified files using SHA-256 delta comparison
       sync_res = await conn.files.sync_dir(
           "./build",
           "/var/www/app",
           delete=True,
           checksum_check=True,
           exclude=["*.pyc", ".git", "__pycache__"],
       )
       print(f"Uploaded: {len(sync_res.uploaded)}, Skipped: {len(sync_res.skipped)}")

       # Render a template atomically on the remote host
       await conn.files.write_template(
           "/etc/app/config.yaml",
           "templates/config.yaml.j2",
           context={"env": "production", "workers": 8},
           mode=0o640,
           atomic=True,
       )

4. Idempotent State Management & Deduplicated Notifications
-----------------------------------------------------------

Linux Provisioning with Unified Diff & ``batch_notifications()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All ``conn.state.ensure_*`` methods check the current state first, compute a unified diff when files change, and trigger ``notify`` handlers only when a mutation actually occurs:

.. code-block:: python

   async with Connection.from_uri("ssh://admin@node-01") as conn:
       reload_nginx = ("reload_nginx", lambda: conn.state.ensure_service("nginx", state="reloaded", sudo=True))

       # Deduplicate notifications across multiple ensure_* operations
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
       # Even if both files changed, 'reload_nginx' runs strictly ONCE on context exit!
       print(f"Triggered: {batch.triggered_count}, Executed: {batch.executed_count}")
       if r1.diff:
           print(r1.diff)

Windows Provisioning over WinRM (``winrm://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Manage Windows packages (``winget``, ``choco``, ``scoop``), Windows services, Registry keys, and Windows Server roles/features:

.. code-block:: python

   async with Connection.from_uri("winrm://Administrator:env://WIN_PASS@10.0.0.50?ssl=true") as win:
       await win.state.ensure_package("Git.Git", manager="winget", state="present")
       await win.state.ensure_windows_service("wuauserv", state="stopped", startup_type="disabled")
       await win.state.ensure_registry_key(
           r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
           name="NoAutoUpdate",
           value=1,
           type="DWORD",
       )
       await win.state.ensure_windows_feature("Web-Server", state="present", include_management_tools=True)

5. Declarative Task DAG Orchestration (``@task`` & ``Flow``)
------------------------------------------------------------

Define reusable tasks with ``depends_on``, guaranteed ``post`` cleanup, ``when`` conditions, automatic parameter injection from ``vars``, and wave-synchronized ``mode="barrier"`` execution across a ``ConnectionPool``:

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
       # 'version' and 'port' are automatically injected from Flow vars!
       return await conn.state.ensure_file(
           "/etc/app.conf",
           content=f"VERSION={version}\nPORT={port}\n",
           atomic=True,
           notify=("restart_app", lambda c: c.state.ensure_service("app", state="restarted", sudo=True)),
       )

   flow = Flow(
       name="canary_rollout",
       tasks=[deploy_release],
       mode="barrier",            # Synchronize wave across hosts before advancing to next task
       batch_size=2,              # Roll out 2 hosts at a time
       max_fail_ratio=0.0,        # Abort immediately if any host fails
       batch_notifications=True,  # Deduplicate 'restart_app' per host at the end of the flow
   )

   async with ConnectionPool.from_file("inventory.yaml", group="web") as pool:
       report = await pool.run_flow(flow, vars={"version": "2.4.0", "port": 9000})
       report.raise_for_status()

6. Network Automation (NETCONF, RESTCONF, gNMI) & YANG State
------------------------------------------------------------

Configure routers and switches using structured YANG data models with automatic candidate datastore locking, validation, and rollback-on-error:

.. code-block:: python

   from uniconn import Connection

   async with Connection.from_uri("netconf://admin:env://NET_PASS@core-rtr-01:830?vendor=junos") as rtr:
       # Query operational state via XPath or subtree filter
       interfaces = await rtr.net.get("/interfaces/interface[name='ge-0/0/0']")
       print(interfaces.data)

       # Idempotent YANG configuration with unified XML/JSON diff
       ens = await rtr.state.ensure_yang(
           "/interfaces/interface[name='ge-0/0/0']",
           config={"interface": {"name": "ge-0/0/0", "description": "Uplink to Core"}},
           validate=True,
       )
       print("Changed:", ens.changed, ens.diff)

7. Virtualization (Proxmox VE ``pve://`` & QEMU Guest Agent ``qga://``)
-----------------------------------------------------------------------

Manage virtual machines and execute commands inside guests without requiring network/SSH access inside the VM:

.. code-block:: python

   from uniconn import Connection

   # 1. Proxmox VE API + Guest Agent execution and snapshot lifecycle
   async with Connection.from_uri("pve://root@pam!token:env://PVE_SECRET@pve-01:8006/105?node=pve1") as vm:
       await vm.run("pve snapshot create pre_upgrade")
       res = await vm.run("apt-get update && apt-get -y upgrade")
       if not res.ok:
           await vm.run("pve snapshot rollback pre_upgrade")

   # 2. Direct QEMU Guest Agent over Unix socket or virsh channel
   async with Connection.from_uri("qga://root@kvm-host-01/vm-prod-01?backend=virsh") as guest:
       print((await guest.run("ip addr")).text)

8. Hardware BMC (Redfish & IPMI), Serial/UART & Reactive Diagnostics
--------------------------------------------------------------------

Bare-Metal BMC Control & Firmware Flashing over UART (YMODEM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from uniconn import Connection

   # Redfish HTTP/2 BMC telemetry & power control
   async with Connection.from_uri("redfish://admin:env://BMC_PASS@192.168.1.100?verify_ssl=false") as bmc:
       print((await bmc.run("power status")).text)
       print((await bmc.run("sensors")).text)

   # Serial/UART hardware reset, U-Boot break, and YMODEM firmware upload
   async with Connection.from_uri("uart:///dev/ttyUSB0:115200") as board:
       await board.transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.1)
       board.transport.send_break(duration=0.25)
       sent = await board.files.upload_ymodem("u-boot.bin", trigger_command="loady 0x82000000\r")
       print(f"Transferred {sent} bytes")

Reactive Log Watchdogs During Hardware Stress Tests (``diagnostic_session``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stream ``dmesg`` and ``journalctl`` in the background while running workloads, automatically aborting with ``HardwareFaultDetectedError`` if a kernel panic, WHEA/MCE fault, or overheating event occurs:

.. code-block:: python

   async with conn.diagnostic_session(
       streams=["dmesg -w", "journalctl -f"],
       watch_rules=["kernel_panic", "hardware_errors"],
       local_dir="./diagnostics",
   ) as diag:
       await conn.run("stress-ng --cpu 8 --timeout 60s")
       diag.check_abort()  # Raises HardwareFaultDetectedError if any critical watch rule matched

9. Deterministic Contract Testing (Cassettes & In-Process Mock Servers)
-----------------------------------------------------------------------

Pytest Cassette Plugin (``@pytest.mark.uniconn_cassette``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Record real SSH/NETCONF/BMC interactions once into a sanitized YAML cassette and replay them deterministically in CI without network access:

.. code-block:: python

   import pytest
   from uniconn import Connection

   @pytest.mark.uniconn_cassette(mode="once")
   async def test_nginx_provisioning():
       async with Connection.from_uri("ssh://admin@prod-web-01") as conn:
           res = await conn.run("nginx -v")
           assert res.ok

In-Process Socket Mock Servers (``MockSSHServer``, ``MockNetconfServer``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test real socket clients (even external tools or ``AsyncSSH``) against an in-memory mock server populated from a cassette:

.. code-block:: python

   from uniconn import Cassette, Connection, MockSSHServer, RecordedExecInteraction

   cassette = Cassette(
       transport="ssh",
       host="mock-node",
       interactions=[RecordedExecInteraction(command="uptime", exit_code=0, stdout="up 10 days\n")],
   )

   async with MockSSHServer.from_cassette(cassette) as server:
       async with Connection.from_uri(server.uri) as conn:
           assert (await conn.run("uptime")).text == "up 10 days"
