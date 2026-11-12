Migration Guides (Ansible, Paramiko, Fabric, Netmiko)
=====================================================

90% of engineers adopting ``uniconn`` are migrating from ``Paramiko``, ``Fabric``, ``Ansible``, or ``Netmiko / Scrapli``. Use the side-by-side reference tables below to translate your existing mental model directly into ``uniconn``.

1. Migrating from Paramiko / AsyncSSH
-------------------------------------

With ``Paramiko``, running a command and uploading a file requires manually managing ``SSHClient``, host key policies, ``exec_command`` streams, exit status polling, and opening a separate ``SFTPClient``. ``uniconn`` replaces 35+ lines of boilerplate with a single context manager, built-in retries, and atomic SFTP operations.

.. list-table::
   :widths: 50 50
   :header-rows: 1

   * - Legacy ``Paramiko`` Boilerplate
     - ``uniconn`` Equivalent (Sync or Async)
   * - .. code-block:: python

          import os, paramiko

          client = paramiko.SSHClient()
          client.load_system_host_keys()
          client.connect(
              "10.0.0.10",
              username="admin",
              password=os.environ["SSH_PASS"],
              timeout=10,
          )
          stdin, stdout, stderr = client.exec_command("uptime")
          exit_code = stdout.channel.recv_exit_status()
          output = stdout.read().decode().strip()

          sftp = client.open_sftp()
          sftp.put("local.conf", "/etc/app.conf")
          sftp.chmod("/etc/app.conf", 0o600)
          sftp.close()
          client.close()
     - .. code-block:: python

          from uniconn import SyncConnection

          with SyncConnection.from_uri(
              "ssh://admin:env://SSH_PASS@10.0.0.10"
          ) as conn:
              output = conn.run("uptime").text
              conn.files.upload(
                  "local.conf",
                  "/etc/app.conf",
                  verify=True,
              )
              conn.files.chmod("/etc/app.conf", 0o600)

2. Migrating from Fabric
------------------------

``Fabric`` is synchronous-only, SSH-only, and lacks built-in idempotent state primitives, circuit breakers, or wave abort thresholds. ``uniconn`` provides drop-in context managers (``conn.cd()``, ``conn.env()``) plus full async concurrency and wave rollouts.

.. list-table::
   :widths: 35 65
   :header-rows: 1

   * - Fabric Construct
     - ``uniconn`` Equivalent
   * - ``from fabric import Connection``
     - ``from uniconn import SyncConnection`` (or async ``Connection``)
   * - ``c.run("uname -a", hide=True)``
     - ``c.run("uname -a")`` (output is captured in ``Result.text`` by default)
   * - ``c.sudo("systemctl restart nginx")``
     - ``c.run("systemctl restart nginx", sudo=True)`` or ``c.state.ensure_service("nginx", state="restarted", sudo=True)``
   * - ``with c.cd("/var/www"), c.prefix("export ENV=prod"):``
     - ``with c.cd("/var/www"), c.env(ENV="prod"):``
   * - ``c.put("app.tar.gz", "/tmp/app.tar.gz")``
     - ``c.files.upload("app.tar.gz", "/tmp/app.tar.gz", verify=True)``
   * - ``SerialGroup(*hosts).run("deploy.sh")``
     - ``ConnectionPool(hosts, batch_size=2, max_fail_ratio=0.0).map("deploy.sh")``
   * - ``@task def deploy(c): ...``
     - ``@task def deploy(conn: Connection, ctx: FlowContext): ...`` with DAG ``depends_on`` and ``post`` hooks

3. Migrating from Ansible Playbooks
-----------------------------------

Instead of debugging YAML indentation, Jinja2-in-YAML quoting issues, and slow 1–2 second task startup overhead, ``uniconn`` gives you native type-checked Python with Ansible-equivalent idempotency, unified diffs, and deduplicated ``notify`` handlers:

.. list-table::
   :widths: 32 43 25
   :header-rows: 1

   * - Ansible Module / Concept
     - ``uniconn`` Python API
     - CLI Equivalent
   * - ``ansible.builtin.setup`` (Facts)
     - ``await conn.gather_facts()``
     - ``uniconn gather-facts``
   * - ``ansible.builtin.apt`` / ``dnf`` / ``apk``
     - ``await conn.state.ensure_package("nginx", state="present")``
     - ``uniconn ensure-package``
   * - ``ansible.builtin.service`` / ``systemd``
     - ``await conn.state.ensure_service("nginx", state="started", enabled=True)``
     - ``uniconn ensure-unit``
   * - ``ansible.builtin.copy`` / ``file``
     - ``await conn.state.ensure_file("/etc/app.conf", content=..., mode=0o644, atomic=True)``
     - ``uniconn upload``
   * - ``ansible.builtin.template``
     - ``await conn.files.write_template("/etc/app.conf", "app.j2", context={...})``
     - ``uniconn write-template``
   * - ``ansible.builtin.lineinfile``
     - ``await conn.state.ensure_line("/etc/ssh/sshd_config", "PermitRootLogin no", regex=r"^PermitRootLogin")``
     - —
   * - ``ansible.builtin.user``
     - ``await conn.state.ensure_user("deploy", uid=1050, groups=["docker"])``
     - ``uniconn ensure-user``
   * - ``ansible.posix.authorized_key``
     - ``await conn.state.ensure_authorized_key("deploy", "ssh-ed25519 AAAA...")``
     - ``uniconn ensure-authorized-key``
   * - ``ansible.posix.sysctl``
     - ``await conn.state.ensure_sysctl("net.ipv4.ip_forward", 1)``
     - ``uniconn ensure-sysctl``
   * - ``ansible.posix.synchronize`` (rsync)
     - ``await conn.files.sync_dir("./dist", "/var/www", delete=True, checksum_check=True)``
     - ``uniconn sync``
   * - ``ansible.builtin.wait_for``
     - ``await conn.wait_for_port(5432)`` / ``await conn.wait_for_path("/tmp/ready")``
     - ``uniconn wait-for port``
   * - ``ansible.windows.win_service`` / ``win_regedit``
     - ``await conn.state.ensure_windows_service(...)`` / ``ensure_registry_key(...)``
     - —
   * - ``handlers:`` + ``notify:``
     - ``ensure_file(..., notify=("reload", fn))`` + ``conn.state.batch_notifications()``
     - ``Flow(batch_notifications=True)``
   * - ``serial: 2`` + ``max_fail_percentage: 0``
     - ``ConnectionPool(..., batch_size=2, max_fail_ratio=0.0)``
     - ``uniconn run-multi --batch-size 2``
   * - ``--check --diff``
     - ``Connection.from_uri(..., dry_run=True)`` (populates ``EnsureResult.diff``)
     - ``--dry-run``
   * - Mitogen Plugin (Zero-Fork Python)
     - Built-in ``await conn.run_python(callable, *args)`` (< 2 ms)
     - —

4. Migrating from Netmiko / Scrapli / ncclient
----------------------------------------------

``uniconn`` unifies CLI screen-scraping (with ``expect()`` and ``textfsm`` / ``ttp`` parsing) and structured model-driven network protocols (``netconf://``, ``restconf://``, ``gnmi://``) under the same ``Connection`` API:

.. list-table::
   :widths: 45 55
   :header-rows: 1

   * - Netmiko / Scrapli / ncclient Pattern
     - ``uniconn`` Pattern
   * - ``net_connect.send_command("show ip int brief", use_textfsm=True)``
     - ``(await conn.run("show ip int brief", parse="textfsm:cisco_ios_show_ip_interface_brief")).parsed``
   * - ``net_connect.send_command_timing(...)`` / interactive prompts
     - ``await conn.expect("copy running-config startup-config", patterns={r"Destination filename": "\n"})``
   * - ``ncclient.manager.connect(host=..., port=830, device_params={'name': 'junos'})``
     - ``Connection.from_uri("netconf://admin:env://PASS@rtr:830?vendor=junos")``
   * - Manual ``lock("candidate")`` $\rightarrow$ ``edit_config`` $\rightarrow$ ``validate`` $\rightarrow$ ``commit``
     - ``await conn.state.ensure_yang("/interfaces", config={...}, validate=True)``
   * - Custom gNMI protobuf stubs
     - ``Connection.from_uri("gnmi://admin:env://PASS@leaf-01:9339?origin=openconfig")`` with ``conn.net.get()`` / ``conn.net.subscribe()``
