Complete Inventory Schema (YAML/TOML/JSON) & Transport URI Reference
====================================================================

**Language:** **[ English ]** | `Русский <ru/inventory_and_uris.rst>`_

This reference manual documents every supported structure for inventory files (``.yaml`` / ``.yml``, ``.toml``, ``.json``), the exact merge precedence rules used by ``InventoryLoader``, dynamic secret resolution (``env://`` and ``file://``), global ``ConnectionConfig`` pipeline parameters, and all **16+ transport URI schemes**.

1. Inventory File Formats & Schema Reference
--------------------------------------------

``Connection.from_file()``, ``Connection.from_inventory()``, ``ConnectionPool.from_file()``, ``SyncConnectionPool.from_file()``, and CLI commands (``--inventory``) all use ``InventoryLoader`` under the hood.

4 Supported Inventory Layouts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``InventoryLoader.parse_data()`` accepts four flexible layouts in YAML, TOML, or JSON:

1. **Canonical Structured Inventory (Recommended)**: A dictionary with ``defaults`` (shared fields), ``groups`` (mapping of group names to host aliases), and ``hosts`` (mapping of host aliases to URI strings or config dicts).
2. **Shorthand Host Alias Mapping**: A top-level dictionary mapping host aliases directly to URI strings or config dictionaries (without a ``hosts:`` wrapper key).
3. **Flat List of Hosts**: A top-level list of URI strings or host dictionaries (``["ssh://node-01", {"uri": "ssh://node-02", "groups": ["web"]}]``).
4. **Single Connection Object**: A single dictionary containing ``transport`` or ``uri``.

Side-by-Side Canonical Inventory Examples (YAML, TOML, JSON)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
     # 1. Shorthand URI string (inherits defaults, name="web-01")
     web-01: "ssh://deploy:env://SSH_PASS?default=devpass@10.0.1.10:22"

     # 2. Full dictionary definition with per-host overrides and inline group membership
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

     # 3. Database host on a different transport or port
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

Merge Precedence & Group Resolution Rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   ┌────────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
   │   1. Global Defaults   │ ──► │ 2. Host Entry Fields   │ ──► │ 3. Explicit Call Args  │
   │  (defaults: {...})     │     │ (hosts.<alias>: {...}) │     │ (from_file(dry_run=..))│
   └────────────────────────┘     └────────────────────────┘     └────────────────────────┘
                                               │
                                               ▼
                        ┌──────────────────────────────────────────────┐
                        │ 4. SecretResolver (env:// & file://)         │
                        │    Resolves all strings & nested dicts first │
                        └──────────────────────────────────────────────┘

1. **Defaults Inheritance**: Every host under ``hosts`` starts with a shallow copy of ``defaults`` and overrides any matching keys with its own dictionary keys. If the host key is ``alias`` and ``name`` / ``host`` are omitted in a dictionary entry, ``name`` and ``host`` automatically default to ``alias``.
2. **Bidirectional Group Membership**: A host belongs to group ``G`` if **either** ``G`` lists the host's ``name``/``host`` in the top-level ``groups:`` section **or** the host entry itself defines ``groups: ["G"]`` (or ``groups: "G"``). Both sources are deduplicated into ``entry["groups"]``.
3. **Filtering (``group=`` and ``host=``)**:
   - Passing ``group="web"`` filters the inventory to members of ``web``. If no host matches, ``KeyError("Group 'web' not found in inventory")`` is raised.
   - Passing ``host="web-01"`` selects that specific host by ``name`` or ``host`` (raising ``KeyError`` if absent).

2. Dynamic Secret Resolution (``SecretResolver``)
-------------------------------------------------

``uniconn`` resolves secret references in both URI strings and inventory dictionaries **before** opening any network connection:

.. list-table::
   :widths: 35 65
   :header-rows: 1

   * - Secret Reference Syntax
     - Behavior & Security Guarantees
   * - ``env://VAR_NAME``
     - Reads ``os.environ["VAR_NAME"]``. Raises ``ConfigurationError`` if unset or empty.
   * - ``env://VAR_NAME?default=fallback``
     - Reads ``os.environ["VAR_NAME"]``, or returns ``"fallback"`` if the variable is not set.
   * - ``file:///abs/path/to/secret``
     - Reads the file at ``/abs/path/to/secret`` and strips trailing ``\r\n``. Raises ``ConfigurationError`` if missing.
   * - ``file://relative/secret?default=val``
     - Reads ``relative/secret`` (restricted to ``base_dir`` if provided to prevent ``../`` path traversal), or falls back to ``"val"``.

.. note::

   All resolved passwords and passphrases are stored as ``pydantic.SecretStr`` on ``ConnectionConfig``. Calling ``conn.config.uri_safe`` or logging events automatically masks credentials (``***REDACTED***``).

3. Global ``ConnectionConfig`` & Pipeline Options
-------------------------------------------------

The following options can be passed as query parameters on **any** transport URI (e.g., ``?timeout=60&auto_diagnostics=true``), in a host dictionary, or as keyword arguments to ``Connection.from_uri()``:

.. list-table::
   :widths: 26 16 14 44
   :header-rows: 1

   * - Option Name
     - Type
     - Default
     - Description
   * - ``timeout``
     - ``float``
     - ``30.0``
     - Default command execution and connection timeout in seconds.
   * - ``retry_attempts``
     - ``int``
     - ``3``
     - Number of attempts in ``RetryMiddleware`` on ``ConnectionError`` or ``TimeoutError`` (set ``1`` to disable retries).
   * - ``rate_limit``
     - ``float``
     - ``None``
     - Maximum commands per second allowed on this connection (Token Bucket ``RateLimiter``).
   * - ``circuit_breaker_threshold``
     - ``int``
     - ``None``
     - Consecutive network/timeout failures before tripping ``CircuitBreaker`` into ``OPEN`` state.
   * - ``circuit_breaker_timeout``
     - ``float``
     - ``30.0``
     - Cooldown window in seconds before an ``OPEN`` circuit transitions to ``HALF_OPEN``.
   * - ``auto_diagnostics``
     - ``bool``
     - ``False``
     - Automatically run ``AutoDiagnosticMiddleware`` root-cause probes whenever a command exits with a non-zero code.
   * - ``dry_run``
     - ``bool``
     - ``False``
     - Short-circuit command execution in ``DryRunMiddleware`` and compute diffs without modifying the target host.
   * - ``sudo_password``
     - ``SecretStr | str``
     - ``None``
     - Password injected into ``sudo -S`` stdin when ``sudo=True`` is used (falls back to connection ``password``).
   * - ``is_production``
     - ``bool``
     - ``False``
     - Marks the host as production for ``HITLApprovalMiddleware`` and ``PolicyGuardrailMiddleware`` (e.g., ``prod-guard`` preset).

4. Complete Transport URI Reference (16+ Schemes)
-------------------------------------------------

4.1. SSH (``ssh://``)
~~~~~~~~~~~~~~~~~~~~~

- **URI Syntax**: ``ssh://[user[:password]@]host[:22][?option=value]``
- **Required Extra**: Included in core ``uniconn`` (uses ``asyncssh`` or ``system_ssh=true`` fallback).

.. list-table::
   :widths: 25 18 57
   :header-rows: 1

   * - Query / Config Option
     - Default
     - Description
   * - ``key_file``
     - ``None``
     - Path to private key (e.g. ``~/.ssh/id_ed25519`` or ``file:///run/secrets/key``).
   * - ``passphrase``
     - ``None``
     - Passphrase for encrypted private key (supports ``env://`` / ``file://``).
   * - ``known_hosts``
     - ``"accept_new"``
     - Host key policy: ``strict``, ``accept_new``, ``none`` (or ``false``), or path to custom ``known_hosts`` file.
   * - ``keepalive``
     - ``30``
     - SSH keepalive interval in seconds.
   * - ``ssh_config``
     - ``None``
     - ``true`` to load ``~/.ssh/config``, or path to a custom OpenSSH config file.
   * - ``use_agent``
     - ``True``
     - Whether to allow SSH agent authentication.
   * - ``proxy``
     - ``None``
     - Comma-separated bastion jump hosts (e.g. ``proxy=bastion1.corp,bastion2.corp``).
   * - ``proxy_command``
     - ``None``
     - Custom ``ProxyCommand`` string (e.g. ``ssh -W %h:%p jump-box``).
   * - ``system_ssh``
     - ``False``
     - Use local OpenSSH ``ssh`` / ``scp`` binary subprocess instead of ``asyncssh``.

4.2. Windows Remote Management (``winrm://``, ``wsman://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **URI Syntax**: ``winrm://[user[:password]@]host[:5985|5986][?option=value]``
- **Required Extra**: ``uv add "uniconn[winrm]"``

.. list-table::
   :widths: 28 18 54
   :header-rows: 1

   * - Query / Config Option
     - Default
     - Description
   * - ``transport``
     - ``"ntlm"``
     - Auth protocol: ``ntlm``, ``kerberos``, ``credssp``, ``basic``, or ``ssl``.
   * - ``ssl``
     - ``False``
     - Use HTTPS (automatically switches default port from ``5985`` to ``5986``).
   * - ``server_cert_validation``
     - ``"ignore"``
     - TLS certificate validation mode: ``ignore`` or ``validate``.
   * - ``shell``
     - ``"ps"``
     - Default execution shell: ``ps`` (PowerShell) or ``cmd`` (Command Prompt).
   * - ``domain``
     - ``None``
     - Active Directory / NTLM domain name (e.g. ``CORP``).
   * - ``read_timeout_sec``
     - ``40``
     - WinRM HTTP read timeout in seconds.
   * - ``operation_timeout_sec``
     - ``30``
     - WinRM WS-Management operation timeout in seconds.

4.3. Structured Network Transports (``netconf://``, ``restconf://``, ``gnmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **NETCONF Syntax**: ``netconf://[user[:password]@]host[:830][?vendor=default&version=1.1]``
- **RESTCONF Syntax**: ``restconf://[user[:password]@]host[:443][/restconf][?scheme=https&format=json]``
- **gNMI Syntax**: ``gnmi://[user[:password]@]host[:9339][?encoding=json_ietf&origin=openconfig]``

.. list-table::
   :widths: 22 18 16 44
   :header-rows: 1

   * - Option
     - Transport
     - Default
     - Description
   * - ``vendor``
     - ``netconf``
     - ``"default"``
     - Device framing profile: ``default``, ``junos``, ``iosxr``, ``iosxe``, ``eos``, ``sros``, ``huawei``.
   * - ``version``
     - ``netconf``
     - ``"1.1"``
     - NETCONF framing version: ``"1.1"`` (chunked) or ``"1.0"`` (``]]>]]>`` EOM).
   * - ``verify_host_key``
     - ``netconf``
     - ``False``
     - Enforce strict SSH host key verification on port 830.
   * - ``root``
     - ``restconf``
     - ``"/restconf"``
     - RESTCONF API root path (or ``auto`` for ``/.well-known/host-meta`` discovery).
   * - ``format``
     - ``restconf``
     - ``"json"``
     - Payload serialization format: ``json`` (``application/yang-data+json``) or ``xml``.
   * - ``verify_tls``
     - ``restconf``
     - ``False``
     - Verify HTTPS server certificate.
   * - ``encoding``
     - ``gnmi``
     - ``"json_ietf"``
     - gNMI payload encoding: ``json_ietf``, ``json``, ``bytes``, ``proto``, ``ascii``.
   * - ``origin``
     - ``gnmi``
     - ``None``
     - YANG schema origin prefix (e.g. ``openconfig``, ``ietf``).
   * - ``insecure``
     - ``gnmi``
     - ``False``
     - Use plaintext gRPC channel or skip TLS certificate verification.

4.4. Virtualization & Hypervisors (``pve://``, ``qga://``, ``qemu-ga://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Proxmox VE Syntax**: ``pve://[user[@realm][!token_id][:secret]@]host[:8006]/<vmid>[?node=pve1&verify_ssl=false]``
- **QEMU Guest Agent Syntax**: ``qga:///path/to/qga.sock`` or ``qga://[user@]kvm-host[:22]/<vm_name>[?backend=socket|virsh]``

.. list-table::
   :widths: 24 16 16 44
   :header-rows: 1

   * - Option
     - Transport
     - Default
     - Description
   * - ``vmid``
     - ``pve``
     - Path ``/<vmid>``
     - Numeric Proxmox VM ID (e.g. ``105``).
   * - ``node``
     - ``pve``
     - Auto-discovered
     - Proxmox cluster node name (e.g. ``pve1``); auto-discovered via cluster resources if omitted.
   * - ``realm``
     - ``pve``
     - ``"pam"``
     - Authentication realm (``pam``, ``pve``, or custom LDAP/OIDC realm).
   * - ``token_id`` & ``secret``
     - ``pve``
     - ``None``
     - Proxmox API Token ID and UUID secret (for stateless non-ticket auth).
   * - ``backend``
     - ``qga``
     - ``"socket"``
     - Transport channel: ``socket`` (Unix socket local or over SSH) or ``virsh`` (``virsh qemu-agent-command``).
   * - ``socket``
     - ``qga``
     - ``None``
     - Explicit Unix domain socket path for the guest agent channel.
   * - ``libvirt_uri``
     - ``qga``
     - ``"qemu:///system"``
     - Connection URI passed to ``virsh -c`` when ``backend=virsh``.

4.5. Containers & Kubernetes (``docker://``, ``podman://``, ``kubectl://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Container Syntax**: ``docker://[user@]container_name[/workdir][?shell=/bin/sh]`` (same for ``podman://``)
- **Kubernetes Syntax**: ``kubectl://[namespace/]pod_name[?container=app&context=prod&kubeconfig=/path]``

.. list-table::
   :widths: 24 20 16 40
   :header-rows: 1

   * - Option
     - Transport
     - Default
     - Description
   * - ``workdir``
     - ``docker``, ``podman``, ``kubectl``
     - Container default
     - Working directory inside the container or pod.
   * - ``shell``
     - ``docker``, ``podman``, ``kubectl``
     - ``"/bin/sh"``
     - Shell executable used to wrap command strings.
   * - ``namespace``
     - ``kubectl``
     - ``"default"``
     - Kubernetes namespace (can also be specified in URI path ``kubectl://ns/pod``).
   * - ``container``
     - ``kubectl``
     - Default container
     - Target container name in a multi-container Pod (``kubectl exec -c``).
   * - ``context``
     - ``docker``, ``kubectl``
     - Active context
     - Docker CLI context or Kubernetes kubeconfig context name.
   * - ``kubeconfig``
     - ``kubectl``
     - ``~/.kube/config``
     - Path to kubeconfig file.

4.6. Bare-Metal BMC, Serial/UART, Telnet, Replay & Local
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 20 34 46
   :header-rows: 1

   * - Scheme
     - URI Syntax Example
     - Key Query Options
   * - ``redfish://``
     - ``redfish://admin:env://PASS@bmc:443``
     - ``verify_ssl=false``, ``system_id=1``, ``chassis_id=1``, ``manager_id=1``, ``multiplexed=true`` (HTTP/2). Requires ``uniconn[bmc]``.
   * - ``ipmi://``
     - ``ipmi://admin:env://PASS@bmc:623``
     - Supports ``power on|off|cycle|reset|status``, ``sensors``, ``sel list|clear``, ``boot pxe|disk|bios``, ``raw``. Requires ``uniconn[bmc]``.
   * - ``serial://`` / ``uart://``
     - ``uart:///dev/ttyUSB0:115200``
     - ``baudrate=115200``, ``parity=N|E|O``, ``stopbits=1|2``, ``bytesize=8``, ``vid=10c4``, ``pid=ea60``. Requires ``uniconn[serial]``.
   * - ``telnet://``
     - ``telnet://admin:pass@switch:23``
     - ``term_type=vt100``, ``login_prompt=login:``, ``password_prompt=Password:``, ``prompt=#``. Requires ``uniconn[telnet]``.
   * - ``replay://``
     - ``replay://node-01?cassette=test.yaml``
     - ``cassette=/path.yaml``, ``mode=none|once|new_episodes|all``, ``normalize_temp=true``.
   * - ``local://``
     - ``local://?timeout=30&rate_limit=50``
     - Executes commands on the local host (equivalent to ``Connection.local()``).
