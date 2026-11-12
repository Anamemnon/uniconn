Transports & Secret Resolution (16+ Schemes)
============================================

**Language:** **[ English ]** | `Русский <ru/inventory_and_uris.rst>`_

Every connection in ``uniconn`` is described by a standardized URI scheme or a ``ConnectionConfig`` object. All schemes support dynamic secret resolution via ``SecretResolver``. For complete YAML/TOML/JSON inventory schemas and exhaustive query parameter tables, see :doc:`inventory_and_uris`.

Dynamic Secret Resolution (``env://`` & ``file://``)
----------------------------------------------------

Passwords, SSH key paths, passphrases, Proxmox API tokens, and sudo passwords in both URIs and inventory files (YAML/TOML/JSON) support ``env://VAR_NAME[?default=fallback]`` and ``file:///path/to/secret[?default=fallback]``. Missing secrets without a ``?default=`` raise ``ConfigurationError`` before any network socket is opened:

.. code-block:: python

   from uniconn import Connection

   conn = Connection.from_uri(
       "ssh://admin:env://SSH_PASS?default=fallback@node-01:22"
       "?key_file=file:///run/secrets/id_ed25519"
   )

Complete Transport URI Matrix
-----------------------------

1. SSH (``ssh://``)
~~~~~~~~~~~~~~~~~~~

Full-featured SSHv2 transport with SFTP, stateful PTY shells, jump-host chains, OpenSSH ``~/.ssh/config`` parsing, and port forwarding.

- **URI Format**: ``ssh://[user[:password]@]host[:22][?option=value]``
- **Key Query Options**: ``key_file``, ``passphrase``, ``known_hosts=strict|accept_new|none``, ``keepalive=30``, ``ssh_config=true``, ``use_agent=true``, ``proxy=bastion1,bastion2``, ``proxy_command=...``, ``rate_limit=10``, ``circuit_breaker_threshold=5``, ``auto_diagnostics=true``.

.. code-block:: python

   conn = Connection.from_uri("ssh://deploy@prod-web-01?key_file=~/.ssh/id_ed25519&proxy=bastion.internal")

2. Windows Remote Management (``winrm://`` / ``wsman://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Agentless Windows PowerShell Remoting and CMD execution, file transfer, fact collection, and Windows state provisioning.

- **URI Format**: ``winrm://[user[:password]@]windows-host[:5985|5986][?option=value]``
- **Key Query Options**: ``transport=ntlm|kerberos|credssp|basic|ssl``, ``ssl=true|false``, ``server_cert_validation=ignore|validate``, ``shell=ps|cmd``, ``domain=CORP``.

.. code-block:: python

   conn = Connection.from_uri("winrm://Administrator:env://WIN_PASS@win-srv-01:5986?ssl=true&transport=ntlm&shell=ps")

3. Structured Network Protocols (``netconf://``, ``restconf://``, ``gnmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Model-driven network management supporting ``conn.net.get()``, ``conn.net.set()``, ``conn.net.rpc()``, ``conn.net.subscribe()``, and idempotent ``conn.state.ensure_yang()`` with candidate locking and unified YANG diffs.

- **NETCONF (RFC 6241 over SSH)**:
  ``netconf://[user[:password]@]host[:830][?vendor=default|junos|iosxr|iosxe|eos|sros|huawei&version=1.1|1.0&verify_host_key=false]``
- **RESTCONF (RFC 8040 over HTTP/HTTPS)**:
  ``restconf://[user[:password]@]host[:443][/restconf][?scheme=https|http&root=auto|/restconf&verify_tls=false&format=json|xml]``
- **gNMI (gRPC Network Management Interface)**:
  ``gnmi://[user[:password]@]host[:9339][?insecure=true|false&encoding=json_ietf|json|proto&origin=openconfig&target=...]``

.. code-block:: python

   netconf_conn = Connection.from_uri("netconf://admin:env://NET_PASS@core-rtr-01:830?vendor=junos")
   restconf_conn = Connection.from_uri("restconf://admin:env://NET_PASS@edge-sw-01?verify_tls=false&format=json")
   gnmi_conn = Connection.from_uri("gnmi://admin:env://NET_PASS@spine-01:9339?origin=openconfig")

4. Virtualization & Hypervisors (``pve://``, ``qga://`` / ``qemu-ga://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute commands and manage files inside virtual machines via hypervisor guest agents without requiring in-guest network connectivity.

- **Proxmox VE API + Guest Agent (``pve://``)**:
  ``pve://[user[@realm][!token_id][:password]@]pve-host[:8006]/<vmid>[?node=pve1&token_id=uniconn&secret=env://PVE_SECRET&verify_ssl=false]``
  Supports guest exec/file I/O plus hypervisor commands: ``pve power status|start|stop|shutdown|reboot|reset`` and ``pve snapshot list|create|rollback|delete``.
- **QEMU Guest Agent (``qga://`` / ``qemu-ga://``)**:
  ``qga:///var/lib/libvirt/qemu/channel/target/domain-1-vm1/org.qemu.guest_agent.0`` or ``qga://root@kvm-host-01/vm-prod-01[?backend=socket|virsh&libvirt_uri=qemu:///system]``.

.. code-block:: python

   pve_vm = Connection.from_uri("pve://root@pam!automation:env://PVE_TOKEN@pve-cluster:8006/105?node=pve1")
   qga_vm = Connection.from_uri("qga://root@kvm-node-01/vm-db-01?backend=virsh")

5. Containers & Kubernetes (``docker://``, ``podman://``, ``kubectl://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execute commands, stream logs, open PTY shells, and synchronize files directly inside containers and Kubernetes pods.

- **Docker**: ``docker://[user@]container_name_or_id[?workdir=/app&shell=/bin/sh&context=...]``
- **Podman**: ``podman://[user@]container_name_or_id[?workdir=/srv&shell=/bin/sh]``
- **Kubernetes**: ``kubectl://[namespace/]pod_name[?container=api&context=prod-cluster&kubeconfig=/path/config&workdir=/app]``

.. code-block:: python

   docker_conn = Connection.from_uri("docker://root@redis-cache?workdir=/data")
   k8s_conn = Connection.from_uri("kubectl://production/api-deployment-7f8b9-x2k?container=api")

6. Bare-Metal BMC Controllers (``redfish://``, ``ipmi://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Out-of-band chassis power management, thermal/fan sensor inspection, System Event Log (SEL) auditing, and PXE boot device configuration.

- **DMTF Redfish HTTP/2**: ``redfish://[user[:password]@]bmc-host[:443][?verify_ssl=false&system_id=1&chassis_id=1&manager_id=1&multiplexed=true]``
- **IPMI v2.0 LAN+**: ``ipmi://[user[:password]@]bmc-host[:623]``
- **Supported Commands**: ``power on|off|cycle|reset|shutdown|status``, ``sensors`` / ``health``, ``sel list|clear``, ``boot pxe|disk|bios|cdrom [once|continuous] [uefi|legacy]``, ``raw <netfn> <cmd>``.

7. Serial / UART & Bootloader Flashing (``serial://``, ``uart://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Direct RS-232 / UART communication with hardware DTR/RTS pin pulsing, BREAK signal generation, binary Modbus RTU framing, and XMODEM/YMODEM/ZMODEM file transfers.

- **URI Format**: ``uart:///dev/ttyUSB0[:115200][?parity=N&stopbits=1]`` or ``uart://COM3[?vid=10c4&pid=ea60]``

8. Telnet (``telnet://``), Replay Cassettes (``replay://``) & Local (``local://``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Telnet**: ``telnet://[user[:password]@]switch.local[:23][?term_type=vt100]``
- **Replay (Contract Testing)**: ``replay://node-01[?cassette=tests/cassettes/node.yaml&mode=none&normalize_temp=true]``
- **Local Subprocess / PTY**: ``local://[?timeout=30&rate_limit=50]`` (or ``Connection.local()``)
