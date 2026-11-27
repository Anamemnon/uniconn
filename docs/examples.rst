Runnable Example Scripts
========================

**Language:** **[ English ]** | :doc:`Русский <ru/examples>`

Every script in ``examples/`` is self-contained, runs cleanly offline without live hardware (via ``local://``, ``replay://`` cassettes, or in-process ``uniconn.mock`` servers), and is executed in our CI architecture suite (``uv run python examples/<script>.py``). For task-oriented recipes, see :doc:`cookbook`.

Overview Table
--------------

.. list-table::
   :widths: 28 38 34
   :header-rows: 1

   * - Scenario
     - Key APIs & Capabilities
     - Page & Source File(s)
   * - Getting Started (Async & Sync)
     - ``Connection.from_uri``, ``SyncConnection``, ``SecretResolver``, ``run``, ``stream``, ``copy``
     - :doc:`examples/basic` (``basic_usage.py``)
   * - Inventory & Result Ergonomics
     - ``from_file``, ``ConnectionPool`` groups, ``Result`` helpers
     - :doc:`examples/inventory` (``ergonomics_and_inventory.py``)
   * - File Transfer & Delta Sync
     - ``conn.files``, ``conn.path``, ``atomic=True``, ``checksum``, ``sync_dir``, ``write_template``
     - :doc:`examples/file_transfer` (``file_transfer.py``)
   * - Interactive PTY Shell & Expect
     - ``conn.open_shell``, ``shell.execute``, ``conn.expect``, ``SyncShellSession``
     - :doc:`examples/shell` (``interactive_shell.py``)
   * - Health Checks & Wait Primitives
     - ``ping``, ``is_alive``, ``wait_for_connection``, ``wait_for_port``, ``wait_for_path``
     - :doc:`examples/health_check` (``health_check.py``)
   * - Fleet Parallelism & Wave Rollout
     - ``ConnectionPool.map``, ``batch_size``, ``max_fail_ratio``, ``select``, ``pool.stream``
     - :doc:`examples/parallel` (``parallel_execution.py``)
   * - Idempotent State, Facts & Stress Diagnostics
     - ``conn.state.ensure_*``, ``gather_facts``, ``diff_facts``, ``diagnostic_session``
     - :doc:`examples/provisioning` (``provisioning_and_facts.py``, ``stress_test_diagnostics.py``, ``stress_test_diagnostics.yaml``)
   * - Resilience, Pools & SSH Tunnels
     - ``CircuitBreaker``, ``RateLimiter``, ``SSHSessionPool``, ``conn.tunnels``
     - :doc:`examples/resilience` (``resilience_rollout_and_waiters.py``)
   * - Background Tasks & Reactive Log Watchdogs
     - ``BackgroundPool``, ``tmux``/``screen``/``nohup``, ``PatternTriggerHandler``, ``LogWatchRule``
     - :doc:`examples/background` (``screen_monitoring.py``, ``screen_pool_config.yaml``, ``reactive_log_watchdog_sct.py``, ``telecom_bs_sct_diagnostics.yaml``)
   * - Windows (``winrm://``) & State Provisioning
     - ``ensure_windows_service``, ``ensure_registry_key``, ``ensure_windows_feature``, ``SyncConnection``
     - :doc:`examples/winrm` (``windows_winrm_management.py``)
   * - QEMU Guest Agent (``qga://``)
     - ``MockQgaServer``, ``backend=tcp`` (``127.0.0.1:port``), Named Pipe & UNIX socket
     - :doc:`examples/qemu_qga` (``qemu_guest_agent.py``)
   * - Network YANG & Telemetry
     - ``netconf://``, ``restconf://`` (SSE), ``gnmi://`` (HTTP/2 gRPC ``jh2``), ``conn.net``
     - :doc:`examples/network_yang` (``network_yang_telemetry.py``)
   * - Bare-Metal BMC (Redfish & IPMI)
     - ``redfish://``, ``ipmi://``, power, sensors, ``VirtualMedia``, ``SecureBoot``, ``raw``
     - :doc:`examples/bmc` (``bmc_management.py``)
   * - Serial / UART & XMODEM Flashing
     - ``serial://``, ``uart://``, Windows ``io_backend=threaded``, ``pulse_dtr_rts``, ``send_break``, ``upload_xmodem``
     - :doc:`examples/serial_uart` (``serial_uart_hardware.py``)
   * - Security Hooks, Logging & Telemetry
     - ``allowlist_hook``, ``blocklist_hook``, ``otel_tracing_hook``, ``configure_logging``
     - :doc:`examples/security_telemetry` (``security_and_hooks.py``, ``structured_logging_telemetry.py``)
   * - Offline Contract Testing (Cassettes)
     - ``use_cassette``, ``pool.use_cassette``, ``Cassette.diff``, pytest plugin
     - :doc:`examples/cassettes` (``contract_testing_cassettes.py``)
   * - Custom Transport Plugin
     - Subclassing ``BaseTransport``, registering via ``entry_points``
     - :doc:`examples/custom_transport` (``custom_transport.py``)

.. toctree::
   :maxdepth: 1
   :caption: Example Walkthroughs:

   examples/basic
   examples/inventory
   examples/file_transfer
   examples/shell
   examples/health_check
   examples/parallel
   examples/provisioning
   examples/resilience
   examples/background
   examples/winrm
   examples/qemu_qga
   examples/network_yang
   examples/bmc
   examples/serial_uart
   examples/security_telemetry
   examples/cassettes
   examples/custom_transport
