Debugging, Exception Hierarchy & Troubleshooting Guide
======================================================

**Language:** **[ English ]** | `Русский <ru/troubleshooting.rst>`_

This guide covers everything you need to diagnose failures, handle exceptions cleanly, enable structured debug logging or OpenTelemetry traces, and resolve common operational issues across SSH, WinRM, ``sudo``, ``RemotePythonWorker``, ``ConnectionPool``, and contract cassettes.

1. Complete Exception Hierarchy (``UniconnError``)
--------------------------------------------------

Every custom exception in ``uniconn`` inherits from ``UniconnError`` and also inherits from the appropriate Python built-in exception (such as ``builtins.ConnectionError``, ``builtins.TimeoutError``, ``ValueError``, ``PermissionError``, or ``NotImplementedError``) so standard ``except ValueError:`` or ``except TimeoutError:`` clauses work seamlessly.

Visual Inheritance Tree
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   Exception
    └── UniconnError (base class: .command, .exit_code, .stdout, .stderr, .host, .diagnostic)
         ├── ConfigurationError (also ValueError)
         │    └── CyclicDependencyError (.cycle)
         ├── ConnectionError (also builtins.ConnectionError)
         │    ├── AuthenticationError
         │    ├── CircuitOpenError (.remaining_seconds)
         │    └── PolicyEngineUnavailableError (.engine_name, .endpoint)
         ├── TimeoutError (also builtins.TimeoutError)
         │    └── ApprovalExpiredError (.approval_id, .approval_request)
         ├── ExecutionError
         │    └── FlowExecutionError (.report, .failed_hosts)
         ├── FileTransferError
         │    └── ModemTransferError
         │         ├── ModemHandshakeTimeoutError
         │         ├── ModemCancelledError
         │         ├── ModemMaxRetriesError
         │         ├── ModemProtocolError
         │         └── ModemChecksumMismatchError
         ├── ParsingError (also ValueError)
         │    ├── ParserNotFoundError (also LookupError)
         │    └── OptionalDependencyError (also ImportError)
         ├── ApprovalError (also PermissionError: .approval_id, .approval_request)
         │    ├── ApprovalRequiredError
         │    ├── ApprovalRejectedError (.decided_by, .decision_reason)
         │    ├── ApprovalExpiredError (also TimeoutError)
         │    ├── ApprovalTamperingError
         │    └── ApprovalAlreadyConsumedError
         ├── PolicyError (also PermissionError)
         │    ├── PolicyViolationError (.decision, .violations, .rule_names, .remediation_hint)
         │    └── PolicyEngineUnavailableError (also ConnectionError)
         ├── BackgroundError
         │    ├── BackgroundBackendError
         │    ├── BackgroundSessionExistsError
         │    ├── BackgroundPoolFullError
         │    └── HardwareFaultDetectedError (.match, .matches)
         ├── CassetteError
         │    └── CassetteMissError (.kind, .command, .host, .candidates)
         ├── BatchAbortedError (.batch_index, .fail_ratio, .max_fail_ratio, .completed_results, .failed_hosts)
         ├── CapabilityNotSupportedError (also NotImplementedError)
         ├── BMCCapabilityError
         └── TransportNotFoundError

Exception Attributes Quick Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 28 32 40
   :header-rows: 1

   * - Exception Class
     - Key Attributes on Instance
     - When It Is Raised & How to Handle
   * - ``UniconnError`` / ``ExecutionError``
     - ``.command``, ``.exit_code``, ``.stdout``, ``.stderr``, ``.host``, ``.diagnostic``
     - Raised by ``conn.run(..., raise_on_error=True)`` or ``result.raise_for_status()`` when ``exit_code != 0``. Inspect ``err.stderr`` and ``err.diagnostic``.
   * - ``ConfigurationError``
     - ``.message``
     - Invalid URI scheme, missing ``env://`` / ``file://`` secret without ``?default=``, or unsupported inventory file extension.
   * - ``CyclicDependencyError``
     - ``.cycle`` (``list[str]``)
     - Raised when building a ``Flow`` DAG whose ``@task(depends_on=...)`` graph contains a cycle (e.g. ``['a', 'b', 'a']``).
   * - ``CircuitOpenError``
     - ``.host``, ``.remaining_seconds``, ``.command``
     - ``CircuitBreaker`` is ``OPEN`` due to repeated network failures. Wait ``err.remaining_seconds`` or call ``conn.circuit_breaker.reset()``.
   * - ``BatchAbortedError``
     - ``.batch_index``, ``.fail_ratio``, ``.max_fail_ratio``, ``.completed_results``, ``.failed_hosts``
     - Wave rollout in ``ConnectionPool`` exceeded ``max_fail_ratio``. Inspect ``err.failed_hosts`` to roll back or retry failed nodes.
   * - ``FlowExecutionError``
     - ``.report`` (``FlowReport``), ``.failed_hosts``
     - Raised by ``flow_report.raise_for_status()`` when one or more tasks failed during ``run_flow()``.
   * - ``CassetteMissError``
     - ``.kind``, ``.command``, ``.host``, ``.candidates``
     - Replay cassette did not find a matching recorded interaction. Inspect ``err.candidates`` to see closest recorded commands.
   * - ``ApprovalRequiredError``
     - ``.approval_id``, ``.approval_request``
     - HITL policy paused execution pending human approval. Approve via ``uniconn approval approve <id>`` and re-run with ``approval_id=err.approval_id``.
   * - ``PolicyViolationError``
     - ``.decision``, ``.violations``, ``.rule_names``, ``.remediation_hint``
     - ``CommandASTParser`` or ``PolicyEngine`` blocked a dangerous or unauthorized command. Check ``err.remediation_hint``.
   * - ``CapabilityNotSupportedError``
     - ``.message``
     - Operation (e.g. SFTP or port forwarding) is not supported by the active transport scheme.

2. Automatic Root-Cause Diagnostics (``diagnose=True``)
-------------------------------------------------------

By default, ``conn.run()`` returns a ``Result`` without throwing an exception when a command exits with a non-zero status (``res.ok == False``). When you pass ``diagnose=True`` to ``conn.run()`` (or enable ``auto_diagnostics=True`` on ``Connection`` / ``ConnectionPool``), ``AutoDiagnosticMiddleware`` automatically runs bounded, read-only probes within a strict time budget (default ``2.0s``) to classify the failure:

.. list-table::
   :widths: 28 32 40
   :header-rows: 1

   * - ``ErrorCategory``
     - What ``ErrorClassifier`` Detects
     - Automatic Probes & Populated Fields on ``res.diagnostic``
   * - ``PORT_CONFLICT``
     - ``EADDRINUSE``, ``Address already in use``, ``bind() failed``
     - Runs ``ss -tlpn`` / ``netstat`` (or ``Get-NetTCPConnection`` on Windows) to populate ``diag.port_conflict`` (``.port``, ``.conflicting_pid``, ``.conflicting_process``).
   * - ``DISK_FULL``
     - ``No space left on device``, ``ENOSPC``, exhausted inodes
     - Collects ``df -Pm / /tmp`` and ``df -Pi /`` into ``diag.vitals`` (``.disk_root_free_mb``, ``.disk_root_inodes_free``).
   * - ``OUT_OF_MEMORY``
     - ``exit_code == 137`` (SIGKILL), ``Out of memory``, ``oom-killer``
     - Reads ``/proc/meminfo``, cgroup ``memory.events`` (``oom_kill`` count in containers), and ``dmesg`` OOM lines into ``diag.dmesg_tail``.
   * - ``PACKAGE_LOCK_CONFLICT``
     - ``Could not get lock /var/lib/dpkg/lock-frontend`` or ``yum.pid``
     - Extracts locking PID and process name and suggests ``fuser -v`` / ``dpkg --configure -a``.
   * - ``SERVICE_CRASH``
     - ``Job for <unit>.service failed``, ``status=1/FAILURE``
     - Queries ``journalctl -u <unit> -n 25`` and performs **cascading reclassification** (e.g. upgrading ``SERVICE_CRASH`` to ``PORT_CONFLICT`` or ``CONFIG_SYNTAX_ERROR`` if found in unit logs!).
   * - ``CONFIG_SYNTAX_ERROR``
     - ``syntax error on line``, ``configtest failed``, ``nginx: [emerg]``
     - Extracts the offending config file path and suggests validation commands.
   * - ``PERMISSION_DENIED``
     - ``Permission denied``, ``EACCES``, ``sudo: a password is required``
     - Probes ``id -un``, ``ls -ld <path>``, and SELinux ``getenforce``.
   * - ``COMMAND_NOT_FOUND``
     - ``exit_code == 127``, ``command not found``
     - Extracts the missing binary name and suggests ``conn.state.ensure_package()``.
   * - ``NETWORK_UNREACHABLE``
     - ``Connection refused``, ``Name or service not known``, ``No route to host``
     - Suggests DNS and routing table checks.

.. code-block:: python

   from uniconn import Connection

   async with Connection.from_uri("ssh://admin@node-01", auto_diagnostics=True) as conn:
       res = await conn.run("systemctl start nginx", sudo=True)
       if not res.ok and res.diagnostic:
           print("Category:", res.diagnostic.category.value)
           print("Root Cause:", res.diagnostic.root_cause_hint)
           for step in res.diagnostic.suggested_actions:
               print(" -> Fix:", step)

3. Enabling Debug Logging, Audit Hooks & OpenTelemetry
------------------------------------------------------

1. **Structured Debug Logging (``structlog``)**:

   .. code-block:: python

      from uniconn import configure_logging, setup_file_logging

      # Print human-readable or JSON debug events (command.start, command.retry, command.finish)
      configure_logging(level="DEBUG", json_format=False)

      # Or write rotating audit logs to disk with automatic secret masking
      setup_file_logging("/var/log/uniconn-debug.log", level="DEBUG")

2. **In-Memory Distributed Tracing (``InMemoryTracer`` & ``otel_tracing_hook``)**:

   .. code-block:: python

      from uniconn import Connection, InMemoryTracer, otel_tracing_hook

      tracer = InMemoryTracer()
      async with Connection.local() as conn:
          otel_tracing_hook(conn, tracer=tracer)
          await conn.run("uname -a")

      for span in tracer.spans:
          print(span.name, span.attributes, span.duration_ms)

4. Common Problems & Solutions Matrix (Symptom → Cause → Fix)
-------------------------------------------------------------

4.1. ``cd /some/dir`` does not persist to the next ``conn.run()`` call
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: Running ``await conn.run("cd /var/www")`` followed by ``await conn.run("pwd")`` still prints the home directory.
- **Cause**: Each ``conn.run()`` executes in a fresh, isolated subprocess/channel so concurrent ``asyncio.gather(conn.run(...), conn.run(...))`` calls never corrupt each other's working directory.
- **Solution**: Use the ``with conn.cd("/var/www"):`` context manager (which is concurrency-safe via ``ContextVar``), or open a stateful PTY session with ``async with await conn.open_shell() as shell:`` where ``await shell.execute("cd /var/www")`` persists across commands.

4.2. ``sudo: a password is required`` or ``sudo: a terminal is required``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: Commands with ``sudo=True`` fail with exit code 1 and stderr ``sudo: a password is required``.
- **Cause**: The remote user does not have ``NOPASSWD: ALL`` in ``/etc/sudoers``, so ``SudoMiddleware`` defaulted to non-interactive ``sudo -n`` because no sudo password was configured.
- **Solution**: Pass ``sudo_password="env://SUDO_PASS"`` in the URI query string (``ssh://user@host?sudo_password=env://SUDO_PASS``), in the inventory ``options``, or directly in ``conn.run("...", sudo=True, sudo_password=...)``. ``SudoMiddleware`` will automatically switch to ``sudo -S -p ''`` and pipe the password safely via ``stdin`` without exposing it in process ``ps`` arguments.

4.3. SSH Host Key Verification Failure in CI/CD or Container Environments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: ``ConnectionError`` during SSH handshake when connecting to newly provisioned cloud VMs or containers.
- **Cause**: Strict host key checking rejected an unknown or rotated host key.
- **Solution**: Pass ``?known_hosts=accept_new`` (default for new hosts) or ``?known_hosts=none`` for ephemeral test containers: ``ssh://root@172.17.0.2?known_hosts=none``.

4.4. ``CassetteMissError`` when Replaying Tests with Temporary Files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: ``conn.files.write_file(..., atomic=True)`` or ``conn.run_script()`` raises ``CassetteMissError`` during offline cassette replay because the temporary file suffix (e.g., ``/tmp/.uniconn-tmp-8f9a1b``) changed between recording and replay.
- **Cause**: Random temporary paths generated during atomic writes or script uploads did not match the literal path recorded in the cassette.
- **Solution**: Enable ``normalize_temp=True`` (enabled by default in ``use_cassette(..., normalize_temp=True)`` and ``replay://...?normalize_temp=true``). Inspect ``err.candidates`` on ``CassetteMissError`` to see the closest recorded commands in the YAML file.

4.5. ``CircuitOpenError`` or ``BatchAbortedError`` During Fleet Rollouts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: ``ConnectionPool.map()`` aborts mid-rollout with ``BatchAbortedError``, or subsequent calls to a host fail immediately with ``CircuitOpenError``.
- **Cause**: One or more hosts in the wave failed, exceeding ``max_fail_ratio`` (or exceeding ``circuit_breaker_threshold`` consecutive connection errors).
- **Solution**:
  - Catch ``BatchAbortedError`` and inspect ``err.completed_results`` (hosts that succeeded) and ``err.failed_hosts`` (hosts that failed in ``err.batch_index``).
  - If you want all hosts to run without wave aborting and receive errors as values in the returned dictionary, use ``await pool.map_safe("cmd")`` instead of ``await pool.map("cmd")``.
  - To manually reset a tripped circuit breaker after fixing a host, call ``conn.circuit_breaker.reset()``.

4.6. ``TransportNotFoundError`` or ``OptionalDependencyError``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **Symptom**: Using ``winrm://``, ``redfish://``, ``ipmi://``, ``uart://``, ``telnet://``, or ``parse="jc:..."`` raises ``TransportNotFoundError`` or ``OptionalDependencyError``.
- **Cause**: Core ``uniconn`` keeps its dependency footprint minimal and loads specialized protocol libraries lazily.
- **Solution**: Install the matching extra:

  - ``winrm://`` / ``wsman://``: ``uv add "uniconn[winrm]"``
  - ``redfish://`` / ``ipmi://``: ``uv add "uniconn[bmc]"``
  - ``serial://`` / ``uart://``: ``uv add "uniconn[serial]"``
  - ``telnet://``: ``uv add "uniconn[telnet]"``
  - ``jc`` / ``textfsm`` / ``ttp`` parsers: ``uv add "uniconn[parsing]"``
  - Everything at once: ``uv add "uniconn[all]"``
