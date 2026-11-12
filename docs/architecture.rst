Core Architecture, Middleware Pipeline & Call Lifecycle
=======================================================

**Language:** **[ English ]** | `Русский <ru/architecture.rst>`_

This guide explains how ``uniconn`` works under the hood: how ``Connection`` and ``SyncConnection`` maintain 100% API parity with sub-millisecond overhead, the exact execution order of middlewares inside ``CommandPipeline``, how ``conn.run_python()`` achieves ``< 2 ms`` latency without SSH process forks, and how to extend the engine with custom middlewares or transports.

1. High-Level System Architecture
---------------------------------

``uniconn`` is structured around four decoupled layers:

1. **Public Facade & Sync Portal**: ``Connection``, ``ConnectionPool``, ``Flow``, ``ShellSession``, and their synchronous counterparts (``SyncConnection``, ``SyncConnectionPool``, ``SyncFlow``, ``SyncShellSession``).
2. **Domain Services**: ``conn.files`` (``FileOperationsService``), ``conn.path`` (``RemotePath``), ``conn.state`` (``StateManagementService``), ``conn.net`` (``NetworkOperationsService``), ``conn.tunnels`` (``TunnelService``), and ``FactCollector``.
3. **Resilience & Middleware Pipeline (``CommandPipeline``)**: A composable Chain-of-Responsibility pipeline that intercepts every ``CommandRequest`` to apply context, security guardrails, privilege escalation, hooks, dry-run short-circuiting, structured telemetry, root-cause diagnostics, circuit breaking, rate limiting, and exponential retries.
4. **ISP Transport Layer**: Pluggable transport drivers implementing capability protocols (``CommandTransport``, ``FileCapableTransport``, ``ShellCapableTransport``, ``TunnelCapableTransport``, ``StructuredNetworkTransport``).

.. code-block:: text

   ┌────────────────────────────────────────────────────────────────────────────────────────┐
   │                        FACADE & PARADIGM LAYER (ASYNC + SYNC)                          │
   │   Async: Connection / ConnectionPool / Flow / ShellSession / BackgroundPool            │
   │   Sync:  SyncConnection / SyncConnectionPool / SyncFlow (via EventLoopPortal < 0.3ms)  │
   └───────────────────────────────────────────┬────────────────────────────────────────────┘
                                               │
                     ┌─────────────────────────▼──────────────────────────┐
                     │               DOMAIN SERVICES LAYER                │
                     │  • conn.files / conn.path (SFTP, Delta Sync, Hash) │
                     │  • conn.state (Idempotent ensure_*, Diff, Notify)  │
                     │  • conn.net   (NETCONF / RESTCONF / gNMI YANG ops) │
                     │  • conn.run_python (Persistent Zero-Fork RPC)      │
                     └─────────────────────────┬──────────────────────────┘
                                               │
                     ┌─────────────────────────▼──────────────────────────┐
                     │           COMMAND PIPELINE (MIDDLEWARE CHAIN)      │
                     │  1. ContextMiddleware (cd / env)                   │
                     │  2. HITLApprovalMiddleware (optional 2-phase auth) │
                     │  3. PolicyGuardrailMiddleware (optional AST/ABAC)  │
                     │  4. SudoMiddleware (sudo -S / -n + stdin injection)│
                     │  5. HookMiddleware (before_run / after_run)        │
                     │  6. DryRunMiddleware (synthetic Result on dry_run) │
                     │  7. ObservabilityMiddleware (logs, raise_on_error) │
                     │  8. AutoDiagnosticMiddleware (root-cause probes)   │
                     │  9. CircuitBreakerMiddleware (CLOSED/OPEN/HALF)    │
                     │ 10. RateLimitMiddleware (async Token Bucket)       │
                     │ 11. RetryMiddleware (Exponential Backoff + Jitter) │
                     └─────────────────────────┬──────────────────────────┘
                                               │
   ┌───────────────────────────────────────────▼────────────────────────────────────────────┐
   │                        ISP TRANSPORT CAPABILITY PROTOCOLS                              │
   ├──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
   │ Command      │ FileCapable  │ ShellCapable │ TunnelCapable│ StructuredNet│ ReplayProxy │
   │ (run/stream) │ (SFTP/Modem) │ (PTY/Expect) │ (PortFwd)    │ (YANG/gNMI)  │ (Cassettes) │
   └──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘

2. How Async + Sync Parity Works (``EventLoopPortal``)
------------------------------------------------------

Unlike libraries that duplicate their entire codebase for synchronous and asynchronous execution, ``uniconn`` implements all I/O natively using ``asyncio`` and exposes synchronous facades via ``EventLoopPortal`` and ``SyncProxyMixin`` (in ``uniconn.core.bridge``):

- **Background Singleton Loop**: ``EventLoopPortal`` manages a dedicated daemon thread running a persistent ``asyncio`` event loop.
- **Zero-Copy Descriptor Delegation**: Methods on ``SyncConnection``, ``SyncConnectionPool``, and synchronous domain services (``.files``, ``.state``, ``.net``, ``.tunnels``) are declared using typed ``ParamSpec`` descriptors (``sync_method``, ``sync_context``, ``sync_iter``).
- **Safe Cross-Thread Execution**: Calling ``sync_conn.run("uptime")`` submits the coroutine to ``EventLoopPortal`` via ``asyncio.run_coroutine_threadsafe()`` and blocks the caller thread until the ``Result`` is ready—adding less than ``0.25 ms`` of overhead and avoiding ``RuntimeError: This event loop is already running`` even when called from inside Jupyter notebooks or mixed frameworks.

.. tip::

   You can convert any existing async ``Connection`` or ``ConnectionPool`` into its synchronous wrapper at any time by calling ``conn.to_sync()`` or ``pool.to_sync()``.

3. Step-by-Step Lifecycle of ``conn.run()``
-------------------------------------------

When you execute ``await conn.run("systemctl restart nginx", sudo=True, parse="auto", diagnose=True)``, ``Connection`` constructs a mutable ``CommandRequest`` dataclass and passes it through ``conn.pipeline.execute(request)``.

Exact Middleware Execution Order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 6 26 68
   :header-rows: 1

   * - Step
     - Middleware Class
     - Responsibility & Mutation of ``CommandRequest`` / ``Result``
   * - **1**
     - ``ContextMiddleware``
     - Reads the active ``conn.cd()`` directory stack and ``conn.env()`` environment variables from ``conn.context`` and merges them into ``request.transport_kwargs`` (``cwd`` and ``env``).
   * - **2**
     - ``HITLApprovalMiddleware`` *(optional)*
     - If attached and enabled, classifies command risk via ``ActionRiskClassifier``. Blocks ``TIER_3_FORBIDDEN`` commands immediately; for ``REQUIRE_APPROVAL`` commands, verifies an ``approval_id`` HMAC token or creates a pending request (raising ``ApprovalRequiredError`` or waiting for operator decision).
   * - **3**
     - ``PolicyGuardrailMiddleware`` *(optional)*
     - If attached, parses the shell command into an Abstract Syntax Tree (``CommandASTParser``) to unwrap nested ``sudo``/``sh -c``/``base64`` wrappers and evaluates ABAC/OPA rules (raising ``PolicyViolationError`` on ``DENY``).
   * - **4**
     - ``SudoMiddleware``
     - If ``request.sudo=True``, transforms ``request.exec_command`` into ``sudo -S -p '' [-u user] -- sh -c '...'`` (when a password is provided via ``sudo_password`` or ``ConnectionConfig``) and prepends the secret password to ``request.transport_kwargs["input"]``, or uses ``sudo -n`` for passwordless sudo.
   * - **5**
     - ``HookMiddleware``
     - Invokes all registered ``before_run(command, host, transport_kwargs)`` callbacks before downstream execution, and ``after_run(result)`` callbacks after downstream execution completes.
   * - **6**
     - ``DryRunMiddleware``
     - If ``request.dry_run=True`` (or connection-wide ``dry_run=True``), logs ``command.dry_run`` and immediately short-circuits the pipeline, returning a synthetic ``Result(exit_code=0, stdout="", _dry_run=True)`` without touching the network or circuit breaker.
   * - **7**
     - ``ObservabilityMiddleware``
     - Binds ``host``, ``transport``, and ``uri_safe`` to ``structlog`` context, logs ``command.start`` and ``command.finish`` (redacting command text if ``sensitive=True``), invokes ``on_error`` hooks on exception, and calls ``result.raise_for_status()`` if ``raise_on_error=True``.
   * - **8**
     - ``AutoDiagnosticMiddleware``
     - If ``result.exit_code != 0`` and ``diagnose=True`` (or ``conn.auto_diagnostics=True``), runs bounded root-cause probes (within ``timeout_budget=2.0s``) using the platform strategy (Linux, Container, Windows, or Passive) and attaches ``DiagnosticSummary`` to ``result.diagnostic``.
   * - **9**
     - ``CircuitBreakerMiddleware``
     - Checks ``conn.circuit_breaker``. If the circuit is ``OPEN``, immediately raises ``CircuitOpenError`` without network I/O. Records ``record_success()`` on completion or ``record_failure()`` on ``ConnectionError`` / ``TimeoutError``.
   * - **10**
     - ``RateLimitMiddleware``
     - Awaits a token from ``conn.rate_limiter`` (asynchronous Token Bucket) before allowing the request to reach the retry/transport layer.
   * - **11**
     - ``RetryMiddleware``
     - Wraps the terminal transport call in an exponential backoff + jitter retry loop (up to ``conn.retry_attempts``). On ``ConnectionError`` or ``TimeoutError``, logs ``command.retry``, disconnects, reconnects the transport, and retries.
   * - **12**
     - ``_terminal_dispatch`` & Parsing
     - Invokes ``transport.run()`` (or ``transport.run_bytes()``). Once the raw ``Result`` returns through the middleware chain, ``CommandPipeline`` attaches ``parse_spec`` (and eagerly evaluates ``result.parsed`` when a Pydantic model or ``eager_parse=True`` is used).

.. important::

   Understanding middleware order explains key operational guarantees:

   - Because ``HookMiddleware`` (Step 5) sits **before** ``DryRunMiddleware`` (Step 6), your ``before_run`` and ``after_run`` audit hooks still fire during ``dry_run=True`` simulations!
   - Because ``ObservabilityMiddleware`` (Step 7) sits **outside** ``AutoDiagnosticMiddleware`` (Step 8), when ``raise_on_error=True`` raises ``ExecutionError``, ``err.diagnostic`` is **already populated** with the root-cause ``DiagnosticSummary``.
   - Because ``CircuitBreakerMiddleware`` (Step 9) sits **outside** ``RetryMiddleware`` (Step 11), a single ``conn.run()`` call only trips the circuit breaker after all retry attempts for that call have been exhausted.

4. Deep Dive: Core Subsystems
-----------------------------

Zero-Fork Remote Python RPC (``RemotePythonWorker``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standard ``conn.run("python3 -c ...")`` forks a new SSH channel, shell, and Python interpreter on every call (typically ``40–150 ms`` per invocation). ``conn.run_python(fn, *args, **kwargs)`` eliminates this penalty:

1. **Lazy Bootstrap**: On the first ``conn.run_python()`` call, ``RemotePythonWorker`` opens a single persistent background process (``python3 -u -c <bootstrap>``) over a bidirectional stdin/stdout pipe.
2. **Callable Serialization**: ``CallableSerializer`` inspects ``fn``. Standard functions and lambdas are serialized via AST/source extraction or bytecode/pickle framing along with ``args`` and ``kwargs``.
3. **Multiplexed Framing**: Requests and responses are exchanged as length-prefixed JSON/base64 frames over the already-open pipe, achieving ``< 2 ms`` round-trip latency on local/LAN links.
4. **Automatic Recovery**: If a remote function crashes the worker process or exceeds ``timeout``, the worker is transparently respawned on the next call.

Stateful PTY Shells (``PosixMarkerProtocol`` & ``ExpectStateMachine``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When you open an interactive terminal via ``async with await conn.open_shell() as shell:``, commands run inside a single persistent pseudoterminal (PTY) where ``cd``, ``export``, and shell aliases persist across calls:

- **Deterministic Boundary Detection (``PosixMarkerProtocol``)**: Because a raw PTY stream has no out-of-band exit code channel, ``shell.execute("cmd")`` appends a unique UUID marker command (``printf "\n__UNICONN_EOF_<uuid>:%d__\n" $?``). The reader strips terminal echo, ANSI escape sequences, and prompt noise, capturing the exact stdout and integer exit code of the command.
- **Interactive Prompt Automation (``ExpectStateMachine``)**: ``conn.expect()`` and ``shell.expect()`` run a compiled regex state machine over the live stream, matching prompts (such as ``Password:`` or ``[y/N]``) and injecting responses while redacting sensitive inputs from logs and exception tracebacks when ``sensitive=True``.

Interface Segregation for Transports (ISP Protocols)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Not every transport supports every operation (for example, ``ipmi://`` does not support SFTP file transfers or SSH port forwarding). Instead of a monolithic base class with stub methods, ``uniconn.transports.base`` defines granular ``@runtime_checkable`` protocols:

- ``BaseTransport``: Lifecycle (``connect()``, ``disconnect()``, ``is_connected``, ``ping()``).
- ``CommandTransport``: ``run()``, ``run_bytes()``, ``stream()``.
- ``FileCapableTransport``: ``read_file()``, ``write_file()``, ``stat()``, ``listdir()``, ``mkdir()``, ``remove_file()``, ``chmod()``.
- ``ShellCapableTransport``: ``open_shell()`` returning a ``ShellProcessProtocol``.
- ``TunnelCapableTransport``: ``forward_local_port()``, ``forward_remote_port()``.
- ``StructuredNetworkTransport``: ``net_get()``, ``net_edit_config()``, ``net_rpc()``, ``net_subscribe()`` (implemented by ``netconf://``, ``restconf://``, ``gnmi://``).

When a domain service requires a specific capability (e.g., ``conn.tunnels.forward_local_port``), it validates the transport via ``require_capability(transport, TunnelCapableTransport, operation="...")``. If unsupported, ``CapabilityNotSupportedError`` (which inherits from both ``UniconnError`` and ``NotImplementedError``) is raised immediately with a clear message.

5. Extending the Pipeline with Custom Middlewares
-------------------------------------------------

You can inject custom cross-cutting logic (such as custom metrics, ticket validation, or command rewriting) into any ``Connection`` via ``conn.pipeline.add_middleware()`` or ``conn.pipeline.insert_middleware(index, mw)``:

.. code-block:: python

   import time
   from uniconn import Connection, Result
   from uniconn.core.pipeline import CommandRequest, NextHandler

   class SlowCommandAlertMiddleware:
       def __init__(self, threshold_sec: float = 5.0) -> None:
           self.threshold_sec = threshold_sec

       async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
           t0 = time.monotonic()
           result = await call_next(request)
           elapsed = time.monotonic() - t0
           if elapsed > self.threshold_sec:
               print(f"[SLOW COMMAND] {request.command!r} took {elapsed:.2f}s")
           return result

   async with Connection.local() as conn:
       # Insert at index 0 so it wraps the entire pipeline including retries
       conn.pipeline.insert_middleware(0, SlowCommandAlertMiddleware(threshold_sec=1.0))
       res = await conn.run("echo hello")
       assert res.ok
