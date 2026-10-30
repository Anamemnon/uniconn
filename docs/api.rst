API Reference
=============

Connection & SyncConnection
---------------------------

.. autoclass:: uniconn.Connection
   :members: from_uri, from_config, from_dict, from_file, from_inventory, local
   :members: run, run_bytes, run_commands, run_script, stream, expect, open_shell, close
   :members: is_alive, ping, wait_for_connection, wait_for_port, wait_for_path
   :members: gather_facts, diagnostic_session, use_cassette
   :members: files, state, tunnels, pipeline
   :members: cd, env, temp_dir, add_hook, to_sync, copy, with_overrides
   :special-members: __aenter__, __aexit__

.. autoclass:: uniconn.SyncConnection
   :members: from_uri, from_config, from_dict, from_file, from_inventory, local
   :members: run, run_bytes, run_commands, run_script, stream, expect, open_shell, close
   :members: is_alive, ping, wait_for_connection, wait_for_port, wait_for_path
   :members: gather_facts, diagnostic_session, use_cassette
   :members: files, state, tunnels
   :members: cd, env, temp_dir, add_hook, copy, with_overrides
   :special-members: __enter__, __exit__

Domain Services (Files, State & Tunnels)
----------------------------------------

.. autoclass:: uniconn.FileOperationsService
   :members: read_file, write_file, remove_file, exists, mkdir, upload, download, checksum, chmod, stat, listdir, sync_dir, write_template

.. autoclass:: uniconn.StateManagementService
   :members: ensure_package, ensure_service, ensure_file, ensure_directory, ensure_line, ensure_user, ensure_authorized_key, ensure_systemd_unit, ensure_sysctl

.. autoclass:: uniconn.TunnelService
   :members: forward_local_port, forward_remote_port

ConnectionPool, SSHSessionPool & BackgroundPool
-----------------------------------------------

.. autoclass:: uniconn.ConnectionPool
   :members: from_file, select, use_cassette, map, map_safe, map_with_callback, apply, stream
   :members: ping, wait_for_connection, wait_for_port, wait_for_path, run_script, gather_facts, diff_facts
   :members: files, state, to_sync

.. autoclass:: uniconn.SyncConnectionPool
   :members: from_file, select, use_cassette, map, map_safe, apply, stream, ping, gather_facts, diff_facts, files, state

.. autoclass:: uniconn.SSHSessionPool
   :members: run, map, resize, stats, check_health, close

.. autoclass:: uniconn.BackgroundPool
   :members: from_file, start, poll_status, poll_logs, wait_all, stop_all, disconnect

ShellSession & SyncShellSession
-------------------------------

.. autoclass:: uniconn.ShellSession
   :members: execute, expect, send, receive, resize, close, is_alive
   :special-members: __aenter__, __aexit__

.. autoclass:: uniconn.SyncShellSession
   :members: execute, expect, send, receive, resize, close, is_alive
   :special-members: __enter__, __exit__

Configuration, Resilience & Results
-----------------------------------

.. autoclass:: uniconn.ConnectionConfig
   :members: from_uri, uri_safe

.. autoclass:: uniconn.SecretResolver
   :members: resolve_str, resolve_secret, resolve_data

.. autoclass:: uniconn.CircuitBreaker
   :members: state, record_success, record_failure, allow_request, reset

.. autoclass:: uniconn.RateLimiter
   :members: acquire

.. autoclass:: uniconn.Result
   :members: ok, text, lines, json, to_dict, raise_for_status

.. autoclass:: uniconn.PingResult
   :members: to_dict

.. autoclass:: uniconn.SyncResult
   :members: to_dict

.. autoclass:: uniconn.EnsureResult
   :members: to_dict

.. autoclass:: uniconn.HostFacts
   :members: to_dict

.. autoclass:: uniconn.FactsDiffReport
   :members: to_dict

.. autoclass:: uniconn.Cassette
   :members: load, save, diff, verify, sanitize

.. autoclass:: uniconn.CassetteDiffReport
   :members: to_dict

Hooks, Telemetry & Logging
--------------------------

.. autofunction:: uniconn.audit_log_hook
.. autofunction:: uniconn.structured_log_hook
.. autofunction:: uniconn.allowlist_hook
.. autofunction:: uniconn.blocklist_hook
.. autoclass:: uniconn.MetricsCollector
   :members:
.. autofunction:: uniconn.metrics_collector_hook
.. autofunction:: uniconn.otel_tracing_hook
.. autoclass:: uniconn.InMemoryTracer
   :members:
.. autofunction:: uniconn.configure_logging
.. autofunction:: uniconn.get_struct_logger
.. autofunction:: uniconn.log_context
.. autofunction:: uniconn.bind_log_context
.. autofunction:: uniconn.unbind_log_context
.. autofunction:: uniconn.clear_log_context
.. autofunction:: uniconn.get_log_context
.. autofunction:: uniconn.get_logger
.. autofunction:: uniconn.setup_file_logging
.. autoclass:: uniconn.SecretMaskingFilter
   :members:

Exceptions
----------

.. autoexception:: uniconn.UniconnError
.. autoexception:: uniconn.ConfigurationError
.. autoexception:: uniconn.ConnectionError
.. autoexception:: uniconn.CircuitOpenError
.. autoexception:: uniconn.BatchAbortedError
.. autoexception:: uniconn.CassetteError
.. autoexception:: uniconn.CassetteMissError
.. autoexception:: uniconn.AuthenticationError
.. autoexception:: uniconn.ExecutionError
.. autoexception:: uniconn.FileTransferError
.. autoexception:: uniconn.TimeoutError
.. autoexception:: uniconn.TransportNotFoundError
.. autoexception:: uniconn.CapabilityNotSupportedError
.. autoexception:: uniconn.BMCCapabilityError
.. autoexception:: uniconn.BackgroundError

Transports
----------

.. autoclass:: uniconn.BaseTransport
   :members: name, is_connected, connect, disconnect, run, stream, ping
