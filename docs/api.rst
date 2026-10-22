API Reference
=============

Connection
----------

.. autoclass:: uniconn.Connection
   :members: from_uri, from_config, from_dict, from_file, from_inventory
   :members: run, run_bytes, run_commands, stream, open_shell, close, is_alive
   :members: cd, env, temp_dir, add_hook
   :members: read_file, write_file, exists, mkdir, upload, download, chmod, stat, listdir
   :members: to_sync, copy, with_overrides
   :special-members: __aenter__, __aexit__

ShellSession
------------

.. autoclass:: uniconn.ShellSession
   :members: execute, send, receive, resize, close, is_alive
   :special-members: __aenter__, __aexit__

ConnectionConfig
----------------

.. autoclass:: uniconn.ConnectionConfig
   :members: from_uri
   :members: uri_safe

ConnectionPool
--------------

.. autoclass:: uniconn.ConnectionPool
   :members: from_file, map, map_safe, map_with_callback, upload, download, apply

SSHSessionPool
--------------

.. autoclass:: uniconn.SSHSessionPool
   :members: run, map, check_health, close

SyncConnection
--------------

.. autoclass:: uniconn.SyncConnection
   :members: run, run_bytes, run_commands, stream, open_shell, close, is_alive
   :members: cd, env, temp_dir, add_hook, read_file, write_file, exists, mkdir
   :special-members: __enter__, __exit__

SyncShellSession
----------------

.. autoclass:: uniconn.SyncShellSession
   :members: execute, send, receive, resize, close, is_alive
   :special-members: __enter__, __exit__

Result
------

.. autoclass:: uniconn.Result
   :members: ok, text, lines, json, to_dict, raise_for_status

Hooks
-----

.. autofunction:: uniconn.audit_log_hook
.. autofunction:: uniconn.structured_log_hook
.. autofunction:: uniconn.allowlist_hook
.. autofunction:: uniconn.blocklist_hook
.. autoclass:: uniconn.MetricsCollector
   :members:
.. autofunction:: uniconn.metrics_collector_hook

Exceptions
----------

.. autoexception:: uniconn.UniconnError
.. autoexception:: uniconn.ConnectionError
.. autoexception:: uniconn.AuthenticationError
.. autoexception:: uniconn.ExecutionError
.. autoexception:: uniconn.TimeoutError
.. autoexception:: uniconn.TransportNotFoundError
.. autoexception:: uniconn.BMCCapabilityError

Logging (structlog & stdlib)
----------------------------

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

Transports
----------

.. autoclass:: uniconn.transports._base.BaseTransport
   :members: name, is_connected, connect, disconnect
   :members: run, stream, ping
   :members: upload, download, chmod, stat, listdir

SSH Transport
~~~~~~~~~~~~~

.. autoclass:: uniconn.transports._ssh.SSHTransport
   :members: upload, download, chmod, stat, listdir
   :no-show-inheritance:
