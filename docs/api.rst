API Reference
=============

Connection
----------

.. autoclass:: uniconn.Connection
   :members: from_uri, from_config, from_dict, from_file
   :members: run, stream, close, is_alive
   :members: upload, download, chmod, stat, listdir
   :members: to_sync, copy, with_overrides
   :special-members: __aenter__, __aexit__

ConnectionConfig
----------------

.. autoclass:: uniconn.ConnectionConfig
   :members: from_uri
   :members: uri_safe

ConnectionPool
--------------

.. autoclass:: uniconn.ConnectionPool
   :members: map, map_safe, map_with_callback

SyncConnection
--------------

.. autoclass:: uniconn.SyncConnection
   :members: run, stream, close, is_alive
   :special-members: __enter__, __exit__

Result
------

.. autoclass:: uniconn.Result
   :members: ok, raise_for_status

Exceptions
----------

.. autoexception:: uniconn.UniconnError
.. autoexception:: uniconn.ConnectionError
.. autoexception:: uniconn.AuthenticationError
.. autoexception:: uniconn.ExecutionError
.. autoexception:: uniconn.TimeoutError
.. autoexception:: uniconn.TransportNotFoundError
.. autoexception:: uniconn.BMCCapabilityError

Logging
-------

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
