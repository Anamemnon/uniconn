Basic Usage (Async & Sync)
==========================

Connecting with ``Connection.from_uri`` and ``SyncConnection``, resolving ``env://`` secrets via ``SecretResolver``, running commands, streaming output, and cloning connections with ``copy()``.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Works identically on Linux, macOS, and Windows (``local://`` in ``main()``)
- **Run**: ``uv run python examples/basic_usage.py``

.. literalinclude:: ../../examples/basic_usage.py
   :language: python
   :linenos:
