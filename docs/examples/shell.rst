Interactive PTY Shell & Expect Dialogs
======================================

Stateful PTY terminal sessions (``conn.open_shell()``, ``SyncShellSession``) preserving ``cd`` and ``export`` across calls, plus automated interactive prompt handling via ``conn.expect()`` and ``shell.expect()`` with ``sensitive=True`` secret masking.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (includes Windows-compatible replay/shell flow)
- **Run**: ``uv run python examples/interactive_shell.py``

.. literalinclude:: ../../examples/interactive_shell.py
   :language: python
   :linenos:
