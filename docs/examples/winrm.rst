Windows Remote Management (WinRM / WS-Management)
=================================================

Managing Windows nodes via ``winrm://`` and ``wsman://``, executing PowerShell and CMD commands, enforcing idempotent Windows state (``ensure_windows_service``, ``ensure_registry_key``, ``ensure_windows_feature``), and running synchronous workflows via ``SyncConnection``.

- **Requirements**: ``uv add "uniconn[winrm]"`` (for live WinRM hosts; offline ``main()`` runs via ``replay://``)
- **Platform Notes**: Works from Linux, macOS, and Windows control hosts
- **Run**: ``uv run python examples/windows_winrm_management.py``

.. literalinclude:: ../../examples/windows_winrm_management.py
   :language: python
   :linenos:
