File Transfer, Checksums & Delta Sync
=====================================

Managing remote files via ``conn.files`` and ``conn.path()``: atomic writes (``atomic=True``), SHA-256 verification (``checksum()`` / ``verify=True``), directory delta synchronization (``sync_dir()``), and template rendering (``write_template()``).

- **Requirements**: Core ``uniconn`` (optional ``uniconn[templates]`` for Jinja2 templates)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/file_transfer.py``

.. literalinclude:: ../../examples/file_transfer.py
   :language: python
   :linenos:
