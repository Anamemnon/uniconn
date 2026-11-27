Inventory Loading & Result Ergonomics
=====================================

Loading host inventories from files with ``Connection.from_file`` and ``ConnectionPool.from_file``, working with ``Result`` helpers (``ok``, ``text``, ``lines``, ``json``), and grouping hosts.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/ergonomics_and_inventory.py``

.. literalinclude:: ../../examples/ergonomics_and_inventory.py
   :language: python
   :linenos:
