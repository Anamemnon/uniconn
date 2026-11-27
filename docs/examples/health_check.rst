Health Checks & Wait Primitives
===============================

Verifying node reachability and waiting for readiness across fleets: ``ping()``, ``is_alive()``, ``wait_for_connection()``, ``wait_for_port()``, and ``wait_for_path()``.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/health_check.py``

.. literalinclude:: ../../examples/health_check.py
   :language: python
   :linenos:
