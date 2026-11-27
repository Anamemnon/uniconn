Custom Transport Plugin
=======================

Implementing a third-party transport by subclassing ``BaseTransport`` (``connect()``, ``disconnect()``, ``run()``, ``stream()``, ``ping()``) and registering it via ``uniconn.transports`` ``entry_points``.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/custom_transport.py``

.. literalinclude:: ../../examples/custom_transport.py
   :language: python
   :linenos:
