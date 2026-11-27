Parallel Execution & Wave Rollouts
==================================

Running commands across multi-host fleets with ``ConnectionPool.map()``, ``map_safe()``, ``select()``, ``pool.stream()``, and bounded wave rollouts (``batch_size``, ``max_fail_ratio``, ``BatchAbortedError``).

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/parallel_execution.py``

.. literalinclude:: ../../examples/parallel_execution.py
   :language: python
   :linenos:
