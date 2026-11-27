Contract Testing & Cassettes
============================

Recording and deterministic offline replay of transport interactions via ``use_cassette()``, fleet cassette replay with ``ConnectionPool.use_cassette()``, and regression drift comparison with ``Cassette.diff()``.

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/contract_testing_cassettes.py``

.. literalinclude:: ../../examples/contract_testing_cassettes.py
   :language: python
   :linenos:
