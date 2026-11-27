Provisioning, Facts & Stress Diagnostics
========================================

Idempotent state management (``conn.state.ensure_*``), host fact collection (``gather_facts()``), cluster drift detection (``diff_facts()``), and crash-safe stress diagnostics (``conn.diagnostic_session()``).

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/provisioning_and_facts.py`` and ``uv run python examples/stress_test_diagnostics.py``

.. literalinclude:: ../../examples/provisioning_and_facts.py
   :language: python
   :linenos:

Stress Testing & Crash-Safe Diagnostics (NVMe / RAM)
----------------------------------------------------

Declarative YAML profile for collecting static and streaming diagnostic logs:

.. literalinclude:: ../../examples/stress_test_diagnostics.yaml
   :language: yaml
   :linenos:

Stress diagnostic runner script (from YAML profile and Python ``dict``):

.. literalinclude:: ../../examples/stress_test_diagnostics.py
   :language: python
   :linenos:
