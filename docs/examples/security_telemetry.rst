Security Hooks, Structured Logging & Telemetry
==============================================

Lifecycle hooks (``allowlist_hook``, ``blocklist_hook``, ``audit_log_hook``, ``metrics_collector_hook``), OpenTelemetry tracing (``otel_tracing_hook``, ``InMemoryTracer``), secret redaction (``sensitive=True``), ``dry_run``, and ``structlog`` JSONL context propagation.

- **Requirements**: Core ``uniconn`` (optional ``uniconn[otel]`` for OpenTelemetry export)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/security_and_hooks.py`` and ``uv run python examples/structured_logging_telemetry.py``

Lifecycle Hooks, Sensitive Mode & OpenTelemetry
-----------------------------------------------

.. literalinclude:: ../../examples/security_and_hooks.py
   :language: python
   :linenos:

Structured Logging & Metrics Collector
--------------------------------------

.. literalinclude:: ../../examples/structured_logging_telemetry.py
   :language: python
   :linenos:
