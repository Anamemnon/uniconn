Background Tasks & Reactive Log Watchdogs
===========================================

Managing long-running detached background tasks via ``uniconn.background.BackgroundPool`` (auto-selecting ``tmux``, ``screen``, ``nohup``, or ``WindowsJobBackend``) and reactive log pipelines with ``PatternTriggerHandler``, ``LogWatchRule``, and Stream Silence Watchdog for hardware/telecom SCT diagnostics.

- **Requirements**: Core ``uniconn`` (``uniconn.background`` subpackage)
- **Platform Notes**: Cross-platform (automatic backend selection for POSIX and Windows)
- **Run**: ``uv run python examples/screen_monitoring.py`` and ``uv run python examples/reactive_log_watchdog_sct.py``

Background Pool YAML Config & Runner
------------------------------------

.. literalinclude:: ../../examples/screen_pool_config.yaml
   :language: yaml
   :linenos:

.. literalinclude:: ../../examples/screen_monitoring.py
   :language: python
   :linenos:

Reactive Log Watchdog (SCT / BBU / Hardware Diagnostics)
--------------------------------------------------------

.. literalinclude:: ../../examples/telecom_bs_sct_diagnostics.yaml
   :language: yaml
   :linenos:

.. literalinclude:: ../../examples/reactive_log_watchdog_sct.py
   :language: python
   :linenos:
