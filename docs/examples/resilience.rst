Resilience, Batch Rollout & Tunnels
===================================

Fault-tolerance primitives (``CircuitBreaker``, ``RateLimiter``), ``ConnectionPool`` wave rollouts (``batch_size``, ``max_fail_ratio``), adaptive ``SSHSessionPool`` multiplexing, and SSH port forwarding (``conn.tunnels``).

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/resilience_rollout_and_waiters.py``

.. literalinclude:: ../../examples/resilience_rollout_and_waiters.py
   :language: python
   :linenos:
