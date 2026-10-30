Resilience, Batch Rollout & Tunnels
===================================

Отказоустойчивость (``CircuitBreaker``, ``RateLimiter``), волновой роллаут пула
(``batch_size``, ``max_fail_ratio``), адаптивный ``SSHSessionPool`` и проброс портов (``conn.tunnels``).

.. literalinclude:: ../../examples/resilience_rollout_and_waiters.py
   :language: python
   :linenos:
