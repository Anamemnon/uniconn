Network Automation (NETCONF, RESTCONF, gNMI)
============================================

Model-driven network automation using ``conn.net`` and ``conn.state.ensure_yang()`` across NETCONF (RFC 6241/6242), RESTCONF (RFC 8040 + SSE streaming), and gNMI (HTTP/2 gRPC over ``jh2``), verified against in-process ``uniconn.mock`` servers.

- **Requirements**: ``uv add "uniconn[netconf,restconf,gnmi]"``
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/network_yang_telemetry.py``

.. literalinclude:: ../../examples/network_yang_telemetry.py
   :language: python
   :linenos:
