BMC Management (Redfish HTTP/2 & IPMI 2.0)
==========================================

Out-of-band server hardware management via DMTF Redfish HTTP/2 (``redfish://``) and IPMI v2.0 LAN+ (``ipmi://``): power control, sensor telemetry, SEL logs, Virtual Media, UEFI SecureBoot, PXE boot overrides, and raw NetFn commands.

- **Requirements**: ``uv add "uniconn[bmc]"`` (offline ``main()`` runs via ``replay://``)
- **Platform Notes**: Cross-platform (Linux, macOS, Windows)
- **Run**: ``uv run python examples/bmc_management.py``

.. literalinclude:: ../../examples/bmc_management.py
   :language: python
   :linenos:
