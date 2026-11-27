Serial / UART Hardware & XMODEM/YMODEM Flashing
===============================================

Direct RS-232 / UART communication on Linux (``/dev/ttyUSB0``) and Windows (``COM3`` with thread-backed ``ProactorEventLoop`` adapter), VID/PID auto-discovery, hardware line control (``pulse_dtr_rts``, ``send_break``, CTS/DSR/CD), binary framing, and XMODEM-1K firmware upload.

- **Requirements**: ``uv add "uniconn[serial]"``
- **Platform Notes**: Cross-platform (``pyserial-asyncio`` on POSIX; automatic ``io_backend=threaded`` on Windows; ZMODEM subprocess adapter is POSIX-only)
- **Run**: ``uv run python examples/serial_uart_hardware.py``

.. literalinclude:: ../../examples/serial_uart_hardware.py
   :language: python
   :linenos:
