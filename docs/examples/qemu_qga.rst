QEMU Guest Agent (``qga://`` / ``qemu-ga://``)
==============================================

Managing virtual machines and QEMU emulators without guest network access across UNIX domain sockets, ``virsh``, TCP chardev channels (``backend=tcp``), and Windows Named Pipes (``backend=pipe``).

- **Requirements**: Core ``uniconn`` (no extras needed)
- **Platform Notes**: TCP and Named Pipe channels work natively on Windows; UNIX socket and ``virsh`` channels work on POSIX/KVM hosts
- **Run**: ``uv run python examples/qemu_guest_agent.py``

.. literalinclude:: ../../examples/qemu_guest_agent.py
   :language: python
   :linenos:
