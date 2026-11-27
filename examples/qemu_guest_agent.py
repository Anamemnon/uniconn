"""Управление виртуальными машинами и эмуляторами через QEMU Guest Agent (``qga://`` / ``qemu-ga://``).

Демонстрирует:
- Подключение без сети внутри гостя: UNIX-сокет, ``backend=virsh``, TCP-сокет (``backend=tcp``) и Windows Named Pipe
- Выполнение команд (``run``), передачу файлов чанками (``conn.files``) и идемпотентный ``conn.state.ensure_file``
- Гибридный сбор фактов ОС и сетевых интерфейсов (``gather_facts``)
- Самодостаточный локальный запуск против ``MockQgaServer`` и реального TCP-сервера QGA
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from uniconn import Connection, ConnectionConfig
from uniconn.mock import MockQgaServer
from uniconn.transports import QgaTransport

# ─── Боевые шаблоны URI для Linux KVM/libvirt и Windows-эмуляторов ───────────


async def qga_production_uris_reference() -> None:
    """Справочные примеры URI для различных окружений QEMU/KVM и Windows."""
    # 1. Локальный UNIX-сокет на Linux-хосте
    async with Connection.from_uri("qga:///var/lib/libvirt/qemu/channel/target/domain-1-vm1/org.qemu.guest_agent.0"):
        pass

    # 2. Удалённый KVM-хост по SSH + libvirt virsh
    async with Connection.from_uri("qemu-ga://root@kvm-host-01/vm-prod-01?backend=virsh"):
        pass

    # 3. Локальный QEMU-эмулятор с -chardev socket,host=127.0.0.1,port=4444,server=on
    async with Connection.from_uri("qga://127.0.0.1:4444?backend=tcp"):
        pass

    # 4. Windows Named Pipe (QEMU / Hyper-V стенды на Windows)
    async with Connection.from_uri(r"qga://?backend=pipe&pipe=\\.\pipe\qga-vm1"):
        pass


# ─── Самодостаточная локальная демонстрация (MockQgaServer + TCP loopback) ───


async def _handle_tcp_qga_client(
    mock_server: MockQgaServer,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Проксировать строки QGA JSON-RPC через локальный TCP-сокет на публичный API ``MockQgaServer``."""
    try:
        while not reader.at_eof():
            raw_line = await reader.readline()
            if not raw_line:
                break
            has_sentinel = b"\xff" in raw_line
            clean = raw_line.replace(b"\xff", b"").strip()
            if not clean:
                continue
            req = json.loads(clean.decode("utf-8"))
            cmd = str(req.get("execute") or "")
            args = req.get("arguments") or {}
            try:
                result = await mock_server.execute(cmd, args)
                resp_obj: dict[str, object] = {"return": result}
            except Exception as exc:
                resp_obj = {"error": {"class": "GenericError", "desc": str(exc)}}
            prefix = b"\xff" if has_sentinel or cmd == "guest-sync-delimited" else b""
            writer.write(prefix + json.dumps(resp_obj).encode("utf-8") + b"\n")
            await writer.drain()
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def main() -> None:
    """Локальный прогон сценариев QGA: in-memory канал + реальный TCP-сокет ``qga://127.0.0.1:<port>?backend=tcp``."""
    print("=== 1. In-memory QgaTransport поверх MockQgaServer ===")
    mock_qga = MockQgaServer(
        hostname="isolated-guest-01",
        files={"/etc/motd": b"Welcome to QEMU guest\n"},
        command_handlers={"uname -r": (0, "6.8.0-45-generic\n", "")},
    )
    cfg = ConnectionConfig.from_uri("qga:///tmp/demo-qga.sock")
    async with Connection(QgaTransport(cfg, channel=mock_qga), cfg) as guest:
        ping = await guest.ping()
        kernel = await guest.run("uname -r")
        print(f"Ping alive={ping.alive}, kernel={kernel.text}")

        ens = await guest.state.ensure_file("/etc/app.env", content="MODE=isolated\n", sudo=False)
        print(f"ensure_file changed={ens.changed}, content={await guest.files.read_file('/etc/app.env')!r}")

        facts = await guest.gather_facts(refresh=True)
        print(f"Guest facts: host={facts.hostname}, os={facts.os_family}, ifaces={[i.name for i in facts.interfaces]}")

    print("\n=== 2. Кроссплатформенный TCP QGA канал (qga://127.0.0.1:<port>?backend=tcp) ===")
    tcp_backend = MockQgaServer(
        hostname="qemu-tcp-emu",
        command_handlers={"id": (0, "uid=0(root) gid=0(root)\n", "")},
    )
    await tcp_backend.open()
    server = await asyncio.start_server(
        lambda r, w: _handle_tcp_qga_client(tcp_backend, r, w),
        "127.0.0.1",
        0,
    )
    port = int(server.sockets[0].getsockname()[1])
    try:
        async with Connection.from_uri(f"qga://127.0.0.1:{port}?backend=tcp") as tcp_guest:
            res = await tcp_guest.run("id")
            await tcp_guest.files.write_file("/tmp/emu.txt", "hello from tcp qga\n")
            read_back = await tcp_guest.files.read_file("/tmp/emu.txt")
            print(f"TCP QGA run: {res.text} | file: {read_back.strip()!r}")
    finally:
        server.close()
        await server.wait_closed()
        await tcp_backend.close()


if __name__ == "__main__":
    asyncio.run(main())
