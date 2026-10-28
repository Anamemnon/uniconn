# examples/ergonomics_and_inventory.py
"""Пример использования возможностей v0.5.0: эргономика Result, файловые хелперы, инвентарь и пул."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Connection, ConnectionPool


async def main() -> None:
    print("=== 1. Эргономика Result (.text, .lines, .json(), bool(result)) ===")
    async with Connection.from_uri("local://") as conn:
        # bool(result) и .text
        if res := await conn.run(["python3", "-c", "print('  node-alpha  ')"]):
            print(f"Host label (.text): {res.text!r}")

        # .lines
        lines_res = await conn.run(["python3", "-c", "print('eth0\\neth1\\nlo')"])
        print(f"Interfaces (.lines): {lines_res.lines}")

        # .json()
        json_res = await conn.run(
            ["python3", "-c", 'import json; print(json.dumps({"cpu": 4, "ok": True}))']
        )
        print(f"Parsed JSON (.json()): {json_res.json()}")

        print("\n=== 2. Файловые хелперы: temp_dir(), mkdir(), exists() ===")
        async with conn.temp_dir(prefix="uniconn_demo_") as tmp:
            print(f"Created temp_dir: {tmp}")
            async with conn.cd(tmp):
                await conn.files.mkdir("releases/v1", mode=0o755)
                await conn.files.write_file("releases/v1/version.txt", "0.5.0\n")
                exists = await conn.files.exists("releases/v1/version.txt")
                content = (await conn.files.read_file("releases/v1/version.txt"))
                assert isinstance(content, str)
                print(f"File exists: {exists}, content: {content.strip()}")
        print(f"After exit temp_dir exists: {await conn.files.exists(tmp)}")

    print("\n=== 3. Мульти-хостовый Inventory и переиспользуемый ConnectionPool ===")
    inventory_yaml = """
defaults:
  transport: local
  timeout: 10.0

hosts:
  worker-1:
    host: localhost
    groups: [workers, prod]
  worker-2:
    host: localhost
    groups: [workers, prod]
"""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, encoding="utf-8"
    ) as f:
        f.write(inventory_yaml)
        inv_path = Path(f.name)

    try:
        single = Connection.from_inventory(inv_path, host="worker-1")
        print(f"Loaded single host from inventory: {single.config.host}")

        async with ConnectionPool.from_file(inv_path, group="workers") as pool:
            results = await pool.map(["echo", "Hello from persistent pool"])
            print(f"Pool map results: {[r.text for r in results]}")

            applied = await pool.apply(lambda c: c.run(["echo", "Custom async fn"]))
            print(f"Pool apply results: {[r.text for r in applied]}")
    finally:
        inv_path.unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
