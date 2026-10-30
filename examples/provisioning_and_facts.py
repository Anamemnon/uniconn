"""Идемпотентное управление состоянием (conn.state), инспекция фактов (gather_facts) и дрейф (diff_facts).

Демонстрирует:
- Сбор системных и пользовательских фактов через conn.gather_facts(spec=FactSpec(...))
- Поиск расхождений конфигураций между хостами через pool.diff_facts() и diff_facts()
- Идемпотентные примитивы conn.state:
  ensure_file (с atomic=True и unified diff), ensure_directory, ensure_line,
  ensure_package, ensure_service, ensure_user, ensure_authorized_key,
  ensure_systemd_unit, ensure_sysctl (в реальном режиме и dry_run=True)
- Диагностические сессии conn.diagnostic_session() со снимками фактов и архивацией
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Connection, CustomCommandSpec, FactSpec, HostFacts, diff_facts

# ─── Справочный пример для настройки продакшн SSH-узла ──────────────


async def ssh_server_provisioning_example() -> None:
    """Полный цикл идемпотентной подготовки Linux-сервера по SSH."""
    async with Connection.from_uri("ssh://admin:env://SSH_PASS@node-01") as conn:
        await conn.state.ensure_package(["nginx", "curl"], state="present", update_cache=True, sudo=True)
        await conn.state.ensure_user("deploy", uid=1050, groups=["docker"], shell="/bin/bash", sudo=True)
        await conn.state.ensure_authorized_key("deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...", sudo=True)
        await conn.state.ensure_sysctl("net.ipv4.ip_forward", 1, reload=True, sudo=True)
        await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)


# ─── Самодостаточная локальная демонстрация ─────────────────────────


async def main() -> None:
    """Локальная демонстрация фактов, поиска дрейфа, conn.state и diagnostic_session."""
    with tempfile.TemporaryDirectory(prefix="uniconn_prov_") as tmpdir:
        root = Path(tmpdir)

        async with Connection.local() as conn:
            print("=== 1. Сбор фактов хоста (gather_facts + кастомный FactSpec) ===")
            spec = FactSpec(
                commands=[CustomCommandSpec(name="python_ver", command="python3 --version")],
            )
            facts = await conn.gather_facts(spec=spec, refresh=True)
            print(f"Host: {facts.hostname}, OS: {facts.os_family}/{facts.distro}, CPUs: {facts.cpu_count}")
            print("Custom fact python_ver:", facts.custom.get("python_ver"))

            print("\n=== 2. Анализ дрейфа конфигураций между хостами (diff_facts) ===")
            node_b = HostFacts(
                os_family=facts.os_family,
                distro=facts.distro,
                kernel="6.99.0-custom",
                arch=facts.arch,
                hostname="node-b",
                cpu_count=facts.cpu_count,
            )
            drift_report = diff_facts({"node-a": facts, "node-b": node_b}, baseline_host="node-a")
            print(f"Has drift: {drift_report.has_drift}, drifted hosts: {list(drift_report.drifted_hosts)}")

            print("\n=== 3. Идемпотентные операции conn.state и Unified Diff ===")
            app_dir = str(root / "etc_app")
            conf_file = str(root / "etc_app" / "app.conf")

            dir_res = await conn.state.ensure_directory(app_dir, mode=0o755)
            file_res1 = await conn.state.ensure_file(
                conf_file,
                content="port = 8080\nworkers = 2\n",
                mode=0o644,
                atomic=True,
            )
            print(f"Создание директории и файла: dir_changed={dir_res.changed}, file_changed={file_res1.changed}")

            # Обновление файла с генерацией unified diff
            file_res2 = await conn.state.ensure_file(
                conf_file,
                content="port = 8080\nworkers = 8\n",
                mode=0o644,
                atomic=True,
            )
            print(f"Обновление файла (changed={file_res2.changed}):\n{file_res2.diff}")

            line_res = await conn.state.ensure_line(conf_file, "log_level = info")
            print(f"ensure_line: changed={line_res.changed}, details={line_res.details}")

            print("\n=== 4. Системные примитивы в режиме dry_run=True ===")
            usr_dry = await conn.state.ensure_user("deploy_bot", shell="/bin/bash", dry_run=True)
            unit_dry = await conn.state.ensure_systemd_unit(
                "demo.service",
                content="[Unit]\nDescription=Demo\n",
                dry_run=True,
            )
            sysctl_dry = await conn.state.ensure_sysctl("net.ipv4.ip_forward", 1, dry_run=True)
            print(
                f"Dry-run check: user={usr_dry.changed}, "
                f"unit={unit_dry.changed}, sysctl={sysctl_dry.changed}"
            )

            print("\n=== 5. Диагностическая сессия (diagnostic_session) ===")
            diag_dir = root / "diag_out"
            archive_file = root / "incident_bundle.tar.gz"
            async with conn.diagnostic_session(
                local_dir=diag_dir,
                archive_path=archive_file,
                archive_format="tar.gz",
            ) as diag:
                await diag.emit_custom_log("deploy", "Applying configuration changes")
                snap_facts = await diag.snapshot("after_config")
                print(f"Снимок фактов сохранён для хоста: {snap_facts.hostname}")
            print(f"Итоговый диагностический архив создан: {archive_file.exists()}")


if __name__ == "__main__":
    asyncio.run(main())
