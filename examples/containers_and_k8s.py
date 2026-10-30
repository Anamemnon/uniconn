"""Работа с контейнерами Docker, Podman и подами Kubernetes (kubectl://).

Демонстрирует:
- Подключение к контейнерам через схемы docker:// и podman://
- Подключение к подам Kubernetes через схему kubectl://namespace/pod?container=...
- Выполнение команд, чтение/запись файлов (conn.files) и идемпотентные операции в контейнерах
- Безопасную локальную верификацию через dry_run=True и Replay-кассету (без запущенного демона Docker/K8s)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Cassette, Connection, RecordedExecInteraction, URIParser

# ─── Боевые примеры для Docker, Podman и Kubernetes ─────────────────


async def docker_and_podman_example() -> None:
    """Выполнение команд и обновление конфигов внутри Docker/Podman контейнеров."""
    # Схема docker://[user@]container[?workdir=/app&shell=/bin/sh&context=...]
    async with Connection.from_uri("docker://root@redis-cache?workdir=/data") as d_conn:
        ping = await d_conn.run(["redis-cli", "ping"])
        print("Redis response:", ping.text)

    # Схема podman://[user@]container[?workdir=/srv]
    async with Connection.from_uri("podman://web-frontend?workdir=/usr/share/nginx/html") as p_conn:
        await p_conn.files.write_file("/usr/share/nginx/html/health.txt", "OK\n", atomic=True)


async def kubernetes_pod_example() -> None:
    """Инспекция и управление приложением внутри пода Kubernetes через kubectl://."""
    uri = "kubectl://production/billing-api-7d9c8b-x2k4p?container=api&context=eu-central-1&workdir=/app"
    async with Connection.from_uri(uri) as k8s_conn:
        res = await k8s_conn.run(["python3", "manage.py", "showmigrations"])
        print(res.stdout)


# ─── Самодостаточная локальная демонстрация ─────────────────────────


async def main() -> None:
    """Локальная демонстрация парсинга контейнерных URI, dry_run и воспроизведения сессии пода."""
    print("=== 1. Разбор контейнерных и Kubernetes URI через URIParser ===")
    sample_uris = [
        "docker://root@api-gateway?workdir=/srv/app&shell=/bin/bash",
        "podman://postgres-local?workdir=/var/lib/postgresql",
        "kubectl://prod-ns/worker-pod-0?container=celery&context=prod-cluster&workdir=/app",
    ]
    for raw_uri in sample_uris:
        cfg = URIParser.parse(raw_uri)
        print(f"  transport={cfg.transport:<8} host={cfg.host:<22} options={cfg.options}")

    print("\n=== 2. Проверка команд на контейнерных транспортах в режиме dry_run=True ===")
    for raw_uri in sample_uris:
        conn = Connection.from_uri(raw_uri, dry_run=True)
        res = await conn.run(["python3", "-m", "healthcheck"])
        print(f"  [{conn.config.transport}] dry_run ok={res.ok}, cmd={res.command!r}")

    print("\n=== 3. Воспроизведение сессии Kubernetes-пода из кассеты ===")
    with tempfile.TemporaryDirectory(prefix="uniconn_k8s_") as tmpdir:
        cassette_file = Path(tmpdir) / "k8s_pod.yaml"
        Cassette(
            transport="kubectl",
            host="worker-pod-0",
            interactions=[
                RecordedExecInteraction(
                    command="hostname && cat /var/run/secrets/kubernetes.io/serviceaccount/namespace",
                    exit_code=0,
                    stdout="worker-pod-0\nprod-ns\n",
                ),
            ],
        ).save(cassette_file)

        async with Connection.from_uri(f"replay://worker-pod-0?cassette={cassette_file}&mode=none") as pod:
            res = await pod.run("hostname && cat /var/run/secrets/kubernetes.io/serviceaccount/namespace")
            print("Replayed pod lines:", res.lines)


if __name__ == "__main__":
    asyncio.run(main())
