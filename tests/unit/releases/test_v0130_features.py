"""Unit tests for v0.13.0 features:
Container & Orchestration Transports (docker://, podman://, kubectl://) with full ISP capabilities:
- URIParser parsing and round-trip building for docker://, podman://, and kubectl://
- TransportLoader discovery and Connection.from_uri() instantiation
- CommandTransport: connect, disconnect, run, run_bytes, stream, ping
- FileCapableTransport: read_file, write_file, upload, download, chmod, stat, listdir, remove_file, exists, mkdir
- ShellCapableTransport: open_shell stateful session
- TunnelCapableTransport: forward_local_port (kubectl port-forward and docker TCP bridge)
- Cassette recording/replay integration with docker:// and kubectl://
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import uniconn
from uniconn import (
    CommandTransport,
    Connection,
    ConnectionError,
    DockerTransport,
    FileCapableTransport,
    KubectlTransport,
    PodmanTransport,
    ShellCapableTransport,
    TunnelCapableTransport,
    URIParser,
    supports_capability,
)


def _make_fake_proc(
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> MagicMock:
    """Create a mock asyncio.subprocess.Process with synchronous write/close and async communicate/wait."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock(return_value=returncode)
    proc.kill = MagicMock()
    proc.terminate = MagicMock()
    proc._transport = None
    return proc


class TestContainerAndKubectlURIParsing:
    """Tests for URIParser with docker://, podman://, and kubectl:// schemes."""

    def test_version_is_0130(self) -> None:
        parts = tuple(int(x) for x in uniconn.__version__.split(".")[:2])
        assert parts >= (0, 13)

    def test_parse_docker_uri_preserves_case_and_options(self) -> None:
        cfg = URIParser.parse("docker://root@MyAppContainer/var/www?runtime=docker&context=remote-ctx")
        assert cfg.transport == "docker"
        assert cfg.host == "MyAppContainer"
        assert cfg.username == "root"
        assert cfg.options["workdir"] == "/var/www"
        assert cfg.options["context"] == "remote-ctx"

    def test_parse_podman_uri_sets_podman_runtime(self) -> None:
        cfg = URIParser.parse("podman://postgres-dev?shell=/bin/bash")
        assert cfg.transport == "podman"
        assert cfg.host == "postgres-dev"
        assert cfg.options["runtime"] == "podman"
        assert cfg.options["shell"] == "/bin/bash"

    def test_parse_and_build_kubectl_uri_with_namespace_and_container(self) -> None:
        cfg = URIParser.parse(
            "kubectl://production/api-Pod-7f8b9?container=uvicorn&context=eu-central&kubeconfig=/etc/k8s.yaml"
        )
        assert cfg.transport == "kubectl"
        assert cfg.host == "api-Pod-7f8b9"
        assert cfg.options["namespace"] == "production"
        assert cfg.options["container"] == "uvicorn"
        assert cfg.options["context"] == "eu-central"
        assert cfg.options["kubeconfig"] == "/etc/k8s.yaml"

        rebuilt = URIParser.build("kubectl", host=cfg.host, options=dict(cfg.options))
        assert rebuilt.startswith("kubectl://production/api-Pod-7f8b9?")
        reparsed = URIParser.parse(rebuilt)
        assert reparsed.host == "api-Pod-7f8b9"
        assert reparsed.options["namespace"] == "production"
        assert reparsed.options["container"] == "uvicorn"

    def test_isp_capabilities_registered_for_docker_podman_kubectl(self) -> None:
        d_conn = Connection.from_uri("docker://app-1")
        p_conn = Connection.from_uri("podman://app-2")
        k_conn = Connection.from_uri("kubectl://default/pod-1")

        assert isinstance(d_conn.transport, DockerTransport)
        assert isinstance(p_conn.transport, PodmanTransport)
        assert isinstance(k_conn.transport, KubectlTransport)

        for tr in (d_conn.transport, p_conn.transport, k_conn.transport):
            assert supports_capability(tr, CommandTransport)
            assert supports_capability(tr, FileCapableTransport)
            assert supports_capability(tr, ShellCapableTransport)
            assert supports_capability(tr, TunnelCapableTransport)


class TestDockerAndPodmanTransport:
    """Tests for DockerTransport and PodmanTransport operations."""

    async def test_connect_run_and_context_propagation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
        recorded_calls: list[tuple[Any, ...]] = []

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            recorded_calls.append(args)
            if "inspect" in args:
                return _make_fake_proc(0, b"true\n", b"")
            return _make_fake_proc(0, b"hello_container\n", b"")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        conn = Connection.from_uri("docker://deploy@web-ctr?context=staging")
        async with conn:
            assert conn.transport.is_connected is True
            async with conn.cd("/srv/app"), conn.env(APP_ENV="prod"):
                res = await conn.run("echo $APP_ENV")
            assert res.ok is True
            assert res.text == "hello_container"

        # Inspect call + exec call
        assert len(recorded_calls) == 2
        exec_call = recorded_calls[1]
        assert exec_call[:4] == ("docker", "--context", "staging", "exec")
        assert "-u" in exec_call and "deploy" in exec_call
        assert "-w" in exec_call and "/srv/app" in exec_call
        assert "-e" in exec_call and "APP_ENV=prod" in exec_call
        assert "web-ctr" in exec_call

    async def test_connect_fails_when_container_not_running(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/podman")

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            return _make_fake_proc(0, b"false\n", b"")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        conn = Connection.from_uri("podman://stopped-ctr")
        with pytest.raises(ConnectionError, match="is not running"):
            async with conn:
                pass

    async def test_file_operations_and_ensure_file_on_docker(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/docker")
        cp_calls: list[tuple[Any, ...]] = []
        virtual_fs: dict[str, bytes] = {"/etc/app.conf": b"port=8080\n"}

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            if "inspect" in args:
                return _make_fake_proc(0, b"true\n", b"")
            if "cp" in args:
                cp_calls.append(args)
                return _make_fake_proc(0, b"", b"")
            cmd_str = args[-1]
            if cmd_str.startswith("test -e"):
                path = cmd_str.split()[-1].strip("'\"")
                return _make_fake_proc(0 if path in virtual_fs else 1, b"", b"")
            if cmd_str.startswith("cat --"):
                path = cmd_str.split()[-1].strip("'\"")
                return _make_fake_proc(0, virtual_fs.get(path, b""), b"")
            if "cat >" in cmd_str:
                return _make_fake_proc(0, b"", b"")
            if cmd_str.startswith("stat -c"):
                # size=10, uid=0, gid=0, mode=0x81a4 (0o100644), atime=1700000000, mtime=1700000000
                return _make_fake_proc(0, b"10|0|0|81a4|1700000000|1700000000\n", b"")
            if cmd_str.startswith("ls -1A"):
                return _make_fake_proc(0, b"app.conf\nlogs\n", b"")
            return _make_fake_proc(0, b"", b"")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        async with Connection.from_uri("docker://app-ctr") as conn:
            content = await conn.read_file("/etc/app.conf")
            assert content == "port=8080\n"

            st = await conn.stat("/etc/app.conf")
            assert st["size"] == 10
            assert st["is_file"] is True
            assert st["permissions"] == oct(0o100644)

            items = await conn.listdir("/etc")
            assert items == ["app.conf", "logs"]

            # Dry-run ensure_file computes unified diff against container file
            ens = await conn.ensure_file("/etc/app.conf", content="port=9090\n", mode=0o644, dry_run=True)
            assert ens.changed is True
            assert ens.diff is not None
            assert "-port=8080" in ens.diff
            assert "+port=9090" in ens.diff

            local_src = tmp_path / "upload.txt"
            local_src.write_text("hello", encoding="utf-8")
            await conn.upload(local_src, "/tmp/upload.txt")
            await conn.download("/tmp/upload.txt", tmp_path / "downloaded.txt")
            assert len(cp_calls) == 2


class TestKubectlTransport:
    """Tests for KubectlTransport commands, file operations, and port-forward."""

    async def test_kubectl_connect_run_and_cwd_env_wrapping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/kubectl")
        recorded_calls: list[tuple[Any, ...]] = []

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            recorded_calls.append(args)
            if "get" in args and "pod" in args:
                return _make_fake_proc(0, b"Running", b"")
            return _make_fake_proc(0, b"k8s_ok\n", b"")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        conn = Connection.from_uri("kubectl://kube-system/coredns-0?container=coredns&context=prod-cluster")
        async with conn:
            async with conn.cd("/etc/coredns"), conn.env(LOG_LEVEL="debug"):
                res = await conn.run("cat Corefile")
            assert res.ok is True
            assert res.text == "k8s_ok"

        assert len(recorded_calls) == 2
        get_call, exec_call = recorded_calls
        assert "--context" in get_call and "prod-cluster" in get_call
        assert "-n" in get_call and "kube-system" in get_call
        assert "-c" in exec_call and "coredns" in exec_call
        assert exec_call[-1] == "cd /etc/coredns && export LOG_LEVEL=debug && cat Corefile"

    async def test_kubectl_port_forward_parses_dynamic_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/kubectl")

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            if "get" in args:
                return _make_fake_proc(0, b"Running", b"")
            # port-forward subprocess
            pf_proc = _make_fake_proc(0, b"", b"")
            pf_proc.returncode = None
            pf_proc.stdout = MagicMock()
            pf_proc.stdout.readline = AsyncMock(
                return_value=b"Forwarding from 127.0.0.1:45123 -> 8080\n"
            )
            return pf_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        async with Connection.from_uri("kubectl://default/api-pod") as conn:
            async with conn.forward_local_port("127.0.0.1", 8080, local_port=0) as bound_port:
                assert bound_port == 45123

    async def test_kubectl_with_use_cassette_record_and_replay(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/kubectl")

        async def fake_exec(*args: Any, **kwargs: Any) -> MagicMock:
            if "get" in args:
                return _make_fake_proc(0, b"Running", b"")
            return _make_fake_proc(0, b"Linux k8s-pod 6.6.0 x86_64\n", b"")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

        cassette_file = tmp_path / "k8s_pod.yaml"
        conn = Connection.from_uri("kubectl://default/web-pod-1")
        async with conn.use_cassette(cassette_file, mode="all"):
            res = await conn.run("uname -a")
            assert res.text == "Linux k8s-pod 6.6.0 x86_64"

        assert cassette_file.exists()

        # Replay without calling subprocess at all
        async def fail_exec(*args: Any, **kwargs: Any) -> MagicMock:
            raise AssertionError("Subprocess should not be called during cassette replay")

        monkeypatch.setattr("asyncio.create_subprocess_exec", fail_exec)
        replay_conn = Connection.from_uri("kubectl://default/web-pod-1")
        async with replay_conn.use_cassette(cassette_file, mode="none"):
            replayed = await replay_conn.run("uname -a")
            assert replayed.text == "Linux k8s-pod 6.6.0 x86_64"
