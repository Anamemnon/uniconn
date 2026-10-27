"""Unit tests for v0.12.0 features:
1. SecretResolver (env://, file://, ?default=) in ConnectionConfig, URIParser, InventoryLoader.
2. Cassette.diff(), CLI `uniconn cassette diff`, and pool.use_cassette() / sync_pool.use_cassette().
3. ensure_file & ensure_directory (content, mode, owner, symlinks, validate) and unified diff in EnsureResult.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from uniconn import (
    Cassette,
    CassetteDiffReport,
    ConfigurationError,
    Connection,
    ConnectionConfig,
    ConnectionPool,
    InteractionDiff,
    InventoryLoader,
    RecordedExecInteraction,
    SecretResolver,
    SyncConnection,
    URIParser,
)
from uniconn.cli import main as cli_main


class TestSecretResolverAndConfig:
    """Tests for SecretResolver across env://, file://, ConnectionConfig, URIParser, and InventoryLoader."""

    def test_resolve_env_success_and_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UNICONN_TEST_SECRET", "s3cr3t_val")
        assert SecretResolver.resolve("env://UNICONN_TEST_SECRET") == "s3cr3t_val"

        monkeypatch.delenv("UNICONN_MISSING_SECRET", raising=False)
        assert SecretResolver.resolve("env://UNICONN_MISSING_SECRET?default=fallback_pw") == "fallback_pw"

    def test_resolve_env_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("UNICONN_MISSING_VAR", raising=False)
        with pytest.raises(ConfigurationError, match="Environment variable 'UNICONN_MISSING_VAR' is not set"):
            SecretResolver.resolve("env://UNICONN_MISSING_VAR")

    def test_resolve_file_success_and_default(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "bmc_pass.txt"
        secret_file.write_text("bmc_secret_123\n", encoding="utf-8")
        assert SecretResolver.resolve(f"file://{secret_file}") == "bmc_secret_123"

        missing_file = tmp_path / "does_not_exist.txt"
        assert SecretResolver.resolve(f"file://{missing_file}?default=default_file_pw") == "default_file_pw"

    def test_resolve_file_missing_raises(self, tmp_path: Path) -> None:
        missing_file = tmp_path / "missing_secret.txt"
        with pytest.raises(ConfigurationError, match="Failed to read secret file"):
            SecretResolver.resolve(f"file://{missing_file}")

    def test_connection_config_and_uri_parser_resolve_secrets(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("UNICONN_SSH_PASS", "env_ssh_pass")
        sudo_file = tmp_path / "sudo_pass"
        sudo_file.write_text("file_sudo_pass\n", encoding="utf-8")

        cfg = ConnectionConfig(
            transport="ssh",
            host="10.0.0.10",
            username="admin",
            password="env://UNICONN_SSH_PASS",  # type: ignore[arg-type]
            passphrase="env://UNICONN_MISSING_PASSPHRASE?default=my_passphrase",  # type: ignore[arg-type]
            options={
                "sudo_password": f"file://{sudo_file}",
            },
        )
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "env_ssh_pass"
        assert cfg.passphrase is not None
        assert cfg.passphrase.get_secret_value() == "my_passphrase"
        assert cfg.options["sudo_password"] == "file_sudo_pass"

        parsed = URIParser.parse("ssh://root@10.0.0.11:2222?password=env://UNICONN_SSH_PASS")
        assert parsed.password is not None
        assert parsed.password.get_secret_value() == "env_ssh_pass"

    def test_inventory_loader_resolves_secrets_in_yaml_and_toml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("INV_DB_PASS", "db_secret_99")
        yaml_file = tmp_path / "inventory.yaml"
        yaml_file.write_text(
            """
defaults:
  username: deploy
  options:
    sudo_password: env://INV_DB_PASS
hosts:
  db-01:
    transport: ssh
    host: 10.10.0.5
    password: env://INV_DB_PASS
""",
            encoding="utf-8",
        )
        entries = InventoryLoader.load_file(yaml_file)
        assert len(entries) == 1
        assert entries[0]["password"] == "db_secret_99"
        assert entries[0]["options"]["sudo_password"] == "db_secret_99"

        conns = Connection.from_file(yaml_file)
        assert len(conns) == 1
        assert conns[0].config.password is not None
        assert conns[0].config.password.get_secret_value() == "db_secret_99"

        toml_file = tmp_path / "inventory.toml"
        toml_file.write_text(
            """
[hosts.edge-01]
transport = "ssh"
host = "10.10.0.9"
password = "env://INV_MISSING?default=toml_fallback"
""",
            encoding="utf-8",
        )
        toml_conns = Connection.from_file(toml_file)
        assert len(toml_conns) == 1
        assert toml_conns[0].config.password is not None
        assert toml_conns[0].config.password.get_secret_value() == "toml_fallback"


class TestCassetteDiffAndPoolCassette:
    """Tests for Cassette.diff(), CLI `uniconn cassette diff`, and pool.use_cassette()."""

    def test_cassette_diff_identical_and_modified(self) -> None:
        left = Cassette(
            host="node-01",
            transport="ssh",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="up 1 day\n", exit_code=0, duration=0.05),
                RecordedExecInteraction(command="uname -r", stdout="6.1.0\n", exit_code=0, duration=0.02),
            ],
        )
        right_same = Cassette(
            host="node-01",
            transport="ssh",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="up 1 day\n", exit_code=0, duration=0.05),
                RecordedExecInteraction(command="uname -r", stdout="6.1.0\n", exit_code=0, duration=0.02),
            ],
        )
        same_report = left.diff(right_same)
        assert isinstance(same_report, CassetteDiffReport)
        assert same_report.is_identical is True
        assert same_report.has_changes is False
        assert same_report.identical_count == 2
        assert same_report.modified_count == 0
        assert same_report.added_count == 0
        assert same_report.removed_count == 0

        right_changed = Cassette(
            host="node-01",
            transport="ssh",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="up 2 days\n", exit_code=0, duration=0.08),
                RecordedExecInteraction(command="df -h", stdout="/dev/sda1 50%\n", exit_code=0, duration=0.03),
                RecordedExecInteraction(command="whoami", stdout="root\n", exit_code=0, duration=0.01),
            ],
        )
        diff_report = left.diff(right_changed)
        assert diff_report.is_identical is False
        assert diff_report.has_changes is True
        assert diff_report.modified_count == 2
        assert diff_report.added_count == 1
        mod0 = diff_report.interactions[0]
        assert isinstance(mod0, InteractionDiff)
        assert mod0.status == "modified"
        assert mod0.stdout_diff is not None
        assert "-up 1 day" in mod0.stdout_diff
        assert "+up 2 days" in mod0.stdout_diff
        assert diff_report.interactions[2].status == "added"
        assert diff_report.to_dict()["is_identical"] is False

    def test_cli_cassette_diff_json_and_fail_on_diff(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        c1_path = tmp_path / "base.yaml"
        c2_path = tmp_path / "cand.yaml"

        c1 = Cassette(
            host="node-a",
            transport="local",
            interactions=[RecordedExecInteraction(command="hostname", stdout="node-a\n", exit_code=0)],
        )
        c2 = Cassette(
            host="node-a",
            transport="local",
            interactions=[RecordedExecInteraction(command="hostname", stdout="node-b\n", exit_code=0)],
        )
        c1.save(c1_path)
        c2.save(c2_path)

        with pytest.raises(SystemExit) as ok_exit:
            cli_main(["cassette", "diff", str(c1_path), str(c2_path), "--format", "json"])
        assert ok_exit.value.code == 0
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["is_identical"] is False
        assert payload["modified_count"] == 1

        with pytest.raises(SystemExit) as exc_info:
            cli_main(["cassette", "diff", str(c1_path), str(c2_path), "--fail-on-diff"])
        assert exc_info.value.code == 1

    async def test_pool_use_cassette_directory_and_single_file(self, tmp_path: Path) -> None:
        c1 = Connection.from_uri("local://").with_overrides(host="host-alpha")
        c2 = Connection.from_uri("local://").with_overrides(host="host-beta")
        pool = ConnectionPool([c1, c2])

        # 1. Directory per host mode
        cassette_dir = tmp_path / "fleet_cassettes"
        async with pool.use_cassette(cassette_dir, mode="all") as host_cassettes:
            results = await pool.map("echo fleet_ok")
            assert all(r.text == "fleet_ok" for r in results)
            assert set(host_cassettes.keys()) == {"host-alpha", "host-beta"}

        assert (cassette_dir / "host-alpha.yaml").exists()
        assert (cassette_dir / "host-beta.yaml").exists()

        # Replay from directory without executing real subprocesses
        r1 = Connection.from_uri("ssh://host-alpha")
        r2 = Connection.from_uri("ssh://host-beta")
        replay_pool = ConnectionPool([r1, r2])
        async with replay_pool.use_cassette(cassette_dir, mode="none"):
            replayed = await replay_pool.map("echo fleet_ok")
            assert [r.text for r in replayed] == ["fleet_ok", "fleet_ok"]

        # 2. Single shared file mode (.yaml)
        shared_file = tmp_path / "shared_fleet.yaml"
        async with pool.use_cassette(shared_file, mode="all"):
            await pool.map("echo shared_ok")
        assert shared_file.exists()

        async with replay_pool.use_cassette(shared_file, mode="none"):
            replayed_shared = await replay_pool.map("echo shared_ok")
            assert [r.text for r in replayed_shared] == ["shared_ok", "shared_ok"]

    def test_sync_pool_use_cassette(self, tmp_path: Path) -> None:
        c1 = Connection.from_uri("local://").with_overrides(host="sync-node-1")
        pool = ConnectionPool([c1]).to_sync()
        cassette_dir = tmp_path / "sync_fleet"
        with pool.use_cassette(cassette_dir, mode="all") as cassettes:
            res = pool.map("echo sync_cassette_ok")
            assert res[0].text == "sync_cassette_ok"
            assert "sync-node-1" in cassettes
        assert (cassette_dir / "sync-node-1.yaml").exists()


class TestEnsureFileDirectoryAndUnifiedDiff:
    """Tests for ensure_file, ensure_directory, and unified diff calculation on dry_run=True."""

    async def test_ensure_file_present_idempotent_mode_validate_and_dry_run_diff(self, tmp_path: Path) -> None:
        target = tmp_path / "app.conf"
        async with Connection.from_uri("local://") as conn:
            # 1. Dry-run creation computes unified diff without creating file
            dry_res = await conn.ensure_file(
                str(target),
                content="port=8080\nworkers=4\n",
                mode=0o640 if sys.platform != "win32" else None,
                dry_run=True,
            )
            assert dry_res.ok is True
            assert dry_res.changed is True
            assert dry_res.dry_run is True
            assert dry_res.diff is not None
            assert "+port=8080" in dry_res.diff
            assert not target.exists()

            # 2. Create file with content, mode, and validation command
            val_cmd = (
                f'"{sys.executable}" -c "import sys; sys.exit(0 if \'port=8080\' in open(sys.argv[1]).read() else 1)" %s'
                if sys.platform == "win32"
                else "grep -q 'port=8080' %s"
            )
            res1 = await conn.ensure_file(
                str(target),
                content="port=8080\nworkers=4\n",
                mode=0o640 if sys.platform != "win32" else None,
                validate=val_cmd,
            )
            assert res1.ok is True
            assert res1.changed is True
            assert res1.diff is not None
            assert "+port=8080" in res1.diff
            assert target.read_text(encoding="utf-8") == "port=8080\nworkers=4\n"
            if sys.platform != "win32":
                assert (target.stat().st_mode & 0o777) == 0o640

            # 3. Second call is idempotent (changed=False, diff=None)
            res2 = await conn.ensure_file(
                str(target),
                content="port=8080\nworkers=4\n",
                mode=0o640 if sys.platform != "win32" else None,
            )
            assert res2.ok is True
            assert res2.changed is False
            assert res2.diff is None

            # 4. Dry-run update computes exact unified diff against existing file
            dry_upd = await conn.ensure_file(
                str(target),
                content="port=9090\nworkers=4\n",
                dry_run=True,
            )
            assert dry_upd.changed is True
            assert dry_upd.dry_run is True
            assert dry_upd.diff is not None
            assert "-port=8080" in dry_upd.diff
            assert "+port=9090" in dry_upd.diff
            assert target.read_text(encoding="utf-8") == "port=8080\nworkers=4\n"

            # 5. Failed validation leaves original file untouched
            bad_val_cmd = (
                f'"{sys.executable}" -c "import sys; sys.exit(0 if \'port=\' in open(sys.argv[1]).read() else 1)" %s'
                if sys.platform == "win32"
                else "grep -q 'port=' %s"
            )
            bad_val = await conn.ensure_file(
                str(target),
                content="invalid_config\n",
                validate=bad_val_cmd,
            )
            assert bad_val.ok is False
            assert bad_val.changed is False
            assert "Validation command failed" in bad_val.details
            assert target.read_text(encoding="utf-8") == "port=8080\nworkers=4\n"

            # 6. Absent state removes file and shows deletion diff
            rm_res = await conn.ensure_file(str(target), state="absent")
            assert rm_res.ok is True
            assert rm_res.changed is True
            assert rm_res.diff is not None
            assert "-port=8080" in rm_res.diff
            assert not target.exists()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Symlinks on Windows require Developer Mode or elevated privileges",
    )
    async def test_ensure_file_symlink(self, tmp_path: Path) -> None:
        src = tmp_path / "target.txt"
        src.write_text("hello link\n", encoding="utf-8")
        link_path = tmp_path / "sym.txt"

        async with Connection.from_uri("local://") as conn:
            res1 = await conn.ensure_file(str(link_path), state="link", target=str(src))
            assert res1.ok is True
            assert res1.changed is True
            assert res1.diff is not None
            assert f"+{src}" in res1.diff
            assert link_path.is_symlink()
            assert link_path.resolve() == src.resolve()

            # Idempotent re-run
            res2 = await conn.ensure_file(str(link_path), state="link", target=str(src))
            assert res2.ok is True
            assert res2.changed is False

    async def test_ensure_directory_and_ensure_line_dry_run_diff(self, tmp_path: Path) -> None:
        dir_path = tmp_path / "nested" / "service_dir"
        conf_path = dir_path / "settings.env"

        async with Connection.from_uri("local://") as conn:
            # Dry-run directory creation
            dry_dir = await conn.ensure_directory(
                str(dir_path), mode=0o750 if sys.platform != "win32" else None, dry_run=True
            )
            assert dry_dir.changed is True
            assert dry_dir.dry_run is True
            assert dry_dir.diff is not None
            assert "+directory" in dry_dir.diff
            assert not dir_path.exists()

            # Real directory creation
            dir_res = await conn.ensure_directory(
                str(dir_path), mode=0o750 if sys.platform != "win32" else None
            )
            assert dir_res.ok is True
            assert dir_res.changed is True
            assert dir_path.is_dir()
            if sys.platform != "win32":
                assert (dir_path.stat().st_mode & 0o777) == 0o750

            # Idempotent check
            dir_res2 = await conn.ensure_directory(
                str(dir_path), mode=0o750 if sys.platform != "win32" else None
            )
            assert dir_res2.ok is True
            assert dir_res2.changed is False

            # ensure_line with dry_run=True computes unified diff
            conf_path.write_text("APP_PORT=3000\n", encoding="utf-8")
            line_dry = await conn.ensure_line(
                str(conf_path),
                "APP_PORT=4000",
                regex=r"^APP_PORT=",
                dry_run=True,
            )
            assert line_dry.changed is True
            assert line_dry.dry_run is True
            assert line_dry.diff is not None
            assert "-APP_PORT=3000" in line_dry.diff
            assert "+APP_PORT=4000" in line_dry.diff
            assert conf_path.read_text(encoding="utf-8") == "APP_PORT=3000\n"

            # Remove directory
            rm_dir = await conn.ensure_directory(str(dir_path), state="absent")
            assert rm_dir.ok is True
            assert rm_dir.changed is True
            assert not dir_path.exists()

    def test_sync_connection_and_pool_ensure_file_directory_parity(self, tmp_path: Path) -> None:
        sync_file = tmp_path / "sync_dir" / "hello.txt"
        with SyncConnection.from_uri("local://") as sconn:
            d_res = sconn.ensure_directory(str(sync_file.parent), mode=0o755)
            assert d_res.ok is True
            assert d_res.changed is True

            f_res = sconn.ensure_file(str(sync_file), content="sync_world\n", mode=0o644)
            assert f_res.ok is True
            assert f_res.changed is True
            assert sync_file.read_text(encoding="utf-8") == "sync_world\n"
