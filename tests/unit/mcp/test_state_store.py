# tests/unit/mcp/test_state_store.py
"""Unit-тесты для StateStore Protocol, InMemoryStateStore, SQLiteStateStore (WAL),
атомарного CAS, многопроцессного IPC и stateless signed opaque checkpoint tokens."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
import time
import zlib
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    ApprovalAlreadyConsumedError,
    ConcurrencyConflictError,
    Connection,
    Flow,
    Result,
    task,
)
from uniconn.cli.cmd_mcp import _build_mcp_server_from_args, build_mcp_client_config
from uniconn.mcp import (
    CHECKPOINT_TOKEN_PREFIX,
    FLOW_CHECKPOINT_NAMESPACE,
    HITL_STATE_NAMESPACE,
    ActionRiskTier,
    ApprovalManager,
    FlowCheckpointRecord,
    FlowCheckpointStore,
    HITLPolicy,
    InMemoryStateStore,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
    SQLiteStateStore,
    StateRecord,
    StateStore,
)


async def _make_store(kind: str, tmp_path: Path) -> StateStore:
    if kind == "memory":
        return InMemoryStateStore()
    return SQLiteStateStore(tmp_path / "state.db")


class TestStateStoreContract:
    """Единый контрактный набор тестов для InMemoryStateStore и SQLiteStateStore."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", ["memory", "sqlite"])
    async def test_put_get_cas_and_delete(self, kind: str, tmp_path: Path) -> None:
        store = await _make_store(kind, tmp_path)
        assert isinstance(store, StateStore)
        try:
            assert await store.get("ns1", "k1") is None

            # Insert-only (expected_version=0)
            rec1 = await store.put(
                "ns1",
                "k1",
                {"hello": "world", "nested": {"v": 1}},
                expected_version=0,
                tenant_id="acme",
                status="PENDING",
            )
            assert rec1.version == 1
            assert rec1.tenant_id == "acme"
            assert rec1.status == "PENDING"

            # Повторный insert-only должен упасть с ConcurrencyConflictError
            with pytest.raises(ConcurrencyConflictError) as exc_info:
                await store.put("ns1", "k1", {"hello": "dup"}, expected_version=0)
            assert exc_info.value.expected_version == 0
            assert exc_info.value.actual_version == 1

            # Deep-copy isolation: мутация полученного value не меняет хранилище
            fetched = await store.get("ns1", "k1")
            assert fetched is not None
            fetched.value["nested"]["v"] = 999
            fetched2 = await store.get("ns1", "k1")
            assert fetched2 is not None
            assert fetched2.value["nested"]["v"] == 1

            # CAS update: неверная версия падает
            with pytest.raises(ConcurrencyConflictError) as exc_cas:
                await store.put("ns1", "k1", {"hello": "stale"}, expected_version=2)
            assert exc_cas.value.expected_version == 2
            assert exc_cas.value.actual_version == 1

            # CAS update: корректная версия инкрементирует version
            rec2 = await store.put(
                "ns1",
                "k1",
                {"hello": "updated"},
                expected_version=1,
                tenant_id="acme",
                status="APPROVED",
            )
            assert rec2.version == 2
            assert rec2.status == "APPROVED"

            # Безусловный upsert (expected_version=None)
            rec3 = await store.put("ns1", "k1", {"hello": "forced"}, expected_version=None)
            assert rec3.version == 3
            assert rec3.value["hello"] == "forced"

            # Удаление
            assert await store.delete("ns1", "k1") is True
            assert await store.delete("ns1", "k1") is False
            assert await store.get("ns1", "k1") is None
        finally:
            await store.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", ["memory", "sqlite"])
    async def test_list_filtering_tenant_isolation_and_ttl_pruning(
        self, kind: str, tmp_path: Path
    ) -> None:
        store = await _make_store(kind, tmp_path)
        try:
            await store.put("ns_a", "k1", {"n": 1}, tenant_id="acme", status="PENDING")
            await store.put("ns_a", "k2", {"n": 2}, tenant_id="globex", status="APPROVED")
            await store.put("ns_a", "k3", {"n": 3}, tenant_id=None, status="PENDING")
            await store.put("ns_b", "k1", {"n": 4}, tenant_id="acme", status="PENDING")
            # Истекшая запись (ttl_seconds очень маленький)
            await store.put(
                "ns_a",
                "k_exp",
                {"n": 5},
                ttl_seconds=0.01,
                tenant_id="acme",
                status="PENDING",
            )
            await asyncio.sleep(0.03)

            # Namespace isolation
            ns_b = await store.list("ns_b")
            assert [r.key for r in ns_b] == ["k1"]

            # Strict tenant isolation
            acme_strict = await store.list("ns_a", tenant_id="acme", strict_tenant=True)
            assert [r.key for r in acme_strict] == ["k1"]

            untagged_strict = await store.list("ns_a", tenant_id=None, strict_tenant=True)
            assert [r.key for r in untagged_strict] == ["k3"]

            # Status filter
            approved_only = await store.list("ns_a", status="APPROVED")
            assert [r.key for r in approved_only] == ["k2"]

            # Expired records excluded by default, included on demand
            all_active = await store.list("ns_a", include_expired=False)
            assert "k_exp" not in {r.key for r in all_active}
            all_with_exp = await store.list("ns_a", include_expired=True)
            assert "k_exp" in {r.key for r in all_with_exp}

            # Prune expired
            removed = await store.prune_expired("ns_a")
            assert removed == 1
            assert await store.get("ns_a", "k_exp") is None
        finally:
            await store.close()


class TestSQLiteStateStoreSecurityAndWAL:
    """Проверки WAL-режима, прав доступа 0o600, защиты от symlink и единого state.db."""

    @pytest.mark.asyncio
    async def test_sqlite_wal_mode_permissions_and_memory_mode(self, tmp_path: Path) -> None:
        db_path = tmp_path / "subdir" / "state.db"
        store = SQLiteStateStore(db_path)
        try:
            await store.put("ns", "k", {"ok": True}, expected_version=0)
            assert db_path.is_file()

            with sqlite3.connect(str(db_path)) as conn:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                assert str(mode).lower() == "wal"

            if sys.platform != "win32":
                assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
        finally:
            await store.close()

        # :memory: режим работает без создания файлов
        mem_store = SQLiteStateStore(":memory:")
        try:
            rec = await mem_store.put("ns", "k", {"v": 42}, expected_version=0)
            assert rec.version == 1
            got = await mem_store.get("ns", "k")
            assert got is not None and got.value == {"v": 42}
        finally:
            await mem_store.close()

    @pytest.mark.asyncio
    async def test_sqlite_rejects_symlink_on_db_and_wal_sidecar(self, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX symlink permissions test")

        real_target = tmp_path / "real.db"
        real_target.write_bytes(b"")
        link_db = tmp_path / "evil_link.db"
        os.symlink(real_target, link_db)

        with pytest.raises(PermissionError, match="symlink"):
            SQLiteStateStore(link_db)

        # Проверка symlink на -wal sidecar
        db_path = tmp_path / "victim.db"
        wal_link = tmp_path / "victim.db-wal"
        os.symlink(real_target, wal_link)
        with pytest.raises(PermissionError, match="symlink"):
            SQLiteStateStore(db_path)

    @pytest.mark.asyncio
    async def test_mcp_server_shares_single_sqlite_db_for_hitl_and_checkpoints(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "shared_state.db"
        reg = MCPHostRegistry.from_sources(
            include_local=True,
            policy=MCPSecurityPolicy(hitl=HITLPolicy(enabled=True, store_path=str(db_path))),
        )
        server = MCPServer(registry=reg)
        try:
            assert isinstance(server.state_store, SQLiteStateStore)
            assert server.approval_manager.store is server.state_store
            assert server.checkpoint_store.store is server.state_store

            req = await server.approval_manager.create_request(
                target_host="local",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
                command="reboot",
            )
            fake_report = type(
                "_Rep",
                (),
                {"flow_name": "demo", "run_id": "run_shared_1", "ok": False, "results": {}},
            )()
            await server.checkpoint_store.record_from_report(fake_report, targets=["local"])

            # В директории не должно быть legacy .json, .key или .lock файлов
            files = {p.name for p in tmp_path.iterdir()}
            assert not any(name.endswith((".json", ".key", ".lock")) for name in files)
            assert "shared_state.db" in files

            hitl_rows = await server.state_store.list(HITL_STATE_NAMESPACE)
            cp_rows = await server.state_store.list(FLOW_CHECKPOINT_NAMESPACE)
            assert [r.key for r in hitl_rows] == [req.approval_id]
            assert [r.key for r in cp_rows] == ["run_shared_1"]
        finally:
            await server.close()


class TestAtomicCASConcurrencyAndIPC:
    """Тесты гонок verify_and_consume (async + multi-process) и кастомного StateStore."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", ["memory", "sqlite"])
    async def test_concurrent_verify_and_consume_allows_strictly_one_winner(
        self, kind: str, tmp_path: Path
    ) -> None:
        store = await _make_store(kind, tmp_path)
        mgr = ApprovalManager(store=store, secret="race-secret")
        try:
            req = await mgr.create_request(
                target_host="prod-01",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
                command="systemctl restart nginx",
                parameters={"command": "systemctl restart nginx"},
            )
            await mgr.approve(req.approval_id, decided_by="sre-lead")

            async def _attempt() -> str:
                try:
                    await mgr.verify_and_consume(
                        req.approval_id,
                        target_host="prod-01",
                        tool_name="uniconn_run",
                        command="systemctl restart nginx",
                        parameters={"command": "systemctl restart nginx"},
                    )
                    return "OK"
                except ApprovalAlreadyConsumedError:
                    return "ALREADY_CONSUMED"

            outcomes = await asyncio.gather(*(_attempt() for _ in range(12)))
            assert outcomes.count("OK") == 1
            assert outcomes.count("ALREADY_CONSUMED") == 11
        finally:
            await store.close()

    @pytest.mark.asyncio
    async def test_multiprocess_sqlite_wal_ipc_race(self, tmp_path: Path) -> None:
        """Два независимых Python-процесса одновременно пытаются поглотить одну заявку из SQLite WAL."""
        db_path = tmp_path / "ipc_state.db"
        mgr = ApprovalManager(store_path=db_path)
        try:
            req = await mgr.create_request(
                target_host="prod-01",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
                command="reboot",
                parameters={"command": "reboot"},
            )
            await mgr.approve(req.approval_id, decided_by="ops")
            appr_id = req.approval_id
        finally:
            await mgr.close()

        worker_code = (
            "import asyncio, sys\n"
            "from uniconn.mcp import ApprovalManager\n"
            "from uniconn.exceptions import ApprovalAlreadyConsumedError\n"
            "async def main():\n"
            "    mgr = ApprovalManager(store_path=sys.argv[1])\n"
            "    try:\n"
            "        await mgr.verify_and_consume(\n"
            "            sys.argv[2], target_host='prod-01', tool_name='uniconn_run',\n"
            "            command='reboot', parameters={'command': 'reboot'},\n"
            "        )\n"
            "        print('WIN')\n"
            "    except ApprovalAlreadyConsumedError:\n"
            "        print('CONSUMED')\n"
            "    finally:\n"
            "        await mgr.close()\n"
            "asyncio.run(main())\n"
        )

        procs = await asyncio.gather(
            *(
                asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    worker_code,
                    str(db_path),
                    appr_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                for _ in range(4)
            )
        )
        results = []
        for p in procs:
            out_b, err_b = await asyncio.wait_for(p.communicate(), timeout=20)
            assert p.returncode == 0, f"Child process failed: {err_b.decode('utf-8', errors='replace')}"
            results.append(out_b.decode("utf-8", errors="replace").strip())

        assert results.count("WIN") == 1
        assert results.count("CONSUMED") == 3

    @pytest.mark.asyncio
    async def test_custom_state_store_protocol_adapter_in_mcp_server(self) -> None:
        """Пользовательский адаптер StateStore подключается к MCPServer без зависимостей ядра."""

        class _DictCustomStore:
            def __init__(self) -> None:
                self.data: dict[tuple[str, str], StateRecord] = {}
                self.put_calls = 0

            async def get(
                self,
                namespace: str,
                key: str,
                *,
                tenant_id: str | None = None,
                strict_tenant: bool = False,
            ) -> StateRecord | None:
                rec = self.data.get((namespace, key))
                if rec is None:
                    return None
                if (strict_tenant or tenant_id is not None) and rec.tenant_id != tenant_id:
                    return None
                return rec

            async def put(
                self,
                namespace: str,
                key: str,
                value: Any,
                *,
                expected_version: int | None = None,
                ttl_seconds: float | None = None,
                tenant_id: str | None = None,
                status: str | None = None,
            ) -> StateRecord:
                existing = self.data.get((namespace, key))
                cur_v = existing.version if existing else 0
                if expected_version is not None and cur_v != expected_version:
                    raise ConcurrencyConflictError(
                        "conflict",
                        namespace=namespace,
                        key=key,
                        expected_version=expected_version,
                        actual_version=cur_v,
                    )
                now = time.time()
                rec = StateRecord(
                    namespace=namespace,
                    key=key,
                    value=json.loads(json.dumps(dict(value))),
                    version=cur_v + 1,
                    created_at=existing.created_at if existing else now,
                    updated_at=now,
                    expires_at=(now + ttl_seconds) if ttl_seconds is not None else None,
                    tenant_id=tenant_id,
                    status=status,
                )
                self.data[(namespace, key)] = rec
                self.put_calls += 1
                return rec

            async def list(
                self,
                namespace: str,
                *,
                tenant_id: str | None = None,
                strict_tenant: bool = False,
                status: str | None = None,
                include_expired: bool = False,
            ) -> list[StateRecord]:
                out = [r for (ns, _), r in self.data.items() if ns == namespace]
                if strict_tenant or tenant_id is not None:
                    out = [r for r in out if r.tenant_id == tenant_id]
                if status is not None:
                    out = [r for r in out if r.status == status]
                if not include_expired:
                    out = [r for r in out if not r.is_expired()]
                return out

            async def delete(self, namespace: str, key: str) -> bool:
                return self.data.pop((namespace, key), None) is not None

            async def prune_expired(self, namespace: str, *, now: float | None = None) -> int:
                return 0

            async def close(self) -> None:
                return None

        custom = _DictCustomStore()
        assert isinstance(custom, StateStore)
        reg = MCPHostRegistry.from_sources(include_local=True)
        server = MCPServer(registry=reg, state_store=custom)
        req = await server.approval_manager.create_request(
            target_host="local",
            tool_name="uniconn_run",
            risk_tier=ActionRiskTier.TIER_1_MUTATING,
            command="touch /tmp/x",
        )
        assert custom.put_calls >= 1
        fetched = await server.approval_manager.get_request(req.approval_id)
        assert fetched.approval_id == req.approval_id


class TestSignedOpaqueCheckpointTokens:
    """Тесты 100% stateless Flow resume через HMAC-подписанные opaque checkpoint_token."""

    @pytest.mark.asyncio
    async def test_stateless_flow_resume_across_two_isolated_inmemory_servers(self) -> None:
        """Flow падает на MCPServer #1 (RAM) -> возобновляется на MCPServer #2 (чистый RAM) по token."""
        step_runs = {"step1": 0, "step2": 0}
        fail_step2 = True

        @task(name="step1_prepare", tags=["safe"])
        async def step1_prepare(conn: Connection) -> Result:
            step_runs["step1"] += 1
            return await conn.run("echo prepared")

        @task(name="step2_apply", depends_on=[step1_prepare], tags=["safe"])
        async def step2_apply(conn: Connection) -> Result:
            step_runs["step2"] += 1
            if fail_step2:
                return await conn.run("sh -c 'echo boom >&2; exit 2'", raise_on_error=False)
            return await conn.run("echo applied")

        flow = Flow(name="stateless_deploy", tasks=[step2_apply], risk_tier="safe")
        shared_secret = "cluster-shared-checkpoint-secret-256bit"

        server_a = MCPServer(
            registry=MCPHostRegistry.from_sources(include_local=True),
            flows=[flow],
            checkpoint_secret=shared_secret,
        )
        assert isinstance(server_a.state_store, InMemoryStateStore)

        resp1 = await server_a.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_run_flow",
                    "arguments": {"flow_name": "stateless_deploy", "targets": ["local"]},
                },
            }
        )
        assert isinstance(resp1, dict)
        data1 = json.loads(resp1["result"]["content"][0]["text"])
        assert data1["ok"] is False
        assert data1["can_resume"] is True
        token = data1["checkpoint_token"]
        assert isinstance(token, str) and token.startswith(CHECKPOINT_TOKEN_PREFIX)
        assert step_runs == {"step1": 1, "step2": 1}

        # Второй совершенно новый MCPServer с пустым InMemoryStateStore (нет общей БД!)
        server_b = MCPServer(
            registry=MCPHostRegistry.from_sources(include_local=True),
            flows=[flow],
            checkpoint_secret=shared_secret,
        )
        assert await server_b.checkpoint_store.list_records() == []

        fail_step2 = False
        resp2 = await server_b.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_resume_flow",
                    "arguments": {"checkpoint_token": token},
                },
            }
        )
        assert isinstance(resp2, dict)
        assert resp2["result"]["isError"] is False
        data2 = json.loads(resp2["result"]["content"][0]["text"])
        assert data2["ok"] is True
        assert data2["resumed_from"] == data1["run_id"]
        # step1_prepare не выполнялся повторно!
        assert step_runs == {"step1": 1, "step2": 2}

    def test_checkpoint_token_security_tamper_expiry_tenant_and_zipbomb(self) -> None:
        secret = "top-secret-key"
        store = FlowCheckpointStore(signing_secret=secret, ttl_seconds=60.0)
        rec = FlowCheckpointRecord(
            run_id="run_tok_1",
            flow_name="deploy",
            targets=["web-01"],
            completed_by_host={"web-01": ["preflight"]},
            tenant_id="acme",
        )
        token = store.encode_token(rec)
        decoded = store.decode_token(token, tenant_id="acme", strict_tenant=True)
        assert decoded.run_id == "run_tok_1"
        assert decoded.completed_by_host == {"web-01": ["preflight"]}

        # 1. Подмена подписи отклоняется
        bad_sig_token = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with pytest.raises(ValueError, match="signature"):
            store.decode_token(bad_sig_token)

        # 2. Другой секрет отклоняется
        other_store = FlowCheckpointStore(signing_secret="different-secret")
        with pytest.raises(ValueError, match="signature"):
            other_store.decode_token(token)

        # 3. Чужой тенант при strict_tenant=True -> PermissionError
        with pytest.raises(PermissionError, match="tenant"):
            store.decode_token(token, tenant_id="globex", strict_tenant=True)

        # 4. Истёкший токен отклоняется
        with pytest.raises(ValueError, match="expired"):
            store.decode_token(token, now=time.time() + 120.0)

        # 5. Zip-bomb (сжатый payload распаковывается в > 512 КБ) отклоняется
        huge_raw = b"A" * (600 * 1024)
        compressed = zlib.compress(huge_raw, level=9)
        body_b64 = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")
        sig = hmac.new(
            secret.encode("utf-8"),
            f"{CHECKPOINT_TOKEN_PREFIX}{body_b64}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        bomb_token = f"{CHECKPOINT_TOKEN_PREFIX}{body_b64}.{sig_b64}"
        with pytest.raises(ValueError, match="decompressed"):
            store.decode_token(bomb_token)

        # 6. Превышение max_token_bytes: encode_token -> ValueError, try_encode_token -> None
        tiny_store = FlowCheckpointStore(signing_secret=secret, max_token_bytes=1024)
        big_rec = FlowCheckpointRecord(
            run_id="run_tok_big",
            flow_name="deploy",
            targets=["web-01"],
            vars={"blob": os.urandom(2048).hex()},
        )
        with pytest.raises(ValueError, match="max_token_bytes"):
            tiny_store.encode_token(big_rec)
        assert tiny_store.try_encode_token(big_rec) is None


class TestCLIStatelessAndStateDBFlags:
    """Проверки CLI-флагов --stateless, --state-db и :memory: (ноль файлов на диске)."""

    @pytest.mark.asyncio
    async def test_cli_stateless_and_memory_store_create_zero_files(self, tmp_path: Path) -> None:
        common_kwargs: dict[str, Any] = {
            "inventory": None,
            "parsed_uris": (),
            "group": None,
            "host": None,
            "local": True,
            "allow_write": False,
            "allow_sudo": False,
            "allow_dynamic_uri": False,
            "dry_run": False,
            "allowlist": None,
            "blocklist": None,
            "audit_log": None,
            "max_read_bytes": 65536,
            "hitl": True,
            "hitl_timeout": 300.0,
            "hitl_wait": False,
            "hitl_webhook_url": None,
            "parsed_flows": (),
            "policy_engine": "embedded",
            "policy_preset": "default",
            "policy_file": None,
            "opa_url": None,
            "agent_role": "operator",
        }

        # 1. --stateless без --state-db -> чистый InMemoryStateStore
        srv_stateless = _build_mcp_server_from_args(
            **common_kwargs,
            hitl_store=None,
            stateless=True,
            checkpoint_secret="my-secret",
        )
        assert isinstance(srv_stateless.state_store, InMemoryStateStore)
        assert srv_stateless.checkpoint_store._signing_key == b"my-secret"

        # 2. --state-db :memory: -> чистый InMemoryStateStore
        srv_mem = _build_mcp_server_from_args(
            **common_kwargs,
            hitl_store=":memory:",
            stateless=False,
        )
        assert isinstance(srv_mem.state_store, InMemoryStateStore)

        # 3. Явный --state-db <path> -> SQLiteStateStore WAL
        db_file = tmp_path / "cli_state.db"
        srv_sql = _build_mcp_server_from_args(
            **common_kwargs,
            hitl_store=str(db_file),
            stateless=False,
        )
        try:
            assert isinstance(srv_sql.state_store, SQLiteStateStore)
            assert srv_sql.approval_manager.store is srv_sql.state_store
            assert srv_sql.checkpoint_store.store is srv_sql.state_store
            await srv_sql.approval_manager.create_request(
                target_host="local",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_1_MUTATING,
                command="echo hi",
            )
            assert db_file.is_file()
        finally:
            await srv_sql.close()


class TestReviewRegressionFixes:
    """Регрессионные тесты на баги, выявленные в ходе ревью слоя StateStore / HITL / Checkpoints."""

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permissions check")
    @pytest.mark.asyncio
    async def test_sqlite_does_not_chmod_preexisting_parent_dir(self, tmp_path: Path) -> None:
        shared_dir = tmp_path / "shared_parent"
        shared_dir.mkdir(mode=0o755)
        os.chmod(shared_dir, 0o755)

        store = SQLiteStateStore(shared_dir / "state.db")
        try:
            assert stat.S_IMODE(shared_dir.stat().st_mode) == 0o755
            assert stat.S_IMODE((shared_dir / "state.db").stat().st_mode) == 0o600
        finally:
            await store.close()

        # А вновь создаваемая поддиректория получает строгие права 0o700
        nested_dir = tmp_path / "brand_new_private_dir"
        store2 = SQLiteStateStore(nested_dir / "state.db")
        try:
            assert stat.S_IMODE(nested_dir.stat().st_mode) == 0o700
            assert stat.S_IMODE((nested_dir / "state.db").stat().st_mode) == 0o600
        finally:
            await store2.close()

        with pytest.raises(IsADirectoryError):
            SQLiteStateStore(shared_dir)

    @pytest.mark.asyncio
    async def test_non_finite_ttl_rejected(self, tmp_path: Path) -> None:
        mem = InMemoryStateStore()
        sql = SQLiteStateStore(tmp_path / "ttl.db")
        cp_store = FlowCheckpointStore(signing_secret="s")
        rec = FlowCheckpointRecord(run_id="r1", flow_name="f", targets=["local"])
        try:
            for bad_ttl in (float("nan"), float("inf"), float("-inf")):
                with pytest.raises(ValueError, match="finite"):
                    await mem.put("ns", "k", {"a": 1}, ttl_seconds=bad_ttl)
                with pytest.raises(ValueError, match="finite"):
                    await sql.put("ns", "k", {"a": 1}, ttl_seconds=bad_ttl)
                with pytest.raises(ValueError, match="finite"):
                    cp_store.encode_token(rec, ttl_seconds=bad_ttl)
        finally:
            await sql.close()

    @pytest.mark.asyncio
    async def test_reject_retries_cas_when_racing_with_approve(self) -> None:
        base_store = InMemoryStateStore()
        mgr = ApprovalManager(
            policy=HITLPolicy(enabled=True, channels=()),
            store=base_store,
            secret="race-secret",
        )
        req = await mgr.create_request(
            target_host="prod-1",
            tool_name="uniconn_run",
            risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
            command="reboot",
        )

        # Имитируем гонку: между get() и put() внутри reject() кто-то успевает выполнить approve()
        original_put = base_store.put
        injected = False

        async def _racing_put(*args: Any, **kwargs: Any) -> StateRecord:
            nonlocal injected
            if not injected and kwargs.get("status") == "REJECTED":
                injected = True
                # Параллельно одобряем заявку, повышая её версию с 1 до 2
                await mgr.approve(req.approval_id, decided_by="concurrent-approver")
            return await original_put(*args, **kwargs)

        base_store.put = _racing_put  # type: ignore[method-assign]
        final_req = await mgr.reject(req.approval_id, decided_by="secops", reason="Block maintenance")
        assert injected is True
        assert final_req.status.value == "REJECTED"
        assert final_req.decided_by == "secops"
        persisted = await mgr.get_request(req.approval_id)
        assert persisted.status.value == "REJECTED"

    @pytest.mark.asyncio
    async def test_cold_server_b_decodes_token_via_shared_async_store_secret(self) -> None:
        """Сервер B с общим async StateStore (без явного секрета) синхронизирует ключ до decode_token()."""
        shared_store = InMemoryStateStore()
        fail_step = True

        @task(name="s1")
        async def s1(conn: Connection) -> str:
            return "s1_ok"

        @task(name="s2", depends_on=[s1])
        async def s2(conn: Connection) -> str:
            if fail_step:
                raise RuntimeError("boom")
            return "s2_ok"

        flow = Flow("shared_secret_flow", tasks=[s1, s2])
        server_a = MCPServer(
            registry=MCPHostRegistry.from_sources(include_local=True),
            state_store=shared_store,
            flows=[flow],
        )
        resp1 = await server_a.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_run_flow",
                    "arguments": {"flow_name": "shared_secret_flow", "targets": ["local"]},
                },
            }
        )
        assert isinstance(resp1, dict)
        data1 = json.loads(resp1["result"]["content"][0]["text"])
        token = data1["checkpoint_token"]

        # Сервер B стартует "холодным" против того же shared_store без checkpoint_secret
        server_b = MCPServer(
            registry=MCPHostRegistry.from_sources(include_local=True),
            state_store=shared_store,
            flows=[flow],
        )
        assert server_b.checkpoint_store._secret_synced is False

        fail_step = False
        resp2 = await server_b.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_resume_flow",
                    "arguments": {"checkpoint_token": token},
                },
            }
        )
        assert isinstance(resp2, dict)
        assert resp2["result"]["isError"] is False
        data2 = json.loads(resp2["result"]["content"][0]["text"])
        assert data2["ok"] is True

    @pytest.mark.asyncio
    async def test_decode_token_rejects_non_ascii_and_bool_exp_and_cross_tenant_overwrite(self) -> None:
        secret = "tok-sec"
        cp_store = FlowCheckpointStore(signing_secret=secret)

        # 1. Non-ASCII символы в токене -> чистый ValueError
        with pytest.raises(ValueError, match="non-ASCII"):
            cp_store.decode_token("ucp1.тест.подпись")

        # 2. Подделанный конверт с булевым exp=True (подписанный тем же ключом) отклоняется
        bad_env = json.dumps({"v": 1, "exp": True, "rec": {"run_id": "r", "flow_name": "f"}}).encode("utf-8")
        body = base64.urlsafe_b64encode(zlib.compress(bad_env)).rstrip(b"=").decode("ascii")
        sig = hmac.new(
            secret.encode("utf-8"),
            f"{CHECKPOINT_TOKEN_PREFIX}{body}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        with pytest.raises(ValueError, match="expired"):
            cp_store.decode_token(f"{CHECKPOINT_TOKEN_PREFIX}{body}.{sig_b64}")

        # 3. Запрет перезаписи чужого run_id другим тенантом
        @task(name="ok_step")
        async def ok_step(conn: Connection) -> str:
            return "ok"

        flow = Flow("tenant_guard_flow", tasks=[ok_step])
        async with Connection.from_uri("local://") as conn:
            report = await flow.run(conn)

        await cp_store.record_from_report(report, targets=["local"], run_id="run_shared_id", tenant_id="tenant-a")
        with pytest.raises(PermissionError, match="another tenant"):
            await cp_store.record_from_report(report, targets=["local"], run_id="run_shared_id", tenant_id="tenant-b")

    @pytest.mark.asyncio
    async def test_cli_memory_and_stateless_ignore_env_db_and_server_reuses_manager_store(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # build_mcp_client_config не должен превращать :memory: в путь на диске
        cfg = build_mcp_client_config(hitl=True, hitl_store=":memory:")
        cli_args = cfg["mcpServers"]["uniconn"]["args"]
        idx = cli_args.index("--hitl-store")
        assert cli_args[idx + 1] == ":memory:"

        # Даже если UNICONN_STATE_DB / UNICONN_FLOW_CHECKPOINT_STORE заданы в env,
        # --stateless и --state-db :memory: обязаны остаться zero-disk InMemoryStateStore
        env_db = tmp_path / "env_should_not_be_created.db"
        env_cp = tmp_path / "env_cp_should_not_be_created.db"
        monkeypatch.setenv("UNICONN_STATE_DB", str(env_db))
        monkeypatch.setenv("UNICONN_FLOW_CHECKPOINT_STORE", str(env_cp))

        common_kwargs: dict[str, Any] = {
            "inventory": None,
            "parsed_uris": (),
            "group": None,
            "host": None,
            "local": True,
            "allow_write": False,
            "allow_sudo": False,
            "allow_dynamic_uri": False,
            "dry_run": False,
            "allowlist": None,
            "blocklist": None,
            "audit_log": None,
            "max_read_bytes": 65536,
            "hitl": True,
            "hitl_timeout": 300.0,
            "hitl_wait": False,
            "hitl_webhook_url": None,
            "parsed_flows": (),
            "policy_engine": "embedded",
            "policy_preset": "default",
            "policy_file": None,
            "opa_url": None,
            "agent_role": "operator",
        }
        srv_stateless = _build_mcp_server_from_args(**common_kwargs, hitl_store=None, stateless=True)
        assert isinstance(srv_stateless.state_store, InMemoryStateStore)
        assert isinstance(srv_stateless.checkpoint_store.store, InMemoryStateStore)
        assert not env_db.exists()
        assert not env_cp.exists()

        # MCPServer(approval_manager=mgr) переиспользует mgr.store без дублирования
        custom_store = InMemoryStateStore()
        mgr = ApprovalManager(store=custom_store)
        async with MCPServer(
            registry=MCPHostRegistry.from_sources(include_local=True),
            approval_manager=mgr,
        ) as srv:
            assert srv.state_store is custom_store
            assert srv.checkpoint_store.store is custom_store

