# src/uniconn/mcp/_tools_files.py
"""Файловые MCP-инструменты (read_file, stat_path, checksum, write_file)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shlex
from typing import TYPE_CHECKING, Any, Literal

from .._logging import SecretMaskingFilter
from ..exceptions import (
    CapabilityNotSupportedError,
    ConnectionError,
    ExecutionError,
    FileTransferError,
    TimeoutError,
)
from ..security.models import PolicyDecision
from ._server_gates import MCPServerGatesMixin, _sanitize_json_value
from .hitl import ActionRiskClassifier, build_unified_diff
from .models import MCPHostEntry, MCPSecurityPolicy

if TYPE_CHECKING:
    from .registry import MCPHostRegistry

_logger = logging.getLogger("uniconn.mcp.server")


class MCPFileToolsMixin(MCPServerGatesMixin):
    """Миксин файловых MCP-инструментов (``read_file``, ``stat_path``, ``checksum``, ``write_file``)."""

    if TYPE_CHECKING:
        registry: MCPHostRegistry

        @property
        def policy(self) -> MCPSecurityPolicy: ...

    async def _tool_read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        path = arguments.get("path")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Reading {path!r} on host {entry.name!r}")

        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_read_file",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled and assessment.requires_approval
        )
        if needs_approval:
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entry,
                tool_name="uniconn_read_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

        raw_max = arguments.get("max_bytes")
        req_max = self.policy.max_read_bytes if raw_max is None else int(raw_max)
        limit = max(1, min(req_max, self.policy.max_read_bytes))

        async with self.registry.create_connection(entry) as conn:
            st: Any = None
            with contextlib.suppress(Exception):
                st = await conn.files.stat(path)

            file_size: int | None = None
            if st is not None:
                if st.get("is_dir"):
                    raise IsADirectoryError(f"Path {path!r} is a directory, not a regular file")
                if not st.get("is_file", True) and not st.get("is_symlink", False):
                    raise PermissionError(f"Reading non-regular file or device {path!r} is forbidden")
                raw_sz = st.get("size")
                if isinstance(raw_sz, int) and raw_sz >= 0:
                    file_size = raw_sz

            max_preload_bytes = max(limit * 4, self.policy.max_read_bytes)
            if file_size is not None and file_size > max_preload_bytes:
                if entry.transport != "winrm":
                    head_res = await conn.run(
                        f"head -c {limit + 1} -- {shlex.quote(path)}",
                        raise_on_error=False,
                    )
                    if head_res.ok:
                        encoded = head_res.stdout.encode("utf-8", errors="replace")
                        truncated = len(encoded) > limit or file_size > limit
                        sliced = encoded[:limit]
                        text = sliced.decode("utf-8", errors="replace")
                        return {
                            "target": entry.name,
                            "path": path,
                            "content": SecretMaskingFilter._mask_string(text),
                            "total_bytes": file_size,
                            "truncated": truncated,
                        }
                raise PermissionError(
                    f"File {path!r} ({file_size} bytes) exceeds safe read limit ({max_preload_bytes} bytes)"
                )

            raw_content = await conn.files.read_file(path, encoding=None)
            encoded = (
                raw_content
                if isinstance(raw_content, bytes)
                else str(raw_content).encode("utf-8")
            )
            truncated = len(encoded) > limit
            sliced = encoded[:limit] if truncated else encoded
            text = sliced.decode("utf-8", errors="replace")

            return {
                "target": entry.name,
                "path": path,
                "content": SecretMaskingFilter._mask_string(text),
                "total_bytes": len(encoded),
                "truncated": truncated,
            }

    async def _tool_stat_path(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        path = arguments.get("path")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Inspecting {path!r} on host {entry.name!r}")

        raw_agent_id = arguments.get("agent_id")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_stat_path",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            enforce_deny=True,
        )
        if policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_id = arguments.get("approval_id")
            wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entry,
                tool_name="uniconn_stat_path",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

        async with self.registry.create_connection(entry) as conn:
            exists = await conn.files.exists(path)
            if not exists:
                return {"target": entry.name, "path": path, "exists": False, "stat": None}
            st = await conn.files.stat(path)
            return {
                "target": entry.name,
                "path": path,
                "exists": True,
                "stat": _sanitize_json_value(dict(st)),
            }

    async def _tool_checksum(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        path = arguments.get("path")
        if not raw_targets:
            raise ValueError("Parameter 'targets' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")
        raw_algo = str(arguments.get("algorithm") or "sha256").lower()
        algo: Literal["sha256", "sha1", "md5"]
        if raw_algo == "md5":
            algo = "md5"
        elif raw_algo == "sha1":
            algo = "sha1"
        elif raw_algo == "sha256":
            algo = "sha256"
        else:
            raise ValueError(f"Unsupported checksum algorithm: {raw_algo!r}")

        entries = self.registry.resolve_targets(raw_targets)
        is_prod = any(e.is_production(self.policy.hitl.prod_groups) for e in entries)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Hashing {path!r}")

        raw_agent_id = arguments.get("agent_id")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name="uniconn_checksum",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            enforce_deny=True,
        )
        if policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_id = arguments.get("approval_id")
            wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            target_label = entries[0].name if len(entries) == 1 else ",".join(e.name for e in entries)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entries[0],
                target_host=target_label,
                tool_name="uniconn_checksum",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path, "algorithm": algo},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

        async def _hash_one(entry: MCPHostEntry) -> tuple[str, str | None]:
            async with self.registry.create_connection(entry) as conn:
                return entry.name, await conn.files.checksum(path, algorithm=algo)

        pairs = await asyncio.gather(*(_hash_one(e) for e in entries))
        checksums: dict[str, str | None] = dict(pairs)

        unique_hashes = {h for h in checksums.values() if h is not None}
        return {
            "path": path,
            "algorithm": algo,
            "checksums": checksums,
            "all_match": len(unique_hashes) == 1 and None not in checksums.values(),
        }

    async def _inspect_remote_file_for_diff(
        self,
        entry: MCPHostEntry,
        path: str,
        new_content: str,
    ) -> tuple[bool, str]:
        """Проверить существование целевого файла и вычислить unified diff."""
        old_text: str | None = None
        exists = False
        try:
            async with self.registry.create_connection(entry) as conn:
                exists = await conn.files.exists(path)
                if exists:
                    raw = await conn.files.read_file(path, encoding=None)
                    raw_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
                    old_text = raw_bytes[: self.policy.max_read_bytes].decode("utf-8", errors="replace")
        except (
            OSError,
            ExecutionError,
            FileTransferError,
            CapabilityNotSupportedError,
            TimeoutError,
            ConnectionError,
            RuntimeError,
            ValueError,
        ) as exc:
            _logger.debug(
                "Remote diff inspection fallback to empty baseline for %s:%s (%s)",
                entry.name,
                path,
                exc,
            )
        return exists, build_unified_diff(path, old_text, new_content)

    async def _tool_write_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        hitl_override_ok = self.policy.hitl.enabled and self.policy.hitl.allow_operator_override
        if not self.policy.allow_write and not hitl_override_ok:
            raise PermissionError(
                "File modification (uniconn_write_file) is disabled by default MCP security "
                "policy (start server with --allow-write to enable)."
            )

        target = arguments.get("target")
        path = arguments.get("path")
        content = arguments.get("content")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")
        if not isinstance(content, str):
            raise ValueError("Parameter 'content' must be a string")

        atomic = bool(arguments.get("atomic", True))
        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)

        file_exists = False
        diff_str: str | None = None
        if self.policy.hitl.enabled:
            file_exists, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)

        assessment = ActionRiskClassifier.classify_file_write(
            path,
            file_exists=file_exists,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Writing to {path!r} on host {entry.name!r}")
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_write_file",
            action_type="file_write",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        if policy_requires_appr and diff_str is None:
            _, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled
            and (assessment.requires_approval or not self.policy.allow_write)
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        hmac_params = {"path": path, "content": content, "atomic": atomic}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_write_file",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            parameters=hmac_params,
            diff=diff_str,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
        )
        if pending_payload is not None:
            return pending_payload

        async with self.registry.create_connection(entry) as conn:
            await conn.files.write_file(path, content, atomic=atomic)
            result_payload: dict[str, Any] = {
                "target": entry.name,
                "path": path,
                "bytes_written": len(content.encode("utf-8")),
                "atomic": atomic,
                "risk_tier": assessment.risk_tier.value,
                "policy_decision": policy_eval.decision.value,
                "dry_run": self.policy.dry_run,
            }
            if consumed_req is not None:
                result_payload["approval"] = self._serialize_approval(consumed_req)
            return result_payload


__all__ = ["MCPFileToolsMixin"]
