# src/uniconn/mcp/_tools_governance.py
"""MCP-инструменты governance (propose_action, evaluate_policy, approvals) и оркестрации Flow."""

from __future__ import annotations

import contextlib
import uuid
from typing import TYPE_CHECKING, Any, Literal

from ..orchestration.flow import Flow
from ..orchestration.scheduler import coerce_to_flow
from ..security.ast_parser import CommandASTParser
from ..security.models import PolicyDecision
from ..services.provisioning._fleet_plan import FleetChangePlan
from ._server_gates import MCPServerGatesMixin, _parse_tags_list
from .flows import (
    FlowCheckpointRecord,
    FlowCheckpointStore,
    FlowRiskEvaluator,
    FlowSchemaGenerator,
    MCPFlowRegistry,
)
from .hitl import ActionRiskClassifier, ApprovalManager
from .models import ApprovalStatus, MCPHostEntry, MCPSecurityPolicy

if TYPE_CHECKING:
    from .registry import MCPHostRegistry


class MCPGovernanceToolsMixin(MCPServerGatesMixin):
    """Миксин MCP-инструментов согласования (HITL), оценки политик и запуска ``Flow``."""

    if TYPE_CHECKING:
        registry: MCPHostRegistry
        approval_manager: ApprovalManager
        flow_registry: MCPFlowRegistry
        checkpoint_store: FlowCheckpointStore

        @property
        def policy(self) -> MCPSecurityPolicy: ...

        async def _inspect_remote_file_for_diff(
            self, entry: MCPHostEntry, path: str, new_content: str
        ) -> tuple[bool, str]: ...

    def _cache_fleet_plan(self, plan: FleetChangePlan) -> None:
        """Сохранить ``FleetChangePlan`` в ограниченном tenant-изолированном кэше по ``plan_hash``."""
        cache: dict[tuple[str | None, str], FleetChangePlan] | None = getattr(
            self, "_fleet_plan_cache", None
        )
        if cache is None:
            cache = {}
            self._fleet_plan_cache = cache
        key = (self._active_tenant_id(), plan.plan_hash)
        cache[key] = plan
        while len(cache) > 256:
            cache.pop(next(iter(cache)))

    def _get_cached_fleet_plan(self, plan_hash: str) -> FleetChangePlan | None:
        """Найти ранее собранный ``FleetChangePlan`` по ``plan_hash`` в рамках текущего тенанта."""
        cache: dict[tuple[str | None, str], FleetChangePlan] | None = getattr(
            self, "_fleet_plan_cache", None
        )
        if not cache:
            return None
        return cache.get((self._active_tenant_id(), plan_hash))

    async def _build_live_flow_plan(
        self,
        flow_obj: Flow,
        entries: list[MCPHostEntry],
        *,
        vars: dict[str, Any],
        tags: list[str] | None,
        mode: str,
    ) -> tuple[FleetChangePlan | None, str | None]:
        """Построить живой read-only ``FleetChangePlan`` с безопасным fallback при ошибках."""
        if not entries:
            return None, "No target hosts resolved"
        try:
            active_flow = coerce_to_flow(flow_obj, mode=mode)
            reg = self._active_registry()
            if len(entries) == 1:
                async with reg.create_connection(
                    entries[0],
                    dry_run=True,
                    auto_diagnostics=False,
                ) as conn:
                    plan = await active_flow.plan(
                        conn,
                        vars=vars,
                        tags=tags,
                    )
            else:
                pool = reg.create_pool(
                    entries,
                    dry_run=True,
                    auto_diagnostics=False,
                )
                async with pool:
                    plan = await active_flow.plan(
                        pool,
                        vars=vars,
                        tags=tags,
                    )
            self._cache_fleet_plan(plan)
            return plan, None
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _serialize_fleet_plan(plan: FleetChangePlan) -> dict[str, Any]:
        """Сериализовать ``FleetChangePlan`` для ответа MCP-инструмента."""
        return plan.to_dict(include_rendered=True)

    async def _propose_flow_action(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        flow_key = str(arguments.get("flow_name") or tool_name).strip()
        flow_obj = self.flow_registry.get_flow(flow_key)
        canonical_tool = self.flow_registry.get_tool_name(flow_obj.name)
        eff_tool = tool_name if tool_name == "uniconn_run_flow" else canonical_tool

        entries, group_str, tags_list = self._resolve_flow_targets_and_tags(arguments)
        validated_vars = FlowSchemaGenerator.extract_and_validate_vars(
            flow_obj,
            arguments,
            tags=tags_list,
        )
        eff_mode = str(arguments.get("mode") or flow_obj.mode)
        assessment, plan_preview = FlowRiskEvaluator.evaluate(
            flow_obj,
            entries=entries,
            vars=validated_vars,
            tags=tags_list,
            mode=eff_mode,
            dry_run=False,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Proposed flow {flow_obj.name!r}")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name=eff_tool,
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=f"flow:{flow_obj.name}",
            flow_name=flow_obj.name,
            flow_tasks=tuple(flow_obj.tasks.keys()),
            agent_id=str(agent_id) if agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        want_live_plan = bool(arguments.get("live_plan", True))
        fleet_plan: FleetChangePlan | None = None
        live_plan_error: str | None = None
        if want_live_plan and entries:
            fleet_plan, live_plan_error = await self._build_live_flow_plan(
                flow_obj,
                entries,
                vars=validated_vars,
                tags=tags_list,
                mode=eff_mode,
            )

        approval_diff = plan_preview
        host_label = ",".join(e.name for e in entries)
        hmac_params: dict[str, Any] = {
            "flow_name": flow_obj.name,
            "targets": [e.name for e in entries],
            "group": group_str or "",
            "vars": validated_vars,
            "tags": list(tags_list or ()),
            "mode": eff_mode,
        }
        if fleet_plan is not None:
            hmac_params["plan_hash"] = fleet_plan.plan_hash
            live_diff = fleet_plan.to_diff()
            if live_diff:
                approval_diff = (
                    f"{plan_preview}\n\n"
                    f"# Live FleetChangePlan (hash={fleet_plan.plan_hash[:12]})\n"
                    f"{live_diff}"
                )

        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        eff_agent_id, eff_tenant_id = self._resolve_hitl_actor(agent_id)
        req = await self.approval_manager.create_request(
            target_host=host_label,
            tool_name=eff_tool,
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            command=f"flow:{flow_obj.name}",
            parameters=hmac_params,
            diff=approval_diff,
            agent_id=eff_agent_id,
            tenant_id=eff_tenant_id,
        )
        out: dict[str, Any] = {
            "assessment": assessment.to_dict(),
            "policy": policy_eval.to_dict(),
            "plan_preview": plan_preview,
            "approval": req.to_public_dict(),
        }
        if fleet_plan is not None:
            out["plan_hash"] = fleet_plan.plan_hash
            out["fleet_plan"] = self._serialize_fleet_plan(fleet_plan)
        elif live_plan_error is not None:
            out["live_plan_error"] = live_plan_error
        return out

    async def _tool_propose_action(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(arguments.get("tool_name") or "uniconn_run").strip()
        if tool_name == "uniconn_run_flow" or tool_name.startswith("flow_"):
            return await self._propose_flow_action(tool_name, arguments)

        agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        eff_agent_id, eff_tenant_id = self._resolve_hitl_actor(agent_id)
        target = arguments.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        entry = self._active_registry().get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)

        if tool_name == "uniconn_read_file":
            path = str(arguments.get("path") or "").strip()
            if not path:
                raise ValueError("Parameter 'path' is required when proposing 'uniconn_read_file'")
            assessment = ActionRiskClassifier.classify_file_read(
                path,
                is_production=is_prod,
                policy=self.policy.hitl,
            )
            self._assert_not_forbidden(assessment, f"Proposed file read of {path!r}")
            _, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                tool_name="uniconn_read_file",
                action_type="file_read",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=str(agent_id) if agent_id else None,
                role=str(raw_role) if raw_role else None,
                enforce_deny=True,
            )
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            req = await self.approval_manager.create_request(
                target_host=entry.name,
                tool_name="uniconn_read_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                parameters={"path": path},
                agent_id=eff_agent_id,
                tenant_id=eff_tenant_id,
            )
            return {
                "assessment": assessment.to_dict(),
                "policy": policy_eval.to_dict(),
                "approval": req.to_public_dict(),
            }

        if tool_name == "uniconn_write_file":
            path = str(arguments.get("path") or "").strip()
            content = arguments.get("content")
            if not path or not isinstance(content, str):
                raise ValueError("Parameters 'path' and 'content' are required when proposing 'uniconn_write_file'")
            atomic = bool(arguments.get("atomic", True))
            file_exists, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)
            assessment = ActionRiskClassifier.classify_file_write(
                path,
                file_exists=file_exists,
                is_production=is_prod,
                policy=self.policy.hitl,
            )
            self._assert_not_forbidden(assessment, f"Proposed file write to {path!r}")
            _, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                tool_name="uniconn_write_file",
                action_type="file_write",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=str(agent_id) if agent_id else None,
                role=str(raw_role) if raw_role else None,
                enforce_deny=True,
            )
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            req = await self.approval_manager.create_request(
                target_host=entry.name,
                tool_name="uniconn_write_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                parameters={"path": path, "content": content, "atomic": atomic},
                diff=diff_str,
                agent_id=eff_agent_id,
                tenant_id=eff_tenant_id,
            )
            return {
                "assessment": assessment.to_dict(),
                "policy": policy_eval.to_dict(),
                "approval": req.to_public_dict(),
            }

        command = str(arguments.get("command") or "").strip()
        if not command:
            raise ValueError("Parameter 'command' is required when proposing 'uniconn_run'")
        sudo = bool(arguments.get("sudo", False))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        self._assert_not_forbidden(assessment, f"Proposed command {command!r}")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=str(agent_id) if agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        req = await self.approval_manager.create_request(
            target_host=entry.name,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters={"command": command, "sudo": sudo, "cwd": cwd_str or ""},
            agent_id=eff_agent_id,
            tenant_id=eff_tenant_id,
        )
        return {
            "assessment": assessment.to_dict(),
            "policy": policy_eval.to_dict(),
            "ast": parsed_ast.to_dict(),
            "approval": req.to_public_dict(),
        }

    async def _tool_evaluate_policy(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Сухая оценка AST-дерева и Policy-as-Code без исполнения действия."""
        tool_name = str(arguments.get("tool_name") or "uniconn_run").strip()
        raw_target = arguments.get("target")
        target_str = raw_target.strip() if isinstance(raw_target, str) and raw_target.strip() else None
        reg = self._active_registry()
        entry: MCPHostEntry | None = None
        if target_str:
            with contextlib.suppress(KeyError):
                entry = reg.get_entry(target_str)
        is_prod = (
            entry.is_production(self.policy.hitl.prod_groups)
            if entry is not None
            else bool(target_str and any(tok in target_str.lower() for tok in ("prod", "prd")))
        )
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        agent_val = str(raw_agent_id) if raw_agent_id else None
        role_val = str(raw_role) if raw_role else None

        if tool_name in ("uniconn_read_file", "uniconn_write_file"):
            path = str(arguments.get("path") or "").strip()
            if not path:
                raise ValueError(f"Parameter 'path' is required when evaluating {tool_name!r}")
            is_read = tool_name == "uniconn_read_file"
            assessment = (
                ActionRiskClassifier.classify_file_read(path, is_production=is_prod, policy=self.policy.hitl)
                if is_read
                else ActionRiskClassifier.classify_file_write(
                    path, file_exists=True, is_production=is_prod, policy=self.policy.hitl
                )
            )
            auth_ctx, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                target_host=target_str,
                tool_name=tool_name,
                action_type="file_read" if is_read else "file_write",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=agent_val,
                role=role_val,
                allow_role_override=True,
                enforce_deny=False,
            )
            return self._build_policy_eval_response(assessment, policy_eval, auth_ctx)

        if tool_name == "uniconn_run_flow" or tool_name.startswith("flow_"):
            flow_key = str(arguments.get("flow_name") or tool_name).strip()
            flow_obj = self.flow_registry.get_flow(flow_key)
            entries = [entry] if entry is not None else reg.list_entries()
            assessment, plan_preview = FlowRiskEvaluator.evaluate(
                flow_obj,
                entries=entries,
                policy=self.policy.hitl,
            )
            auth_ctx, policy_eval = await self._evaluate_policy_gate(
                entries=entries,
                target_host=target_str,
                tool_name=tool_name,
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                command=f"flow:{flow_obj.name}",
                flow_name=flow_obj.name,
                flow_tasks=tuple(flow_obj.tasks.keys()),
                agent_id=agent_val,
                role=role_val,
                allow_role_override=True,
                enforce_deny=False,
            )
            return self._build_policy_eval_response(
                assessment, policy_eval, auth_ctx, plan_preview=plan_preview
            )

        command = str(arguments.get("command") or "").strip()
        if not command:
            raise ValueError("Parameter 'command' is required when evaluating 'uniconn_run'")
        sudo = bool(arguments.get("sudo", False))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        auth_ctx, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            target_host=target_str,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=agent_val,
            role=role_val,
            allow_role_override=True,
            enforce_deny=False,
        )
        return self._build_policy_eval_response(
            assessment, policy_eval, auth_ctx, ast=parsed_ast.to_dict()
        )

    async def _tool_check_approval(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tenant_id = self._active_tenant_id()
        strict_tenant = self._is_verified_caller()
        approval_id = arguments.get("approval_id")
        if isinstance(approval_id, str) and approval_id.strip():
            req = await self.approval_manager.get_request(
                approval_id.strip(),
                tenant_id=tenant_id,
                strict_tenant=strict_tenant,
            )
            return {"approval": req.to_public_dict()}

        status_filter = arguments.get("status")
        reqs = await self.approval_manager.list_requests(
            status=str(status_filter) if status_filter else None,
            tenant_id=tenant_id,
            strict_tenant=strict_tenant,
        )
        return {
            "approvals": [r.to_public_dict() for r in reqs],
            "count": len(reqs),
        }

    async def _tool_wait_approval(self, arguments: dict[str, Any]) -> dict[str, Any]:
        approval_id = arguments.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("Parameter 'approval_id' is required")
        timeout = float(arguments.get("timeout", self.policy.hitl.wait_timeout_seconds))
        req = await self.approval_manager.wait_for_decision(
            approval_id.strip(),
            timeout=timeout,
            tenant_id=self._active_tenant_id(),
            strict_tenant=self._is_verified_caller(),
        )
        return {
            "approval_id": req.approval_id,
            "status": req.status.value,
            "approved": req.status == ApprovalStatus.APPROVED,
            "approval": req.to_public_dict(),
        }

    async def _tool_list_flows(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_cp = bool(arguments.get("include_checkpoints", True))
        flows_list = self.flow_registry.to_summary_list(policy=self.policy.hitl)
        out: dict[str, Any] = {
            "flows": flows_list,
            "count": len(flows_list),
        }
        if include_cp:
            records = await self.checkpoint_store.list_records(
                only_resumable=True,
                tenant_id=self._active_tenant_id(),
                strict_tenant=self._is_verified_caller(),
            )
            out["resumable_checkpoints"] = [r.to_dict() for r in records]
        return out

    async def _tool_inspect_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        flow_name = arguments.get("flow_name")
        if not isinstance(flow_name, str) or not flow_name.strip():
            raise ValueError("Parameter 'flow_name' is required")
        flow_obj = self.flow_registry.get_flow(flow_name.strip())
        raw_targets = arguments.get("targets")
        group = arguments.get("group")
        reg = self._active_registry()
        if raw_targets or group:
            entries = reg.resolve_targets(
                raw_targets,
                group=str(group) if group else None,
            )
        else:
            entries = reg.list_entries()

        tags_list = _parse_tags_list(arguments.get("tags"))
        raw_vars = arguments.get("vars")
        vars_dict = dict(raw_vars) if isinstance(raw_vars, dict) else {}
        assessment, plan_preview = FlowRiskEvaluator.evaluate(
            flow_obj,
            entries=entries,
            vars=vars_dict,
            tags=tags_list,
            policy=self.policy.hitl,
        )
        tool_def = FlowSchemaGenerator.generate_tool_definition(
            flow_obj,
            tool_name=self.flow_registry.get_tool_name(flow_obj.name),
        )
        out: dict[str, Any] = {
            "flow_name": flow_obj.name,
            "tool_name": tool_def.name,
            "description": tool_def.description,
            "mode": flow_obj.mode,
            "fail_fast": flow_obj.fail_fast,
            "risk_assessment": assessment.to_dict(),
            "plan_preview": plan_preview,
            "input_schema": tool_def.input_schema,
            "waves": [[t.name for t in layer] for layer in flow_obj.get_layers()],
        }
        if bool(arguments.get("live_plan", False)):
            fleet_plan, live_err = await self._build_live_flow_plan(
                flow_obj,
                entries,
                vars=vars_dict,
                tags=tags_list,
                mode=flow_obj.mode,
            )
            if fleet_plan is not None:
                out["plan_hash"] = fleet_plan.plan_hash
                out["fleet_plan"] = self._serialize_fleet_plan(fleet_plan)
            elif live_err is not None:
                out["live_plan_error"] = live_err
        return out

    async def _tool_run_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        flow_name = arguments.get("flow_name")
        if not isinstance(flow_name, str) or not flow_name.strip():
            raise ValueError("Parameter 'flow_name' is required")
        flow_obj = self.flow_registry.get_flow(flow_name.strip())
        return await self._execute_flow_by_object(
            flow_obj,
            tool_name="uniconn_run_flow",
            arguments=arguments,
        )

    async def _tool_resume_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_token = arguments.get("checkpoint_token")
        raw_run_id = arguments.get("run_id")
        tenant_id = self._active_tenant_id()
        strict_tenant = self._is_verified_caller()

        if isinstance(raw_token, str) and raw_token.strip():
            await self.checkpoint_store.ensure_ready()
            cp_record = self.checkpoint_store.decode_token(
                raw_token.strip(),
                tenant_id=tenant_id,
                strict_tenant=strict_tenant,
            )
        elif isinstance(raw_run_id, str) and raw_run_id.strip():
            cp_record = await self.checkpoint_store.get(
                raw_run_id.strip(),
                tenant_id=tenant_id,
                strict_tenant=strict_tenant,
            )
        else:
            raise ValueError("Either 'run_id' or 'checkpoint_token' is required")

        flow_obj = self.flow_registry.get_flow(cp_record.flow_name)
        merged_args: dict[str, Any] = {
            "resume_run_id": cp_record.run_id,
            "targets": cp_record.targets,
            "group": cp_record.group,
            "tags": cp_record.tags,
            "mode": cp_record.mode,
            "vars": dict(cp_record.vars),
        }
        override_vars = arguments.get("vars")
        if isinstance(override_vars, dict):
            merged_args["vars"].update(override_vars)
        for passthrough in ("approval_id", "wait_for_approval", "agent_id", "role"):
            if passthrough in arguments:
                merged_args[passthrough] = arguments[passthrough]
        return await self._execute_flow_by_object(
            flow_obj,
            tool_name=self.flow_registry.get_tool_name(flow_obj.name),
            arguments=merged_args,
            checkpoint_record=cp_record,
        )

    async def _execute_flow_by_object(
        self,
        flow_obj: Flow,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        checkpoint_record: FlowCheckpointRecord | None = None,
    ) -> dict[str, Any]:
        """Единый конвейер запуска ``Flow`` с поддержкой HITL 4.2, диагностики 4.1 и чекпоинтов."""
        resume_id_raw = arguments.get("resume_run_id") or arguments.get("run_id")
        resume_run_id = (
            str(resume_id_raw).strip()
            if isinstance(resume_id_raw, str) and str(resume_id_raw).strip()
            else None
        )
        raw_cp_token = arguments.get("checkpoint_token")
        cp_token_arg = (
            raw_cp_token.strip()
            if isinstance(raw_cp_token, str) and raw_cp_token.strip()
            else None
        )
        prior_completed: dict[str, list[str]] = {}
        prior_outputs: dict[str, dict[str, Any]] = {}
        base_vars: dict[str, Any] = {}
        default_targets: Any = None
        default_group: str | None = None
        default_tags: list[str] | None = None
        default_mode: str | None = None

        tenant_id = self._active_tenant_id()
        strict_tenant = self._is_verified_caller()
        cp: FlowCheckpointRecord | None = checkpoint_record
        if cp is None and cp_token_arg is not None:
            await self.checkpoint_store.ensure_ready()
            cp = self.checkpoint_store.decode_token(
                cp_token_arg,
                tenant_id=tenant_id,
                strict_tenant=strict_tenant,
            )
            resume_run_id = cp.run_id
        elif cp is None and resume_run_id is not None:
            cp = await self.checkpoint_store.get(
                resume_run_id,
                tenant_id=tenant_id,
                strict_tenant=strict_tenant,
            )

        if cp is not None:
            resume_run_id = cp.run_id
            if cp.flow_name != flow_obj.name:
                raise ValueError(
                    f"Checkpoint {resume_run_id!r} belongs to flow {cp.flow_name!r}, "
                    f"cannot resume flow {flow_obj.name!r}"
                )
            prior_completed = {h: list(t_list) for h, t_list in cp.completed_by_host.items()}
            prior_outputs = {h: dict(out_dict) for h, out_dict in cp.task_outputs_by_host.items()}
            base_vars = dict(cp.vars)
            default_targets = cp.targets
            default_group = cp.group
            default_tags = cp.tags or None
            default_mode = cp.mode

        entries, group_str, tags_list = self._resolve_flow_targets_and_tags(
            arguments,
            default_targets=default_targets,
            default_group=default_group,
            default_tags=default_tags,
        )
        validated_vars = FlowSchemaGenerator.extract_and_validate_vars(
            flow_obj,
            arguments,
            base_vars=base_vars,
            tags=tags_list,
        )

        raw_mode = arguments.get("mode") or default_mode or flow_obj.mode
        eff_mode: Literal["barrier", "independent"] = (
            "independent" if str(raw_mode) == "independent" else "barrier"
        )
        req_dry_run = bool(arguments.get("dry_run", False))
        eff_dry_run = self.policy.dry_run or req_dry_run

        assessment, plan_preview = FlowRiskEvaluator.evaluate(
            flow_obj,
            entries=entries,
            vars=validated_vars,
            tags=tags_list,
            mode=eff_mode,
            dry_run=eff_dry_run,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Flow {flow_obj.name!r}")
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name=tool_name,
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=f"flow:{flow_obj.name}",
            flow_name=flow_obj.name,
            flow_tasks=tuple(flow_obj.tasks.keys()),
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = (
            not eff_dry_run and policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        )
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled and assessment.requires_approval
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        target_names = [e.name for e in entries]
        host_label = ",".join(target_names)
        hmac_params: dict[str, Any] = {
            "flow_name": flow_obj.name,
            "targets": target_names,
            "group": group_str or "",
            "vars": validated_vars,
            "tags": list(tags_list or ()),
            "mode": eff_mode,
        }
        raw_plan_hash = arguments.get("plan_hash")
        if isinstance(raw_plan_hash, str) and raw_plan_hash.strip():
            hmac_params["plan_hash"] = raw_plan_hash.strip()
        canonical_flow_tool = self.flow_registry.get_tool_name(flow_obj.name)
        allowed_tools = (tool_name, canonical_flow_tool, "uniconn_run_flow")

        gate_diff = None if (approval_id is not None and "plan_hash" in hmac_params) else plan_preview
        consumed_req, pending_payload = await self._resolve_hitl_gate(
            target_host=host_label,
            tool_name=tool_name,
            allowed_tool_names=allowed_tools,
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=f"flow:{flow_obj.name}",
            parameters=hmac_params,
            diff=gate_diff,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            pending_extra={
                "flow_name": flow_obj.name,
                "targets": target_names,
                "plan_preview": plan_preview,
            },
        )
        if pending_payload is not None:
            return pending_payload

        active_flow = coerce_to_flow(flow_obj, mode=eff_mode)
        run_id = resume_run_id or f"run_{uuid.uuid4().hex[:12]}"
        expected_plan: FleetChangePlan | None = None
        if not eff_dry_run and "plan_hash" in hmac_params:
            expected_plan = self._get_cached_fleet_plan(str(hmac_params["plan_hash"]))

        reg = self._active_registry()
        if len(entries) == 1:
            async with reg.create_connection(
                entries[0],
                dry_run=eff_dry_run,
                auto_diagnostics=True,
            ) as conn:
                report = await active_flow.run(
                    conn,
                    vars=validated_vars,
                    tags=tags_list,
                    dry_run=eff_dry_run,
                    completed_tasks_by_host=prior_completed,
                    checkpoint_outputs_by_host=prior_outputs,
                    run_id=run_id,
                    resumed_from=resume_run_id,
                    expected_plan=expected_plan,
                )
        else:
            pool = reg.create_pool(
                entries,
                dry_run=eff_dry_run,
                auto_diagnostics=True,
            )
            async with pool:
                report = await active_flow.run(
                    pool,
                    vars=validated_vars,
                    tags=tags_list,
                    dry_run=eff_dry_run,
                    completed_tasks_by_host=prior_completed,
                    checkpoint_outputs_by_host=prior_outputs,
                    run_id=run_id,
                    resumed_from=resume_run_id,
                    expected_plan=expected_plan,
                )

        cp_record = await self.checkpoint_store.record_from_report(
            report,
            targets=target_names,
            group=group_str,
            vars=validated_vars,
            tags=tags_list,
            mode=eff_mode,
            prior_completed=prior_completed,
            prior_outputs=prior_outputs,
            run_id=run_id,
            tenant_id=tenant_id,
        )

        report_dict = report.to_dict()
        payload: dict[str, Any] = {
            "status": "COMPLETED" if report.ok else "FAILED",
            "ok": report.ok,
            "flow_name": flow_obj.name,
            "tool_name": canonical_flow_tool,
            "mode": report.mode,
            "run_id": cp_record.run_id,
            "can_resume": not report.ok,
            "resumed_from": resume_run_id,
            "duration_ms": round(report.duration * 1000, 3),
            "dry_run": eff_dry_run,
            "risk_tier": assessment.risk_tier.value,
            "targets": target_names,
            "summary": {
                "total_tasks": report.total_tasks,
                "succeeded_count": report.succeeded_count,
                "failed_count": report.failed_count,
                "skipped_count": report.skipped_count,
                "changed_count": report.changed_count,
                "failed_hosts": report.failed_hosts,
            },
            "failed_tasks": cp_record.failed_tasks,
            "completed_by_host": cp_record.completed_by_host,
            "results": report_dict["results"],
        }
        if not report.ok:
            cp_token = self.checkpoint_store.try_encode_token(cp_record)
            if cp_token is not None:
                payload["checkpoint_token"] = cp_token
        if consumed_req is not None:
            payload["approval"] = self._serialize_approval(consumed_req)
        return payload


__all__ = ["MCPGovernanceToolsMixin"]
