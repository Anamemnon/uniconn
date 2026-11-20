# src/uniconn/mcp/flows.py
"""Динамический экспорт сценариев оркестрации Flow как инструментов MCP (Flow-as-Tool)."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..exceptions import ConfigurationError
from ..orchestration.flow import Flow, SyncFlow
from ..orchestration.task import Task
from ._flow_checkpoints import (
    FlowCheckpointRecord,
    FlowCheckpointStore,
    FlowRiskEvaluator,
    _mask_nested_value,
    _to_checkpoint_json_safe,
)
from ._flow_schema import (
    _RESERVED_MCP_FLOW_ARGS,
    FlowSchemaGenerator,
    normalize_flow_tool_name,
)
from .models import HITLPolicy, MCPToolDefinition


class MCPFlowRegistry:
    """Реестр сценариев ``Flow``, экспортируемых в MCP-сервер."""

    def __init__(
        self,
        flows: Sequence[Flow | SyncFlow] = (),
    ) -> None:
        self._flows_by_name: dict[str, Flow] = {}
        self._flows_by_tool: dict[str, Flow] = {}
        self._tool_name_by_flow: dict[str, str] = {}
        for item in flows:
            self.register(item)

    @classmethod
    def from_sources(
        cls,
        *,
        specs: Sequence[str | Path] = (),
        flows: Sequence[Flow | SyncFlow] = (),
    ) -> MCPFlowRegistry:
        """Создать ``MCPFlowRegistry`` из списка Python-файлов/модулей и объектов ``Flow``."""
        reg = cls(flows=flows)
        for spec in specs:
            reg.load_from_spec(spec)
        return reg

    def register(
        self,
        flow: Flow | SyncFlow,
        *,
        tool_name: str | None = None,
    ) -> Flow:
        """Зарегистрировать сценарий ``Flow`` (или ``SyncFlow``) в реестре MCP."""
        flow_obj = flow._async_flow if isinstance(flow, SyncFlow) else flow
        if not isinstance(flow_obj, Flow):
            raise ConfigurationError(
                f"Expected Flow or SyncFlow instance, got {type(flow).__name__}"
            )
        flow_obj.validate()
        t_name = tool_name or normalize_flow_tool_name(flow_obj.name)
        self._flows_by_name[flow_obj.name] = flow_obj
        if flow_obj.expose_as_tool:
            self._flows_by_tool[t_name] = flow_obj
        self._tool_name_by_flow[flow_obj.name] = t_name
        return flow_obj

    def load_from_spec(self, spec: str | Path) -> list[Flow]:
        """Загрузить все объекты ``Flow`` / ``SyncFlow`` из файла, директории или модуля ``module[:attr]``."""
        spec_str = str(spec).strip()
        if not spec_str:
            return []

        path_candidate = Path(spec_str).expanduser()
        if path_candidate.is_dir():
            loaded: list[Flow] = []
            for py_file in sorted(path_candidate.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                loaded.extend(self._load_from_module(self._import_file(py_file), attr_name=None))
            return loaded

        if path_candidate.is_file():
            return self._load_from_module(self._import_file(path_candidate), attr_name=None)

        attr_name: str | None = None
        target_part = spec_str
        if ":" in spec_str:
            candidate_target, _, candidate_attr = spec_str.rpartition(":")
            if candidate_target and candidate_attr.isidentifier():
                target_part = candidate_target
                attr_name = candidate_attr

        file_candidate = Path(target_part).expanduser()

        if file_candidate.is_file() or target_part.endswith(".py"):
            mod = self._import_file(file_candidate)
        else:
            try:
                mod = importlib.import_module(target_part)
            except Exception as exc:
                raise ConfigurationError(
                    f"Cannot import flow module {target_part!r}: {exc}"
                ) from exc

        return self._load_from_module(mod, attr_name=attr_name)

    @staticmethod
    def _import_file(file_path: Path) -> types.ModuleType:
        resolved = file_path.expanduser().resolve()
        if not resolved.is_file():
            raise ConfigurationError(f"Flow Python file not found: {file_path}")
        mod_name = f"_uniconn_mcp_flow_{resolved.stem}_{abs(hash(str(resolved))) & 0xFFFF:04x}"
        spec = importlib.util.spec_from_file_location(mod_name, str(resolved))
        if spec is None or spec.loader is None:
            raise ConfigurationError(f"Cannot load module specification from {resolved}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(mod_name, None)
            raise
        return module

    def _load_from_module(
        self,
        module: types.ModuleType,
        *,
        attr_name: str | None,
    ) -> list[Flow]:
        discovered: list[Flow] = []
        if attr_name:
            if not hasattr(module, attr_name):
                raise ConfigurationError(
                    f"Module {module.__name__!r} has no attribute {attr_name!r}"
                )
            obj = getattr(module, attr_name)
            if callable(obj) and not isinstance(obj, (Flow, SyncFlow, Task)):
                obj = obj()
            flow_obj = obj._async_flow if isinstance(obj, SyncFlow) else obj
            if isinstance(flow_obj, Flow):
                self.register(flow_obj)
                discovered.append(flow_obj)
            else:
                raise ConfigurationError(
                    f"Attribute {attr_name!r} in {module.__name__!r} is not a Flow"
                )
            return discovered

        seen_ids: set[int] = set()
        for _, val in inspect.getmembers(module):
            flow_cand = val._async_flow if isinstance(val, SyncFlow) else val
            if isinstance(flow_cand, Flow) and id(flow_cand) not in seen_ids:
                seen_ids.add(id(flow_cand))
                if flow_cand.expose_as_tool:
                    self.register(flow_cand)
                    discovered.append(flow_cand)
        return discovered

    def list_flows(self) -> list[Flow]:
        """Вернуть список всех зарегистрированных сценариев ``Flow``."""
        return [f for f in self._flows_by_name.values() if f.expose_as_tool]

    def get_flow(self, name_or_tool: str) -> Flow:
        """Найти сценарий ``Flow`` по его имени или имени MCP-инструмента ``flow_<name>``."""
        key = name_or_tool.strip()
        cand: Flow | None = None
        if key in self._flows_by_name:
            cand = self._flows_by_name[key]
        elif key in self._flows_by_tool:
            cand = self._flows_by_tool[key]
        else:
            norm = normalize_flow_tool_name(key)
            if norm in self._flows_by_tool:
                cand = self._flows_by_tool[norm]

        if cand is not None and cand.expose_as_tool:
            return cand

        available = sorted(f.name for f in self.list_flows())
        raise KeyError(
            f"Flow {key!r} is not registered in MCPFlowRegistry (available: {available})"
        )

    def get_tool_name(self, flow_name: str) -> str:
        """Вернуть имя MCP-инструмента для сценария ``flow_name``."""
        if flow_name in self._tool_name_by_flow:
            return self._tool_name_by_flow[flow_name]
        return normalize_flow_tool_name(flow_name)

    def build_dynamic_tools(self) -> list[MCPToolDefinition]:
        """Сгенерировать список динамических ``MCPToolDefinition`` по одному на каждый ``Flow``."""
        out: list[MCPToolDefinition] = []
        for flow_obj in self.list_flows():
            t_name = self.get_tool_name(flow_obj.name)
            out.append(
                FlowSchemaGenerator.generate_tool_definition(
                    flow_obj,
                    tool_name=t_name,
                )
            )
        return out

    def to_summary_list(self, *, policy: HITLPolicy | None = None) -> list[dict[str, Any]]:
        """Сформировать сериализуемый список метаданных всех зарегистрированных ``Flow``."""
        summaries: list[dict[str, Any]] = []
        for flow_obj in self.list_flows():
            t_name = self.get_tool_name(flow_obj.name)
            user_props, required_user = FlowSchemaGenerator.extract_user_parameters(flow_obj)
            assessment, plan_str = FlowRiskEvaluator.evaluate(
                flow_obj,
                policy=policy,
            )
            layers = flow_obj.get_layers()
            summaries.append(
                {
                    "flow_name": flow_obj.name,
                    "tool_name": t_name,
                    "description": FlowSchemaGenerator.build_description(flow_obj),
                    "mode": flow_obj.mode,
                    "fail_fast": flow_obj.fail_fast,
                    "risk_tier": assessment.risk_tier.value,
                    "requires_approval": assessment.requires_approval,
                    "risk_reasons": list(assessment.reasons),
                    "tasks": [
                        {
                            "name": t.name,
                            "depends_on": sorted(flow_obj.dag.get(t.name, ())),
                            "tags": list(t.tags),
                            "always_run": t.always_run,
                            "ignore_errors": t.options.ignore_errors,
                            "retries": t.options.retries,
                        }
                        for t in flow_obj.tasks_in_order()
                    ],
                    "waves": [[t.name for t in layer] for layer in layers],
                    "parameters": user_props,
                    "required_parameters": required_user,
                    "plan_preview": plan_str,
                }
            )
        return summaries


__all__ = [
    "_RESERVED_MCP_FLOW_ARGS",
    "FlowCheckpointRecord",
    "FlowCheckpointStore",
    "FlowRiskEvaluator",
    "FlowSchemaGenerator",
    "MCPFlowRegistry",
    "_mask_nested_value",
    "_to_checkpoint_json_safe",
    "normalize_flow_tool_name",
]
