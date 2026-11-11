# src/uniconn/mcp/flows.py
"""Динамический экспорт сценариев оркестрации Flow как инструментов MCP (Flow-as-Tool)."""

from __future__ import annotations

import dataclasses
import enum
import importlib
import importlib.util
import inspect
import json
import os
import re
import sys
import types
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin, get_type_hints

from .._logging import SecretMaskingFilter
from ..exceptions import ConfigurationError
from ..orchestration.flow import Flow, SyncFlow
from ..orchestration.models import FlowReport
from ..orchestration.scheduler import compute_active_tasks_by_tags
from ..orchestration.task import _CONN_PARAM_NAMES, _CTX_PARAM_NAMES, Task
from .models import (
    ActionRiskTier,
    HITLPolicy,
    MCPHostEntry,
    MCPToolDefinition,
    RiskAssessment,
)

_RESERVED_MCP_FLOW_ARGS: frozenset[str] = frozenset(
    {
        "flow_name",
        "flow",
        "targets",
        "target",
        "group",
        "tags",
        "mode",
        "dry_run",
        "vars",
        "batch_size",
        "max_fail_ratio",
        "approval_id",
        "wait_for_approval",
        "resume_run_id",
        "run_id",
        "agent_id",
    }
)

_HIGH_RISK_TAGS: frozenset[str] = frozenset(
    {
        "destructive",
        "danger",
        "dangerous",
        "drop",
        "purge",
        "format",
        "wipe",
        "reboot",
        "shutdown",
        "delete",
    }
)
_MEDIUM_RISK_TAGS: frozenset[str] = frozenset(
    {
        "mutating",
        "write",
        "deploy",
        "release",
        "restart",
        "reload",
        "upgrade",
        "update",
        "rollback",
        "migrate",
        "migration",
        "provision",
        "configure",
        "install",
    }
)
_SAFE_TAGS: frozenset[str] = frozenset(
    {
        "safe",
        "readonly",
        "read_only",
        "read-only",
        "check",
        "preflight",
        "verify",
        "audit",
        "inspect",
        "diagnostics",
        "status",
        "ping",
        "facts",
    }
)

_PARAM_DOC_RE = re.compile(
    r"^\s*(?::param\s+(?P<sphinx_name>[a-zA-Z_]\w*)\s*:|(?P<google_name>[a-zA-Z_]\w*)\s*(?:\([^)]*\))?\s*:)\s*(?P<desc>.+)$"
)


def normalize_flow_tool_name(flow_name: str) -> str:
    """Нормализовать имя ``Flow`` в безопасное имя MCP-инструмента ``flow_<name>``."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", flow_name.strip()).strip("_").lower()
    if not cleaned:
        cleaned = "unnamed"
    if cleaned.startswith("flow_"):
        return cleaned
    return f"flow_{cleaned}"


def _parse_docstring_param_descriptions(docstring: str | None) -> dict[str, str]:
    """Извлечь описания параметров из docstring функции (форматы Google и Sphinx)."""
    if not docstring:
        return {}
    descriptions: dict[str, str] = {}
    for raw_line in inspect.cleandoc(docstring).splitlines():
        match = _PARAM_DOC_RE.match(raw_line)
        if not match:
            continue
        param_name = match.group("sphinx_name") or match.group("google_name")
        desc = match.group("desc").strip()
        if param_name and desc and param_name not in descriptions:
            descriptions[param_name] = desc
    return descriptions


def _extract_first_paragraph(docstring: str | None) -> str | None:
    """Вернуть первую осмысленную строку/абзац из docstring."""
    if not docstring:
        return None
    cleaned = inspect.cleandoc(docstring).strip()
    if not cleaned:
        return None
    first_para = cleaned.split("\n\n", 1)[0].strip()
    lines = [
        ln.strip()
        for ln in first_para.splitlines()
        if ln.strip() and not ln.strip().lower().startswith(("args:", "parameters:", ":param"))
    ]
    return " ".join(lines) if lines else None


def _mask_nested_value(val: Any) -> Any:
    """Рекурсивно замаскировать секреты в строках, словарях и списках."""
    if isinstance(val, str):
        return SecretMaskingFilter._mask_string(val)
    if isinstance(val, Mapping):
        return {str(k): _mask_nested_value(v) for k, v in val.items()}
    if isinstance(val, list | tuple):
        return [_mask_nested_value(item) for item in val]
    return val


def _to_checkpoint_json_safe(val: Any) -> Any:
    """Преобразовать возвращаемое значение задачи в JSON-безопасное представление с маскированием секретов."""
    if val is None or isinstance(val, bool | int | float):
        return val
    if isinstance(val, str):
        return SecretMaskingFilter._mask_string(val)
    if isinstance(val, Mapping):
        return {str(k): _to_checkpoint_json_safe(v) for k, v in val.items()}
    if isinstance(val, list | tuple | set | frozenset):
        return [_to_checkpoint_json_safe(item) for item in val]
    if hasattr(val, "to_dict"):
        to_dict_fn = getattr(val, "to_dict", None)
        if callable(to_dict_fn):
            try:
                return _to_checkpoint_json_safe(to_dict_fn())
            except Exception:
                return None
    if hasattr(val, "model_dump"):
        dump_fn = getattr(val, "model_dump", None)
        if callable(dump_fn):
            try:
                return _to_checkpoint_json_safe(dump_fn())
            except Exception:
                return None
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        try:
            return _to_checkpoint_json_safe(dataclasses.asdict(val))
        except Exception:
            return None
    return SecretMaskingFilter._mask_string(str(val))


def _unwrap_annotated(tp: Any) -> tuple[Any, dict[str, Any]]:
    """Распаковать ``typing.Annotated[T, ...]`` и извлечь метаданные описания/дефолта."""
    extra: dict[str, Any] = {}
    while get_origin(tp) is Annotated:
        args = get_args(tp)
        if not args:
            break
        tp = args[0]
        for meta in args[1:]:
            if isinstance(meta, str) and meta.strip() and "description" not in extra:
                extra["description"] = meta.strip()
            else:
                desc_attr = getattr(meta, "description", None)
                if isinstance(desc_attr, str) and desc_attr.strip() and "description" not in extra:
                    extra["description"] = desc_attr.strip()
                def_attr = getattr(meta, "default", dataclasses.MISSING)
                if (
                    def_attr is not dataclasses.MISSING
                    and isinstance(def_attr, str | int | float | bool | list | dict)
                    and "default" not in extra
                ):
                    extra["default"] = def_attr
    return tp, extra


def _python_type_to_json_schema(tp: Any) -> dict[str, Any]:
    """Преобразовать аннотацию типа Python в фрагмент JSON Schema."""
    if tp is inspect.Parameter.empty or tp is Any:
        return {"type": "string"}

    tp, annotated_extra = _unwrap_annotated(tp)

    if isinstance(tp, str):
        norm = tp.strip().lower()
        base_schema: dict[str, Any]
        if norm in ("str", "string", "path"):
            base_schema = {"type": "string"}
        elif norm in ("int", "integer"):
            base_schema = {"type": "integer"}
        elif norm in ("float", "number", "decimal"):
            base_schema = {"type": "number"}
        elif norm in ("bool", "boolean"):
            base_schema = {"type": "boolean"}
        elif norm.startswith(("list", "sequence", "tuple", "set")):
            base_schema = {"type": "array", "items": {"type": "string"}}
        elif norm.startswith(("dict", "mapping")):
            base_schema = {"type": "object"}
        else:
            base_schema = {"type": "string"}
        return {**base_schema, **annotated_extra}

    origin = get_origin(tp)
    args = get_args(tp)

    if origin in (Union, types.UnionType):
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return {**_python_type_to_json_schema(non_none[0]), **annotated_extra}
        if non_none:
            return {
                "oneOf": [_python_type_to_json_schema(a) for a in non_none],
                **annotated_extra,
            }
        return {"type": "string", **annotated_extra}

    if origin is Literal:
        literals = [a for a in args if isinstance(a, (str, int, float, bool))]
        if literals:
            first_type = type(literals[0])
            json_t = "string"
            if first_type is bool:
                json_t = "boolean"
            elif first_type is int:
                json_t = "integer"
            elif first_type is float:
                json_t = "number"
            return {"type": json_t, "enum": literals, **annotated_extra}

    if isinstance(tp, type) and issubclass(tp, enum.Enum):
        vals = [item.value for item in tp]
        return {"type": "string", "enum": vals, **annotated_extra}

    if tp is str or tp is Path:
        return {"type": "string", **annotated_extra}
    if tp is bool:
        return {"type": "boolean", **annotated_extra}
    if tp is int:
        return {"type": "integer", **annotated_extra}
    if tp is float:
        return {"type": "number", **annotated_extra}

    if origin in (list, tuple, set, frozenset, Sequence) or tp in (list, tuple, set, frozenset):
        item_schema = _python_type_to_json_schema(args[0]) if args else {"type": "string"}
        return {"type": "array", "items": item_schema, **annotated_extra}

    if origin in (dict, Mapping) or tp is dict:
        return {"type": "object", **annotated_extra}

    return {"type": "string", **annotated_extra}


def _is_optional_annotation(tp: Any) -> bool:
    """Проверить, допускает ли аннотация типа значение ``None`` (``Optional[T]`` / ``T | None``)."""
    tp, _ = _unwrap_annotated(tp)
    origin = get_origin(tp)
    if origin in (Union, types.UnionType):
        return type(None) in get_args(tp)
    if isinstance(tp, str):
        return "none" in tp.lower()
    return False


class FlowSchemaGenerator:
    """Генератор JSON Schema и описаний MCP-инструментов из объектов ``Flow``."""

    @classmethod
    def extract_user_parameters(
        cls,
        flow: Flow,
        *,
        tags: Sequence[str] | None = None,
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Извлечь ``(properties, required)`` пользовательских параметров сценария ``Flow``."""
        properties: dict[str, dict[str, Any]] = {}
        required_set: set[str] = set()
        optional_with_default: set[str] = set()
        active_task_names = compute_active_tasks_by_tags(flow.tasks, flow.dag, tags)

        model = flow.params_model
        if model is not None:
            if isinstance(model, Mapping):
                raw_props = model.get("properties")
                if isinstance(raw_props, Mapping):
                    for k, v in raw_props.items():
                        if isinstance(v, Mapping):
                            properties[str(k)] = dict(v)
                    raw_req = model.get("required")
                    if isinstance(raw_req, Sequence) and not isinstance(raw_req, str):
                        for r in raw_req:
                            required_set.add(str(r))
                else:
                    for k, v in model.items():
                        if isinstance(v, Mapping):
                            properties[str(k)] = dict(v)
            elif hasattr(model, "model_json_schema"):
                schema_fn = getattr(model, "model_json_schema", None)
                raw_schema: Any = schema_fn() if callable(schema_fn) else {}
                schema_dict: dict[str, Any] = (
                    raw_schema if isinstance(raw_schema, dict) else {}
                )
                raw_props_obj = schema_dict.get("properties")
                if isinstance(raw_props_obj, Mapping):
                    for k, v in raw_props_obj.items():
                        if isinstance(v, Mapping):
                            prop_copy = dict(v)
                            prop_copy.pop("title", None)
                            properties[str(k)] = prop_copy
                            if "default" in prop_copy:
                                optional_with_default.add(str(k))
                raw_req_obj = schema_dict.get("required", ())
                if isinstance(raw_req_obj, Sequence) and not isinstance(raw_req_obj, str):
                    for r in raw_req_obj:
                        required_set.add(str(r))
            elif dataclasses.is_dataclass(model):
                dc_hints: dict[str, Any] = {}
                try:
                    dc_target = model if isinstance(model, type) else type(model)
                    dc_hints = get_type_hints(dc_target, include_extras=True)
                except Exception:
                    dc_hints = {}
                for f in dataclasses.fields(model):
                    f_type = dc_hints.get(f.name, f.type)
                    prop = _python_type_to_json_schema(f_type)
                    has_default = (
                        f.default is not dataclasses.MISSING
                        or f.default_factory is not dataclasses.MISSING
                    )
                    if f.default is not dataclasses.MISSING and isinstance(
                        f.default, (str, int, float, bool, list, dict)
                    ):
                        prop["default"] = f.default
                    properties[f.name] = prop
                    if has_default or _is_optional_annotation(f_type):
                        optional_with_default.add(f.name)
                    else:
                        required_set.add(f.name)

        for t_obj in flow.tasks_in_order():
            fn = t_obj.fn
            try:
                sig = inspect.signature(fn)
            except (ValueError, TypeError):
                continue

            try:
                type_hints = get_type_hints(fn, include_extras=True)
            except Exception:
                type_hints = {}

            doc_descriptions = _parse_docstring_param_descriptions(inspect.getdoc(fn))
            params = list(sig.parameters.values())
            conn_seen = False
            ctx_seen = False

            for idx, param in enumerate(params):
                if param.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                ):
                    continue

                p_name = param.name
                ann = type_hints.get(p_name, param.annotation)
                ann_str = str(ann)

                is_ctx = p_name in _CTX_PARAM_NAMES or "FlowContext" in ann_str
                if is_ctx:
                    ctx_seen = True
                    continue

                is_conn = not conn_seen and (
                    p_name in _CONN_PARAM_NAMES
                    or "Connection" in ann_str
                    or (
                        idx == 0
                        and p_name != "host"
                        and param.annotation is inspect.Parameter.empty
                    )
                )
                if is_conn:
                    conn_seen = True
                    continue

                if p_name == "host" and param.default is inspect.Parameter.empty:
                    continue

                if (
                    not ctx_seen
                    and idx == 1
                    and param.default is inspect.Parameter.empty
                    and param.annotation is inspect.Parameter.empty
                ):
                    ctx_seen = True
                    continue

                if p_name in _RESERVED_MCP_FLOW_ARGS:
                    continue

                prop = dict(properties.get(p_name) or _python_type_to_json_schema(ann))
                desc = doc_descriptions.get(p_name)
                if desc and "description" not in prop:
                    prop["description"] = desc
                elif "description" not in prop:
                    prop["description"] = f"Parameter '{p_name}' for task '{t_obj.name}'."

                has_default = (
                    param.default is not inspect.Parameter.empty
                    or "default" in prop
                )
                is_task_active = (
                    active_task_names is None or t_obj.name in active_task_names
                )
                if has_default:
                    optional_with_default.add(p_name)
                    if (
                        param.default is not inspect.Parameter.empty
                        and param.default is not None
                        and isinstance(param.default, (str, int, float, bool, list, dict))
                        and "default" not in prop
                    ):
                        prop["default"] = param.default
                elif (
                    is_task_active
                    and not _is_optional_annotation(ann)
                    and p_name not in optional_with_default
                ):
                    required_set.add(p_name)

                properties[p_name] = prop

        required_list = sorted(required_set - optional_with_default)
        return properties, required_list

    @classmethod
    def generate_tool_schema(cls, flow: Flow) -> dict[str, Any]:
        """Сформировать полную JSON Schema (`inputSchema`) для MCP-инструмента сценария ``Flow``."""
        user_props, required_user = cls.extract_user_parameters(flow)
        properties: dict[str, Any] = {
            "targets": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ],
                "description": (
                    "Target host alias or list of host aliases from the MCP registry "
                    "(defaults to all registered hosts or 'group' if omitted)."
                ),
            },
            "group": {
                "type": "string",
                "description": "Optional inventory group name to filter target hosts.",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of task tags to selectively run a subgraph of the Flow.",
            },
            "mode": {
                "type": "string",
                "enum": ["barrier", "independent"],
                "description": f"Fleet execution strategy (default for this flow: {flow.mode!r}).",
                "default": flow.mode,
            },
            "dry_run": {
                "type": "boolean",
                "description": "Preview execution in dry-run mode without mutating target hosts.",
                "default": False,
            },
            "vars": {
                "type": "object",
                "description": "Optional dictionary of FlowContext.vars parameters.",
                "properties": dict(user_props),
            },
            "approval_id": {
                "type": "string",
                "description": (
                    "Single-use HITL approval token ID (e.g. 'appr_...') obtained after "
                    "human operator approval."
                ),
            },
            "wait_for_approval": {
                "type": "boolean",
                "description": (
                    "Wait synchronously for human operator approval if this Flow triggers HITL policy."
                ),
            },
            "resume_run_id": {
                "type": "string",
                "description": (
                    "Optional checkpoint run_id (e.g. 'run_...') from a previously failed Flow run "
                    "to skip already completed (host, task) nodes."
                ),
            },
        }
        for k, v in user_props.items():
            if k not in properties:
                properties[k] = v

        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": True,
        }
        if required_user:
            schema["required"] = required_user
        return schema

    @classmethod
    def build_description(cls, flow: Flow) -> str:
        """Собрать информативное описание сценария ``Flow`` для LLM-агента."""
        layers = flow.get_layers()
        wave_parts: list[str] = []
        for idx, layer in enumerate(layers, 1):
            names = ", ".join(t.name for t in layer)
            wave_parts.append(f"Wave {idx}: [{names}]")
        dag_summary = " -> ".join(wave_parts) if wave_parts else "empty"

        if flow.description:
            head = flow.description
        else:
            task_docs: list[str] = []
            for t_obj in flow.tasks_in_order():
                first_line = _extract_first_paragraph(inspect.getdoc(t_obj.fn))
                if first_line:
                    task_docs.append(f"{t_obj.name}: {first_line}")
            head = (
                f"Execute declarative DAG orchestration flow '{flow.name}'. "
                + ("Steps: " + "; ".join(task_docs) if task_docs else "")
            ).strip()

        all_tags = sorted({tag for t in flow.tasks.values() for tag in t.tags})
        tags_note = f" Tags: {all_tags}." if all_tags else ""
        return (
            f"{head} [DAG ({flow.mode}, {len(flow.tasks)} tasks, {len(layers)} waves): "
            f"{dag_summary}].{tags_note}"
        )

    @classmethod
    def generate_tool_definition(
        cls,
        flow: Flow,
        *,
        tool_name: str | None = None,
    ) -> MCPToolDefinition:
        """Создать ``MCPToolDefinition`` для экспорта сценария ``Flow`` в ``tools/list``."""
        eff_name = tool_name or normalize_flow_tool_name(flow.name)
        return MCPToolDefinition(
            name=eff_name,
            description=cls.build_description(flow),
            input_schema=cls.generate_tool_schema(flow),
        )

    @classmethod
    def extract_and_validate_vars(
        cls,
        flow: Flow,
        arguments: Mapping[str, Any],
        *,
        base_vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Извлечь, объединить и провалидировать входные переменные ``vars`` для запуска ``Flow``."""
        eff_tags = tags
        if eff_tags is None:
            raw_tags = arguments.get("tags")
            if isinstance(raw_tags, str) and raw_tags.strip():
                eff_tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
            elif isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str):
                eff_tags = [str(t).strip() for t in raw_tags if str(t).strip()]

        user_props, required_user = cls.extract_user_parameters(flow, tags=eff_tags)
        merged: dict[str, Any] = dict(base_vars) if base_vars else {}

        for prop_name, prop_schema in user_props.items():
            if "default" in prop_schema and prop_name not in merged:
                merged[prop_name] = prop_schema["default"]

        nested_vars = arguments.get("vars")
        if isinstance(nested_vars, Mapping):
            for k, v in nested_vars.items():
                merged[str(k)] = v

        for k, v in arguments.items():
            if k in _RESERVED_MCP_FLOW_ARGS:
                continue
            merged[str(k)] = v

        model = flow.params_model
        if model is not None:
            if hasattr(model, "model_validate"):
                validate_fn = getattr(model, "model_validate", None)
                if callable(validate_fn):
                    validated_obj: Any = validate_fn(merged)
                    dump_fn = getattr(validated_obj, "model_dump", None)
                    if callable(dump_fn):
                        dumped = dump_fn()
                        if isinstance(dumped, dict):
                            merged.update(dumped)
            elif dataclasses.is_dataclass(model) and isinstance(model, type):
                dc_field_names = {f.name for f in dataclasses.fields(model)}
                dc_kwargs = {k: v for k, v in merged.items() if k in dc_field_names}
                instance = model(**dc_kwargs)
                merged.update(dataclasses.asdict(instance))

        missing = [req for req in required_user if req not in merged or merged[req] is None]
        if missing:
            raise ValueError(
                f"Flow {flow.name!r} missing required parameter(s): {', '.join(missing)}"
            )

        return merged


class FlowRiskEvaluator:
    """Статический анализатор уровня риска ``ActionRiskTier`` и генератор плана для ``Flow``."""

    _EXPLICIT_TIER_MAP: dict[str, ActionRiskTier] = {
        "safe": ActionRiskTier.TIER_0_SAFE,
        "tier_0_safe": ActionRiskTier.TIER_0_SAFE,
        "readonly": ActionRiskTier.TIER_0_SAFE,
        "low": ActionRiskTier.TIER_1_MUTATING,
        "tier_1_low": ActionRiskTier.TIER_1_MUTATING,
        "tier_1_mutating": ActionRiskTier.TIER_1_MUTATING,
        "medium": ActionRiskTier.TIER_1_MUTATING,
        "tier_2_medium": ActionRiskTier.TIER_1_MUTATING,
        "mutating": ActionRiskTier.TIER_1_MUTATING,
        "high": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "tier_2_destructive": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "tier_3_high": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "destructive": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "forbidden": ActionRiskTier.TIER_3_FORBIDDEN,
        "tier_3_forbidden": ActionRiskTier.TIER_3_FORBIDDEN,
    }

    @classmethod
    def evaluate(
        cls,
        flow: Flow,
        *,
        entries: Sequence[MCPHostEntry] = (),
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str | None = None,
        dry_run: bool = False,
        policy: HITLPolicy | None = None,
    ) -> tuple[RiskAssessment, str]:
        """Оценить риск запуска ``Flow`` и сформировать ASCII DAG-план для ``ApprovalRequest.diff``."""
        eff_policy = policy or HITLPolicy()
        target_names = [e.name for e in entries]
        masked_vars: dict[str, Any] = (
            _mask_nested_value(dict(vars)) if vars else {}
        )

        plan_preview = flow.describe_plan(
            targets=target_names,
            vars=masked_vars,
            tags=tags,
            mode=mode,
            dry_run=dry_run,
        )

        prod_hosts = [
            e.name for e in entries if e.is_production(eff_policy.prod_groups)
        ]
        any_prod = bool(prod_hosts)

        if dry_run:
            return (
                RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_0_SAFE,
                    reasons=("Flow invoked with dry_run=True (simulation only)",),
                    is_production=any_prod,
                    requires_approval=False,
                ),
                plan_preview,
            )

        reasons: list[str] = []
        tier: ActionRiskTier | None = None

        if flow.risk_tier and flow.risk_tier in cls._EXPLICIT_TIER_MAP:
            tier = cls._EXPLICIT_TIER_MAP[flow.risk_tier]
            reasons.append(f"Flow explicitly declares risk_tier={flow.risk_tier!r}")

        active_names = compute_active_tasks_by_tags(flow.tasks, flow.dag, tags)
        active_tasks: list[Task[Any, Any]] = [
            t
            for name, t in flow.tasks.items()
            if active_names is None or name in active_names
        ]
        active_tags = {tag.lower() for t in active_tasks for tag in t.tags}

        high_matched = sorted(active_tags & _HIGH_RISK_TAGS)
        medium_matched = sorted(active_tags & _MEDIUM_RISK_TAGS)
        has_post_hooks = any(bool(t.post) for t in active_tasks)

        if high_matched:
            if tier not in (
                ActionRiskTier.TIER_3_FORBIDDEN,
                ActionRiskTier.TIER_2_DESTRUCTIVE,
            ):
                tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(
                f"Flow contains destructive task tags: {', '.join(high_matched)}"
            )
        elif medium_matched or has_post_hooks:
            if tier is None or tier == ActionRiskTier.TIER_0_SAFE:
                tier = ActionRiskTier.TIER_1_MUTATING
            if medium_matched:
                reasons.append(
                    f"Flow contains mutating task tags: {', '.join(medium_matched)}"
                )
            if has_post_hooks:
                reasons.append("Flow tasks trigger post-execution handlers")
        elif active_tags and active_tags <= _SAFE_TAGS:
            if tier is None:
                tier = ActionRiskTier.TIER_0_SAFE
                reasons.append(
                    "All active tasks are marked read-only/safe "
                    f"({', '.join(sorted(active_tags))})"
                )
        if tier is None:
            tier = ActionRiskTier.TIER_1_MUTATING
            reasons.append(
                f"Multi-step orchestration flow {flow.name!r} "
                f"({len(active_tasks)} active tasks)"
            )

        if any_prod and tier == ActionRiskTier.TIER_1_MUTATING:
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(
                f"Targets production host(s): {', '.join(prod_hosts)}"
            )
        elif any_prod and tier == ActionRiskTier.TIER_2_DESTRUCTIVE:
            reasons.append(
                f"Targets production host(s): {', '.join(prod_hosts)}"
            )

        requires_appr = eff_policy.requires_approval(
            tier, is_production=any_prod
        ) or (
            eff_policy.enabled
            and tier in (ActionRiskTier.TIER_1_MUTATING, ActionRiskTier.TIER_2_DESTRUCTIVE)
        )
        return (
            RiskAssessment(
                risk_tier=tier,
                reasons=tuple(reasons),
                is_production=any_prod,
                requires_approval=requires_appr,
            ),
            plan_preview,
        )


@dataclass(slots=True)
class FlowCheckpointRecord:
    """Запись чекпоинта выполнения сценария ``Flow`` для возобновления по ``run_id``."""

    run_id: str
    flow_name: str
    targets: list[str]
    group: str | None = None
    vars: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    mode: str = "barrier"
    completed_by_host: dict[str, list[str]] = field(default_factory=dict)
    task_outputs_by_host: dict[str, dict[str, Any]] = field(default_factory=dict)
    failed_tasks: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = False
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать запись чекпоинта в сериализуемый словарь."""
        return {
            "run_id": self.run_id,
            "flow_name": self.flow_name,
            "targets": list(self.targets),
            "group": self.group,
            "vars": dict(self.vars),
            "tags": list(self.tags),
            "mode": self.mode,
            "completed_by_host": {
                h: list(tasks) for h, tasks in self.completed_by_host.items()
            },
            "task_outputs_by_host": {
                h: dict(outputs) for h, outputs in self.task_outputs_by_host.items()
            },
            "failed_tasks": list(self.failed_tasks),
            "ok": self.ok,
            "can_resume": not self.ok,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FlowCheckpointRecord:
        """Восстановить ``FlowCheckpointRecord`` из словаря."""
        raw_completed = data.get("completed_by_host") or {}
        completed_map: dict[str, list[str]] = {}
        if isinstance(raw_completed, Mapping):
            for h, t_list in raw_completed.items():
                if isinstance(t_list, Sequence) and not isinstance(t_list, str):
                    completed_map[str(h)] = [str(x) for x in t_list]
        raw_outputs = data.get("task_outputs_by_host") or {}
        outputs_map: dict[str, dict[str, Any]] = {}
        if isinstance(raw_outputs, Mapping):
            for h, out_dict in raw_outputs.items():
                if isinstance(out_dict, Mapping):
                    outputs_map[str(h)] = {str(k): v for k, v in out_dict.items()}
        raw_targets = data.get("targets") or ()
        targets_list = (
            [str(t) for t in raw_targets]
            if isinstance(raw_targets, Sequence) and not isinstance(raw_targets, str)
            else []
        )
        raw_tags = data.get("tags") or ()
        tags_list = (
            [str(t) for t in raw_tags]
            if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str)
            else []
        )
        raw_vars = data.get("vars")
        vars_dict = dict(raw_vars) if isinstance(raw_vars, Mapping) else {}
        raw_failed = data.get("failed_tasks") or ()
        failed_list = (
            [dict(item) for item in raw_failed if isinstance(item, Mapping)]
            if isinstance(raw_failed, Sequence)
            else []
        )
        return cls(
            run_id=str(data.get("run_id") or f"run_{uuid.uuid4().hex[:12]}"),
            flow_name=str(data.get("flow_name") or "uniconn_flow"),
            targets=targets_list,
            group=str(data["group"]) if data.get("group") else None,
            vars=vars_dict,
            tags=tags_list,
            mode=str(data.get("mode") or "barrier"),
            completed_by_host=completed_map,
            task_outputs_by_host=outputs_map,
            failed_tasks=failed_list,
            ok=bool(data.get("ok", False)),
            created_at=str(data.get("created_at") or datetime.now(UTC).isoformat()),
            updated_at=str(data.get("updated_at") or datetime.now(UTC).isoformat()),
        )


class FlowCheckpointStore:
    """Хранилище чекпоинтов выполнения ``Flow`` (в памяти и опционально на диске)."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = (
            Path(store_path).expanduser() if store_path is not None else None
        )
        self._records: dict[str, FlowCheckpointRecord] = {}
        if self.store_path is not None and self.store_path.is_file():
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        if self.store_path is None or not self.store_path.is_file():
            return
        try:
            raw = json.loads(self.store_path.read_text(encoding="utf-8"))
            items = raw.get("checkpoints", {}) if isinstance(raw, Mapping) else {}
            if isinstance(items, Mapping):
                for r_id, item in items.items():
                    if isinstance(item, Mapping):
                        self._records[str(r_id)] = FlowCheckpointRecord.from_dict(item)
        except Exception:
            return

    def _save_to_disk(self) -> None:
        if self.store_path is None:
            return
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(
                os.open(
                    str(self.store_path) + ".tmp",
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                ),
                "w",
                encoding="utf-8",
            ) as fh:
                payload = {
                    "checkpoints": {
                        k: v.to_dict() for k, v in self._records.items()
                    }
                }
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(str(self.store_path) + ".tmp", self.store_path)
        except Exception:
            return

    def record_from_report(
        self,
        report: FlowReport,
        *,
        targets: Sequence[str],
        group: str | None = None,
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str = "barrier",
        prior_completed: Mapping[str, Sequence[str]] | None = None,
        prior_outputs: Mapping[str, Mapping[str, Any]] | None = None,
        run_id: str | None = None,
    ) -> FlowCheckpointRecord:
        """Сохранить состояние выполнения ``FlowReport`` в чекпоинт и вернуть запись."""
        if self.store_path is not None:
            self._load_from_disk()

        eff_run_id = run_id or report.run_id or f"run_{uuid.uuid4().hex[:12]}"
        completed_map: dict[str, list[str]] = {}
        if prior_completed:
            for h, tasks in prior_completed.items():
                completed_map[str(h)] = list(dict.fromkeys(str(t) for t in tasks))

        outputs_map: dict[str, dict[str, Any]] = {}
        if prior_outputs:
            for h, out_dict in prior_outputs.items():
                if isinstance(out_dict, Mapping):
                    outputs_map[str(h)] = {
                        str(k): _to_checkpoint_json_safe(v)
                        for k, v in out_dict.items()
                    }

        failed_tasks: list[dict[str, Any]] = []
        for host, results in report.results.items():
            host_done = completed_map.setdefault(host, [])
            host_outputs = outputs_map.setdefault(host, {})
            for r in results:
                if r.status == "success" or r.skip_reason == "checkpoint_completed":
                    if r.task_name not in host_done:
                        host_done.append(r.task_name)
                    if r.return_value is not None:
                        host_outputs[r.task_name] = _to_checkpoint_json_safe(
                            r.return_value
                        )
                elif not r.ok:
                    fail_entry: dict[str, Any] = {
                        "host": host,
                        "task_name": r.task_name,
                        "error": SecretMaskingFilter._mask_string(
                            r.error or (str(r.exception) if r.exception else "failed")
                        ),
                        "attempts": r.attempts,
                    }
                    r_dict = r.to_dict()
                    if "diagnostic" in r_dict:
                        fail_entry["diagnostic"] = r_dict["diagnostic"]
                    failed_tasks.append(fail_entry)

        now_iso = datetime.now(UTC).isoformat()
        existing = self._records.get(eff_run_id)
        created_iso = existing.created_at if existing is not None else now_iso

        masked_vars: dict[str, Any] = (
            _mask_nested_value(dict(vars)) if vars else {}
        )

        record = FlowCheckpointRecord(
            run_id=eff_run_id,
            flow_name=report.flow_name,
            targets=[str(t) for t in targets],
            group=group,
            vars=masked_vars,
            tags=[str(t) for t in (tags or ())],
            mode=mode,
            completed_by_host=completed_map,
            task_outputs_by_host=outputs_map,
            failed_tasks=failed_tasks,
            ok=report.ok,
            created_at=created_iso,
            updated_at=now_iso,
        )
        self._records[eff_run_id] = record
        self._save_to_disk()
        return record

    def get(self, run_id: str) -> FlowCheckpointRecord:
        """Получить чекпоинт по ``run_id`` или выбросить ``KeyError``."""
        if self.store_path is not None:
            self._load_from_disk()
        key = run_id.strip()
        if key not in self._records:
            raise KeyError(f"Flow checkpoint run_id {key!r} not found")
        return self._records[key]

    def list_records(self, *, only_resumable: bool = False) -> list[FlowCheckpointRecord]:
        """Вернуть список сохранённых чекпоинтов."""
        if self.store_path is not None:
            self._load_from_disk()
        items = list(self._records.values())
        if only_resumable:
            items = [r for r in items if not r.ok]
        return items


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
    "FlowCheckpointRecord",
    "FlowCheckpointStore",
    "FlowRiskEvaluator",
    "FlowSchemaGenerator",
    "MCPFlowRegistry",
    "normalize_flow_tool_name",
]
