# src/uniconn/mcp/_flow_schema.py
"""Генерация JSON Schema и валидация параметров MCP-инструментов из объектов Flow."""

from __future__ import annotations

import dataclasses
import enum
import inspect
import re
import types
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin, get_type_hints

from ..orchestration.flow import Flow
from ..orchestration.scheduler import compute_active_tasks_by_tags
from ..orchestration.task import _CONN_PARAM_NAMES, _CTX_PARAM_NAMES
from .models import MCPToolDefinition

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
        "role",
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


__all__ = [
    "_RESERVED_MCP_FLOW_ARGS",
    "FlowSchemaGenerator",
    "normalize_flow_tool_name",
]
