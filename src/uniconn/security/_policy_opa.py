# src/uniconn/security/_policy_opa.py
"""Клиент оценки политик через внешний сервер Open Policy Agent (OPAPolicyEngine)."""

from __future__ import annotations

import asyncio
import inspect
import json
import time
import urllib.request
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from ..exceptions import ConfigurationError, PolicyEngineUnavailableError
from ._policy_rules import _PolicyTTLCache
from .models import AuthContext, PolicyDecision, PolicyEvaluationResult, PolicyViolation
from .url_validation import open_ssrf_safe_url, validate_outbound_url

if TYPE_CHECKING:
    from .engine import EmbeddedPolicyEngine

OPASenderCallable = Callable[[str, dict[str, Any], float], Awaitable[dict[str, Any]] | dict[str, Any]]


class OPAPolicyEngine:
    """Клиент оценки политик через внешний сервер Open Policy Agent (OPA REST API / Rego)."""

    def __init__(
        self,
        opa_url: str = "http://localhost:8181/v1/data/uniconn/authz",
        *,
        timeout_seconds: float = 3.0,
        timeout: float | None = None,
        fail_closed: bool = True,
        allow_safe_on_failure: bool = False,
        allow_private_network: bool = True,
        cache_ttl_seconds: float = 5.0,
        fallback_embedded: EmbeddedPolicyEngine | None = None,
        sender: OPASenderCallable | None = None,
    ) -> None:
        """Инициализировать OPA-движок с URL политики, режимом fail-closed и TTL-кэшем."""
        self.allow_private_network = bool(allow_private_network)
        self.opa_url = validate_outbound_url(
            opa_url,
            allow_private_network=self.allow_private_network,
            resolve_dns=False,
        )
        eff_timeout = timeout if timeout is not None else timeout_seconds
        self.timeout_seconds = max(0.05, float(eff_timeout))
        self.fail_closed = fail_closed
        self.allow_safe_on_failure = allow_safe_on_failure
        self._cache = _PolicyTTLCache(ttl_seconds=cache_ttl_seconds)
        if fallback_embedded is None:
            from .engine import EmbeddedPolicyEngine

            self._pre_guard = EmbeddedPolicyEngine(preset="default", cache_ttl_seconds=0.0)
        else:
            self._pre_guard = fallback_embedded
        self._sender = sender

    def _prepare_evaluation(self, context: AuthContext) -> tuple[PolicyEvaluationResult | None, str, dict[str, Any]]:
        """Выполнить пре-проверку AST и поиск в кэше перед обращением к OPA."""
        local_check = self._pre_guard.evaluate_sync(context)
        if local_check.decision == PolicyDecision.DENY:
            return local_check.model_copy(update={"engine_name": "opa+ast_guard"}), "", {}

        ckey = f"opa:{self.opa_url}:{context.cache_key()}"
        cached = self._cache.get(ckey)
        if cached is not None:
            return cached, ckey, {}

        return None, ckey, {"input": context.to_input_dict()}

    def _finalize_response(
        self,
        resp_data: Mapping[str, Any],
        context: AuthContext,
        ckey: str,
        t0: float,
    ) -> PolicyEvaluationResult:
        dur_ms = (time.perf_counter() - t0) * 1000.0
        result = self._parse_opa_response(resp_data, context, dur_ms)
        self._cache.put(ckey, result)
        return result

    async def evaluate(self, context: AuthContext) -> PolicyEvaluationResult:
        """Отправить канонический документ ``{"input": ...}`` в OPA и интерпретировать ответ Rego."""
        short_circuit, ckey, payload = self._prepare_evaluation(context)
        if short_circuit is not None:
            return short_circuit

        t0 = time.perf_counter()
        try:
            if self._sender is not None:
                raw_resp = self._sender(self.opa_url, payload, self.timeout_seconds)
                if inspect.isawaitable(raw_resp):
                    resp_data = await raw_resp
                else:
                    resp_data = cast(dict[str, Any], raw_resp)
            else:
                resp_data = await asyncio.to_thread(
                    self._default_http_post,
                    self.opa_url,
                    payload,
                    self.timeout_seconds,
                    allow_private_network=self.allow_private_network,
                )
        except ConfigurationError:
            raise
        except Exception as exc:
            return self._handle_opa_unavailable(context, exc, t0)

        return self._finalize_response(resp_data, context, ckey, t0)

    def evaluate_sync(self, context: AuthContext) -> PolicyEvaluationResult:
        """Синхронная обёртка оценки политики через OPA."""
        short_circuit, ckey, payload = self._prepare_evaluation(context)
        if short_circuit is not None:
            return short_circuit

        t0 = time.perf_counter()
        try:
            if self._sender is not None:
                raw_resp = self._sender(self.opa_url, payload, self.timeout_seconds)
                if inspect.isawaitable(raw_resp):
                    if asyncio.iscoroutine(raw_resp):
                        raw_resp.close()
                    raise RuntimeError("Cannot call async OPA sender from evaluate_sync")
                resp_data = cast(dict[str, Any], raw_resp)
            else:
                resp_data = self._default_http_post(
                    self.opa_url,
                    payload,
                    self.timeout_seconds,
                    allow_private_network=self.allow_private_network,
                )
        except ConfigurationError:
            raise
        except Exception as exc:
            return self._handle_opa_unavailable(context, exc, t0)

        return self._finalize_response(resp_data, context, ckey, t0)

    def _handle_opa_unavailable(
        self,
        context: AuthContext,
        exc: Exception,
        t0: float,
    ) -> PolicyEvaluationResult:
        """Обработать отказ сервера OPA согласно политикам fail_closed и allow_safe_on_failure."""
        dur_ms = (time.perf_counter() - t0) * 1000.0
        is_safe_ro = (
            context.action.risk_tier == "SAFE"
            and not context.action.sudo
            and not context.action.ast.get("has_destructive_verbs")
            and not context.action.ast.get("is_obfuscated")
            and context.action.type == "command_execution"
        )
        if not self.fail_closed or (self.allow_safe_on_failure and is_safe_ro):
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                allowed=True,
                requires_approval=False,
                reasons=(f"OPA unreachable ({exc}); permitted as safe read-only fallback",),
                violations=(),
                risk_tier=context.action.risk_tier,
                ast=context.action.ast,
                evaluation_duration_ms=round(dur_ms, 4),
                engine_name="opa_fallback",
            )

        raise PolicyEngineUnavailableError(
            f"Open Policy Agent endpoint {self.opa_url!r} is unreachable and fail_closed=True: {exc}",
            engine_name="opa",
            endpoint=self.opa_url,
            command=context.action.raw_command or None,
            host=context.resource.host,
        ) from exc

    @staticmethod
    def _default_http_post(
        url: str,
        payload: dict[str, Any],
        timeout: float,
        *,
        allow_private_network: bool = True,
        max_response_bytes: int = 262_144,
    ) -> dict[str, Any]:
        safe_url = validate_outbound_url(
            url,
            allow_private_network=allow_private_network,
            resolve_dns=False,
        )
        raw_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            safe_url,
            data=raw_bytes,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with open_ssrf_safe_url(
            req,
            timeout=timeout,
            allow_private_network=allow_private_network,
            allow_redirects=False,
        ) as resp:
            raw_resp = resp.read(max_response_bytes + 1)
            if len(raw_resp) > max_response_bytes:
                raise ValueError(f"OPA response exceeded maximum allowed size of {max_response_bytes} bytes")
            resp_body = raw_resp.decode("utf-8", errors="replace")
            parsed = json.loads(resp_body) if resp_body.strip() else {}
            if not isinstance(parsed, dict):
                return {"result": parsed}
            return parsed

    @staticmethod
    def _parse_opa_mapping(
        reg_res: Mapping[str, Any],
    ) -> tuple[PolicyDecision, list[PolicyViolation], list[str], str | None]:
        violations: list[PolicyViolation] = []
        reasons: list[str] = []
        raw_hint = reg_res.get("remediation_hint")
        top_hint = str(raw_hint) if raw_hint else None

        raw_deny_items: Any = reg_res.get("deny") or reg_res.get("violations") or []
        deny_items: list[Any] = [raw_deny_items] if isinstance(raw_deny_items, str) else list(raw_deny_items)
        raw_reasons: Any = reg_res.get("reasons") or []
        reason_items: list[Any] = [raw_reasons] if isinstance(raw_reasons, str) else list(raw_reasons)
        for r_str in reason_items:
            if str(r_str) not in reasons:
                reasons.append(str(r_str))

        explicit_dec_str = str(reg_res.get("decision") or "").strip().upper()
        req_appr = bool(reg_res.get("require_approval", False)) or explicit_dec_str == "REQUIRE_APPROVAL"
        allow_flag = bool(reg_res.get("allow", False)) or explicit_dec_str == "ALLOW"

        for idx, item in enumerate(deny_items):
            if isinstance(item, Mapping):
                item_map = cast(Mapping[str, Any], item)
                item_hint = item_map.get("remediation_hint")
                v = PolicyViolation(
                    rule_id=str(item_map.get("rule_id") or f"opa.deny.{idx + 1}"),
                    rule_name=str(item_map.get("rule_name") or "OPA Rego Deny Rule"),
                    message=str(item_map.get("message") or item_map),
                    remediation_hint=str(item_hint) if item_hint else top_hint,
                )
            else:
                v = PolicyViolation(
                    rule_id=f"opa.deny.{idx + 1}",
                    rule_name="OPA Rego Deny Rule",
                    message=str(item),
                    remediation_hint=top_hint,
                )
            violations.append(v)
            if v.message not in reasons:
                reasons.append(v.message)

        if violations or explicit_dec_str == "DENY":
            decision = PolicyDecision.DENY
            if not violations:
                msg = reasons[0] if reasons else "Denied by OPA Rego policy"
                violations.append(
                    PolicyViolation(
                        rule_id="opa.deny",
                        rule_name="OPA Rego Policy",
                        message=msg,
                        remediation_hint=top_hint,
                    )
                )
                if msg not in reasons:
                    reasons.append(msg)
        elif req_appr:
            decision = PolicyDecision.REQUIRE_APPROVAL
            appr_msg = str(
                reg_res.get("approval_reason")
                or (reasons[0] if reasons else "Action requires human operator approval per OPA Rego policy")
            )
            if appr_msg not in reasons:
                reasons.append(appr_msg)
            violations.append(
                PolicyViolation(
                    rule_id="opa.require_approval",
                    rule_name="OPA HITL Requirement",
                    message=appr_msg,
                    severity="WARNING",
                    remediation_hint=top_hint,
                )
            )
        elif allow_flag:
            decision = PolicyDecision.ALLOW
            if not reasons:
                reasons.append("Allowed by Open Policy Agent Rego policy")
        else:
            decision = PolicyDecision.DENY
            msg = reasons[0] if reasons else "Denied by default OPA policy (allow=false)"
            if msg not in reasons:
                reasons.append(msg)
            violations.append(
                PolicyViolation(
                    rule_id="opa.default_deny",
                    rule_name="OPA Default Deny",
                    message=msg,
                    remediation_hint=top_hint,
                )
            )

        return decision, violations, reasons, top_hint

    @classmethod
    def _parse_opa_response(
        cls,
        resp_data: Mapping[str, Any],
        context: AuthContext,
        dur_ms: float,
    ) -> PolicyEvaluationResult:
        """Преобразовать ответ Rego (``result``) в ``PolicyEvaluationResult``."""
        reg_res = resp_data.get("result")
        violations: list[PolicyViolation] = []
        reasons: list[str] = []
        top_hint: str | None = None

        if isinstance(reg_res, bool):
            decision = PolicyDecision.ALLOW if reg_res else PolicyDecision.DENY
            if not reg_res:
                msg = "Denied by Open Policy Agent boolean rule"
                reasons.append(msg)
                violations.append(PolicyViolation(rule_id="opa.boolean", rule_name="OPA Rego Policy", message=msg))
            else:
                reasons.append("Allowed by Open Policy Agent")
        elif isinstance(reg_res, Mapping):
            decision, violations, reasons, top_hint = cls._parse_opa_mapping(reg_res)
        else:
            decision = PolicyDecision.DENY
            msg = "Denied: empty or unrecognized OPA response payload"
            reasons.append(msg)
            violations.append(PolicyViolation(rule_id="opa.invalid_response", rule_name="OPA Guard", message=msg))

        return PolicyEvaluationResult(
            decision=decision,
            allowed=(decision == PolicyDecision.ALLOW),
            requires_approval=(decision == PolicyDecision.REQUIRE_APPROVAL),
            reasons=tuple(reasons),
            violations=tuple(violations),
            risk_tier=context.action.risk_tier,
            ast=context.action.ast,
            evaluation_duration_ms=round(dur_ms, 4),
            engine_name="opa",
            explicit_remediation_hint=top_hint,
        )
