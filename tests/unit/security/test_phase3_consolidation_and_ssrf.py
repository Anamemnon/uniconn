# tests/unit/security/test_phase3_consolidation_and_ssrf.py
"""Unit-тесты Этапа 3: унификация AST + ActionRiskClassifier, защита от SSRF и ReDoS."""

from __future__ import annotations

import socket

import pytest

from uniconn import (
    ActionRiskClassifier,
    ActionRiskTier,
    CommandASTParser,
    ConfigurationError,
    DeclarativePolicyRule,
    OPAPolicyEngine,
    WebhookApprovalChannel,
    blocklist_hook,
)
from uniconn.security import validate_outbound_url, validate_safe_regex


class TestASTClassifierConsolidation:
    """Контрактные тесты единой классификации на базе CommandASTParser."""

    def test_wrapped_shell_safe_vs_destructive_without_duplicate_unwrapper(self) -> None:
        safe_wrapped = ActionRiskClassifier.classify_command("sudo bash -c 'ls -la /var/log'")
        assert safe_wrapped.risk_tier == ActionRiskTier.TIER_0_SAFE

        dest_wrapped = ActionRiskClassifier.classify_command(
            "env FOO=bar timeout 10 sudo bash -c 'systemctl stop nginx'"
        )
        assert dest_wrapped.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE

        m_flag_safe = ActionRiskClassifier.classify_command("systemctl -M my-container status nginx")
        assert m_flag_safe.risk_tier == ActionRiskTier.TIER_0_SAFE

    def test_redirects_and_tee_classification_via_ast(self) -> None:
        dev_null = ActionRiskClassifier.classify_command("ls -la /tmp > /dev/null 2>&1")
        assert dev_null.risk_tier == ActionRiskTier.TIER_0_SAFE

        tmp_write = ActionRiskClassifier.classify_command("echo ok > /tmp/result.txt")
        assert tmp_write.risk_tier == ActionRiskTier.TIER_1_MUTATING

        etc_write = ActionRiskClassifier.classify_command("echo evil >> /etc/hosts")
        assert etc_write.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE

        tee_etc = ActionRiskClassifier.classify_command("echo 'worker_processes 2;' | tee /etc/nginx/nginx.conf")
        assert tee_etc.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE

        tee_sudoers = ActionRiskClassifier.classify_command("echo 'ALL ALL=(ALL) ALL' | tee /etc/sudoers.d/pwn")
        assert tee_sudoers.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN

    def test_equivalence_between_ast_and_risk_classifier_on_obfuscation(self) -> None:
        for cmd in (
            "rm$IFS-rf$IFS/var/log",
            "echo cm0gLXJmIC8= | base64 -d | sh",
            "{rm,-rf,/tmp/x}",
        ):
            ast = CommandASTParser.parse(cmd)
            assessment = ActionRiskClassifier.classify_command(cmd, ast=ast)
            assert ast.is_obfuscated is True
            assert assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN


class TestSSRFUrlValidation:
    """Тесты единого SSRF-валидатора для Webhook, OPA и веб-панели."""

    @pytest.mark.parametrize(
        "bad_url",
        [
            "http://127.0.0.1:8080/hook",
            "http://localhost:8181/hook",
            "http://[::1]:8080/hook",
            "http://[::ffff:127.0.0.1]/hook",
            "http://10.0.0.12/hook",
            "http://192.168.1.50/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://0.0.0.0:8080/hook",
            "file:///etc/passwd",
            "ftp://example.com/file",
        ],
    )
    def test_webhook_blocks_unsafe_urls_by_default(self, bad_url: str) -> None:
        with pytest.raises(ConfigurationError):
            WebhookApprovalChannel(bad_url)

    def test_webhook_allows_public_and_opt_in_private_but_never_metadata(self) -> None:
        ch_public = WebhookApprovalChannel("https://hooks.example.com/uniconn")
        assert ch_public.url == "https://hooks.example.com/uniconn"

        ch_priv = WebhookApprovalChannel("http://127.0.0.1:9000/hook", allow_private_network=True)
        assert ch_priv.url == "http://127.0.0.1:9000/hook"

        with pytest.raises(ConfigurationError):
            WebhookApprovalChannel("http://169.254.169.254/latest/meta-data/", allow_private_network=True)

    def test_opa_url_policy_ssrf_guard(self) -> None:
        # OPA allows localhost sidecars by default, but never cloud metadata
        opa_local = OPAPolicyEngine("http://127.0.0.1:8181/v1/data/uniconn/authz")
        assert "127.0.0.1" in opa_local.opa_url

        with pytest.raises(ConfigurationError):
            OPAPolicyEngine("http://169.254.169.254/latest/meta-data/")

        with pytest.raises(ConfigurationError):
            OPAPolicyEngine("http://10.10.10.5:8181/v1/data", allow_private_network=False)

    def test_dns_rebinding_protection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_getaddrinfo(
            host: str, port: object, type: int = 0
        ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            del host, port, type
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        # Structural check passes before DNS resolution, DNS resolution catches rebinding
        assert validate_outbound_url("https://rebind.attacker.example/hook", resolve_dns=False)
        with pytest.raises(ConfigurationError, match="loopback/private"):
            validate_outbound_url("https://rebind.attacker.example/hook", resolve_dns=True)


class TestRegexSafetyAndReDoS:
    """Тесты защиты от синтаксически битых regex и ReDoS в политиках, хуках и песочнице."""

    @pytest.mark.parametrize(
        "bad_pattern",
        [
            "",
            "[unclosed",
            "(a+)+",
            "(a*)*",
            "([a-zA-Z]+)+$",
            "(.*a){2,}",
            "x" * 600,
        ],
    )
    def test_validate_safe_regex_rejects_invalid_and_redos(self, bad_pattern: str) -> None:
        with pytest.raises(ConfigurationError):
            validate_safe_regex(bad_pattern)

    def test_declarative_rule_and_blocklist_hook_enforce_regex_safety(self) -> None:
        with pytest.raises(ConfigurationError):
            DeclarativePolicyRule.from_dict(
                {"id": "bad", "decision": "DENY", "command_regex": "(a+)+"}
            )

        with pytest.raises(ConfigurationError):
            DeclarativePolicyRule.from_dict(
                {"id": "syntax", "decision": "DENY", "path_regex": "[unclosed"}
            )

        with pytest.raises(ConfigurationError):
            blocklist_hook(["([0-9]+)+"])
