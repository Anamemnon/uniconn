# tests/unit/security/test_security_fuzz_hypothesis.py
"""Property-based fuzzing критических парсеров безопасности и протоколов (Hypothesis)."""

from __future__ import annotations

import base64
import ipaddress

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from uniconn._logging import SecretMaskingFilter
from uniconn.config.uri import URIParser
from uniconn.core._shell_quoting import ps_encoded_command, ps_quote
from uniconn.exceptions import ConfigurationError, UniconnError
from uniconn.mcp.risk_classifier import ActionRiskClassifier, ActionRiskTier
from uniconn.security import CommandASTParser, PowerShellASTParser
from uniconn.security.url_validation import validate_outbound_url
from uniconn.shell.marker_protocol import PosixMarkerProtocol

pytestmark = pytest.mark.fuzz

_FUZZ_SETTINGS = settings(max_examples=80, deadline=None)


@_FUZZ_SETTINGS
@given(cmd=st.text(min_size=0, max_size=200))
def test_fuzz_command_ast_parser_never_crashes_posix(cmd: str) -> None:
    """CommandASTParser (auto/builtin) никогда не падает с необработанным исключением."""
    ast_auto = CommandASTParser.parse(cmd, dialect="posix", backend="auto")
    assert ast_auto.raw_command == cmd.strip()
    assert isinstance(ast_auto.executables, tuple)
    assert isinstance(ast_auto.syntax_errors, tuple)

    ast_bi = CommandASTParser.parse(cmd, dialect="posix", backend="builtin")
    assert ast_bi.raw_command == cmd.strip()


@_FUZZ_SETTINGS
@given(cmd=st.text(min_size=0, max_size=200))
def test_fuzz_powershell_ast_parser_never_crashes(cmd: str) -> None:
    """PowerShellASTParser никогда не падает на произвольных строках и управляющих символах."""
    ast_ps = PowerShellASTParser.parse(cmd)
    assert ast_ps.dialect == "powershell"
    assert ast_ps.raw_command == cmd.strip()
    assert isinstance(ast_ps.syntax_errors, tuple)


@_FUZZ_SETTINGS
@given(
    prefix=st.text(
        alphabet=st.characters(blacklist_characters="'\"`\\;\n\r|&()"),
        min_size=1,
        max_size=30,
    ),
    quote_char=st.sampled_from(["'", '"']),
)
def test_fuzz_unclosed_quotes_always_detected_and_fail_closed(
    prefix: str, quote_char: str
) -> None:
    """Незакрытые кавычки всегда фиксируются в syntax_errors и никогда не получают TIER_0_SAFE."""
    malformed = f"echo {quote_char}{prefix}"
    ast_obj = CommandASTParser.parse(malformed, dialect="posix")
    assert ast_obj.has_syntax_errors is True

    assessment = ActionRiskClassifier.classify_command(malformed)
    assert assessment.risk_tier.severity > ActionRiskTier.TIER_0_SAFE.severity


@_FUZZ_SETTINGS
@given(cmd=st.text(min_size=0, max_size=200))
def test_fuzz_risk_classifier_never_crashes(cmd: str) -> None:
    """ActionRiskClassifier.classify_command стабилен на любом произвольном входе."""
    assessment = ActionRiskClassifier.classify_command(cmd)
    assert isinstance(assessment.risk_tier, ActionRiskTier)
    assert isinstance(assessment.reasons, tuple)


@_FUZZ_SETTINGS
@given(
    oct2=st.integers(min_value=0, max_value=255),
    oct3=st.integers(min_value=0, max_value=255),
    oct4=st.integers(min_value=0, max_value=255),
    port=st.integers(min_value=1, max_value=65535),
)
def test_fuzz_validate_outbound_url_blocks_loopback_and_metadata(
    oct2: int, oct3: int, oct4: int, port: int
) -> None:
    """SSRF-валидатор никогда не пропускает loopback (127.0.0.0/8) и link-local metadata."""
    loopback_url = f"http://127.{oct2}.{oct3}.{oct4}:{port}/v1/data"
    with pytest.raises(ConfigurationError):
        validate_outbound_url(loopback_url, allow_private_network=False, resolve_dns=False)

    meta_url = f"http://169.254.{oct3}.{oct4}/latest/meta-data/"
    with pytest.raises(ConfigurationError):
        validate_outbound_url(
            meta_url, allow_private_network=True, allow_metadata=False, resolve_dns=False
        )


@_FUZZ_SETTINGS
@given(
    scheme=st.sampled_from(["file", "ftp", "gopher", "javascript", "data", "ssh", "ldap"]),
    host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-", min_size=1, max_size=20),
)
def test_fuzz_validate_outbound_url_blocks_non_http_schemes(scheme: str, host: str) -> None:
    """SSRF-валидатор отклоняет любые не-HTTP(S) схемы."""
    url = f"{scheme}://{host}/resource"
    with pytest.raises(ConfigurationError):
        validate_outbound_url(url, allow_private_network=True, resolve_dns=False)


@_FUZZ_SETTINGS
@given(
    ip_int=st.integers(min_value=0, max_value=(1 << 32) - 1),
)
def test_fuzz_validate_outbound_url_ipv4_private_classification(ip_int: int) -> None:
    """Любой приватный/зарезервированный IPv4 блокируется при allow_private_network=False."""
    ip_obj = ipaddress.IPv4Address(ip_int)
    is_restricted = (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or ip_obj == ipaddress.IPv4Address("100.100.100.200")
    )
    url = f"https://{ip_obj}/health"
    if is_restricted:
        with pytest.raises(ConfigurationError):
            validate_outbound_url(url, allow_private_network=False, resolve_dns=False)
    else:
        assert validate_outbound_url(url, allow_private_network=False, resolve_dns=False) == url


@_FUZZ_SETTINGS
@given(
    value=st.text(
        alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
        min_size=0,
        max_size=150,
    )
)
def test_fuzz_ps_quote_and_encoded_command_roundtrip(value: str) -> None:
    """ps_quote и ps_encoded_command корректно экранируют произвольный валидный Unicode без NUL."""
    quoted = ps_quote(value)
    assert quoted.startswith("'")
    assert quoted.endswith("'")
    inner = quoted[1:-1]
    assert inner.replace("''", "").count("'") == 0

    encoded_cmd = ps_encoded_command(value)
    assert encoded_cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
    b64_part = encoded_cmd.rsplit(" ", 1)[1]
    decoded = base64.b64decode(b64_part).decode("utf-16le")
    assert decoded == value


def test_ps_encoded_command_rejects_lone_surrogate() -> None:
    """ps_encoded_command отклоняет одиночные суррогаты UTF-16 чистым ValueError."""
    with pytest.raises(ValueError, match="surrogate"):
        ps_encoded_command("\ud800")


@_FUZZ_SETTINGS
@given(
    secret=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
        min_size=12,
        max_size=36,
    ),
    noise=st.text(alphabet="xyz .,;[]", min_size=0, max_size=40),
)
def test_fuzz_secret_masking_hides_credentials(secret: str, noise: str) -> None:
    """SecretMaskingFilter никогда не оставляет пароль в URI или Bearer-токен в открытом виде."""
    assume(secret not in noise)
    uri_line = f"{noise} ssh://admin:{secret}@10.0.0.5:22 {noise}"
    masked_uri = SecretMaskingFilter._mask_string(uri_line)
    assert secret not in masked_uri

    bearer_line = f"Authorization: Bearer {secret} {noise}"
    masked_bearer = SecretMaskingFilter._mask_string(bearer_line)
    assert secret not in masked_bearer


@_FUZZ_SETTINGS
@given(raw=st.text(min_size=0, max_size=150))
def test_fuzz_uri_parser_only_raises_expected_errors(raw: str) -> None:
    """URIParser.parse либо возвращает валидный ConnectionConfig, либо бросает ConfigurationError/ValueError."""
    try:
        cfg = URIParser.parse(raw)
        assert isinstance(cfg.transport, str)
    except (UniconnError, ConfigurationError, ValueError):
        pass


@_FUZZ_SETTINGS
@given(
    body=st.text(
        alphabet=st.characters(blacklist_characters="\r\x00"),
        min_size=0,
        max_size=120,
    ),
    exit_code=st.integers(min_value=0, max_value=255),
)
def test_fuzz_posix_marker_protocol_extracts_exact_exit_code(body: str, exit_code: int) -> None:
    """PosixMarkerProtocol корректно выделяет маркер и код возврата из произвольного вывода."""
    proto = PosixMarkerProtocol()
    wrapped = proto.wrap_command("echo test")
    assert proto.uuid in wrapped

    simulated_output = f"{wrapped}{body}\n__UNICONN_{proto.uuid}__{exit_code}\n"
    match = proto.search(simulated_output)
    assert match is not None
    assert int(match.group(1)) == exit_code

    cleaned = proto.clean_output(simulated_output[: match.start()], "echo test", wrapped)
    assert f"__UNICONN_{proto.uuid}__" not in cleaned
