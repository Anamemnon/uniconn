# src/uniconn/transports/replay/_proxy_matching.py
"""Нормализация ключей, маскирование секретов и сопоставление эпизодов кассеты."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from ..._logging import SecretMaskingFilter
from ...exceptions import CassetteMissError, UniconnError
from .models import (
    _ERROR_MAP,
    _SUDO_WRAPPER_RE,
    Cassette,
    FsOperationName,
    MatchField,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedPyRpcInteraction,
    RecordMode,
    normalize_temp_paths,
)

if TYPE_CHECKING:
    from ...config.models import ConnectionConfig


class _CassetteMatchingMixin:
    """Миксин санитизации и поиска совпадений эпизодов для ``CassetteTransportProxy``."""

    if TYPE_CHECKING:
        config: ConnectionConfig
        _cassette: Cassette
        _mode: RecordMode
        _cassette_exists: bool
        _match_on: set[MatchField]
        _normalize_temp: bool
        _allow_playback_repeats: bool
        _mask_secrets: bool
        _consumed_indices: set[int]

    def _can_replay(self) -> bool:
        if self._mode == RecordMode.ALL:
            return False
        if self._mode == RecordMode.ONCE:
            return self._cassette_exists
        return True

    def _can_record(self) -> bool:
        if self._mode == RecordMode.NONE:
            return False
        if self._mode == RecordMode.ONCE:
            return not self._cassette_exists
        return True

    def _known_secrets(self) -> list[str]:
        secrets: list[str] = []
        for val in (
            self.config.password,
            self.config.passphrase,
            self.config.options.get("sudo_password"),
        ):
            if isinstance(val, SecretStr):
                raw = val.get_secret_value()
                if raw:
                    secrets.append(raw)
            elif isinstance(val, str) and val:
                secrets.append(val)
        return secrets

    def _sanitize_text(self, text: str, *, normalize: bool = False) -> str:
        if not text:
            return text
        res = normalize_temp_paths(text) if (normalize and self._normalize_temp) else text
        if self._mask_secrets:
            for secret in self._known_secrets():
                res = res.replace(secret, "***REDACTED***")
            res = SecretMaskingFilter._mask_string(res)
        return res

    def _norm_key(self, text: str | None) -> str | None:
        if text is None:
            return None
        res = normalize_temp_paths(text) if self._normalize_temp else text
        if self._mask_secrets:
            for secret in self._known_secrets():
                res = res.replace(secret, "***REDACTED***")
            res = SecretMaskingFilter._mask_string(res)
        return res

    @staticmethod
    def _raise_recorded_error(
        error_class: str | None,
        error_message: str | None,
        *,
        command: str | None = None,
        host: str | None = None,
    ) -> None:
        if not error_class:
            return
        exc_cls = _ERROR_MAP.get(error_class, UniconnError)
        msg = error_message or error_class
        if issubclass(exc_cls, UniconnError):
            raise exc_cls(msg, command=command, host=host)
        raise exc_cls(msg)

    def _unwrap_sudo(self, cmd: str) -> str:
        stripped = cmd.strip()
        if not _SUDO_WRAPPER_RE.match(stripped):
            return stripped
        marker = "-- sh -c "
        idx = stripped.find(marker)
        if idx == -1:
            return stripped
        inner = stripped[idx + len(marker) :].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in ("'", '"'):
            return inner[1:-1]
        return inner

    def _match_exec(
        self,
        command: str,
        cwd: str | None,
        sudo: bool,
    ) -> RecordedExecInteraction | None:
        norm_cmd = self._norm_key(command) or ""
        norm_unwrapped = self._norm_key(self._unwrap_sudo(command)) or ""
        norm_cwd = self._norm_key(cwd)
        matched_repeat: RecordedExecInteraction | None = None

        for idx, item in enumerate(self._cassette.interactions):
            if not isinstance(item, RecordedExecInteraction):
                continue
            item_cmd = self._norm_key(item.command) or ""
            item_unwrapped = self._norm_key(self._unwrap_sudo(item.command)) or ""
            cmd_candidates = (norm_cmd, norm_unwrapped)
            if (
                "command" in self._match_on
                and item_cmd not in cmd_candidates
                and item_unwrapped not in cmd_candidates
            ):
                continue
            if "cwd" in self._match_on and self._norm_key(item.cwd) != norm_cwd:
                continue
            if "sudo" in self._match_on and item.sudo != sudo:
                continue

            if idx not in self._consumed_indices:
                self._consumed_indices.add(idx)
                return item
            matched_repeat = item

        if self._allow_playback_repeats and matched_repeat is not None:
            return matched_repeat
        return None

    def _match_fs(
        self,
        operation: FsOperationName,
        path: str,
    ) -> RecordedFsInteraction | None:
        norm_path = self._norm_key(path) or ""
        matched_repeat: RecordedFsInteraction | None = None

        for idx, item in enumerate(self._cassette.interactions):
            if not isinstance(item, RecordedFsInteraction):
                continue
            if item.operation != operation:
                continue
            if (self._norm_key(item.path) or "") != norm_path:
                continue
            if idx not in self._consumed_indices:
                self._consumed_indices.add(idx)
                return item
            matched_repeat = item

        if self._allow_playback_repeats and matched_repeat is not None:
            return matched_repeat
        return None

    def _raise_fs_miss(self, operation: FsOperationName, path: str) -> None:
        candidates = [
            f"{it.operation}:{it.path}"
            for it in self._cassette.interactions
            if isinstance(it, RecordedFsInteraction)
        ]
        raise CassetteMissError(
            f"No matching fs interaction in cassette for {operation}({path!r})",
            kind="fs",
            command=f"{operation} {path}",
            host=self.config.host,
            candidates=candidates,
        )

    def _match_py_rpc(
        self,
        op: str,
        func_name: str,
        source: str,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> RecordedPyRpcInteraction | None:
        norm_source = (self._norm_key(source) or "").strip()
        matched_repeat: RecordedPyRpcInteraction | None = None

        for idx, item in enumerate(self._cassette.interactions):
            if not isinstance(item, RecordedPyRpcInteraction):
                continue
            if item.op != op:
                continue
            if op == "call":
                if item.func_name != func_name:
                    continue
                if norm_source and item.source and (self._norm_key(item.source) or "").strip() != norm_source:
                    continue
                if item.args != args or item.kwargs != kwargs:
                    continue
            elif item.kwargs and kwargs and item.kwargs != kwargs:
                continue
            if idx not in self._consumed_indices:
                self._consumed_indices.add(idx)
                return item
            matched_repeat = item

        if self._allow_playback_repeats and matched_repeat is not None:
            return matched_repeat
        return None


__all__ = ["_CassetteMatchingMixin"]
