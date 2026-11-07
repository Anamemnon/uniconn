# src/uniconn/services/facts.py
"""Доменный сервис сбора системных фактов (HostFacts) о целевом хосте."""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .facts_models import (
    DEFAULT_DIFF_FIELDS,
    FACT_COLLECTION_SCRIPT,
    WINDOWS_FACT_POWERSHELL_SCRIPT,
    CustomCommandSpec,
    DiskInfo,
    ExternalToolSpec,
    FactsDiffReport,
    FactSpec,
    FileSourceSpec,
    HostFacts,
    NetworkInterface,
    diff_facts,
    parse_facts_output,
    parse_redfish_facts,
    parse_windows_facts_output,
)

if TYPE_CHECKING:
    from ..core.connection import Connection

_ARTIFACT_PATH_RE = re.compile(
    r"(/[A-Za-z0-9._/-]+\.(?:tar\.xz|tar\.gz|tgz|tar\.bz2|zip|log|json|txt))"
)


def _collect_windows_local_facts(default_host: str) -> HostFacts:
    """Собрать базовые системные факты для локального хоста на платформе Windows через единый Python-сборщик."""
    from ..core.python_worker import collect_local_python_facts

    return collect_local_python_facts(default_host, force_windows=True)


def _is_windows_remote_connection(conn: Connection) -> bool:
    """Проверить, является ли подключение удалённым Windows-хостом (winrm/wsman, включая Cassette)."""
    cfg = getattr(conn, "config", None)
    if getattr(cfg, "transport", "") in ("winrm", "wsman"):
        return True
    tr = getattr(conn, "transport", None)
    if getattr(tr, "name", "") in ("winrm", "wsman"):
        return True
    wrapped = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
    if getattr(wrapped, "name", "") in ("winrm", "wsman"):
        return True
    cassette = getattr(tr, "cassette", None)
    return getattr(cassette, "transport", "") in ("winrm", "wsman")


class ExternalToolRunner:
    """Адаптер делегирования сбора информации внешним диагностическим утилитам."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать адаптер внешних утилит для подключения."""
        self._conn = conn

    async def run_tool(
        self,
        tool: ExternalToolSpec,
        default_timeout: float | None = None,
        artifact_dir: str | Path | None = None,
    ) -> Any:
        """Выполнить внешнюю утилиту и вернуть структурированный результат или путь к артефакту."""
        binary = tool.resolved_binary()
        if binary:
            if _is_windows_remote_connection(self._conn):
                ps_bin = "'" + binary.replace("'", "''") + "'"
                probe = f"if (Get-Command {ps_bin} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
            else:
                probe = f"command -v {shlex.quote(binary)} >/dev/null 2>&1"
            chk = await self._conn.run(
                probe,
                raise_on_error=False,
            )
            if not chk.ok:
                return {
                    "ok": False,
                    "error": f"Tool {binary!r} not found on host",
                    "binary": binary,
                }

        eff_timeout = tool.timeout if tool.timeout is not None else default_timeout
        res = await self._conn.run(
            tool.command,
            timeout=eff_timeout,
            raise_on_error=False,
        )

        if tool.output_mode == "json":
            raw = res.stdout.strip()
            if raw:
                try:
                    return json.loads(raw)
                except ValueError:
                    pass
            return {
                "ok": res.ok,
                "exit_code": res.exit_code,
                "raw": raw,
                "stderr": res.stderr.strip(),
            }

        if tool.output_mode == "artifact":
            remote_artifact = ""
            if tool.artifact_glob:
                if re.search(r"[;|&`$><\n\r]", tool.artifact_glob):
                    return {
                        "ok": False,
                        "exit_code": 1,
                        "error": f"Unsafe characters in artifact_glob: {tool.artifact_glob!r}",
                    }
                if _is_windows_remote_connection(self._conn):
                    ps_glob = "'" + tool.artifact_glob.replace("'", "''") + "'"
                    glob_cmd = (
                        f"Get-ChildItem -Path {ps_glob} -ErrorAction SilentlyContinue | "
                        "Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName"
                    )
                else:
                    glob_cmd = f"ls -1td {tool.artifact_glob} 2>/dev/null | head -n 1"
                glob_res = await self._conn.run(
                    glob_cmd,
                    raise_on_error=False,
                )
                if glob_res.ok and glob_res.stdout.strip():
                    remote_artifact = glob_res.stdout.strip().splitlines()[0].strip()

            if not remote_artifact:
                combined = f"{res.stdout}\n{res.stderr}"
                match = _ARTIFACT_PATH_RE.search(combined)
                if match:
                    remote_artifact = match.group(1)

            if not remote_artifact:
                return {
                    "ok": False,
                    "exit_code": res.exit_code,
                    "error": "Artifact file not found after running tool",
                    "stdout": res.stdout.strip(),
                }

            artifact_name = Path(remote_artifact.replace("\\", "/")).name
            if not artifact_name or artifact_name in {".", ".."}:
                return {
                    "ok": False,
                    "exit_code": res.exit_code,
                    "error": f"Invalid artifact filename resolved from {remote_artifact!r}",
                }

            target_dir = Path(tool.local_dir or artifact_dir or "./artifacts")
            target_dir.mkdir(parents=True, exist_ok=True)
            local_dest = target_dir / artifact_name
            await self._conn.files.download(remote_artifact, str(local_dest))
            if tool.cleanup_remote:
                with contextlib.suppress(Exception):
                    await self._conn.files.remove_file(remote_artifact)
            return {
                "ok": True,
                "artifact_path": str(local_dest),
                "remote_path": remote_artifact,
            }

        if res.ok:
            return res.stdout.strip()
        return {
            "ok": False,
            "exit_code": res.exit_code,
            "error": res.stderr.strip() or res.stdout.strip(),
        }


class FactCollector:
    """Сервис инспекции хоста и кэширования ``HostFacts``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сборщик фактов для подключения."""
        self._conn = conn
        self.cached: HostFacts | None = None
        self._cached_at: float | None = None
        self._tool_runner = ExternalToolRunner(conn)

    def _is_run_mocked(self) -> bool:
        """Проверить, переопределен ли метод run у подключения или транспорта (для тестов/моков)."""
        conn_run = getattr(self._conn, "run", None)
        conn_type_run = getattr(type(self._conn), "run", None)
        if getattr(conn_run, "__func__", None) is not conn_type_run:
            return True
        tr = getattr(self._conn, "transport", None)
        if tr is not None:
            tr_run = getattr(tr, "run", None)
            tr_type_run = getattr(type(tr), "run", None)
            if getattr(tr_run, "__func__", None) is not tr_type_run:
                return True
        return False

    def _is_redfish_connection(self) -> bool:
        """Проверить, является ли целевое соединение Redfish BMC (включая Cassette/Replay)."""
        if self._conn.config.transport == "redfish":
            return True
        tr = self._conn.transport
        if getattr(tr, "name", "") == "redfish":
            return True
        wrapped = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
        if getattr(wrapped, "name", "") == "redfish":
            return True
        cassette = getattr(tr, "cassette", None)
        return getattr(cassette, "transport", "") == "redfish"

    def _is_windows_connection(self) -> bool:
        """Проверить, является ли целевое соединение WinRM/WSMan (включая Cassette/Replay)."""
        return _is_windows_remote_connection(self._conn)

    async def gather(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        artifact_dir: str | Path | None = None,
        ttl: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты (базовые + декларативные источники ``FactSpec``)."""
        resolved_spec = FactSpec.coerce(spec)
        if (
            not refresh
            and resolved_spec is None
            and self.cached is not None
            and (
                ttl is None
                or (
                    self._cached_at is not None
                    and (time.monotonic() - self._cached_at) <= ttl
                )
            )
        ):
            return self.cached

        default_host = self._conn.config.host or "localhost"
        if self._conn.dry_run:
            os_fam = "Windows" if self._is_windows_connection() else "Unknown"
            facts = HostFacts(os_family=os_fam, hostname=default_host)
            self.cached = facts
            self._cached_at = time.monotonic()
            return facts

        include_builtin = (
            True if resolved_spec is None else resolved_spec.include_builtin
        )
        if include_builtin:
            if self._is_redfish_connection():
                res = await self._conn.run(
                    "inventory",
                    timeout=timeout,
                    raise_on_error=False,
                )
                facts = parse_redfish_facts(res.stdout, default_host=default_host)
            elif self._is_windows_connection():
                win_res = await self._conn.run(
                    WINDOWS_FACT_POWERSHELL_SCRIPT,
                    timeout=timeout,
                    raise_on_error=False,
                )
                facts = parse_windows_facts_output(
                    win_res.stdout, default_host=default_host
                )
            else:
                worker = getattr(self._conn, "_python_worker", None)
                worker_facts: HostFacts | None = None
                if worker is not None and worker.can_auto_accelerate():
                    with contextlib.suppress(Exception):
                        worker_facts = await worker.gather_facts(
                            default_host=default_host,
                            timeout=timeout,
                        )
                if worker_facts is not None:
                    facts = worker_facts
                elif (
                    sys.platform == "win32"
                    and self._conn.transport_name == "local"
                    and not self._is_run_mocked()
                ):
                    facts = _collect_windows_local_facts(default_host)
                else:
                    res = await self._conn.run(
                        FACT_COLLECTION_SCRIPT,
                        timeout=timeout,
                        raise_on_error=False,
                    )
                    facts = parse_facts_output(res.stdout, default_host=default_host)
                    if facts.os_family == "Unknown":
                        win_res = await self._conn.run(
                            WINDOWS_FACT_POWERSHELL_SCRIPT,
                            timeout=timeout,
                            raise_on_error=False,
                        )
                        if win_res.ok and win_res.stdout.strip():
                            win_facts = parse_windows_facts_output(
                                win_res.stdout, default_host=default_host
                            )
                            if win_facts.os_family == "Windows":
                                facts = win_facts
        else:
            facts = HostFacts(hostname=default_host)

        if resolved_spec is not None:
            await self._collect_spec_sources(
                facts,
                resolved_spec,
                default_timeout=timeout,
                artifact_dir=artifact_dir,
            )

        if include_builtin:
            self.cached = facts
            self._cached_at = time.monotonic()
        return facts

    @staticmethod
    def _parse_custom_value(raw: str, parse_json: bool) -> Any:
        """Безопасно преобразовать JSON-строку или вернуть сырое текстовое значение."""
        if parse_json and raw:
            with contextlib.suppress(ValueError):
                return json.loads(raw)
        return raw

    async def _read_file_source(
        self,
        file_spec: FileSourceSpec,
        default_timeout: float | None = None,
    ) -> str:
        """Прочитать содержимое файла с ограничением по байтам и безопасным fallback."""
        max_bytes = int(file_spec.max_bytes)
        try:
            content = await self._conn.files.read_file(file_spec.path, encoding="utf-8")
            if isinstance(content, str):
                return content[:max_bytes].strip()
            if isinstance(content, bytes):
                return content[:max_bytes].decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        # Fallback через shell-команду head -c (для совместимости с моками или хостами без SFTP)
        try:
            q_path = shlex.quote(file_spec.path)
            cmd = f"head -c {max_bytes} {q_path} 2>/dev/null || true"
            res = await self._conn.run(cmd, timeout=default_timeout, raise_on_error=False)
            return res.stdout.strip()
        except Exception:
            return ""

    async def _collect_spec_sources(
        self,
        facts: HostFacts,
        spec: FactSpec,
        default_timeout: float | None = None,
        artifact_dir: str | Path | None = None,
    ) -> None:
        """Собрать пользовательские команды, файлы и внешние утилиты по ``FactSpec``."""
        for cmd_spec in spec.commands:
            eff_timeout = cmd_spec.timeout if cmd_spec.timeout is not None else default_timeout
            res = await self._conn.run(
                cmd_spec.command,
                timeout=eff_timeout,
                raise_on_error=False,
            )
            facts.custom[cmd_spec.name] = self._parse_custom_value(res.stdout.strip(), cmd_spec.parse_json)

        for file_spec in spec.files:
            raw_file = await self._read_file_source(file_spec, default_timeout=default_timeout)
            facts.custom[file_spec.name] = self._parse_custom_value(raw_file, file_spec.parse_json)

        for tool_spec in spec.tools:
            facts.tools[tool_spec.name] = await self._tool_runner.run_tool(
                tool_spec,
                default_timeout=default_timeout,
                artifact_dir=artifact_dir,
            )


__all__ = [
    "DEFAULT_DIFF_FIELDS",
    "FACT_COLLECTION_SCRIPT",
    "WINDOWS_FACT_POWERSHELL_SCRIPT",
    "CustomCommandSpec",
    "DiskInfo",
    "ExternalToolRunner",
    "ExternalToolSpec",
    "FactCollector",
    "FactSpec",
    "FactsDiffReport",
    "FileSourceSpec",
    "HostFacts",
    "NetworkInterface",
    "diff_facts",
    "parse_facts_output",
    "parse_redfish_facts",
    "parse_windows_facts_output",
]

