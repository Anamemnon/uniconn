# src/uniconn/background/_diagnostic.py
"""Оркестратор диагностической сессии (DiagnosticSession) для сбора слепков и потоковых логов."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shlex
import time
import tomllib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field

from ..exceptions import ConfigurationError
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts, diff_facts
from ._log_pipeline import (
    ArchiveHandler,
    DirectStreamCollector,
    ForwardHandler,
    LocalFileHandler,
    LogHandler,
    LogPipeline,
    _sanitize_name,
)

if TYPE_CHECKING:
    from .._connection import Connection

logger = logging.getLogger(__name__)


class StreamSourceSpec(BaseModel):
    """Спецификация фонового потокового источника логов (dmesg -w, journalctl -f и т.д.)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str
    command: str
    mode: Literal["auto", "stream", "screen"] = "auto"
    restart_on_exit: bool = False
    timeout: float | None = None

    @classmethod
    def coerce(cls, item: StreamSourceSpec | Mapping[str, Any] | str) -> Self:
        """Привести строку команды или словарь к ``StreamSourceSpec``."""
        if isinstance(item, cls):
            return item
        if isinstance(item, str):
            safe = _sanitize_name(item.split()[0] if item.split() else "stream")
            return cls(name=safe, command=item)
        if isinstance(item, Mapping):
            return cls(**item)
        raise TypeError(f"Unsupported StreamSourceSpec item: {type(item).__name__}")


class DiagnosticConfig(BaseModel):
    """Конфигурация комплексной диагностической сессии ``DiagnosticSession``."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    facts: FactSpec = Field(default_factory=FactSpec)
    streams: list[StreamSourceSpec] = Field(default_factory=list)
    local_dir: str = "./diagnostics"
    archive_path: str | None = None
    archive_format: Literal["tar.gz", "zip", "none"] = "tar.gz"
    fsync_realtime: bool = True
    forward_uri: str | None = None
    forward_remote_dir: str = "/tmp/uniconn_diagnostics"
    gather_pre_facts: bool = True
    gather_post_facts: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Создать ``DiagnosticConfig`` из словаря."""
        payload = dict(data)
        raw_facts = payload.get("facts")
        facts_spec = FactSpec.coerce(raw_facts) if raw_facts is not None else FactSpec()

        raw_streams = payload.get("streams", [])
        streams_list: list[StreamSourceSpec] = []
        if isinstance(raw_streams, Mapping):
            for k, v in raw_streams.items():
                if isinstance(v, str):
                    streams_list.append(StreamSourceSpec(name=str(k), command=v))
                elif isinstance(v, Mapping):
                    streams_list.append(StreamSourceSpec(name=str(k), **v))
        elif isinstance(raw_streams, Sequence):
            for s in raw_streams:
                streams_list.append(StreamSourceSpec.coerce(s))

        return cls(
            facts=facts_spec or FactSpec(),
            streams=streams_list,
            local_dir=str(payload.get("local_dir", "./diagnostics")),
            archive_path=payload.get("archive_path"),
            archive_format=payload.get("archive_format", "tar.gz"),
            fsync_realtime=bool(payload.get("fsync_realtime", True)),
            forward_uri=payload.get("forward_uri"),
            forward_remote_dir=str(
                payload.get("forward_remote_dir", "/tmp/uniconn_diagnostics")
            ),
            gather_pre_facts=bool(payload.get("gather_pre_facts", True)),
            gather_post_facts=bool(payload.get("gather_post_facts", True)),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        """Загрузить ``DiagnosticConfig`` из YAML, JSON или TOML файла."""
        filepath = Path(path)
        content = filepath.read_text(encoding="utf-8")
        suffix = filepath.suffix.lower()
        if suffix in (".yaml", ".yml"):
            import yaml

            loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
            data = yaml.load(content, Loader=loader) or {}
        elif suffix == ".json":
            data = json.loads(content)
        elif suffix == ".toml":
            data = tomllib.loads(content)
        else:
            raise ConfigurationError(
                f"Unsupported DiagnosticConfig file format: {filepath.suffix}. "
                "Use .yaml, .yml, .json or .toml"
            )
        if not isinstance(data, Mapping):
            raise ConfigurationError(
                f"DiagnosticConfig file {filepath} must contain a mapping"
            )
        return cls.from_dict(data)

    @classmethod
    def coerce(
        cls, config: DiagnosticConfig | Mapping[str, Any] | str | Path | None
    ) -> DiagnosticConfig:
        """Привести аргумент ``config`` к экземпляру ``DiagnosticConfig``."""
        if config is None:
            return cls()
        if isinstance(config, cls):
            return config
        if isinstance(config, (str, Path)):
            return cls.from_file(config)
        if isinstance(config, Mapping):
            return cls.from_dict(config)
        raise TypeError(f"Unsupported DiagnosticConfig type: {type(config).__name__}")


class DiagnosticResult(BaseModel):
    """Итоговый результат и манифест выполненной диагностической сессии."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: str
    started_at: str
    finished_at: str
    duration_seconds: float
    host_survived: bool = True
    workspace_dir: str
    archive_path: str | None = None
    pre_facts: HostFacts | None = None
    post_facts: HostFacts | None = None
    facts_diff: FactsDiffReport | None = None
    snapshots: dict[str, HostFacts] = Field(default_factory=dict)
    stream_files: dict[str, str] = Field(default_factory=dict)
    tool_artifacts: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)

    def to_manifest_dict(self) -> dict[str, Any]:
        """Сериализовать метаданные сессии для записи в ``manifest.json``."""
        return {
            "host": self.host,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "host_survived": self.host_survived,
            "workspace_dir": self.workspace_dir,
            "archive_path": self.archive_path,
            "has_pre_facts": self.pre_facts is not None,
            "has_post_facts": self.post_facts is not None,
            "has_drift": self.facts_diff.has_drift if self.facts_diff else False,
            "snapshots": list(self.snapshots.keys()),
            "stream_files": dict(self.stream_files),
            "tool_artifacts": dict(self.tool_artifacts),
            "errors": list(self.errors),
        }


def _write_json_atomic(path: Path, data: Any, fsync: bool = True) -> None:
    """Записать JSON-файл с опциональным ``os.fsync`` для защиты от потери данных."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    with path.open("w", encoding="utf-8") as f:
        f.write(text)
        if fsync:
            f.flush()
            os.fsync(f.fileno())


class DiagnosticSession:
    """Контекстный менеджер комплексной диагностики и отказоустойчивого сбора логов.

    Объединяет разовые слепки ``gather_facts`` (до, во время и после теста)
    с фоновым потоковым сбором ``LogPipeline`` (``LocalFileHandler`` в режиме
    ``realtime`` + ``ForwardHandler`` на резервный сервер) и финальной упаковкой
    в единый ``.tar.gz`` / ``.zip`` архив с ``manifest.json``.
    """

    def __init__(
        self,
        connection: Connection,
        config: DiagnosticConfig | Mapping[str, Any] | str | Path | None = None,
        *,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        streams: Sequence[StreamSourceSpec | Mapping[str, Any] | str] | None = None,
        local_dir: str | Path | None = None,
        archive_path: str | Path | None = None,
        archive_format: Literal["tar.gz", "zip", "none"] | None = None,
        forward_to: Connection | str | None = None,
        forward_remote_dir: str | None = None,
        fsync_realtime: bool | None = None,
        gather_pre_facts: bool | None = None,
        gather_post_facts: bool | None = None,
    ) -> None:
        base_cfg = DiagnosticConfig.coerce(config)
        resolved_spec = FactSpec.coerce(spec) if spec is not None else base_cfg.facts
        resolved_streams = (
            [StreamSourceSpec.coerce(s) for s in streams]
            if streams is not None
            else list(base_cfg.streams)
        )

        self._conn = connection
        self._config = DiagnosticConfig(
            facts=resolved_spec or FactSpec(),
            streams=resolved_streams,
            local_dir=str(local_dir) if local_dir is not None else base_cfg.local_dir,
            archive_path=(
                str(archive_path) if archive_path is not None else base_cfg.archive_path
            ),
            archive_format=(
                archive_format
                if archive_format is not None
                else base_cfg.archive_format
            ),
            fsync_realtime=(
                fsync_realtime
                if fsync_realtime is not None
                else base_cfg.fsync_realtime
            ),
            forward_uri=(
                forward_to
                if isinstance(forward_to, str)
                else base_cfg.forward_uri
            ),
            forward_remote_dir=(
                forward_remote_dir
                if forward_remote_dir is not None
                else base_cfg.forward_remote_dir
            ),
            gather_pre_facts=(
                gather_pre_facts
                if gather_pre_facts is not None
                else base_cfg.gather_pre_facts
            ),
            gather_post_facts=(
                gather_post_facts
                if gather_post_facts is not None
                else base_cfg.gather_post_facts
            ),
        )
        self._external_forward_conn: Connection | None = (
            forward_to if not isinstance(forward_to, str) else None
        )
        self._owned_forward_conn: Connection | None = None

        self.pre_facts: HostFacts | None = None
        self.post_facts: HostFacts | None = None
        self.facts_diff: FactsDiffReport | None = None
        self.snapshots: dict[str, HostFacts] = {}
        self.errors: list[str] = []
        self.result: DiagnosticResult | None = None

        self._started_mono: float = 0.0
        self._started_iso: str = ""
        self._workspace_dir: Path = Path(self._config.local_dir)
        self._local_handler: LocalFileHandler | None = None
        self._forward_handler: ForwardHandler | None = None
        self._pipeline: LogPipeline | None = None
        self._stream_collectors: list[DirectStreamCollector] = []
        self._screen_commands: list[tuple[str, str]] = []

    @property
    def workspace_dir(self) -> Path:
        """Рабочая директория текущей диагностической сессии."""
        return self._workspace_dir

    def _active_forward_conn(self) -> Connection | None:
        return self._external_forward_conn or self._owned_forward_conn

    async def _forward_json(self, filename: str, payload: Any) -> None:
        """Переслать JSON-слепок на резервный сервер (best-effort)."""
        fwd_conn = self._active_forward_conn()
        if fwd_conn is None:
            return
        remote_dir = self._config.forward_remote_dir.rstrip("/")
        remote_file = f"{remote_dir}/{_sanitize_name(filename)}"
        try:
            await fwd_conn.run(
                f"mkdir -p {shlex.quote(remote_dir)}", raise_on_error=False
            )
            text = json.dumps(payload, indent=2, ensure_ascii=False)
            await fwd_conn.run(
                f"printf '%s' {shlex.quote(text)} > {shlex.quote(remote_file)}",
                raise_on_error=False,
            )
        except Exception as exc:
            logger.warning(f"Не удалось переслать {filename} на резервный хост: {exc}")

    async def __aenter__(self) -> Self:
        """Начать диагностическую сессию: создать рабочую папку, собрать pre_facts и запустить потоки."""
        self._started_mono = time.monotonic()
        now_dt = datetime.now(UTC)
        self._started_iso = now_dt.isoformat()
        ts_str = now_dt.strftime("%Y%m%d_%H%M%S")
        host_str = self._conn.config.host or "localhost"
        safe_host = _sanitize_name(host_str)

        base_dir = Path(self._config.local_dir)
        self._workspace_dir = base_dir / f"diag_{safe_host}_{ts_str}"
        streams_dir = self._workspace_dir / "streams"
        tools_dir = self._workspace_dir / "tools"
        streams_dir.mkdir(parents=True, exist_ok=True)
        tools_dir.mkdir(parents=True, exist_ok=True)

        if self._external_forward_conn is None and self._config.forward_uri:
            from .._connection import Connection as ConnCls

            try:
                self._owned_forward_conn = ConnCls.from_uri(self._config.forward_uri)
                await self._owned_forward_conn.__aenter__()
            except Exception as exc:
                self.errors.append(f"forward_connect: {exc}")

        handlers: list[LogHandler] = []
        self._local_handler = LocalFileHandler(
            local_dir=streams_dir,
            name_template="{session_id}.log",
            host=host_str,
            strategy="realtime",
            fsync=self._config.fsync_realtime,
        )
        handlers.append(self._local_handler)

        fwd_conn = self._active_forward_conn()
        if fwd_conn is not None:
            remote_dir = self._config.forward_remote_dir.rstrip("/")
            with contextlib.suppress(Exception):
                await fwd_conn.run(
                    f"mkdir -p {shlex.quote(remote_dir)}", raise_on_error=False
                )
            self._forward_handler = ForwardHandler(
                connection=fwd_conn,
                remote_path=f"{remote_dir}/{{session_id}}.log",
            )
            handlers.append(self._forward_handler)

        self._pipeline = LogPipeline(handlers)

        if self._config.gather_pre_facts:
            try:
                self.pre_facts = await self._conn._facts_collector.gather(
                    refresh=True,
                    spec=self._config.facts,
                    artifact_dir=tools_dir,
                )
                pre_dict = self.pre_facts.to_dict()
                _write_json_atomic(
                    self._workspace_dir / "pre_facts.json",
                    pre_dict,
                    fsync=self._config.fsync_realtime,
                )
                await self._forward_json("pre_facts.json", pre_dict)
            except Exception as exc:
                self.errors.append(f"pre_facts: {exc}")

        for stream_spec in self._config.streams:
            await self._start_stream_source(stream_spec)

        return self

    async def _start_stream_source(self, spec: StreamSourceSpec) -> None:
        """Запустить потоковый источник в режиме ``stream`` или ``screen`` (с автовыбором)."""
        assert self._pipeline is not None
        effective_command = spec.command

        if spec.mode == "screen":
            chk = await self._conn.run(
                "command -v screen >/dev/null 2>&1", raise_on_error=False
            )
            if chk.ok:
                screen_name = f"uniconn_diag_{_sanitize_name(spec.name)}"
                remote_log = f"/tmp/{screen_name}.log"
                launch_cmd = (
                    f"rm -f {shlex.quote(remote_log)} && "
                    f"screen -dmS {shlex.quote(screen_name)} "
                    f"sh -c {shlex.quote(f'{spec.command} > {remote_log} 2>&1')}"
                )
                res = await self._conn.run(launch_cmd, raise_on_error=False)
                if res.ok:
                    self._screen_commands.append((screen_name, remote_log))
                    effective_command = f"tail -n +1 -f {shlex.quote(remote_log)}"

        collector = DirectStreamCollector(
            connection=self._conn,
            name=spec.name,
            command=effective_command,
            pipeline=self._pipeline,
            timeout=spec.timeout,
            restart_on_exit=spec.restart_on_exit,
        )
        collector.start()
        self._stream_collectors.append(collector)

    async def snapshot(self, label: str = "snapshot") -> HostFacts:
        """Сделать промежуточный слепок ``HostFacts`` во время выполнения теста."""
        safe_label = _sanitize_name(label)
        tools_dir = self._workspace_dir / "tools"
        facts = await self._conn._facts_collector.gather(
            refresh=True,
            spec=self._config.facts,
            artifact_dir=tools_dir,
        )
        self.snapshots[safe_label] = facts
        snap_dict = facts.to_dict()
        _write_json_atomic(
            self._workspace_dir / "snapshots" / f"{safe_label}.json",
            snap_dict,
            fsync=self._config.fsync_realtime,
        )
        await self._forward_json(f"snapshot_{safe_label}.json", snap_dict)
        return facts

    async def emit_custom_log(self, name: str, text: str) -> None:
        """Записать пользовательское сообщение/метку в конвейер логов сессии."""
        if self._pipeline is None:
            return
        line = text if text.endswith("\n") else f"{text}\n"
        await self._pipeline.emit(name, [line])

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Остановить потоки, проверить выживаемость хоста, собрать post_facts и упаковать бандл."""
        host_survived = True
        if exc_val is not None:
            self.errors.append(f"workload_exception: {type(exc_val).__name__}: {exc_val}")

        for collector in self._stream_collectors:
            await collector.stop()
            if collector.error:
                self.errors.append(f"stream[{collector.name}]: {collector.error}")

        # Останавливаем screen-сессии на хосте, если они запускались и хост отвечает
        for screen_name, remote_log in self._screen_commands:
            try:
                await self._conn.run(
                    f"screen -S {shlex.quote(screen_name)} -X quit >/dev/null 2>&1; "
                    f"rm -f {shlex.quote(remote_log)}",
                    timeout=3.0,
                    raise_on_error=False,
                )
            except Exception:
                host_survived = False

        if self._pipeline is not None:
            await self._pipeline.finalize()

        tools_dir = self._workspace_dir / "tools"
        if self._config.gather_post_facts:
            try:
                ping_res = await self._conn.ping(timeout=3.0)
                if not ping_res.alive:
                    host_survived = False
                    self.errors.append(
                        f"post_ping_failed: {ping_res.error or 'Host unreachable'}"
                    )
                else:
                    self.post_facts = await self._conn._facts_collector.gather(
                        refresh=True,
                        spec=self._config.facts,
                        artifact_dir=tools_dir,
                    )
                    post_dict = self.post_facts.to_dict()
                    _write_json_atomic(
                        self._workspace_dir / "post_facts.json",
                        post_dict,
                        fsync=self._config.fsync_realtime,
                    )
                    await self._forward_json("post_facts.json", post_dict)
            except Exception as exc:
                host_survived = False
                self.errors.append(f"post_facts: {exc}")

        if self.pre_facts is not None and self.post_facts is not None:
            self.facts_diff = diff_facts(
                {"pre": self.pre_facts, "post": self.post_facts},
                baseline_host="pre",
            )
            diff_dict = self.facts_diff.to_dict()
            _write_json_atomic(
                self._workspace_dir / "facts_diff.json",
                diff_dict,
                fsync=self._config.fsync_realtime,
            )
            await self._forward_json("facts_diff.json", diff_dict)

        stream_files: dict[str, str] = {}
        if self._local_handler is not None:
            for sid, p in self._local_handler.written_paths.items():
                stream_files[sid] = str(p)

        tool_artifacts: dict[str, str] = {}
        for facts_obj in (self.pre_facts, self.post_facts):
            if facts_obj is not None:
                for tool_name, tool_val in facts_obj.tools.items():
                    if isinstance(tool_val, Mapping) and "artifact_path" in tool_val:
                        tool_artifacts[tool_name] = str(tool_val["artifact_path"])

        finished_iso = datetime.now(UTC).isoformat()
        duration_sec = max(0.0, time.monotonic() - self._started_mono)
        host_str = self._conn.config.host or "localhost"

        resolved_archive: str | None = None
        if self._config.archive_format in ("tar.gz", "zip"):
            ext = ".tar.gz" if self._config.archive_format == "tar.gz" else ".zip"
            if self._config.archive_path:
                ts_now = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
                formatted = self._config.archive_path.format(
                    host=_sanitize_name(host_str),
                    timestamp=ts_now,
                )
                resolved_archive = str(Path(formatted))
            else:
                resolved_archive = f"{self._workspace_dir}{ext}"

        self.result = DiagnosticResult(
            host=host_str,
            started_at=self._started_iso,
            finished_at=finished_iso,
            duration_seconds=duration_sec,
            host_survived=host_survived,
            workspace_dir=str(self._workspace_dir),
            archive_path=resolved_archive,
            pre_facts=self.pre_facts,
            post_facts=self.post_facts,
            facts_diff=self.facts_diff,
            snapshots=dict(self.snapshots),
            stream_files=stream_files,
            tool_artifacts=tool_artifacts,
            errors=list(self.errors),
        )

        manifest_dict = self.result.to_manifest_dict()
        _write_json_atomic(
            self._workspace_dir / "manifest.json",
            manifest_dict,
            fsync=self._config.fsync_realtime,
        )
        await self._forward_json("manifest.json", manifest_dict)

        if resolved_archive is not None and self._config.archive_format in (
            "tar.gz",
            "zip",
        ):
            await asyncio.to_thread(
                ArchiveHandler.build_archive,
                self._workspace_dir,
                resolved_archive,
                self._config.archive_format,
            )
            fwd_conn = self._active_forward_conn()
            if fwd_conn is not None:
                remote_dir = self._config.forward_remote_dir.rstrip("/")
                remote_arch = f"{remote_dir}/{Path(resolved_archive).name}"
                try:
                    await fwd_conn.upload(resolved_archive, remote_arch)
                except Exception as exc:
                    logger.warning(
                        f"Не удалось загрузить архив {resolved_archive} на резервный хост: {exc}"
                    )

        if self._owned_forward_conn is not None:
            with contextlib.suppress(Exception):
                await self._owned_forward_conn.close()
            self._owned_forward_conn = None

        return False


__all__ = [
    "DiagnosticConfig",
    "DiagnosticResult",
    "DiagnosticSession",
    "StreamSourceSpec",
]
