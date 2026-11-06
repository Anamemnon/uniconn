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

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..exceptions import ConfigurationError, HardwareFaultDetectedError
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts, diff_facts
from ._log_pipeline import (
    ArchiveHandler,
    DirectStreamCollector,
    ForwardHandler,
    LocalFileHandler,
    LogHandler,
    LogPipeline,
    LogWatchRule,
    MatchCallback,
    PatternTriggerHandler,
    StallCallback,
    TimelineHandler,
    _sanitize_name,
    resolve_watch_rules,
)
from ._models import LogMatchEvent, StallEvent
from ._session import BackgroundSession

if TYPE_CHECKING:
    from ..core.connection import Connection

logger = logging.getLogger(__name__)


class StreamSourceSpec(BaseModel):
    """Спецификация фонового потокового или периодически опрашиваемого источника логов."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str
    command: str
    mode: Literal["auto", "stream", "background"] = "auto"
    restart_on_exit: bool = False
    interval: float | None = None
    timestamp_lines: bool = False
    timeout: float | None = None
    max_silence_seconds: float | None = None

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except Exception as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError(str(exc)) from exc

    @field_validator("max_silence_seconds")
    @classmethod
    def _validate_max_silence(cls, value: float | None) -> float | None:
        if value is not None and value <= 0:
            raise ConfigurationError("StreamSourceSpec.max_silence_seconds must be > 0")
        return value

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


def _coerce_streams_list(raw_streams: Any) -> list[StreamSourceSpec]:
    """Нормализовать входной список или словарь потоков в ``list[StreamSourceSpec]``."""
    if raw_streams is None:
        return []
    streams_list: list[StreamSourceSpec] = []
    if isinstance(raw_streams, Mapping):
        for k, v in raw_streams.items():
            if isinstance(v, str):
                streams_list.append(StreamSourceSpec(name=str(k), command=v))
            elif isinstance(v, Mapping):
                spec_dict = dict(v)
                spec_dict.setdefault("name", str(k))
                streams_list.append(StreamSourceSpec(**spec_dict))
            elif isinstance(v, StreamSourceSpec):
                streams_list.append(v)
            else:
                raise ConfigurationError(
                    f"Unsupported stream entry for {k!r}: {type(v).__name__}"
                )
    elif isinstance(raw_streams, str):
        streams_list.append(StreamSourceSpec.coerce(raw_streams))
    elif isinstance(raw_streams, Sequence):
        for s in raw_streams:
            streams_list.append(StreamSourceSpec.coerce(s))
    else:
        raise ConfigurationError(
            f"Unsupported streams collection: {type(raw_streams).__name__}"
        )
    return streams_list


class DiagnosticConfig(BaseModel):
    """Конфигурация комплексной диагностической сессии ``DiagnosticSession``."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    facts: FactSpec = Field(default_factory=FactSpec)
    streams: list[StreamSourceSpec] = Field(default_factory=list)
    watch_rules: list[LogWatchRule] = Field(default_factory=list)
    local_dir: str = "./diagnostics"
    archive_path: str | None = None
    archive_format: Literal["tar.gz", "zip", "none"] = "tar.gz"
    fsync_realtime: bool = True
    forward_uri: str | None = None
    forward_remote_dir: str = "/tmp/uniconn_diagnostics"
    gather_pre_facts: bool = True
    gather_post_facts: bool = True
    enable_timeline: bool = True

    @field_validator("streams", mode="before")
    @classmethod
    def _validate_streams(cls, value: Any) -> list[StreamSourceSpec]:
        return _coerce_streams_list(value)

    @field_validator("watch_rules", mode="before")
    @classmethod
    def _validate_watch_rules(cls, value: Any) -> list[LogWatchRule]:
        return resolve_watch_rules(value)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        """Создать ``DiagnosticConfig`` из словаря."""
        payload = dict(data)
        raw_facts = payload.get("facts")
        facts_spec = FactSpec.coerce(raw_facts) if raw_facts is not None else FactSpec()

        return cls(
            facts=facts_spec or FactSpec(),
            streams=_coerce_streams_list(payload.get("streams", [])),
            watch_rules=resolve_watch_rules(payload.get("watch_rules")),
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
            enable_timeline=bool(payload.get("enable_timeline", True)),
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
    timeline_file: str | None = None
    pre_facts: HostFacts | None = None
    post_facts: HostFacts | None = None
    facts_diff: FactsDiffReport | None = None
    snapshots: dict[str, HostFacts] = Field(default_factory=dict)
    stream_files: dict[str, str] = Field(default_factory=dict)
    tool_artifacts: dict[str, str] = Field(default_factory=dict)
    matches: list[dict[str, Any]] = Field(default_factory=list)
    stalled_streams: list[str] = Field(default_factory=list)
    aborted_by_rule: str | None = None
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
            "timeline_file": self.timeline_file,
            "has_pre_facts": self.pre_facts is not None,
            "has_post_facts": self.post_facts is not None,
            "has_drift": self.facts_diff.has_drift if self.facts_diff else False,
            "snapshots": list(self.snapshots.keys()),
            "stream_files": dict(self.stream_files),
            "tool_artifacts": dict(self.tool_artifacts),
            "matches": list(self.matches),
            "stalled_streams": list(self.stalled_streams),
            "aborted_by_rule": self.aborted_by_rule,
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
    ``realtime`` + ``ForwardHandler`` на резервный сервер + ``PatternTriggerHandler``
    + ``TimelineHandler``) и финальной упаковкой в единый ``.tar.gz`` / ``.zip``
    архив с ``manifest.json`` и ``timeline.jsonl``.
    """

    def __init__(
        self,
        connection: Connection,
        config: DiagnosticConfig | Mapping[str, Any] | str | Path | None = None,
        *,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        streams: Sequence[StreamSourceSpec | Mapping[str, Any] | str] | None = None,
        watch_rules: Sequence[LogWatchRule | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | str
        | None = None,
        on_match: MatchCallback | None = None,
        on_stall: StallCallback | None = None,
        enable_timeline: bool | None = None,
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
            _coerce_streams_list(streams)
            if streams is not None
            else list(base_cfg.streams)
        )
        resolved_watch = (
            resolve_watch_rules(watch_rules)
            if watch_rules is not None
            else list(base_cfg.watch_rules)
        )

        self._conn = connection
        self._on_match = on_match
        self._on_stall = on_stall
        self._config = DiagnosticConfig(
            facts=resolved_spec or FactSpec(),
            streams=resolved_streams,
            watch_rules=resolved_watch,
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
            enable_timeline=(
                enable_timeline
                if enable_timeline is not None
                else base_cfg.enable_timeline
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
        self._timeline_handler: TimelineHandler | None = None
        self._trigger_handler: PatternTriggerHandler | None = None
        self._pipeline: LogPipeline | None = None
        self._stream_collectors: list[DirectStreamCollector] = []
        self._background_sessions: list[BackgroundSession] = []

    @property
    def workspace_dir(self) -> Path:
        """Рабочая директория текущей диагностической сессии."""
        return self._workspace_dir

    @property
    def matches(self) -> list[LogMatchEvent]:
        """Список зафиксированных совпадений по правилам ``watch_rules``."""
        if self._trigger_handler is None:
            return []
        return self._trigger_handler.matches

    @property
    def stalled_streams(self) -> list[str]:
        """Список имён потоков, в которых сработал детектор зависания ``max_silence_seconds``."""
        return [c.name for c in self._stream_collectors if c.stalled]

    @property
    def stall_events(self) -> list[StallEvent]:
        """Список событий зависания потоков ``StallEvent``."""
        return [
            c.stall_event
            for c in self._stream_collectors
            if c.stall_event is not None
        ]

    def check_abort(self) -> None:
        """Выбросить ``HardwareFaultDetectedError``, если сработало правило с ``abort_on_match=True``."""
        if self._trigger_handler is not None:
            self._trigger_handler.check_abort()

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
            from ..core.connection import Connection as ConnCls

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

        if self._config.enable_timeline:
            self._timeline_handler = TimelineHandler(
                self._workspace_dir / "timeline.jsonl",
                fsync=self._config.fsync_realtime,
                started_mono=self._started_mono,
            )
            self._timeline_handler.record_event(
                stream="diagnostic",
                kind="marker",
                text="session_start",
                extra={"host": host_str},
            )
            handlers.append(self._timeline_handler)

        if self._config.watch_rules or self._on_match is not None:
            self._trigger_handler = PatternTriggerHandler(
                rules=self._config.watch_rules,
                on_match=self._on_match,
                timeline=self._timeline_handler,
                host=host_str,
            )
            handlers.append(self._trigger_handler)

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
        """Запустить потоковый источник в режиме ``stream`` или ``background`` (с автовыбором)."""
        assert self._pipeline is not None
        effective_command = spec.command

        if spec.mode == "background":
            bg_name = f"uniconn_diag_{_sanitize_name(spec.name)}"
            remote_log = f"/tmp/{bg_name}.log"
            await self._conn.run(
                f"rm -f {shlex.quote(remote_log)}", raise_on_error=False
            )
            bg_session = BackgroundSession(
                self._conn, bg_name, remote_log, backend="auto"
            )
            try:
                await bg_session.create(spec.command)
                self._background_sessions.append(bg_session)
                effective_command = f"tail -n +1 -f {shlex.quote(remote_log)}"
            except Exception as exc:
                logger.warning(
                    f"Не удалось запустить фоновый источник {bg_name!r}, откат на stream: {exc}"
                )

        effective_restart = spec.restart_on_exit or (
            spec.interval is not None and spec.interval > 0
        )
        effective_delay = (
            spec.interval
            if (spec.interval is not None and spec.interval > 0)
            else 1.0
        )
        collector = DirectStreamCollector(
            connection=self._conn,
            name=spec.name,
            command=effective_command,
            pipeline=self._pipeline,
            timeout=spec.timeout,
            restart_on_exit=effective_restart,
            restart_delay=effective_delay,
            timestamp_lines=spec.timestamp_lines,
            max_silence_seconds=spec.max_silence_seconds,
            on_stall=self._on_stall,
            timeline=self._timeline_handler,
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
        if self._timeline_handler is not None:
            self._timeline_handler.record_event(
                stream="diagnostic",
                kind="marker",
                text=f"snapshot:{safe_label}",
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
        if exc_val is not None and not isinstance(exc_val, HardwareFaultDetectedError):
            self.errors.append(
                f"workload_exception: {type(exc_val).__name__}: {exc_val}"
            )

        for collector in self._stream_collectors:
            await collector.stop()
            if collector.error:
                self.errors.append(f"stream[{collector.name}]: {collector.error}")

        # Останавливаем фоновые сессии на хосте, если они запускались и хост отвечает
        for bg_session in self._background_sessions:
            try:
                await bg_session.kill(graceful=False)
                await bg_session.cleanup()
            except Exception:
                host_survived = False

        if self._timeline_handler is not None:
            self._timeline_handler.record_event(
                stream="diagnostic",
                kind="marker",
                text="session_end",
            )

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

        matches_dicts = [m.to_dict() for m in self.matches]
        stalled_list = self.stalled_streams
        first_abort = (
            self._trigger_handler.first_abort_match
            if self._trigger_handler is not None
            else None
        )
        aborted_by_rule = first_abort.rule_name if first_abort is not None else None
        if aborted_by_rule is not None:
            abort_err = f"abort_on_match[{aborted_by_rule}]: {first_abort.matched_line if first_abort else ''}"
            if abort_err not in self.errors:
                self.errors.append(abort_err)

        timeline_file_str: str | None = None
        if self._timeline_handler is not None and self._timeline_handler.path.exists():
            timeline_file_str = str(self._timeline_handler.path)

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
            timeline_file=timeline_file_str,
            pre_facts=self.pre_facts,
            post_facts=self.post_facts,
            facts_diff=self.facts_diff,
            snapshots=dict(self.snapshots),
            stream_files=stream_files,
            tool_artifacts=tool_artifacts,
            matches=matches_dicts,
            stalled_streams=stalled_list,
            aborted_by_rule=aborted_by_rule,
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
                    await fwd_conn.files.upload(resolved_archive, remote_arch)
                except Exception as exc:
                    logger.warning(
                        f"Не удалось загрузить архив {resolved_archive} на резервный хост: {exc}"
                    )

        if self._owned_forward_conn is not None:
            with contextlib.suppress(Exception):
                await self._owned_forward_conn.close()
            self._owned_forward_conn = None

        # Если сработало правило с abort_on_match=True и внутри блока ещё не было выброшено
        # исключение HardwareFaultDetectedError, выбрасываем его после полной упаковки бандла.
        if first_abort is not None and not isinstance(
            exc_val, HardwareFaultDetectedError
        ):
            try:
                self.check_abort()
            except HardwareFaultDetectedError as fault_err:
                if exc_val is not None:
                    raise fault_err from exc_val
                raise

        return False


__all__ = [
    "DiagnosticConfig",
    "DiagnosticResult",
    "DiagnosticSession",
    "StreamSourceSpec",
]
