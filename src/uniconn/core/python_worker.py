# src/uniconn/core/python_worker.py
"""Постоянный удалённый Python-воркер (Persistent Remote Python Worker, концепция Mitogen).

Обеспечивает выполнение нативных Python-функций и лямбда-выражений без накладных
расходов на форк оболочки и инициализацию SSH-каналов, а также ускоряет сбор
системных фактов (``gather_facts``), пакетный обход ФС (``RemotePath.glob``)
и идемпотентное управление состоянием (``conn.state``) через единый JSON-RPC пайп.
"""

from __future__ import annotations

import asyncio
import base64
import builtins
import contextlib
import inspect
import json
import logging
import re
import shlex
import sys
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

from ..exceptions import CapabilityNotSupportedError, ConnectionError, ExecutionError, TimeoutError
from ..result import Result
from ..services.facts_models import HostFacts
from ..transports.base import ShellCapableTransport, ShellProcessProtocol, supports_capability
from ._worker_runtime import (
    _SERIALIZED_CODE_CACHE as _SERIALIZED_CODE_CACHE,
)
from ._worker_runtime import (
    WORKER_BOOTSTRAP_SCRIPT,
    WORKER_READY_MARKER,
    WORKER_RPC_PREFIX,
    CallableSerializer,
    _decode_worker_value,
    _encode_worker_value,
    collect_local_python_facts,
    raw_dict_to_host_facts,
)
from ._worker_runtime import (
    _LambdaFinder as _LambdaFinder,
)
from .pipeline import CommandRequest, prepare_sudo_command

if TYPE_CHECKING:
    from .connection import Connection

logger = logging.getLogger(__name__)


class RemotePythonWorker:
    """Менеджер постоянного удалённого Python-воркера для соединения ``Connection``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать менеджер Python-воркера."""
        self._conn = conn
        self._lock = asyncio.Lock()
        self._req_id = 0
        self._local_proc: asyncio.subprocess.Process | None = None
        self._shell_proc: ShellProcessProtocol | None = None
        self._unavailable = False
        self._active = False

    @property
    def is_active(self) -> bool:
        """Запущен ли сейчас постоянный процесс воркера."""
        if self._local_proc is not None and self._local_proc.returncode is None:
            return True
        return self._active and self._shell_proc is not None

    @property
    def is_running(self) -> bool:
        """Псевдоним ``is_active``: запущен ли сейчас постоянный процесс воркера."""
        return self.is_active

    @property
    def is_unavailable(self) -> bool:
        """Признак того, что на целевом хосте отсутствует Python 3 или транспорт не поддерживает воркер."""
        return self._unavailable

    def _python_interpreter(self) -> str:
        """Определить команду запуска интерпретатора Python."""
        opt = self._conn.config.options.get("python_interpreter")
        if isinstance(opt, str) and opt.strip():
            return opt.strip()
        if self._conn.transport_name == "local":
            return sys.executable
        return "python3"

    def _is_auto_enabled(self) -> bool:
        """Проверить, разрешена ли авто-активация воркера в настройках подключения."""
        if self._unavailable:
            return False
        raw_opt = self._conn.config.options.get("python_worker", "auto")
        if isinstance(raw_opt, bool):
            return raw_opt
        return str(raw_opt).strip().lower() not in ("false", "0", "no", "off", "disabled")

    def _is_transport_mocked_or_unsupported(self) -> bool:
        """Проверить, не замокан ли транспорт/run в тестах и поддерживает ли он Python-воркер."""
        tr_name = self._conn.transport_name
        if tr_name in ("ipmi", "redfish", "serial", "uart", "telnet"):
            return True

        conn_run = getattr(self._conn, "run", None)
        conn_type_run = getattr(type(self._conn), "run", None)
        if getattr(conn_run, "__func__", None) is not conn_type_run:
            return True

        tr = getattr(self._conn, "transport", None)
        if tr is None:
            return True
        tr_run = getattr(tr, "run", None)
        tr_type_run = getattr(type(tr), "run", None)
        if getattr(tr_run, "__func__", None) is not tr_type_run:
            return True

        cassette = getattr(tr, "cassette", None)
        if cassette is not None:
            has_sys_py_rpc = any(
                getattr(it, "kind", "") == "py_rpc"
                and getattr(it, "op", "") in ("facts", "glob", "checksum", "sync_scan")
                for it in getattr(cassette, "interactions", [])
            )
            if not has_sys_py_rpc:
                return True
        return False

    def can_auto_accelerate(self) -> bool:
        """Проверить, можно ли прозрачно ускорить операцию (gather_facts / glob / state) через воркер."""
        if self._conn.dry_run:
            return False
        if not self._is_auto_enabled():
            return False
        if self._is_transport_mocked_or_unsupported():
            return False
        raw_opt = self._conn.config.options.get("python_worker", "auto")
        is_explicit = raw_opt is True or str(raw_opt).strip().lower() in ("true", "1", "yes", "on", "always")
        if not is_explicit:
            if self._conn.operation_observers:
                return False
            if any(type(m).__name__ == "TracingMiddleware" for m in self._conn.pipeline.middlewares):
                return False
        return True

    def _build_bootstrap_command(self) -> str:
        """Сформировать однострочную команду запуска постоянного воркера со сжатым base64-скриптом."""
        b64_script = base64.b64encode(WORKER_BOOTSTRAP_SCRIPT.encode("utf-8")).decode("ascii")
        raw_interp = self._python_interpreter()
        from ..services.provisioning.windows import is_windows_connection

        if self._conn.transport_name in ("winrm", "wsman") or (
            self._conn.transport_name != "local" and is_windows_connection(self._conn)
        ):
            clean_interp = raw_interp.replace('"', "").strip() or "python"
            interp_expr = f'& "{clean_interp}"' if (" " in clean_interp or "\\" in clean_interp) else clean_interp
            return (
                f"{interp_expr} -u -c "
                f"\"import base64; exec(base64.b64decode('{b64_script}').decode('utf-8'))\""
            )
        if re.search(r"[;|&`$><\n\r]", raw_interp):
            safe_interp = shlex.quote(raw_interp)
        else:
            try:
                parts = shlex.split(raw_interp)
            except ValueError:
                parts = [raw_interp]
            safe_interp = shlex.join(parts) if parts else "python3"
        return (
            f"{safe_interp} -u -c "
            f"\"import base64; exec(base64.b64decode('{b64_script}').decode('utf-8'))\""
        )

    async def _start_local_worker(self, timeout: float = 10.0) -> bool:
        """Запустить постоянный локальный подпроцесс Python-воркера через stdin/stdout пайп."""
        if self._local_proc is not None and self._local_proc.returncode is None:
            return True

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-u",
                "-c",
                WORKER_BOOTSTRAP_SCRIPT,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            line = raw_line.decode("utf-8", errors="replace").strip()
            if WORKER_READY_MARKER not in line:
                with contextlib.suppress(OSError, ProcessLookupError, RuntimeError):
                    if proc.stdin is not None:
                        proc.stdin.close()
                    proc.kill()
                    await proc.wait()
                transport = getattr(proc, "_transport", None)
                if transport is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        transport.close()
                self._unavailable = True
                return False
            self._local_proc = proc
            self._active = True
            return True
        except (OSError, builtins.TimeoutError, ExecutionError, RuntimeError, ValueError) as exc:
            logger.debug("Failed to start local Python worker: %s", exc)
            self._unavailable = True
            return False

    async def _start_remote_shell_worker(self, timeout: float = 10.0) -> bool:
        """Запустить постоянный удалённый процесс воркера через поток ShellCapableTransport."""
        if self._active and self._shell_proc is not None:
            return True

        tr = self._conn.transport
        if not tr.is_connected:
            await tr.connect()

        if not supports_capability(tr, ShellCapableTransport):
            return False

        try:
            proc = await tr.open_shell(term_type="dumb", term_size=(200, 24))
            boot_cmd = self._build_bootstrap_command()
            launch_line = f"stty -echo 2>/dev/null || true; exec {boot_cmd}\n"
            proc.stdin.write(launch_line)
            await proc.stdin.drain()

            deadline = time.monotonic() + timeout
            buf = ""
            while time.monotonic() < deadline:
                rem = max(0.1, deadline - time.monotonic())
                chunk_raw = await asyncio.wait_for(proc.stdout.read(4096), timeout=rem)
                if not chunk_raw:
                    break
                chunk = (
                    chunk_raw.decode("utf-8", errors="replace")
                    if isinstance(chunk_raw, bytes)
                    else str(chunk_raw)
                )
                buf += chunk
                if WORKER_READY_MARKER in buf:
                    self._shell_proc = proc
                    self._active = True
                    return True
            with contextlib.suppress(OSError, RuntimeError, builtins.TimeoutError, ConnectionError):
                proc.close()
                await proc.wait_closed()
            return False
        except (OSError, builtins.TimeoutError, ExecutionError, ConnectionError, RuntimeError) as exc:
            logger.debug("Failed to start remote shell Python worker: %s", exc)
            return False

    async def ensure_started(self, timeout: float | None = None) -> bool:
        """Гарантировать, что постоянный воркер запущен (возвращает True при успехе)."""
        if self.is_active:
            return True
        if self._unavailable:
            return False

        eff_timeout = (
            timeout
            if timeout is not None
            else (self._conn.config.timeout if self._conn.config.timeout is not None else 10.0)
        )
        if self._conn.transport_name == "local" and not self._is_transport_mocked_or_unsupported():
            return await self._start_local_worker(timeout=eff_timeout)

        if not self._is_transport_mocked_or_unsupported():
            started = await self._start_remote_shell_worker(timeout=eff_timeout)
            if started:
                return True

        return False

    async def _send_over_pipe(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Отправить JSON-RPC запрос по активному пайпу и дождаться ответа с маркером."""
        eff_timeout = (
            timeout
            if timeout is not None
            else (self._conn.config.timeout if self._conn.config.timeout is not None else 30.0)
        )
        req_line = json.dumps(payload, ensure_ascii=False) + "\n"

        if self._local_proc is not None and self._local_proc.returncode is None:
            assert self._local_proc.stdin is not None
            assert self._local_proc.stdout is not None
            self._local_proc.stdin.write(req_line.encode("utf-8"))
            await self._local_proc.stdin.drain()

            deadline = time.monotonic() + eff_timeout
            while True:
                rem = max(0.05, deadline - time.monotonic())
                try:
                    raw = await asyncio.wait_for(
                        self._local_proc.stdout.readline(), timeout=rem
                    )
                except builtins.TimeoutError as exc:
                    await self._reset_worker()
                    raise TimeoutError(
                        f"Python worker timed out after {eff_timeout}s",
                        host=self._conn.config.host,
                    ) from exc
                if not raw:
                    await self._reset_worker()
                    raise ExecutionError(
                        "Python worker process closed stdout unexpectedly",
                        host=self._conn.config.host,
                    )
                text = raw.decode("utf-8", errors="replace").strip()
                if WORKER_RPC_PREFIX in text:
                    json_part = text.split(WORKER_RPC_PREFIX, 1)[1]
                    try:
                        return json.loads(json_part)
                    except json.JSONDecodeError as exc:
                        await self._reset_worker()
                        raise ExecutionError(
                            f"Malformed JSON-RPC frame from Python worker: {exc}",
                            host=self._conn.config.host,
                        ) from exc

        if self._shell_proc is not None:
            self._shell_proc.stdin.write(req_line)
            await self._shell_proc.stdin.drain()

            deadline = time.monotonic() + eff_timeout
            buf = ""
            while True:
                rem = max(0.05, deadline - time.monotonic())
                try:
                    chunk_raw = await asyncio.wait_for(
                        self._shell_proc.stdout.read(65536), timeout=rem
                    )
                except builtins.TimeoutError as exc:
                    await self._reset_worker()
                    raise TimeoutError(
                        f"Remote Python worker timed out after {eff_timeout}s",
                        host=self._conn.config.host,
                    ) from exc
                if not chunk_raw:
                    await self._reset_worker()
                    raise ExecutionError(
                        "Remote Python worker closed shell stream unexpectedly",
                        host=self._conn.config.host,
                    )
                chunk = (
                    chunk_raw.decode("utf-8", errors="replace")
                    if isinstance(chunk_raw, bytes)
                    else str(chunk_raw)
                )
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if WORKER_RPC_PREFIX in line:
                        json_part = line.split(WORKER_RPC_PREFIX, 1)[1]
                        try:
                            return json.loads(json_part)
                        except json.JSONDecodeError as exc:
                            await self._reset_worker()
                            raise ExecutionError(
                                f"Malformed JSON-RPC frame from remote Python worker: {exc}",
                                host=self._conn.config.host,
                            ) from exc

        raise ExecutionError("Python worker pipe is not connected", host=self._conn.config.host)

    async def _execute_oneshot_via_run(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        *,
        sudo: bool = False,
        bypass_pipeline: bool = False,
    ) -> dict[str, Any]:
        """Выполнить RPC-запрос одноразовым вызовом ``python3 -u -c ...``."""
        cmd = self._build_bootstrap_command()
        req_input = json.dumps(payload, ensure_ascii=False) + '\n{"id": 0, "op": "exit"}\n'
        conn_run = getattr(self._conn, "run", None)
        conn_type_run = getattr(type(self._conn), "run", None)
        is_conn_run_mocked = getattr(conn_run, "__func__", None) is not conn_type_run

        if bypass_pipeline and not is_conn_run_mocked:
            tr = self._conn.transport
            if not tr.is_connected:
                await tr.connect()
            exec_cmd, effective_input = prepare_sudo_command(
                cmd,
                sudo=sudo,
                sudo_user=None,
                sudo_password=None,
                input_data=req_input,
                config_options=self._conn.config.options,
                config_password=self._conn.config.password,
            )
            tr_kwargs: dict[str, Any] = {}
            self._conn.context.apply_to_kwargs(tr_kwargs)
            if effective_input is not None:
                tr_kwargs["input"] = effective_input
            res = await tr.run(
                exec_cmd,
                timeout=timeout if timeout is not None else self._conn.config.timeout,
                **tr_kwargs,
            )
        else:
            res = await self._conn.run(
                cmd,
                input=req_input,
                timeout=timeout,
                sudo=sudo,
                raise_on_error=False,
                dry_run=False,
            )
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if WORKER_RPC_PREFIX in stripped:
                json_part = stripped.split(WORKER_RPC_PREFIX, 1)[1]
                try:
                    return json.loads(json_part)
                except json.JSONDecodeError as exc:
                    raise ExecutionError(
                        f"Malformed JSON-RPC frame from oneshot Python worker: {exc}",
                        command=cmd,
                        stdout=res.stdout,
                        stderr=res.stderr,
                        host=self._conn.config.host,
                    ) from exc

        if not sudo:
            self._unavailable = True
        raise ExecutionError(
            res.stderr.strip() or "Python 3 interpreter is not available on target host",
            command=cmd,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            host=self._conn.config.host,
        )

    async def request(
        self,
        op: str,
        *,
        timeout: float | None = None,
        sudo: bool = False,
        allow_oneshot_fallback: bool = True,
        **params: Any,
    ) -> Any:
        """Отправить типизированный RPC-запрос в Python-воркер (с поддержкой записи в Cassette)."""
        tr = self._conn.transport
        record_or_replay = getattr(tr, "record_or_replay_py_rpc", None)
        if callable(record_or_replay):
            coro = cast(
                Awaitable[Any],
                record_or_replay(
                    self,
                    op=op,
                    timeout=timeout,
                    sudo=sudo,
                    allow_oneshot_fallback=allow_oneshot_fallback,
                    **params,
                ),
            )
            return await coro

        return await self._raw_request(
            op,
            timeout=timeout,
            sudo=sudo,
            allow_oneshot_fallback=allow_oneshot_fallback,
            **params,
        )

    async def _raw_request(
        self,
        op: str,
        *,
        timeout: float | None = None,
        sudo: bool = False,
        allow_oneshot_fallback: bool = True,
        **params: Any,
    ) -> Any:
        """Низкоуровневое выполнение RPC-запроса под защитой асинхронной блокировки."""
        async with self._lock:
            self._req_id += 1
            bypass_pipeline = bool(params.pop("_bypass_pipeline", False))
            payload: dict[str, Any] = {"id": self._req_id, "op": op, **params}

            if sudo:
                resp = await self._execute_oneshot_via_run(
                    payload,
                    timeout=timeout,
                    sudo=True,
                    bypass_pipeline=bypass_pipeline,
                )
            else:
                started = await self.ensure_started(timeout=timeout)
                if started:
                    try:
                        resp = await self._send_over_pipe(payload, timeout=timeout)
                    except ExecutionError:
                        if await self.ensure_started(timeout=timeout):
                            resp = await self._send_over_pipe(payload, timeout=timeout)
                        elif allow_oneshot_fallback:
                            resp = await self._execute_oneshot_via_run(
                                payload,
                                timeout=timeout,
                                bypass_pipeline=bypass_pipeline,
                            )
                        else:
                            raise
                elif allow_oneshot_fallback:
                    resp = await self._execute_oneshot_via_run(
                        payload,
                        timeout=timeout,
                        bypass_pipeline=bypass_pipeline,
                    )
                else:
                    raise CapabilityNotSupportedError(
                        "Persistent Python worker is not available on this connection",
                        host=self._conn.config.host,
                    )

        if not resp.get("ok", False):
            err_type = resp.get("error_type", "RuntimeError")
            err_msg = resp.get("error_message", "Unknown error in remote Python worker")
            tb = resp.get("traceback", "")
            raise ExecutionError(
                f"Remote Python {err_type}: {err_msg}",
                command=f"run_python({params.get('func_name', op)})",
                exit_code=1,
                stdout=resp.get("stdout", ""),
                stderr=tb or err_msg,
                host=self._conn.config.host,
            )

        return _decode_worker_value(resp.get("result"))

    async def call(
        self,
        fn: Callable[..., Any] | str,
        *args: Any,
        timeout: float | None = None,
        sudo: bool = False,
        dry_run: bool | None = None,
        **kwargs: Any,
    ) -> Any:
        """Выполнить Python-функцию, lambda или выражение в удалённом воркере через CommandPipeline."""
        effective_dry = self._conn.dry_run if dry_run is None else dry_run
        source, func_name, is_expr = CallableSerializer.serialize(fn)
        cmd_label = f"run_python:{func_name}"
        encoded_args = _encode_worker_value(list(args))
        encoded_kwargs = _encode_worker_value(dict(kwargs))

        req = CommandRequest(
            raw_command=cmd_label,
            command=cmd_label,
            exec_command=cmd_label,
            timeout=timeout,
            raise_on_error=True,
            sudo=sudo,
            dry_run=effective_dry,
            transport_kwargs={
                "sudo": sudo,
                "args": args,
                "kwargs": kwargs,
            },
        )
        ret_holder: list[Any] = [None]

        async def _py_terminal(r: CommandRequest) -> Result:
            t0 = time.monotonic()
            val = await self.request(
                "call",
                timeout=r.timeout,
                sudo=r.sudo,
                source=source,
                func_name=func_name,
                is_expr=is_expr,
                args=encoded_args,
                kwargs=encoded_kwargs,
                cwd=r.transport_kwargs.get("cwd") or self._conn.current_cwd,
                env=r.transport_kwargs.get("env") or self._conn.current_env,
                _bypass_pipeline=True,
            )
            ret_holder[0] = val
            return Result(
                exit_code=0,
                stdout=repr(val),
                stderr="",
                duration=time.monotonic() - t0,
                command=cmd_label,
                host=self._conn.config.host,
            )

        await self._conn.pipeline.execute(req, terminal_handler=_py_terminal)
        return ret_holder[0]

    async def gather_facts(
        self,
        default_host: str = "localhost",
        timeout: float | None = None,
    ) -> HostFacts:
        """Мгновенно собрать ``HostFacts`` напрямую из памяти Python-воркера (/proc и sysfs)."""
        raw = await self.request(
            "facts",
            timeout=timeout,
            allow_oneshot_fallback=False,
            default_host=default_host,
        )
        return raw_dict_to_host_facts(raw, default_host=default_host)

    async def glob_with_stat(
        self,
        base_path: str,
        pattern: str = "*",
        *,
        recursive: bool = False,
        iterdir_only: bool = False,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        """Пакетно обойти директорию в воркере и вернуть список путей вместе со словарями FileStat."""
        res = await self.request(
            "glob",
            timeout=timeout,
            allow_oneshot_fallback=False,
            path=base_path,
            pattern=pattern,
            recursive=recursive,
            iterdir_only=iterdir_only,
        )
        return list(res or [])

    async def _reset_worker(self) -> None:
        """Сбросить аварийно завершённый процесс воркера и закрыть пайп-транспорты (Windows Proactor)."""
        self._active = False
        if self._local_proc is not None:
            proc = self._local_proc
            self._local_proc = None
            if proc.stdin is not None:
                with contextlib.suppress(OSError, RuntimeError):
                    proc.stdin.close()
            with contextlib.suppress(OSError, ProcessLookupError, RuntimeError):
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(OSError, RuntimeError):
                    transport.close()
                with contextlib.suppress(RuntimeError):
                    await asyncio.sleep(0)
        if self._shell_proc is not None:
            sproc = self._shell_proc
            self._shell_proc = None
            with contextlib.suppress(OSError, RuntimeError, builtins.TimeoutError, ConnectionError):
                sproc.close()
                wait_closed = getattr(sproc, "wait_closed", None)
                if callable(wait_closed):
                    res_wc = wait_closed()
                    if inspect.isawaitable(res_wc):
                        await res_wc

    async def close(self) -> None:
        """Корректно остановить постоянный Python-воркер и закрыть пайпы."""
        async with self._lock:
            if self._local_proc is not None and self._local_proc.returncode is None:
                with contextlib.suppress(OSError, ProcessLookupError, RuntimeError, builtins.TimeoutError):
                    if self._local_proc.stdin is not None:
                        self._local_proc.stdin.write(b'{"id": 0, "op": "exit"}\n')
                        await self._local_proc.stdin.drain()
                        self._local_proc.stdin.close()
                    await asyncio.wait_for(self._local_proc.wait(), timeout=1.0)
            if self._shell_proc is not None:
                with contextlib.suppress(OSError, RuntimeError, builtins.TimeoutError, ConnectionError):
                    self._shell_proc.stdin.write('{"id": 0, "op": "exit"}\n')
                    await self._shell_proc.stdin.drain()
            await self._reset_worker()


async def run_python(
    conn: Connection,
    fn: Callable[..., Any] | str,
    *args: Any,
    timeout: float | None = None,
    sudo: bool = False,
    dry_run: bool | None = None,
    **kwargs: Any,
) -> Any:
    """Выполнить нативную Python-функцию или лямбда-выражение на удалённом хосте без форка shell."""
    return await conn.python_worker.call(
        fn,
        *args,
        timeout=timeout,
        sudo=sudo,
        dry_run=dry_run,
        **kwargs,
    )


run_python.__name__ = "run_python"

__all__ = [
    "WORKER_BOOTSTRAP_SCRIPT",
    "WORKER_READY_MARKER",
    "WORKER_RPC_PREFIX",
    "CallableSerializer",
    "RemotePythonWorker",
    "_decode_worker_value",
    "_encode_worker_value",
    "collect_local_python_facts",
    "raw_dict_to_host_facts",
    "run_python",
]
