# src/uniconn/core/python_worker.py
"""Постоянный удалённый Python-воркер (Persistent Remote Python Worker, концепция Mitogen).

Обеспечивает выполнение нативных Python-функций и лямбда-выражений без накладных
расходов на форк оболочки и инициализацию SSH-каналов, а также ускоряет сбор
системных фактов (``gather_facts``), пакетный обход ФС (``RemotePath.glob``)
и идемпотентное управление состоянием (``conn.state``) через единый JSON-RPC пайп.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import builtins
import contextlib
import inspect
import json
import logging
import os
import sys
import textwrap
import time
import weakref
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

from ..exceptions import CapabilityNotSupportedError, ExecutionError, TimeoutError
from ..result import Result
from ..services.facts_models import DiskInfo, HostFacts, NetworkInterface
from ..transports.base import ShellCapableTransport, ShellProcessProtocol, supports_capability

if TYPE_CHECKING:
    from .connection import Connection

logger = logging.getLogger(__name__)

WORKER_READY_MARKER = "__UNICONN_PYWORKER_READY__"
WORKER_RPC_PREFIX = "__UNICONN_PYRPC__:"

# Кэш сериализованных функций по объекту кода для нулевых накладных расходов при повторных вызовах
_SERIALIZED_CODE_CACHE: weakref.WeakKeyDictionary[Any, tuple[str, str, bool]] = (
    weakref.WeakKeyDictionary()
)

# Компактный самодостаточный bootstrap-скрипт удалённого Python 3 воркера (только stdlib)
WORKER_BOOTSTRAP_SCRIPT = r"""
import asyncio, base64, contextlib, difflib, fnmatch, glob, hashlib, inspect
import io, json, os, pathlib, platform, re, shutil, socket, stat, struct, sys, time, traceback
try:
    import fcntl, pwd, grp
except ImportError:
    fcntl = pwd = grp = None

_REAL_STDOUT = sys.stdout
_READY = "__UNICONN_PYWORKER_READY__"
_PREFIX = "__UNICONN_PYRPC__:"

_BASE_NS = {
    "os": os, "sys": sys, "json": json, "re": re, "pathlib": pathlib, "Path": pathlib.Path,
    "platform": platform, "shutil": shutil, "socket": socket, "stat": stat, "time": time,
    "hashlib": hashlib, "fnmatch": fnmatch, "glob": glob, "difflib": difflib,
    "pwd": pwd, "grp": grp, "asyncio": asyncio,
}

def _decode_input(val):
    if isinstance(val, dict):
        if len(val) == 1 and "__bytes_b64__" in val:
            return base64.b64decode(val["__bytes_b64__"])
        return {k: _decode_input(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_decode_input(x) for x in val]
    return val

def _normalize_value(val):
    if val is None or isinstance(val, (bool, int, float, str)):
        return val
    if isinstance(val, bytes):
        return {"__bytes_b64__": base64.b64encode(val).decode("ascii")}
    if isinstance(val, pathlib.PurePath):
        return str(val)
    if isinstance(val, (list, tuple, set, frozenset)):
        return [_normalize_value(x) for x in val]
    if isinstance(val, dict):
        return {str(k): _normalize_value(v) for k, v in val.items()}
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return _normalize_value(val.to_dict())
    return repr(val)

def _stat_dict(st, is_link=False):
    mode = st.st_mode
    return {
        "size": int(st.st_size),
        "uid": int(getattr(st, "st_uid", 0)),
        "gid": int(getattr(st, "st_gid", 0)),
        "permissions": oct(stat.S_IMODE(mode)),
        "mode": int(mode),
        "mtime": float(st.st_mtime),
        "atime": float(st.st_atime),
        "is_dir": bool(stat.S_ISDIR(mode)),
        "is_file": bool(stat.S_ISREG(mode)),
        "is_symlink": bool(is_link or stat.S_ISLNK(mode)),
    }

def _op_glob(req):
    base = req.get("path", ".")
    pattern = req.get("pattern", "*")
    recursive = bool(req.get("recursive", False))
    iterdir_only = bool(req.get("iterdir_only", False))
    base_path = pathlib.Path(base)
    if not base_path.exists():
        return []
    items = []
    if iterdir_only:
        with os.scandir(base_path) as it:
            for entry in sorted(it, key=lambda e: e.name):
                try:
                    is_lnk = entry.is_symlink()
                    st = entry.stat(follow_symlinks=True)
                except OSError:
                    st = entry.stat(follow_symlinks=False)
                    is_lnk = True
                items.append({
                    "path": entry.path,
                    "rel_path": entry.name,
                    "name": entry.name,
                    "stat": _stat_dict(st, is_lnk),
                })
        return items
    iterator = base_path.rglob(pattern) if recursive else base_path.glob(pattern)
    for p in sorted(iterator, key=lambda x: str(x)):
        try:
            is_lnk = p.is_symlink()
            st = p.stat()
        except OSError:
            try:
                st = p.lstat()
                is_lnk = True
            except OSError:
                continue
        try:
            rel_str = str(p.relative_to(base_path))
        except ValueError:
            rel_str = p.name
        items.append({
            "path": str(p),
            "rel_path": rel_str,
            "name": p.name,
            "stat": _stat_dict(st, is_lnk),
        })
    return items

def _op_facts(req):
    uname = platform.uname()
    os_family = "Windows" if os.name == "nt" else (uname.system or "Linux")
    distro = os_family
    os_rel = {}
    if os.path.isfile("/etc/os-release"):
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as fp:
                for line in fp:
                    if "=" in line and not line.startswith("#"):
                        k, v = line.strip().split("=", 1)
                        os_rel[k.strip()] = v.strip().strip('"').strip("'")
            distro = os_rel.get("PRETTY_NAME") or os_rel.get("NAME") or distro
            ids = {os_rel.get("ID", "").lower()} | set(os_rel.get("ID_LIKE", "").lower().split())
            if ids & {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}:
                os_family = "Debian"
            elif ids & {"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn"}:
                os_family = "RedHat"
            elif "alpine" in ids:
                os_family = "Alpine"
            elif ids & {"arch", "manjaro", "endeavouros"}:
                os_family = "Arch"
            elif ids & {"sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"}:
                os_family = "Suse"
        except OSError:
            pass
    uptime = 0.0
    if os.path.isfile("/proc/uptime"):
        try:
            with open("/proc/uptime", encoding="utf-8") as fp:
                uptime = round(float(fp.read().split()[0]), 1)
        except Exception:
            pass
    mem_total = 0
    mem_avail = 0
    if os.path.isfile("/proc/meminfo"):
        try:
            with open("/proc/meminfo", encoding="utf-8") as fp:
                info = {}
                for line in fp:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = parts[1].strip().split()[0]
                        if v.isdigit():
                            info[k] = int(v) * 1024
                mem_total = info.get("MemTotal", 0)
                mem_avail = info.get("MemAvailable", info.get("MemFree", 0))
        except Exception:
            pass
    disks = []
    if os.path.isfile("/proc/mounts"):
        seen_mounts = set()
        skip_fs = {
            "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
            "pstore", "squashfs", "overlay", "autofs", "mqueue", "hugetlbfs",
            "debugfs", "tracefs", "securityfs", "configfs", "fusectl", "binfmt_misc",
        }
        try:
            with open("/proc/mounts", encoding="utf-8") as fp:
                for line in fp:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    dev, mp, fstype = parts[0], parts[1], parts[2]
                    if fstype in skip_fs or mp in seen_mounts or dev.startswith("none"):
                        continue
                    seen_mounts.add(mp)
                    try:
                        usage = shutil.disk_usage(mp)
                        if usage.total > 0:
                            pct = round((usage.used / usage.total) * 100.0, 1)
                            disks.append({
                                "device": dev, "mountpoint": mp, "fstype": fstype,
                                "total_bytes": int(usage.total), "used_bytes": int(usage.used),
                                "available_bytes": int(usage.free), "use_percent": pct,
                            })
                    except OSError:
                        continue
        except Exception:
            pass
    if not disks:
        try:
            root_mp = "C:\\" if os.name == "nt" else "/"
            usage = shutil.disk_usage(root_mp)
            pct = round((usage.used / usage.total) * 100.0, 1) if usage.total > 0 else 0.0
            disks.append({
                "device": root_mp, "mountpoint": root_mp, "fstype": "root",
                "total_bytes": int(usage.total), "used_bytes": int(usage.used),
                "available_bytes": int(usage.free), "use_percent": pct,
            })
        except Exception:
            pass
    interfaces = []
    ipv6_by_iface = {}
    if os.path.isfile("/proc/net/if_inet6"):
        with contextlib.suppress(Exception):
            with open("/proc/net/if_inet6", encoding="utf-8") as fp:
                for line in fp:
                    parts = line.split()
                    if len(parts) >= 6:
                        addr6 = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(parts[0]))
                        plen = int(parts[2], 16)
                        ifname = parts[5]
                        ipv6_by_iface.setdefault(ifname, []).append(f"{addr6}/{plen}")
    if os.path.isdir("/sys/class/net"):
        try:
            for iface in sorted(os.listdir("/sys/class/net")):
                net_dir = f"/sys/class/net/{iface}"
                mac = ""
                state = "UNKNOWN"
                mtu = 1500
                with contextlib.suppress(OSError):
                    mac = open(f"{net_dir}/address", encoding="utf-8").read().strip()
                with contextlib.suppress(OSError):
                    state = open(f"{net_dir}/operstate", encoding="utf-8").read().strip().upper()
                with contextlib.suppress(OSError, ValueError):
                    mtu = int(open(f"{net_dir}/mtu", encoding="utf-8").read().strip())
                ipv4_list = []
                if fcntl is not None:
                    with contextlib.suppress(Exception):
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            ifreq = struct.pack("256s", iface.encode("utf-8")[:15])
                            ip_raw = fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24]
                            mask_raw = fcntl.ioctl(s.fileno(), 0x891B, ifreq)[20:24]
                            ip_str = socket.inet_ntoa(ip_raw)
                            plen4 = sum(bin(b).count("1") for b in mask_raw)
                            ipv4_list.append(f"{ip_str}/{plen4}")
                        finally:
                            s.close()
                interfaces.append({
                    "name": iface,
                    "mac": mac,
                    "ipv4": ipv4_list,
                    "ipv6": ipv6_by_iface.get(iface, []),
                    "state": "UP" if state in ("UP", "UNKNOWN") and iface == "lo" else state,
                    "mtu": mtu,
                })
        except Exception:
            pass
    return {
        "os_family": os_family,
        "distro": distro,
        "kernel": uname.release or "unknown",
        "arch": uname.machine or "unknown",
        "hostname": socket.gethostname() or uname.node or req.get("default_host", "localhost"),
        "uptime_seconds": uptime,
        "cpu_count": os.cpu_count() or 1,
        "memory_total_bytes": mem_total,
        "memory_available_bytes": mem_avail,
        "disks": disks,
        "interfaces": interfaces,
    }

def _op_checksum(req):
    p = req["path"]
    algo = req.get("algorithm", "sha256")
    h = hashlib.new(algo)
    with open(p, "rb") as fp:
        while chunk := fp.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()

def _handle_request(req):
    op = req.get("op", "call")
    if op == "ping":
        return {"pid": os.getpid(), "version": sys.version.split()[0]}
    if op == "facts":
        return _op_facts(req)
    if op == "glob":
        return _op_glob(req)
    if op == "checksum":
        return _op_checksum(req)
    if op == "call":
        source = req.get("source", "")
        func_name = req.get("func_name", "")
        is_expr = bool(req.get("is_expr", False))
        args = _decode_input(req.get("args") or [])
        kwargs = _decode_input(req.get("kwargs") or {})
        cwd = req.get("cwd")
        env = req.get("env")
        prev_cwd = os.getcwd()
        old_env = {}
        try:
            if cwd:
                os.chdir(cwd)
            if env:
                for k, v in env.items():
                    old_env[k] = os.environ.get(k)
                    os.environ[str(k)] = str(v)
            ns = dict(_BASE_NS)
            if is_expr:
                val = eval(source, ns, ns)
                res = val(*args, **kwargs) if callable(val) else val
            else:
                exec(compile(source, "<uniconn_run_python>", "exec"), ns, ns)
                target_fn = ns.get(func_name)
                if not callable(target_fn):
                    for v in reversed(list(ns.values())):
                        if callable(v) and v not in _BASE_NS.values():
                            target_fn = v
                            break
                if not callable(target_fn):
                    raise ValueError(f"Callable {func_name!r} not found in source")
                res = target_fn(*args, **kwargs)
            if inspect.iscoroutine(res):
                res = asyncio.run(res)
            return _normalize_value(res)
        finally:
            if cwd:
                with contextlib.suppress(OSError):
                    os.chdir(prev_cwd)
            if env:
                for k, prev_v in old_env.items():
                    if prev_v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = prev_v
    raise ValueError(f"Unsupported worker op: {op!r}")

_REAL_STDOUT.write(_READY + "\n")
_REAL_STDOUT.flush()

for raw_line in sys.stdin:
    line = raw_line.strip()
    if not line:
        continue
    req_id = 0
    buf = io.StringIO()
    try:
        req = json.loads(line)
        req_id = req.get("id", 0)
        if req.get("op") == "exit":
            break
        with contextlib.redirect_stdout(buf):
            result = _handle_request(req)
        resp = {"id": req_id, "ok": True, "result": result, "stdout": buf.getvalue()}
    except Exception as exc:
        resp = {
            "id": req_id,
            "ok": False,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "traceback": traceback.format_exc(),
            "stdout": buf.getvalue(),
        }
    _REAL_STDOUT.write(_PREFIX + json.dumps(resp, ensure_ascii=False) + "\n")
    _REAL_STDOUT.flush()
""".strip()


class _LambdaFinder(ast.NodeVisitor):
    """AST-визитор для извлечения узлов ``ast.Lambda`` из строки вызова."""

    def __init__(self) -> None:
        self.lambdas: list[ast.Lambda] = []

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.lambdas.append(node)
        self.generic_visit(node)


class CallableSerializer:
    """Сериализатор Python-функций, лямбда-выражений и строковых сниппетов."""

    @staticmethod
    def serialize(fn: Callable[..., Any] | str) -> tuple[str, str, bool]:
        """Преобразовать функцию, lambda или строку кода в кортеж ``(source, func_name, is_expr)``."""
        if isinstance(fn, str):
            cleaned = textwrap.dedent(fn).strip()
            if not cleaned:
                raise ValueError("Empty Python code passed to run_python()")
            try:
                tree = ast.parse(cleaned)
            except SyntaxError as exc:
                raise ValueError(f"Invalid Python syntax in run_python(): {exc}") from exc

            if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                return cleaned, "<expr>", True
            for node in tree.body:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    return cleaned, node.name, False
            return cleaned, "<snippet>", True

        if not callable(fn):
            raise TypeError(f"Expected a callable or source string for run_python(), got {type(fn).__name__}")

        code_obj = getattr(fn, "__code__", None)
        if code_obj is not None and code_obj in _SERIALIZED_CODE_CACHE:
            return _SERIALIZED_CODE_CACHE[code_obj]

        func_name = getattr(fn, "__name__", "<callable>")
        try:
            raw_source = inspect.getsource(fn)
        except (OSError, TypeError) as exc:
            raise ValueError(
                f"Cannot extract source code for {fn!r}. Define a regular function, lambda, "
                "or pass source code as a string."
            ) from exc

        dedented = textwrap.dedent(raw_source).strip()

        if func_name == "<lambda>":
            extracted_lambda = CallableSerializer._extract_lambda_source(dedented, code_obj)
            res = (extracted_lambda, "<lambda>", True)
            if code_obj is not None:
                _SERIALIZED_CODE_CACHE[code_obj] = res
            return res

        # Обычная функция def name(...):
        try:
            tree = ast.parse(dedented)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name == func_name:
                    # Очищаем декораторы, которых может не быть на удалённом хосте
                    node.decorator_list = []
                    clean_def = ast.unparse(node)
                    res = (clean_def, func_name, False)
                    if code_obj is not None:
                        _SERIALIZED_CODE_CACHE[code_obj] = res
                    return res
        except SyntaxError:
            pass

        res = (dedented, func_name, False)
        if code_obj is not None:
            _SERIALIZED_CODE_CACHE[code_obj] = res
        return res

    @staticmethod
    def _extract_lambda_source(source_text: str, code_obj: Any = None) -> str:
        """Извлечь чистое выражение ``lambda ...: ...`` из строки вызова."""
        for candidate in (source_text, source_text.strip().rstrip(",)")):
            with contextlib.suppress(SyntaxError):
                tree = ast.parse(candidate)
                finder = _LambdaFinder()
                finder.visit(tree)
                if finder.lambdas:
                    if len(finder.lambdas) == 1 or code_obj is None:
                        return ast.unparse(finder.lambdas[0])
                    arg_count = getattr(code_obj, "co_argcount", -1)
                    for lmb in finder.lambdas:
                        if len(lmb.args.args) == arg_count:
                            return ast.unparse(lmb)
                    return ast.unparse(finder.lambdas[0])

        # Резервный поиск подстроки lambda ...
        idx = source_text.find("lambda")
        if idx != -1:
            sub = source_text[idx:].strip()
            # Пробуем отсечь закрывающие скобки от внешнего вызова run_python(lambda: ...)
            for trim in range(len(sub), 6, -1):
                fragment = sub[:trim].rstrip(", ")
                with contextlib.suppress(SyntaxError):
                    tree = ast.parse(fragment, mode="eval")
                    if isinstance(tree.body, ast.Lambda):
                        return ast.unparse(tree.body)

        raise ValueError(f"Could not parse lambda expression from source: {source_text!r}")


def _encode_worker_value(val: Any) -> Any:
    """Сериализовать аргументы Python-вызова (bytes, PathLike, tuple, set) в JSON-совместимый вид."""
    if val is None or isinstance(val, bool | int | float | str):
        return val
    if isinstance(val, bytes | bytearray | memoryview):
        return {"__bytes_b64__": base64.b64encode(bytes(val)).decode("ascii")}
    if isinstance(val, os.PathLike):
        return os.fspath(val)
    if isinstance(val, list | tuple | set | frozenset):
        return [_encode_worker_value(x) for x in val]
    if isinstance(val, dict):
        return {str(k): _encode_worker_value(v) for k, v in val.items()}
    return val


def _decode_worker_value(val: Any) -> Any:
    """Декодировать специальные обёртки JSON-ответа воркера (например, бинарные данные)."""
    if isinstance(val, dict):
        if len(val) == 1 and "__bytes_b64__" in val:
            return base64.b64decode(val["__bytes_b64__"])
        return {k: _decode_worker_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_decode_worker_value(x) for x in val]
    return val


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

        # Если используется Cassette/Replay без записанных системных py_rpc эпизодов (facts/glob)
        cassette = getattr(tr, "cassette", None)
        if cassette is not None:
            has_sys_py_rpc = any(
                getattr(it, "kind", "") == "py_rpc"
                and getattr(it, "op", "") in ("facts", "glob", "checksum")
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
        interp = self._python_interpreter()
        return (
            f"{interp} -u -c "
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
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            line = raw_line.decode("utf-8", errors="replace").strip()
            if WORKER_READY_MARKER not in line:
                with contextlib.suppress(Exception):
                    proc.kill()
                    await proc.wait()
                self._unavailable = True
                return False
            self._local_proc = proc
            self._active = True
            return True
        except Exception:
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
            with contextlib.suppress(Exception):
                proc.close()
                await proc.wait_closed()
            return False
        except Exception:
            return False

    async def ensure_started(self, timeout: float | None = None) -> bool:
        """Гарантировать, что постоянный воркер запущен (возвращает True при успехе)."""
        if self.is_active:
            return True
        if self._unavailable:
            return False

        eff_timeout = timeout or self._conn.config.timeout or 10.0
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
        eff_timeout = timeout or self._conn.config.timeout or 30.0
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
                    return json.loads(json_part)

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
                        return json.loads(json_part)

        raise ExecutionError("Python worker pipe is not connected", host=self._conn.config.host)

    async def _execute_oneshot_via_run(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        *,
        sudo: bool = False,
    ) -> dict[str, Any]:
        """Выполнить RPC-запрос одноразовым вызовом ``python3 -u -c ...`` через ``conn.run``."""
        cmd = self._build_bootstrap_command()
        req_input = json.dumps(payload, ensure_ascii=False) + '\n{"id": 0, "op": "exit"}\n'
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
                return json.loads(json_part)

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
            payload: dict[str, Any] = {"id": self._req_id, "op": op, **params}

            if sudo:
                resp = await self._execute_oneshot_via_run(payload, timeout=timeout, sudo=True)
            else:
                started = await self.ensure_started(timeout=timeout)
                if started:
                    try:
                        resp = await self._send_over_pipe(payload, timeout=timeout)
                    except ExecutionError:
                        # Если воркер закрыл пайп во время простоя, пробуем перезапустить один раз
                        if await self.ensure_started(timeout=timeout):
                            resp = await self._send_over_pipe(payload, timeout=timeout)
                        elif allow_oneshot_fallback:
                            resp = await self._execute_oneshot_via_run(payload, timeout=timeout)
                        else:
                            raise
                elif allow_oneshot_fallback:
                    resp = await self._execute_oneshot_via_run(payload, timeout=timeout)
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
        """Выполнить Python-функцию, lambda или выражение в удалённом воркере."""
        effective_dry = self._conn.dry_run if dry_run is None else dry_run
        source, func_name, is_expr = CallableSerializer.serialize(fn)
        cmd_label = f"run_python:{func_name}"

        if effective_dry:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping {cmd_label} on {self._conn.config.uri_safe}"
            )
            return None

        cwd = self._conn.current_cwd
        env = self._conn.current_env
        encoded_args = _encode_worker_value(list(args))
        encoded_kwargs = _encode_worker_value(dict(kwargs))
        start_t = time.monotonic()

        # Интеграция с lifecycle-хуками Connection (before_run / after_run / on_error)
        hook_kwargs: dict[str, Any] = {
            "cwd": cwd,
            "env": env,
            "sudo": sudo,
            "args": args,
            "kwargs": kwargs,
        }
        for before_cb in self._conn.get_hooks("before_run"):
            res_cb = before_cb(cmd_label, self._conn.config.host, hook_kwargs)
            if inspect.isawaitable(res_cb):
                await res_cb

        try:
            result = await self.request(
                "call",
                timeout=timeout,
                sudo=sudo,
                source=source,
                func_name=func_name,
                is_expr=is_expr,
                args=encoded_args,
                kwargs=encoded_kwargs,
                cwd=cwd,
                env=env,
            )
        except Exception as exc:
            for err_cb in self._conn.get_hooks("on_error"):
                res_err = err_cb(exc, cmd_label, self._conn.config.host)
                if inspect.isawaitable(res_err):
                    await res_err
            raise

        duration = time.monotonic() - start_t
        after_hooks = self._conn.get_hooks("after_run")
        if after_hooks:
            synth_res = Result(
                exit_code=0,
                stdout=repr(result),
                stderr="",
                duration=duration,
                command=cmd_label,
                host=self._conn.config.host,
            )
            for after_cb in after_hooks:
                res_after = after_cb(synth_res)
                if inspect.isawaitable(res_after):
                    await res_after

        return result

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
        disks = [
            DiskInfo(
                device=d["device"],
                mountpoint=d["mountpoint"],
                fstype=d.get("fstype", ""),
                total_bytes=int(d.get("total_bytes", 0)),
                used_bytes=int(d.get("used_bytes", 0)),
                available_bytes=int(d.get("available_bytes", 0)),
                use_percent=float(d.get("use_percent", 0.0)),
            )
            for d in raw.get("disks", [])
        ]
        interfaces = [
            NetworkInterface(
                name=iface["name"],
                mac=iface.get("mac", ""),
                ipv4=list(iface.get("ipv4", [])),
                ipv6=list(iface.get("ipv6", [])),
                state=iface.get("state", "UNKNOWN"),
                mtu=int(iface.get("mtu", 1500)),
            )
            for iface in raw.get("interfaces", [])
        ]
        return HostFacts(
            os_family=raw.get("os_family", "Linux"),
            distro=raw.get("distro", "Linux"),
            kernel=raw.get("kernel", "unknown"),
            arch=raw.get("arch", "unknown"),
            hostname=raw.get("hostname", default_host),
            uptime_seconds=float(raw.get("uptime_seconds", 0.0)),
            cpu_count=int(raw.get("cpu_count", 1)),
            memory_total_bytes=int(raw.get("memory_total_bytes", 0)),
            memory_available_bytes=int(raw.get("memory_available_bytes", 0)),
            disks=disks,
            interfaces=interfaces,
        )

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
        """Сбросить аварийно завершённый процесс воркера."""
        self._active = False
        if self._local_proc is not None:
            proc = self._local_proc
            self._local_proc = None
            with contextlib.suppress(Exception):
                proc.kill()
                await proc.wait()
        if self._shell_proc is not None:
            sproc = self._shell_proc
            self._shell_proc = None
            with contextlib.suppress(Exception):
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
                with contextlib.suppress(Exception):
                    if self._local_proc.stdin is not None:
                        self._local_proc.stdin.write(b'{"id": 0, "op": "exit"}\n')
                        await self._local_proc.stdin.drain()
                        self._local_proc.stdin.close()
            if self._shell_proc is not None:
                with contextlib.suppress(Exception):
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
    "run_python",
]
