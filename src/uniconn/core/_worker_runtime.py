# src/uniconn/core/_worker_runtime.py
"""Вспомогательные компоненты рантайма удалённого Python-воркера: bootstrap-скрипт, сериализация и факты."""

from __future__ import annotations

import ast
import base64
import builtins
import contextlib
import functools
import inspect
import os
import textwrap
import weakref
from collections.abc import Callable, Mapping
from typing import Any, cast

from ..services.facts_models import DiskInfo, HostFacts, NetworkInterface

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
            rel_str = p.relative_to(base_path).as_posix()
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
    is_win = os.name == "nt" or bool(req.get("force_windows", False))
    uname = platform.uname()
    os_family = "Windows" if is_win else (uname.system or "Linux")
    distro = f"Windows {uname.release}" if is_win else os_family
    os_rel = {}
    if not is_win and os.path.isfile("/etc/os-release"):
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
    if not is_win and os.path.isfile("/proc/uptime"):
        try:
            with open("/proc/uptime", encoding="utf-8") as fp:
                uptime = round(float(fp.read().split()[0]), 1)
        except Exception:
            pass
    mem_total = 0
    mem_avail = 0
    if not is_win and os.path.isfile("/proc/meminfo"):
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
    if not is_win and mem_total == 0 and hasattr(os, "sysconf"):
        with contextlib.suppress(Exception):
            ps = os.sysconf("SC_PAGE_SIZE")
            pp = os.sysconf("SC_PHYS_PAGES")
            if ps > 0 and pp > 0:
                mem_total = int(ps * pp)
                ap = os.sysconf("SC_AVPHYS_PAGES") if "SC_AVPHYS_PAGES" in os.sysconf_names else -1
                mem_avail = int(ps * ap) if ap > 0 else mem_total // 2
    if os_family == "Darwin":
        import subprocess
        if mem_total == 0:
            with contextlib.suppress(Exception):
                out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], timeout=2).decode().strip()
                if out.isdigit():
                    mem_total = int(out)
                    mem_avail = mem_total // 2
        if uptime == 0.0:
            with contextlib.suppress(Exception):
                out = subprocess.check_output(["sysctl", "-n", "kern.boottime"], timeout=2).decode()
                m = re.search(r"sec\s*=\s*(\d+)", out)
                if m:
                    uptime = round(max(0.0, time.time() - float(m.group(1))), 1)
    disks = []
    if is_win:
        with contextlib.suppress(Exception):
            import ctypes
            k32 = getattr(getattr(ctypes, "windll", None), "kernel32", None)
            if k32 is not None:
                try:
                    class _MEMSTAT(ctypes.Structure):
                        _fields_ = [
                            ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                        ]
                    ms = _MEMSTAT()
                    ms.dwLength = ctypes.sizeof(_MEMSTAT)
                    if k32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                        mem_total = int(ms.ullTotalPhys)
                        mem_avail = int(ms.ullAvailPhys)
                except Exception:
                    pass
                with contextlib.suppress(Exception):
                    uptime = round(k32.GetTickCount64() / 1000.0, 1)
                with contextlib.suppress(Exception):
                    drive_mask = k32.GetLogicalDrives()
                    fs_buf = ctypes.create_unicode_buffer(256)
                    for i in range(26):
                        if not (drive_mask & (1 << i)):
                            continue
                        letter = chr(65 + i)
                        root = f"{letter}:\\"
                        if k32.GetDriveTypeW(root) not in (2, 3, 4, 6):
                            continue
                        try:
                            total, used, free = shutil.disk_usage(root)
                            fstype = "NTFS"
                            if k32.GetVolumeInformationW(root, None, 0, None, None, None, fs_buf, 256):
                                fstype = fs_buf.value or "NTFS"
                            pct = round((used / total) * 100.0, 1) if total > 0 else 0.0
                            disks.append({
                                "device": f"{letter}:", "mountpoint": root, "fstype": fstype,
                                "total_bytes": int(total), "used_bytes": int(used),
                                "available_bytes": int(free), "use_percent": pct,
                            })
                        except OSError:
                            continue
    if not is_win and os.path.isfile("/proc/mounts"):
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
                        total, used, free = shutil.disk_usage(mp)
                        if total > 0:
                            pct = round((used / total) * 100.0, 1)
                            disks.append({
                                "device": dev, "mountpoint": mp, "fstype": fstype,
                                "total_bytes": int(total), "used_bytes": int(used),
                                "available_bytes": int(free), "use_percent": pct,
                            })
                    except OSError:
                        continue
        except Exception:
            pass
    if not disks:
        try:
            root_mp = "C:\\" if is_win else "/"
            total, used, free = shutil.disk_usage(root_mp)
            pct = round((used / total) * 100.0, 1) if total > 0 else 0.0
            disks.append({
                "device": "C:" if is_win else root_mp,
                "mountpoint": root_mp,
                "fstype": "NTFS" if is_win else "root",
                "total_bytes": int(total), "used_bytes": int(used),
                "available_bytes": int(free), "use_percent": pct,
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
    host_val = (
        (uname.node or socket.gethostname())
        if is_win
        else (socket.gethostname() or uname.node)
    ) or req.get("default_host", "localhost")
    return {
        "os_family": os_family,
        "distro": distro,
        "kernel": uname.release or ("Windows" if is_win else "unknown"),
        "arch": uname.machine or ("x86_64" if is_win else "unknown"),
        "hostname": host_val,
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

def _op_sync_scan(req):
    base = req.get("path", ".")
    mkdirs = req.get("mkdirs") or []
    want_checksum = bool(req.get("checksum", False))
    delete_paths = req.get("delete_paths") or []
    exclude_patterns = [p for p in (req.get("exclude") or []) if p]
    do_scan = bool(req.get("scan", True))
    exclude_re = None
    if exclude_patterns:
        exclude_re = re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in exclude_patterns))

    def _is_excl(rel_p, item_name):
        if exclude_re is None:
            return False
        if exclude_re.match(item_name) or exclude_re.match(rel_p):
            return True
        return any(exclude_re.match(part) for part in rel_p.split("/"))

    base_path = pathlib.Path(base)
    for rel_d in mkdirs:
        target_d = base_path / rel_d if rel_d else base_path
        target_d.mkdir(parents=True, exist_ok=True)
    deleted = []
    for rel_del in delete_paths:
        target_f = base_path / rel_del
        try:
            target_f.unlink()
            deleted.append(rel_del)
        except OSError:
            pass
    if not do_scan:
        return {"exists": base_path.exists(), "entries": {}, "deleted": deleted}
    if not base_path.exists():
        return {"exists": False, "entries": {}, "deleted": deleted}
    entries = {}
    for root, dirs, files in os.walk(base_path):
        rel_root_p = pathlib.Path(root).relative_to(base_path)
        rel_root = "" if str(rel_root_p) == "." else rel_root_p.as_posix()
        kept_dirs = []
        for d in dirs:
            d_rel = f"{rel_root}/{d}" if rel_root else d
            if _is_excl(d_rel, d):
                continue
            kept_dirs.append(d)
            full_d = pathlib.Path(root) / d
            try:
                st = full_d.stat()
                entries[d_rel] = {
                    "is_dir": True,
                    "size": 0,
                    "mtime": float(st.st_mtime),
                    "mode": int(stat.S_IMODE(st.st_mode)),
                }
            except OSError:
                continue
        dirs[:] = kept_dirs
        for fn in files:
            f_rel = f"{rel_root}/{fn}" if rel_root else fn
            if _is_excl(f_rel, fn):
                continue
            full_f = pathlib.Path(root) / fn
            try:
                is_link = full_f.is_symlink()
                st = full_f.lstat() if is_link else full_f.stat()
                item = {
                    "is_dir": False,
                    "size": int(st.st_size),
                    "mtime": float(st.st_mtime),
                    "mode": int(stat.S_IMODE(st.st_mode)),
                }
                if want_checksum and not is_link:
                    h = hashlib.sha256()
                    with open(full_f, "rb") as fp:
                        while chunk := fp.read(65536):
                            h.update(chunk)
                    item["sha256"] = h.hexdigest().lower()
                entries[f_rel] = item
            except OSError:
                continue
    return {"exists": True, "entries": entries, "deleted": deleted}

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
    if op == "sync_scan":
        return _op_sync_scan(req)
    if op == "call":
        source = req.get("source", "")
        func_name = req.get("func_name", "")
        is_expr = bool(req.get("is_expr", False))
        args = _decode_input(req.get("args") or [])
        kwargs = _decode_input(req.get("kwargs") or {})
        cwd = req.get("cwd")
        env = req.get("env")
        prev_cwd = os.getcwd()
        orig_env = os.environ.copy()
        try:
            if cwd:
                os.chdir(cwd)
            if env:
                for k, v in env.items():
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
            if os.environ != orig_env:
                os.environ.clear()
                os.environ.update(orig_env)
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
    """Сериализатор Python-функций, лямбда-выражений, замыканий и строковых сниппетов."""

    @classmethod
    def _is_simple_value(cls, val: Any) -> bool:
        if val is None or isinstance(val, bool | int | float | str | bytes):
            return True
        if isinstance(val, list | tuple | set | frozenset):
            return all(cls._is_simple_value(x) for x in val)
        if isinstance(val, dict):
            return all(cls._is_simple_value(k) and cls._is_simple_value(v) for k, v in val.items())
        return False

    @classmethod
    def _extract_closure_bindings(cls, fn: Any) -> dict[str, Any]:
        """Извлечь сериализуемые переменные замыкания (``__closure__``) и простые глобальные константы."""
        bindings: dict[str, Any] = {}
        code_obj = getattr(fn, "__code__", None)
        if code_obj is None:
            return bindings

        freevars = getattr(code_obj, "co_freevars", ())
        closure_cells = getattr(fn, "__closure__", None)
        if freevars and closure_cells:
            for name, cell in zip(freevars, closure_cells, strict=False):
                with contextlib.suppress(ValueError):
                    val = cell.cell_contents
                    if cls._is_simple_value(val):
                        bindings[name] = val

        fn_globals = getattr(fn, "__globals__", None)
        if isinstance(fn_globals, dict):
            for name in getattr(code_obj, "co_names", ()):
                if (
                    name not in bindings
                    and name in fn_globals
                    and not hasattr(builtins, name)
                    and name != getattr(fn, "__name__", "")
                ):
                    val = fn_globals[name]
                    if cls._is_simple_value(val):
                        bindings[name] = val
        return bindings

    @staticmethod
    def _serialize_partial(fn: functools.partial[Any]) -> tuple[str, str, bool]:
        """Сериализовать ``functools.partial`` в выражение или функцию-обёртку."""
        inner_src, inner_name, inner_is_expr = CallableSerializer.serialize(fn.func)
        if not fn.args and not fn.keywords:
            return inner_src, inner_name, inner_is_expr
        pos_args = [repr(a) for a in fn.args]
        pos_args.append("*_a")
        pos_str = ", ".join(pos_args)
        kw_str = f"**{{**{dict(fn.keywords)!r}, **_kw}}" if fn.keywords else "**_kw"
        call_args = f"{pos_str}, {kw_str}"
        if inner_is_expr:
            return f"(lambda *_a, **_kw: ({inner_src})({call_args}))", inner_name, True
        wrapper_name = f"_partial_{inner_name}"
        partial_src = f"{inner_src}\n\ndef {wrapper_name}(*_a, **_kw):\n    return {inner_name}({call_args})"
        return partial_src, wrapper_name, False

    @staticmethod
    def serialize(fn: Callable[..., Any] | str) -> tuple[str, str, bool]:
        """Преобразовать функцию, lambda, partial или строку кода в ``(source, func_name, is_expr)``."""
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

        if isinstance(fn, functools.partial):
            return CallableSerializer._serialize_partial(fn)

        if not callable(fn):
            raise TypeError(f"Expected a callable or source string for run_python(), got {type(fn).__name__}")

        closure_bindings = CallableSerializer._extract_closure_bindings(fn)
        code_obj = getattr(fn, "__code__", None)
        if not closure_bindings and code_obj is not None and code_obj in _SERIALIZED_CODE_CACHE:
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
            if closure_bindings:
                params_str = ", ".join(f"{k}={v!r}" for k, v in closure_bindings.items())
                extracted_lambda = f"(lambda {params_str}: ({extracted_lambda}))()"
            res = (extracted_lambda, "<lambda>", True)
            if not closure_bindings and code_obj is not None:
                _SERIALIZED_CODE_CACHE[code_obj] = res
            return res

        final_def = dedented
        with contextlib.suppress(SyntaxError):
            tree = ast.parse(dedented)
            for node in tree.body:
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == func_name:
                    node.decorator_list = []
                    final_def = ast.unparse(node)
                    break

        if closure_bindings:
            preamble = "\n".join(f"{k} = {v!r}" for k, v in closure_bindings.items())
            final_def = f"{preamble}\n\n{final_def}"
        res = (final_def, func_name, False)
        if not closure_bindings and code_obj is not None:
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

        idx = source_text.find("lambda")
        if idx != -1:
            sub = source_text[idx:].strip()
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


_LOCAL_OP_FACTS_FN: Callable[[dict[str, Any]], dict[str, Any]] | None = None


def raw_dict_to_host_facts(
    raw: Mapping[str, Any],
    default_host: str = "localhost",
) -> HostFacts:
    """Преобразовать сырой словарь фактов воркера ``_op_facts`` в типизированный ``HostFacts``."""
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


def collect_local_python_facts(
    default_host: str = "localhost",
    *,
    force_windows: bool = False,
) -> HostFacts:
    """Собрать ``HostFacts`` в текущем процессе Python через единую функцию ``_op_facts`` воркера."""
    global _LOCAL_OP_FACTS_FN
    if _LOCAL_OP_FACTS_FN is None:
        defs_only = WORKER_BOOTSTRAP_SCRIPT.split("_REAL_STDOUT.write(_READY", 1)[0]
        ns: dict[str, Any] = {}
        exec(compile(defs_only, "<uniconn_worker_facts>", "exec"), ns, ns)
        _LOCAL_OP_FACTS_FN = cast(
            Callable[[dict[str, Any]], dict[str, Any]],
            ns["_op_facts"],
        )
    raw = _LOCAL_OP_FACTS_FN(
        {"default_host": default_host, "force_windows": force_windows}
    )
    return raw_dict_to_host_facts(raw, default_host=default_host)
