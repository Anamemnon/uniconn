# src/uniconn/transports/virtualization/pve_client.py
"""Асинхронный HTTP-клиент Proxmox VE REST API (PVEAPIToken, Ticket+CSRF, QGA и UPID-задачи)."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import sys
import time
from typing import Any
from urllib.parse import quote

from ...exceptions import (
    AuthenticationError,
    ConnectionError,
    ExecutionError,
    FileTransferError,
    TimeoutError,
)
from ..bmc.redfish.client import builtins_timeout_errors, resolve_lazy_response

try:
    import niquests
except ImportError:
    niquests = None  # type: ignore[assignment]


def get_pve_niquests_module() -> Any:
    """Получить модуль ``niquests`` с учётом возможного патчинга в тестах."""
    pve_mod = sys.modules.get("uniconn.transports.virtualization.pve")
    if pve_mod is not None and "niquests" in pve_mod.__dict__:
        return pve_mod.__dict__["niquests"]
    client_mod = sys.modules.get(__name__)
    if client_mod is not None and "niquests" in client_mod.__dict__:
        return client_mod.__dict__["niquests"]
    return niquests


class PveHttpClient:
    """Асинхронный клиент Proxmox VE REST API поверх ``niquests.AsyncSession``."""

    def __init__(
        self,
        *,
        base_url: str,
        vmid: int | str,
        node: str | None = None,
        username: str | None = None,
        realm: str = "pam",
        password: str | None = None,
        token_id: str | None = None,
        token_secret: str | None = None,
        verify: bool | str = True,
        default_timeout: float = 30.0,
        poll_interval: float = 0.2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.vmid = vmid
        self.node = node
        self.username = username
        self.realm = realm or "pam"
        self.password = password
        self.token_id = token_id
        self.token_secret = token_secret
        self.verify = verify
        self.default_timeout = default_timeout
        self.poll_interval = max(0.02, poll_interval)

        self.session: Any = None
        self.auth_mode: str = "none"
        self.ticket: str | None = None
        self.csrf_token: str | None = None

    @property
    def full_user(self) -> str:
        """Вернуть имя пользователя с ``@realm`` (например, ``root@pam``)."""
        user = self.username or "root"
        if "@" in user:
            return user
        return f"{user}@{self.realm}"

    def create_async_session(self) -> Any:
        """Создать и сконфигурировать ``niquests.AsyncSession``."""
        niq = get_pve_niquests_module()
        if niq is None:
            raise ImportError(
                "niquests not installed. Run: pip install uniconn[bmc] or uniconn[pve]"
            )
        session = niq.AsyncSession(base_url=self.base_url, multiplexed=False)
        session.verify = self.verify
        session.headers.update({"Accept": "application/json"})
        return session

    async def connect(self, timeout: float | None = None) -> None:
        """Инициализировать HTTP-сессию, выполнить аутентификацию и определить ноду ВМ."""
        eff_timeout = timeout if timeout is not None else self.default_timeout
        self.session = self.create_async_session()
        try:
            if self.token_id and self.token_secret:
                self.auth_mode = "token"
                auth_val = f"PVEAPIToken={self.full_user}!{self.token_id}={self.token_secret}"
                self.session.headers["Authorization"] = auth_val
            elif self.password is not None:
                self.auth_mode = "ticket"
                await self._authenticate_ticket(timeout=eff_timeout)
            else:
                raise AuthenticationError(
                    "Proxmox VE requires either token_id + secret or username + password"
                )

            if not self.node:
                self.node = await self.discover_vm_node(timeout=eff_timeout)
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Закрыть HTTP-сессию."""
        session = self.session
        self.session = None
        if session is not None:
            close_fn = getattr(session, "close", None)
            if callable(close_fn):
                res = close_fn()
                if asyncio.iscoroutine(res):
                    with contextlib.suppress(Exception):
                        await res

    async def _authenticate_ticket(self, timeout: float) -> None:
        """Получить ``ticket`` и ``CSRFPreventionToken`` через ``POST /api2/json/access/ticket``."""
        status, body = await self.request_json(
            "POST",
            "/api2/json/access/ticket",
            payload={"username": self.full_user, "password": self.password or ""},
            timeout=timeout,
            _retry_on_401=False,
        )
        data = body.get("data") if isinstance(body, dict) else None
        if status not in (200, 201) or not isinstance(data, dict) or not data.get("ticket"):
            raise AuthenticationError(
                f"Proxmox VE ticket authentication failed for {self.full_user} on {self.base_url} (HTTP {status})"
            )
        self.ticket = str(data["ticket"])
        self.csrf_token = str(data.get("CSRFPreventionToken") or "")
        self.session.headers["Cookie"] = f"PVEAuthCookie={self.ticket}"
        if self.csrf_token:
            self.session.headers["CSRFPreventionToken"] = self.csrf_token

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        timeout: float | None = None,
        _retry_on_401: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        """Выполнить HTTP-запрос к Proxmox VE REST API и вернуть ``(status_code, json_dict)``."""
        if self.session is None:
            raise ConnectionError("PVE HTTP session is not initialized")

        eff_timeout = timeout if timeout is not None else self.default_timeout
        norm_path = path if path.startswith("/") else f"/{path}"
        if params:
            query_parts = [f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in params.items()]
            sep = "&" if "?" in norm_path else "?"
            norm_path = f"{norm_path}{sep}{'&'.join(query_parts)}"

        method_upper = method.upper()
        try:
            req_fn = getattr(self.session, method_upper.lower())
            kwargs: dict[str, Any] = {"timeout": eff_timeout}
            if payload is not None:
                kwargs["json"] = payload
            resp = await req_fn(norm_path, **kwargs)
            await resolve_lazy_response(self.session, resp)
        except builtins_timeout_errors() as exc:
            raise TimeoutError(f"PVE {method_upper} {norm_path} timed out after {eff_timeout}s") from exc
        except Exception as exc:
            raise ConnectionError(f"PVE {method_upper} {norm_path} failed: {exc}") from exc

        status = int(getattr(resp, "status_code", 0) or 0)
        if status == 401 and _retry_on_401 and self.auth_mode == "ticket" and self.password is not None:
            await self._authenticate_ticket(timeout=eff_timeout)
            return await self.request_json(
                method,
                path,
                params=params,
                payload=payload,
                timeout=timeout,
                _retry_on_401=False,
            )

        if status in (401, 403):
            raise AuthenticationError(f"PVE {method_upper} {norm_path} unauthorized (HTTP {status})")

        data: dict[str, Any] = {}
        raw_text = getattr(resp, "text", "")
        if raw_text:
            try:
                parsed = resp.json()
                data = parsed if isinstance(parsed, dict) else {"data": parsed}
            except Exception:
                data = {"raw": str(raw_text)}
        else:
            with contextlib.suppress(Exception):
                parsed = resp.json()
                if isinstance(parsed, dict):
                    data = parsed

        return status, data

    async def discover_vm_node(self, timeout: float | None = None) -> str:
        """Автоматически определить имя ноды кластера Proxmox по ``vmid`` через ``/cluster/resources``."""
        status, body = await self.request_json(
            "GET",
            "/api2/json/cluster/resources",
            params={"type": "vm"},
            timeout=timeout,
        )
        if status != 200:
            raise ConnectionError(f"Failed to query Proxmox cluster resources (HTTP {status})")
        items = body.get("data")
        target_str = str(self.vmid)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and str(item.get("vmid")) == target_str and item.get("node"):
                    return str(item["node"])
        raise ConnectionError(
            f"VM {self.vmid!r} not found in Proxmox cluster resources. Specify ?node=<node_name> explicitly."
        )

    @property
    def _vm_base(self) -> str:
        """Базовый префикс эндпоинтов целевой QEMU ВМ."""
        if not self.node:
            raise ConnectionError("Proxmox node is not resolved")
        return f"/api2/json/nodes/{self.node}/qemu/{self.vmid}"

    async def agent_ping(self, timeout: float = 5.0) -> bool:
        """Проверить доступность QEMU Guest Agent через ``POST /agent/ping``."""
        try:
            status, _ = await self.request_json("POST", f"{self._vm_base}/agent/ping", timeout=timeout)
            return 200 <= status < 300
        except Exception:
            return False

    async def agent_get(self, endpoint: str, timeout: float = 5.0) -> Any:
        """Выполнить GET к эндпоинту агента (``get-osinfo``, ``network-get-interfaces`` и др.)."""
        status, body = await self.request_json(
            "GET",
            f"{self._vm_base}/agent/{endpoint.lstrip('/')}",
            timeout=timeout,
        )
        if status < 200 or status >= 300:
            raise ExecutionError(f"PVE agent/{endpoint} failed (HTTP {status})")
        data = body.get("data") if isinstance(body, dict) else None
        if isinstance(data, dict) and "result" in data:
            return data["result"]
        return data

    async def agent_exec(
        self,
        command_args: list[str],
        *,
        input_data: bytes | None = None,
        timeout: float = 60.0,
        is_windows: bool = False,
    ) -> tuple[int, str, str]:
        """Запустить команду через ``POST /agent/exec`` и опросить ``GET /agent/exec-status``."""
        payload: dict[str, Any] = {"command": list(command_args)}
        if input_data is not None:
            payload["input-data"] = input_data.decode("utf-8", errors="replace")

        status, body = await self.request_json(
            "POST",
            f"{self._vm_base}/agent/exec",
            payload=payload,
            timeout=min(timeout, 15.0),
        )
        data = body.get("data") if isinstance(body, dict) else None
        if status not in (200, 201) or not isinstance(data, dict) or "pid" not in data:
            err_msg = body.get("errors") or body.get("message") or f"HTTP {status}"
            raise ExecutionError(
                f"PVE agent/exec failed: {err_msg}",
                command=" ".join(command_args),
            )

        pid = int(data["pid"])
        deadline = time.monotonic() + timeout
        delay = self.poll_interval

        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    await self._kill_guest_pid(pid, is_windows=is_windows)
                    raise TimeoutError(
                        f"PVE agent/exec (pid={pid}) timed out after {timeout}s",
                        command=" ".join(command_args),
                    )
                st_code, st_body = await self.request_json(
                    "GET",
                    f"{self._vm_base}/agent/exec-status",
                    params={"pid": pid},
                    timeout=min(remaining, 10.0),
                )
                st_data = st_body.get("data") if isinstance(st_body, dict) else None
                if st_code == 200 and isinstance(st_data, dict) and int(st_data.get("exited", 0)) == 1:
                    sig = st_data.get("signal")
                    default_exit = (128 + int(sig)) if isinstance(sig, int) else (137 if sig else 0)
                    exit_code = int(st_data.get("exitcode", default_exit))
                    stdout = str(st_data.get("out-data") or "")
                    stderr = str(st_data.get("err-data") or "")
                    return exit_code, stdout, stderr

                await asyncio.sleep(min(delay, max(0.02, deadline - time.monotonic())))
                delay = min(0.5, delay * 1.3)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await self._kill_guest_pid(pid, is_windows=is_windows)
            raise

    async def _kill_guest_pid(self, pid: int, *, is_windows: bool = False) -> None:
        """Завершить зависший процесс внутри ВМ через ``POST /agent/exec``."""
        with contextlib.suppress(Exception):
            cmd = ["taskkill.exe", "/F", "/PID", str(pid)] if is_windows else ["/bin/kill", "-9", str(pid)]
            await self.request_json(
                "POST",
                f"{self._vm_base}/agent/exec",
                payload={"command": cmd},
                timeout=3.0,
            )

    async def agent_file_read(self, remote_path: str, timeout: float = 60.0) -> bytes:
        """Прочитать файл через ``GET /agent/file-read`` (при ``truncated=1`` возбуждает ``FileTransferError``)."""
        status, body = await self.request_json(
            "GET",
            f"{self._vm_base}/agent/file-read",
            params={"file": remote_path},
            timeout=timeout,
        )
        data = body.get("data") if isinstance(body, dict) else None
        if status != 200 or not isinstance(data, dict) or "content" not in data:
            raise FileTransferError(
                f"PVE agent/file-read failed for {remote_path!r} (HTTP {status})"
            )
        if data.get("truncated") in (1, True, "1"):
            raise FileTransferError(
                f"PVE agent/file-read response was truncated for {remote_path!r}"
            )
        raw_content = data.get("content", "")
        if data.get("encode") in (1, True):
            return base64.b64decode(str(raw_content))
        if isinstance(raw_content, bytes):
            return raw_content
        return str(raw_content).encode("utf-8")

    async def agent_file_write(self, remote_path: str, content: bytes, timeout: float = 60.0) -> None:
        """Записать байты в файл через ``POST /agent/file-write`` с ``encode=1`` (base64)."""
        b64_str = base64.b64encode(content).decode("ascii")
        status, body = await self.request_json(
            "POST",
            f"{self._vm_base}/agent/file-write",
            payload={"file": remote_path, "content": b64_str, "encode": 1},
            timeout=timeout,
        )
        if status not in (200, 201, 204):
            err_msg = body.get("errors") or body.get("message") or f"HTTP {status}"
            raise FileTransferError(
                f"PVE agent/file-write failed for {remote_path!r}: {err_msg}"
            )

    async def wait_for_upid(self, upid: str, timeout: float = 60.0) -> dict[str, Any]:
        """Ожидать завершения асинхронной задачи Proxmox VE (``UPID:...``)."""
        if not upid or not upid.startswith("UPID:"):
            return {"status": "stopped", "exitstatus": "OK", "upid": upid}

        encoded_upid = quote(upid, safe="")
        deadline = time.monotonic() + timeout
        delay = self.poll_interval
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Proxmox task {upid} timed out after {timeout}s")
            status, body = await self.request_json(
                "GET",
                f"/api2/json/nodes/{self.node}/tasks/{encoded_upid}/status",
                timeout=min(remaining, 10.0),
            )
            data = body.get("data") if isinstance(body, dict) else None
            if status == 200 and isinstance(data, dict) and data.get("status") == "stopped":
                exit_status = str(data.get("exitstatus") or "OK")
                if exit_status != "OK":
                    raise ExecutionError(f"Proxmox task {upid} failed with status: {exit_status}")
                return data
            await asyncio.sleep(min(delay, max(0.02, deadline - time.monotonic())))
            delay = min(0.5, delay * 1.3)

    async def vm_status(self, timeout: float = 10.0) -> dict[str, Any]:
        """Получить текущий статус ВМ (``GET /status/current``)."""
        status, body = await self.request_json(
            "GET",
            f"{self._vm_base}/status/current",
            timeout=timeout,
        )
        if status != 200 or not isinstance(body.get("data"), dict):
            raise ExecutionError(f"Failed to query VM {self.vmid} status (HTTP {status})")
        return body["data"]

    async def vm_power(self, action: str, *, wait: bool = True, timeout: float = 60.0) -> dict[str, Any]:
        """Выполнить действие питания ВМ (``start``, ``stop``, ``shutdown``, ``reboot``, ``reset`` и др.)."""
        norm_action = action.lower().strip()
        allowed = {"start", "stop", "shutdown", "reboot", "reset", "suspend", "resume"}
        if norm_action not in allowed:
            raise ExecutionError(f"Unsupported PVE power action {action!r}. Allowed: {sorted(allowed)}")

        status, body = await self.request_json(
            "POST",
            f"{self._vm_base}/status/{norm_action}",
            timeout=timeout,
        )
        if status not in (200, 201, 202):
            raise ExecutionError(f"PVE power {norm_action} failed (HTTP {status})")
        upid = str(body.get("data") or "")
        if wait and upid.startswith("UPID:"):
            task_info = await self.wait_for_upid(upid, timeout=timeout)
            return {"action": norm_action, "vmid": self.vmid, "upid": upid, "task": task_info}
        return {"action": norm_action, "vmid": self.vmid, "upid": upid}

    async def list_snapshots(self, timeout: float = 15.0) -> list[dict[str, Any]]:
        """Получить список снапшотов ВМ (``GET /snapshot``)."""
        status, body = await self.request_json(
            "GET",
            f"{self._vm_base}/snapshot",
            timeout=timeout,
        )
        if status != 200 or not isinstance(body.get("data"), list):
            raise ExecutionError(f"Failed to list snapshots for VM {self.vmid} (HTTP {status})")
        return [item for item in body["data"] if isinstance(item, dict)]

    async def create_snapshot(
        self,
        snapname: str,
        *,
        description: str = "",
        vmstate: bool = False,
        wait: bool = True,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Создать снапшот ВМ (``POST /snapshot``)."""
        payload: dict[str, Any] = {"snapname": snapname}
        if description:
            payload["description"] = description
        if vmstate:
            payload["vmstate"] = 1
        status, body = await self.request_json(
            "POST",
            f"{self._vm_base}/snapshot",
            payload=payload,
            timeout=timeout,
        )
        if status not in (200, 201, 202):
            raise ExecutionError(f"Failed to create snapshot {snapname!r} (HTTP {status})")
        upid = str(body.get("data") or "")
        if wait and upid.startswith("UPID:"):
            await self.wait_for_upid(upid, timeout=timeout)
        return {"snapshot": snapname, "action": "created", "upid": upid}

    async def rollback_snapshot(
        self,
        snapname: str,
        *,
        wait: bool = True,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Откатить ВМ к снапшоту (``POST /snapshot/{snapname}/rollback``)."""
        status, body = await self.request_json(
            "POST",
            f"{self._vm_base}/snapshot/{quote(snapname, safe='')}/rollback",
            timeout=timeout,
        )
        if status not in (200, 201, 202):
            raise ExecutionError(f"Failed to rollback snapshot {snapname!r} (HTTP {status})")
        upid = str(body.get("data") or "")
        if wait and upid.startswith("UPID:"):
            await self.wait_for_upid(upid, timeout=timeout)
        return {"snapshot": snapname, "action": "rolled_back", "upid": upid}

    async def delete_snapshot(
        self,
        snapname: str,
        *,
        wait: bool = True,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Удалить снапшот ВМ (``DELETE /snapshot/{snapname}``)."""
        status, body = await self.request_json(
            "DELETE",
            f"{self._vm_base}/snapshot/{quote(snapname, safe='')}",
            timeout=timeout,
        )
        if status not in (200, 201, 202):
            raise ExecutionError(f"Failed to delete snapshot {snapname!r} (HTTP {status})")
        upid = str(body.get("data") or "")
        if wait and upid.startswith("UPID:"):
            await self.wait_for_upid(upid, timeout=timeout)
        return {"snapshot": snapname, "action": "deleted", "upid": upid}


__all__ = ["PveHttpClient", "get_pve_niquests_module", "niquests"]
