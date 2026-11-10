# src/uniconn/mock/pve_server.py
"""Mock-сервер Proxmox VE REST API для детерминированного unit-тестирования pve://."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .qga_server import MockQgaServer


@dataclass
class MockPveResponse:
    """Имитация ответа ``niquests.Response`` для ``PveHttpClient``."""

    status_code: int
    payload: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)
    lazy: bool = False

    @property
    def text(self) -> str:
        """Текстовое представление JSON-ответа."""
        import json

        return json.dumps(self.payload)

    def json(self) -> dict[str, Any]:
        """Десериализованный словарь ответа."""
        return self.payload


class MockPveServer:
    """In-memory имитатор Proxmox VE REST API (Ticket/CSRF, API Token, Cluster, QGA, Power, Snapshots).

    Может передаваться напрямую в ``PveHttpClient`` через подмену ``session``
    или использоваться для создания настроенного ``PveHttpClient``.
    """

    def __init__(
        self,
        *,
        node: str = "pve-node1",
        vmid: int | str = 105,
        valid_user: str = "root@pam",
        valid_password: str = "secret-pass",
        valid_token_id: str = "uniconn",
        valid_token_secret: str = "token-secret-123",
        qga_backend: MockQgaServer | None = None,
    ) -> None:
        self.node = node
        self.vmid = str(vmid)
        self.valid_user = valid_user
        self.valid_password = valid_password
        self.valid_token_id = valid_token_id
        self.valid_token_secret = valid_token_secret
        self.qga = qga_backend or MockQgaServer(hostname=f"pve-vm-{vmid}")

        self.headers: dict[str, str] = {}
        self.verify: bool | str = True
        self.vm_state: str = "running"
        self.snapshots: list[dict[str, Any]] = [
            {"name": "initial", "description": "Initial clean state", "snaptime": 1700000000}
        ]
        self.tasks: dict[str, dict[str, Any]] = {}
        self._task_seq = 1
        self.requests_log: list[tuple[str, str, dict[str, Any] | None]] = []

    def _issue_upid(self, action_type: str) -> str:
        seq = self._task_seq
        self._task_seq += 1
        upid = f"UPID:{self.node}:0000{seq:04X}:00000000:65000000:{action_type}:{self.vmid}:{self.valid_user}:"
        self.tasks[upid] = {"status": "stopped", "exitstatus": "OK", "upid": upid}
        return upid

    def _check_auth(self, method: str, path: str) -> bool:
        if path.startswith("/api2/json/access/ticket"):
            return True
        auth_hdr = self.headers.get("Authorization", "")
        expected_token = f"PVEAPIToken={self.valid_user}!{self.valid_token_id}={self.valid_token_secret}"
        if auth_hdr == expected_token:
            return True
        cookie = self.headers.get("Cookie", "")
        if "PVEAuthCookie=PVE:MOCK_TICKET" in cookie:
            if method.upper() in ("POST", "PUT", "DELETE"):
                return self.headers.get("CSRFPreventionToken") == "MOCK_CSRF_TOKEN"
            return True
        return False

    async def _request(self, method: str, path: str, **kwargs: Any) -> MockPveResponse:
        json_body: dict[str, Any] | None = kwargs.get("json")
        self.requests_log.append((method.upper(), path, json_body))

        parsed = urlsplit(path)
        clean_path = parsed.path
        query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

        if clean_path == "/api2/json/access/ticket" and method.upper() == "POST":
            body = json_body or {}
            if body.get("username") == self.valid_user and body.get("password") == self.valid_password:
                return MockPveResponse(
                    200,
                    {
                        "data": {
                            "ticket": "PVE:MOCK_TICKET",
                            "CSRFPreventionToken": "MOCK_CSRF_TOKEN",
                            "username": self.valid_user,
                        }
                    },
                )
            return MockPveResponse(401, {"errors": "authentication failure"})

        if not self._check_auth(method, clean_path):
            return MockPveResponse(401, {"errors": "permission check failed"})

        if clean_path == "/api2/json/cluster/resources" and method.upper() == "GET":
            return MockPveResponse(
                200,
                {
                    "data": [
                        {
                            "id": f"qemu/{self.vmid}",
                            "type": "qemu",
                            "vmid": int(self.vmid) if self.vmid.isdigit() else self.vmid,
                            "node": self.node,
                            "status": self.vm_state,
                            "name": self.qga.hostname,
                        }
                    ]
                },
            )

        task_prefix = f"/api2/json/nodes/{self.node}/tasks/"
        if clean_path.startswith(task_prefix) and clean_path.endswith("/status"):
            raw_upid = unquote(clean_path[len(task_prefix) : -len("/status")])
            task_data = self.tasks.get(raw_upid, {"status": "stopped", "exitstatus": "OK"})
            return MockPveResponse(200, {"data": task_data})

        vm_prefix = f"/api2/json/nodes/{self.node}/qemu/{self.vmid}"
        if not clean_path.startswith(vm_prefix):
            return MockPveResponse(404, {"errors": f"No such resource {clean_path}"})

        sub_path = clean_path[len(vm_prefix) :]

        # --- Управление питанием и статусом ВМ ---
        if sub_path == "/status/current" and method.upper() == "GET":
            return MockPveResponse(
                200,
                {
                    "data": {
                        "vmid": int(self.vmid) if self.vmid.isdigit() else self.vmid,
                        "status": self.vm_state,
                        "name": self.qga.hostname,
                        "cpus": len(self.qga.vcpus),
                        "maxmem": 4294967296,
                        "qmpstatus": self.vm_state,
                    }
                },
            )

        if sub_path.startswith("/status/") and method.upper() == "POST":
            action = sub_path.split("/")[-1]
            if action in ("start", "resume", "reboot", "reset"):
                self.vm_state = "running"
            elif action in ("stop", "shutdown"):
                self.vm_state = "stopped"
            elif action == "suspend":
                self.vm_state = "paused"
            return MockPveResponse(200, {"data": self._issue_upid(f"qm{action}")})

        # --- Снапшоты ВМ ---
        if sub_path == "/snapshot" and method.upper() == "GET":
            return MockPveResponse(200, {"data": list(self.snapshots)})

        if sub_path == "/snapshot" and method.upper() == "POST":
            body = json_body or {}
            snapname = str(body.get("snapname") or "snap")
            self.snapshots.append(
                {
                    "name": snapname,
                    "description": str(body.get("description") or ""),
                    "vmstate": int(body.get("vmstate", 0)),
                }
            )
            return MockPveResponse(200, {"data": self._issue_upid("qmsnap")})

        if sub_path.startswith("/snapshot/") and sub_path.endswith("/rollback") and method.upper() == "POST":
            snapname = unquote(sub_path[len("/snapshot/") : -len("/rollback")])
            if not any(s.get("name") == snapname for s in self.snapshots):
                return MockPveResponse(404, {"errors": f"Snapshot {snapname} does not exist"})
            return MockPveResponse(200, {"data": self._issue_upid("qmrollback")})

        if sub_path.startswith("/snapshot/") and method.upper() == "DELETE":
            snapname = unquote(sub_path[len("/snapshot/") :])
            self.snapshots = [s for s in self.snapshots if s.get("name") != snapname]
            return MockPveResponse(200, {"data": self._issue_upid("qmdelsnap")})

        # --- Эндпоинты QEMU Guest Agent ---
        if sub_path == "/agent/ping" and method.upper() == "POST":
            return MockPveResponse(200, {"data": {"result": {}}})

        if sub_path == "/agent/get-osinfo" and method.upper() == "GET":
            return MockPveResponse(200, {"data": {"result": dict(self.qga.osinfo)}})

        if sub_path == "/agent/get-host-name" and method.upper() == "GET":
            return MockPveResponse(200, {"data": {"result": {"host-name": self.qga.hostname}}})

        if sub_path == "/agent/network-get-interfaces" and method.upper() == "GET":
            return MockPveResponse(200, {"data": {"result": list(self.qga.interfaces)}})

        if sub_path == "/agent/get-fsinfo" and method.upper() == "GET":
            return MockPveResponse(200, {"data": {"result": list(self.qga.fsinfo)}})

        if sub_path == "/agent/get-vcpus" and method.upper() == "GET":
            return MockPveResponse(200, {"data": {"result": list(self.qga.vcpus)}})

        if sub_path == "/agent/exec" and method.upper() == "POST":
            body = json_body or {}
            cmd_list = body.get("command")
            if not isinstance(cmd_list, list) or not cmd_list:
                return MockPveResponse(400, {"errors": "command must be a non-empty list"})
            exec_args: dict[str, Any] = {"path": cmd_list[0], "arg": cmd_list[1:]}
            if "input-data" in body and body["input-data"] is not None:
                raw_in = str(body["input-data"]).encode("utf-8")
                exec_args["input-data"] = base64.b64encode(raw_in).decode("ascii")
            rpc_res = self.qga._rpc_guest_exec(exec_args)
            return MockPveResponse(200, {"data": {"pid": rpc_res["pid"]}})

        if sub_path == "/agent/exec-status" and method.upper() == "GET":
            pid = int(query.get("pid", -1))
            st = self.qga._rpc_guest_exec_status({"pid": pid})
            if not st.get("exited"):
                return MockPveResponse(200, {"data": {"exited": 0}})
            out_str = base64.b64decode(st.get("out-data", "")).decode("utf-8", errors="replace")
            err_str = base64.b64decode(st.get("err-data", "")).decode("utf-8", errors="replace")
            return MockPveResponse(
                200,
                {
                    "data": {
                        "exited": 1,
                        "exitcode": st.get("exitcode", 0),
                        "out-data": out_str,
                        "err-data": err_str,
                    }
                },
            )

        if sub_path == "/agent/file-read" and method.upper() == "GET":
            file_path = query.get("file", "")
            if file_path not in self.qga.files:
                return MockPveResponse(500, {"errors": f"File not found: {file_path}"})
            raw_bytes = self.qga.files[file_path]
            truncated = 1 if getattr(self, "force_truncate_reads", False) else 0
            return MockPveResponse(
                200,
                {"data": {"content": raw_bytes.decode("utf-8", errors="replace"), "truncated": truncated}},
            )

        if sub_path == "/agent/file-write" and method.upper() == "POST":
            body = json_body or {}
            file_path = str(body.get("file") or "")
            content = str(body.get("content") or "")
            raw_bytes = (
                base64.b64decode(content)
                if body.get("encode") in (1, True, "1")
                else content.encode("utf-8")
            )
            self.qga.files[file_path] = raw_bytes
            self.qga.file_modes.setdefault(file_path, 0o644)
            return MockPveResponse(200, {"data": None})

        return MockPveResponse(501, {"errors": f"Method {method} on {sub_path} not implemented"})

    async def get(self, path: str, **kwargs: Any) -> MockPveResponse:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> MockPveResponse:
        return await self._request("POST", path, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> MockPveResponse:
        return await self._request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> MockPveResponse:
        return await self._request("DELETE", path, **kwargs)

    async def close(self) -> None:
        return None


__all__ = ["MockPveResponse", "MockPveServer"]
