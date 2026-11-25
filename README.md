# uniconn

**Unified Async/Sync Infrastructure Automation & Execution Engine for Python**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type Checker: Pyright](https://img.shields.io/badge/type%20checking-pyright-brightgreen.svg)](https://github.com/microsoft/pyright)
[![Tests Passing](https://img.shields.io/badge/tests-1%2C437%20passed-brightgreen.svg)](tests/)
[![Cold Import](https://img.shields.io/badge/import-~11ms-brightgreen.svg)](benchmarks/overhead_bench.py)
[![Poe Tasks](https://img.shields.io/badge/tasks-poethepoet-blueviolet.svg)](https://github.com/nat-n/poethepoet)

---

### Language: **[ English ]** &nbsp;|&nbsp; **[Русский](README.ru.md)** &nbsp;

**📚 Documentation:** **[Overview & Cheat Sheet](docs/index.rst)** · **[5-Min Quickstart](docs/quickstart.rst)** · **[Core Architecture & Pipeline](docs/architecture.rst)** · **[Inventory & URI Reference](docs/inventory_and_uris.rst)** · **[Cookbook Recipes](docs/cookbook.rst)** · **[Debugging & Troubleshooting](docs/troubleshooting.rst)** · **[Migration Guides](docs/migration.rst)** · **[CLI, MCP & Policy](docs/cli_and_mcp.rst)** · **[API Reference](docs/api.rst)**

---

`uniconn` eliminates infrastructure glue code by providing a single, resilient `Connection` facade and a built-in **MCP Server (`uniconn mcp`)** for command execution, file synchronization, idempotent state enforcement, DAG task orchestration, and hardware diagnostics across **SSH, WinRM, QEMU Guest Agent (QGA), Proxmox VE, NETCONF/RESTCONF/gNMI, Serial/UART, IPMI, Redfish BMC, Telnet, and Local systems** — with **100% Async + Sync parity**, **~11 ms lazy startup**, and zero boilerplate.

<p align="center">
  <img src="./docs/assets/terminal_demo.svg" alt="uniconn interactive terminal demo" width="100%" />
</p>

---

## ⚡ 5-Line Quick Start

### 🚀 Asynchronous (`Connection`)

Execute commands, parse structured output, write configs atomically, and enforce service states with `sudo`:

```python
from uniconn import Connection

async with Connection.from_uri("ssh://admin:env://SSH_PASS@node-01") as conn:
    disks = (await conn.run("df -h", parse="auto")).parsed
    await conn.files.write_file("/etc/app.conf", "port = 8080\n", atomic=True)
    await conn.state.ensure_service("nginx", state="started", enabled=True, sudo=True)
```

### ⏱️ Synchronous (`SyncConnection`)

Zero `asyncio.run()` boilerplate for scripts, CLI utilities, and sync frameworks:

```python
from uniconn import SyncConnection

with SyncConnection.from_uri("local://") as conn:
    print(conn.run(["uname", "-s"]).text)
    print("OS:", conn.gather_facts().os_family)
```

---

## 💡 Why uniconn?

Modern infrastructure is fundamentally heterogeneous: Linux servers run alongside Windows nodes, KVM/Proxmox virtual machines rely on guest-agent channels, routers expose NETCONF/RESTCONF/gNMI APIs, and bare-metal servers require BMC out-of-band management or serial bootloader flashing.

Traditionally, teams maintain a fragmented stack: `AsyncSSH` or `Paramiko` for SSH, `pywinrm` for Windows, `ncclient` or `Scrapli` for network devices, `Pyinfra` or `Ansible` for provisioning, `pyserial` for serial devices, and `Testinfra` for assertions.

`uniconn` unifies all of these into a **single, lightweight, sub-millisecond execution engine** with PEP 562 lazy loading (~11 ms cold import):

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                       USER APPLICATION / CLI / MCP SERVER (AI)                         │
│       Async API: Connection / ConnectionPool / Flow / ShellSession / MCPServer         │
│       Sync API:  SyncConnection / SyncConnectionPool / SyncFlow (via EventLoopPortal)  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                  ┌─────────────────────────▼──────────────────────────┐
                  │               DOMAIN SERVICES LAYER                │
                  │  • conn.files / conn.path (SFTP, Delta Sync, Hash) │
                  │  • conn.state (Idempotent ensure_*, Diff, Notify)  │
                  │  • conn.net (NETCONF, RESTCONF, gNMI, YANG diffs)  │
                  │  • conn.gather_facts / diff_facts / diagnostics    │
                  │  • conn.run_python (Persistent Zero-Fork RPC)      │
                  └─────────────────────────┬──────────────────────────┘
                                            │
                  ┌─────────────────────────▼──────────────────────────┐
                  │            RESILIENCE & MIDDLEWARE PIPELINE        │
                  │  [Context] ──► [Policy/AST] ──► [HITL] ──► [Sudo]  │
                  │  ──► [Hooks/OTel] ──► [DryRun] ──► [CircuitBreaker]│
                  │  ──► [RateLimiter] ──► [Retry] ──► [Cassettes]     │
                  └─────────────────────────┬──────────────────────────┘
                                            │
┌───────────────────────────────────────────▼────────────────────────────────────────────┐
│                        PLUGGABLE TRANSPORT LAYER (ISP PROTOCOLS)                       │
├───────────┬───────────┬───────────┬────────────┬───────────┬────────────┬──────────────┤
│  ssh://   │  winrm:// │  qga://   │ netconf:// │  uart://  │ redfish:// │  replay://   │
│  telnet://│  wsman:// │  pve://   │ restconf://│  serial://│   ipmi://  │  local://    │
│           │           │ qemu-ga://│   gnmi://  │           │            │              │
└───────────┴───────────┴───────────┴────────────┴───────────┴────────────┴──────────────┘
```

### 📊 Competitive Comparison Matrix

| Feature | `uniconn` | `Ansible` | `Fabric` | `Pyinfra` | `Nornir` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Core Paradigm** | **Python SDK** | YAML Playbooks | CLI Runner | Python Deploy | Network SDK |
| **Async + Sync Parity** | **✅ 100%** | ❌ Process | ❌ Sync only | ❌ Threads | ⚠️ Scrapli only |
| **13+ Transports** | **✅ Unified** | ⚠️ Plugins | ❌ SSH only | ⚠️ Linux/SSH | ❌ Network CLI |
| **Idempotent State (`ensure_*`)** | **✅ Built-in** | ✅ YAML | ❌ None | ✅ Python ops | ❌ None |
| **DAG Orchestration (`@task`)** | **✅ Built-in** | ✅ Playbooks | ❌ None | ⚠️ Linear | ⚠️ Runners |
| **Zero-Fork RPC (`run_python`)** | **✅ < 2 ms** | ⚠️ Mitogen plugin | ❌ None | ⚠️ Connector | ❌ None |
| **Structured Output Parsing** | **✅ `auto`** | ⚠️ Filters | ❌ None | ❌ None | ✅ TextFSM |
| **Hardware BMC & UART** | **✅ Out-of-box** | ⚠️ Roles | ❌ None | ❌ None | ⚠️ Serial only |
| **Offline Testing (Cassettes)** | **✅ Built-in** | ❌ None | ❌ None | ❌ None | ❌ None |
| **MCP Server for AI Agents** | **✅ Built-in** | ❌ None | ❌ None | ❌ None | ❌ None |
| **Resilience (CircuitBreaker)** | **✅ Built-in** | ⚠️ `max_fail` | ❌ None | ❌ None | ❌ None |
| **Cold Import Startup** | **⚡ ~11 ms** | ~ 400–900 ms | ~ 80–150 ms | ~ 150–300 ms | ~ 100–200 ms |
| **Task Overhead** | **⚡ < 0.3 ms** | ~ 500–2000 ms | ~ 3–8 ms | ~ 5–15 ms | ~ 1–5 ms |

> 💡 *Note: Testinfra assertions and Scrapli network drivers integrate seamlessly with uniconn via its pluggable transport layer and pytest plugin.*

---

## 📦 Installation

Lightweight core installation (includes SSH/SFTP, Local, QGA, Replay transport, resilient pipeline, and structured logging — with ~11 ms lazy startup):

```bash
# Using uv (recommended):
uv add uniconn

# Using pip:
pip install uniconn
```

### Optional Extras

Install all optional transports, network/virtualization drivers, BMC controllers, serial modems, security guardrails, and the CLI in one shot:

```bash
uv add "uniconn[all]"
```

Or pick only what you need:

| Extra | Command | Description |
| :--- | :--- | :--- |
| **CLI** | `uv add "uniconn[cli]"` | Rich terminal CLI (`cyclopts`, `rich`) |
| **WinRM** | `uv add "uniconn[winrm]"` | Windows Remote Management (`pywinrm`) |
| **BMC** | `uv add "uniconn[bmc]"` | IPMI (`pyghmi`) and Redfish HTTP/2 (`niquests`) |
| **Proxmox VE** | `uv add "uniconn[pve]"` | Proxmox VE API & QEMU Guest Agent (`niquests`) |
| **NETCONF** | `uv add "uniconn[netconf]"` | NETCONF over SSH (`asyncssh`) |
| **RESTCONF** | `uv add "uniconn[restconf]"` | RESTCONF HTTP/2 client (`niquests`) |
| **gNMI** | `uv add "uniconn[gnmi]"` | gNMI HTTP/2 telemetry & config (`niquests`) |
| **Serial** | `uv add "uniconn[serial]"` | Serial/UART console (`pyserial-asyncio`) & X/Y/ZMODEM |
| **Telnet** | `uv add "uniconn[telnet]"` | Telnet transport (`telnetlib3`) |
| **Templates** | `uv add "uniconn[templates]"` | Jinja2 templating engine for `write_template()` |
| **Parsing** | `uv add "uniconn[parsing]"` | Semantic parsers (`jc`, `ttp`, `textfsm`, `ntc-templates`) |
| **Telemetry** | `uv add "uniconn[otel]"` | OpenTelemetry distributed tracing hooks |
| **Security** | `uv add "uniconn[security]"` | Tree-sitter Bash AST parsing for Policy-as-Code (`tree-sitter`, `tree-sitter-bash`) |
| **MCP HTTP** | `uv add "uniconn[mcp-http]"` | HTTP/SSE MCP server transport with JWT auth (`starlette`, `uvicorn`, `pyjwt`, `cryptography`) |

---

## 🌐 Supported Transports & URI Syntax

Every transport is represented via a standardized, human-readable URI with automatic secret resolution:

| Transport | URI Scheme | Real-World Example |
| :--- | :--- | :--- |
| **SSH** | `ssh://` | `ssh://admin:env://SSH_PASS@node-01:22?key_file=/path/id_ed25519&proxy=bastion&keepalive=30` |
| **NETCONF** | `netconf://` | `netconf://admin:env://NET_PASS@router-01:830?vendor=junos&version=1.1` |
| **RESTCONF** | `restconf://` | `restconf://admin:env://NET_PASS@router-01/restconf?verify_tls=false&format=json` |
| **gNMI** | `gnmi://` | `gnmi://admin:env://NET_PASS@spine-01:9339?encoding=json_ietf&origin=openconfig` |
| **Windows Remote** | `winrm://`, `wsman://` | `winrm://Administrator:env://WIN_PASS@win-server:5986?ssl=true&shell=ps&transport=ntlm` |
| **QEMU Guest Agent** | `qga://`, `qemu-ga://` | `qga://root@kvm-host-01/vm-prod-01?backend=virsh` or `qga:///var/run/qemu/vm1.sock` |
| **Proxmox VE** | `pve://` | `pve://root@pam!uniconn:env://PVE_SECRET@pve-host:8006/105?node=pve1&verify_ssl=false` |
| **Redfish BMC** | `redfish://` | `redfish://admin:env://BMC_PASS@bmc.local?verify_ssl=false&system_id=1` |
| **IPMI BMC** | `ipmi://` | `ipmi://admin:password@bmc.local:623` (`power status`, `sensors`, `boot device`) |
| **Serial / UART** | `serial://`, `uart://` | `uart:///dev/ttyUSB0:115200?parity=N&stopbits=1` or `uart://COM3?vid=10c4&pid=ea60` |
| **Telnet** | `telnet://` | `telnet://admin:pass@switch.local:23?term_type=vt100` |
| **Replay (Cassette)** | `replay://` | `replay://node-01?cassette=tests/cassettes/node.yaml&mode=none` |
| **Local** | `local://` | `local://?timeout=30&rate_limit=50` (or `Connection.local()`) |

> 🔒 **Dynamic Secret Resolution**: Passwords, sudo tokens, and key paths support `env://VAR_NAME[?default=fallback]` and `file:///path/to/secret[?default=fallback]`. Missing secrets without defaults raise `ConfigurationError` before any network connection is attempted.

---

## 🛠️ Production Recipes & Advanced Examples

### 1. Declarative DAG Task Orchestration (`uniconn.orchestration`)

Build dependency graphs with prerequisites (`depends_on`), cleanup post-actions (`post`), condition guards (`when`), and wave-synchronized execution (`mode="barrier"`) across a fleet:

```python
from uniconn import Connection, ConnectionPool
from uniconn.orchestration import Flow, FlowContext, task

@task(name="check_environment", tags=["preflight"])
async def check_environment(conn: Connection, ctx: FlowContext):
    facts = await conn.gather_facts()
    ctx.host_set(conn, "os_family", facts.os_family)
    return await conn.run("uname -a")

@task(name="cleanup_artifacts", always_run=True)
async def cleanup_artifacts(conn: Connection):
    await conn.files.remove_file("/tmp/release.tar.gz")

@task(
    name="deploy_application",
    depends_on=[check_environment],
    post=[cleanup_artifacts],
    when=lambda conn, ctx: ctx.host_get(conn, "os_family") == "Linux",
    retries=2,
    retry_delay=1.0,
)
async def deploy_application(conn: Connection):
    return await conn.state.ensure_file(
        "/etc/app.conf",
        content="PORT=8080\nWORKERS=4\n",
        mode=0o644,
        atomic=True,
        notify=("reload_app", lambda c: c.state.ensure_service("app", state="reloaded", sudo=True)),
    )

# Orchestrate rollout across nodes with wave synchronization and deduplicated service reloads
flow = Flow(
    name="production_release",
    tasks=[deploy_application],  # Transitively pulls in check_environment and cleanup_artifacts
    mode="barrier",              # All nodes pass each task wave before advancing to the next
    batch_size=2,                # Roll out 2 nodes at a time
    max_fail_ratio=0.0,          # Abort immediately if any batch fails
    batch_notifications=True,    # Execute 'reload_app' only ONCE per host at the end of the flow
)

async with ConnectionPool.from_file("fleet.yaml", group="prod") as pool:
    report = await pool.run_flow(flow, vars={"release": "v2.5.0"})
    report.raise_for_status()
```

---

### 2. Persistent Zero-Fork Remote Python RPC (`conn.run_python`)

Execute arbitrary Python callables directly inside a persistent background Python worker over a bidirectional pipe (Mitogen-style). Eliminates SSH shell overhead, file upload latency, and process fork penalties:

```python
import os
from uniconn import Connection

async with Connection.from_uri("ssh://admin@remote-node") as conn:
    # 1. Execute an inline lambda directly on the remote host (< 2ms round-trip)
    kernel_release = await conn.run_python(lambda: os.uname().release)
    print("Remote Kernel:", kernel_release)

    # 2. Execute parameterized functions with remote library imports
    def inspect_system(threshold_pct: float) -> dict:
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        return {
            "cpu_percent": cpu_usage,
            "is_stressed": cpu_usage > threshold_pct,
            "memory_free_gb": psutil.virtual_memory().available / (1024 ** 3),
        }

    stats = await conn.run_python(inspect_system, 85.0, sudo=False, timeout=15.0)
    print("Health report:", stats["cpu_percent"], stats["is_stressed"])
```

---

### 3. Bare-Metal Redfish BMC & Hardware Telemetry

Manage rack servers directly out-of-band using DMTF Redfish HTTP/2 (powered by `niquests`) and IPMI protocols:

```python
from uniconn import Connection

# 1. Redfish BMC: Query sensors, health states, and manage power
async with Connection.from_uri("redfish://admin:env://BMC_PASS@192.168.1.100?verify_ssl=false") as bmc:
    power_res = await bmc.run("power status")
    print("Server Power:", power_res.text)  # "On"

    # Query hardware inventory and chassis thermal telemetry
    thermal = await bmc.run("sensors")
    print(thermal.text)

    # Power cycle bare-metal host
    await bmc.run("power cycle")

# 2. IPMI BMC: Direct netfn raw commands and boot order manipulation
async with Connection.from_uri("ipmi://admin:env://IPMI_PASS@192.168.1.100:623") as ipmi:
    # Set one-time PXE network boot for automated bare-metal provisioning
    await ipmi.run("boot pxe once")
    await ipmi.run("power reset")
```

---

### 4. Serial / UART Controls & Bootloader Flashing (X/Y/ZMODEM)

Direct hardware communication for embedded boards, network switches, and IoT microcontrollers:

```python
from uniconn import Connection

async with Connection.from_uri("uart:///dev/ttyUSB0:115200?parity=N&stopbits=1") as board:
    # 1. Trigger hardware reset via DTR/RTS pin pulsing
    await board.transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.1)

    # 2. Send serial BREAK signal to interrupt boot sequence and enter U-Boot / ROMMON
    board.transport.send_break(duration=0.25)

    # 3. Flash firmware directly into memory over YMODEM protocol
    bytes_sent = await board.files.upload_ymodem(
        "build/u-boot-custom.bin",
        trigger_command="loady 0x82000000\r",
        progress_callback=lambda current, total: print(f"Flashing: {current}/{total} bytes"),
    )
    print(f"Firmware flashed: {bytes_sent} bytes transferred")

    # 4. Stream serial console output in real time
    async for line in board.stream():
        print("[UART]:", line)
        if "Kernel panic" in line:
            break
```

---

### 5. Stateful PTY Shell Sessions & Automated Expect Dialogs

Maintain state across multiple commands in a real pseudoterminal (preserving `cd` and `export`) and automate interactive terminal prompts:

```python
from uniconn import Connection

async with Connection.from_uri("ssh://admin@node-01") as conn:
    # 1. Stateful PTY Shell: Environment variables and directory persist across executions
    async with await conn.open_shell(term_type="xterm-256color", term_size=(120, 40)) as shell:
        await shell.execute("cd /var/log/nginx && export LOG_LEVEL=debug")
        res = await shell.execute("pwd && echo $LOG_LEVEL")
        assert "/var/log/nginx" in res.text
        assert "debug" in res.text

    # 2. Declarative Expect: Automate prompts with password masking
    await conn.expect(
        "passwd deployer",
        patterns={
            r"New password:": "SecureP@ssw0rd!123",
            r"Retype new password:": "SecureP@ssw0rd!123",
        },
        final_prompt=r"password updated successfully",
        sensitive=True,  # Automatically redacts passwords from audit logs, traces, and exceptions
    )
```

---

### 6. Fleet Orchestration & Canary Rollouts (`ConnectionPool`)

Deploy across hundreds of nodes with built-in concurrency limits, circuit breakers, and automatic rollout abortion on failure:

```python
import asyncio
from uniconn import ConnectionPool, BatchAbortedError

async def deploy_fleet():
    hosts = ["ssh://admin@web-01", "ssh://admin@web-02", "ssh://admin@web-03", "ssh://admin@web-04"]

    async with ConnectionPool(hosts, max_concurrent=10, batch_size=2, max_fail_ratio=0.0) as pool:
        # 1. Canary check on subset (reuses persistent connections)
        canary = pool.select(["web-01"])
        assert (await canary.ping()).all_alive

        # 2. Wave rollout with zero-tolerance failure guard (raises BatchAbortedError)
        try:
            await pool.files.sync_dir("./dist", "/var/www/app", delete=True)
            await pool.state.ensure_service("nginx", state="restarted", sudo=True)
        except BatchAbortedError as err:
            print(f"Rollout halted at batch {err.batch_index}: {err}")

        # 3. Detect drift across cluster facts
        drift = await pool.diff_facts()
        if drift.has_drift:
            print("Configuration drift detected:", drift.mismatches)

asyncio.run(deploy_fleet())
```

---

### 7. Object-Oriented Remote Filesystem (`conn.path` & `conn.files`)

Work with remote files using a `pathlib.Path`-compatible API with zero round-trip overhead:

```python
# Pathlib-style directory traversal
log_dir = conn.path("/var/log/nginx")
if await log_dir.exists():
    async for log_file in log_dir.glob("*.log"):
        st = await log_file.stat()  # Zero extra network trips (preloaded during glob)
        print(log_file.name, st.st_size)

# High-performance delta directory sync (rsync alternative)
sync_res = await conn.files.sync_dir(
    "./build",
    "/var/www/app",
    delete=True,
    checksum_check=True,
    exclude=["*.pyc", ".git"],
)
```

---

### 8. Deterministic Offline Testing (`use_cassette` & Pytest Plugin)

Record real infrastructure interactions (commands, SFTP, streams, PTY shells) into clean YAML cassettes with automatic secret redaction, and replay them in CI without network access:

```python
import pytest
from uniconn import Connection

# In your test suite:
@pytest.mark.uniconn_cassette(mode="once")
async def test_server_provisioning():
    # Automatically wrapped in ReplayTransport when cassette exists
    async with Connection.from_uri("ssh://admin@production-host") as conn:
        res = await conn.run("hostname")
        assert res.ok
        assert res.text == "prod-web-01"
```

---

### 9. Official MCP Server for AI Agents (`uniconn mcp`)

Expose your infrastructure inventory safely to AI agents and IDEs (**Claude Desktop, Cursor, Windsurf, Cline**) over the **Model Context Protocol (MCP, JSON-RPC 2.0 over `stdio` or HTTP/SSE with JWT via `uniconn[mcp-http]`)** with zero external MCP SDK dependencies.

By default, `uniconn mcp` runs in **Safe Mode**:

- File modification (`uniconn_write_file`) and privileged execution (`sudo=True`) are disabled by default.
- Destructive commands (`rm -rf /`, `mkfs`, `shutdown`, etc.) are blocked via `blocklist_hook`, with optional Tree-sitter AST Policy-as-Code (`uniconn[security]`) and Human-in-the-Loop (HITL) approvals.
- Credentials, tokens, and `SecretResolver` references (`env://`, `file://`) are automatically redacted in URIs (`mask_uri_secrets`) and outputs (`SecretMaskingFilter`).
- Multi-host operations (`uniconn_ping`, `uniconn_diff_facts`, `uniconn_checksum`) run concurrently via `asyncio.gather` with per-host error isolation.

```bash
# Start MCP server over JSON-RPC 2.0 stdio in safe read-only mode
uvx --from "uniconn[cli]" uniconn mcp --inventory hosts.yaml

# Start with command allowlist, file write access, and JSONL audit log
uniconn mcp --inventory hosts.yaml --group web --allow-write --allowlist "df,uptime,systemctl status" --audit-log ./mcp-audit.jsonl

# Generate ready-to-paste mcpServers JSON config for Claude Desktop / Cursor
uniconn mcp --inventory hosts.yaml --group web --max-read-bytes 131072 --print-config
```

Example `mcp.json` / `claude_desktop_config.json` configuration:

```json
{
  "mcpServers": {
    "uniconn": {
      "command": "uvx",
      "args": [
        "--from",
        "uniconn[cli]",
        "uniconn",
        "mcp",
        "--inventory",
        "/etc/uniconn/hosts.yaml",
        "--audit-log",
        "/var/log/uniconn-mcp-audit.jsonl"
      ]
    }
  }
}
```

#### Exposed MCP Tools & Resources

| Tool / Resource | Description | Security Guardrail |
| :--- | :--- | :--- |
| `uniconn_list_hosts` | List registered hosts, groups, transport schemes, and active security policy. | Read-only (secrets masked) |
| `uniconn_ping` | Concurrent connectivity check and RTT measurement across target hosts. | Read-only (per-host fault isolation) |
| `uniconn_run` | Execute a command with automatic semantic output parsing (`parse="auto"`). | `blocklist_hook` / `allowlist_hook`; `sudo` requires `--allow-sudo` |
| `uniconn_gather_facts` | Collect structured `HostFacts` (OS, kernel, CPU, RAM, disks, network, uptime). | Read-only |
| `uniconn_diff_facts` | Concurrently collect and compare facts across hosts/groups for drift detection (`has_drift`). | Read-only |
| `uniconn_read_file` | Read UTF-8 file content with size truncation (`max_bytes`) and secret masking. | Read-only (capped by `--max-read-bytes`) |
| `uniconn_stat_path` | Inspect path existence, size, permissions, and modification time. | Read-only |
| `uniconn_checksum` | Concurrently compute file digest (`sha256`, `sha1`, `md5`) across hosts. | Read-only |
| `uniconn_write_file` | Write text content to a remote file (atomically by default `atomic=True`). | **Requires `--allow-write`** |
| `uniconn_evaluate_policy` | Dry-run AST command decomposition and Policy-as-Code evaluation (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`). | Read-only (no execution) |
| `uniconn_propose_action` | Evaluate risk tier (`SAFE`/`MUTATING`/`DESTRUCTIVE`/`FORBIDDEN`) and open an HITL approval request. | Two-phase HITL approval |
| `uniconn_check_approval` | Inspect the status of a specific `approval_id` or list active HITL approval requests. | Read-only |
| `uniconn_wait_approval` | Asynchronously wait for a human operator to approve or reject a pending `approval_id`. | Read-only (bounded timeout) |
| `uniconn_list_flows` | List registered declarative DAG orchestration Flows exported to MCP with risk assessments. | Read-only |
| `uniconn_inspect_flow` | Inspect a Flow's ASCII DAG plan, topological waves, parameter schema, and HITL risk. | Read-only |
| `uniconn_run_flow` | Execute a registered DAG Flow across hosts/groups with HITL approval and checkpointing. | Policy + HITL approval |
| `uniconn_resume_flow` | Resume a failed Flow from a `run_id` or signed `checkpoint_token`, skipping completed tasks. | Policy + signed checkpoint |
| `uniconn://inventory/hosts` | Static resource returning the host manifest, groups, and active security policy. | Read-only |
| `uniconn://hosts/{host}/facts` | Resource Template returning live `HostFacts` JSON for any registered host. | Read-only |

#### Programmatic `MCPServer` Usage in Python

You can also embed `MCPServer` directly inside custom agent runners (including JSON-RPC 2.0 batch requests):

```python
from uniconn.mcp import MCPHostRegistry, MCPSecurityPolicy, MCPServer

policy = MCPSecurityPolicy(allow_write=False, allowlist=("echo", "df", "uptime"))
registry = MCPHostRegistry.from_sources(inventory="hosts.yaml", policy=policy)
server = MCPServer(registry=registry)

response = await server.handle_message({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "uniconn_run",
        "arguments": {"target": "web-01", "command": "df -h", "parse": True},
    },
})
```

---

## 📚 Local Documentation Server (Sphinx)

Build and browse the full bilingual Sphinx HTML documentation locally on port `3000` (or run the quick in-process CLI showcase without flags):

```bash
# Build Sphinx HTML docs (if needed) and serve on http://0.0.0.0:3000
python main.py --serve

# Run quick local CLI showcase
python main.py
```

---

## 📖 Documentation Suite (`docs/` & `docs/ru/`)

Full user guides, task-to-solution matrices, architectural deep dives, and references are located in [`docs/`](docs/) (English) and [`docs/ru/`](docs/ru/) (Russian):

| Guide (English) | Руководство (На русском) | What You Will Find |
| :--- | :--- | :--- |
| **[Overview & Cheat Sheet](docs/index.rst)** | **[Обзор и шпаргалка](docs/ru/index.rst)** | 10-second Task-to-Solution matrix and role-based entry paths |
| **[5-Minute Quickstart](docs/quickstart.rst)** | **[Быстрый старт за 5 мин](docs/ru/quickstart.rst)** | Installation extras (`uniconn[all]`, `[winrm]`, `[bmc]`), zero-setup sandbox, Async vs. Sync vs. CLI |
| **[Core Architecture & Pipeline](docs/architecture.rst)** | **[Архитектура ядра и пайплайн](docs/ru/architecture.rst)** | `CommandPipeline`, exact 11-step middleware execution order, `EventLoopPortal`, `RemotePythonWorker`, ISP protocols |
| **[Inventory & URI Reference](docs/inventory_and_uris.rst)** | **[Схемы инвентаря и URI](docs/ru/inventory_and_uris.rst)** | Full YAML/TOML/JSON schemas, `defaults`/`groups` merge rules, `env://` & `file://` secrets, all 13+ transport options |
| **[Step-by-Step Cookbook](docs/cookbook.rst)** | **[Кулинарная книга (Cookbook)](docs/ru/cookbook.rst)** | Production recipes for auto-parsing, Zero-Fork RPC (`run_python`), `RemotePath`, `ensure_*`, `Flow`, NETCONF/YANG, BMC/UART, and cassettes |
| **[Debugging & Troubleshooting](docs/troubleshooting.rst)** | **[Отладка и исключения](docs/ru/troubleshooting.rst)** | Full `UniconnError` inheritance tree, `diagnose=True` root-cause strategies, debug logging, and Symptom → Fix matrix |
| **[Migration Guides](docs/migration.rst)** | **[Гайд по миграции](docs/migration.rst)** | Side-by-side translation tables from **Ansible**, **Paramiko**, **Fabric**, and **Netmiko / Scrapli** |
| **[Transports Overview](docs/transports.rst)** | **[Обзор 13+ транспортов](docs/transports.rst)** | Quick summary of all 13+ transport URI schemes |
| **[CLI, MCP & Security](docs/cli_and_mcp.rst)** | **[CLI, MCP и Policy](docs/cli_and_mcp.rst)** | Modular CLI commands, `uniconn mcp` AI server, HITL approvals, and `CommandASTParser` Policy-as-Code |
| **[API Reference](docs/api.rst)** | **[Справочник API](docs/api.rst)** | Complete class and function reference synchronized with `llms.txt` |

---

## 🧪 Runnable Examples Catalog (`examples/`)

Every script in [`examples/`](examples/) is self-contained and verified in our CI test suite (`uv run python examples/<script>.py`):

| Scenario | Key APIs Demonstrated | Runnable Script |
| :--- | :--- | :--- |
| **Getting Started (Async & Sync)** | `Connection.from_uri`, `SyncConnection`, `SecretResolver`, `run`, `stream`, `copy` | [examples/basic_usage.py](examples/basic_usage.py) |
| **Inventory & Result Ergonomics** | `from_file`, `Result` helpers, `ConnectionPool` inventory groups | [examples/ergonomics_and_inventory.py](examples/ergonomics_and_inventory.py) |
| **File Operations & Delta Sync** | `conn.files.write_file(atomic=True)`, `checksum`, `sync_dir`, `write_template` | [examples/file_transfer.py](examples/file_transfer.py) |
| **Interactive PTY Shell & Expect** | `conn.open_shell`, `shell.execute`, `conn.expect`, `SyncShellSession` | [examples/interactive_shell.py](examples/interactive_shell.py) |
| **Health Checks & Wait Primitives** | `ping`, `is_alive`, `wait_for_connection`, `wait_for_port`, `wait_for_path` | [examples/health_check.py](examples/health_check.py) |
| **Fleet Parallelism & Wave Rollout** | `ConnectionPool.map`, `batch_size`, `max_fail_ratio`, `select`, `pool.stream` | [examples/parallel_execution.py](examples/parallel_execution.py) |
| **Idempotent State & Drift Detection** | `conn.state.ensure_*`, `gather_facts`, `diff_facts`, `diagnostic_session` | [examples/provisioning_and_facts.py](examples/provisioning_and_facts.py) |
| **Resilience, Pools & SSH Tunnels** | `CircuitBreaker`, `RateLimiter`, `SSHSessionPool`, `conn.tunnels` | [examples/resilience_rollout_and_waiters.py](examples/resilience_rollout_and_waiters.py) |
| **Bare-Metal BMC (Redfish & IPMI)** | `redfish://`, `ipmi://`, power control, sensors, cassette replay | [examples/bmc_management.py](examples/bmc_management.py) |
| **Background Task Monitoring** | `BackgroundPool.from_file`, `tmux`/`screen`/`nohup` auto-backend, log polling | [examples/screen_monitoring.py](examples/screen_monitoring.py) · [YAML](examples/screen_pool_config.yaml) |
| **NVMe / RAM Stress Diagnostics** | `diagnostic_session`, `fsync_realtime=True`, pre/post `facts_diff`, `.tar.gz` | [examples/stress_test_diagnostics.py](examples/stress_test_diagnostics.py) · [YAML](examples/stress_test_diagnostics.yaml) |
| **Reactive Log Watchdog (SCT / BBU)** | `PatternTriggerHandler`, `LogWatchRule`, Stream Silence Watchdog | [examples/reactive_log_watchdog_sct.py](examples/reactive_log_watchdog_sct.py) · [YAML](examples/telecom_bs_sct_diagnostics.yaml) |
| **Security Hooks & OpenTelemetry** | `allowlist_hook`, `blocklist_hook`, `audit_log_hook`, `otel_tracing_hook`, `dry_run` | [examples/security_and_hooks.py](examples/security_and_hooks.py) |
| **Structured Logging & Metrics** | `configure_logging(fmt="json")`, `log_context`, `metrics_collector_hook` | [examples/structured_logging_telemetry.py](examples/structured_logging_telemetry.py) |
| **Offline Contract Testing (Cassettes)** | `conn.use_cassette`, `pool.use_cassette`, `cassette.diff`, pytest plugin | [examples/contract_testing_cassettes.py](examples/contract_testing_cassettes.py) |
| **Custom Transport Plugin** | Subclassing `BaseTransport`, implementing `run`/`stream`/`ping`, entry-points | [examples/custom_transport.py](examples/custom_transport.py) |

---

## 🛠️ Modular CLI

`uniconn` features an ergonomic command-line interface powered by `cyclopts` and `rich`:

```bash
# Execute command with sudo and JSON output
uniconn run "ssh://user@host" "systemctl status nginx" --sudo --format json

# Multi-host wave rollout
uniconn run-multi --inventory fleet.yaml --group web -c "nginx -t" --batch-size 2 --max-fail-ratio 0.0

# Ping and latency probe
uniconn ping "ssh://node-01" "winrm://win-01" "redfish://bmc-01"

# Wait primitives (connection, port, or file content regex)
uniconn wait-for connection "ssh://node-01" --timeout 120
uniconn wait-for port 5432 "ssh://node-01" --state open --check-from remote
uniconn wait-for path /var/run/app.pid "ssh://node-01" --regex "READY"

# File integrity & delta synchronization
uniconn checksum /etc/app.conf "ssh://node-01" "ssh://node-02" --algorithm sha256
uniconn sync ./dist /var/www/app --inventory fleet.yaml --group web --delete --checksum

# Idempotent state commands with diff preview
uniconn ensure-user deploy "ssh://node-01" --uid 1050 --groups docker,sudo --sudo
uniconn ensure-unit myapp.service "ssh://node-01" --file ./myapp.service --state started --enabled

# Record & replay contract cassettes
uniconn record "ssh://user@host" -c ./cassettes/node.yaml --sanitize-ip -- uptime
uniconn replay ./cassettes/node.yaml -- uptime
uniconn cassette diff ./cassettes/v1.yaml ./cassettes/v2.yaml --fail-on-diff

# Launch Official MCP Server for AI Agents (JSON-RPC 2.0 stdio)
uniconn mcp --inventory fleet.yaml --allowlist "df,uptime,systemctl status,journalctl"
```

---

## 🤝 Community & Governance

We are committed to building an open, welcoming, and secure automation ecosystem. Please review our community guidelines:

- **[Contributing Guide (CONTRIBUTING.md)](CONTRIBUTING.md)**: Setup instructions (`uv`, `poe`), coding standards, architectural invariants, and PR guidelines.
- **[Code of Conduct (CODE_OF_CONDUCT.md)](CODE_OF_CONDUCT.md)**: Our pledge and standards based on Contributor Covenant v2.1.
- **[Security Policy (SECURITY.md)](SECURITY.md)**: Responsible disclosure instructions and vulnerability response SLAs.

---

## 📄 License

`uniconn` is released under the **MIT License**. See the [LICENSE](LICENSE) file for details.
