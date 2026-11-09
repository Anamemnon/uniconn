# Contributing to uniconn

Thank you for your interest in contributing to **`uniconn`**! We welcome bug reports, feature suggestions, documentation improvements, and code contributions.

This document outlines our development workflows, coding standards, architectural invariants, and testing practices.

---

## 🛠️ Development Setup

`uniconn` uses [`uv`](https://docs.astral.sh/uv/) for high-speed, reproducible Python package and environment management (Python 3.11+ required).

### 1. Clone the repository and install dependencies

```bash
git clone https://github.com/ChekirDmitry/uniconn.git
cd uniconn

# Install all runtime, transport, CLI, and development dependencies
uv sync
```

### 2. Available Poe Tasks

We use [`poethepoet`](https://github.com/nat-n/poethepoet) as our task runner:

```bash
uv run poe check       # Comprehensive check: lint + typecheck + architecture tests
uv run poe lint        # Code style & quality check (ruff)
uv run poe typecheck   # Static type verification (pyright)
uv run poe test        # Run all fast unit tests
uv run poe bench       # Run core overhead and latency benchmarks against SLA thresholds
```

---

## 🏛️ Architectural Invariants

Before writing or modifying code, please keep these four golden rules in mind:

### 1. Pragmatic Async + Sync Parity Without Code Duplication
- The core of `uniconn` is strictly asynchronous (`asyncio`).
- All user-facing APIs on `Connection`, `ConnectionPool`, `ShellSession`, and domain services (`.files`, `.state`, `.tunnels`) must be reflected in their synchronous counterparts (`SyncConnection`, `SyncConnectionPool`, `SyncShellSession`) **declaratively** via single-line `ParamSpec` descriptors in `src/uniconn/core/bridge.py` (`sync_method`, `sync_context`, `sync_iter`, `sync_factory`, etc.) and `SyncProxyMixin`.
- **Never manually copy-paste method signatures and docstrings** between async and sync implementations.

### 2. Strict Zero RuntimeWarning Policy
- Our test configuration enables `-W error::RuntimeWarning`.
- Unawaited coroutines (`coroutine was never awaited`) will immediately fail the test suite. When mocking `asyncio.StreamWriter`, use `MagicMock()` for synchronous methods like `.write()` and `.close()`, never `AsyncMock()`.

### 3. Public API Exports and Documentation Parity
- Every public class and function must be exported in `src/uniconn/__init__.py` (`__all__`).
- New public methods, transports, or decorators must also be documented in `llms.txt` and the feature catalog.

### 4. Zero Secrets in Logs and Traces
- All user secrets (passwords, tokens, keys) must pass through `SecretResolver` / `SecretStr`.
- Any component outputting telemetry, logs, or traces must support masking (`sensitive=True`, `mask_secrets=True`).

---

## 🧪 Testing Guidelines

Unit tests (`tests/unit/`, 600+ tests) strictly mirror the `src/uniconn/` domain packages:

```
tests/unit/
├── architecture/    # API surface, async/sync parity, exception hierarchy
├── core/            # Connection, pipeline, context, waiters, resilience, hooks
├── services/        # files, state, facts, templates, remote_path
├── transports/      # ssh, telnet, serial, bmc (ipmi/redfish), replay, container
├── pools/           # ConnectionPool, SSHSessionPool, batch rollout, stream mux
├── background/      # BackgroundPool, DiagnosticSession, LogPipeline
├── orchestration/   # Flow, Task, task decorator, DAG barriers
├── parsing/         # Structured CLI parsing (jc, ttp, textfsm, json)
├── mock/            # In-memory SSH, Telnet, SFTP mock servers
└── cli/             # Cyclopts commands and Rich renderers
```

### Running Tests

```bash
# Run all unit tests with compact summary output
uv run pytest -m "not integration" -q --tb=short | tail -n 5

# Re-run only failed tests with detailed tracebacks during debugging
uv run pytest -m "not integration" -q --tb=short --lf | tail -n 30

# Run tests for a specific domain
uv run pytest tests/unit/services/ -q
```

Every bugfix or new feature **must** include dedicated unit tests in the appropriate domain folder.

---

## 🎨 Code Style and Quality Standards

- **Line Length**: Max **120 characters**, enforced by `ruff`.
- **Linter**: `ruff check src/ benchmarks/ examples/ tests/` (imports sorted automatically via `isort` rules).
- **Type Checker**: `pyright` in `standard` mode (0 errors allowed).
- **Core Overhead SLA**: `python -m benchmarks.overhead_bench --check-thresholds` must pass to ensure the execution pipeline remains sub-millisecond.

---

## 🔄 Pull Request Workflow

1. **Fork and branch**: Create a descriptive feature branch from `main`:
   ```bash
   git checkout -b feat/add-winrm-kerberos-support
   ```
2. **Follow Conventional Commits**:
   - `feat:` for new capabilities or transports
   - `fix:` for bug fixes
   - `docs:` for documentation updates
   - `refactor:` for code reorganization without behavior changes
   - `test:` for test additions or improvements
   - `perf:` for latency/overhead optimizations
3. **Verify locally before pushing**:
   ```bash
   uv run poe check
   uv run poe test
   ```
4. **Submit PR**: Open a Pull Request targeting `main`. Describe what changed, the rationale, and link any related issues.

---

## 💬 Community & Questions

- For general discussions, architecture questions, or proposals: open a [GitHub Discussion](https://github.com/ChekirDmitry/uniconn/discussions).
- For bug reports and reproducible defects: file a [GitHub Issue](https://github.com/ChekirDmitry/uniconn/issues).
- For security vulnerabilities: please consult [SECURITY.md](SECURITY.md) for private disclosure instructions.
