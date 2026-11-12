CLI, MCP Server, HITL Approvals & Policy Guardrails
===================================================

``uniconn`` includes a modular CLI built on ``cyclopts`` and ``rich``, an official Model Context Protocol (MCP) server over JSON-RPC 2.0 (``stdio``), Human-in-the-Loop (HITL) cryptographic approval workflows, and an AST-based Policy-as-Code engine.

1. Modular CLI Reference (``uniconn``)
--------------------------------------

Execution, Waiting & Multi-Host Rollouts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Single-host execution with sudo and JSON output
   uniconn run "ssh://admin@node-01" "systemctl status nginx" --sudo --format json

   # Wave rollout across an inventory group with automatic failure abort
   uniconn run-multi --inventory fleet.yaml --group web -c "nginx -t" --batch-size 2 --max-fail-ratio 0.0

   # Concurrent latency probe across heterogeneous transports
   uniconn ping "ssh://node-01" "winrm://win-01" "kubectl://prod/api-pod-0"

   # Wait primitives (connection readiness, TCP port state, file regex)
   uniconn wait-for connection "ssh://node-01" --timeout 120
   uniconn wait-for port 5432 "ssh://node-01" --state open --check-from remote
   uniconn wait-for path /var/run/app.pid "ssh://node-01" --regex "READY"

Files, Integrity & Idempotent State Provisioning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Verify SHA-256 checksums and run delta directory synchronization
   uniconn checksum /etc/app.conf "ssh://node-01" "ssh://node-02" --algorithm sha256
   uniconn sync ./dist /var/www/app --inventory fleet.yaml --group web --delete --checksum

   # Idempotent system provisioning with unified diff preview (--dry-run)
   uniconn ensure-user deploy "ssh://node-01" --uid 1050 --groups docker,sudo --sudo
   uniconn ensure-authorized-key deploy "ssh-ed25519 AAAA..." "ssh://node-01" --sudo
   uniconn ensure-unit myapp.service "ssh://node-01" --file ./myapp.service --state started --enabled
   uniconn ensure-sysctl net.ipv4.ip_forward 1 "ssh://node-01" --dry-run

Declarative Task DAG Flows (``uniconn flow``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # List and inspect task dependency graphs in a Python file
   uniconn flow list deploy_flows.py
   uniconn flow inspect deploy_flows.py:prod_deploy --format tree

   # Execute a DAG flow in barrier mode with injected variables
   uniconn flow run deploy_flows.py:prod_deploy "ssh://web-01" "ssh://web-02" \
       --mode barrier --batch-size 2 --var version=1.4.2 --var port=9090

Contract Testing Cassettes & In-Process Mock Servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Record a live session into a sanitized YAML cassette
   uniconn record "ssh://admin@node-01" -c ./cassettes/node.yaml --sanitize-ip -- uptime

   # Replay offline and compare two cassettes for regression drift
   uniconn replay ./cassettes/node.yaml -- uptime
   uniconn cassette diff ./cassettes/baseline.yaml ./cassettes/candidate.yaml --fail-on-diff

2. Official MCP Server for AI Agents (``uniconn mcp``)
------------------------------------------------------

Connect your infrastructure inventory to AI agents and IDEs (**Claude Desktop, Cursor, Windsurf, Cline**) over **Model Context Protocol (JSON-RPC 2.0 stdio)**.

Safe Mode by Default
~~~~~~~~~~~~~~~~~~~~

- File mutation (``uniconn_write_file``) and privilege escalation (``sudo=True``) are disabled unless ``--allow-write`` / ``--allow-sudo`` are explicitly passed.
- Destructive patterns (``rm -rf /``, ``mkfs``, ``shutdown``) are blocked via pipeline hooks and AST inspection.
- Secrets from ``SecretResolver`` (``env://``, ``file://``) are redacted in both URIs (``mask_uri_secrets``) and command outputs (``SecretMaskingFilter``).
- Declarative ``Flow`` objects marked with ``expose_as_tool=True`` are automatically exported as typed MCP tools (``flow_<name>``).

.. code-block:: bash

   # Start read-only MCP server with audit logging and Policy-as-Code preset
   uniconn mcp --inventory hosts.yaml --policy-preset prod-guard --audit-log ./mcp-audit.jsonl

   # Export custom Python DAG flows as typed MCP tools with Human-in-the-Loop approvals
   uniconn mcp --inventory hosts.yaml --flows deploy_flows.py --hitl --allow-write

   # Print ready-to-paste JSON block for claude_desktop_config.json / Cursor mcp.json
   uniconn mcp --inventory hosts.yaml --group web --print-config

3. Human-in-the-Loop (HITL) Approvals (``uniconn approval``)
------------------------------------------------------------

When ``--hitl`` is enabled (or when a Policy-as-Code rule returns ``REQUIRE_APPROVAL``), mutating or high-risk actions pause and generate a tamper-evident approval request with a SHA-256 payload digest and unified diff preview:

.. code-block:: bash

   # List pending approval requests created by an AI agent
   uniconn approval list --status PENDING

   # Inspect the exact command, target host, risk reasons, and unified file diff
   uniconn approval show appr_9f8e7d6c5b4a

   # Approve or reject the request from the operator terminal
   uniconn approval approve appr_9f8e7d6c5b4a --by sre_lead --reason "Verified maintenance window"
   uniconn approval reject appr_9f8e7d6c5b4a --by sre_lead --reason "Freeze window active"

4. AST Command Verification & Policy-as-Code Guardrails (``uniconn.security``)
------------------------------------------------------------------------------

Regex blocklists are easily bypassed by shell tricks (`echo cm0gLXJmIC8= | base64 -d | sh` or `find / -exec rm -rf {} \;`). ``uniconn`` includes a recursive **Shell AST Parser** (`CommandASTParser`) and an **ABAC Policy Engine** (`EmbeddedPolicyEngine` and Open Policy Agent `OPAPolicyEngine`):

- **Deep Wrapper Unwrapping**: Recursively unwraps ``sudo``, ``env``, ``nohup``, ``timeout``, ``nice``, ``xargs``, ``find -exec``, ``sh -c``, ``bash -c``, ``python -c``, and ``ssh`` to extract every underlying atomic executable and flag.
- **Obfuscation Detection**: Automatically flags base64/hex decoding pipes into interpreters, ``eval``, dynamic command substitution ``$(...)``, and excessive pipeline depth.
- **Built-in Policy Presets**: ``default``, ``prod-guard`` (blocks mutations on production hosts outside maintenance windows and requires HITL approval for ``sudo``), ``least-privilege``, and ``strict``.

CLI Inspection & Policy Evaluation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Decompose a complex shell pipeline into atomic AST commands and flags
   uniconn policy parse "echo cm0gLXJmIC8= | base64 -d | sh"

   # Evaluate a command against ABAC context (role, environment, sudo, maintenance window)
   uniconn policy eval "systemctl restart postgresql" \
       --host prod-db-01 --env prod --role operator --sudo --preset prod-guard

Programmatic Python Usage
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from uniconn import (
       CommandASTParser,
       PolicyGuardrailConfig,
       build_auth_context,
       create_policy_engine,
   )

   ast = CommandASTParser.parse("sudo find /var/tmp -exec rm -rf {} \\;")
   assert "rm" in ast.verbs

   engine = create_policy_engine(PolicyGuardrailConfig(enabled=True, preset="prod-guard"))
   ctx = build_auth_context(
       agent_id="ops-bot",
       role="operator",
       host_name="prod-db-01",
       environment="prod",
       is_production=True,
       tool_name="uniconn_run",
       command="systemctl restart postgresql",
       ast=CommandASTParser.parse("systemctl restart postgresql"),
       sudo=True,
   )
   result = await engine.evaluate(ctx)
   print(result.decision.value, result.reasons)  # REQUIRE_APPROVAL
