# Security Policy

The `uniconn` project takes the security and integrity of our codebase and your infrastructure very seriously.

Because `uniconn` executes commands, handles authentication secrets, transfers files, and manages system state across remote environments, we design every component with defense-in-depth principles.

---

## 🛡️ Supported Versions

We provide security updates and patches for the following versions:

| Version | Supported          | Status |
| :------ | :----------------: | :----- |
| `0.18.x`| :white_check_mark: | Current active release branch |
| `main`  | :white_check_mark: | Development branch |
| `< 0.18`| :x:                | End of life; please upgrade to `>= 0.18.0` |

---

## 🔒 Reporting a Vulnerability

**Please do NOT disclose security vulnerabilities publicly via GitHub Issues, Discussions, or social media.**

If you believe you have found a security vulnerability in `uniconn`:

1. **Email us privately**: Send an encrypted or plain-text report directly to **`ChekirDmitry@gmail.com`**.
   - Alternatively, submit a private advisory via [GitHub Security Advisories](https://github.com/ChekirDmitry/uniconn/security/advisories/new).
2. **Include details**:
   - Description of the potential vulnerability and its impact.
   - Minimal reproduction script or test case.
   - Affected transport(s), components, or versions.
   - Any potential mitigation or workaround you have identified.
3. **Response Timeline SLA**:
   - **Acknowledgment**: You will receive an acknowledgment of your report within **48 hours**.
   - **Assessment**: We will triage and assess the severity within **5 business days**.
   - **Resolution & Disclosure**: We will coordinate with you on the timeline for deploying a patch and publishing a coordinated CVE advisory.

---

## 🛡️ Security Architecture & Invariants in uniconn

`uniconn` includes several built-in mechanisms designed to safeguard sensitive infrastructure:

1. **Automatic Secret Resolution (`SecretResolver`)**:
   - Secrets are loaded dynamically via `env://VAR_NAME` or `file:///path/to/secret` syntax rather than being committed to inventory files or hardcoded in scripts.
2. **Output & Telemetry Masking (`sensitive=True`)**:
   - Passwords, keys, and commands flagged with `sensitive=True` are automatically redacted in `repr(Result)`, `to_dict()`, `structlog` JSONL logs, and OpenTelemetry spans.
3. **Safe Privilege Escalation (`sudo`)**:
   - `sudo` passwords are transmitted strictly through interactive `stdin` buffers and are never passed via command-line arguments (preventing visibility in `/proc` or `ps aux`).
4. **Injection-Safe Command Execution**:
   - Passing commands as sequences of strings (`["systemctl", "status", service_name]`) uses safe argument serialization (`shlex.join`) to avoid shell injection vectors.
5. **Cassette Sanitization**:
   - When using record/replay cassettes for testing, `uniconn cassette sanitize` strips private tokens, passwords, and IP addresses before committing cassettes to version control.
