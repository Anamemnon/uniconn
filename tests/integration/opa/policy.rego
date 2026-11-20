package uniconn.authz

import rego.v1

default allow := false
default require_approval := false

# Explicitly deny malformed AST syntax (fail-closed)
deny contains msg if {
    input.action.ast.has_syntax_errors == true
    msg := "Malformed shell/PowerShell syntax rejected by OPA Rego policy"
}

# Explicitly deny forbidden system shutdown/disk-format binaries
_blocked_executables := {"shutdown", "reboot", "poweroff", "halt", "mkfs", "dd"}

deny contains msg if {
    some exe in input.action.ast.executables
    exe in _blocked_executables
    msg := sprintf("Executable %q is forbidden by OPA Rego policy", [exe])
}

# Explicitly deny commands targeting /etc/shadow
deny contains msg if {
    contains(input.action.command, "/etc/shadow")
    msg := "Reading or modifying /etc/shadow is forbidden by OPA Rego policy"
}

# Require human approval (HITL) for destructive commands or mutating operations on production
require_approval if {
    count(deny) == 0
    input.action.risk_tier == "DESTRUCTIVE"
}

require_approval if {
    count(deny) == 0
    input.resource.environment == "production"
    input.action.risk_tier == "MUTATING"
}

require_approval if {
    count(deny) == 0
    input.resource.environment == "production"
    input.action.sudo == true
}

# Allow when there are no deny violations and approval is not required
allow if {
    count(deny) == 0
    not require_approval
}

approval_reason := "Production or destructive change requires human approval per OPA policy" if {
    require_approval
}

remediation_hint := "Use read-only diagnostic commands or request HITL approval for production changes."
