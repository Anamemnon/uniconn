# src/uniconn/mcp/risk_classifier.py
"""Детерминированный классификатор рисков команд и файловых операций (ActionRiskClassifier).

Выделен из ``uniconn.mcp.hitl`` для модульности и работает поверх единого
``ParsedCommandAST`` (POSIX + PowerShell) из ``uniconn.security.ast_parser``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..security.ast_parser import (
    _SHELL_BINARIES,
    CommandASTParser,
    normalize_target_path,
)
from ._risk_rules import (
    _ALL_PS_DISPATCH_BINARIES,
    _AWK_BINARIES,
    _AWK_EXEC_OR_WRITE_RE,
    _CONTAINER_RO_SUBCOMMANDS,
    _DESTRUCTIVE_PATTERNS,
    _DESTRUCTIVE_PKG_VERBS,
    _FIND_MUTATING_FLAGS,
    _FORBIDDEN_FILE_PREFIXES,
    _FORBIDDEN_PATTERNS,
    _FORBIDDEN_READ_EXACT,
    _GIT_RO_SUBCOMMANDS,
    _MUTATING_EXECUTABLES,
    _MUTATING_PATTERNS,
    _MUTATING_PKG_VERBS,
    _NO_FILE_READ_COMMANDS,
    _OUTPUT_REDIRECT_TARGET_RE,
    _PACKAGE_MANAGERS,
    _PROTECTED_PATH_PREFIXES,
    _PS_CARRIER_BINARIES,
    _PS_CRITICAL_ROOT_RE,
    _PS_DESTRUCTIVE_CMDLETS,
    _PS_FORBIDDEN_CMDLETS,
    _PS_MUTATING_CMDLETS,
    _PS_SAFE_CMDLETS,
    _SAFE_COMMANDS,
    _SYSTEMCTL_RO_SUBCOMMANDS,
    _collect_atom_candidate_paths,
    _extract_first_subcommand,
    _match_forbidden_read_path,
    _resolve_normalized_write_path,
    _split_shell_segments,
    build_unified_diff,
)
from .models import ActionRiskTier, HITLPolicy, RiskAssessment


class ActionRiskClassifier:
    """Детерминированный классификатор рисков команд и инструментов ИИ-агента."""

    @classmethod
    def classify_command(
        cls,
        command: str,
        *,
        sudo: bool = False,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
        ast: Any = None,
        _depth: int = 0,
        _preparsed_ast: Any = None,
    ) -> RiskAssessment:
        """Оценить уровень риска shell/PowerShell-команды на базе единого AST ``CommandASTParser``."""
        del _depth
        cmd_stripped = command.strip()
        if not cmd_stripped:
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_0_SAFE,
                reasons=("Empty command",),
                is_production=is_production,
                requires_approval=False,
            )

        reasons: list[str] = []
        max_tier = ActionRiskTier.TIER_0_SAFE

        def _elevate(tier: ActionRiskTier, msg: str | None = None) -> None:
            nonlocal max_tier
            if tier.severity > max_tier.severity:
                max_tier = tier
            if msg and msg not in reasons:
                reasons.append(msg)

        for regex, reason in _FORBIDDEN_PATTERNS:
            if regex.search(cmd_stripped):
                return RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                    reasons=(reason,),
                    is_production=is_production,
                    requires_approval=False,
                )

        ast_obj = ast if ast is not None else _preparsed_ast
        if ast_obj is None:
            ast_obj = CommandASTParser.parse(cmd_stripped, sudo=sudo)

        syntax_errors = tuple(getattr(ast_obj, "syntax_errors", ()) or ())
        if getattr(ast_obj, "is_obfuscated", False):
            obf_reasons: list[str] = [
                str(r)
                for r in (
                    getattr(ast_obj, "obfuscation_reasons", ()) or ("Obfuscated command syntax detected",)
                )
            ]
            if syntax_errors and not any("syntax" in r.lower() for r in obf_reasons):
                obf_reasons.append(
                    f"Malformed shell/PowerShell syntax detected (fail-closed): {'; '.join(syntax_errors)}"
                )
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=tuple(obf_reasons),
                is_production=is_production,
                requires_approval=False,
            )

        ast_dialect = str(getattr(ast_obj, "dialect", "posix") or "posix").lower()
        atomic_commands = tuple(getattr(ast_obj, "atomic_commands", ()) or ())
        for idx, atom in enumerate(atomic_commands):
            is_unwrapped_shell_carrier = (
                atom.executable in _SHELL_BINARIES
                and any(flag in atom.flags for flag in ("-c", "-lc", "-ic"))
                and any(
                    f"{atom.executable} " in w
                    for child in atomic_commands[idx + 1 :]
                    for w in getattr(child, "wrappers", ())
                )
            )
            is_unwrapped_ps_carrier = (
                atom.executable in _PS_CARRIER_BINARIES
                and any(
                    any(tag in w for tag in ("powershell", "pwsh"))
                    for child in atomic_commands[idx + 1 :]
                    for w in getattr(child, "wrappers", ())
                )
            )
            if is_unwrapped_shell_carrier or is_unwrapped_ps_carrier:
                continue

            if ast_dialect == "powershell" or atom.executable in _ALL_PS_DISPATCH_BINARIES:
                atom_tier, atom_reasons = cls._classify_powershell_atomic(atom, inherited_sudo=sudo)
            else:
                atom_tier, atom_reasons = cls._classify_atomic_command(atom, inherited_sudo=sudo)

            for msg in atom_reasons:
                _elevate(atom_tier, msg)
            if not atom_reasons:
                _elevate(atom_tier)

        dest_sev = ActionRiskTier.TIER_2_DESTRUCTIVE.severity
        if syntax_errors:
            syntax_msg = f"Malformed shell/PowerShell syntax detected (fail-closed): {'; '.join(syntax_errors)}"
            if max_tier.severity < dest_sev:
                _elevate(ActionRiskTier.TIER_2_DESTRUCTIVE, syntax_msg)
            elif not any("syntax" in r.lower() for r in reasons):
                reasons.append(syntax_msg)
        if getattr(ast_obj, "has_destructive_verbs", False) and max_tier.severity < dest_sev:
            ast_execs = ", ".join(getattr(ast_obj, "executables", ()))
            _elevate(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"AST analysis detected nested destructive operation ({ast_execs})",
            )
        if getattr(ast_obj, "complexity_exceeded", False) and max_tier.severity < dest_sev:
            _elevate(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                "Command exceeds AST complexity threshold (opaque script)",
            )

        if sudo and max_tier == ActionRiskTier.TIER_1_MUTATING and is_production:
            max_tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append("Privileged (sudo=True) mutating command on a production host")
        elif sudo and max_tier == ActionRiskTier.TIER_0_SAFE and not reasons:
            reasons.append("Read-only inspection command executed with sudo")

        if not reasons:
            reasons.append(f"Classified as {max_tier.value}")

        requires_appr = (
            policy.requires_approval(max_tier, is_production=is_production)
            if policy is not None
            else (
                max_tier == ActionRiskTier.TIER_2_DESTRUCTIVE
                or (is_production and max_tier == ActionRiskTier.TIER_1_MUTATING)
            )
        )
        return RiskAssessment(
            risk_tier=max_tier,
            reasons=tuple(reasons),
            is_production=is_production,
            requires_approval=requires_appr,
        )

    @classmethod
    def _classify_powershell_atomic(
        cls,
        atom: Any,
        *,
        inherited_sudo: bool = False,
    ) -> tuple[ActionRiskTier, list[str]]:
        """Классифицировать атомарный PowerShell cmdlet / Windows-утилиту."""
        best_tier, reasons = cls._classify_redirect_or_tee(atom)
        base_bin = str(atom.executable or "").lower()
        sub_raw = atom.subcommand or (atom.arguments[0] if atom.arguments else None)
        sub = str(sub_raw).lower() if sub_raw else None
        args_lower = [str(a).lower() for a in atom.arguments]
        flags_lower = {k.lower(): v for k, v in atom.flags.items()}

        def _pick(tier: ActionRiskTier, msg: str) -> tuple[ActionRiskTier, list[str]]:
            if best_tier.severity > tier.severity:
                return best_tier, reasons
            return tier, [msg] if msg else reasons

        if base_bin in _PS_FORBIDDEN_CMDLETS:
            return _pick(
                ActionRiskTier.TIER_3_FORBIDDEN,
                f"Critical PowerShell operation ({base_bin}) is strictly forbidden",
            )

        if base_bin in ("vssadmin", "vssadmin.exe") and sub == "delete" and any("shadow" in a for a in args_lower):
            return _pick(
                ActionRiskTier.TIER_3_FORBIDDEN,
                "Deleting Volume Shadow Copies via vssadmin is strictly forbidden",
            )

        if base_bin == "remove-item":
            has_recurse = "-recurse" in flags_lower or "-r" in flags_lower
            candidates = list(atom.arguments) + [
                str(v) for k, v in flags_lower.items() if k in ("-path", "-literalpath") and isinstance(v, str)
            ]
            if has_recurse and any(_PS_CRITICAL_ROOT_RE.match(str(c).strip()) for c in candidates):
                return _pick(
                    ActionRiskTier.TIER_3_FORBIDDEN,
                    "Recursive Remove-Item against system root or Windows directory is forbidden",
                )

        if base_bin not in _NO_FILE_READ_COMMANDS:
            for candidate in _collect_atom_candidate_paths(atom):
                forbidden_path = _match_forbidden_read_path(candidate)
                if forbidden_path is not None:
                    return _pick(
                        ActionRiskTier.TIER_3_FORBIDDEN,
                        f"Accessing sensitive credential, key, or device path {forbidden_path!r} is forbidden",
                    )

        if base_bin in ("bcdedit", "bcdedit.exe", "diskpart", "diskpart.exe"):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Destructive Windows boot/disk utility ({base_bin})",
            )

        if base_bin in ("del", "erase"):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Destructive Windows file deletion ({base_bin})",
            )

        if base_bin in _PS_DESTRUCTIVE_CMDLETS or CommandASTParser._is_atomic_destructive(atom):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Destructive PowerShell/Windows operation ({base_bin}{f' {sub}' if sub else ''})",
            )

        if base_bin in ("reg", "reg.exe") and sub in ("delete", "import", "restore"):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, f"Destructive registry modification (reg {sub})")
        if base_bin in ("reg", "reg.exe") and sub in ("add", "copy", "save"):
            return _pick(ActionRiskTier.TIER_1_MUTATING, f"Registry modification (reg {sub})")
        if base_bin in ("reg", "reg.exe") and sub in ("query", "compare"):
            return _pick(ActionRiskTier.TIER_0_SAFE, "Read-only registry query")

        if base_bin in ("sc", "sc.exe") and sub in ("delete", "stop", "failure"):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, f"Destructive Windows service operation (sc {sub})")
        if base_bin in ("sc", "sc.exe") and sub in ("query", "qc", "queryex"):
            return _pick(ActionRiskTier.TIER_0_SAFE, "Read-only Windows service query")

        if base_bin in ("net", "net.exe") and sub in ("user", "localgroup") and any(
            a in ("/delete", "/add", "/active:no") for a in args_lower
        ):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, f"Modifying Windows accounts via net {sub}")

        if base_bin in _PS_MUTATING_CMDLETS:
            return _pick(ActionRiskTier.TIER_1_MUTATING, f"Mutating PowerShell cmdlet ({base_bin})")

        if base_bin in _PS_SAFE_CMDLETS or base_bin in _SAFE_COMMANDS:
            return _pick(ActionRiskTier.TIER_0_SAFE, f"Safe read-only PowerShell command ({base_bin})")

        if bool(atom.is_sudo or inherited_sudo):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Unrecognized PowerShell command ({base_bin!r}) with elevated privileges",
            )
        return _pick(
            ActionRiskTier.TIER_1_MUTATING,
            f"Unrecognized or potentially mutating PowerShell command ({base_bin!r})",
        )

    @classmethod
    def _classify_redirect_or_tee(cls, atom: Any) -> tuple[ActionRiskTier, list[str]]:
        """Оценить риск перенаправлений вывода (``>``, ``>>``) и записи через ``tee``."""
        tier = ActionRiskTier.TIER_0_SAFE
        reasons: list[str] = []

        def _check_target(target: str) -> None:
            nonlocal tier
            norm = _resolve_normalized_write_path(target)
            if norm == "/dev/null" or norm.startswith("&"):
                return
            if any(norm == p.rstrip("/") or norm.startswith(p) for p in _PROTECTED_PATH_PREFIXES):
                tier = ActionRiskTier.TIER_2_DESTRUCTIVE
                reasons.append("Overwriting or appending to protected system configuration path")
            elif tier.severity < ActionRiskTier.TIER_1_MUTATING.severity:
                tier = ActionRiskTier.TIER_1_MUTATING
                reasons.append("Shell output redirection to file")

        for redir in getattr(atom, "redirects", ()):
            match = _OUTPUT_REDIRECT_TARGET_RE.search(redir.strip())
            if match:
                _check_target(match.group(1))

        if atom.executable == "tee":
            for arg in atom.arguments:
                _check_target(arg)

        return tier, reasons

    @staticmethod
    def _classify_package_manager(
        sub: str | None, args_lower: list[str], flags_dict: Mapping[str, Any]
    ) -> tuple[ActionRiskTier, str] | None:
        verb = sub or (args_lower[0] if args_lower else None)
        if verb in _DESTRUCTIVE_PKG_VERBS or any(k.startswith("-R") for k in flags_dict):
            return ActionRiskTier.TIER_2_DESTRUCTIVE, "Removing or purging installed packages"
        if verb in _MUTATING_PKG_VERBS or any(a in _MUTATING_PKG_VERBS for a in args_lower):
            return ActionRiskTier.TIER_1_MUTATING, "Installing or updating packages"
        return None

    @staticmethod
    def _classify_container_cli(
        base_bin: str, sub: str | None, args_lower: list[str]
    ) -> tuple[ActionRiskTier, str]:
        if (
            base_bin in ("docker", "podman")
            and sub in ("system", "volume")
            and any(a in ("prune", "rm") for a in args_lower)
        ):
            return ActionRiskTier.TIER_2_DESTRUCTIVE, "Destructive container or Kubernetes workload operation"
        if sub is None or sub in _CONTAINER_RO_SUBCOMMANDS:
            return ActionRiskTier.TIER_0_SAFE, f"Read-only {base_bin} inspection"
        return ActionRiskTier.TIER_1_MUTATING, f"Container/cluster operation: {base_bin} {sub}"

    @staticmethod
    def _classify_awk(args: Sequence[Any], flags_dict: Mapping[str, Any]) -> tuple[ActionRiskTier, str]:
        script_parts = [str(a) for a in args]
        script_parts.extend(str(v) for v in flags_dict.values() if isinstance(v, str))
        joined_args = " ".join(script_parts)
        if _AWK_EXEC_OR_WRITE_RE.search(joined_args) or "-f" in flags_dict or "--file" in flags_dict:
            return (
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                "awk script with external command execution, file output, or script file",
            )
        return ActionRiskTier.TIER_1_MUTATING, "awk scripting interpreter may execute commands or write files"

    @classmethod
    def _classify_special_binary(
        cls,
        base_bin: str,
        sub: str | None,
        args: Sequence[Any],
        args_lower: list[str],
        flags_dict: Mapping[str, Any],
    ) -> tuple[ActionRiskTier, str] | None:
        """Разобрать команды со смешанными read-only и mutating подкомандами/флагами."""
        if base_bin in _PACKAGE_MANAGERS:
            return cls._classify_package_manager(sub, args_lower, flags_dict)
        if base_bin in _AWK_BINARIES:
            return cls._classify_awk(args, flags_dict)
        if base_bin == "ip":
            ip_mut = ("add", "del", "delete", "set", "flush", "change", "replace")
            if sub in ip_mut or any(a in ip_mut for a in args_lower):
                return ActionRiskTier.TIER_2_DESTRUCTIVE, "Network interface or routing table modification via ip"
            return ActionRiskTier.TIER_0_SAFE, "Safe read-only command (ip)"
        if base_bin == "sysctl":
            if "-w" in flags_dict or any("=" in a for a in args_lower):
                return ActionRiskTier.TIER_1_MUTATING, "Kernel parameter modification via sysctl"
            return ActionRiskTier.TIER_0_SAFE, "Safe read-only command (sysctl)"
        if base_bin == "systemctl":
            if sub is None or sub in _SYSTEMCTL_RO_SUBCOMMANDS:
                return ActionRiskTier.TIER_0_SAFE, "Read-only systemctl inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Mutating systemctl action: {sub}"
        if base_bin == "service":
            if sub is None or sub == "status":
                return ActionRiskTier.TIER_0_SAFE, "Read-only service inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Starting or restarting a system service ({sub})"
        if base_bin == "find":
            if any(k in flags_dict for k in _FIND_MUTATING_FLAGS):
                return ActionRiskTier.TIER_1_MUTATING, "find with command execution or file output flags"
            return ActionRiskTier.TIER_0_SAFE, "Read-only find search"
        if base_bin == "git":
            if sub is None or sub in _GIT_RO_SUBCOMMANDS:
                return ActionRiskTier.TIER_0_SAFE, "Read-only git inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Git operation: {sub}"
        if base_bin in ("docker", "podman", "kubectl"):
            return cls._classify_container_cli(base_bin, sub, args_lower)
        if base_bin == "command":
            is_lookup_flag = any(
                k.startswith("-") and not k.startswith("--") and ("v" in k[1:] or "V" in k[1:])
                for k in flags_dict
            )
            if is_lookup_flag:
                return ActionRiskTier.TIER_0_SAFE, "Safe read-only command lookup (command -v/-V)"
            return ActionRiskTier.TIER_1_MUTATING, "Command builtin execution"
        if base_bin == "sed" and (
            "-i" in flags_dict or "--in-place" in flags_dict or any(k.startswith("-i") for k in flags_dict)
        ):
            return ActionRiskTier.TIER_1_MUTATING, "In-place file editing"
        return None

    @classmethod
    def _classify_atomic_command(
        cls, atom: Any, *, inherited_sudo: bool = False
    ) -> tuple[ActionRiskTier, list[str]]:
        """Классифицировать одиночный POSIX ``AtomicCommand``, уже очищенный от обёрток парсером AST."""
        best_tier, reasons = cls._classify_redirect_or_tee(atom)
        base_bin = str(atom.executable or "").lower()
        sub = atom.subcommand.lower() if atom.subcommand else None
        args_lower = [str(a).lower() for a in atom.arguments]
        flags_dict = atom.flags
        effective_sudo = bool(atom.is_sudo or inherited_sudo)

        def _pick(tier: ActionRiskTier, msg: str) -> tuple[ActionRiskTier, list[str]]:
            if best_tier.severity > tier.severity:
                return best_tier, reasons
            return tier, [msg] if msg else reasons

        if base_bin == "rm":
            has_recursive = any(k in flags_dict for k in ("-r", "-R", "--recursive"))
            targets_root = any(
                str(a).strip() in ("/", "/*") or normalize_target_path(str(a)) in ("/", "/*")
                for a in atom.arguments
            )
            if "--no-preserve-root" in flags_dict or (has_recursive and targets_root):
                return _pick(
                    ActionRiskTier.TIER_3_FORBIDDEN,
                    "Recursive deletion of root filesystem (/ or /*) is strictly forbidden",
                )
        if base_bin == "mkfs" or base_bin.startswith("mkfs."):
            return _pick(ActionRiskTier.TIER_3_FORBIDDEN, f"Formatting filesystem ({base_bin}) is strictly forbidden")

        if base_bin not in _NO_FILE_READ_COMMANDS:
            for candidate in _collect_atom_candidate_paths(atom):
                forbidden_path = _match_forbidden_read_path(candidate)
                if forbidden_path is not None:
                    return _pick(
                        ActionRiskTier.TIER_3_FORBIDDEN,
                        f"Accessing sensitive credential, key, or device path {forbidden_path!r} is forbidden",
                    )

        if CommandASTParser._is_atomic_destructive(atom):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Destructive operation ({base_bin}{f' {sub}' if sub else ''})",
            )

        if base_bin in ("iptables", "ip6tables") and any(
            k in ("-F", "-X", "-Z", "--flush", "--delete-chain") for k in flags_dict
        ):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, "Destructive firewall rule modification or flush")

        if base_bin in ("passwd", "chage") and (base_bin == "chage" or "-l" in flags_dict):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, "Deleting or locking system user/group accounts")

        special = cls._classify_special_binary(base_bin, sub, atom.arguments, args_lower, flags_dict)
        if special is not None:
            return _pick(special[0], special[1])

        if base_bin in _MUTATING_EXECUTABLES:
            return _pick(ActionRiskTier.TIER_1_MUTATING, f"Mutating command ({base_bin})")

        if base_bin in _SAFE_COMMANDS or (base_bin == "tee" and best_tier != ActionRiskTier.TIER_0_SAFE):
            msg = "" if (base_bin == "tee" and reasons) else f"Safe read-only command ({base_bin})"
            return _pick(ActionRiskTier.TIER_0_SAFE, msg)

        if effective_sudo:
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Unrecognized command ({base_bin!r}) executed with sudo privileges",
            )
        return _pick(
            ActionRiskTier.TIER_1_MUTATING,
            f"Unrecognized or potentially mutating command ({base_bin!r})",
        )

    @classmethod
    def classify_file_write(
        cls,
        path: str,
        *,
        file_exists: bool = False,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Оценить уровень риска записи файла (uniconn_write_file)."""
        norm_path = _resolve_normalized_write_path(path)
        reasons: list[str] = []

        if (
            norm_path in ("/", "/etc/sudoers")
            or norm_path in _FORBIDDEN_READ_EXACT
            or norm_path.startswith((*_FORBIDDEN_FILE_PREFIXES, "/etc/sudoers.d/"))
        ):
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=(f"Writing to critical device or security file {norm_path!r} is forbidden",),
                is_production=is_production,
                requires_approval=False,
            )

        tier = ActionRiskTier.TIER_1_MUTATING
        if (
            any(norm_path == prefix.rstrip("/") or norm_path.startswith(prefix) for prefix in _PROTECTED_PATH_PREFIXES)
            or "/.ssh/" in norm_path
            or norm_path.endswith("/.ssh")
        ):
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Target path {norm_path!r} is inside a protected system directory")
        elif file_exists:
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Overwriting existing file {norm_path!r}")
        else:
            reasons.append(f"Creating or writing file {norm_path!r}")

        requires_appr = (
            policy.requires_approval(tier, is_production=is_production)
            if policy is not None
            else (
                tier == ActionRiskTier.TIER_2_DESTRUCTIVE
                or (is_production and tier == ActionRiskTier.TIER_1_MUTATING)
            )
        )
        return RiskAssessment(
            risk_tier=tier,
            reasons=tuple(reasons),
            is_production=is_production,
            requires_approval=requires_appr,
        )

    @classmethod
    def classify_file_read(
        cls,
        path: str,
        *,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Оценить уровень риска чтения файла (uniconn_read_file)."""
        del policy
        norm_path = _resolve_normalized_write_path(path)
        if _match_forbidden_read_path(path) is not None:
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=(f"Reading sensitive credential, key, or device path {norm_path!r} is forbidden",),
                is_production=is_production,
                requires_approval=False,
            )
        return RiskAssessment(
            risk_tier=ActionRiskTier.TIER_0_SAFE,
            reasons=(f"Read-only file access ({norm_path!r})",),
            is_production=is_production,
            requires_approval=False,
        )

    @classmethod
    def classify_tool_call(
        cls,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        is_production: bool = False,
        file_exists: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Классифицировать любой вызов MCP-инструмента по имени и аргументам."""
        if tool_name == "uniconn_run":
            return cls.classify_command(
                str(arguments.get("command") or ""),
                sudo=bool(arguments.get("sudo", False)),
                is_production=is_production,
                policy=policy,
            )
        if tool_name == "uniconn_write_file":
            return cls.classify_file_write(
                str(arguments.get("path") or ""),
                file_exists=file_exists,
                is_production=is_production,
                policy=policy,
            )
        if tool_name == "uniconn_read_file":
            return cls.classify_file_read(
                str(arguments.get("path") or ""),
                is_production=is_production,
                policy=policy,
            )
        return RiskAssessment(
            risk_tier=ActionRiskTier.TIER_0_SAFE,
            reasons=(f"Read-only or metadata tool ({tool_name})",),
            is_production=is_production,
            requires_approval=False,
        )


__all__ = [
    "_DESTRUCTIVE_PATTERNS",
    "_FORBIDDEN_FILE_PREFIXES",
    "_FORBIDDEN_PATTERNS",
    "_MUTATING_PATTERNS",
    "_PROTECTED_PATH_PREFIXES",
    "_SAFE_COMMANDS",
    "ActionRiskClassifier",
    "_extract_first_subcommand",
    "_split_shell_segments",
    "build_unified_diff",
]
