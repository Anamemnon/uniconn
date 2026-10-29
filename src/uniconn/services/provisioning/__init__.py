# src/uniconn/services/provisioning/__init__.py
"""Пакет идемпотентного управления состоянием (декомпозиция с 100% обратной совместимостью)."""

from __future__ import annotations

from ._plan import (
    ChangePlan,
    _parse_mode,
    apply_owner_group,
    can_inspect_in_dry_run,
    extract_stat_mode,
    get_owner_group,
)
from .facade import StateManagementService
from .files import (
    ensure_directory,
    ensure_file,
    ensure_line,
    transform_lines_absent,
    transform_lines_present,
)
from .packages import (
    PACKAGE_STRATEGIES,
    ApkStrategy,
    AptStrategy,
    DnfYumStrategy,
    PackageManagerStrategy,
    PacmanStrategy,
    PkgManagerName,
    ZypperStrategy,
    ensure_package,
    resolve_pkg_manager,
)
from .service_managers import (
    SERVICE_STRATEGIES,
    OpenRCStrategy,
    ServiceAction,
    ServiceManagerStrategy,
    ServiceState,
    SystemdStrategy,
    SysVStrategy,
    UniversalServiceStrategy,
    ensure_service,
    resolve_service_transition,
)
from .system import (
    UserAttributeSpec,
    build_useradd_command,
    ensure_authorized_key,
    ensure_sysctl,
    ensure_systemd_unit,
    ensure_user,
    resolve_user_home,
    transform_authorized_keys,
)

__all__ = [
    "PACKAGE_STRATEGIES",
    "SERVICE_STRATEGIES",
    "ApkStrategy",
    "AptStrategy",
    "ChangePlan",
    "DnfYumStrategy",
    "OpenRCStrategy",
    "PackageManagerStrategy",
    "PacmanStrategy",
    "PkgManagerName",
    "ServiceAction",
    "ServiceManagerStrategy",
    "ServiceState",
    "StateManagementService",
    "SysVStrategy",
    "SystemdStrategy",
    "UniversalServiceStrategy",
    "UserAttributeSpec",
    "ZypperStrategy",
    "_parse_mode",
    "apply_owner_group",
    "build_useradd_command",
    "can_inspect_in_dry_run",
    "ensure_authorized_key",
    "ensure_directory",
    "ensure_file",
    "ensure_line",
    "ensure_package",
    "ensure_service",
    "ensure_sysctl",
    "ensure_systemd_unit",
    "ensure_user",
    "extract_stat_mode",
    "get_owner_group",
    "resolve_pkg_manager",
    "resolve_service_transition",
    "resolve_user_home",
    "transform_authorized_keys",
    "transform_lines_absent",
    "transform_lines_present",
]
