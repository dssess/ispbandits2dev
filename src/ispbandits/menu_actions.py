"""Declarative navigation registry for the Neverbandits terminal menu.

The Nevermore menu labels are presentation metadata. Existing ISPBandits CLI
handlers remain the authority for business operations; unsupported items are
shown honestly and are never dispatched.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    legacy_id: int
    label: str
    section: str
    handler: str
    command: str | None = None
    requires_root: bool = False
    confirmation: str | None = None
    description: str = ""


@dataclass(frozen=True)
class ReferenceOption:
    key: str
    label: str
    action: int | str | None
    available: bool
    description: str = ""
    dashboard: bool = True


ACTIONS: dict[int, Action] = {
    1: Action(1, "Create SSH / HTTP Custom account", "P", "protocol_create", "sshws-create", True),
    2: Action(2, "Create VLESS account", "P", "protocol_create", "vless-create", True),
    3: Action(3, "Create Trojan account", "P", "protocol_create", "trojan-create", True),
    4: Action(4, "Account usage", "T", "cli", "usage"),
    5: Action(5, "Online SSH sessions", "T", "cli", "online"),
    6: Action(6, "Service and local endpoint status", "D", "diagnostics"),
    7: Action(7, "Process account expiry", "O", "cli", "expire", True),
    8: Action(8, "Create database backup", "B", "cli", "backup", True),
    9: Action(9, "Verify database integrity", "D", "cli", "verify"),
    10: Action(10, "Set lifetime quota", "T", "quota", "quota-set", True),
    11: Action(11, "List all accounts", "C", "cli", "account-list"),
    12: Action(12, "View account details", "C", "account", "account-show", True),
    13: Action(13, "Renew account", "C", "account", "renew", True),
    14: Action(14, "Disable account", "C", "account", "disable", True),
    15: Action(15, "Enable account", "C", "account", "enable", True),
    16: Action(16, "Reset SSH account password", "S", "account", "ssh-password-reset", True),
    17: Action(17, "Permanently delete account", "C", "delete", "account-delete", True,
               confirmation="re-enter username"),
    18: Action(18, "Restore database", "B", "restore", "restore", True,
               confirmation="type RESTORE"),
}

# Dashboard options are implemented actions, numbered consecutively for quick entry.
REFERENCE_MENU: tuple[ReferenceOption, ...] = (
    ReferenceOption("1", "SSHWS", 1, True, "Create one managed SSH/HTTP Custom account"),
    ReferenceOption("2", "VLESS", 2, True, "Create one managed VLESS account"),
    ReferenceOption("3", "TROJAN", 3, True, "Create one managed Trojan account"),
    ReferenceOption("4", "REBOOT", "reboot", True, "Queues a server reboot after yes/no confirmation"),
    ReferenceOption("5", "RESTART", "restart", True, "Restarts managed services after yes/no confirmation"),
    ReferenceOption("6", "RENEW CERT", "tls-renew", True, "Validates the renewed certificate"),
    ReferenceOption("7", "RUNNING STATUS", 6, True, "Systemd and local endpoint diagnostics"),
    ReferenceOption("8", "USER BANDWIDTH", 4, True, "Stored per-account traffic totals"),
    ReferenceOption("9", "CHECK BANDWIDTH", "bandwidth", True, "Host daily and monthly vnStat totals"),
    ReferenceOption("10", "TASK MANAGER", "process-list", True, "Read-only process summary"),
    ReferenceOption("11", "BACKUP", 8, True, "Create a protected database backup"),
    ReferenceOption("12", "RESTORE", 18, True, "Validated database restore"),
    ReferenceOption("13", "INFO SCRIPT", "about", True, "Publisher and license", dashboard=False),
    ReferenceOption("14", "XRAY-CORE MENU", 6, True, "Service diagnostics", dashboard=False),
    ReferenceOption("15", "SERVER INFO", "server", True, "Server information", dashboard=False),
)
REFERENCE_MENU_BY_KEY = {item.key: item for item in REFERENCE_MENU}

EXIT_KEYS = frozenset({"0", "00", "q", "Q", "x", "X"})
BACK_KEYS = frozenset({"b", "B"})
REFRESH_KEYS = frozenset({"r", "R"})

SECTIONS: dict[str, dict[str, object]] = {
    "C": {
        "title": "CLIENT MANAGEMENT",
        "description": "Accounts, renewals and customer controls",
        "actions": (11, 12, 13, 15, 14, 17),
    },
    "P": {
        "title": "PROTOCOL MANAGEMENT",
        "description": "Create SSH / HTTP Custom, VLESS, or Trojan accounts",
        "actions": (1, 2, 3),
    },
    "T": {
        "title": "TRAFFIC & QUOTA",
        "description": "Host bandwidth estimates, active SSH process monitoring, and account quotas",
        "actions": (4, 5, 10),
    },
    "O": {
        "title": "SERVER OPERATIONS",
        "description": "Existing account-expiry maintenance",
        "actions": (7,),
    },
    "S": {
        "title": "SECURITY CENTRE",
        "description": "Managed SSH account password operation",
        "actions": (16,),
    },
    "B": {
        "title": "BACKUP & RECOVERY",
        "description": "Database backup and restoration",
        "actions": (8, 18),
    },
    "D": {
        "title": "DIAGNOSTICS",
        "description": "Systemd states, local checks, and database integrity",
        "actions": (6, 9),
    },
    "I": {
        "title": "SETTINGS & INFORMATION",
        "description": "Existing information commands and server summary",
        "actions": (),
    },
    "L": {
        "title": "MORE ACTIONS",
        "description": "Management sections and all existing ISPBandits actions",
        "actions": (),
    },
    "M": {
        "title": "LEGACY ISPBandits ACTIONS",
        "description": "All existing ISPBandits actions 1–18 remain available here",
        "actions": tuple(range(1, 19)),
    },
}

MAIN_SECTIONS = ("L",)
MORE_SECTIONS = ("C", "P", "T", "O", "S", "B", "D", "I")

# Local submenu numbering is distinct from the original Nevermore top-level keys.
SUBMENU_KEYS: dict[str, dict[str, int | str]] = {
    "C": {str(index + 1): action_id for index, action_id in enumerate(SECTIONS["C"]["actions"])},
    "P": {str(index + 1): action_id for index, action_id in enumerate(SECTIONS["P"]["actions"])},
    "T": {str(index + 1): action_id for index, action_id in enumerate(SECTIONS["T"]["actions"])},
    "O": {"1": 7},
    "S": {"1": 16},
    "B": {str(index + 1): action_id for index, action_id in enumerate(SECTIONS["B"]["actions"])},
    "D": {"1": 6, "2": 9},
    "I": {"1": "about", "2": "version", "3": "server"},
    "L": {**{key: key for key in MORE_SECTIONS}, "1": "M"},
    "M": {str(action_id): action_id for action_id in ACTIONS},
}

assert set(ACTIONS) == set(range(1, 19))
assert len(REFERENCE_MENU_BY_KEY) == len(REFERENCE_MENU)
