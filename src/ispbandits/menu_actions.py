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

# Option numbers and concise labels match the owner's Nevermore visual master.
# None is an explicit unsupported operation; it can only produce an explanation.
REFERENCE_MENU: tuple[ReferenceOption, ...] = (
    ReferenceOption("1", "SSHWS", 1, True, "Create one managed SSH/HTTP Custom account"),
    ReferenceOption("2", "VMESS", None, False, "VMess is not supported by this release"),
    ReferenceOption("3", "VLESS", 2, True, "Create one managed VLESS account"),
    ReferenceOption("4", "TROJAN", 3, True, "Create one managed Trojan account"),
    ReferenceOption("5", "SHADOWSOCKS", None, False, "Shadowsocks is not supported by this release"),
    ReferenceOption("6", "EXP FILES", None, False, "Expiry-file operations are not implemented"),
    ReferenceOption("7", "AUTO REBOOT", None, False, "No reboot scheduler is configured by this release"),
    ReferenceOption("8", "REBOOT", "reboot", True, "Queues a system reboot after exact confirmation"),
    ReferenceOption("9", "RESTART", "restart", True, "Restarts only managed Neverbandits services after confirmation"),
    ReferenceOption("11", "ADD HOST/DOMAIN", None, False, "Domain selection is an install-time operation; live mutation is not implemented"),
    ReferenceOption("12", "RENEW CERT", "tls-renew", True, "Runs the managed Certbot renewal check and validates the installed certificate"),
    ReferenceOption("13", "EDIT BANNER", None, False, "SSH banner editing is not implemented"),
    ReferenceOption("14", "RUNNING STATUS", 6, True, "Shows systemd and local endpoint diagnostics; external client access is not tested"),
    ReferenceOption("15", "USER BANDWIDTH", 4, True, "Shows stored per-account traffic counters"),
    ReferenceOption("16", "SPEEDTEST", None, False, "No speed-test backend is installed"),
    ReferenceOption("17", "CHECK BANDWIDTH", "bandwidth", True, "Shows host interface counters since boot; not per-user or daily usage"),
    ReferenceOption("18", "LIMIT SPEED", None, False, "Per-user rate limiting is not implemented"),
    ReferenceOption("19", "WEBMIN", None, False, "Webmin is not installed or managed by this release"),
    ReferenceOption("20", "INFO SCRIPT", "about", True, "Shows ISPBandits publisher, version, and license notice", dashboard=False),
    ReferenceOption("21", "CLEAR LOG", None, False, "Log deletion is not implemented"),
    ReferenceOption("22", "TASK MANAGER", "process-list", True, "Shows a read-only process summary"),
    ReferenceOption("23", "DNS CHANGER", None, False, "Host resolver changes are not implemented"),
    ReferenceOption("24", "NETFLIX CHECKER", None, False, "No regional streaming-connectivity checker is installed"),
    ReferenceOption("25", "TENDANG", None, False, "Per-user session disconnection is not implemented"),
    ReferenceOption("55", "XRAY-CORE MENU", 6, True, "Opens the service and local-endpoint diagnostics", dashboard=False),
    ReferenceOption("66", "INSTALL BBRPLUS", None, False, "Kernel congestion-control installation is not implemented"),
    ReferenceOption("77", "SWAPRAM MENU", "server", True, "Shows memory and swap context only; does not modify swap", dashboard=False),
    ReferenceOption("88", "BACKUP", 8, True, "Creates a protected SQLite backup"),
    ReferenceOption("99", "RESTORE", 18, True, "Validates archive integrity and requires exact RESTORE confirmation"),
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
        "description": "Usage, approximate SSH process monitoring, and limits",
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
