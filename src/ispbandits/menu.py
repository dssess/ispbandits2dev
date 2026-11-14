"""Interactive Neverbandits administration dashboard."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from io import StringIO
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import socket
import subprocess
import sys

from . import database
from . import menu_actions, menu_ui
from .menu_ui import show_result

NOTICE = "© 2026 ISPbandits Dev. All rights reserved. Proprietary software."
WIDTH = 68
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


class _Colors:
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[1;31m"
    MAGENTA = "\033[1;35m"
    RESET = "\033[0m"


class _TeeStream:
    """Capture emitted CLI text while forwarding it immediately to the terminal."""

    def __init__(self, original: object) -> None:
        self._original = original
        self._capture_tail = ""

    def write(self, text: str) -> int:
        self._capture_tail = (self._capture_tail + text)[-4096:]
        return self._original.write(text)  # type: ignore[attr-defined, no-any-return]

    def flush(self) -> None:
        self._original.flush()  # type: ignore[attr-defined]

    def isatty(self) -> bool:
        return bool(self._original.isatty())  # type: ignore[attr-defined]

    @property
    def encoding(self) -> str | None:
        return getattr(self._original, "encoding", None)

    @property
    def captured_text(self) -> str:
        return self._capture_tail

    def __getattr__(self, name: str) -> object:
        return getattr(self._original, name)


def _colors_enabled() -> bool:
    return bool(sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ)


def _paint(text: str, color: str) -> str:
    return f"{color}{text}{_Colors.RESET}" if _colors_enabled() else text


def _frame(char: str = "─") -> str:
    return _paint("┌" + char * WIDTH + "┐" if char == "─" else "├" + char * WIDTH + "┤", _Colors.CYAN)


def _bottom_frame() -> str:
    return _paint("└" + "─" * WIDTH + "┘", _Colors.CYAN)


def _box_line(text: str = "") -> str:
    visible = _ANSI_RE.sub("", text)
    if len(visible) > WIDTH:
        text = visible[:WIDTH]
        visible = text
    text += " " * max(0, WIDTH - len(visible))
    return f"{_paint('│', _Colors.CYAN)}{text}{_paint('│', _Colors.CYAN)}"


def _uptime() -> str:
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return "unknown"
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _memory() -> str:
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(value.split()[0])
    except (OSError, ValueError, IndexError):
        return "unknown"
    if not {"MemTotal", "MemAvailable"}.issubset(values):
        return "unknown"
    total = values["MemTotal"] // 1024
    used = (values["MemTotal"] - values["MemAvailable"]) // 1024
    return f"{used} / {total} MiB"


def _load() -> str:
    try:
        values = os.getloadavg()
        cores = os.cpu_count() or 1
        return f"{values[0]:.2f} / {cores} cores"
    except (OSError, AttributeError):
        return "unknown"


def _domain() -> str:
    marker = Path("/opt/ispbandits-dev/INSTALL_INFO")
    try:
        for line in marker.read_text(encoding="utf-8").splitlines():
            if line.startswith("domain="):
                return line.partition("=")[2].strip() or "not configured"
    except OSError:
        pass
    return "not configured"


def _service_state(unit: str) -> str:
    try:
        result = subprocess.run(["systemctl", "is-active", unit], check=False,
                                capture_output=True, text=True, timeout=2)
        state = result.stdout.strip() or "inactive"
    except (OSError, subprocess.TimeoutExpired):
        state = "unavailable"
    return state


def _collect_checks(checks: list[tuple[str, Callable[[], object]]], timeout: float = 4.0) -> dict[str, str]:
    """Run bounded independent status probes concurrently; pending probes become unknown."""
    if not checks:
        return {}
    executor = ThreadPoolExecutor(max_workers=min(8, len(checks)))
    futures = {executor.submit(check): label for label, check in checks}
    done, pending = wait(futures, timeout=timeout)
    states: dict[str, str] = {}
    for future in done:
        label = futures[future]
        try:
            states[label] = str(future.result())
        except Exception:
            states[label] = "unavailable"
    for future in pending:
        states[futures[future]] = "unknown (probe timed out)"
        future.cancel()
    executor.shutdown(wait=False, cancel_futures=True)
    return states


def _service_badge(label: str, unit: str) -> str:
    state = _service_state(unit)
    color = _Colors.GREEN if state == "active" else _Colors.RED
    return f"{_paint(label, _Colors.CYAN)} {_paint('[' + state.upper() + ']', color)}"


def _tcp_listener_state(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=1):
            return "ready"
    except OSError:
        return "unreachable"


def _xray_api_state() -> str:
    try:
        result = subprocess.run(
            ["/usr/local/bin/xray", "api", "statsquery", "--server=127.0.0.1:10085"],
            check=False, capture_output=True, text=True, timeout=3,
        )
        return "ready" if result.returncode == 0 else "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def _server_summary(db_path: Path) -> list[str]:
    try:
        os_info = platform.freedesktop_os_release().get("PRETTY_NAME", platform.system())
    except (OSError, AttributeError):
        os_info = platform.system()
    try:
        rows = database.list_usage(db_path)
    except Exception:
        rows = []
    active = sum(1 for row in rows if str(row["status"]).upper() == "ACTIVE")
    expired = sum(1 for row in rows if str(row["status"]).upper() == "EXPIRED")
    quota = sum(1 for row in rows if str(row["status"]).upper() == "QUOTA_EXCEEDED")
    measured = sum(int(row["measured_bytes"]) for row in rows)
    traffic_gb = measured / 1_000_000_000
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    try:
        kernel = platform.release()
    except Exception:
        kernel = "unknown"
    return [
        f"Host            : {hostname}",
        f"Operating system: {os_info}",
        f"Kernel          : {kernel}",
        f"Uptime          : {_uptime()}   Load: {_load()}",
        f"Memory used     : {_memory()}",
        f"Primary domain  : {_domain()}",
        f"Accounts        : {active} active / {len(rows)} total | expired {expired} | quota-locked {quota}",
        f"Measured traffic: {traffic_gb:.3f} GB stored measured counters",
    ]


def _database_counts(db_path: Path) -> dict[str, int] | None:
    """Read dashboard counts with a short, read-only SQLite timeout."""
    try:
        uri = f"{db_path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=0.5)
        try:
            conn.execute("PRAGMA busy_timeout = 500")
            rows = conn.execute(
                "SELECT upper(coalesce(status, 'UNKNOWN')), COUNT(*) FROM users GROUP BY upper(coalesce(status, 'UNKNOWN'))"
            ).fetchall()
            measured_bytes = int(conn.execute(
                "SELECT coalesce(sum(upload_bytes + download_bytes), 0) FROM traffic_totals"
            ).fetchone()[0])
            protocol_rows = conn.execute(
                """SELECT lower(p.protocol), p.user_id
                   FROM protocol_accounts AS p JOIN users AS u ON u.id=p.user_id
                   WHERE p.enabled=1 AND upper(coalesce(u.status, ''))='ACTIVE'"""
            ).fetchall()
        finally:
            conn.close()
        counts = {str(status): int(count) for status, count in rows}
        protocol_users: dict[str, set[int]] = {"ssh": set(), "vless": set(), "trojan": set()}
        for protocol, user_id in protocol_rows:
            protocol = str(protocol)
            if protocol in {"openssh", "dropbear"}:
                protocol_users["ssh"].add(int(user_id))
            elif protocol in {"vless", "trojan"}:
                protocol_users[protocol].add(int(user_id))
        return {
            "total": sum(counts.values()),
            "active": counts.get("ACTIVE", 0),
            "disabled": counts.get("DISABLED", 0),
            "expired": counts.get("EXPIRED", 0),
            "quota": counts.get("QUOTA_EXCEEDED", 0),
            "measured_bytes": measured_bytes,
            "protocol_counts": {key: len(user_ids) for key, user_ids in protocol_users.items()},
        }
    except (OSError, sqlite3.Error, ValueError):
        return None


def _memory_percent() -> str:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            name, _, raw = line.partition(":")
            if name in {"MemTotal", "MemAvailable"}:
                values[name] = int(raw.split()[0])
        total, available = values["MemTotal"], values["MemAvailable"]
        return f"{max(0, min(100, round((total - available) * 100 / total)))}%"
    except (OSError, ValueError, KeyError, ZeroDivisionError, IndexError):
        return "unknown"


def _storage_summary() -> str:
    try:
        usage = shutil.disk_usage("/")
        percent = round(usage.used * 100 / usage.total) if usage.total else 0
        return f"{percent}% used ({usage.used // (1024 ** 3)} / {usage.total // (1024 ** 3)} GiB)"
    except OSError:
        return "unavailable"


def _public_interface_ip() -> str:
    """Report a public address assigned locally; do not query an external service."""
    try:
        result = subprocess.run(["ip", "-j", "address", "show", "scope", "global"],
                                check=False, capture_output=True, text=True, timeout=1.5)
        if result.returncode:
            return "not detected locally"
        import ipaddress
        candidates = []
        for interface in json.loads(result.stdout or "[]"):
            for address in interface.get("addr_info", []):
                raw = address.get("local")
                if raw:
                    parsed = ipaddress.ip_address(raw)
                    if parsed.is_global:
                        candidates.append((parsed.version != 4, str(parsed)))
        return sorted(candidates)[0][1] if candidates else "not detected locally"
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        return "not detected locally"


def _cpu_details() -> tuple[str, str]:
    """Read CPU identity/frequency locally; report load, not a fabricated CPU-percent sample."""
    model = "unknown"
    frequencies: list[float] = []
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="ascii").splitlines():
            key, _, value = line.partition(":")
            if key.strip().lower() == "model name" and model == "unknown":
                model = value.strip() or model
            elif key.strip().lower() == "cpu mhz":
                frequencies.append(float(value.strip()))
    except (OSError, ValueError):
        pass
    cores = os.cpu_count() or 1
    frequency = f"{max(frequencies):.0f} MHz" if frequencies else "frequency unavailable"
    try:
        load = f"load {os.getloadavg()[0]:.2f}"
    except (OSError, AttributeError):
        load = "load unavailable"
    return model, f"{cores} Cores @ {frequency} ({load})"


def _uptime_readable() -> str:
    try:
        seconds = int(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0]))
    except (OSError, ValueError, IndexError):
        return "unknown"
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    if days:
        return f"{days} days, {hours} hours"
    if hours:
        return f"{hours} hours, {minutes} minutes"
    return f"{minutes} minutes"


def _ssh_unit_state() -> str:
    state = _service_state("ssh.service")
    return state if state == "active" else _service_state("sshd.service")


def _dashboard_snapshot(db_path: Path) -> dict[str, object]:
    try:
        os_info = platform.freedesktop_os_release().get("PRETTY_NAME", platform.system())
    except (OSError, AttributeError):
        os_info = platform.system()
    try:
        kernel = platform.release()
    except OSError:
        kernel = "unknown"
    counts = _database_counts(db_path)
    cpu_name, cpu_info = _cpu_details()
    total = str(counts.get("total", "unavailable")) if counts else "unavailable"
    active = str(counts.get("active", "unavailable")) if counts else "unavailable"
    disabled = str(counts.get("disabled", "unavailable")) if counts else "unavailable"
    measured = (f"{counts.get('measured_bytes', 0) / 1_000_000_000:.3f} GB stored account counters"
                if counts else "unavailable")
    overview = [
        f"OS Linux        : {os_info}",
        f"Kernel          : {kernel}",
        f"CPU Name        : {cpu_name}",
        f"CPU Info        : {cpu_info}",
        f"Total RAM       : {_memory()} ({_memory_percent()})",
        f"System Uptime   : {_uptime_readable()}",
        f"Current Domain  : {_domain()}",
        f"IP-VPS          : {_public_interface_ip()}",
    ]
    account_rows = [
        f"TOTAL ACCOUNTS     {total}",
        f"ACTIVE ACCOUNTS    {active}",
        f"DISABLED ACCOUNTS  {disabled}",
        (f"EXPIRED / QUOTA    {counts.get('expired', 'unavailable')} / {counts.get('quota', 'unavailable')}"
         if counts else "EXPIRED / QUOTA    unavailable"),
        f"Measured account traffic: {measured}",
        "ONLINE SSH         Not sampled on dashboard; see Traffic & Quota (approximate process counts)",
    ]
    service_checks = [
        ("SSH unit", _ssh_unit_state),
        ("NGINX unit", lambda: _service_state("nginx.service")),
        ("XRAY unit", lambda: _service_state("ispbandits-xray.service")),
        ("DROPBEAR unit", lambda: _service_state("dropbear.service")),
        ("SSH-WS unit", lambda: _service_state("neverbandits-ssh-http.service")),
        ("SSH-WS port", lambda: _tcp_listener_state("127.0.0.1", 80)),
        ("VLESS port", lambda: _tcp_listener_state("127.0.0.1", 10001)),
        ("TROJAN port", lambda: _tcp_listener_state("127.0.0.1", 10002)),
    ]
    service_states = _collect_checks(service_checks)
    health = [(label, service_states.get(label, "unavailable")) for label, _ in service_checks]
    health.append(("DATABASE", "available" if counts is not None else "unavailable"))
    protocol_counts = counts.get("protocol_counts") if counts else None
    return {"overview": overview, "health": health, "accounts": account_rows,
            "protocol_counts": protocol_counts}


_QUICK_ACTION_LABELS = tuple(
    f"[{item.key.zfill(2) if item.key.isdigit() and len(item.key) < 2 else item.key}] {item.label}"
    for item in menu_actions.REFERENCE_MENU
)


def _show_dashboard(db_path: Path) -> None:
    sections = [(key, str(menu_actions.SECTIONS[key]["title"]))
                for key in menu_actions.MAIN_SECTIONS]
    menu_ui.show_dashboard(_dashboard_snapshot(db_path), sections, _QUICK_ACTION_LABELS,
                           reference_options=menu_actions.REFERENCE_MENU)


def _call_cli(db_path: Path, *arguments: str) -> int:
    """Dispatch a menu action through the same CLI handlers used by operators."""
    from .cli import main as cli_main
    return cli_main(["--db", str(db_path), *arguments])


def _pause() -> None:
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def _invoke_cli(db_path: Path, *arguments: str) -> tuple[str, str]:
    """Run the existing CLI handler, preserve its output, and classify its result."""
    stderr_capture = StringIO()
    stdout_tee = _TeeStream(sys.stdout)
    try:
        with redirect_stdout(stdout_tee), redirect_stderr(stderr_capture):
            return_code = _call_cli(db_path, *arguments)
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Operation cancelled; no changes were made."
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        return "FAILED", str(exc)

    stderr_text = stderr_capture.getvalue()
    if stderr_text:
        sys.stderr.write(stderr_text)
        sys.stderr.flush()
    if return_code == 0:
        return "SUCCESS", "Operation completed."
    combined_output = stdout_tee.captured_text + stderr_text
    cancellation_signature = "account creation cancelled; no changes were made"
    output_lines = {line.strip().lower() for line in combined_output.splitlines()}
    output_lines.update(line.removeprefix("error:").strip()
                        for line in tuple(output_lines) if line.startswith("error:"))
    if cancellation_signature in output_lines:
        return "CANCELLED", "Operation cancelled; no changes were made."
    return "FAILED", f"Operation failed (CLI exit code {return_code})."


def _create_protocol_account(db_path: Path, command: str, label: str) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "Account creation requires root. Start the menu as root: sudo menu"
    result, message = _invoke_cli(db_path, command)
    if result == "FAILED":
        return result, f"{label} account was not created. Correct the reported issue and try again. {message}"
    return result, message


def _set_quota(db_path: Path) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "Changing account quotas requires root. Start the menu with: sudo menu"
    try:
        username = input("Account username: ").strip()
        if not username:
            return "CANCELLED", "Quota update cancelled; username was empty."
        limit = int(input("New shared lifetime quota in GB [0 = unlimited]: ").strip())
        if limit < 0:
            return "FAILED", "Quota must be a non-negative whole number of GB."
        return _invoke_cli(db_path, "quota-set", username, "--limit-gb", str(limit))
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Quota update cancelled; no changes were made."
    except ValueError:
        return "FAILED", "Quota must be a non-negative whole number of GB."


def _root_action(db_path: Path, command: str, prompt: str, extra: tuple[str, ...] = ()) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "This operation requires root. Start the menu with: sudo menu"
    try:
        username = input(prompt).strip()
        if not username:
            return "CANCELLED", "Operation cancelled; username was empty."
        if command == "renew":
            expiry = input("New expiry date (YYYY-MM-DD): ").strip()
            if not expiry:
                return "CANCELLED", "Renewal cancelled; no changes were made."
            return _invoke_cli(db_path, "renew", username, "--expires", expiry)
        else:
            return _invoke_cli(db_path, command, username, *extra)
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Operation cancelled; no changes were made."


def _delete_account(db_path: Path) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "Account deletion requires root. Start the menu with: sudo menu"
    try:
        username = input("Account username to permanently delete: ").strip()
        if not username:
            return "CANCELLED", "Deletion cancelled; no account was changed."
        confirm = input(f"This permanently deletes {username} and its usage. Type the username again: ").strip()
        if confirm != username:
            return "CANCELLED", "Confirmation did not match; no changes made."
        return _invoke_cli(db_path, "account-delete", username, "--yes")
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Deletion cancelled; no changes were made."


def _restore_database(db_path: Path) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "Database restore requires root. Start the menu with: sudo menu"
    try:
        archive = input("Absolute path to ISPbandits backup archive: ").strip()
        if not archive.startswith("/"):
            return "FAILED", "Use an absolute archive path; no changes made."
        confirm = input("Restore replaces the current database; a rollback backup will be saved. Type RESTORE: ").strip()
        if confirm != "RESTORE":
            return "CANCELLED", "Restore cancelled; no changes made."
        result, message = _invoke_cli(db_path, "restore", archive, "--confirm", "RESTORE",
                                      "--dir", "/var/backups/ispbandits-dev")
        if result == "SUCCESS":
            print("Important: database restore does not restore OS accounts, certificates, or service files.")
        return result, message
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Restore cancelled; no changes were made."


def _diagnostic_rows(db_path: Path) -> list[tuple[str, str]]:
    """Return independent systemd, local endpoint/API, and database checks."""
    checks = [
        ("Nginx frontend", lambda: _service_state("nginx.service")),
        ("Xray core", lambda: _service_state("ispbandits-xray.service")),
        ("SSH HTTP Custom port 80", lambda: _service_state("neverbandits-ssh-http.service")),
        ("Nginx TLS listener 127.0.0.1:443", lambda: _tcp_listener_state("127.0.0.1", 443)),
        ("SSH relay listener 127.0.0.1:80", lambda: _tcp_listener_state("127.0.0.1", 80)),
        ("Xray StatsService API", _xray_api_state),
        ("VLESS inbound listener only", lambda: _tcp_listener_state("127.0.0.1", 10001)),
        ("Trojan inbound listener only", lambda: _tcp_listener_state("127.0.0.1", 10002)),
        ("Database", lambda: "available" if _database_counts(db_path) is not None else "unavailable"),
    ]
    states = _collect_checks(checks, timeout=4.0)
    return [(label, states.get(label, "unavailable")) for label, _ in checks]


def _service_status(db_path: Path | None = None) -> None:
    menu_ui.show_diagnostics(_diagnostic_rows(db_path or database.DEFAULT_DB))


def _execute_action(db_path: Path, action_id: int) -> tuple[str, str]:
    action = menu_actions.ACTIONS.get(action_id)
    if action is None:
        return "FAILED", f"Unknown action ID: {action_id}"
    if action.requires_root and os.geteuid() != 0:
        return "FAILED", "This operation requires root. Start the menu with: sudo menu"

    if action.handler == "protocol_create":
        labels = {1: "HTTP Custom SSH", 2: "VLESS", 3: "Trojan"}
        return _create_protocol_account(db_path, action.command or "", labels[action_id])
    if action.handler == "cli":
        if action_id == 8:
            return _invoke_cli(db_path, "backup", "--dir", "/var/backups/ispbandits-dev")
        return _invoke_cli(db_path, action.command or "")
    if action.handler == "diagnostics":
        _service_status(db_path)
        return "SUCCESS", "Diagnostics refreshed; external client connectivity remains untested."
    if action.handler == "quota":
        return _set_quota(db_path)
    if action.handler == "account":
        prompts = {
            12: ("account-show", "Account username: "),
            13: ("renew", "Account username: "),
            14: ("disable", "Account username to disable: "),
            15: ("enable", "Account username to enable: "),
            16: ("ssh-password-reset", "Account username: "),
        }
        command, prompt = prompts[action_id]
        return _root_action(db_path, command, prompt)
    if action.handler == "delete":
        return _delete_account(db_path)
    if action.handler == "restore":
        return _restore_database(db_path)
    return "FAILED", f"No menu handler is registered for action {action_id}."


def _information_action(db_path: Path, item: str) -> tuple[str, str]:
    if item == "about":
        return _invoke_cli(db_path, "about")
    if item == "version":
        from . import __version__
        print(f"Neverbandits installed version: {__version__}")
        return "SUCCESS", "Version information displayed."
    if item == "server":
        menu_ui.panel("NEVERBANDITS / SERVER INFORMATION", _dashboard_snapshot(db_path)["overview"])
        return "SUCCESS", "Server information displayed."
    return "FAILED", "Unknown information action."


def _confirm_action(db_path: Path, phrase: str, prompt: str, *arguments: str) -> tuple[str, str]:
    if os.geteuid() != 0:
        return "FAILED", "This operation requires root. Start the menu with: sudo menu"
    try:
        confirmation = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "CANCELLED", "Operation cancelled; no changes were made."
    if confirmation != phrase:
        return "CANCELLED", "Confirmation did not match; no operation was run."
    return _invoke_cli(db_path, *arguments)


def _execute_reference_option(db_path: Path, key: str) -> tuple[str, str]:
    option = menu_actions.REFERENCE_MENU_BY_KEY.get(key)
    if option is None:
        return "FAILED", f"Unknown Nevermore menu option: {key}"
    if not option.available or option.action is None:
        return "FAILED", f"{option.label} is unavailable: {option.description}. No command was run."
    if isinstance(option.action, int):
        return _execute_action(db_path, option.action)
    if option.action == "about":
        return _information_action(db_path, "about")
    if option.action == "server":
        return _information_action(db_path, "server")
    if option.action == "reboot":
        return _confirm_action(
            db_path, "REBOOT", "This queues a server reboot and disconnects customers. Type REBOOT: ",
            "reboot", "--confirm", "REBOOT")
    if option.action == "restart":
        return _confirm_action(
            db_path, "RESTART", "This restarts managed services and may interrupt traffic. Type RESTART: ",
            "service-restart", "--confirm", "RESTART")
    if option.action == "tls-renew":
        return _confirm_action(
            db_path, "RENEW", "Certbot may briefly pause the port-80 SSH relay. Type RENEW: ",
            "tls-renew", "--confirm", "RENEW")
    if option.action in {"bandwidth", "process-list"}:
        return _invoke_cli(db_path, str(option.action))
    return "FAILED", f"No safe ISPBandits handler is registered for {option.label}."


def _section_actions(section: str) -> list[tuple[str, str, str]]:
    mapping = menu_actions.SUBMENU_KEYS[section]
    result = []
    for local_key, target in mapping.items():
        if isinstance(target, int):
            action = menu_actions.ACTIONS[target]
            result.append((local_key, action.label, action.description or action.command or "Existing operation"))
        else:
            labels = {"about": "About Neverbandits", "version": "Installed version", "server": "Server information"}
            result.append((local_key, labels[target], "Existing application or server information"))
    return result


def _section_extra(db_path: Path, section: str) -> list[str | tuple[str, str]]:
    if section == "C":
        return ["Permanent deletion removes the selected account and requires re-entering its username."]
    if section == "T":
        timer_checks = [
            ("Xray collection timer", lambda: _service_state("ispbandits-collect.timer")),
            ("Experimental SSH meter timer", lambda: _service_state("ispbandits-ssh-meter.timer")),
            ("Full quota collector timer", lambda: _service_state("ispbandits-ssh-collect.timer")),
        ]
        timer_states = _collect_checks(timer_checks)
        return [
            (f"{label}: {timer_states.get(label, 'unavailable')}",
             menu_ui.state_color(timer_states.get(label, "unavailable")))
            for label, _ in timer_checks
        ] + [
            "Quota sampling is not a hard real-time byte cap.",
        ]
    if section == "O":
        return ["SERVER INFORMATION"] + list(_dashboard_snapshot(db_path)["overview"])
    if section == "S":
        return ["Password changes affect the selected account.", "Store replacement credentials securely."]
    if section == "B":
        return ["Restore replaces the current database.", "Exact RESTORE confirmation is mandatory."]
    if section == "D":
        return ["SYSTEMD / LOCAL ENDPOINT / DATABASE RESULTS"] + [
            (f"{label:<34} {state.upper()}", menu_ui.state_color(state))
            for label, state in _diagnostic_rows(db_path)
        ] + [("External client connectivity: NOT TESTED", "yellow")]
    return []


def _dispatch_information(db_path: Path, choice: str) -> tuple[str, str] | None:
    target = menu_actions.SUBMENU_KEYS["I"].get(choice)
    if not isinstance(target, str):
        return None
    return _information_action(db_path, target)


def _dispatch_section_action(db_path: Path, section: str, choice: str) -> tuple[str, str] | None:
    if section == "I":
        return _dispatch_information(db_path, choice)
    target = menu_actions.SUBMENU_KEYS[section].get(choice)
    return _execute_action(db_path, target) if isinstance(target, int) else None


def _more_action_items() -> list[tuple[str, str, str]]:
    items = [
        (key, str(menu_actions.SECTIONS[key]["title"]),
         str(menu_actions.SECTIONS[key]["description"]))
        for key in menu_actions.MORE_SECTIONS
    ]
    items.append(("1", "LEGACY ISPBandits ACTIONS 1–18",
                  "All previous numbered account, traffic, backup, and recovery actions"))
    return items


def run_menu(db_path: Path) -> int:
    """Run the interactive NEXUS Control Centre; CLI commands remain the engine."""
    if not sys.stdin.isatty():
        print("The interactive menu needs a terminal. Run: sudo menu", file=sys.stderr)
        return 2

    section: str | None = None
    while True:
        try:
            menu_ui.clear_screen()
            if section is None:
                _show_dashboard(db_path)
                choice = input().strip()
                if choice in menu_actions.EXIT_KEYS:
                    print("Goodbye.")
                    return 0
                normalized = choice.upper()
                if normalized in menu_actions.MAIN_SECTIONS:
                    section = normalized
                    continue
                reference_key = str(int(choice)) if choice.isdigit() else choice
                if reference_key in menu_actions.REFERENCE_MENU_BY_KEY:
                    result, message = _execute_reference_option(db_path, reference_key)
                    show_result(result, message)
                    _pause()
                    continue
                show_result("FAILED", "Unknown selection. Choose a displayed number, L for More Actions, or X to exit.")
                _pause()
                continue

            if section == "L":
                menu_ui.show_more_actions(_more_action_items())
                choice = input().strip()
                if choice in {"0", "00"}:
                    section = None
                    continue
                if choice.upper() in {"Q", "X"}:
                    print("Goodbye.")
                    return 0
                if choice.upper() == "R":
                    section = None
                    continue
                lookup = choice.upper() if choice.isalpha() else choice
                target = menu_actions.SUBMENU_KEYS["L"].get(lookup)
                if target == "M":
                    section = "M"
                    continue
                if isinstance(target, str) and target in menu_actions.MORE_SECTIONS:
                    section = target
                    continue
                show_result("FAILED", "Unknown selection. Choose a displayed section, 1 for legacy actions, R, 0, or X.")
                _pause()
                continue

            section_meta = menu_actions.SECTIONS[section]
            title = str(section_meta["title"])
            description = str(section_meta["description"])
            extra = _section_extra(db_path, section)
            menu_ui.show_section(section, title, description, _section_actions(section), extra=extra)
            choice = input().strip()
            if choice in menu_actions.BACK_KEYS:
                section = "L"
                continue
            if choice in menu_actions.EXIT_KEYS:
                print("Goodbye.")
                return 0
            result = _dispatch_section_action(db_path, section, choice)
            if result is None:
                show_result("FAILED", "Unknown selection. Use a displayed action, B to return to More Actions, or 0 to exit.")
            else:
                show_result(*result)
            _pause()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Neverbandits.")
            return 0


__all__ = ["run_menu"]
