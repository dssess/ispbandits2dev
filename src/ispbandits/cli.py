"""Neverbandits administration CLI by ISPbandits Dev."""
from __future__ import annotations
import argparse
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import sys
import shutil
import subprocess
import tarfile
from . import __version__, database, backup
from . import collector
from . import sessions
from . import system_monitor
from . import xray_config
from . import provisioning
from . import ssh_meter

NOTICE = "© 2026 ISPbandits Dev. All rights reserved. Proprietary software."


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="neverbandits", description="Neverbandits unified VPS management")
    p.add_argument("--db", default=str(database.DEFAULT_DB), help="SQLite path (default: %(default)s)")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("menu", help="open the interactive administration menu")
    sub.add_parser("about", help="show publisher and copyright information")
    sub.add_parser("init", help="initialize or migrate the SQLite database")
    add = sub.add_parser("user-add", help="add a management account record (does not provision a Linux/Xray user yet)")
    add.add_argument("username")
    add.add_argument("--expires", required=True, help="expiry date YYYY-MM-DD")
    add.add_argument("--max-logins", type=int, default=2)
    add.add_argument("--limit-bytes", type=int, default=0)
    create = sub.add_parser("account-create", help="advanced account creation for explicitly selected protocols")
    create.add_argument("username")
    create.add_argument("--expires", required=True, help="expiry date YYYY-MM-DD")
    create.add_argument("--limit-gb", type=int, default=0,
                        help="shared lifetime quota in decimal GB (0 = unlimited); requires the active experimental meter and a fresh snapshot")
    create.add_argument("--protocols", nargs="+", choices=("openssh", "vless", "trojan"),
                        default=("openssh",))
    create.add_argument("--prompt-password", action="store_true",
                        help="prompt twice without echoing for a chosen OpenSSH password")
    sub.add_parser("sshws-create", help="interactively create one HTTP Custom SSH account on port 80 and show its connection sheet")
    sub.add_parser("vless-create", help="interactively create one VLESS account and import link")
    sub.add_parser("trojan-create", help="interactively create one Trojan account and import link")
    sub.add_parser("account-list", help="list accounts and provisioned protocol state without secrets")
    show = sub.add_parser("account-show", help="show one account, protocol state, and traffic breakdown without secrets")
    show.add_argument("username")
    renew = sub.add_parser("renew", help="set an account expiry date without clearing disabled/quota state")
    renew.add_argument("username")
    renew.add_argument("--expires", required=True, help="new expiry date YYYY-MM-DD")
    disable = sub.add_parser("disable", help="revoke all enabled protocol access for an account")
    disable.add_argument("username")
    enable = sub.add_parser("enable", help="reactivate an eligible disabled or renewed account")
    enable.add_argument("username")
    delete = sub.add_parser("account-delete", help="permanently remove an account after revoking access")
    delete.add_argument("username")
    delete.add_argument("--yes", action="store_true", help="confirm irreversible account and usage deletion")
    reset = sub.add_parser("ssh-password-reset", help="set a new SSH password for a managed OpenSSH account")
    reset.add_argument("username")
    quota = sub.add_parser("quota-set", help="set an account's shared lifetime quota in decimal GB")
    quota.add_argument("username")
    quota.add_argument("--limit-gb", type=int, required=True,
                       help="decimal GB (1 GB = 1,000,000,000 bytes); 0 = unlimited")
    link = sub.add_parser("link-protocol", help="link an external protocol identity to an account")
    link.add_argument("username")
    link.add_argument("protocol", choices=sorted(database.PROTOCOLS))
    link.add_argument("identity", help="SSH username or unique Xray stats email/tag; not a secret")
    link.add_argument("--credential-ref", help="reference to separately protected credentials, never the credential itself")
    sub.add_parser("usage", help="show stored per-account usage totals")
    sub.add_parser("online", help="show approximate online SSH/Dropbear process counts (not device counts)")
    sub.add_parser("expire", help="expire due accounts, lock Linux users, and reconcile active Xray config")
    xp = sub.add_parser("xray-provision", help="create a VLESS UUID or Trojan password for an existing account")
    xp.add_argument("username")
    xp.add_argument("protocol", choices=("vless", "trojan"))
    xp.add_argument("--rotate", action="store_true", help="replace an existing protocol credential")
    xc = sub.add_parser("xray-config", help="generate a protected, validated Xray VLESS/Trojan config")
    xc.add_argument("--cert-file", required=True, help="TLS certificate chain path")
    xc.add_argument("--key-file", required=True, help="TLS private key path")
    xc.add_argument("--output", default="/etc/ispbandits-dev/xray.json")
    xc.add_argument("--vless-port", type=int, default=10001,
                    help="loopback VLESS WebSocket port behind Nginx (default: %(default)s)")
    xc.add_argument("--trojan-port", type=int, default=10002,
                    help="loopback Trojan WebSocket port behind Nginx (default: %(default)s)")
    xc.add_argument("--legacy-trojan-port", type=int, default=None,
                    help="temporarily retain an old direct Trojan TLS listener during migration")
    xc.add_argument("--api-port", type=int, default=10085)
    xc.add_argument("--xray-bin", default=shutil.which("xray") or "/usr/local/bin/xray")
    xc.add_argument("--check-only", action="store_true", help="validate without writing the secret-bearing config")
    xc.add_argument("--apply", action="store_true", help="install config and restart ispbandits-xray.service with rollback on failure")
    b = sub.add_parser("backup", help="create an online SQLite backup archive")
    b.add_argument("--dir", default=None, help="backup directory (default: sibling backups/)")
    r = sub.add_parser("restore", help="validate and restore a backup; preserves a rollback backup")
    r.add_argument("archive")
    r.add_argument("--dir", default=None)
    r.add_argument("--confirm", choices=("RESTORE",), required=True,
                   help="required exact destructive-operation confirmation")
    v = sub.add_parser("verify", help="run SQLite integrity check")
    reboot = sub.add_parser("reboot", help="queue a server reboot after explicit confirmation")
    reboot.add_argument("--confirm", choices=("REBOOT",), required=True)
    restart = sub.add_parser("service-restart", help="restart only managed Nginx, Xray, and SSH relay services")
    restart.add_argument("--confirm", choices=("RESTART",), required=True)
    renew_tls = sub.add_parser("tls-renew", help="run the managed Certbot renewal check and validate the installed TLS certificate")
    renew_tls.add_argument("--confirm", choices=("RENEW",), required=True)
    sub.add_parser("bandwidth", help="show host network-interface byte counters; not per-user usage")
    sub.add_parser("process-list", help="show a read-only process summary")
    c = sub.add_parser("collect", help="collect Xray and SSH-meter counters atomically")
    c.add_argument("--dry-run", action="store_true", help="roll back after validating inputs")
    c.add_argument("--xray-only", action="store_true", help="collect VLESS/Trojan until the SSH network meter is installed")
    c.add_argument("--enforce-quotas", action="store_true",
                   help="after a full fresh Xray+SSH collection, disable accounts at their lifetime quota")
    meter = sub.add_parser("ssh-meter", help="sample the experimental OpenSSH per-session nftables meter")
    meter.add_argument("--state", default=str(ssh_meter.DEFAULT_STATE))
    meter.add_argument("--snapshot", default=str(ssh_meter.DEFAULT_SNAPSHOT))
    meter.add_argument("--sshd-bin", default="sshd")
    return p


def _quota_revoke(path: Path, usernames: list[str]) -> None:
    """Lock Linux sessions and remove quota-exceeded users from active Xray."""
    errors = []
    for username in usernames:
        try:
            if _has_managed_linux_ssh(path, username):
                provisioning.expire_linux_ssh_account(username)
        except Exception as exc:
            errors.append(f"{username}: {exc}")
    try:
        _reconcile_quota_xray(path)
    except Exception as exc:
        subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                       check=False, capture_output=True)
        raise RuntimeError("Quota-exceeded accounts were recorded, but Xray reconciliation failed; Xray was stopped fail-closed") from exc
    if errors:
        raise RuntimeError("Some SSH accounts could not be locked: " + "; ".join(errors))


def _reconcile_quota_xray(path: Path) -> None:
    _reconcile_xray_if_active(path)


def _quota_reactivate(path: Path, username: str, expiry_date: str) -> None:
    if _has_managed_linux_ssh(path, username):
        provisioning.reactivate_linux_ssh_account(username, expiry_date)
    _reconcile_xray_if_active(path)


def _has_managed_linux_ssh(path: Path, username: str) -> bool:
    try:
        return _managed_ssh_identity(database.get_account(path, username)) is not None
    except ValueError:
        return False


def _revoke_external_access(path: Path, username: str) -> None:
    account = database.get_account(path, username)
    ssh_identity = _managed_ssh_identity(account)
    if ssh_identity:
        provisioning.expire_linux_ssh_account(ssh_identity)
    try:
        _reconcile_xray_if_active(path)
    except Exception as exc:
        subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                       check=False, capture_output=True)
        raise RuntimeError("Account state changed, but Xray reconciliation failed; Xray was stopped fail-closed") from exc


def _activate_external_access(path: Path, username: str, expiry_date: str) -> None:
    account = database.get_account(path, username)
    ssh_identity = _managed_ssh_identity(account)
    try:
        if ssh_identity:
            provisioning.reactivate_linux_ssh_account(ssh_identity, expiry_date)
        _reconcile_xray_if_active(path)
    except Exception as exc:
        try:
            database.disable_user(path, username)
            if ssh_identity:
                provisioning.expire_linux_ssh_account(ssh_identity)
            _reconcile_xray_if_active(path)
        except Exception:
            subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                           check=False, capture_output=True)
        raise RuntimeError("Activation failed; the account was returned to a disabled state where possible") from exc


def _ssh_meter_timer_active() -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", "ispbandits-ssh-meter.timer"],
                              check=False, capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _quota_enforcement_timer_active() -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", "ispbandits-ssh-collect.timer"],
                              check=False, capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _xray_service_active() -> bool:
    return _service_active("ispbandits-xray.service")


def _service_active(unit: str) -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", unit],
                              check=False, capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ssh_meter_ready(path: Path) -> bool:
    if (not _ssh_meter_timer_active() or not _quota_enforcement_timer_active()
            or not _xray_service_active()):
        return False
    try:
        ssh_meter.load_managed_openssh_users(path)
        collector.read_ssh_samples()
        return True
    except (OSError, RuntimeError, ValueError, KeyError):
        return False


def _seed_new_account_checkpoints(path: Path, username: str, xray_active: bool,
                                  meter_active: bool) -> int:
    if not xray_active and not meter_active:
        return 0
    xray_samples = collector.read_xray_samples() if xray_active else []
    xray_gen = None
    if xray_active:
        xray_gen = xray_samples[0].generation if xray_samples else collector.xray_generation()
    ssh_samples = []
    if meter_active:
        ssh_meter.collect_snapshot(path)
        ssh_samples = collector.read_ssh_samples()
    return collector.seed_account_checkpoints(path, username, xray_samples,
                                              ssh_samples, xray_gen)


def _managed_ssh_identity(account: dict[str, object]) -> str | None:
    for protocol in account["protocols"]:
        if protocol["protocol"] == "openssh":
            return str(protocol["identity"])
    return None


def _reconcile_xray_if_active(path: Path) -> bool:
    active = _xray_service_active()
    output = Path("/etc/ispbandits-dev/xray.json")
    if not active and not output.exists():
        return False
    config = xray_config.build_config(path, "/etc/ispbandits-dev/tls/current/fullchain.pem",
                                     "/etc/ispbandits-dev/tls/current/privkey.pem",
                                     legacy_trojan_port=_legacy_trojan_port())
    expected = json.dumps(config, indent=2, sort_keys=True) + "\n"
    try:
        current = output.read_text(encoding="utf-8")
    except OSError:
        current = None
    if current != expected:
        if active:
            xray_config.apply_config(config, output, "/usr/local/bin/xray")
        else:
            xray_config.write_config(config, output)
    return active


def _systemd_active_state(unit: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=ActiveState", "--value", unit],
            check=False, capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Could not determine the current state of {unit}; no services were stopped") from exc
    state = result.stdout.strip().lower()
    if result.returncode != 0 or state not in {
        "active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "not-found",
    }:
        raise RuntimeError(f"Could not determine the current state of {unit}; no services were stopped")
    return state


def _resume_restore_units(path: Path, active_units: set[str],
                          timers: tuple[str, ...], services: tuple[str, ...]) -> list[str]:
    errors: list[str] = []
    try:
        _reconcile_xray_if_active(path)
    except Exception as exc:
        errors.append(f"Xray configuration reconciliation: {exc}")
        return errors
    ordered_services = ("ispbandits-xray.service",) + tuple(
        unit for unit in services if unit != "ispbandits-xray.service"
    )
    for unit in ordered_services:
        if unit not in active_units:
            continue
        try:
            result = subprocess.run(["systemctl", "start", unit], check=False,
                                    capture_output=True, timeout=30)
            if result.returncode != 0:
                errors.append(unit)
            elif unit == "ispbandits-xray.service" and not _xray_service_active():
                errors.append(unit)
        except (OSError, subprocess.SubprocessError):
            errors.append(unit)
    for unit in timers:
        if unit not in active_units:
            continue
        try:
            result = subprocess.run(["systemctl", "start", unit], check=False,
                                    capture_output=True, timeout=15)
            if result.returncode != 0:
                errors.append(unit)
        except (OSError, subprocess.SubprocessError):
            errors.append(unit)
    return errors


def _restore_managed_database(path: Path, archive: str, directory: Path) -> Path | None:
    timers = ("ispbandits-collect.timer", "ispbandits-ssh-collect.timer",
              "ispbandits-expire.timer", "ispbandits-ssh-meter.timer")
    services = ("ispbandits-collect.service", "ispbandits-ssh-collect.service",
                "ispbandits-expire.service", "ispbandits-ssh-meter.service",
                "ispbandits-xray.service")
    with backup.prepare_restore(archive, path.parent) as staged:
        # Snapshot every managed unit before changing service state. An unknown
        # systemd response aborts safely instead of assuming a unit was inactive.
        unit_states = {unit: _systemd_active_state(unit) for unit in (*timers, *services)}
        active_units = {unit for unit, state in unit_states.items() if state == "active"}
        stopped_units: list[str] = []
        for unit in (*timers, *services):
            if unit not in active_units:
                continue
            try:
                stopped = subprocess.run(["systemctl", "stop", unit], check=False,
                                         capture_output=True, timeout=15)
                state_after = _systemd_active_state(unit)
            except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                pause_error = f"Could not quiesce {unit}: {exc}"
                break
            if stopped.returncode != 0 or state_after == "active":
                pause_error = f"Could not quiesce managed unit {unit}"
                break
            stopped_units.append(unit)
        else:
            pause_error = ""
        if pause_error:
            recovery_errors = _resume_restore_units(path, active_units, timers, services)
            suffix = ("; recovery failed for: " + ", ".join(recovery_errors)) if recovery_errors else ""
            raise RuntimeError(pause_error + "; database was not restored" + suffix)

        rollback: Path | None = None
        try:
            rollback = backup.install_validated_restore(path, staged, directory)
            resume_errors = _resume_restore_units(path, active_units, timers, services)
            if resume_errors:
                raise RuntimeError("Previously active units failed to resume: " + ", ".join(resume_errors))
            return rollback
        except Exception as restore_error:
            # Prevent any partially resumed collector/Xray from operating while
            # restoring the rollback database.
            stop_errors = []
            for unit in reversed((*timers, *services)):
                if unit in active_units:
                    try:
                        stopped = subprocess.run(["systemctl", "stop", unit], check=False,
                                                 capture_output=True, timeout=15)
                        if stopped.returncode != 0:
                            stop_errors.append(unit)
                    except (OSError, subprocess.SubprocessError):
                        stop_errors.append(unit)

            rollback_error: Exception | None = None
            if rollback is not None and rollback.is_file():
                try:
                    with backup.prepare_restore(rollback, path.parent) as original:
                        backup.install_validated_restore(path, original, directory)
                except Exception as exc:
                    rollback_error = exc

            if rollback_error is None:
                recovery_errors = _resume_restore_units(path, active_units, timers, services)
                details = []
                if recovery_errors:
                    details.append("previously active units failed to resume: " + ", ".join(recovery_errors))
                if stop_errors:
                    details.append("units could not be stopped before rollback: " + ", ".join(stop_errors))
                suffix = ("; " + "; ".join(details)) if details else ""
                raise RuntimeError("Restore failed; the original database was preserved or rolled back" + suffix) from restore_error

            stopped_text = ", ".join(sorted(active_units)) or "none"
            if stop_errors:
                stopped_text += "; stop failed: " + ", ".join(stop_errors)
            raise RuntimeError(
                "CRITICAL: restore and database rollback both failed. Managed units were left stopped where possible "
                f"to avoid serving inconsistent state (previously active: {stopped_text}). Inspect archive {rollback}."
            ) from rollback_error


def _legacy_trojan_port() -> int | None:
    return 8443 if _install_info().get("trojan_legacy_8443") == "1" else None


def _install_info() -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        for line in Path("/opt/ispbandits-dev/INSTALL_INFO").read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                info[key] = value
    except OSError:
        pass
    return info


def _ssh_http_ready() -> bool:
    """Return true only for the managed HTTP Custom SSH listener on TCP port 80."""
    info = _install_info()
    if info.get("ssh_http_custom") != "1":
        return False
    if not _service_active("neverbandits-ssh-http.service"):
        return False
    try:
        target_port = int(info["ssh_target_port"])
        if not 1 <= target_port <= 65535:
            return False
        with socket.create_connection(("127.0.0.1", 80), timeout=2):
            pass
        with socket.create_connection(("127.0.0.1", target_port), timeout=2):
            return True
    except (KeyError, ValueError, OSError):
        return False


def _configured_ssh_ports() -> list[int]:
    sshd = shutil.which("sshd")
    if not sshd:
        return []
    try:
        result = subprocess.run([sshd, "-T"], check=False, capture_output=True,
                                text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode:
        return []
    ports = set()
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key.lower() == "port":
            try:
                port = int(value.strip())
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def _require_working_ssh_login(username: str) -> list[int]:
    """Refuse to hand out unusable password/tunnel accounts; never edit sshd config."""
    sshd = shutil.which("sshd")
    if not sshd:
        raise RuntimeError("OpenSSH server (sshd) is not installed; Neverbandits will not alter the administrator's SSH service")
    try:
        result = subprocess.run([sshd, "-T", "-C",
                                 f"user={username},host=localhost,addr=127.0.0.1"],
                                check=False, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not inspect effective sshd settings; refusing to create an SSH account") from exc
    if result.returncode != 0:
        raise RuntimeError("sshd rejected its effective configuration; fix sshd before creating SSH accounts")
    settings = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key:
            settings[key.lower()] = value.strip().lower()
    if settings.get("passwordauthentication") != "yes":
        raise RuntimeError("Effective sshd PasswordAuthentication is not enabled for this account; no SSH config was changed")
    if settings.get("allowtcpforwarding") != "yes" or settings.get("disableforwarding") == "yes":
        raise RuntimeError("Effective sshd settings do not permit TCP forwarding for this account; no SSH config was changed")
    auth_methods = settings.get("authenticationmethods", "any")
    if auth_methods not in {"any", "password"}:
        raise RuntimeError("Effective sshd AuthenticationMethods requires more than the generated password; no SSH config was changed")
    active = False
    for unit in ("ssh.service", "sshd.service", "ssh.socket"):
        try:
            if subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False,
                              capture_output=True, timeout=4).returncode == 0:
                active = True
                break
        except (OSError, subprocess.TimeoutExpired):
            continue
    if not active:
        raise RuntimeError("OpenSSH daemon/socket is not active; start the existing ssh service before creating SSH users")
    ports = []
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key.lower() == "port":
            try:
                port = int(value.strip())
            except ValueError:
                continue
            if 1 <= port <= 65535:
                ports.append(port)
    return sorted(set(ports))


def _print_connection_details(username: str, credentials: list[dict[str, str]],
                              has_ssh: bool = False,
                              ssh_ports: list[int] | None = None,
                              expiry_date: str | None = None,
                              ssh_password: str | None = None,
                              limit_gb: int | None = None) -> None:
    info = _install_info()
    host = info.get("domain", "").strip()
    protocols = ([("SSH HTTP Custom", "") ] if has_ssh else [])
    protocols.extend((item["protocol"].upper(), item["protocol"])
                     for item in credentials if item.get("protocol") in {"vless", "trojan"})
    protocol_names = ", ".join(label for label, _protocol in protocols) or "Protocol details"
    protocol_kinds = {str(item.get("protocol", "")) for item in credentials}
    formatted_receipt = has_ssh or "trojan" in protocol_kinds

    addresses: list[str] = []
    if host:
        try:
            resolved = subprocess.run(["getent", "ahosts", host], check=False,
                                      capture_output=True, text=True, timeout=4)
            addresses = sorted({line.split()[0] for line in resolved.stdout.splitlines() if line.split()})
        except (OSError, subprocess.TimeoutExpired):
            pass

    def card(title: str, rows: list[tuple[str, str]]) -> None:
        width = 72
        print("╭" + "─" * (width - 2) + "╮")
        print("│ " + title[:width - 4].ljust(width - 4) + " │")
        print("├" + "─" * (width - 2) + "┤")
        for label, value in rows:
            line = f"{label:<16}: {value}"
            print("│ " + line.ljust(width - 4) + " │")
        print("╰" + "─" * (width - 2) + "╯")

    quota = "Unlimited" if limit_gb in (None, 0) else f"{limit_gb} GB lifetime (shared across protocols)"
    divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    def print_fields(rows: list[tuple[str, str]]) -> None:
        for label, value in rows:
            print(f"{label} : {value}")

    if not formatted_receipt:
        summary = [("Username", username), ("Protocol(s)", protocol_names)]
        if expiry_date:
            summary.append(("Expires", expiry_date))
        summary.append(("Bandwidth quota", quota))
        if host:
            summary.append(("Server", host))
            summary.append(("Server IP", ", ".join(addresses) if addresses else "DNS lookup unavailable"))
        card("NEVERBANDITS  |  ACCOUNT READY", summary)

    if has_ssh:
        if host and _ssh_http_ready():
            print_fields([
                ("Username", username),
                ("Password", ssh_password if ssh_password is not None else "not available"),
                ("Expired On", expiry_date or "Not set"),
                ("Bandwidth quota", quota),
            ])
            print(divider)
            print_fields([
                ("IP Address", ", ".join(addresses) if addresses else "DNS lookup unavailable"),
                ("Host", host),
                ("SSH-WS", "80"),
            ])
            print(divider)
            print("Payload (copy into HTTP Custom) :")
            print(f"GET / HTTP/1.1[crlf]Host: {host}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]")
        else:
            print_fields([
                ("Username", username),
                ("Expired On", expiry_date or "Not set"),
                ("Bandwidth quota", quota),
            ])
            print(divider)
            print_fields([
                ("IP Address", ", ".join(addresses) if addresses else "DNS lookup unavailable"),
                ("Host", host or "Not configured"),
                ("SSH-WS", "Unavailable (expected port 80)"),
            ])
            print("HTTP Custom relay is unavailable; no connection payload was issued.")

    from urllib.parse import quote
    for item in credentials:
        protocol = item.get("protocol")
        if protocol not in {"vless", "trojan"}:
            continue
        if not host:
            card(protocol.upper(), [("Status", "Hostname is not configured; no import link is available.")])
            continue
        if protocol == "vless":
            link = (f"vless://{item['credential']}@{host}:443?encryption=none&security=tls"
                    f"&sni={host}&type=ws&host={host}&path={quote('/vless', safe='')}#{username}-vless")
            rows = [
                ("Server", f"{host}:443"), ("Path", "/vless"), ("Transport", "WebSocket over TLS"),
            ]
            if formatted_receipt:
                rows.extend([("Expired On", expiry_date or "Not set"), ("Bandwidth quota", quota)])
            card("VLESS  |  WEBSOCKET + TLS", rows)
            print("VLESS import link (copy; secret shown once):")
            print(link)
            continue

        secret = item["credential"]
        escaped_secret = quote(secret, safe="")
        profile_name = quote(username, safe="")
        host_ip = f"{host} ({', '.join(addresses)})" if addresses else host
        print_fields([
            ("Remarks", username),
            ("Host/IP", host_ip),
            ("Port", "443"),
            ("Key", secret),
            ("Network", "ws"),
            ("Path", "/trojan-ws"),
        ])
        print(divider)
        link = (f"trojan://{escaped_secret}@{host}:443?path={quote('/trojan-ws', safe='')}"
                f"&security=tls&host={host}&type=ws&sni={host}#TROJAN_WS_{profile_name}")
        print(f"Link WS : {link}")
        print(divider)
        print_fields([
            ("Expired On", expiry_date or "Not set"),
            ("Bandwidth quota", quota),
        ])


def _rollback_unpublished_account(path: Path, username: str, ssh_password: object,
                                  xray_managed: bool) -> None:
    errors = []
    try:
        database.delete_user_record(path, username)
    except Exception as exc:
        errors.append(exc)
    if ssh_password:
        try:
            provisioning.delete_linux_ssh_account(username)
        except Exception as exc:
            errors.append(exc)
    if xray_managed:
        try:
            if errors:
                raise RuntimeError("Account record or Linux user cleanup failed")
            config = xray_config.build_config(
                path, "/etc/ispbandits-dev/tls/current/fullchain.pem",
                "/etc/ispbandits-dev/tls/current/privkey.pem",
                legacy_trojan_port=_legacy_trojan_port())
            if _xray_service_active():
                xray_config.apply_config(config, "/etc/ispbandits-dev/xray.json", "/usr/local/bin/xray")
            else:
                xray_config.write_config(config, "/etc/ispbandits-dev/xray.json")
        except Exception:
            subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                           check=False, capture_output=True)
            raise
    if errors:
        raise RuntimeError("Account record or Linux user cleanup failed") from errors[0]


def _create_managed_account(path: Path, username: str, expiry: str, limit_gb: int,
                            protocols: tuple[str, ...], ssh_password: str | None = None,
                            prompt_password: bool = False) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Creating managed system accounts requires root")
    database.validate_username(username)
    if limit_gb < 0:
        raise ValueError("--limit-gb must be zero or greater")
    if limit_gb and not _ssh_meter_ready(path):
        raise RuntimeError("A shared lifetime quota requires the experimental SSH meter, the full quota collector, and a fresh valid snapshot")
    install_info = _install_info()
    if install_info.get("full_xray") != "1":
        raise RuntimeError("A full Neverbandits network deployment is required before creating protocol accounts")
    if any(protocol in protocols for protocol in ("vless", "trojan")):
        if not install_info.get("domain"):
            raise RuntimeError("The full install marker has no client hostname; no protocol account was created")
        if not _xray_service_active():
            raise RuntimeError("Xray is not active; no VLESS/Trojan account was created")
        if not _service_active("nginx.service"):
            raise RuntimeError("Nginx is not active; no TLS/WebSocket protocol account was created")
    ssh_ports = _require_working_ssh_login(username) if "openssh" in protocols else []
    if "openssh" in protocols:
        if install_info.get("ssh_http_custom") != "1":
            raise RuntimeError("The port-80 HTTP Custom SSH relay is not installed; no account was created")
        if not _ssh_http_ready():
            raise RuntimeError("The HTTP Custom SSH relay or OpenSSH backend is not active; no account was created")
    if prompt_password:
        if "openssh" not in protocols:
            raise ValueError("--prompt-password requires openssh in --protocols")
        ssh_password = getpass.getpass("New SSH password: ")
        confirmation = getpass.getpass("Confirm SSH password: ")
        if not ssh_password or ssh_password != confirmation:
            raise ValueError("Passwords were empty or did not match; no account was created")

    result = provisioning.create_managed_account(
        path, username, expiry, protocols=tuple(protocols),
        data_limit=limit_gb * 1_000_000_000, ssh_password=ssh_password)
    xray_activated = False
    xray_active = _xray_service_active()
    xray_managed = xray_active or Path("/etc/ispbandits-dev/xray.json").exists()
    if result["xray_credentials"]:
        try:
            xray_activated = _reconcile_xray_if_active(path)
        except Exception as exc:
            _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
            raise RuntimeError("Account creation rolled back because Xray config activation failed") from exc
        if not xray_activated:
            try:
                _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
            except Exception as rollback_exc:
                raise RuntimeError("Xray stopped during account creation and rollback was incomplete") from rollback_exc
            raise RuntimeError("Account creation rolled back because Xray stopped before activation")
    meter_active = _ssh_meter_timer_active()
    if xray_active or meter_active:
        try:
            _seed_new_account_checkpoints(path, username, xray_active, meter_active)
        except Exception as exc:
            try:
                _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
            except Exception as rollback_exc:
                raise RuntimeError("Counter baseline failed and account rollback was incomplete; Xray was stopped if its configuration could not be reconciled") from rollback_exc
            raise RuntimeError("Account creation rolled back because initial traffic-counter checkpoints could not be established") from exc
    if "openssh" in protocols and not _ssh_http_ready():
        try:
            _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
        except Exception as rollback_exc:
            raise RuntimeError("HTTP Custom SSH service failed before credential disclosure and rollback was incomplete") from rollback_exc
        raise RuntimeError("Account creation rolled back because the HTTP Custom SSH service stopped")
    if any(protocol in protocols for protocol in ("vless", "trojan")) and not _service_active("nginx.service"):
        try:
            _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
        except Exception as rollback_exc:
            raise RuntimeError("Nginx failed before credential disclosure and rollback was incomplete") from rollback_exc
        raise RuntimeError("Account creation rolled back because Nginx stopped")
    if result["xray_credentials"] and not _xray_service_active():
        try:
            _rollback_unpublished_account(path, username, result["ssh_password"], xray_managed)
        except Exception as rollback_exc:
            raise RuntimeError("Xray failed before credential disclosure and rollback was incomplete") from rollback_exc
        raise RuntimeError("Account creation rolled back because Xray stopped")
    _print_connection_details(username, result["xray_credentials"],
                              "openssh" in protocols, ssh_ports,
                              result["expiry_date"], result["ssh_password"], limit_gb)
    if result["xray_credentials"] and xray_activated:
        print("Xray account is active. Save the import link; its credential is shown only once.")


def _interactive_protocol_create(path: Path, protocol: str) -> None:
    labels = {"openssh": "SSH HTTP Custom", "vless": "VLESS", "trojan": "Trojan"}
    if os.geteuid() != 0:
        raise PermissionError("Creating managed protocol accounts requires root")
    try:
        print(f"Create {labels[protocol]} account")
        username = input("Username : ").strip()
        database.validate_username(username)
        password = None
        if protocol == "openssh":
            password = getpass.getpass("Password : ")
            if not password:
                raise ValueError("Password cannot be empty")
            if any(character in password for character in ":\r\n"):
                raise ValueError("Password cannot contain colon or newline")
        raw_days = input("Expired (days): ").strip()
        try:
            days = int(raw_days)
        except ValueError as exc:
            raise ValueError("Expiry must be a whole number of days") from exc
        if not 1 <= days <= 3650:
            raise ValueError("Expiry must be between 1 and 3650 days")
        expiry = (dt.date.today() + dt.timedelta(days=days)).isoformat()
        raw_quota = input("Bandwidth quota (GB, lifetime; 0 = unlimited): ").strip()
        try:
            limit_gb = int(raw_quota)
        except ValueError as exc:
            raise ValueError("Quota must be a whole number of GB") from exc
        if limit_gb < 0:
            raise ValueError("Quota must be zero or greater")
        quota_label = "Unlimited" if limit_gb == 0 else f"{limit_gb} GB"
        print(f"\nExpires on: {expiry}  |  Lifetime quota: {quota_label}")
        print("Creating this protocol only; no other protocol will be added.\n")
        _create_managed_account(path, username, expiry, limit_gb, (protocol,), password)
    except (EOFError, KeyboardInterrupt) as exc:
        raise RuntimeError("Account creation cancelled; no changes were made") from exc


def _restart_managed_services() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Restarting managed services requires root")
    units = (
        ("Nginx", "nginx.service"),
        ("Xray", "ispbandits-xray.service"),
        ("SSH HTTP Custom relay", "neverbandits-ssh-http.service"),
    )
    installed = 0
    failures: list[str] = []
    for label, unit in units:
        load = subprocess.run(["systemctl", "show", "--property=LoadState", "--value", unit],
                              check=False, capture_output=True, text=True, timeout=5)
        if load.returncode != 0 or load.stdout.strip() != "loaded":
            print(f"{label}: not installed/loaded; skipped")
            continue
        installed += 1
        restart = subprocess.run(["systemctl", "restart", unit], check=False,
                                 capture_output=True, text=True, timeout=45)
        if restart.returncode != 0:
            failures.append(f"{label}: restart failed")
            print(f"{label}: restart FAILED")
            continue
        state = subprocess.run(["systemctl", "is-active", unit], check=False,
                               capture_output=True, text=True, timeout=5)
        if state.returncode == 0 and state.stdout.strip() == "active":
            print(f"{label}: active after restart")
        else:
            failures.append(f"{label}: not active after restart")
            print(f"{label}: not active after restart")
    if installed == 0:
        raise RuntimeError("No managed Nginx/Xray/SSH relay service units were found")
    if failures:
        raise RuntimeError("Managed service restart had failures: " + "; ".join(failures))
    print("Managed service restart checks passed. This does not test external customer connectivity.")


def _renew_managed_tls() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Certificate renewal requires root")
    domain = _install_info().get("domain", "").strip()
    if not domain:
        raise RuntimeError("No managed domain is configured")
    certbot = shutil.which("certbot")
    if not certbot:
        raise RuntimeError("Certbot is not installed; no renewal was attempted")
    result = subprocess.run([certbot, "renew", "--cert-name", domain], check=False,
                            capture_output=True, text=True, timeout=300)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"Certbot renewal check failed for {domain} (exit {result.returncode})")

    refresh = Path("/usr/local/sbin/ispbandits-dev-refresh-tls")
    if not refresh.is_file():
        refresh = Path(__file__).resolve().parents[2] / "scripts" / "refresh-tls.sh"
    if not refresh.is_file():
        raise RuntimeError("The managed TLS refresh helper is missing; certificate paths were not changed")
    applied = subprocess.run([str(refresh)], check=False, capture_output=True,
                             text=True, timeout=120)
    if applied.stdout:
        print(applied.stdout.rstrip())
    if applied.stderr:
        print(applied.stderr.rstrip(), file=sys.stderr)
    if applied.returncode != 0:
        raise RuntimeError("Renewed certificate could not be safely applied; inspect the TLS refresh journal")

    cert = Path("/etc/ispbandits-dev/tls/current/fullchain.pem")
    verified = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout",
                               "-checkhost", domain, "-checkend", "86400"],
                              check=False, capture_output=True, text=True, timeout=10)
    if verified.returncode != 0:
        raise RuntimeError(f"Installed certificate did not validate for {domain} or expires within 24 hours")
    logger = shutil.which("logger")
    if logger:
        subprocess.run([logger, "-t", "ispbandits-tls-renew",
                        f"certificate renewal check and validation succeeded for {domain}"],
                       check=False, capture_output=True, timeout=3)
    print(f"Certificate validated for {domain}; external client connectivity is not tested.")


def _host_bandwidth() -> None:
    snapshot = system_monitor.bandwidth_snapshot()
    if snapshot["source"] == "vnstat":
        print(f"Host bandwidth estimates for {snapshot['interface']} (vnStat):")
        print(f"  Today: {snapshot['daily']} (received {snapshot['received']}, sent {snapshot['sent']})")
        print(f"  Month: {snapshot['monthly']} ({snapshot['month']})")
        print("Host-interface totals; not per-user traffic or exact account quota usage.")
        return
    if snapshot["source"] == "kernel-since-boot":
        received = system_monitor.humanize_bytes(int(snapshot["received_bytes"]))
        sent = system_monitor.humanize_bytes(int(snapshot["sent_bytes"]))
        print(f"Host interface counters across {snapshot['interface']}:")
        print(f"  Received since boot/counter reset: {received}")
        print(f"  Sent since boot/counter reset:     {sent}")
        print("Daily/monthly totals unavailable (vnStat not reporting); not per-user usage.")
        return
    raise RuntimeError("Host network usage is unavailable: neither vnStat nor kernel interface counters could be read")


def _process_list() -> None:
    result = subprocess.run(["ps", "-eo", "pid,comm,pcpu,pmem", "--sort=-pcpu"],
                            check=False, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        raise RuntimeError("The process list could not be read")
    rows = result.stdout.splitlines()
    print("Top processes by CPU (read-only; command names only):")
    print("\n".join(rows[:16]))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    path = Path(args.db)
    if args.command is None or args.command == "menu":
        if args.command is None and not sys.stdin.isatty():
            parser().print_help()
            return 2
        from .menu import run_menu
        return run_menu(path)
    try:
        if args.command == "about":
            print(f"Neverbandits {__version__} | Publisher: ISPbandits Dev | {NOTICE}")
        elif args.command == "reboot":
            if os.geteuid() != 0:
                raise PermissionError("Queuing a server reboot requires root")
            result = subprocess.run(["systemctl", "reboot", "--no-block"], check=False,
                                    capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "systemd rejected the reboot request")
            print("Server reboot queued. Existing sessions will disconnect; no external service check is implied.")
        elif args.command == "service-restart":
            if args.confirm != "RESTART":
                raise ValueError("Managed service restart requires exact RESTART confirmation")
            _restart_managed_services()
        elif args.command == "tls-renew":
            if args.confirm != "RENEW":
                raise ValueError("Certificate renewal requires exact RENEW confirmation")
            _renew_managed_tls()
        elif args.command == "bandwidth":
            _host_bandwidth()
        elif args.command == "process-list":
            _process_list()
        elif args.command == "init":
            database.initialize(path)
            print(f"Database ready: {path}")
        elif args.command == "user-add":
            user_id = database.add_user(path, args.username, args.expires, args.max_logins, args.limit_bytes)
            print(f"Created account record id={user_id} username={args.username}; protocol provisioning is not yet enabled.")
        elif args.command == "account-create":
            _create_managed_account(path, args.username, args.expires, args.limit_gb,
                                    tuple(args.protocols), prompt_password=args.prompt_password)
        elif args.command == "sshws-create":
            _interactive_protocol_create(path, "openssh")
        elif args.command == "vless-create":
            _interactive_protocol_create(path, "vless")
        elif args.command == "trojan-create":
            _interactive_protocol_create(path, "trojan")
        elif args.command == "account-list":
            rows = database.list_accounts(path)
            if not rows:
                print("No accounts.")
            else:
                print(f"{'USERNAME':<20} {'STATUS':<16} {'EXPIRES':<12} {'PROTOCOLS':<28} {'QUOTA BYTES':>12}")
                for row in rows:
                    protocols = ",".join(p["protocol"] for p in row["protocols"]) or "none"
                    limit = int(row["data_limit"])
                    print(f"{row['username']:<20} {row['status']:<16} {row['expiry_date'][:10]:<12} {protocols:<28} {limit:>12}")
        elif args.command == "account-show":
            row = database.get_account(path, args.username)
            print(f"Account: {row['username']} | status={row['status']} | expiry={row['expiry_date'][:10]}")
            print(f"Lifetime quota: {row['data_limit']} bytes (0 means unlimited); max logins={row['max_logins']}")
            print("Protocols (credentials are never shown by account-show):")
            if not row["protocols"]:
                print("  none")
            for protocol in row["protocols"]:
                enabled = "enabled" if protocol["enabled"] else "disabled"
                provisioned = "credential stored" if protocol["credential_provisioned"] else "no managed secret"
                print(f"  {protocol['protocol']}: identity={protocol['identity']} [{enabled}; {provisioned}]")
            print("Usage by protocol (bytes):")
            if not row["traffic"]:
                print("  no counters collected")
            for traffic in row["traffic"]:
                print(f"  {traffic['protocol']}: upload={traffic['upload_bytes']} download={traffic['download_bytes']} legacy={traffic['legacy_bytes']} updated={traffic['updated_at']}")
        elif args.command == "renew":
            if os.geteuid() != 0:
                raise PermissionError("Renewing managed accounts requires root")
            old = database.get_account(path, args.username)
            result = database.renew_user(path, args.username, args.expires)
            if result["status"] == "ACTIVE":
                ssh_identity = _managed_ssh_identity(old)
                if ssh_identity:
                    provisioning.reactivate_linux_ssh_account(ssh_identity, args.expires)
                _reconcile_xray_if_active(path)
                print(f"Renewed {args.username} through {args.expires}; access remains ACTIVE.")
            else:
                print(f"Renewed expiry for {args.username} through {args.expires}; status remains {result['status']}.")
                if result["status"] == "EXPIRED":
                    print("After payment/authorization, run `neverbandits enable USER` to explicitly restore access.")
        elif args.command == "disable":
            if os.geteuid() != 0:
                raise PermissionError("Disabling managed accounts requires root")
            result = database.disable_user(path, args.username)
            _revoke_external_access(path, args.username)
            print(f"Account {args.username} is {result['status']}; linked OpenSSH sessions were terminated and Xray was reconciled where active.")
        elif args.command == "enable":
            if os.geteuid() != 0:
                raise PermissionError("Enabling managed accounts requires root")
            result = database.enable_user(path, args.username)
            _activate_external_access(path, args.username, str(result["expiry_date"]))
            print(f"Account {args.username} is ACTIVE through {result['expiry_date']}.")
        elif args.command == "account-delete":
            if os.geteuid() != 0:
                raise PermissionError("Deleting managed accounts requires root")
            if not args.yes:
                raise ValueError("Permanent deletion requires --yes; first make a backup if the records may be needed")
            account = database.get_account(path, args.username)
            ssh_identity = _managed_ssh_identity(account)
            database.disable_user(path, args.username)
            if ssh_identity:
                provisioning.expire_linux_ssh_account(ssh_identity)
            try:
                _reconcile_xray_if_active(path)
            except Exception as exc:
                subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                               check=False, capture_output=True)
                raise RuntimeError("Account is disabled but Xray reconciliation failed; Xray was stopped; record retained") from exc
            database.delete_user_record(path, args.username)
            if ssh_identity:
                provisioning.delete_linux_ssh_account(ssh_identity)
            print(f"Permanently removed {args.username} and its account/usage records.")
        elif args.command == "ssh-password-reset":
            if os.geteuid() != 0:
                raise PermissionError("Resetting managed SSH passwords requires root")
            account = database.get_account(path, args.username)
            ssh_identity = _managed_ssh_identity(account)
            if not ssh_identity:
                raise ValueError("This account has no managed OpenSSH identity")
            password = provisioning.reset_linux_ssh_password(ssh_identity)
            print(f"New OpenSSH password for {args.username} (shown once; store securely): {password}")
        elif args.command == "link-protocol":
            if _ssh_meter_timer_active() and args.protocol == "dropbear":
                raise ValueError("Dropbear is unsupported by the experimental per-user meter")
            if _ssh_meter_timer_active() and args.protocol == "vmess":
                raise ValueError("VMess is not part of this alpha's managed Xray configuration and cannot be covered by shared quota enforcement")
            if _ssh_meter_timer_active() and args.protocol == "openssh":
                if args.identity != args.username:
                    raise ValueError("Experimental OpenSSH metering requires the managed Linux username as its protocol identity")
                try:
                    pwd.getpwnam(args.identity)
                except KeyError as exc:
                    raise ValueError("Experimental OpenSSH metering requires an existing Linux account; use account-create") from exc
            database.link_protocol(path, args.username, args.protocol, args.identity, args.credential_ref)
            print(f"Linked {args.protocol} identity for {args.username}.")
        elif args.command == "quota-set":
            if os.geteuid() != 0:
                raise PermissionError("Changing account quotas requires root")
            if args.limit_gb < 0:
                raise ValueError("--limit-gb must be zero or greater")
            if args.limit_gb and not _ssh_meter_ready(path):
                raise RuntimeError("A shared lifetime quota requires the experimental SSH meter, the full quota collector, and a fresh valid snapshot")
            account = database.get_account(path, args.username)
            protocols = [(str(item["protocol"]), str(item["identity"]))
                         for item in account["protocols"]]
            must_validate_protocols = bool(args.limit_gb) or account["status"] == "QUOTA_EXCEEDED"
            unsupported = sorted({protocol for protocol, _identity in protocols} -
                                 {"openssh", "vless", "trojan"})
            if must_validate_protocols and unsupported:
                raise ValueError("Shared quota is not supported for this account's linked protocol(s): " + ", ".join(unsupported))
            if must_validate_protocols:
                for protocol, identity in protocols:
                    if protocol == "openssh":
                        if identity != args.username:
                            raise ValueError("Shared quota requires OpenSSH identity to match the managed Linux username")
                        try:
                            pwd.getpwnam(identity)
                        except KeyError as exc:
                            raise ValueError("Shared quota requires an existing managed Linux OpenSSH account") from exc
            result = database.set_data_limit(path, args.username, args.limit_gb * 1_000_000_000)
            if result["status"] == "QUOTA_EXCEEDED":
                _quota_revoke(path, [args.username])
            elif result["old_status"] == "QUOTA_EXCEEDED" and result["status"] == "ACTIVE":
                try:
                    _quota_reactivate(path, args.username, str(result["expiry_date"]))
                except Exception as exc:
                    database.restore_quota_lock(path, args.username, int(result["old_limit_bytes"]))
                    revoke_error = None
                    try:
                        _quota_revoke(path, [args.username])
                    except Exception as cleanup_exc:
                        revoke_error = cleanup_exc
                    if revoke_error:
                        raise RuntimeError(
                            "Quota lift failed and the database lock was restored, but external revocation needs operator verification: "
                            + str(revoke_error)) from exc
                    raise RuntimeError("Quota lift failed; the previous cap and external protocol lock were restored") from exc
            print(f"Quota for {args.username}: {args.limit_gb} GB lifetime; measured={result['measured_bytes']} bytes; status={result['status']}")
        elif args.command == "usage":
            for row in database.list_usage(path):
                quota = "unlimited" if not row["data_limit"] else f"{row['measured_bytes']}/{row['data_limit']} bytes"
                print(f"{row['username']:<20} {row['status']:<14} up={row['upload_bytes']} down={row['download_bytes']} measured={row['measured_bytes']} legacy={row['legacy_bytes']} quota={quota} expires={row['expiry_date']}")
        elif args.command == "online":
            rows = sessions.online_ssh_processes(path)
            print("ACTIVE SSH/Dropbear SESSIONS — observed daemon processes (approximate; not unique device counts)")
            print(f"Sampled at: {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}")
            if not rows:
                print("No active SSH/Dropbear processes observed.")
            else:
                print(f"{'USERNAME':<20} {'PROTOCOL':<10} {'OBSERVED PROCESSES':>18}")
                for row in rows:
                    print(f"{row['username']:<20} {row['protocol']:<10} {row['observed_processes']:>18}")
        elif args.command == "expire":
            if os.geteuid() != 0:
                raise PermissionError("Account expiry maintenance requires root")
            expired = database.expire_users(path)
            errors = []
            inactive = database.inactive_usernames(path)
            for username in inactive:
                try:
                    account = database.get_account(path, username)
                    ssh_identity = _managed_ssh_identity(account)
                    if ssh_identity:
                        provisioning.expire_linux_ssh_account(ssh_identity)
                except Exception as exc:
                    errors.append(f"{username}: {exc}")
            try:
                _reconcile_xray_if_active(path)
            except Exception as exc:
                subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                               check=False, capture_output=True)
                raise RuntimeError("Inactive users were revoked in the database, but Xray reconciliation failed; Xray was stopped fail-closed") from exc
            print(f"Expired accounts processed: {len(expired)}")
            print(f"Inactive accounts reconciled for external revocation: {len(inactive)}")
            if errors:
                raise RuntimeError("Some Linux accounts could not be locked: " + "; ".join(errors))
        elif args.command == "xray-provision":
            if os.geteuid() != 0:
                raise PermissionError("Xray credential management requires root")
            install_info = _install_info()
            if install_info.get("full_xray") != "1" or not install_info.get("domain"):
                raise RuntimeError("A full Neverbandits deployment with a configured hostname is required before provisioning Xray identities")
            if not _xray_service_active():
                raise RuntimeError("Xray is not active; no protocol credential was created")
            if not _service_active("nginx.service"):
                raise RuntimeError("Nginx is not active; no TLS/WebSocket credential was created")
            account = database.get_account(path, args.username)
            if int(account["data_limit"]) and not _ssh_meter_ready(path):
                raise RuntimeError("This account has a lifetime quota; the SSH meter, full quota collector, and fresh snapshot must be active before adding an Xray identity")
            previous = database.get_xray_protocol_state(path, args.username, args.protocol)
            secret = database.create_xray_protocol(path, args.username, args.protocol, rotate=args.rotate)
            try:
                if not _reconcile_xray_if_active(path):
                    raise RuntimeError("Xray stopped before the new credential was activated")
            except Exception as exc:
                try:
                    database.restore_xray_protocol_state(path, args.username, args.protocol, previous)
                    _reconcile_xray_if_active(path)
                except Exception:
                    subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                                   check=False, capture_output=True)
                raise RuntimeError("Xray credential was not activated; previous database credential restored where possible") from exc
            if not _xray_service_active() or not _service_active("nginx.service"):
                try:
                    database.restore_xray_protocol_state(path, args.username, args.protocol, previous)
                    _reconcile_xray_if_active(path)
                except Exception:
                    subprocess.run(["systemctl", "stop", "ispbandits-xray.service"],
                                   check=False, capture_output=True)
                raise RuntimeError("Xray/Nginx stopped before credential disclosure; previous protocol state was restored where possible")
            limit_gb = int(account["data_limit"]) // 1_000_000_000
            _print_connection_details(args.username, [secret],
                                      expiry_date=str(account["expiry_date"]),
                                      limit_gb=limit_gb)
            print("Active Xray configuration is validated; save the one-time import link.")
        elif args.command == "xray-config":
            if os.geteuid() != 0:
                raise PermissionError("Xray config generation requires root because it contains client credentials")
            legacy_trojan_port = (args.legacy_trojan_port if args.legacy_trojan_port is not None
                                  else _legacy_trojan_port())
            config = xray_config.build_config(path, args.cert_file, args.key_file,
                                             args.vless_port, args.trojan_port, args.api_port,
                                             legacy_trojan_port)
            xray_config.validate_with_xray(config, args.xray_bin)
            if args.check_only:
                print("Xray accepted the generated configuration; no file was written.")
            else:
                if args.apply:
                    output = xray_config.apply_config(config, args.output, args.xray_bin)
                else:
                    output = xray_config.write_config(config, args.output)
                print(f"Validated Xray config written with protected permissions: {output}")
        elif args.command == "backup":
            directory = Path(args.dir) if args.dir else path.parent / "backups"
            print(backup.create_backup(path, directory))
        elif args.command == "restore":
            if os.geteuid() != 0:
                raise PermissionError("Restoring the managed database requires root")
            directory = Path(args.dir) if args.dir else path.parent / "backups"
            rollback = _restore_managed_database(path, args.archive, directory)
            if rollback:
                print(f"Restore complete. Previous database saved at: {rollback}")
            else:
                print("Restore complete. No previous database existed to back up.")
            print("Archive integrity was validated before service quiescence; previously active managed units were resumed.")
        elif args.command == "verify":
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            finally:
                conn.close()
            print(result)
            return 0 if result == "ok" else 1
        elif args.command == "collect":
            if os.geteuid() != 0:
                raise PermissionError("Traffic collection requires root access to local service metadata")
            if args.enforce_quotas and (args.xray_only or args.dry_run):
                raise ValueError("Quota enforcement requires a committed full Xray+SSH collection")
            collector.DB_PATH = path
            samples, delta_bytes, resets = collector.collect(dry_run=args.dry_run, xray_only=args.xray_only)
            action = "dry-run (rolled back)" if args.dry_run else "committed"
            print(f"Collection {action}: counter_directions={samples}, delta_bytes={delta_bytes}, generation_changes={resets}")
            if args.enforce_quotas:
                newly_exceeded = database.enforce_data_quotas(path)
                quota_users = database.list_quota_exceeded_users(path)
                if quota_users:
                    _quota_revoke(path, quota_users)
                print(f"Lifetime quota enforcement: newly exceeded={len(newly_exceeded)}; accounts reconciled={len(quota_users)}")
        elif args.command == "ssh-meter":
            result = ssh_meter.collect_snapshot(path, state_path=Path(args.state),
                                                snapshot_path=Path(args.snapshot),
                                                sshd_bin=args.sshd_bin)
            print(f"Experimental SSH meter snapshot: active_flows={result['active_flows']} tracked_users={result['tracked_users']} generation={result['generation']}")
        return 0
    except (ValueError, OSError, RuntimeError, sqlite3.Error, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def menu_main() -> int:
    """Console-script entrypoint for the literal `menu` command."""
    return main(["menu"])


if __name__ == "__main__":
    raise SystemExit(main())
