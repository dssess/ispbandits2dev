"""Read-only active SSH/Dropbear process observations."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess


_IGNORED_USERS = {
    "root", "nobody", "syslog", "messagebus", "danted", "systemd-resolve",
}


def online_ssh_processes(database: Path | str) -> list[dict[str, object]]:
    """Return managed active accounts and observed daemon-process counts.

    This follows Nginxbandit's `ps -eo user=,pid=,comm=` algorithm. Only
    `sshd`, `sshd-session`, or Dropbear processes owned by managed accounts with `/bin/false`
    shells are counted. The value is a process-count estimate, not unique
    client-device identification.
    """
    if os.geteuid() != 0:
        raise PermissionError("Online SSH monitoring requires root to inspect all process owners")

    today = dt.date.today().isoformat()
    database_path = Path(database).resolve()
    conn = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True, timeout=2)
    try:
        records = conn.execute(
            """SELECT p.protocol, p.external_identity
               FROM protocol_accounts p
               JOIN users u ON u.id=p.user_id
               WHERE p.enabled=1 AND p.protocol IN ('openssh','dropbear')
                 AND upper(coalesce(u.status,''))='ACTIVE'
                 AND (u.expiry_date IS NULL OR substr(u.expiry_date,1,10) >= ?)
               ORDER BY p.external_identity, p.protocol""",
            (today,),
        ).fetchall()
    finally:
        conn.close()

    configured: dict[tuple[str, str], int] = {
        (str(protocol), str(identity)): 0 for protocol, identity in records
    }
    if not configured:
        return []

    try:
        result = subprocess.run(
            ["ps", "-eo", "user=,pid=,comm="], check=False,
            capture_output=True, text=True, timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("The active SSH process scan is unavailable") from exc
    if result.returncode != 0:
        raise RuntimeError("The active SSH process scan failed")

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        username, _pid, command = parts[:3]
        if command in {"sshd", "sshd-session"}:
            protocol = "openssh"
        elif command == "dropbear":
            protocol = "dropbear"
        else:
            continue
        if username in _IGNORED_USERS:
            continue
        try:
            account = pwd.getpwnam(username)
        except KeyError:
            continue
        if account.pw_shell != "/bin/false":
            continue
        key = (protocol, username)
        if key in configured:
            configured[key] += 1

    active_users: dict[str, dict[str, object]] = {}
    for (protocol, username), count in sorted(
        configured.items(), key=lambda item: (item[0][1], item[0][0])
    ):
        if not count:
            continue
        row = active_users.setdefault(
            username, {"username": username, "protocols": set(), "observed_processes": 0}
        )
        protocols = row["protocols"]
        assert isinstance(protocols, set)
        protocols.add(protocol)
        row["observed_processes"] = int(row["observed_processes"]) + count

    rows: list[dict[str, object]] = []
    for username in sorted(active_users):
        row = active_users[username]
        protocols = row.pop("protocols")
        assert isinstance(protocols, set)
        row["protocol"] = "/".join(sorted(str(protocol) for protocol in protocols))
        rows.append(row)
    return rows
