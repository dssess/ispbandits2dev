"""Read-only host network usage snapshots for the dashboard and CLI."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess


def _parse_vnstat_line(output: str) -> dict[str, str] | None:
    """Parse vnStat's stable semicolon-delimited --oneline format."""
    for line in output.splitlines():
        fields = [field.strip() for field in line.split(";")]
        if len(fields) < 11:
            continue
        interface = fields[1]
        today = fields[5]
        month = fields[10]
        if not interface or not today or not month:
            continue
        return {
            "source": "vnstat",
            "interface": interface,
            "daily": today,
            "monthly": month,
            "received": fields[3],
            "sent": fields[4],
            "month": fields[7],
        }
    return None


def _kernel_counters(proc_net_dev: Path) -> dict[str, str] | None:
    """Return aggregate interface counters, whose period is since boot/reset."""
    try:
        lines = proc_net_dev.read_text(encoding="ascii").splitlines()[2:]
    except OSError:
        return None
    received = sent = interfaces = 0
    for line in lines:
        name, separator, counters = line.partition(":")
        if not separator or name.strip() == "lo":
            continue
        values = counters.split()
        if len(values) < 9:
            continue
        try:
            received += int(values[0])
            sent += int(values[8])
        except ValueError:
            continue
        interfaces += 1
    if not interfaces:
        return None
    return {
        "source": "kernel-since-boot",
        "interface": f"{interfaces} non-loopback interfaces",
        "received_bytes": str(received),
        "sent_bytes": str(sent),
    }


def bandwidth_snapshot(proc_net_dev: Path = Path("/proc/net/dev")) -> dict[str, str]:
    """Read a host-wide snapshot; vnStat is preferred, procfs is the fallback."""
    vnstat = shutil.which("vnstat")
    if vnstat:
        try:
            result = subprocess.run(
                [vnstat, "--oneline"], check=False, capture_output=True,
                text=True, timeout=3,
            )
            if result.returncode == 0:
                parsed = _parse_vnstat_line(result.stdout)
                if parsed:
                    return parsed
        except (OSError, subprocess.TimeoutExpired):
            pass
    counters = _kernel_counters(proc_net_dev)
    if counters:
        return counters
    return {"source": "unavailable", "interface": "unavailable"}


def humanize_bytes(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{amount:.2f} TiB"
