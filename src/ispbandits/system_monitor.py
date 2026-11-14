"""Read-only host metrics matching the original Nginxbandit dashboard."""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess


def _run(command: list[str], timeout: float = 3.0) -> subprocess.CompletedProcess[str] | None:
    executable = shutil.which(command[0])
    if not executable:
        return None
    try:
        return subprocess.run(
            [executable, *command[1:]], check=False, capture_output=True,
            text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _parse_vnstat_line(output: str) -> dict[str, str] | None:
    """Parse the same vnStat --oneline fields used by Nginxbandit (6 and 11)."""
    for line in output.splitlines():
        fields = [field.strip() for field in line.split(";")]
        if len(fields) < 11 or not fields[1]:
            continue
        today, month = fields[5], fields[10]
        if not today or not month:
            continue
        return {
            "source": "vnstat",
            "interface": fields[1],
            "daily": today,
            "monthly": month,
            "received": fields[3],
            "sent": fields[4],
            "month": fields[7],
        }
    return None


def bandwidth_snapshot() -> dict[str, str]:
    """Use vnStat daily/monthly host totals; never substitute since-boot counters."""
    if not shutil.which("vnstat"):
        return {"source": "unavailable", "interface": "unavailable",
                "daily": "unavailable", "monthly": "unavailable"}
    result = _run(["vnstat", "--oneline"])
    if result and result.returncode == 0:
        parsed = _parse_vnstat_line(result.stdout)
        if parsed:
            return parsed
    return {"source": "collecting", "interface": "default interface",
            "daily": "collecting", "monthly": "collecting"}


def _uptime() -> str:
    result = _run(["uptime", "-p"])
    if not result or result.returncode != 0 or not result.stdout.strip():
        return "unavailable"
    return re.sub(r"^up\s+", "", result.stdout.strip(), flags=re.IGNORECASE)


def _memory() -> tuple[str, str]:
    result = _run(["free", "-m"])
    if not result or result.returncode != 0:
        return "unavailable", "unavailable"
    row = next((line.split() for line in result.stdout.splitlines()
                if line.split() and line.split()[0].rstrip(":").lower() == "mem"), None)
    if not row or len(row) < 3:
        return "unavailable", "unavailable"
    try:
        total_mb, used_mb = int(row[1]), int(row[2])
    except ValueError:
        return "unavailable", "unavailable"
    if total_mb <= 0:
        return "unavailable", "unavailable"
    percent = max(0, min(100, round(used_mb * 100 / total_mb)))
    return f"{used_mb}MB / {total_mb}MB", f"{percent}%"


def _cpu_usage() -> str:
    result = _run(["top", "-bn1"])
    if not result or result.returncode != 0:
        return "unavailable"
    for line in result.stdout.splitlines():
        if "cpu(s)" not in line.lower() and "%cpu" not in line.lower():
            continue
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*%?\s*(?:id|idle)\b", line, re.IGNORECASE)
        if match:
            idle = float(match.group(1))
            return f"{max(0.0, min(100.0, 100.0 - idle)):.1f}%"
    return "unavailable"


def resource_snapshot() -> dict[str, str]:
    """Sample uptime, RAM, and CPU using the same standard tools as Nginxbandit."""
    memory, memory_percent = _memory()
    return {
        "uptime": _uptime(),
        "memory": memory,
        "memory_percent": memory_percent,
        "cpu": _cpu_usage(),
    }
