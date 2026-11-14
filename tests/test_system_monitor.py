from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from ispbandits import system_monitor


class SystemMonitorTests(unittest.TestCase):
    def test_vnstat_oneline_parses_today_and_month_totals(self):
        output = (
            "1;ens18;2026-11-14;20.98 GiB;19.69 GiB;40.67 GiB;8.38 Mbit/s;"
            "2026-11;247.82 GiB;235.97 GiB;483.79 GiB;10.46 Mbit/s;"
            "247.82 GiB;235.97 GiB;483.79 GiB\n"
        )
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", return_value=subprocess.CompletedProcess(
                 ["vnstat", "--oneline"], 0, output, "")):
            result = system_monitor.bandwidth_snapshot()
        self.assertEqual("vnstat", result["source"])
        self.assertEqual("ens18", result["interface"])
        self.assertEqual("40.67 GiB", result["daily"])
        self.assertEqual("483.79 GiB", result["monthly"])

    def test_unavailable_vnstat_falls_back_to_labeled_since_boot_counters(self):
        fake = (
            "Inter-| Receive\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes\n"
            "eth0: 1024 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0\n"
            "lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\n"
        )
        with patch.object(system_monitor.shutil, "which", return_value=None), \
             patch.object(Path, "read_text", return_value=fake):
            result = system_monitor.bandwidth_snapshot(Path("/fixture/net/dev"))
        self.assertEqual("kernel-since-boot", result["source"])
        self.assertEqual("1024", result["received_bytes"])
        self.assertEqual("2048", result["sent_bytes"])
        self.assertEqual("1 non-loopback interfaces", result["interface"])

    def test_malformed_vnstat_response_uses_kernel_fallback(self):
        fake = "Inter-| Receive\n face |header\neth0: 12 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n"
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", return_value=subprocess.CompletedProcess(
                 ["vnstat", "--oneline"], 0, "not-a-vnstat-row\n", "")), \
             patch.object(Path, "read_text", return_value=fake):
            result = system_monitor.bandwidth_snapshot(Path("/fixture/net/dev"))
        self.assertEqual("kernel-since-boot", result["source"])
        self.assertEqual("12", result["received_bytes"])

    def test_vnstat_timeout_falls_back_without_hanging(self):
        fake = "Inter-| Receive\n face |header\neth0: 12 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n"
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", side_effect=subprocess.TimeoutExpired("vnstat", 3)), \
             patch.object(Path, "read_text", return_value=fake):
            result = system_monitor.bandwidth_snapshot(Path("/fixture/net/dev"))
        self.assertEqual("kernel-since-boot", result["source"])

    def test_humanize_bytes_uses_binary_units(self):
        self.assertEqual("1.00 KiB", system_monitor.humanize_bytes(1024))
        self.assertEqual("0.00 B", system_monitor.humanize_bytes(-1))


if __name__ == "__main__":
    unittest.main()
