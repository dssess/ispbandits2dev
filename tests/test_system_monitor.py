import subprocess
import unittest
from unittest.mock import patch

from ispbandits import system_monitor


class SystemMonitorTests(unittest.TestCase):
    def test_vnstat_oneline_parses_fields_six_and_eleven(self):
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

    def test_missing_vnstat_is_unavailable_not_a_since_boot_estimate(self):
        with patch.object(system_monitor.shutil, "which", return_value=None):
            result = system_monitor.bandwidth_snapshot()
        self.assertEqual("unavailable", result["source"])
        self.assertEqual("unavailable", result["daily"])
        self.assertEqual("unavailable", result["monthly"])

    def test_vnstat_without_history_reports_collecting(self):
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", return_value=subprocess.CompletedProcess(
                 ["vnstat", "--oneline"], 1, "", "Not enough data available yet.")):
            result = system_monitor.bandwidth_snapshot()
        self.assertEqual("collecting", result["source"])
        self.assertEqual("collecting", result["daily"])
        self.assertEqual("collecting", result["monthly"])

    def test_malformed_vnstat_output_reports_collecting(self):
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", return_value=subprocess.CompletedProcess(
                 ["vnstat", "--oneline"], 0, "not-a-vnstat-row\n", "")):
            result = system_monitor.bandwidth_snapshot()
        self.assertEqual("collecting", result["source"])

    def test_vnstat_timeout_is_bounded_and_reports_collecting(self):
        with patch.object(system_monitor.shutil, "which", return_value="/usr/bin/vnstat"), \
             patch.object(system_monitor.subprocess, "run", side_effect=subprocess.TimeoutExpired("vnstat", 3)):
            result = system_monitor.bandwidth_snapshot()
        self.assertEqual("collecting", result["source"])

    def test_resource_snapshot_matches_nginxbandit_top_free_uptime_calculations(self):
        free = "              total        used        free      shared  buff/cache   available\nMem:           3911         237          68           1        3747        3572\n"
        uptime = "up 14 days, 6 hours\n"
        top = "%Cpu(s): 10.0 us, 2.0 sy, 0.0 ni, 88.0 id, 0.0 wa, 0.0 hi, 0.0 si, 0.0 st\n"
        responses = [
            subprocess.CompletedProcess(["free", "-m"], 0, free, ""),
            subprocess.CompletedProcess(["uptime", "-p"], 0, uptime, ""),
            subprocess.CompletedProcess(["top", "-bn1"], 0, top, ""),
        ]
        with patch.object(system_monitor.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"), \
             patch.object(system_monitor.subprocess, "run", side_effect=responses):
            result = system_monitor.resource_snapshot()
        self.assertEqual("237MB / 3911MB", result["memory"])
        self.assertEqual("6%", result["memory_percent"])
        self.assertEqual("12.0%", result["cpu"])
        self.assertEqual("14 days, 6 hours", result["uptime"])

    def test_missing_resource_commands_are_reported_unavailable(self):
        with patch.object(system_monitor.shutil, "which", return_value=None):
            result = system_monitor.resource_snapshot()
        self.assertEqual("unavailable", result["cpu"])
        self.assertEqual("unavailable", result["memory"])
        self.assertEqual("unavailable", result["uptime"])


if __name__ == "__main__":
    unittest.main()
