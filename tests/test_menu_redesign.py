import io
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ispbandits import cli, database, menu, menu_actions, menu_ui


class MenuRedesignRegistryTests(unittest.TestCase):
    def test_registry_covers_all_legacy_actions_and_sections(self):
        self.assertEqual(set(menu_actions.ACTIONS), set(range(1, 19)))
        self.assertEqual(menu_actions.EXIT_KEYS, {"0", "00", "q", "Q", "x", "X"})
        self.assertEqual(menu_actions.MAIN_SECTIONS, ("L",))
        self.assertEqual(set(menu_actions.MORE_SECTIONS), set("CPTOSBDI"))
        for section in menu_actions.MAIN_SECTIONS:
            self.assertIn(section, menu_actions.SUBMENU_KEYS)
        self.assertEqual(set(menu_actions.SUBMENU_KEYS["L"]), set("CPTOSBDI") | {"1"})
        self.assertEqual(set(menu_actions.SUBMENU_KEYS["M"]), {str(action_id) for action_id in range(1, 19)})

    def test_reference_menu_preserves_original_keys_and_never_dispatches_unsupported_features(self):
        self.assertEqual(
            [item.key for item in menu_actions.REFERENCE_MENU],
            ["1", "2", "3", "4", "5", "6", "7", "8", "9", "11", "12", "13",
             "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24",
             "25", "55", "66", "77", "88", "99"],
        )
        for option in menu_actions.REFERENCE_MENU:
            if option.available:
                continue
            with self.subTest(option=option.key), patch("ispbandits.menu._invoke_cli") as invoke:
                result = menu._execute_reference_option(Path("/tmp/db"), option.key)
            self.assertEqual(result[0], "FAILED")
            self.assertIn("unavailable", result[1].lower())
            invoke.assert_not_called()

    def test_all_actions_dispatch_to_existing_commands(self):
        expected = {
            1: ("sshws-create",),
            2: ("vless-create",),
            3: ("trojan-create",),
            4: ("usage",),
            5: ("online",),
            7: ("expire",),
            8: ("backup", "--dir", "/var/backups/ispbandits-dev"),
            9: ("verify",),
            10: ("quota-set", "alice", "--limit-gb", "25"),
            11: ("account-list",),
            12: ("account-show", "alice"),
            13: ("renew", "alice", "--expires", "2026-12-31"),
            14: ("disable", "alice"),
            15: ("enable", "alice"),
            16: ("ssh-password-reset", "alice"),
            17: ("account-delete", "alice", "--yes"),
            18: ("restore", "/tmp/backup.tar.gz", "--confirm", "RESTORE",
                 "--dir", "/var/backups/ispbandits-dev"),
        }
        prompts = {
            10: ("alice", "25"),
            12: ("alice",),
            13: ("alice", "2026-12-31"),
            14: ("alice",),
            15: ("alice",),
            16: ("alice",),
            17: ("alice", "alice"),
            18: ("/tmp/backup.tar.gz", "RESTORE"),
        }
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "database.db"
            for action_id, expected_args in expected.items():
                calls = []
                with self.subTest(action_id=action_id), \
                     patch("ispbandits.menu.os.geteuid", return_value=0), \
                     patch("ispbandits.menu._invoke_cli", side_effect=lambda _db, *args: (calls.append(args) or ("SUCCESS", "ok"))), \
                     patch("ispbandits.menu._service_status"), \
                     patch("builtins.input", side_effect=prompts.get(action_id, ())):
                    result = menu._execute_action(db_path, action_id)
                self.assertEqual(result[0], "SUCCESS")
                self.assertEqual(calls, [expected_args])

    def test_protocol_menu_choices_remain_separate(self):
        self.assertEqual(menu_actions.SUBMENU_KEYS["P"], {"1": 1, "2": 2, "3": 3})
        expected = {1: "sshws-create", 2: "vless-create", 3: "trojan-create"}
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "database.db"
            for action_id, command in expected.items():
                with self.subTest(action_id=action_id), \
                     patch("ispbandits.menu.os.geteuid", return_value=0), \
                     patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
                    result = menu._execute_action(db_path, action_id)
                self.assertEqual(result[0], "SUCCESS")
                self.assertEqual(invoke.call_args.args[1:], (command,))

    def test_reference_create_options_route_to_separate_existing_handlers(self):
        expected = {"1": "sshws-create", "3": "vless-create", "4": "trojan-create"}
        for key, command in expected.items():
            with self.subTest(key=key), patch("ispbandits.menu.os.geteuid", return_value=0), \
                 patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
                result = menu._execute_reference_option(Path("/tmp/db"), key)
            self.assertEqual(result[0], "SUCCESS")
            self.assertEqual(invoke.call_args.args[1:], (command,))

    def test_root_required_actions_are_blocked_before_dispatch(self):
        root_ids = [action_id for action_id, action in menu_actions.ACTIONS.items() if action.requires_root]
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "database.db"
            for action_id in root_ids:
                with self.subTest(action_id=action_id), \
                     patch("ispbandits.menu.os.geteuid", return_value=1000), \
                     patch("ispbandits.menu._invoke_cli") as invoke:
                    result = menu._execute_action(db_path, action_id)
                self.assertEqual(result[0], "FAILED")
                invoke.assert_not_called()

    def test_create_delete_and_restore_submenu_ids_are_preserved(self):
        self.assertEqual(menu_actions.SUBMENU_KEYS["C"], {
            "1": 11, "2": 12, "3": 13, "4": 15, "5": 14, "6": 17,
        })
        self.assertEqual(menu_actions.SUBMENU_KEYS["B"], {"1": 8, "2": 18})
        self.assertEqual(menu_actions.SUBMENU_KEYS["D"], {"1": 6, "2": 9})


class MenuSafetyAndResultTests(unittest.TestCase):
    def test_delete_mismatch_never_dispatches_cli(self):
        with patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("builtins.input", side_effect=("alice", "bob")), \
             patch("ispbandits.menu._invoke_cli") as invoke:
            result = menu._delete_account(Path("/tmp/db"))
        self.assertEqual(result[0], "CANCELLED")
        invoke.assert_not_called()

    def test_restore_requires_absolute_archive_path_and_exact_confirmation(self):
        for answers in (("relative.tar", "RESTORE"), ("/tmp/a.tar", "restore")):
            with self.subTest(answers=answers), \
                 patch("ispbandits.menu.os.geteuid", return_value=0), \
                 patch("builtins.input", side_effect=answers), \
                 patch("ispbandits.menu._invoke_cli") as invoke:
                result = menu._restore_database(Path("/tmp/db"))
            self.assertIn(result[0], {"FAILED", "CANCELLED"})
            invoke.assert_not_called()

    def test_confirmed_restore_passes_exact_token_to_cli(self):
        with patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("builtins.input", side_effect=("/tmp/backup.tar.gz", "RESTORE")), \
             patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
            result = menu._restore_database(Path("/tmp/db"))
        self.assertEqual(result[0], "SUCCESS")
        self.assertEqual(invoke.call_args.args[1:],
                         ("restore", "/tmp/backup.tar.gz", "--confirm", "RESTORE",
                          "--dir", "/var/backups/ispbandits-dev"))

    def test_prompt_interruptions_cancel_without_cli_dispatch(self):
        with patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("builtins.input", side_effect=KeyboardInterrupt), \
             patch("ispbandits.menu._invoke_cli") as invoke:
            self.assertEqual(menu._set_quota(Path("/tmp/db"))[0], "CANCELLED")
            self.assertEqual(menu._root_action(Path("/tmp/db"), "disable", "Username: ")[0], "CANCELLED")
            self.assertEqual(menu._restore_database(Path("/tmp/db"))[0], "CANCELLED")
        invoke.assert_not_called()

    def test_matching_delete_confirmation_dispatches_irreversible_flag(self):
        with patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("builtins.input", side_effect=("alice", "alice")), \
             patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
            result = menu._delete_account(Path("/tmp/db"))
        self.assertEqual(result[0], "SUCCESS")
        self.assertEqual(invoke.call_args.args[1:], ("account-delete", "alice", "--yes"))

    def test_cli_nonzero_is_failed_and_cancellation_marker_is_cancelled(self):
        with patch("ispbandits.menu._call_cli", return_value=2):
            result = menu._invoke_cli(Path("/tmp/db"), "verify")
        self.assertEqual(result[0], "FAILED")

        def cancelled(_db, *_args):
            import sys
            print("Account creation cancelled; no changes were made")
            print("error: Account creation cancelled; no changes were made", file=sys.stderr)
            return 2

        with patch("ispbandits.menu._call_cli", side_effect=cancelled):
            result = menu._invoke_cli(Path("/tmp/db"), "sshws-create")
        self.assertEqual(result[0], "CANCELLED")

    def test_failure_containing_username_cancelled_is_not_misclassified(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "database.db"
            database.initialize(db_path)
            with redirect_stderr(io.StringIO()):
                result = menu._invoke_cli(db_path, "account-show", "cancelled")
        self.assertEqual(result[0], "FAILED")

    def test_cli_stdout_is_forwarded_while_handler_runs(self):
        output = io.StringIO()

        def existing_handler(_db, *_args):
            print("Username: ", end="", flush=True)
            self.assertEqual(input(), "alice")
            print("Account created")
            return 0

        with patch("ispbandits.menu._call_cli", side_effect=existing_handler), \
             patch("builtins.input", return_value="alice"), redirect_stdout(output):
            result = menu._invoke_cli(Path("/tmp/db"), "sshws-create")
        self.assertEqual(result[0], "SUCCESS")
        self.assertIn("Username: Account created", output.getvalue())

    def test_no_success_result_after_nonzero_cli_return(self):
        with patch("ispbandits.menu._call_cli", return_value=1), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = menu._invoke_cli(Path("/tmp/db"), "account-list")
        self.assertNotEqual(result[0], "SUCCESS")


class OriginalMenuOperationalCommandTests(unittest.TestCase):
    @staticmethod
    def completed(args, code=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(args, code, stdout, stderr)

    def test_reboot_is_root_only_and_queues_without_waiting_for_disconnect(self):
        output = io.StringIO()
        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli.subprocess.run", return_value=self.completed([], stdout="")) as run, \
             redirect_stdout(output):
            result = cli.main(["reboot", "--confirm", "REBOOT"])
        self.assertEqual(result, 0)
        self.assertEqual(run.call_args.args[0], ["systemctl", "reboot", "--no-block"])
        self.assertIn("queued", output.getvalue())

    def test_managed_restart_touches_only_allowlisted_units_and_checks_each_state(self):
        outputs = []
        for _label, unit in (("Nginx", "nginx.service"), ("Xray", "ispbandits-xray.service"),
                             ("SSH HTTP Custom relay", "neverbandits-ssh-http.service")):
            outputs.extend((self.completed([], stdout="loaded\n"), self.completed([]),
                            self.completed([], stdout="active\n")))
        output = io.StringIO()
        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli.subprocess.run", side_effect=outputs) as run, \
             redirect_stdout(output):
            result = cli.main(["service-restart", "--confirm", "RESTART"])
        self.assertEqual(result, 0)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([cmd[2] for cmd in commands if cmd[1:2] == ["restart"]],
                         ["nginx.service", "ispbandits-xray.service", "neverbandits-ssh-http.service"])
        self.assertIn("does not test external customer connectivity", output.getvalue())

    def test_managed_restart_fails_closed_when_any_restart_or_health_check_fails(self):
        outputs = [
            self.completed([], stdout="loaded\n"),
            self.completed([], 1, stderr="unit failed"),
            self.completed([], stdout="loaded\n"), self.completed([]), self.completed([], stdout="active\n"),
            self.completed([], stdout="loaded\n"), self.completed([]), self.completed([], stdout="active\n"),
        ]
        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli.subprocess.run", side_effect=outputs), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["service-restart", "--confirm", "RESTART"]), 2)

    def test_reboot_and_restart_block_non_root_before_system_calls(self):
        with patch("ispbandits.cli.os.geteuid", return_value=1000), \
             patch("ispbandits.cli.subprocess.run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["reboot", "--confirm", "REBOOT"]), 2)
        run.assert_not_called()
        with patch("ispbandits.cli.os.geteuid", return_value=1000), \
             patch("ispbandits.cli.subprocess.run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["service-restart", "--confirm", "RESTART"]), 2)
        run.assert_not_called()

    def test_tls_renewal_runs_refresh_then_checks_hostname_and_expiry(self):
        output = io.StringIO()
        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli._install_info", return_value={"domain": "vpn.example.test"}), \
             patch("ispbandits.cli.shutil.which", side_effect=lambda name: "/usr/bin/certbot" if name == "certbot" else None), \
             patch("ispbandits.cli.subprocess.run", side_effect=lambda *args, **kwargs: self.completed(args[0])) as run, \
             redirect_stdout(output):
            result = cli.main(["tls-renew", "--confirm", "RENEW"])
        self.assertEqual(result, 0)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0], ["/usr/bin/certbot", "renew", "--cert-name", "vpn.example.test"])
        self.assertIn("scripts/refresh-tls.sh", commands[1][-1])
        self.assertEqual(commands[2][:6], ["openssl", "x509", "-in",
                                           "/etc/ispbandits-dev/tls/current/fullchain.pem", "-noout", "-checkhost"])
        self.assertIn("external client connectivity is not tested", output.getvalue())

    def test_tls_renewal_requires_domain_and_never_claims_success_on_certbot_failure(self):
        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli._install_info", return_value={}), \
             patch("ispbandits.cli.shutil.which", return_value="/usr/bin/certbot"), \
             patch("ispbandits.cli.subprocess.run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["tls-renew", "--confirm", "RENEW"]), 2)
        run.assert_not_called()

        with patch("ispbandits.cli.os.geteuid", return_value=0), \
             patch("ispbandits.cli._install_info", return_value={"domain": "vpn.example.test"}), \
             patch("ispbandits.cli.shutil.which", return_value="/usr/bin/certbot"), \
             patch("ispbandits.cli.subprocess.run", return_value=self.completed([], 1, stderr="failed")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["tls-renew", "--confirm", "RENEW"]), 2)

    def test_bandwidth_and_process_list_are_read_only_and_truthfully_labeled(self):
        output = io.StringIO()
        vnstat = {"source": "vnstat", "interface": "ens18", "daily": "40.67 GiB",
                  "monthly": "483.79 GiB", "received": "20.98 GiB", "sent": "19.69 GiB",
                  "month": "2026-11"}
        with patch.object(cli.system_monitor, "bandwidth_snapshot", return_value=vnstat), redirect_stdout(output):
            cli._host_bandwidth()
        self.assertIn("Today: 40.67 GiB", output.getvalue())
        self.assertIn("Month: 483.79 GiB", output.getvalue())
        self.assertIn("not per-user", output.getvalue())

        with patch("ispbandits.cli.subprocess.run", return_value=self.completed([], stdout="PID COMMAND %CPU %MEM\n1 init 0 1\n")), \
             redirect_stdout(output):
            cli._process_list()
        self.assertIn("read-only", output.getvalue())
        self.assertIn("1 init", output.getvalue())

    def test_menu_confirmation_mismatch_never_dispatches_operational_command(self):
        for key, answer in (("8", "no"), ("9", "REBOOT"), ("12", "no")):
            with self.subTest(key=key), patch("ispbandits.menu.os.geteuid", return_value=0), \
                 patch("builtins.input", return_value=answer), \
                 patch("ispbandits.menu._invoke_cli") as invoke:
                result = menu._execute_reference_option(Path("/tmp/db"), key)
            self.assertEqual(result[0], "CANCELLED")
            invoke.assert_not_called()

    def test_database_unavailable_is_not_reported_as_zero_accounts(self):
        with patch("ispbandits.menu._database_counts", return_value=None), \
             patch("ispbandits.menu._service_state", return_value="active"):
            snapshot = menu._dashboard_snapshot(Path("/missing/database.db"))
        self.assertTrue(any("unavailable" in line.lower() for line in snapshot["accounts"]))
        self.assertIn(("DATABASE", "unavailable"), snapshot["health"])

    def test_dashboard_snapshot_includes_resource_bandwidth_and_live_ssh_summary(self):
        counts = {"total": 4, "active": 3, "disabled": 1, "expired": 0,
                  "quota": 0, "measured_bytes": 12345,
                  "protocol_counts": {"ssh": 2, "vless": 1, "trojan": 0}}
        bandwidth = {"source": "vnstat", "interface": "ens18", "daily": "2.50 GiB",
                     "monthly": "80.00 GiB", "received": "1.30 GiB", "sent": "1.20 GiB",
                     "month": "2026-11"}
        sessions = [{"username": "alice", "protocol": "openssh", "observed_processes": 2}]
        with patch("ispbandits.menu._database_counts", return_value=counts), \
             patch("ispbandits.menu._cpu_details", return_value=("CPU model", "2 Cores (load 0.10)")), \
             patch("ispbandits.menu._cpu_usage_percent", return_value="7% (sample)"), \
             patch("ispbandits.menu._memory", return_value="512 / 2048 MiB"), \
             patch("ispbandits.menu._memory_percent", return_value="25%"), \
             patch("ispbandits.menu._uptime_readable", return_value="2 days, 3 hours"), \
             patch("ispbandits.menu._domain", return_value="vpn.example.test"), \
             patch("ispbandits.menu._public_interface_ip", return_value="203.0.113.10"), \
             patch("ispbandits.menu._storage_summary", return_value="18% used (18 / 100 GiB)"), \
             patch("ispbandits.menu.system_monitor.bandwidth_snapshot", return_value=bandwidth), \
             patch("ispbandits.menu._online_ssh_snapshot", return_value=sessions), \
             patch("ispbandits.menu._collect_checks", return_value={}):
            snapshot = menu._dashboard_snapshot(Path("/tmp/db"))
        overview = "\n".join(snapshot["overview"])
        self.assertIn("CPU Usage       : 7% (sample)", overview)
        self.assertIn("Total RAM", overview)
        self.assertIn("Storage", overview)
        self.assertIn("Daily Bandwidth : 2.50 GiB (ens18, vnStat)", overview)
        self.assertIn("Monthly Bandwidth: 80.00 GiB (2026-11)", overview)
        self.assertIn("1 active username(s), 2 observed process(es)", overview)
        self.assertEqual(sessions, snapshot["ssh_sessions"])

    def test_systemd_timeout_is_reported_as_unavailable(self):
        with patch("ispbandits.menu.subprocess.run", side_effect=subprocess.TimeoutExpired("systemctl", 2)):
            self.assertEqual(menu._service_state("nginx.service"), "unavailable")

    def test_cpu_usage_is_sampled_from_procfs_and_handles_missing_data(self):
        samples = iter(("cpu 100 0 0 20 0 0 0 0 0 0\n",
                        "cpu 130 0 0 30 0 0 0 0 0 0\n"))
        with patch("ispbandits.menu.Path.read_text", side_effect=lambda *a, **k: next(samples)), \
             patch("ispbandits.menu.time.sleep"):
            self.assertEqual("75% (sample)", menu._cpu_usage_percent())
        with patch("ispbandits.menu.Path.read_text", side_effect=OSError("procfs unavailable")):
            self.assertEqual("unavailable", menu._cpu_usage_percent())

    def test_overall_probe_timeout_returns_unknown_instead_of_hanging(self):
        def slow_probe():
            time.sleep(0.15)
            return "active"

        started = time.monotonic()
        result = menu._collect_checks([("slow", slow_probe)], timeout=0.01)
        elapsed = time.monotonic() - started
        self.assertEqual(result["slow"], "unknown (probe timed out)")
        self.assertLess(elapsed, 0.1)

    def test_systemd_active_does_not_imply_protocol_listener_or_client_health(self):
        def listener_state(_host, port):
            return "unreachable" if port == 10001 else "ready"

        output = io.StringIO()
        with patch("ispbandits.menu._service_state", return_value="active"), \
             patch("ispbandits.menu._tcp_listener_state", side_effect=listener_state), \
             patch("ispbandits.menu._xray_api_state", return_value="ready"), \
             patch("ispbandits.menu._database_counts", return_value={"total": 0}), \
             redirect_stdout(output):
            menu._service_status(Path("/tmp/db"))
        rendered = output.getvalue()
        self.assertIn("Nginx frontend", rendered)
        self.assertIn("VLESS inbound listener only", rendered)
        self.assertIn("Trojan inbound listener only", rendered)
        self.assertRegex(rendered, r"VLESS inbound listener only\s+unreachable")
        self.assertRegex(rendered, r"Trojan inbound listener only\s+ready")
        self.assertIn("EXTERNAL CLIENT CONNECTIVITY: NOT TESTED", rendered)


class MenuInteractionAndTerminalTests(unittest.TestCase):
    class _TTY(io.StringIO):
        def isatty(self):
            return True

    def test_back_exit_and_local_section_dispatch(self):
        answers = iter(("P", "", "L", "P", "2", "", "B", "0", "0"))
        with tempfile.TemporaryDirectory() as directory, \
             patch("ispbandits.menu.sys.stdin", self._TTY()), \
             patch("builtins.input", side_effect=lambda *_args: next(answers)), \
             patch("ispbandits.menu._dashboard_snapshot", return_value={"overview": [], "health": [], "accounts": []}), \
             patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
            result = menu.run_menu(Path(directory) / "db.sqlite")
        self.assertEqual(result, 0)
        self.assertEqual(invoke.call_args.args[1:], ("vless-create",))

    def test_legacy_action_10_remains_available_inside_more_actions(self):
        answers = iter(("L", "1", "10", "alice", "25", "", "B", "0", "0"))
        with tempfile.TemporaryDirectory() as directory, \
             patch("ispbandits.menu.sys.stdin", self._TTY()), \
             patch("builtins.input", side_effect=lambda *_args: next(answers)), \
             patch("ispbandits.menu._dashboard_snapshot", return_value={"overview": [], "health": [], "accounts": []}), \
             patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("ispbandits.menu._invoke_cli", return_value=("SUCCESS", "ok")) as invoke:
            result = menu.run_menu(Path(directory) / "db.sqlite")
        self.assertEqual(result, 0)
        self.assertEqual(invoke.call_args.args[1:], ("quota-set", "alice", "--limit-gb", "25"))

    def test_return_to_main_and_exit_repaint_instead_of_stacking_menus(self):
        answers = iter(("L", "0", "0"))
        with tempfile.TemporaryDirectory() as directory, \
             patch("ispbandits.menu.sys.stdin", self._TTY()), \
             patch("builtins.input", side_effect=lambda *_args: next(answers)), \
             patch("ispbandits.menu._show_dashboard"), \
             patch("ispbandits.menu.menu_ui.clear_screen") as clear:
            result = menu.run_menu(Path(directory) / "db.sqlite")
        self.assertEqual(result, 0)
        # Initial dashboard, More Actions, returned dashboard, and a clean exit view.
        self.assertEqual(clear.call_count, 4)

    def test_dumb_terminal_uses_plain_repaint_fallback(self):
        output = self._TTY()
        with patch("ispbandits.menu_ui.sys.stdout", output), \
             patch("ispbandits.menu_ui._dimensions", return_value=(80, 24)), \
             patch.dict("os.environ", {"TERM": "dumb"}, clear=False):
            menu_ui.clear_screen()
        rendered = output.getvalue()
        self.assertGreaterEqual(rendered.count("\n"), 24)
        self.assertNotIn("\033[", rendered)

    def test_traffic_section_lists_only_active_ssh_processes(self):
        active = [
            {"username": "alice", "protocol": "openssh", "observed_processes": 2},
        ]
        with patch("ispbandits.menu._collect_checks", return_value={}), \
             patch("ispbandits.menu._online_ssh_snapshot", return_value=active):
            rows = menu._section_extra(Path("/tmp/db"), "T")
        rendered = "\n".join(str(item[0] if isinstance(item, tuple) else item) for item in rows)
        self.assertIn("ACTIVE SSH SESSIONS", rendered)
        self.assertIn("alice", rendered)
        self.assertIn("2", rendered)
        self.assertIn("do not identify unique devices", rendered)

    def test_traffic_section_reports_no_sessions_without_inactive_accounts(self):
        with patch("ispbandits.menu._collect_checks", return_value={}), \
             patch("ispbandits.menu._online_ssh_snapshot", return_value=[]):
            rows = menu._section_extra(Path("/tmp/db"), "T")
        rendered = "\n".join(str(item[0] if isinstance(item, tuple) else item) for item in rows)
        self.assertIn("No active SSH/Dropbear processes observed.", rendered)
        self.assertNotIn("USERNAME", rendered)

    def test_more_actions_hub_contains_letters_and_legacy_menu(self):
        output = io.StringIO()
        with patch("ispbandits.menu_ui._dimensions", return_value=(80, 30)), \
             patch.dict("os.environ", {"TERM": "xterm", "NO_COLOR": "1"}), \
             redirect_stdout(output):
            menu_ui.show_more_actions(menu._more_action_items())
        rendered = output.getvalue()
        for expected in ("[C] CLIENT MANAGEMENT", "[P] PROTOCOL MANAGEMENT",
                         "[T] TRAFFIC & QUOTA", "[D] DIAGNOSTICS",
                         "[1] LEGACY ISPBandits ACTIONS 1–18", "[R] Refresh dashboard",
                         "[0] Back to Control Centre"):
            self.assertIn(expected, rendered)

    def test_narrow_terminal_uses_wrapped_plain_fallback(self):
        output = io.StringIO()
        with patch("ispbandits.menu_ui._dimensions", return_value=(36, 20)), \
             patch.dict("os.environ", {"TERM": "dumb", "NO_COLOR": "1"}), \
             redirect_stdout(output):
            menu_ui.panel("NEXUS CONTROL", ["A very long panel line that must wrap on a narrow mobile terminal."])
        rendered = output.getvalue()
        self.assertNotIn("╔", rendered)
        self.assertIn("NEXUS CONTROL", rendered)
        self.assertIn("mobile terminal.", rendered)
        self.assertNotIn("\033[", rendered)

    def test_dashboard_fits_requested_terminal_widths(self):
        snapshot = {
            "overview": ["HOSTNAME example-node", "A long item " + ("x" * 95)],
            "health": [("NGINX systemd", "active"), ("Xray API", "unavailable")],
            "accounts": ["TOTAL ACCOUNTS 24", "Measured traffic: 4.567 GB"],
        }
        section_items = [(key, str(menu_actions.SECTIONS[key]["title"]))
                         for key in menu_actions.MAIN_SECTIONS]
        for width in (40, 50, 58, 80, 120):
            with self.subTest(width=width):
                output = io.StringIO()
                with patch("ispbandits.menu_ui._dimensions", return_value=(width, 24)), \
                     patch.dict("os.environ", {"TERM": "xterm"}, clear=False), \
                     redirect_stdout(output):
                    menu_ui.show_dashboard(snapshot, section_items,
                                          ("[01] CREATE SSH", "[18] RESTORE DATABASE"),
                                          reference_options=menu_actions.REFERENCE_MENU)
                self.assertLessEqual(max(map(len, output.getvalue().splitlines())), width)

    def test_dashboard_uses_reference_layout_without_inventing_bandwidth_or_client_health(self):
        snapshot = {
            "overview": [
                "OS Linux        : Ubuntu 24.04 LTS",
                "CPU Name        : Test CPU",
                "Daily Bandwidth : 40.67 GiB (ens18, vnStat)",
                "Monthly Bandwidth: 483.79 GiB (2026-11)",
                "Online SSH      : 2 active username(s), 3 observed process(es) (approximate)",
            ],
            "health": [
                ("SSH unit", "active"), ("NGINX unit", "active"),
                ("VLESS port", "ready"), ("TROJAN port", "unreachable"),
            ],
            "protocol_counts": {"ssh": 2, "vless": 3, "trojan": 1},
        }
        output = io.StringIO()
        with patch("ispbandits.menu_ui._dimensions", return_value=(80, 30)), \
             patch.dict("os.environ", {"TERM": "xterm", "NO_COLOR": "1"}), \
             redirect_stdout(output):
            menu_ui.show_dashboard(
                snapshot,
                [(key, str(menu_actions.SECTIONS[key]["title"]))
                 for key in menu_actions.MAIN_SECTIONS],
                reference_options=menu_actions.REFERENCE_MENU,
            )
        rendered = output.getvalue()
        self.assertIn("Server Informations", rendered)
        self.assertNotIn("NEVERBANDITS MENU", rendered)
        self.assertIn("[01] SSHWS", rendered)
        self.assertIn("[03] VLESS", rendered)
        self.assertIn("[04] TROJAN", rendered)
        self.assertIn("[2]", rendered)
        self.assertIn("[3]", rendered)
        self.assertIn("[1]", rendered)
        self.assertNotIn("[02] VMESS", rendered)
        self.assertNotIn("[N/A]", rendered)
        self.assertNotIn("[55] XRAY-CORE MENU", rendered)
        self.assertNotIn("[77] SWAPRAM MENU", rendered)
        self.assertIn("Daily Bandwidth", rendered)
        self.assertIn("Monthly Bandwidth", rendered)
        self.assertIn("Online SSH", rendered)
        self.assertIn("TROJAN : OFF", rendered)
        self.assertNotIn("EXTERNAL CLIENT CONNECTIVITY: NOT TESTED", rendered)
        self.assertIn("[L] More actions", rendered)
        self.assertIn("Version :", rendered)
        self.assertIn("Select menu :", rendered)
        self.assertLessEqual(max(map(len, rendered.splitlines())), 80)

    def test_no_color_environment_disables_ansi_even_in_tty(self):
        output = self._TTY()
        with patch("ispbandits.menu_ui._dimensions", return_value=(80, 24)), \
             patch.dict("os.environ", {"TERM": "xterm", "NO_COLOR": "1"}), \
             redirect_stdout(output):
            menu_ui.panel("NEXUS CONTROL", ["Healthy endpoint"])
        self.assertNotIn("\033[", output.getvalue())

    def test_noninteractive_menu_is_rejected_without_waiting(self):
        with patch("ispbandits.menu.sys.stdin", io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(menu.run_menu(Path("/tmp/db")), 2)

    def test_existing_standalone_cli_command_still_works(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["about"]), 0)
        self.assertIn("Neverbandits", output.getvalue())


if __name__ == "__main__":
    unittest.main()
