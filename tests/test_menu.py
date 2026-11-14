import io
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from ispbandits import cli, database, menu


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


class MenuTests(unittest.TestCase):
    def test_literal_menu_entrypoint_dispatches_existing_menu_command(self):
        with patch.object(cli, "main", return_value=0) as run:
            self.assertEqual(cli.menu_main(), 0)
        run.assert_called_once_with(["menu"])

    def test_explicit_menu_opens_and_exits(self):
        with patch("ispbandits.menu.sys.stdin", _FakeTTY()), \
             patch("builtins.input", return_value="0"):
            self.assertEqual(cli.main(["menu"]), 0)

    def test_no_arguments_opens_menu_in_terminal(self):
        with patch("ispbandits.menu.sys.stdin", _FakeTTY()), \
             patch("builtins.input", return_value="0"):
            self.assertEqual(cli.main([]), 0)

    def test_usage_menu_choice_dispatches_cli_action(self):
        answers = iter(("15", "", "0"))
        with patch("ispbandits.menu.sys.stdin", _FakeTTY()), \
             patch("builtins.input", side_effect=lambda _prompt="": next(answers)), \
             patch("ispbandits.menu._call_cli", return_value=0) as run_action:
            self.assertEqual(cli.main(["menu"]), 0)
        run_action.assert_called_once()
        self.assertEqual(run_action.call_args.args[1], "usage")

    def test_protocol_creation_options_dispatch_to_separate_commands(self):
        answers = iter(("1", "", "3", "", "4", "", "0"))
        with patch("ispbandits.menu.sys.stdin", _FakeTTY()), \
             patch("builtins.input", side_effect=lambda _prompt="": next(answers)), \
             patch("ispbandits.menu.os.geteuid", return_value=0), \
             patch("ispbandits.menu._call_cli", return_value=0) as run_action:
            self.assertEqual(cli.main(["menu"]), 0)
        commands = [call.args[1] for call in run_action.call_args_list]
        self.assertEqual(commands, ["sshws-create", "vless-create", "trojan-create"])

    def test_dashboard_displays_framed_summary_and_separate_protocol_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "db.sqlite"
            database.initialize(db_path)
            output = io.StringIO()
            with patch("sys.stdout", output), patch.object(menu, "_service_state", return_value="active"):
                menu._show_dashboard(db_path)
        screen = output.getvalue()
        self.assertIn("┌", screen)
        self.assertIn("Server Informations", screen)
        self.assertIn("SSH-WS : ON", screen)
        self.assertIn("Daily Bandwidth : not collected", screen)
        self.assertIn("[01] SSHWS", screen)
        self.assertIn("[02] VMESS", screen)
        self.assertIn("[03] VLESS", screen)
        self.assertIn("[04] TROJAN", screen)
        self.assertIn("[18] LIMIT SPEED", screen)
        self.assertIn("[N/A]", screen)
        self.assertIn("[L] Legacy ISPBandits actions 1–18", screen)
        self.assertIn("Version :", screen)
        self.assertIn("Select menu :", screen)

    def test_no_arguments_print_help_without_terminal(self):
        output = io.StringIO()
        with patch("ispbandits.menu.sys.stdin", io.StringIO()), \
             patch("sys.stdout", output):
            self.assertEqual(cli.main([]), 2)
        self.assertIn("usage: neverbandits", output.getvalue())


if __name__ == "__main__":
    unittest.main()
