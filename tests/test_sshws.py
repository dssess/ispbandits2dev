from __future__ import annotations

import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

from ispbandits import cli, database, provisioning, xray_config


ROOT = Path(__file__).resolve().parents[1]


class SSHWebSocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "db.sqlite"
        database.initialize(self.db)
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        database.add_user(self.db, "alice", expiry)
        database.create_xray_protocol(self.db, "alice", "vless")
        database.create_xray_protocol(self.db, "alice", "trojan")

    def tearDown(self):
        self.tmp.cleanup()

    def test_xray_config_uses_loopback_vless_and_trojan_ws_with_optional_legacy_tls(self):
        with patch.object(xray_config, "_validate_tls", return_value=("/cert.pem", "/key.pem")):
            config = xray_config.build_config(self.db, "/cert.pem", "/key.pem")
        inbounds = {item["protocol"]: item for item in config["inbounds"]}
        vless = inbounds["vless"]
        self.assertEqual("127.0.0.1", vless["listen"])
        self.assertEqual(10001, vless["port"])
        self.assertEqual("ws", vless["streamSettings"]["network"])
        self.assertEqual("none", vless["streamSettings"]["security"])
        self.assertEqual("/vless", vless["streamSettings"]["wsSettings"]["path"])
        trojan = inbounds["trojan"]
        self.assertEqual(10002, trojan["port"])
        self.assertEqual("127.0.0.1", trojan["listen"])
        self.assertEqual("ws", trojan["streamSettings"]["network"])
        self.assertEqual("none", trojan["streamSettings"]["security"])
        self.assertEqual("/trojan-ws", trojan["streamSettings"]["wsSettings"]["path"])
        self.assertEqual(2, len(config["inbounds"]))

        with patch.object(xray_config, "_validate_tls", return_value=("/cert.pem", "/key.pem")):
            compatible = xray_config.build_config(
                self.db, "/cert.pem", "/key.pem", legacy_trojan_port=8443)
        legacy = next(item for item in compatible["inbounds"] if item["tag"] == "trojan-tls-legacy")
        self.assertEqual(8443, legacy["port"])
        self.assertEqual("0.0.0.0", legacy["listen"])
        self.assertEqual("tls", legacy["streamSettings"]["security"])
        self.assertEqual("127.0.0.1:10085", config["api"]["listen"])

    def test_http_custom_ssh_connection_sheet_is_copyable_and_ssh_only(self):
        with patch.object(cli, "_install_info", return_value={"domain": "vpn.example.test"}), \
             patch.object(cli, "_ssh_http_ready", return_value=True), \
             patch.object(cli.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="203.0.113.42 STREAM vpn.example.test\n", stderr="")), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            cli._print_connection_details("alice", [], has_ssh=True, ssh_ports=[2222],
                                          expiry_date="2026-12-13", ssh_password="ssh-secret")
        rendered = output.getvalue()
        self.assertIn("Username : alice", rendered)
        self.assertIn("Password : ssh-secret", rendered)
        self.assertIn("Expired On : 2026-12-13", rendered)
        self.assertIn("IP Address : 203.0.113.42", rendered)
        self.assertIn("Host : vpn.example.test", rendered)
        self.assertIn("SSH-WS : 80", rendered)
        self.assertIn("Payload (copy into HTTP Custom) :", rendered)
        self.assertIn("GET / HTTP/1.1[crlf]Host: vpn.example.test[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]", rendered)
        for unsupported in ("OpenSSH", "Dropbear", "SSH-SSL-WS", "SSL/TLS", "UDPGW", "2222", ":443"):
            self.assertNotIn(unsupported, rendered)
        self.assertNotIn("wss://", rendered)
        self.assertNotIn("vless://", rendered)
        self.assertNotIn("trojan://", rendered)

    def test_vless_connection_sheet_contains_only_vless_import_link(self):
        secret = "11111111-1111-4111-8111-111111111111"
        with patch.object(cli, "_install_info", return_value={"domain": "vpn.example.test"}), \
             patch.object(cli.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="203.0.113.42 STREAM vpn.example.test\n", stderr="")), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            cli._print_connection_details("alice", [{"protocol": "vless", "credential": secret}],
                                          expiry_date="2026-12-13")
        rendered = output.getvalue()
        self.assertIn("type=ws", rendered)
        self.assertIn("path=%2Fvless", rendered)
        self.assertIn(f"vless://{secret}@vpn.example.test:443", rendered)
        self.assertEqual(1, rendered.count(secret))
        self.assertNotIn("trojan://", rendered)
        self.assertNotIn("SSH-WS endpoint", rendered)

    def test_trojan_connection_sheet_contains_only_trojan_import_link(self):
        secret = "trojan-secret-value"
        with patch.object(cli, "_install_info", return_value={"domain": "vpn.example.test"}), \
             patch.object(cli.subprocess, "run", return_value=SimpleNamespace(
                 returncode=0, stdout="203.0.113.42 STREAM vpn.example.test\n", stderr="")), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            cli._print_connection_details("alice", [{"protocol": "trojan", "credential": secret}],
                                          expiry_date="2026-12-13")
        rendered = output.getvalue()
        self.assertIn(
            f"trojan://{secret}@vpn.example.test:443?path=%2Ftrojan-ws&security=tls"
            "&host=vpn.example.test&type=ws&sni=vpn.example.test#TROJAN_WS_alice", rendered)
        self.assertIn("Remarks : alice", rendered)
        self.assertIn("Host/IP : vpn.example.test (203.0.113.42)", rendered)
        self.assertIn("Port : 443", rendered)
        self.assertIn(f"Key : {secret}", rendered)
        self.assertIn("Network : ws", rendered)
        self.assertIn("path=%2Ftrojan-ws", rendered)
        self.assertIn("Path : /trojan-ws", rendered)
        self.assertIn("security=tls", rendered)
        self.assertIn("Link WS : trojan://", rendered)
        self.assertIn("Expired On : 2026-12-13", rendered)
        self.assertEqual(2, rendered.count(secret))
        for unsupported in ("trojan-go://", "type=grpc", "serviceName=", "Link GO", "Link GRPC",
                            "Trojan Config", ":8443", ":81"):
            self.assertNotIn(unsupported, rendered)
        self.assertNotIn("vless://", rendered)
        self.assertNotIn("SSH-WS endpoint", rendered)

    def test_interactive_create_commands_provision_only_the_selected_protocol(self):
        commands = (
            ("sshws-create", "openssh", ("alice", "temporary-password", "14", "0"), "temporary-password"),
            ("vless-create", "vless", ("Bobby", "14", "0"), None),
            ("trojan-create", "trojan", ("carol", "14", "0"), None),
        )
        for command, protocol, answers, password in commands:
            with self.subTest(command=command):
                inputs = iter(answers)
                with patch.object(cli.os, "geteuid", return_value=0), \
                     patch("builtins.input", side_effect=lambda _prompt="": next(inputs)) as prompt_input, \
                     patch.object(cli, "_create_managed_account") as create, \
                     patch("sys.stdout", new_callable=io.StringIO):
                    result = cli.main(["--db", str(self.db), command])
                self.assertEqual(0, result)
                username = answers[0]
                expected_expiry = (dt.date.today() + dt.timedelta(days=14)).isoformat()
                create.assert_called_once_with(self.db, username, expected_expiry, 0,
                                               (protocol,), password)
                expected_prompts = ["Username : "]
                if protocol == "openssh":
                    expected_prompts.append("Password : ")
                expected_prompts.append("Expired (days): ")
                expected_prompts.append("Bandwidth quota (GB, lifetime; 0 = unlimited): ")
                self.assertEqual(expected_prompts,
                                 [call.args[0] for call in prompt_input.call_args_list])

    def test_account_create_default_is_not_a_combined_protocol_bundle(self):
        args = cli.parser().parse_args(["account-create", "alice", "--expires", "2026-12-13"])
        self.assertEqual(("openssh",), args.protocols)

    def test_interactive_protocol_create_passes_requested_lifetime_quota(self):
        inputs = iter(("alice", "14", "25"))
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch("builtins.input", side_effect=lambda _prompt="": next(inputs)), \
             patch.object(cli, "_create_managed_account") as create, \
             patch("sys.stdout", new_callable=io.StringIO):
            result = cli.main(["--db", str(self.db), "vless-create"])
        expiry = (dt.date.today() + dt.timedelta(days=14)).isoformat()
        self.assertEqual(0, result)
        create.assert_called_once_with(self.db, "alice", expiry, 25, ("vless",), None)

    def test_http_custom_readiness_checks_public_listener_and_recorded_ssh_port(self):
        with patch.object(cli, "_install_info", return_value={
                "ssh_http_custom": "1", "ssh_target_port": "2222"}), \
             patch.object(cli, "_service_active", return_value=True), \
             patch.object(cli.socket, "create_connection") as connect:
            self.assertTrue(cli._ssh_http_ready())
        self.assertEqual([call(("127.0.0.1", 80), timeout=2),
                          call(("127.0.0.1", 2222), timeout=2)], connect.call_args_list)

        with patch.object(cli, "_install_info", return_value={
                "ssh_http_custom": "1", "ssh_target_port": "2222"}), \
             patch.object(cli, "_service_active", return_value=True), \
             patch.object(cli.socket, "create_connection", side_effect=OSError("closed")):
            self.assertFalse(cli._ssh_http_ready())

    def test_account_create_visible_prompt_passes_password_to_provisioning_only(self):
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        fake_result = {"username": "alice", "expiry_date": expiry,
                       "ssh_password": "chosen-secret", "xray_credentials": []}
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli, "_ssh_meter_timer_active", return_value=False), \
             patch.object(cli, "_require_working_ssh_login", return_value=[22]), \
             patch.object(cli, "_install_info", return_value={
                 "full_xray": "1", "ssh_http_custom": "1", "ssh_target_port": "22"}), \
             patch.object(cli, "_ssh_http_ready", return_value=True), \
             patch.object(cli.provisioning, "create_managed_account", return_value=fake_result) as create, \
             patch.object(cli, "_xray_service_active", return_value=False), \
             patch.object(cli, "_print_connection_details"), \
             patch("builtins.input", side_effect=["chosen-secret", "chosen-secret"]):
            result = cli.main(["--db", str(self.db), "account-create", "alice", "--expires", expiry,
                               "--protocols", "openssh", "--prompt-password"])
        self.assertEqual(0, result)
        self.assertEqual("chosen-secret", create.call_args.kwargs["ssh_password"])
        self.assertEqual(("openssh",), create.call_args.kwargs["protocols"])

    def test_managed_provisioning_passes_chosen_password_to_linux_account_helper(self):
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        with patch.object(provisioning, "create_linux_ssh_account", return_value="chosen-secret") as create_linux:
            result = provisioning.create_managed_account(
                self.db, "Bobby", expiry, protocols=("openssh",), ssh_password="chosen-secret")
        create_linux.assert_called_once_with("Bobby", expiry, "chosen-secret")
        self.assertEqual("chosen-secret", result["ssh_password"])

    def test_account_creation_refuses_foundation_only_install(self):
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli, "_install_info", return_value={"full_xray": "0"}), \
             patch.object(cli.provisioning, "create_managed_account") as create, \
             patch("sys.stderr", new_callable=io.StringIO):
            result = cli.main(["--db", str(self.db), "account-create", "Bobby", "--expires", expiry,
                               "--protocols", "openssh"])
        self.assertEqual(2, result)
        create.assert_not_called()

    def test_vless_creation_refuses_inactive_xray_before_provisioning(self):
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli, "_install_info", return_value={
                 "full_xray": "1", "domain": "vpn.example.test"}), \
             patch.object(cli, "_xray_service_active", return_value=False), \
             patch("builtins.input", side_effect=("bob", "30", "0")), \
             patch.object(cli.provisioning, "create_managed_account") as create, \
             patch("sys.stderr", new_callable=io.StringIO):
            result = cli.main(["--db", str(self.db), "vless-create"])
        self.assertEqual(2, result)
        create.assert_not_called()

    def test_trojan_creation_refuses_inactive_xray_before_provisioning(self):
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli, "_install_info", return_value={
                 "full_xray": "1", "domain": "vpn.example.test"}), \
             patch.object(cli, "_xray_service_active", return_value=False), \
             patch("builtins.input", side_effect=("bob", "30", "0")), \
             patch.object(cli.provisioning, "create_managed_account") as create, \
             patch("sys.stderr", new_callable=io.StringIO):
            result = cli.main(["--db", str(self.db), "trojan-create"])
        self.assertEqual(2, result)
        create.assert_not_called()

    def test_xray_only_creation_provisions_only_the_selected_protocol(self):
        expiry = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        for protocol in ("vless", "trojan"):
            with self.subTest(protocol=protocol):
                credential = {"protocol": protocol, "identity": f"alice-{protocol}@xray.invalid",
                              "credential": f"{protocol}-one-time-secret"}
                result = {"username": "alice", "expiry_date": expiry,
                          "ssh_password": None, "xray_credentials": [credential]}
                with patch.object(cli.os, "geteuid", return_value=0), \
                     patch.object(cli, "_install_info", return_value={
                         "full_xray": "1", "domain": "vpn.example.test"}), \
                     patch.object(cli, "_xray_service_active", return_value=True), \
                     patch.object(cli, "_service_active", return_value=True), \
                     patch.object(cli, "_reconcile_xray_if_active", return_value=True), \
                     patch.object(cli, "_ssh_meter_timer_active", return_value=False), \
                     patch.object(cli, "_seed_new_account_checkpoints"), \
                     patch.object(cli.provisioning, "create_managed_account", return_value=result) as create, \
                     patch.object(cli, "_print_connection_details") as sheet, \
                     patch("sys.stdout", new_callable=io.StringIO):
                    cli._create_managed_account(self.db, "alice", expiry, 0, (protocol,))
                self.assertEqual((protocol,), create.call_args.kwargs["protocols"])
                self.assertEqual([credential], sheet.call_args.args[1])
                self.assertFalse(sheet.call_args.kwargs.get("has_ssh", False))

    def test_quick_install_waits_for_acme_timewait_before_full_install(self):
        source = (ROOT / "quick-install.sh").read_text(encoding="utf-8")
        certbot = source.index("certbot certonly --standalone")
        wait = source.index("wait_for_acme_http_timewait", certbot)
        full_install = source.index('bash "$SOURCE_DIR/install.sh" --full', wait)
        self.assertLess(certbot, wait)
        self.assertLess(wait, full_install)
        self.assertIn("ss -H -tan state time-wait", source)

    def test_full_installer_port_probe_allows_recently_closed_connections(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)", source)
        self.assertIn("Required listener address {host}:{port} is unavailable", source)

    def test_nginx_template_leaves_port_80_to_ssh_and_routes_vless_and_trojan_on_443(self):
        template = (ROOT / "nginx" / "neverbandits.conf.in").read_text(encoding="utf-8")
        rendered = template.replace("@DOMAIN@", "vpn.example.test")
        self.assertIn("listen 443 ssl;", rendered)
        self.assertIn("location ^~ /vless", rendered)
        self.assertIn("proxy_pass http://127.0.0.1:10001;", rendered)
        self.assertIn("location = /trojan-ws", rendered)
        self.assertIn("proxy_pass http://127.0.0.1:10002;", rendered)
        self.assertNotIn("listen 80", rendered)
        self.assertNotIn("/sshws", rendered)
        self.assertNotIn("6080", rendered)
        self.assertIn("neverbandits-ssh-http.service", (ROOT / "src" / "ispbandits" / "cli.py").read_text())
        self.assertNotIn("proxy_pass http://127.0.0.1:22", rendered)
        self.assertNotIn("listen 10001", rendered)


if __name__ == "__main__":
    unittest.main()
