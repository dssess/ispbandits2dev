from __future__ import annotations

import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from ispbandits import menu


ROOT = Path(__file__).resolve().parents[1]


class InstallerActivationTests(unittest.TestCase):
    def test_installer_adds_menu_command_transactionally_and_preserves_cli_aliases(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('MENU_WRAPPER="$BIN_DIR/menu"', source)
        self.assertIn("ISPbandits Dev managed menu wrapper", source)
        self.assertIn('exec python3 -m ispbandits menu "\\$@"', source)
        self.assertIn("NEW_MENU_WRAPPER_INSTALLED", source)
        self.assertIn("OLD_MENU_WRAPPER", source)
        self.assertIn("Refusing to overwrite it.", source)
        self.assertIn('Run sudo menu to open the interactive administration menu.', source)
        rerun = source[source.index("verify_managed_full_rerun() {"):source.index("while (($#)); do")]
        self.assertIn('&& -f "$MENU_WRAPPER"', rerun)
        self.assertIn('&& ! -e "$MENU_WRAPPER"', source)
        self.assertIn('echo "Admin menu:  sudo menu"', source)
        quick = (ROOT / "quick-install.sh").read_text(encoding="utf-8")
        self.assertIn("ispbandits2dev/tar.gz/refs/heads/release-candidate/alpha-6", quick)
        self.assertIn('[[ -t 0 && -x /usr/local/bin/menu ]]', quick)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('menu = "ispbandits.cli:menu_main"', project)

    def test_tls_is_staged_before_nginx_site_is_enabled_and_started(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        deploy = source[source.index("deploy_xray() {"):source.index("# Create only missing directories")]
        tls = deploy.index("/usr/local/sbin/ispbandits-dev-refresh-tls || fail")
        mark_files = deploy.index("NGINX_FILES_INSTALLED=1")
        link_site = deploy.index("ln -s /etc/nginx/sites-available/neverbandits")
        nginx_test = deploy.index("/usr/sbin/nginx -t || fail")
        nginx_start = deploy.index("systemctl enable --now nginx.service")
        health = deploy.index("verify_full_runtime_health")
        self.assertLess(tls, mark_files)
        self.assertLess(mark_files, link_site)
        self.assertLess(link_site, nginx_test)
        self.assertLess(nginx_test, nginx_start)
        self.assertLess(nginx_start, health)
        self.assertIn("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", deploy)

    def test_components_have_independent_service_and_listener_checks(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        health = source[source.index("verify_full_runtime_health() {"):source.index("verify_managed_full_rerun() {")]
        self.assertIn('required_service_active nginx.service "Nginx"', health)
        self.assertIn('required_service_active neverbandits-ssh-http.service "HTTP Custom SSH relay"', health)
        self.assertIn('required_service_active ispbandits-xray.service "Xray core"', health)
        self.assertIn('wait_for_tcp_listener "Nginx TLS frontend" 127.0.0.1 443', health)
        self.assertIn('wait_for_tcp_listener "HTTP Custom SSH relay" 127.0.0.1 80', health)
        self.assertIn('wait_for_tcp_listener "VLESS Xray inbound (listener only)" 127.0.0.1 10001', health)
        self.assertIn('wait_for_tcp_listener "Trojan Xray inbound (listener only)" 127.0.0.1 10002', health)
        self.assertIn('statsquery --server=127.0.0.1:10085', health)
        self.assertIn("VLESS/Trojan checks confirm their loopback listeners only", source)

    def test_rerun_is_recognized_and_does_not_reinstall_or_mutate_database(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        rerun = source[source.index("verify_managed_full_rerun() {"):source.index("while (($#)); do")]
        self.assertIn("grep -Fxq \"database_path=$DB_PATH\"", rerun)
        self.assertIn("systemctl enable --now nginx.service", rerun)
        self.assertIn("verify_full_runtime_health", rerun)
        self.assertNotIn("apt-get", rerun)
        self.assertNotIn("sqlite", rerun.lower())
        self.assertNotIn("rm -", rerun)
        self.assertIn("verify_managed_full_rerun", source)
        quick = (ROOT / "quick-install.sh").read_text(encoding="utf-8")
        self.assertIn('bash "$SOURCE_DIR/install.sh" --full --domain "$EXISTING_DOMAIN"', quick)

    def test_failed_required_service_stops_before_success_and_runs_rollback(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        deploy = source[source.index("deploy_xray() {"):source.index("# Create only missing directories")]
        self.assertIn("trap cleanup EXIT", source)
        self.assertIn("Nginx could not be enabled and started", deploy)
        self.assertIn("HTTP Custom SSH relay could not be enabled and started", deploy)
        self.assertIn("Xray core could not be enabled and started", deploy)
        self.assertLess(deploy.index("verify_full_runtime_health"),
                        deploy.index("Neverbandits full deployment passed"))
        cleanup = source[source.index("cleanup() {"):source.index("trap cleanup EXIT")]
        self.assertIn("systemctl stop nginx.service", cleanup)
        self.assertIn("systemctl disable nginx.service", cleanup)
        self.assertIn("rm -f /etc/nginx/sites-enabled/neverbandits", cleanup)
        self.assertIn('[[ ! -e "$DB_PATH" ]] || fail', source)
        self.assertIn('[[ ! -e "$MARKER" && ! -e "$PREFIX/src/ispbandits" ]]', source)

    def test_email_is_not_prompted_for_and_acme_uses_http01_without_cloudflare(self):
        source = (ROOT / "quick-install.sh").read_text(encoding="utf-8")
        self.assertNotIn('prompt EMAIL', source)
        self.assertIn("--register-unsafely-without-email", source)
        self.assertIn("certbot certonly --standalone", source)
        self.assertIn("--preferred-challenges http", source)
        self.assertNotIn("CF_API", source)
        self.assertNotIn("CLOUDFLARE_API", source)

    def test_tls_refresh_rolls_back_current_pointer_when_xray_restart_fails(self):
        refresh = (ROOT / "scripts" / "refresh-tls.sh").read_text(encoding="utf-8")
        self.assertIn("openssl x509 -in", refresh)
        self.assertIn("openssl pkey -passin pass:", refresh)
        self.assertIn("restore_previous_state", refresh)
        self.assertIn("nginx -t", refresh)
        self.assertIn("systemctl reload", refresh)
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True).returncode != 0:
                self.skipTest("TLS refresh failure injection requires root or passwordless sudo")
        else:
            sudo = None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cert = root / "renewed-cert.pem"
            key = root / "renewed-key.pem"
            cert.write_text("test-certificate", encoding="utf-8")
            key.write_text("test-private-key", encoding="utf-8")
            tls_root = root / "tls"
            previous = tls_root / "versions" / "previous"
            previous.mkdir(parents=True)
            (previous / "fullchain.pem").write_text("previous-certificate", encoding="utf-8")
            (previous / "privkey.pem").write_text("previous-key", encoding="utf-8")
            (tls_root / "current").symlink_to(previous)
            env_file = root / "source.env"
            env_file.write_text(
                f'TLS_CERT_SOURCE="{cert}"\nTLS_KEY_SOURCE="{key}"\nTLS_DOMAIN="vpn.example.test"\n',
                encoding="utf-8",
            )
            systemctl_log = root / "systemctl.log"
            fail_marker = root / "xray-first-restart.failed"
            nginx_log = root / "nginx.log"
            (bin_dir / "openssl").write_text(
                "#!/usr/bin/env bash\n"
                'case "$*" in\n'
                '  *-checkhost*|*-checkend*) exit 0 ;;\n'
                '  *-pubkey*|*-pubin*|*-pubout*) printf same-public-key ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n', encoding="utf-8",
            )
            (bin_dir / "systemctl").write_text(
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$*" >> "$SYSTEMCTL_LOG"; chmod 0644 "$SYSTEMCTL_LOG"\n'
                'case "$1" in\n'
                '  is-active) exit 0 ;;\n'
                '  restart) if [[ "$2" == "ispbandits-xray.service" && ! -e "$FAIL_MARKER" ]]; then touch "$FAIL_MARKER"; exit 1; fi; exit 0 ;;\n'
                '  reload) exit 0 ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n', encoding="utf-8",
            )
            (bin_dir / "nginx").write_text(
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$*" >> "$NGINX_LOG"; chmod 0644 "$NGINX_LOG"; exit 0\n',
                encoding="utf-8",
            )
            for executable in bin_dir.iterdir():
                executable.chmod(0o755)
            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "ISPBD_TLS_ENV": str(env_file),
                "ISPBD_TLS_ROOT": str(tls_root),
                "ISPBD_TLS_GROUP": str(os.getgid()),
                "SYSTEMCTL_LOG": str(systemctl_log),
                "FAIL_MARKER": str(fail_marker),
                "NGINX_LOG": str(nginx_log),
            })
            if sudo:
                assignments = [f"{name}={value}" for name, value in env.items()
                               if name in {"PATH", "ISPBD_TLS_ENV", "ISPBD_TLS_ROOT", "ISPBD_TLS_GROUP",
                                           "SYSTEMCTL_LOG", "FAIL_MARKER", "NGINX_LOG"}]
                command = [sudo, "-n", "env", *assignments, "bash", str(ROOT / "scripts" / "refresh-tls.sh")]
            else:
                command = ["bash", str(ROOT / "scripts" / "refresh-tls.sh")]
            try:
                result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=20)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertTrue((tls_root / "current").resolve().samefile(previous))
                calls = systemctl_log.read_text(encoding="utf-8")
                self.assertGreaterEqual(calls.count("restart ispbandits-xray.service"), 2)
                self.assertIn("reload nginx.service", calls)
                self.assertIn("-t", nginx_log.read_text(encoding="utf-8"))
                self.assertIn("restoring the previous certificate", result.stderr)
            finally:
                if sudo:
                    subprocess.run([sudo, "-n", "rm", "-rf", str(root)], check=False,
                                   capture_output=True, timeout=20)
                else:
                    shutil.rmtree(root, ignore_errors=True)

    def test_menu_reports_nginx_xray_vless_trojan_and_ssh_checks_independently(self):
        def listener_state(host: str, port: int) -> str:
            return "unreachable" if port == 10001 else "ready"

        output = StringIO()
        with patch.object(menu, "_service_state", return_value="active"), \
             patch.object(menu, "_tcp_listener_state", side_effect=listener_state), \
             patch.object(menu, "_xray_api_state", return_value="ready"), \
             redirect_stdout(output):
            menu._service_status()
        rendered = output.getvalue()
        self.assertIn("Nginx frontend", rendered)
        self.assertIn("Nginx TLS listener 127.0.0.1:443", rendered)
        self.assertIn("SSH HTTP Custom port 80", rendered)
        self.assertIn("Xray StatsService API", rendered)
        self.assertIn("VLESS inbound listener only", rendered)
        self.assertIn("Trojan inbound listener only", rendered)
        self.assertRegex(rendered, r"VLESS inbound listener only\s+unreachable")
        self.assertRegex(rendered, r"Trojan inbound listener only\s+ready")
        self.assertIn("EXTERNAL CLIENT CONNECTIVITY: NOT TESTED", rendered)


class CertbotRenewalHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.systemctl = self.root / "systemctl"
        self.log = self.root / "calls.log"
        self.active = self.root / "relay.active"
        self.state = self.root / "state" / "was-active"
        self.systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf "%s\\n" "$*" >> "$CALL_LOG"\n'
            'case "$1" in\n'
            '  is-active) [[ -f "$ACTIVE_MARKER" ]] ;;\n'
            '  stop) [[ "${FAIL_STOP:-0}" != 1 ]] || exit 1; rm -f "$ACTIVE_MARKER" ;;\n'
            '  start) touch "$ACTIVE_MARKER" ;;\n'
            '  *) exit 2 ;;\n'
            'esac\n',
            encoding="utf-8",
        )
        self.systemctl.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update({
            "NEVERBANDITS_SYSTEMCTL": str(self.systemctl),
            "NEVERBANDITS_CERTBOT_STATE_FILE": str(self.state),
            "CALL_LOG": str(self.log),
            "ACTIVE_MARKER": str(self.active),
        })

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, filename: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env.update(extra_env)
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / filename)],
            check=False, capture_output=True, text=True, env=env,
        )

    def test_active_relay_is_paused_and_restored_without_touching_nginx(self):
        self.active.touch()
        pre = self.run_hook("certbot-stop-nginx.sh")
        self.assertEqual(0, pre.returncode, pre.stderr)
        self.assertTrue(self.state.is_file())
        self.assertFalse(self.active.exists())
        post = self.run_hook("certbot-start-nginx.sh")
        self.assertEqual(0, post.returncode, post.stderr)
        self.assertTrue(self.active.is_file())
        self.assertFalse(self.state.exists())
        calls = self.log.read_text(encoding="utf-8")
        self.assertIn("stop neverbandits-ssh-http.service", calls)
        self.assertIn("start neverbandits-ssh-http.service", calls)
        self.assertNotIn("nginx", calls.lower())

    def test_inactive_relay_stays_inactive_after_renewal(self):
        pre = self.run_hook("certbot-stop-nginx.sh")
        self.assertEqual(0, pre.returncode, pre.stderr)
        post = self.run_hook("certbot-start-nginx.sh")
        self.assertEqual(0, post.returncode, post.stderr)
        self.assertFalse(self.active.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn("start neverbandits-ssh-http.service", self.log.read_text(encoding="utf-8"))

    def test_post_hook_recovers_relay_after_pre_hook_stop_failure(self):
        self.active.touch()
        pre = self.run_hook("certbot-stop-nginx.sh", FAIL_STOP="1")
        self.assertNotEqual(0, pre.returncode)
        self.assertTrue(self.state.is_file())
        post = self.run_hook("certbot-start-nginx.sh")
        self.assertEqual(0, post.returncode, post.stderr)
        self.assertTrue(self.active.is_file())
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
