# Neverbandits — Unified VPS Manager

**Version:** 1.0.0-alpha.6 candidate
**Publisher:** ISPbandits Dev
**License:** Proprietary (`LICENSE.proprietary`)

<p align="center">
  <img src="assets/ispbandits-breathing-banner.gif" alt="A cyan and amber network loop softly breathing against a deep navy background" width="100%" />
</p>

<p align="center"><strong>One control plane. A steady pulse.</strong><br />
HTTP Custom SSH · VLESS · Trojan WebSocket · SQLite · Unified traffic records</p>

Neverbandits combines Nevermore-style account creation and connection sheets with ISPbandits Dev's unified SQLite account lifecycle, Xray VLESS/Trojan identities, usage collection, backups, expiry processing, and optional experimental shared-quota enforcement.

> **Alpha warning:** The HTTP Custom SSH relay is being validated against the original Nginx Bandit port-80 flow. Authenticated Android-client login against Neverbandits still needs real-device testing. Use a **fresh, disposable VPS** for new deployment. The optional OpenSSH traffic meter and shared lifetime quota remain experimental and are not validated for production billing or hard caps.

## What runs on the VPS

| Client protocol | Public entry | Backend | Notes |
|---|---|---|---|
| SSH with HTTP Custom payload | TCP 80 | restricted relay → existing sshd port | Legacy Nginx Bandit handshake; SSH verifies/encrypts the session |
| VLESS over WebSocket/TLS | TCP 443, path `/vless` | Nginx TLS → Xray at `127.0.0.1:10001` | SSH is not exposed on 443 |
| Trojan over WebSocket/TLS | TCP 443, path `/trojan-ws` | Nginx TLS → Xray at `127.0.0.1:10002` | New receipts use the shared HTTPS front door |
| Legacy Trojan over TLS/TCP | TCP 8443 | Xray | Retained only on upgraded alpha-5 servers during client migration |
| Xray StatsService | loopback `127.0.0.1:10085` | Xray | Never exposed on a public interface |

The SSH relay owns public TCP port 80 and connects only to the effective local port reported by `sshd -T`. Nginx terminates TLS on 443 and routes `/vless` and `/trojan-ws` to separate loopback Xray inbounds. A recognized alpha-5 upgrade temporarily retains direct Trojan on 8443 for existing clients; new Trojan receipts use 443. Neverbandits does **not** rewrite SSH configuration, install a replacement SSH daemon, modify firewall rules, or change cloud firewall settings.

See [the HTTP Custom SSH architecture and safety notes](docs/sshws-architecture.md) for service details and the alpha-4 migration.

## Requirements and pre-install checks

Use a fresh Ubuntu 22.04/24.04 or Debian 12/13 VPS with systemd, root access, and internet connectivity. The host must already have a working OpenSSH server/socket. Password authentication and TCP forwarding must be allowed by that account's effective sshd policy; Neverbandits will refuse SSH account creation rather than silently weakening that policy.

1. Point the chosen hostname's DNS A/AAAA records at this VPS. The hostname must resolve to the server and match the TLS certificate. The installer enables IPv6 Nginx listeners only when the VPS kernel supports IPv6; do not publish an AAAA record unless that IPv6 address is reachable. No special nameserver delegation is needed beyond your normal DNS setup.
2. Keep public TCP **80 and 443** free for Neverbandits. Xray loopback ports **10001, 10002, and 10085** must also be free. The installer detects conflicts before deployment. Existing alpha-5 upgrades retain their current 8443 listener for compatibility.
3. Allow inbound TCP **80 and 443** in the VPS/provider firewall. The installer does not change those rules. Keep your existing SSH admin port reachable; Neverbandits does not change it. Do not close 8443 on an upgraded server until all old Trojan clients have moved to 443.
4. Use a Let's Encrypt certificate (recommended) or provide an existing certificate and matching key. A self-signed certificate is for testing only and must be explicitly trusted by clients.

Do not run a full install on an existing NevermoreSSH/Nginx Bandit VPS or a host with an active Nginx site. The installer refuses occupied ports, active Nginx, non-default enabled Nginx sites, and extra `conf.d` files instead of replacing them.

## Quick install (fresh VPS)

Review the bootstrapper before running it on the new VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/dssess/ispbandits2dev/refs/heads/release-candidate/alpha-6/quick-install.sh -o quick-install.sh
less quick-install.sh
sudo bash quick-install.sh
```

The guided installer asks for the hostname and TLS choice. Let's Encrypt requires DNS already pointed at the VPS and port 80 reachable; certificate registration does not prompt for an email address (an optional `--email` can be supplied). Nginx is configured only after the managed certificate/key are staged, checked with `nginx -t`, enabled, started, and verified. Standalone HTTP-01 renewal briefly stops only the port-80 SSH relay because it owns the challenge port; active SSH relay sessions may disconnect, but Nginx stays online on 443. The relay is restored only if it was active before renewal. You can instead provide certificate files or explicitly choose self-signed testing TLS. The script pauses for a typed `YES` before changing the fresh VPS.

For disposable quota testing only, opt into sampled SSH+Xray quota enforcement with `sudo bash quick-install.sh --experimental-ssh-meter`; it is disabled by default and is not a strict byte ceiling.

The full installer installs Nginx, Xray, the restricted SSH HTTP Custom relay, Neverbandits-owned systemd units, SQLite/CLI files, and the network configuration. It independently checks the Nginx TLS listener, SSH relay, Xray API, and VLESS/Trojan loopback listeners; listener checks are not a substitute for real client-authentication tests. Re-running `quick-install.sh` on a recognized full install performs a non-destructive health recheck and ensures Nginx is enabled/running without changing the database or overwriting configuration. It does not open ports in the provider firewall. When installation completes, open the original cyan-framed interactive menu with:

```bash
sudo menu
```

The `neverbandits` and `ispbandits` commands remain available for direct CLI operations; `menu` is the interactive entrypoint.

## Manual full install

From a checked-out source tree, supply a matching TLS certificate/key pair:

```bash
sudo ./install.sh --full \
  --domain vpn.example.com \
  --cert-file /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key-file /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

For Certbot certificates obtained using the standalone HTTP-01 method, add `--certbot-standalone` so renewal hooks briefly stop/restart only the port-80 SSH relay and deploy the renewed certificate to Xray/Nginx. Nginx remains online on 443. Use `--self-signed` only for testing. `./install.sh --check` runs syntax and unit tests without installing system files.

The earlier `v1.0.0-alpha.1` full deployment has a different topology and cannot be upgraded in place. Alpha-6 migrates recognized older full installs to HTTP Custom SSH on port 80 and Trojan WebSocket on TLS 443. It retains the direct 8443 Trojan listener for existing clients, backs up the managed Nginx/Xray files and database, and prints only the new 443 connection details.

## Create accounts and get connection details

The cyan-framed menu follows the original Nevermore arrangement: server information, a compact service-status strip, numbered options, version footer, and `Select menu :` prompt. The protocol entries are **[01] SSHWS**, **[03] VLESS**, and **[04] TROJAN**; VMess is not implemented and is not presented as a working option. Choose **[L] More actions** to open the management sections, then select **[1] Legacy ISPBandits actions 1–18** to reach all previous numbered actions. Unsupported Nevermore-only features are not represented as successful operations. Choosing a protocol entry creates only that protocol; the CLI remains the execution engine.

SSH follows Nevermore's prompt order: `Username :`, `Password :`, `Expired (days):`, then `Bandwidth quota (GB, lifetime; 0 = unlimited):`. Password entry uses a hidden prompt and is sent to `chpasswd` over stdin; after successful provisioning, the password is shown once in the receipt and is not stored in SQLite, CLI arguments, or Nginx configuration. The copy-ready receipt lists the username, password, expiry, quota, IP address, host, `SSH-WS : 80`, and HTTP Custom payload. It omits the sshd backend and unrelated ports; customer SSH is presented on port 80 only.

VLESS and Trojan each prompt for username, expiry, and the same lifetime quota choice, generate their own credential, and show only that protocol's server settings and import link. The Trojan receipt lists remarks, host/IP, key, expiry, quota, port 443, WebSocket network, `/trojan-ws` path, and one `trojan://` WebSocket link. It does not advertise Trojan-Go, gRPC, or a config-file endpoint; those formats are not implemented by this release. The protocol flows do not create an SSH Linux user or provision the other Xray protocol. A nonzero cap is accepted only while the experimental meter and full quota collector are active with a fresh valid snapshot; otherwise creation fails before provisioning.

For a directly opened interactive flow, use one command at a time:

```bash
sudo neverbandits sshws-create
sudo neverbandits vless-create
sudo neverbandits trojan-create
```

Before provisioning, Neverbandits checks the corresponding live services and the loopback sshd target where relevant. If the required Xray/Nginx/HTTP Custom SSH service is unavailable, account creation stops before provisioning; if a listener fails during activation, it rolls back the new account before showing the receipt. VLESS UUIDs and Trojan credentials appear only in their protocol-specific receipt; the Trojan key is also part of its WebSocket import link. The lower-level `account-create` command remains available for an operator who explicitly wants to create multiple protocols together; it is not used by the dashboard's three create actions.

The SSH sheet uses the conventional GET/Upgrade payload shape:

```text
GET / HTTP/1.1[crlf]Host: HOST[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```

Use an HTTP Custom-compatible client and replace `HOST` with the configured domain. The Android client connects to port 80. The HTTP payload itself is not TLS-protected, but the SSH session that follows is authenticated and encrypted. Verify the SSH host key. The previous CONNECT-style Nginx Bandit payload remains supported by the relay, but new Neverbandits receipts use GET.

## Account lifecycle and monitoring

```bash
sudo neverbandits account-list
sudo neverbandits account-show alice       # never prints stored credentials
sudo neverbandits usage
sudo neverbandits online                  # approximate sshd process counts, not devices
sudo neverbandits renew alice --expires 2027-06-01
sudo neverbandits disable alice
sudo neverbandits enable alice
sudo neverbandits ssh-password-reset alice # displays the replacement once
sudo neverbandits expire
sudo neverbandits verify
```

The menu dashboard shows host CPU, RAM, storage, uptime, and network totals. When `vnstat` is available, daily and monthly host-interface totals are shown in the Nginxbandit style; these are host-wide traffic estimates, not per-user usage or quota measurements. Full fresh installs include vnStat. Option 17 (`CHECK BANDWIDTH`) uses the same daily/monthly view, falling back to kernel interface counters since boot or counter reset if vnStat is unavailable. The Traffic & Quota screen lists only usernames with an observed SSH/Dropbear daemon process. Its process count is approximate and must not be treated as a unique device count. Live session checks are on demand; Neverbandits does not add a monitoring daemon.

Account creation provisions a no-home `/bin/false` Linux SSH account and selected Xray identities. Before creating an SSH account it checks effective `PasswordAuthentication`, TCP forwarding, authentication-method, and daemon state; it never edits sshd configuration. Disable/expiry locks the Linux password, terminates managed SSH sessions, and removes the account's Xray identities from active configuration. Renewal does not silently clear disabled, expired, or quota states. Permanent deletion requires `account-delete USER --yes` and removes usage history, so back up first.

The default collector records Xray VLESS/Trojan usage every minute. SSH network-byte metering is a separate opt-in experimental install option. It counts per-session IP-layer bytes (not pure payload), can miss authentication-period traffic, and may overshoot between samples. Do not use it for billing or strict production caps until validated on each exact OS/kernel/OpenSSH configuration.

## Shared lifetime quota (experimental)

The experimental quota mode combines measured managed OpenSSH plus VLESS/Trojan traffic in SQLite. It disables all linked protocols when measured usage reaches the cap. This is sampled enforcement, not a hard byte ceiling: the five-second collection interval, concurrent sessions, retransmissions, traffic before account attribution, and in-flight data can overshoot. It requires the SSH meter, full quota collector, fresh valid snapshot, and active Xray service. `0` means unlimited; values are decimal GB (1 GB = 1,000,000,000 bytes).

On a fresh disposable test VPS only, opt in during installation with `--experimental-ssh-meter` and review [the metering contract](docs/ssh-meter-contract.md). The interactive SSH/VLESS/Trojan create flows ask for the cap; the explicit quota command remains available:

```bash
sudo neverbandits quota-set alice --limit-gb 50
sudo neverbandits quota-set alice --limit-gb 0  # unlimited
```

## Back up and restore

```bash
sudo neverbandits backup --dir /var/backups/ispbandits-dev
sudo neverbandits restore /var/backups/ispbandits-dev/ispbandits-YYYYMMDDTHHMMSS.ffffffZ.tar.gz \
  --dir /var/backups/ispbandits-dev
```

Backups contain account records and protocol secrets; keep them private. Restore validates the archive and checksum, preserves a rollback backup, quiesces managed services, and reconciles Xray. It is not a full VPS image and does not restore certificates, Nginx/service files, or Linux accounts removed outside Neverbandits.

## Development and release checks

The Python application requires Python 3.10+ with SQLite. Local tests do not require third-party Python runtime packages:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
bash -n install.sh quick-install.sh scripts/refresh-tls.sh scripts/certbot-stop-nginx.sh scripts/certbot-start-nginx.sh scripts/certbot-refresh-tls.sh scripts/migrate-ssh-http80.sh
./install.sh --check
```

The earlier full installer and a trusted public certificate were validated on one fresh Ubuntu 24.04 VPS. The alpha-5 SSH port-80 relay has been confirmed working on the VPS. Alpha-6 adds GET payload regression coverage and an upgrade migration that verifies `/trojan-ws` returns a TLS WebSocket `101` while preserving legacy 8443 access. Remaining release gates include retesting the GET payload and authenticated login in the Android client, testing a real Trojan VPN client, and fresh Ubuntu 22.04/Debian 12/13 installs.

The current unit suite tests the HTTP Custom payload, legacy `101` response, raw SSH banner forwarding and byte relay using loopback-only temporary servers. It does not touch the VPS or bind public ports:

```bash
PYTHONPATH=src python3 -m unittest tests.test_ssh_http_proxy -v
```

Passing these tests confirms the relay protocol path with a dummy SSH backend only. It does **not** prove authenticated login against sshd, real Android app payload compatibility, or successful installation on every supported operating system.

## Branding and copyright

**Neverbandits** is the product name. **ISPbandits Dev** is the publisher and copyright owner.

© 2026 ISPbandits Dev. All rights reserved. Proprietary software. Unauthorized copying, redistribution, or resale is prohibited. Public repository visibility does not grant a right to reuse or redistribute this code; see `LICENSE.proprietary`.
