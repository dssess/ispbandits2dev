# Neverbandits HTTP Custom SSH transport

## Data path

- Android clients such as HTTP Custom connect to the VPS on public TCP port 80 and send the legacy Nginx Bandit-style HTTP payload.
- The dedicated `neverbandits-ssh-http.service` listener consumes the payload, returns the legacy `101 Switching Protocols` response, then relays the SSH byte stream to the existing OpenSSH daemon at `127.0.0.1:<effective-sshd-port>`.
- The relay is not a general-purpose CONNECT proxy. It has no arbitrary destination option, applies per-IP and global connection limits, bounds/time-limits the initial payload, and runs as the restricted `ispbd-ws` service account with only the capability needed to bind port 80.
- SSH is advertised only on TCP 80. Neverbandits no longer exposes SSH on 443 or prints a WSS option. SSH still uses OpenSSH authentication and encryption; clients should verify the SSH host key.
- Nginx listens on TLS port 443 and routes `/vless` and `/trojan-ws` to separate loopback Xray inbounds. The alpha-6 Trojan migration is independent of this SSH transport migration; it keeps the old 8443 listener temporarily for existing clients.

## Copy sheet and account creation

The dashboard keeps independent SSH, VLESS, and Trojan creation actions. SSH prompts in Nevermore order: username, visible password, expiry days, then lifetime quota in whole GB (`0` means unlimited). The password is passed to `chpasswd` through stdin and is not stored in SQLite or a command-line argument. The account sheet is arranged by account summary and protocol card, with the server, username, password, expiry, quota and HTTP Custom payload:

```text
GET / HTTP/1.1[crlf]Host: HOSTNAME[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```

Replace `HOSTNAME` with the configured server domain. The relay routes to the server's local SSH daemon, so the backend SSH port is not the Android client port. The relay still accepts the earlier CONNECT-style Nginx Bandit payload. The account remains SSH-only unless a separate protocol is created.

## Upgrade and certificate renewal

On an existing alpha-4 full deployment, run `scripts/migrate-ssh-http80.sh` as root from the new source tree. The migration saves the current managed Nginx site, default-site link, relevant Certbot hooks and new unit path under `/var/backups/ispbandits-dev/`. It stops the legacy bridge, removes Nginx from port 80, removes the SSH path from TLS 443, starts the port-80 relay, and verifies that the local handshake is followed by an actual OpenSSH banner. It restores the previous service files and active state if any migration check fails.

For standalone Certbot renewal, the pre-hook records whether the SSH port-80 relay was active and stops only that relay so Certbot can bind TCP 80. Nginx serves TLS on 443 and stays online. The post-hook restores the relay only when the pre-hook recorded it as active. During an actual renewal attempt, new SSH-over-port-80 connections are unavailable and stopping the relay can interrupt existing relay sessions; Nginx/TLS service is not stopped. A no-interruption HTTP-01 design would require port-80 challenge routing without moving the confirmed relay endpoint, so that topology change remains a separate review item.

The SSH transport migration does not change SSH daemon configuration, account passwords, Xray credentials, firewall rules, or provider firewall settings. Alpha-6 separately adds Trojan WebSocket on TLS 443 and keeps 8443 available for old Trojan clients until they move. New full installs need public TCP 80 and 443; retain TCP 8443 only on an upgraded server while legacy clients still use it.
