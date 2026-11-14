# Neverbandits protocol integration (alpha-6 candidate)

Neverbandits creates separate VLESS UUIDs and Trojan passwords in the protected SQLite database, then generates a root-protected Xray configuration. VLESS uses WebSocket path `/vless` on loopback `127.0.0.1:10001`; Trojan uses WebSocket path `/trojan-ws` on loopback `127.0.0.1:10002`. Nginx terminates TLS on public TCP 443 and proxies each path to its separate Xray inbound. Xray StatsService stays on `127.0.0.1:10085`. Trojan receipts now follow Nevermore's URI format, including query order and profile label:

```text
trojan://<credential>@<domain>:443?path=%2Ftrojan-ws&security=tls&host=<domain>&type=ws&sni=<domain>#TROJAN_WS_<username>
```

The ordering is for format compatibility; it does not make encryption stronger by itself. TLS strength comes from the TLS connection and valid certificate, while Trojan authentication uses the credential. A recognized alpha-5 upgrade retains its old direct Trojan TLS listener on TCP 8443, with unchanged account passwords and stats identities, until users migrate; fresh installs do not expose 8443. The generated Xray configuration contains credentials and must remain root-owned and readable only by the Xray service group.

## SSH-over-HTTP Custom

SSH uses a dedicated public TCP port-80 relay that reproduces the Nginx Bandit HTTP Custom flow. It consumes an HTTP-looking client payload, returns the legacy `101 Switching Protocols` response, then relays the SSH stream to the existing local sshd port. New Neverbandits receipts use a conventional `GET / HTTP/1.1` WebSocket-upgrade payload; the earlier CONNECT-style payload is also accepted. SSH is not exposed on port 443. The SSH password is sent to `chpasswd` over stdin and is never stored in SQLite or CLI arguments. See [the HTTP Custom SSH transport note](sshws-architecture.md).

## Commands and creation prompts

```text
sudo neverbandits sshws-create
sudo neverbandits vless-create
sudo neverbandits trojan-create
neverbandits account-create USER --expires YYYY-MM-DD [--protocols openssh vless trojan] [--prompt-password]
neverbandits xray-provision USER vless|trojan [--rotate]
sudo neverbandits xray-config --cert-file CERT --key-file KEY [--check-only]
sudo neverbandits online
sudo neverbandits renew USER --expires YYYY-MM-DD
sudo neverbandits disable USER
sudo neverbandits enable USER
sudo neverbandits account-delete USER --yes
```

The dashboard's creation actions are independent. SSH prompts in Nevermore's order: username, visible password, expiry days, then lifetime quota in whole GB (`0` means unlimited). VLESS and Trojan each prompt for username, expiry days, and the same quota choice. SSH creates only a no-home `/bin/false` Linux account; VLESS/Trojan create only that Xray protocol. Before SSH creation, Neverbandits checks the existing sshd's effective password-authentication and TCP-forwarding policy. It does not alter sshd or administrator account settings. Receipts are arranged as an account summary plus protocol-specific copy-ready connection sheets.

A nonzero shared quota is accepted only when the experimental SSH meter and the full quota-enforcement collector are active and a fresh valid snapshot exists; otherwise the account is not provisioned. The installer keeps this mode opt-in pending live validation. See [the shared quota contract](ssh-meter-contract.md).

`xray-provision` and credential rotation require a recognized full install marker, active Xray and active Nginx. If activation or a post-activation health check fails, the previous credential state is restored where possible. The one-time credential is contained only in its protocol-specific import link.

`xray-config` validates through the installed Xray executable before writing a protected configuration. `--apply` atomically updates configuration and restores the prior file if restart fails. For an upgraded alpha-5 installation, config reconciliation preserves both the new Trojan WS inbound and the temporary legacy 8443 inbound using the same stable account identities. Expiry reconciliation stops Xray if the regenerated configuration cannot be activated.

On a fresh full installation, TLS material is validated and staged before the TLS Nginx site is enabled. The installer runs `nginx -t`, enables/starts Nginx, and then checks Nginx TCP 443, the SSH relay service and TCP 80, Xray's service and StatsService API, and the VLESS (`127.0.0.1:10001`) and Trojan (`127.0.0.1:10002`) listeners independently. The menu's SERVICE STATUS screen reports these same units, API, and local listeners independently; a healthy Nginx badge does not imply healthy VLESS/Trojan listeners. These TCP/API checks fail installation on missing required components, but a listener check alone does not prove successful external routing or authenticated client connectivity. Re-running quick-install on a recognized full deployment revalidates health and idempotently ensures Nginx is enabled/running without rewriting the site or database.

## Traffic and online status

Xray statistics require a `stats` object, per-level `statsUserUplink` and `statsUserDownlink` policy flags, and unique non-empty user `email` identities. The collector maps each identity to one VLESS or Trojan account. `statsUserOnline` is enabled, but the management CLI does not yet display Xray online counts. SSH online status counts matching sshd processes and is not a unique-device count.

The default collector records Xray traffic only. An opt-in experimental OpenSSH producer samples nftables counters and a separate full collector enforces shared lifetime quotas across managed OpenSSH, VLESS and Trojan. It counts IP-layer bytes, not pure payload, can miss traffic before a session is attributed, and may overshoot between samples. Enforcement polls about every five seconds, so this is not a hard real-time byte ceiling and must not be used for billing or strict production caps.

## Validation and known limits

Automated tests cover Xray config generation, loopback inbounds and paths, stable user identities, protocol-specific connection sheets, the GET-style and legacy HTTP Custom handshakes, account flow and failure rollback. The SSH relay has been confirmed working on the authorized VPS with the original Android payload. The alpha-6 migration performs an Xray config test, reloads Nginx, applies the dual Trojan listeners, and verifies a local TLS `/trojan-ws` handshake before committing the marker. Android authenticated login using the new GET payload and a real Trojan VPN-client connection remain acceptance tests; additional supported OS/kernel/OpenSSH quota validation is also outstanding.

## Official Xray references

- [Xray installation](https://xtls.github.io/en/document/install.html)
- [Xray API](https://xtls.github.io/en/config/api.html)
- [Xray policy](https://xtls.github.io/en/config/policy.html)
- [Xray traffic statistics](https://xtls.github.io/en/config/stats.html)
- [Xray VLESS inbound](https://xtls.github.io/en/config/inbounds/vless.html)
- [Xray Trojan inbound](https://xtls.github.io/en/config/inbounds/trojan.html)
- [Xray WebSocket transport](https://xtls.github.io/en/config/transports/websocket.html)
