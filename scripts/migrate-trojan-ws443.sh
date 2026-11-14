#!/usr/bin/env bash
# Migrate a managed Neverbandits deployment to Trojan WebSocket over TLS/443.
# Existing direct Trojan TLS/8443 clients remain supported during transition.
set -Eeuo pipefail
umask 077

PREFIX=/opt/ispbandits-dev
MARKER=$PREFIX/INSTALL_INFO
SITE=/etc/nginx/sites-available/neverbandits
ENABLED_SITE=/etc/nginx/sites-enabled/neverbandits
XRAY_CONFIG=/etc/ispbandits-dev/xray.json
DB=/var/lib/ispbandits-dev/database.db
CLI=/usr/local/bin/neverbandits
BACKUP_ROOT=/var/backups/ispbandits-dev
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() { echo "Trojan WS migration: $*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || fail "run as root."
[[ -r "$MARKER" && -r "$SITE" && -r "$XRAY_CONFIG" && -L "$ENABLED_SITE" && -f "$DB" ]] || fail "recognized full install files are missing."
grep -Fxq 'managed_by=ISPbandits-Dev-install.sh' "$MARKER" || fail "unknown install marker; refusing migration."
grep -Fxq 'full_xray=1' "$MARKER" || fail "full Xray/Nginx deployment is required."
domain=$(sed -n 's/^domain=//p' "$MARKER" | head -n 1)
[[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || fail "invalid domain in install marker."
[[ -x "$CLI" && -f "$SOURCE_DIR/nginx/neverbandits.conf.in" ]] || fail "updated CLI or Nginx template is missing."
systemctl is-active --quiet nginx.service || fail "Nginx is not active; no changes made."
systemctl is-active --quiet ispbandits-xray.service || fail "Xray is not active; no changes made."

if grep -Fxq 'trojan_ws=1' "$MARKER" && grep -Fq 'location = /trojan-ws' "$SITE"; then
  echo "Trojan WebSocket on TLS/443 is already configured; no changes made."
  exit 0
fi

# Only migrate the known current alpha-5 direct TLS listener. Refuse unknown layouts.
python3 - "$XRAY_CONFIG" "$SITE" <<'PY' || fail "installed Xray/Nginx layout is not the expected alpha-5 configuration."
import json, sys
config = json.load(open(sys.argv[1], encoding="utf-8"))
site = open(sys.argv[2], encoding="utf-8").read()
legacy = [item for item in config.get("inbounds", [])
          if item.get("protocol") == "trojan" and item.get("port") == 8443
          and item.get("listen") == "0.0.0.0"
          and item.get("streamSettings", {}).get("network") == "tcp"
          and item.get("streamSettings", {}).get("security") == "tls"]
vless = [item for item in config.get("inbounds", [])
         if item.get("protocol") == "vless" and item.get("port") == 10001
         and item.get("listen") == "127.0.0.1"]
if len(legacy) != 1 or len(vless) != 1 or "location ^~ /vless" not in site:
    raise SystemExit(1)
PY

python3 - <<'PY' || fail "loopback port 10002 is already in use."
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", 10002))
finally:
    s.close()
PY

install -d -o root -g root -m 0700 "$BACKUP_ROOT"
backup=$(mktemp -d "$BACKUP_ROOT/trojan-ws443-migration-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
install -d -o root -g root -m 0700 "$backup/files"
cp -a -- "$SITE" "$backup/files/neverbandits.site"
cp -a -- "$XRAY_CONFIG" "$backup/files/xray.json"
cp -a -- "$MARKER" "$backup/files/INSTALL_INFO"
printf 'nginx_active=1\nxray_active=1\n' > "$backup/service-state"

complete=0
rollback() {
  local rc=$?
  if (( rc != 0 && complete == 0 )); then
    echo "Migration failed; restoring the prior site, Xray config and marker from $backup" >&2
    set +e
    cp -a -- "$backup/files/neverbandits.site" "$SITE"
    cp -a -- "$backup/files/xray.json" "$XRAY_CONFIG"
    cp -a -- "$backup/files/INSTALL_INFO" "$MARKER"
    /usr/sbin/nginx -t >/dev/null 2>&1
    systemctl reload nginx.service >/dev/null 2>&1 || systemctl restart nginx.service >/dev/null 2>&1
    systemctl restart ispbandits-xray.service >/dev/null 2>&1
    set -e
    echo "Rollback attempted; inspect Nginx/Xray service state and $backup." >&2
  fi
  exit "$rc"
}
trap rollback EXIT

# Stage and test the exact Nginx configuration before it becomes active.
if python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    s.bind(("::1", 0))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
then
  sed "s/@DOMAIN@/$domain/g" "$SOURCE_DIR/nginx/neverbandits.conf.in" > "$backup/neverbandits.site.new"
else
  sed -e "s/@DOMAIN@/$domain/g" -e '/^[[:space:]]*listen \[::\]:/d' \
    "$SOURCE_DIR/nginx/neverbandits.conf.in" > "$backup/neverbandits.site.new"
fi
chmod 0644 "$backup/neverbandits.site.new"

# Verify the new Xray WS inbound is accepted before touching the active config.
"$CLI" xray-config --cert-file /etc/ispbandits-dev/tls/current/fullchain.pem \
  --key-file /etc/ispbandits-dev/tls/current/privkey.pem \
  --output "$XRAY_CONFIG" --vless-port 10001 --trojan-port 10002 \
  --legacy-trojan-port 8443 --api-port 10085 --xray-bin /usr/local/bin/xray --check-only

# Xray stats are in memory; collect them transactionally before its config reload resets counters.
"$CLI" collect --xray-only

install -o root -g root -m 0644 "$backup/neverbandits.site.new" "$SITE"
/usr/sbin/nginx -t
systemctl reload nginx.service

# Apply the dual-listener config. User identities and Xray stats emails are unchanged.
"$CLI" xray-config --cert-file /etc/ispbandits-dev/tls/current/fullchain.pem \
  --key-file /etc/ispbandits-dev/tls/current/privkey.pem \
  --output "$XRAY_CONFIG" --vless-port 10001 --trojan-port 10002 \
  --legacy-trojan-port 8443 --api-port 10085 --xray-bin /usr/local/bin/xray --apply
systemctl is-active --quiet nginx.service || fail "Nginx stopped after applying the route."
systemctl is-active --quiet ispbandits-xray.service || fail "Xray stopped after adding Trojan WS."

# Verify public TLS termination and the WebSocket upgrade locally, using the real domain SNI.
python3 - "$domain" <<'PY'
import socket, ssl, sys
host = sys.argv[1]
context = ssl.create_default_context()
with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
    with context.wrap_socket(raw, server_hostname=host) as conn:
        conn.settimeout(5)
        request = (f"GET /trojan-ws HTTP/1.1\r\nHost: {host}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        conn.sendall(request.encode("ascii"))
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 4096:
            block = conn.recv(1)
            if not block:
                break
            response += block
        if not response.startswith(b"HTTP/1.1 101"):
            raise SystemExit("TLS /trojan-ws did not return HTTP 101")
print("TLS /trojan-ws WebSocket upgrade: PASS")
PY

# Record the compatibility mode; the 8443 listener intentionally remains until users migrate.
python3 - "$MARKER" <<'PY'
import os, sys, tempfile
from pathlib import Path
p = Path(sys.argv[1])
lines = [line for line in p.read_text(encoding="utf-8").splitlines()
         if not line.startswith(("trojan_ws=", "trojan_legacy_8443="))]
lines.extend(("trojan_ws=1", "trojan_legacy_8443=1"))
fd, tmp = tempfile.mkstemp(prefix=".INSTALL_INFO.", dir=p.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, p)
finally:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY

complete=1
trap - EXIT
printf 'Trojan WebSocket migration complete. Backup: %s\n' "$backup"
printf '%s\n' 'New accounts use TLS/443 with path /trojan-ws. Existing TCP/TLS 8443 access remains active for client migration.'
