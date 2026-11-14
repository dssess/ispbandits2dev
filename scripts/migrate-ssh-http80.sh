#!/usr/bin/env bash
# Migrate a managed Neverbandits alpha-4 install to the HTTP Custom SSH transport.
set -Eeuo pipefail
umask 077

PREFIX=/opt/ispbandits-dev
MARKER=$PREFIX/INSTALL_INFO
SITE=/etc/nginx/sites-available/neverbandits
ENABLED_SITE=/etc/nginx/sites-enabled/neverbandits
DEFAULT_SITE=/etc/nginx/sites-enabled/default
UNIT=/etc/systemd/system/neverbandits-ssh-http.service
BACKUP_ROOT=/var/backups/ispbandits-dev
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

[[ ${EUID} -eq 0 ]] || { echo "Run this migration as root." >&2; exit 1; }
[[ -r "$MARKER" && -r "$SITE" && -L "$ENABLED_SITE" ]] || { echo "A recognized full Neverbandits install is required." >&2; exit 1; }
grep -Fxq 'managed_by=ISPbandits-Dev-install.sh' "$MARKER" || { echo "Unknown install marker; refusing migration." >&2; exit 1; }
grep -Fxq 'full_xray=1' "$MARKER" || { echo "A full Xray/Nginx install is required." >&2; exit 1; }
domain=$(sed -n 's/^domain=//p' "$MARKER" | head -n 1)
ssh_port=$(sed -n 's/^ssh_target_port=//p' "$MARKER" | head -n 1)
[[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || { echo "Invalid domain in install marker." >&2; exit 1; }
[[ "$ssh_port" =~ ^[0-9]+$ ]] && (( ssh_port >= 1 && ssh_port <= 65535 )) || { echo "Invalid SSH port in install marker." >&2; exit 1; }
[[ -f "$SOURCE_DIR/nginx/neverbandits.conf.in" && -f "$SOURCE_DIR/systemd/neverbandits-ssh-http.service.in" && -f "$SOURCE_DIR/src/ispbandits/ssh_http_proxy.py" ]] || { echo "Migration source files are missing." >&2; exit 1; }
id ispbd-ws >/dev/null 2>&1 || { echo "Expected managed service account ispbd-ws is missing." >&2; exit 1; }

# Only migrate the known managed site; do not take over unrelated port-80 servers.
if ! grep -Fq 'proxy_pass http://127.0.0.1:6080;' "$SITE"; then
  if grep -Fxq 'ssh_http_custom=1' "$MARKER" && systemctl is-active --quiet neverbandits-ssh-http.service; then
    echo "HTTP Custom port-80 SSH is already active; no changes made."
    exit 0
  fi
  echo "The installed Nginx site does not match the managed alpha-4 SSH-WebSocket topology." >&2
  exit 1
fi
if [[ -e "$DEFAULT_SITE" && ! -L "$DEFAULT_SITE" ]]; then
  echo "Unexpected non-symlink Nginx default site at $DEFAULT_SITE; refusing to remove it." >&2
  exit 1
fi

install -d -o root -g root -m 0700 "$BACKUP_ROOT"
backup=$(mktemp -d "$BACKUP_ROOT/ssh-http80-migration-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
install -d -o root -g root -m 0700 "$backup/files"
backup_one() {
  local path=$1 rel=$2
  if [[ -e "$path" || -L "$path" ]]; then
    mkdir -p "$backup/files/$(dirname "$rel")"
    cp -a -- "$path" "$backup/files/$rel"
    mkdir -p "$(dirname "$backup/$rel.present")"
    : > "$backup/$rel.present"
  fi
}
restore_one() {
  local path=$1 rel=$2
  if [[ -e "$backup/$rel.present" ]]; then
    mkdir -p "$(dirname "$path")"
    rm -rf -- "$path"
    cp -a -- "$backup/files/$rel" "$path"
  else
    rm -rf -- "$path"
  fi
}
backup_one "$SITE" etc/nginx/sites-available/neverbandits
backup_one "$DEFAULT_SITE" etc/nginx/sites-enabled/default
backup_one "$UNIT" etc/systemd/system/neverbandits-ssh-http.service
backup_one /etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx
backup_one /etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx

nginx_was_active=0
websockify_was_active=0
nginx_was_enabled=0
websockify_was_enabled=0
systemctl is-active --quiet nginx.service && nginx_was_active=1 || true
systemctl is-active --quiet neverbandits-websockify.service && websockify_was_active=1 || true
systemctl is-enabled --quiet nginx.service && nginx_was_enabled=1 || true
systemctl is-enabled --quiet neverbandits-websockify.service && websockify_was_enabled=1 || true
printf 'nginx_active=%s\nwebsockify_active=%s\nnginx_enabled=%s\nwebsockify_enabled=%s\n' \
  "$nginx_was_active" "$websockify_was_active" "$nginx_was_enabled" "$websockify_was_enabled" > "$backup/service-state"

complete=0
rollback() {
  local rc=$?
  if (( rc != 0 && complete == 0 )); then
    echo "Migration failed; restoring prior Nginx/SSH service configuration from $backup" >&2
    set +e
    systemctl stop neverbandits-ssh-http.service >/dev/null 2>&1
    restore_one "$SITE" etc/nginx/sites-available/neverbandits
    restore_one "$DEFAULT_SITE" etc/nginx/sites-enabled/default
    restore_one "$UNIT" etc/systemd/system/neverbandits-ssh-http.service
    restore_one /etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx
    restore_one /etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx
    systemctl daemon-reload
    if (( nginx_was_active )); then systemctl restart nginx.service; else systemctl stop nginx.service; fi
    if (( websockify_was_active )); then systemctl start neverbandits-websockify.service; else systemctl stop neverbandits-websockify.service; fi
    if (( nginx_was_enabled )); then systemctl enable nginx.service >/dev/null 2>&1; else systemctl disable nginx.service >/dev/null 2>&1; fi
    if (( websockify_was_enabled )); then systemctl enable neverbandits-websockify.service >/dev/null 2>&1; else systemctl disable neverbandits-websockify.service >/dev/null 2>&1; fi
  fi
  exit "$rc"
}
trap rollback EXIT

# Preserve a local rollback copy before replacing any active transport files.
new_site="$backup/neverbandits.new"
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
  sed "s/@DOMAIN@/$domain/g" "$SOURCE_DIR/nginx/neverbandits.conf.in" > "$new_site"
else
  sed -e "s/@DOMAIN@/$domain/g" -e '/^[[:space:]]*listen \[::\]:/d' "$SOURCE_DIR/nginx/neverbandits.conf.in" > "$new_site"
fi
sed "s/@SSH_PORT@/$ssh_port/g" "$SOURCE_DIR/systemd/neverbandits-ssh-http.service.in" > "$backup/neverbandits-ssh-http.service.new"
chmod 0644 "$new_site" "$backup/neverbandits-ssh-http.service.new"

systemctl stop neverbandits-websockify.service
systemctl stop nginx.service
install -o root -g root -m 0644 "$new_site" "$SITE"
if [[ -L "$DEFAULT_SITE" ]] && [[ "$(readlink -f "$DEFAULT_SITE")" == /etc/nginx/sites-available/default ]]; then
  rm -- "$DEFAULT_SITE"
fi
install -o root -g root -m 0644 "$backup/neverbandits-ssh-http.service.new" "$UNIT"
if [[ -f /etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx ]]; then
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/certbot-stop-nginx.sh" /etc/letsencrypt/renewal-hooks/pre/neverbandits-stop-nginx
fi
if [[ -f /etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx ]]; then
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/certbot-start-nginx.sh" /etc/letsencrypt/renewal-hooks/post/neverbandits-start-nginx
fi
systemctl daemon-reload
/usr/sbin/nginx -t
systemctl start nginx.service
systemctl disable neverbandits-websockify.service >/dev/null 2>&1 || true
systemctl enable --now neverbandits-ssh-http.service
systemctl is-active --quiet nginx.service
systemctl is-active --quiet neverbandits-ssh-http.service

# Verify the real local relay, expected upgrade response and actual sshd banner.
relay_ready=0
for attempt in {1..20}; do
  if python3 - <<'PY'
import socket
try:
    s=socket.create_connection(("127.0.0.1",80),timeout=1)
    s.settimeout(1)
    s.sendall(b"CONNECT netfin.co.ke:GET HTTP/1.1\r\nHost: localhost:80\r\n\r\n")
    response=b""
    while not response.endswith(b"\r\n\r\n") and len(response)<2048:
        block=s.recv(1)
        if not block: break
        response += block
    if not response.startswith(b"HTTP/1.1 101 Switching Protocols"):
        raise SystemExit(1)
    banner=s.recv(256)
    if not banner.startswith(b"SSH-2.0-"):
        raise SystemExit(1)
    print("Port 80 HTTP Custom handshake and live SSH banner: PASS")
    s.close()
except OSError:
    raise SystemExit(1)
PY
  then
    relay_ready=1
    break
  fi
  sleep 0.25
done
(( relay_ready == 1 )) || { echo "HTTP Custom relay did not return the expected handshake and SSH banner." >&2; exit 1; }

# Record the transport mode while preserving any unrelated install metadata.
if ! grep -Fxq 'ssh_http_custom=1' "$MARKER"; then
  printf 'ssh_http_custom=1\n' >> "$MARKER"
fi

complete=1
trap - EXIT
printf 'Migration complete. Previous service/config snapshot: %s\n' "$backup"
printf '%s\n' 'SSH is exposed only on TCP 80; Nginx remains on TLS 443 for VLESS; Trojan remains unchanged.'
