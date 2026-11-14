#!/usr/bin/env bash
# Certbot pre-hook for standalone HTTP-01: only the SSH relay owns port 80.
# Nginx remains online on TCP 443 during certificate renewal.
set -Eeuo pipefail

SYSTEMCTL=${NEVERBANDITS_SYSTEMCTL:-/usr/bin/systemctl}
STATE_FILE=${NEVERBANDITS_CERTBOT_STATE_FILE:-/run/neverbandits/certbot-ssh-http-was-active}
SERVICE=neverbandits-ssh-http.service

if "$SYSTEMCTL" is-active --quiet "$SERVICE"; then
  install -d -m 0700 "$(dirname -- "$STATE_FILE")"
  if [[ ! -e "$STATE_FILE" ]]; then
    temp_file="${STATE_FILE}.$$"
    trap 'rm -f -- "$temp_file"' EXIT
    printf 'active\n' > "$temp_file"
    chmod 0600 "$temp_file"
    mv -f -- "$temp_file" "$STATE_FILE"
    trap - EXIT
  fi
  "$SYSTEMCTL" stop "$SERVICE"
fi
