#!/usr/bin/env bash
# Certbot post-hook for standalone HTTP-01: restore only the port-80 SSH relay.
set -Eeuo pipefail

SYSTEMCTL=${NEVERBANDITS_SYSTEMCTL:-/usr/bin/systemctl}
STATE_FILE=${NEVERBANDITS_CERTBOT_STATE_FILE:-/run/neverbandits/certbot-ssh-http-was-active}
SERVICE=neverbandits-ssh-http.service

if [[ -f "$STATE_FILE" ]]; then
  "$SYSTEMCTL" start "$SERVICE"
  rm -f -- "$STATE_FILE"
fi
