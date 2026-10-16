#!/usr/bin/env bash
# Embedded by mindustry-forwarder-decoder.
# Adds a non-127 address on lo so IP_TRANSPARENT dial works on lo-only boxes.
# Requires: root, iproute2.

set -euo pipefail

ALIAS_IP="${1:-172.31.255.1}"
UNDO=0
QUIET="${MINDUSTRY_SETUP_LO_QUIET:-0}"

if [[ "${1:-}" == "--undo" || "${1:-}" == "-u" ]]; then
  UNDO=1
  ALIAS_IP="${2:-172.31.255.1}"
fi

log() {
  if [[ "$QUIET" != "1" ]]; then
    echo "$@"
  fi
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: must run as root (needed for ip/sysctl and IP_TRANSPARENT)" >&2
  exit 1
fi

if [[ "$UNDO" -eq 1 ]]; then
  ip addr del "${ALIAS_IP}/32" dev lo 2>/dev/null || true
  log "removed ${ALIAS_IP}/32 from lo (if it was present)"
  exit 0
fi

case "$ALIAS_IP" in
  127.*)
    echo "error: do not use a 127.0.0.0/8 address; pick something like 172.31.255.1" >&2
    exit 1
    ;;
esac

log "==> adding ${ALIAS_IP}/32 on lo"
ip addr replace "${ALIAS_IP}/32" dev lo

log "==> sysctl for transparent / local delivery"
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
sysctl -w net.ipv4.conf.lo.route_localnet=1 >/dev/null
# Accept packets with "foreign" source on lo (spoofed client IPs).
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.lo.rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null
sysctl -w net.ipv4.conf.lo.accept_local=1 >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

log "lo alias ready: ${ALIAS_IP}"
