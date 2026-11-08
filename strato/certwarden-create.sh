#!/bin/sh
# Cert Warden, Anbieter "dns-01 Manual Script" -> Create Script
# Cert Warden übergibt: $1 = _acme-challenge.<name>  $2 = Wert
# Zugangsdaten als Umgebungsvariablen im Anbieter eintragen (STRATO_USER=..., STRATO_PASS=...)
DIR="$(cd "$(dirname "$0")" && pwd)"
STRATO_WAIT_MAX="${STRATO_WAIT_MAX:-900}" exec python3 "$DIR/strato_dns.py" add "$1" "$2"
