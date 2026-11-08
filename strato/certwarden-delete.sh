#!/bin/sh
# Cert Warden, Anbieter "dns-01 Manual Script" -> Delete Script
# Cert Warden übergibt: $1 = _acme-challenge.<name>  $2 = Wert
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/strato_dns.py" rm "$1" "$2"
