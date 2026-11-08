#!/bin/bash
# Legt ein neu ausgestelltes/erneuertes Zertifikat auf die Unraid-Freigabe (/zertifikate) ab.
# In Cert Warden je Zertifikat unter "Post Processing" eintragen:
#   Skript:     /opt/ablage/cw-ablegen.sh
#   Umgebung:   CW_NAME={{CERTIFICATE_NAME}}
#               CW_CERT={{CERTIFICATE_PEM}}
#               CW_KEY={{PRIVATE_KEY_PEM}}
# Ergebnis je Zertifikat in /zertifikate/<name>/:
#   cert.pem (Zertifikat + Kette), privkey.pem, combined.pem (Schlüssel + Kette, z. B. HAProxy),
#   info.txt (Ablauf, Namen). Alte Fassung bleibt als *.vorher erhalten.
set -euo pipefail
ZIEL="${ABLAGE_DIR:-/zertifikate}"
NAME="${CW_NAME:-}"
log() { echo "[cw-ablegen] $*"; }

case "$NAME" in ""|*[!A-Za-z0-9._-]*) log "CW_NAME fehlt oder ungültig: '$NAME'"; exit 1;; esac
[ -n "${CW_CERT:-}" ] && [ -n "${CW_KEY:-}" ] || { log "CW_CERT/CW_KEY fehlen (Platzhalter in Post Processing eintragen)"; exit 1; }
[ -d "$ZIEL" ] || { log "$ZIEL ist nicht eingebunden (Pfad 'Zertifikat-Freigabe' in der Vorlage)"; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf '%s\n' "$CW_CERT" | sed '/^$/d' > "$T/cert.pem"
printf '%s\n' "$CW_KEY"  | sed '/^$/d' > "$T/privkey.pem"

# Schlüssel passt zum Zertifikat?
A="$(openssl x509 -noout -pubkey -in "$T/cert.pem" | sha256sum)"
B="$(openssl pkey -pubout -in "$T/privkey.pem" | sha256sum)"
[ "$A" = "$B" ] || { log "$NAME: Schlüssel passt nicht zum Zertifikat – nichts abgelegt"; exit 1; }
cat "$T/privkey.pem" "$T/cert.pem" > "$T/combined.pem"
{
  echo "name=$NAME"
  openssl x509 -noout -subject -enddate -in "$T/cert.pem"
  openssl x509 -noout -ext subjectAltName -in "$T/cert.pem" 2>/dev/null | tail -n +2 | sed 's/^ */san=/'
  echo "abgelegt=$(date -Iseconds)"
} > "$T/info.txt"

D="$ZIEL/$NAME"; mkdir -p "$D"
for f in cert.pem privkey.pem combined.pem; do
  [ -f "$D/$f" ] && cp -p "$D/$f" "$D/$f.vorher"
done
install -m 644 "$T/cert.pem" "$D/cert.pem"
install -m "${ABLAGE_SCHLUESSEL_MODUS:-640}" "$T/privkey.pem" "$D/privkey.pem"
install -m "${ABLAGE_SCHLUESSEL_MODUS:-640}" "$T/combined.pem" "$D/combined.pem"
install -m 644 "$T/info.txt" "$D/info.txt"
# Unraid-Standard: nobody:users, damit SMB-Freigabe und andere Container lesen können
chown -R "${PUID:-99}:${PGID:-100}" "$D" 2>/dev/null || true
log "$NAME abgelegt ($(openssl x509 -noout -enddate -in "$D/cert.pem"))"
