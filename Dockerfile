# certwarden-unraid: offizielles Cert-Warden-Image + python3 + STRATO-DNS-01-Skript.
# Neu gebaut, sobald das offizielle Image (ghcr.io/gregtwallace/certwarden:latest) sich ändert.
ARG CW_TAG=latest
FROM ghcr.io/gregtwallace/certwarden:${CW_TAG}

ARG CW_TAG
ARG BASE_DIGEST=unbekannt
ARG QUELLE=https://github.com/
LABEL org.opencontainers.image.title="certwarden-unraid" \
      org.opencontainers.image.description="Cert Warden (ACME mit Weboberfläche) mit STRATO-DNS-01 und Hetzner für Unraid" \
      org.opencontainers.image.source="${QUELLE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="ghcr.io/gregtwallace/certwarden:${CW_TAG}" \
      org.opencontainers.image.base.digest="${BASE_DIGEST}"

RUN apk add --no-cache python3
COPY strato/strato_dns.py strato/certwarden-create.sh strato/certwarden-delete.sh /opt/acme-strato/
# Ablage auf eine Unraid-Freigabe (Post Processing je Zertifikat)
COPY ablage/cw-ablegen.sh /opt/ablage/
# Zeilenenden absichern; Selbsttest: ohne Argumente endet das Skript mit Code 2 (Hilfe)
RUN sed -i 's/\r$//' /opt/acme-strato/* /opt/ablage/* \
 && chmod 755 /opt/acme-strato/*.sh /opt/acme-strato/strato_dns.py /opt/ablage/*.sh \
 && bash -n /opt/ablage/cw-ablegen.sh \
 && (python3 /opt/acme-strato/strato_dns.py >/dev/null 2>&1 || [ $? -eq 2 ])
ENV STRATO_BACKUP_DIR=/app/data/strato-backup \
    ABLAGE_DIR=/zertifikate \
    TZ=Europe/Berlin
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsk -m 4 -o /dev/null https://127.0.0.1:4055/ || curl -fs -m 4 -o /dev/null http://127.0.0.1:4050/ || exit 1
