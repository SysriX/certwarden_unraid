# certwarden-unraid

[Cert Warden](https://www.certwarden.com/) (offizielles Image) für Unraid: holt und erneuert Let's-Encrypt-Zertifikate automatisch, mit Weboberfläche und API – und legt sie auf eine Unraid-Freigabe, damit andere Container sie nutzen können.

`ghcr.io/sysrix/certwarden-unraid:latest`

## Was es kann

- **Weboberfläche** für Konten, Schlüssel und Zertifikate; erneuert automatisch vor Ablauf
- **DNS-01** für STRATO (über den Kundenlogin, ohne API) und Hetzner (eingebaut), **HTTP-01** über Port 4060
- **Ablage auf eine Unraid-Freigabe** nach jeder Ausstellung und Erneuerung
- **API** zum Abholen der Zertifikate, z. B. durch [haproxy-unraid](../haproxy/README.md)
- öffentliche DNS-Server voreingestellt, damit DNS-01 auch bei internem Split-DNS funktioniert

Läuft **allein**; HAProxy ist nicht nötig.

## Installation in Unraid

1. In Unraid eine Freigabe anlegen, z. B. `zertifikate` (SMB nur für Admins oder gar nicht exportieren).
2. Vorlage holen und in **Apps › Private** `certwarden-unraid` installieren:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/SysriX/unraid-images/main/unraid/private-vorlagen.sh | bash
   ```
3. Netzwerk `br0` (bzw. VLAN) mit **fester IP**.
4. Aufruf: `https://<IP_CertWarden>:4055/`. Erste Anmeldung `admin` / `password` – **sofort ändern**.

## Einstellungen

| Feld | Variable / Pfad | Pflicht | Bedeutung |
| --- | --- | --- | --- |
| Daten | `/app/data` | ja | Datenbank, Schlüssel, Zertifikate. Unraid ohne Cache: Plattenpfad wie `/mnt/disk1/appdata/certwarden/data` |
| Zertifikat-Freigabe | `/zertifikate` | nein | Ziel der Ablage, z. B. `/mnt/user/zertifikate` |
| Besitzer UID / GID | `PUID`, `PGID` | nein | Besitzer der abgelegten Dateien (Standard 99/100 = nobody/users) |
| Rechte Schlüsseldateien | `ABLAGE_SCHLUESSEL_MODUS` | nein | Standard `640` |
| STRATO: Wartezeit DNS | `STRATO_WAIT_MAX` | nein | Sekunden bis der TXT-Eintrag sichtbar ist (Standard 900) |

## Zertifikate auf die Freigabe legen

In Cert Warden je Zertifikat › **Edit** › **Post Processing**:

- Skript: `/opt/ablage/cw-ablegen.sh`
- Umgebungsvariablen:
  ```
  CW_NAME={{CERTIFICATE_NAME}}
  CW_CERT={{CERTIFICATE_PEM}}
  CW_KEY={{PRIVATE_KEY_PEM}}
  ```

Einmal unter **ACME Orders › Post Process** testen. Danach geschieht es bei jeder Erneuerung automatisch.

Ergebnis in `zertifikate/<name>/`:

| Datei | Inhalt |
| --- | --- |
| `cert.pem` | Zertifikat, wie Cert Warden es liefert |
| `privkey.pem` | privater Schlüssel |
| `combined.pem` | Schlüssel + Zertifikat in einer Datei (z. B. für HAProxy) |
| `info.txt` | Name, Ablaufdatum, alle Namen im Zertifikat |
| `*.vorher` | vorige Fassung |

Das Skript prüft vorher, ob Schlüssel und Zertifikat zusammenpassen; sonst bleibt die alte Fassung liegen.

## Andere Container mit Zertifikaten versorgen

Im anderen Container **nur den eigenen Unterordner lesend** einbinden, z. B.:

| Host-Pfad | Container-Pfad | Modus |
| --- | --- | --- |
| `/mnt/user/zertifikate/nextcloud` | `/certs` | `ro` (nur lesen) |

Programme, die Zertifikate nicht selbst neu einlesen, nach der Erneuerung neu starten (z. B. Unraid-User-Script `docker restart <name>` wöchentlich).

## Updates

Neu gebaut, sobald das offizielle Cert-Warden-Image aktualisiert wird; Unraid zeigt dann „Update verfügbar“.
