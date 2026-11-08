#!/usr/bin/env python3
"""
strato_dns.py - TXT-Einträge für ACME DNS-01 bei STRATO setzen und entfernen.

STRATO hat keine DNS-API. Das Skript meldet sich deshalb wie ein Browser im
STRATO-Kundenlogin an und ändert die Seite "TXT- und CNAME-Records" der Domain.
Ablauf nach dem Vorbild von github.com/Buxdehuda/strato-certbot, aber:
  * nur Python-Standardbibliothek (läuft in jedem Container mit python3)
  * SPF-Einstellung wird gelesen und unverändert zurückgeschrieben
  * vor jeder Änderung Sicherung als JSON, danach Gegenprüfung
  * Sperre gegen parallele Aufrufe (zwei Namen im selben Zertifikat)
  * Abbruch statt Überschreiben, wenn die Seite nicht wie erwartet aussieht

Aufruf:
  strato_dns.py add  _acme-challenge.mail.example.de  <wert>
  strato_dns.py rm   _acme-challenge.mail.example.de  <wert>
  strato_dns.py list example.de            (nur lesen, ändert nichts)

Einstellungen über Umgebungsvariablen (siehe strato.env.example):
  STRATO_USER, STRATO_PASS             Kundennummer/E-Mail + Kennwort (Pflicht)
  STRATO_TOTP_SECRET, STRATO_TOTP_DEVICE  nur bei Zwei-Faktor-Anmeldung
  STRATO_DOMAIN       Domain im STRATO-Paket (Standard: letzte zwei Teile)
  STRATO_PACKAGE_ID   Paketnummer (cID), falls die Erkennung scheitert
  STRATO_URL          Standard https://www.strato.de/apps/CustomerService
  STRATO_SPF_TYPE     nur nötig, wenn die SPF-Auswahl nicht erkannt wird
  STRATO_WAIT_MAX     Sekunden, die nach "add" auf die Veröffentlichung
                      gewartet wird (0 = nicht warten; Standard 0)
  STRATO_BACKUP_DIR   Ordner für Sicherungen (Standard: ./backup neben Skript)
  STRATO_LOCK         Sperrdatei (Standard: /tmp/strato_dns.lock)
"""

import base64
import datetime
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import struct
import sys
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser

DEFAULT_URL = "https://www.strato.de/apps/CustomerService"
USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
              "Gecko/20100101 Firefox/128.0")
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "param", "source", "track", "wbr"}


def log(msg):
    print(f"[strato_dns] {msg}", file=sys.stderr, flush=True)


def fail(msg, code=1):
    log(f"FEHLER: {msg}")
    sys.exit(code)


# --------------------------------------------------------------------------
# Kleiner HTML-Baum (statt BeautifulSoup)
# --------------------------------------------------------------------------
class Node:
    __slots__ = ("tag", "attrs", "children", "parent", "data")

    def __init__(self, tag, attrs=None, parent=None, data=None):
        self.tag = tag
        self.attrs = dict(attrs or [])
        self.children = []
        self.parent = parent
        self.data = data  # nur bei Textknoten (tag == "#text")

    def text(self):
        if self.tag == "#text":
            return self.data
        return "".join(c.text() for c in self.children)

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def iter(self):
        for c in self.children:
            if c.tag == "#text":
                continue
            yield c
            yield from c.iter()

    def find_all(self, tag=None, **attrs):
        out = []
        for n in self.iter():
            if tag and n.tag != tag:
                continue
            ok = True
            for k, v in attrs.items():
                k = k.rstrip("_")
                if k == "cls":
                    if v not in n.classes():
                        ok = False
                elif n.attrs.get(k) != v:
                    ok = False
            if ok:
                out.append(n)
        return out

    def find(self, tag=None, **attrs):
        r = self.find_all(tag, **attrs)
        return r[0] if r else None


class TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root")
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        attrs = [(k, "" if v is None else v) for k, v in attrs]
        node = Node(tag, attrs, self.cur)
        self.cur.children.append(node)
        if tag not in VOID_TAGS:
            self.cur = node

    def handle_startendtag(self, tag, attrs):
        attrs = [(k, "" if v is None else v) for k, v in attrs]
        self.cur.children.append(Node(tag, attrs, self.cur))

    def handle_endtag(self, tag):
        n = self.cur
        while n is not self.root and n.tag != tag:
            n = n.parent
        if n is not self.root:
            self.cur = n.parent

    def handle_data(self, data):
        self.cur.children.append(Node("#text", parent=self.cur, data=data))


def parse_html(text):
    b = TreeBuilder()
    b.feed(text)
    b.close()
    return b.root


# --------------------------------------------------------------------------
# TOTP (RFC 6238) ohne Zusatzpaket
# --------------------------------------------------------------------------
def totp_now(secret, for_time=None, digits=6, step=30):
    s = re.sub(r"\s", "", secret).upper()
    s += "=" * (-len(s) % 8)
    key = base64.b32decode(s)
    counter = int((for_time if for_time is not None else time.time()) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# --------------------------------------------------------------------------
# Seiten auslesen (getrennt vom Netzwerk, damit offline testbar)
# --------------------------------------------------------------------------
def selected_option(select):
    """Wert der gewählten Option eines <select> (Text, sonst value)."""
    opts = select.find_all("option")
    for o in opts:
        if "selected" in o.attrs:
            return (o.attrs.get("value") or o.text()).strip()
    if select.attrs.get("value"):
        return select.attrs["value"].strip()
    if opts:
        return (opts[0].attrs.get("value") or opts[0].text()).strip()
    return None


def parse_records(html):
    """Liest alle TXT/CNAME-Einträge, die SPF-Auswahl und den Speichern-Knopf.

    Rückgabe: dict(records=[{prefix,type,value}], spf_type=str|None,
                   submit_value=str|None, form_found=bool)
    """
    root = parse_html(html)
    form_found = "action_change_txt_records" in html
    records = []
    for div in root.find_all("div", cls="txt-record-tmpl"):
        p = div.find("input", name="prefix")
        t = div.find("select", name="type")
        v = div.find("textarea", name="value")
        if p is None or t is None or v is None:
            raise ValueError("Eintrag ohne prefix/type/value gefunden - "
                             "STRATO-Seite hat sich geändert")
        prefix = p.attrs.get("value", "").strip()
        rtype = (selected_option(t) or "").upper()
        value = v.text().strip()
        if not prefix and not value:
            continue  # leere Vorlage-Zeile zum Hinzufügen
        if rtype not in ("TXT", "CNAME"):
            raise ValueError(f"Unbekannter Typ '{rtype}' bei '{prefix}'")
        records.append({"prefix": prefix, "type": rtype, "value": value})

    spf = None
    sel = root.find("select", name="spf_type")
    if sel is not None:
        spf = selected_option(sel)
    else:
        for r in root.find_all("input", name="spf_type"):
            if "checked" in r.attrs:
                spf = r.attrs.get("value")
                break

    submit = None
    for el in root.find_all(name="action_change_txt_records"):
        submit = el.attrs.get("value") or el.text().strip() or None
        break

    return {"records": records, "spf_type": spf,
            "submit_value": submit, "form_found": form_found}


def parse_package_id(html, domain):
    """Findet die Paketnummer (cID) des Pakets, das die Domain enthält."""
    root = parse_html(html)
    table = root.find(id="package_list") or root
    for tr in table.find_all("tr"):
        if domain not in tr.text():
            continue
        links = [a for a in tr.find_all("a") if "cID=" in a.attrs.get("href", "")]
        own = [a for a in links
               if any("jss_with_own_packagename" in (anc.attrs.get("class") or "")
                      for anc in _ancestors(a, tr))]
        for a in own + links:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(a.attrs["href"]).query)
            if q.get("cID") and q["cID"][0] not in ("0", ""):
                return q["cID"][0]
    return None


def _ancestors(node, stop):
    n = node
    while n is not None and n is not stop:
        yield n
        n = n.parent


def is_2fa_page(html):
    root = parse_html(html)
    return any(re.search(r"Zwei.?Faktor.?Authentifizierung", h.text())
               for h in root.find_all("h1"))


def parse_2fa_form(html, username, device_name):
    root = parse_html(html)
    tok = root.find("input", name="totp_token")
    if tok is None:
        raise ValueError("2FA-Seite ohne totp_token")
    pw_id = None
    for o in root.find_all("option"):
        val = o.attrs.get("value", "")
        if username in val and o.text().strip() == device_name.strip():
            pw_id = val
            break
    if pw_id is None:
        raise ValueError(f"2FA-Gerät '{device_name}' nicht gefunden")
    return {"totp_token": tok.attrs.get("value", ""), "pw_id": pw_id}


# --------------------------------------------------------------------------
# Netzwerk
# --------------------------------------------------------------------------
class Strato:
    def __init__(self, url, user, password, totp_secret=None, totp_device=None):
        self.url = url
        self.user = user
        self.password = password
        self.totp_secret = totp_secret
        self.totp_device = totp_device
        self.session_id = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.opener.addheaders = [("User-Agent", USER_AGENT),
                                  ("Accept-Language", "de-DE,de;q=0.9")]

    def _req(self, params=None, data=None):
        url = self.url
        if params:
            url += "?" + urllib.parse.urlencode(params)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
        with self.opener.open(url, body, timeout=60) as r:
            raw = r.read()
            charset = r.headers.get_content_charset() or "utf-8"
            return r.geturl(), raw.decode(charset, errors="replace")

    def login(self):
        self._req()
        time.sleep(2)
        final_url, html = self._req(data={
            "identifier": self.user,
            "passwd": self.password,
            "action_customer_login.x": "Login",
        })
        if is_2fa_page(html):
            if not (self.totp_secret and self.totp_device):
                fail("STRATO verlangt Zwei-Faktor-Anmeldung, aber "
                     "STRATO_TOTP_SECRET/STRATO_TOTP_DEVICE fehlen")
            f = parse_2fa_form(html, self.user, self.totp_device)
            final_url, html = self._req(data={
                "identifier": self.user,
                "totp_token": f["totp_token"],
                "pw_id": f["pw_id"],
                "totp": totp_now(self.totp_secret),
                "action_customer_login.x": 1,
            })
        q = urllib.parse.parse_qs(urllib.parse.urlparse(final_url).query)
        if "sessionID" not in q:
            fail("Anmeldung bei STRATO nicht angenommen (Kennwort, 2FA oder "
                 "Sperre nach zu vielen Versuchen?)")
        self.session_id = q["sessionID"][0]
        log("Anmeldung bei STRATO erfolgreich")

    def package_id(self, domain):
        env = os.environ.get("STRATO_PACKAGE_ID")
        if env:
            return env
        _, html = self._req(params={"sessionID": self.session_id, "cID": 0,
                                    "node": "kds_CustomerEntryPage"})
        cid = parse_package_id(html, domain)
        if not cid:
            fail(f"Paket mit {domain} nicht gefunden - STRATO_PACKAGE_ID setzen "
                 "(Zahl hinter cID= in der Adresszeile des Pakets)")
        log(f"Paket {cid} enthält {domain}")
        return cid

    def read(self, cid, domain):
        _, html = self._req(params={
            "sessionID": self.session_id, "cID": cid, "node": "ManageDomains",
            "action_show_txt_records": "", "vhost": domain})
        page = parse_records(html)
        if not page["form_found"]:
            fail("Seite 'TXT- und CNAME-Records' nicht erkannt - es wird "
                 "nichts geändert")
        return page

    def write(self, cid, domain, records, spf_type, submit_value):
        data = [("sessionID", self.session_id), ("cID", cid),
                ("node", "ManageDomains"), ("vhost", domain),
                ("spf_type", spf_type)]
        for r in records:
            data += [("prefix", r["prefix"]), ("type", r["type"]),
                     ("value", r["value"])]
        data.append(("action_change_txt_records",
                     submit_value or "Einstellung übernehmen"))
        self._req(data=data)


# --------------------------------------------------------------------------
# Hilfen
# --------------------------------------------------------------------------
def split_name(record_name, domain=None):
    name = record_name.strip().rstrip(".").lower()
    if domain is None:
        domain = ".".join(name.split(".")[-2:])
    domain = domain.strip().rstrip(".").lower()
    if name == domain:
        fail(f"'{record_name}' hat kein Präfix")
    if not name.endswith("." + domain):
        fail(f"'{record_name}' gehört nicht zu {domain}")
    return name[: -(len(domain) + 1)], domain


def backup(domain, page, action):
    d = os.environ.get("STRATO_BACKUP_DIR") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "backup")
    os.makedirs(d, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(d, f"{domain}-{stamp}-{action}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"domain": domain, "spf_type": page["spf_type"],
                   "records": page["records"]}, f, ensure_ascii=False, indent=2)
    # nur die letzten 50 Sicherungen behalten
    files = sorted(x for x in os.listdir(d) if x.startswith(domain + "-"))
    for old in files[:-50]:
        try:
            os.remove(os.path.join(d, old))
        except OSError:
            pass
    return path


class Lock:
    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            return self  # Windows: keine Sperre
        self.fh = open(self.path, "w")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        if self.fh:
            self.fh.close()


def wait_published(name, value, max_s):
    if max_s <= 0:
        return
    log(f"Warte bis {name} öffentlich sichtbar ist (max. {max_s} s)")
    end = time.time() + max_s
    while time.time() < end:
        try:
            url = ("https://dns.google/resolve?" +
                   urllib.parse.urlencode({"name": name, "type": "TXT"}))
            with urllib.request.urlopen(url, timeout=20) as r:
                ans = json.load(r).get("Answer", [])
            if any(value in a.get("data", "") for a in ans):
                log("TXT-Eintrag ist sichtbar")
                return
        except Exception as e:  # noqa: BLE001
            log(f"DNS-Abfrage fehlgeschlagen: {e}")
        time.sleep(30)
    log("Zeit abgelaufen - Eintrag noch nicht sichtbar, ACME prüft trotzdem")


def same(a, b):
    return (a["prefix"].lower() == b["prefix"].lower()
            and a["type"] == b["type"] and a["value"] == b["value"])


# --------------------------------------------------------------------------
# Hauptprogramm
# --------------------------------------------------------------------------
def main(argv):
    if len(argv) < 2 or argv[1] not in ("add", "rm", "list"):
        print(__doc__)
        return 2
    action = argv[1]
    user = os.environ.get("STRATO_USER")
    password = os.environ.get("STRATO_PASS")
    if not user or not password:
        fail("STRATO_USER und STRATO_PASS müssen gesetzt sein")
    url = os.environ.get("STRATO_URL") or DEFAULT_URL
    s = Strato(url, user, password, os.environ.get("STRATO_TOTP_SECRET"),
               os.environ.get("STRATO_TOTP_DEVICE"))

    if action == "list":
        if len(argv) != 3:
            fail("Aufruf: strato_dns.py list <domain>")
        domain = argv[2].rstrip(".").lower()
        s.login()
        page = s.read(s.package_id(domain), domain)
        print(f"SPF-Auswahl: {page['spf_type']}")
        for r in page["records"]:
            print(f"{r['type']:5} {r['prefix']:40} {r['value']}")
        return 0

    if len(argv) != 4:
        fail(f"Aufruf: strato_dns.py {action} <eintrag> <wert>")
    record_name, value = argv[2], argv[3]
    prefix, domain = split_name(record_name, os.environ.get("STRATO_DOMAIN"))
    mine = {"prefix": prefix, "type": "TXT", "value": value}

    with Lock(os.environ.get("STRATO_LOCK") or "/tmp/strato_dns.lock"):
        s.login()
        cid = s.package_id(domain)
        page = s.read(cid, domain)
        spf = page["spf_type"] or os.environ.get("STRATO_SPF_TYPE")
        if not spf:
            fail("SPF-Auswahl auf der STRATO-Seite nicht erkannt. Damit sie "
                 "nicht zurückgesetzt wird, STRATO_SPF_TYPE setzen "
                 "(Wert wie in 'list' angezeigt, z. B. NONE)")
        old = page["records"]
        bpath = backup(domain, page, action)
        log(f"Sicherung: {bpath}")

        if action == "add":
            if any(same(r, mine) for r in old):
                log("Eintrag ist schon vorhanden - nichts zu tun")
                new = old
            else:
                new = old + [mine]
        else:
            new = [r for r in old if not same(r, mine)]
            if len(new) == len(old):
                log("Eintrag war nicht vorhanden - nichts zu tun")

        if new is not old and new != old:
            s.write(cid, domain, new, spf, page["submit_value"])
            check = s.read(cid, domain)
            missing = [r for r in new if not any(same(r, c) for c in check["records"])]
            extra = [c for c in check["records"] if not any(same(c, r) for r in new)]
            if missing or extra or (check["spf_type"] and check["spf_type"] != spf):
                fail("Gegenprüfung nach dem Speichern stimmt nicht: "
                     f"fehlt={missing} zusätzlich={extra} spf={check['spf_type']}. "
                     f"Vorheriger Stand liegt in {bpath}")
            log(f"{'Gesetzt' if action == 'add' else 'Entfernt'}: "
                f"TXT {prefix}.{domain}")

    if action == "add":
        wait_published(f"{prefix}.{domain}", value,
                       int(os.environ.get("STRATO_WAIT_MAX") or 0))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (OSError, ValueError) as e:  # Netzwerk, HTTP-Fehler, Seitenaufbau
        fail(f"{type(e).__name__}: {e}")
