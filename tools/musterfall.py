#!/usr/bin/env python3
"""Baut den Musterfall MUSTER-2026-001 komplett ohne Netz und ohne Schlüssel.

    python3 tools/musterfall.py

Der Musterfall zeigt, was am Ende einer Ermittlung in der Fallakte liegt, und dient zugleich als
Durchlauftest: Er ruft dieselben Gateway-Werkzeuge auf wie eine echte Ermittlung. Nur die
Antworten der Quellen sind vorgefertigt. Alle Daten sind erfunden (Dokumentations-IP-Bereiche
nach RFC 5737, Domains unter .example). Die Bitcoin-Adressen und Transaktionen stammen aus einer erfundenen
Kette (tools/_kryptowelt.py): Sie haben gültige Prüfsummen, gehören aber niemandem.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start(venv=True)      # braucht die Pakete des Gateways (httpx, pydantic)

os.environ.setdefault("OSINT_PROJEKT", str(PROJEKT))
for _name in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "SPUR_TOKEN", "ABUSEIPDB_API_KEY", "URLQUERY_API_KEY",
              "RANSOMWARE_LIVE_API_KEY"):
    os.environ[_name] = "MUSTER-SCHLUESSEL-0000"
for _name in ("OSINT_PROXY", "ETHERSCAN_API_KEY", "TRONSCAN_API_KEY", "TRONGRID_API_KEY", "CHAINABUSE_API_KEY", "IKNAIO_API_KEY",
              "KRYPTO_BITCOIN_API"):
    os.environ.pop(_name, None)         # der Musterfall läuft ohne die Zusatzschlüssel der Blockchain-Analyse
os.environ["OSINT_ZEITZONE"] = "Europe/Zurich"     # der Musterfall soll auf jedem Rechner identisch ausfallen

try:
    import httpx
    from gateway import kern, quellen_infrastruktur as infra, quellen_krypto as krypto, quellen_szene as szene, quellen_web as web
    from tools import _kryptowelt as kw
except ModuleNotFoundError as e:
    sys.exit(f"Paket '{e.name}' fehlt. Bitte zuerst {plattform.SETUP} ausführen.")

from gateway.akte import FAELLE, SITZUNGEN  # noqa: E402
from tools import fall as fallwerkzeug, protokoll, rapport  # noqa: E402
from tools._html import zahl_ch  # noqa: E402

FALL = "MUSTER-2026-001"
SITZUNG = "muster-sitzung-0001"
DOMAIN, DOMAIN2 = "kundenportal-sicher.example", "rechnung-portal.example"
URL = f"https://{DOMAIN}/login"
IP_SERVER, IP_LOGIN = "203.0.113.7", "198.51.100.23"
DATEI = hashlib.sha256(b"MUSTER-Schadsoftware, erfunden").hexdigest()
ONION = base64.b32encode(hashlib.sha256(b"musterlocker").digest() + b"\x00\x00\x03").decode().lower()[:56] + ".onion"
GRUPPE = "musterlocker"

# Lösegeld in einer erfundenen Bitcoin-Kette: Zahlung der Geschädigten, Weiterleitung in zwei Teilen, der grössere an
# eine Börse, vom kleineren bleibt die Hälfte liegen, die andere geht durch einen Mischdienst.
LOESEGELD, ZAHLUNG = kw.btc("musterlocker-loesegeld"), kw.txid("zahlung")
EINZAHLUNG, LIEGT = kw.btc("einzahlung-boerse"), kw.btc("zwischenlager")


def _zeitpunkt(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc).timestamp())


def kette() -> kw.Welt:
    w = kw.Welt()
    w.kurse["coingecko:bitcoin"] = 98_400.0
    w.btc_zahlung("zahlung", [("extern", "handelsplattform-geschaedigte", 60_000_000)],
                  [("musterlocker-loesegeld", 50_000_000), ("handelsplattform-wechsel", 9_990_000)], _zeitpunkt("2026-10-03 13:42"))
    w.btc_zahlung("aufteilung", [("zahlung", 0)], [("einzahlung-boerse", 30_000_000), ("durchgang", 19_950_000)], _zeitpunkt("2026-10-03 21:05"))
    w.btc_zahlung("sammlung", [("aufteilung", 0)] + [("extern", f"kunde-{i}", 4_000_000 + 250_000 * i) for i in range(11)],
                  [("boerse-sammeladresse", 87_700_000)], _zeitpunkt("2026-10-04 02:30"))
    w.btc_zahlung("zusammenlegung", [("aufteilung", 1), ("extern", "fremdes-guthaben", 30_000_000)],
                  [("zwischenlager", 25_000_000), ("vor-mischdienst", 24_900_000)], _zeitpunkt("2026-10-04 09:17"))
    w.btc_zahlung("mischung", [("zusammenlegung", 1)] + [("extern", f"teilnehmer-{i}", 10_000_000) for i in range(5)],
                  [(f"mischausgang-{i}", 10_000_000) for i in range(7)] + [("mischrest", 4_800_000)], _zeitpunkt("2026-10-05 18:44"))
    w.walletexplorer[EINZAHLUNG] = "Beispielboerse.example"
    w.ransomwhere[LOESEGELD] = "MusterLocker"
    return w


KETTE = kette()

EINGANG = f"""# Polizeirapport (pseudonymisierte Fassung) – MUSTER, frei erfunden

## Sachverhalt

1. Am 02.10.2026 meldete [PERSON_01], Leiterin Finanzen der [ORG_01], einen Betrugsverdacht.
2. Am 29.09.2026 um 09:14 Uhr erhielt [PERSON_02], Sachbearbeiter der [ORG_01], eine E-Mail mit dem
   Absender rechnung@kundenportal-sicher[.]example und dem Link hxxps://kundenportal-sicher[.]example/login.
3. [PERSON_02] gab auf der verlinkten Seite die Zugangsdaten zum Kundenportal der [ORG_01] ein. Laut
   Serverprotokoll der [ORG_01] erfolgte am 29.09.2026 um 09:31 Uhr eine Anmeldung mit diesen Zugangsdaten
   von der IP-Adresse 198.51.100.23.
4. Der E-Mail war die Datei «Rechnung_Q3.pdf.exe» angehängt. SHA-256: {DATEI}
5. Laut Kopfzeilen wurde die E-Mail vom Host 203.0.113.7 eingeliefert.
6. Am 01.10.2026 ging bei der [ORG_01] ein Erpresserschreiben ein, unterzeichnet mit «MusterLocker». Es
   verweist auf die Adresse {ONION}
7. Das Schreiben verlangt 0.5 Bitcoin an die Adresse {LOESEGELD}. Die [ORG_01] hat den Betrag am 03.10.2026
   über ihre Handelsplattform bezahlt. Transaktions-ID laut Auszug: {ZAHLUNG}

## Auftrag

Infrastruktur hinter der Phishing-Seite und der Anmeldung klären, die angehängte Datei einordnen, prüfen,
ob ein Bezug zur genannten Gruppe besteht, und den Verbleib der Lösegeldzahlung klären.
"""

# --------------------------------------------------------------------------- vorgefertigte Antworten

SHODAN_HOST = {
    "ip_str": IP_SERVER, "org": "Beispiel Hosting AG", "isp": "Beispiel Hosting AG", "asn": "AS64500",
    "country_code": "NL", "country_name": "Netherlands", "city": "Amsterdam", "os": "Linux",
    "hostnames": [DOMAIN, f"mail.{DOMAIN}"], "domains": [DOMAIN], "ports": [22, 25, 80, 443],
    "tags": ["self-signed"], "last_update": "2026-10-04T03:12:44.120000", "vulns": [],
    "data": [
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "9.2p1", "timestamp": "2026-10-03T22:01:10",
         "ssh": {"fingerprint": "5a:1c:9e:20:77:af:31:0d:44:b2:9c:e1:6f:08:d3:aa"}},
        {"port": 25, "transport": "tcp", "product": "Postfix smtpd", "timestamp": "2026-10-04T01:40:02"},
        {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24.0", "timestamp": "2026-10-04T03:12:44",
         "http": {"title": "301 Moved Permanently", "server": "nginx/1.24.0", "status": 301}},
        {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0", "timestamp": "2026-10-04T03:12:44",
         "http": {"title": "Kundenportal – Anmeldung", "server": "nginx/1.24.0", "status": 200, "favicon": {"hash": -1293847561}},
         "ssl": {"cert": {"subject": {"CN": DOMAIN}, "issuer": {"CN": "R11"}, "expires": "20261225093000Z",
                          "fingerprint": {"sha256": hashlib.sha256(b"muster-zertifikat").hexdigest()}}}}]}

VT_STATS = lambda boese, gesamt: {"malicious": boese, "suspicious": 1, "undetected": gesamt - boese - 1 - 20, "harmless": 20, "timeout": 0}  # noqa: E731


def _zeit(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp())


ANTWORTEN: dict[tuple[str, str], tuple[int, object]] = {
    ("api.shodan.io", f"/shodan/host/{IP_SERVER}"): (200, SHODAN_HOST),
    ("internetdb.shodan.io", f"/{IP_LOGIN}"): (200, {"ip": IP_LOGIN, "ports": [443, 1194], "hostnames": [], "cpes": [],
                                                    "tags": ["vpn"], "vulns": []}),
    ("api.spur.us", f"/v2/context/{IP_LOGIN}"): (200, {
        "ip": IP_LOGIN, "as": {"number": 64501, "organization": "Beispiel Transit BV"}, "infrastructure": "DATACENTER",
        "organization": "Beispiel Transit BV", "location": {"city": "Frankfurt am Main", "country": "DE", "state": "Hessen"},
        "risks": ["TUNNEL", "CALLBACK_PROXY"], "services": ["OPENVPN", "WIREGUARD"],
        "client": {"behaviors": ["TOR_PROXY_USER"], "count": 214, "countries": 31, "types": ["DESKTOP", "MOBILE"]},
        "tunnels": [{"anonymous": True, "operator": "BEISPIEL_VPN", "type": "VPN", "entries": ["198.51.100.20"]}]}),
    ("api.spur.us", f"/v2/context/{IP_SERVER}"): (200, {
        "ip": IP_SERVER, "as": {"number": 64500, "organization": "Beispiel Hosting AG"}, "infrastructure": "DATACENTER",
        "organization": "Beispiel Hosting AG", "location": {"city": "Amsterdam", "country": "NL"}, "risks": [], "services": []}),
    ("www.virustotal.com", f"/api/v3/domains/{DOMAIN}"): (200, {"data": {"type": "domain", "id": DOMAIN, "attributes": {
        "last_analysis_stats": VT_STATS(14, 93), "reputation": -38, "tags": [], "registrar": "Beispiel Registrar Ltd.",
        "creation_date": _zeit("2026-09-26T07:41:00"), "last_update_date": _zeit("2026-09-26T07:41:05"), "tld": "example",
        "categories": {"Beispiel-Scanner A": "phishing", "Beispiel-Scanner B": "phishing and fraud"},
        "last_analysis_date": _zeit("2026-10-04T10:00:00"),
        "last_analysis_results": {"Scanner A": {"category": "malicious", "result": "phishing"},
                                  "Scanner B": {"category": "malicious", "result": "phishing"}},
        "last_dns_records": [{"type": "A", "value": IP_SERVER, "ttl": 300}, {"type": "MX", "value": f"mail.{DOMAIN}", "ttl": 300},
                             {"type": "NS", "value": "ns1.beispiel-dns.example", "ttl": 3600}],
        "last_https_certificate": {"thumbprint_sha256": hashlib.sha256(b"muster-zertifikat").hexdigest(),
                                   "subject": {"CN": DOMAIN}, "issuer": {"O": "Let's Encrypt"}}}}}),
    ("www.virustotal.com", f"/api/v3/ip_addresses/{IP_SERVER}"): (200, {"data": {"type": "ip_address", "id": IP_SERVER, "attributes": {
        "last_analysis_stats": VT_STATS(9, 93), "reputation": -21, "as_owner": "Beispiel Hosting AG", "asn": 64500,
        "country": "NL", "network": "203.0.113.0/24", "last_analysis_date": _zeit("2026-10-04T10:05:00"),
        "last_analysis_results": {"Scanner A": {"category": "malicious", "result": "phishing"}}}}}),
    ("www.virustotal.com", f"/api/v3/ip_addresses/{IP_SERVER}/resolutions"): (200, {"data": [
        {"type": "resolution", "id": f"{IP_SERVER}{DOMAIN}", "attributes": {"ip_address": IP_SERVER, "host_name": DOMAIN, "date": _zeit("2026-09-26T08:10:00")}},
        {"type": "resolution", "id": f"{IP_SERVER}{DOMAIN2}", "attributes": {"ip_address": IP_SERVER, "host_name": DOMAIN2, "date": _zeit("2026-09-19T15:22:00")}}]}),
    ("www.virustotal.com", f"/api/v3/files/{DATEI}"): (200, {"data": {"type": "file", "id": DATEI, "attributes": {
        "last_analysis_stats": {"malicious": 41, "suspicious": 2, "undetected": 29, "harmless": 0}, "sha256": DATEI,
        "type_description": "Win32 EXE", "size": 482816, "meaningful_name": "Rechnung_Q3.pdf.exe",
        "names": ["Rechnung_Q3.pdf.exe", "invoice.exe"], "times_submitted": 6,
        "first_submission_date": _zeit("2026-09-27T11:02:00"), "last_analysis_date": _zeit("2026-10-03T19:30:00"),
        "popular_threat_classification": {"suggested_threat_label": "trojan.musterstealer/stealer",
                                          "popular_threat_category": [{"value": "trojan", "count": 22}, {"value": "stealer", "count": 9}]},
        "last_analysis_results": {"Scanner A": {"category": "malicious", "result": "Trojan.MusterStealer"},
                                  "Scanner C": {"category": "malicious", "result": "Stealer/Muster.A"}}}}}),
    ("www.virustotal.com", f"/api/v3/files/{DATEI}/contacted_ips"): (200, {"data": [
        {"type": "ip_address", "id": IP_SERVER, "attributes": {"last_analysis_stats": VT_STATS(9, 93)}}]}),
    ("api.urlquery.net", "/public/v1/search/reports/"): (200, {"query": DOMAIN, "total_hits": 1, "limit": 10, "offset": 0, "reports": [
        {"report_id": "0f6c2b1e-5d1a-4c7e-9a3b-7e2d5c9b1a44", "status": "done", "date": "2026-09-30T06:18:00Z", "tags": ["phishing"],
         "url": {"addr": URL}, "ip": {"addr": IP_SERVER, "asn": 64500, "as": "Beispiel Hosting AG", "country_code": "NL"},
         "final": {"url": {"addr": URL}, "title": "Kundenportal – Anmeldung"}, "stats": {"alert_count": {"ids": 0, "urlquery": 2, "analyzer": 1}}}]}),
    ("api.urlquery.net", "/public/v1/report/0f6c2b1e-5d1a-4c7e-9a3b-7e2d5c9b1a44"): (200, {
        "report_id": "0f6c2b1e-5d1a-4c7e-9a3b-7e2d5c9b1a44", "status": "done", "date": "2026-09-30T06:18:00Z", "tags": ["phishing"],
        "url": {"addr": URL}, "ip": {"addr": IP_SERVER, "asn": 64500, "as": "Beispiel Hosting AG", "country_code": "NL"},
        "final": {"url": {"addr": URL}, "title": "Kundenportal – Anmeldung"}, "stats": {"alert_count": {"ids": 0, "urlquery": 2, "analyzer": 1}},
        "summary": [{"fqdn": DOMAIN, "ip": {"addr": IP_SERVER}, "domain_registered": "2026-09-26", "alert_count": 3, "request_count": 14}],
        "sensors": {"urlquery": [{"sensor_name": "urlquery", "verdict": "phishing", "trigger": URL, "comment": "Nachbau einer Anmeldemaske, Formular sendet an /gate.php"},
                                 {"sensor_name": "urlquery", "verdict": "suspicious", "trigger": DOMAIN, "comment": "Domain jünger als 7 Tage"}],
                    "analyzer": [{"sensor_name": "phishing-kit", "verdict": "phishing", "trigger": "gate.php", "comment": "Bekanntes Formular-Sammelskript"}], "ids": []},
        "http": [{"url": {"addr": URL}, "ip": {"addr": IP_SERVER}}, {"url": {"addr": f"https://{DOMAIN}/gate.php"}, "ip": {"addr": IP_SERVER}}],
        "files": []}),
    ("web.archive.org", "/cdx/search/cdx"): (200, [
        ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
        ["20260928101500", URL, "200", "text/html", "K4JQ2WFT6ZL3ZC7E5N2DQGZ4H3PXMUST", "5121"],
        ["20261001174233", URL, "200", "text/html", "Q7LB6ZC7E5N2DQGZ4H3PK4JQ2WFTMUST", "5388"]]),
    ("api-pro.ransomware.live", f"/groups/{GRUPPE}"): (200, {
        "name": GRUPPE, "description": "Erfundene Gruppe für den Musterfall. Betreibt laut Eigendarstellung eine Leak-Seite und droht mit Veröffentlichung.",
        "locations": [{"fqdn": ONION, "title": "MusterLocker Blog", "available": True, "updated": "2026-10-03T21:00:00"}]}),
    ("api-pro.ransomware.live", "/victims/"): (200, {"victims": [
        {"victim": "Beispiel Logistik GmbH", "group": GRUPPE, "discovered": "2026-09-12 08:30:11", "attackdate": "2026-09-09",
         "country": "DE", "activity": "Transportation/Logistics", "domain": "beispiel-logistik.example",
         "description": "Erfundener Eintrag für den Musterfall.", "claim_url": f"http://{ONION}/post/17"},
        {"victim": "Muster Treuhand AG", "group": GRUPPE, "discovered": "2026-08-30 19:02:45", "attackdate": "2026-08-27",
         "country": "CH", "activity": "Business Services", "domain": "muster-treuhand.example",
         "description": "Erfundener Eintrag für den Musterfall.", "claim_url": f"http://{ONION}/post/16"}]}),
    ("ahmia.fi", "/blacklist/banned/"): (200, "\n".join(hashlib.md5(f"gesperrt{i}.onion".encode()).hexdigest() for i in range(40))),
    ("t.me", "/s/breachdetect"): (200, """<html><body>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="breachdetect/4411">
<div class="tgme_widget_message_text">Neuer Datensatz im Umlauf: Beispiel Versand GmbH, 120k Kundendaten<br>
<a href="https://beispiel-quelle.example/leak/4411">Details</a></div>
<a class="tgme_widget_message_date"><time datetime="2026-10-02T18:04:11+00:00">18:04</time></a></div></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="breachdetect/4412">
<div class="tgme_widget_message_text">Forum-Angebot: Zugangsdaten Muster-Bank, ungeprüft</div>
<a class="tgme_widget_message_date"><time datetime="2026-10-03T07:40:52+00:00">07:40</time></a></div></div>
</body></html>"""),
    ("127.0.0.1", "/api/dns"): (200, {"A": [{"address": IP_SERVER, "family": 4}], "AAAA": [], "MX": [{"exchange": f"mail.{DOMAIN}", "priority": 10}],
                                    "TXT": [["v=spf1 ip4:203.0.113.7 -all"]], "NS": ["ns1.beispiel-dns.example", "ns2.beispiel-dns.example"],
                                    "CNAME": [], "SOA": {"nsname": "ns1.beispiel-dns.example", "serial": 2026092601}, "SRV": [], "PTR": []}),
}


def _json(status: int, inhalt: object) -> httpx.Response:
    """Antwort mit festgelegter Bytefolge, unabhängig von der httpx-Version."""
    return httpx.Response(status, content=json.dumps(inhalt, ensure_ascii=False, separators=(",", ":")).encode(),
                          headers={"content-type": "application/json"})


KETTENDIENSTE = ("mempool.space", "blockstream.info", "www.walletexplorer.com", "sanctionslistservice.ofac.treas.gov", "api.ransomwhe.re",
                 "api.trmlabs.com", "coins.llama.fi", "data-api.ecb.europa.eu")


def antworten(anfrage: httpx.Request) -> httpx.Response:
    host, pfad = anfrage.url.host, anfrage.url.path
    if host == "api.abuseipdb.com" and pfad.endswith("/check"):
        ip = parse_qs(anfrage.url.query.decode()).get("ipAddress", [""])[0]
        server = ip == IP_SERVER
        return _json(200, {"data": {
            "ipAddress": ip, "isPublic": True, "isWhitelisted": False, "abuseConfidenceScore": 87 if server else 12,
            "countryCode": "NL" if server else "DE", "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Beispiel Hosting AG" if server else "Beispiel Transit BV", "domain": "beispiel-hosting.example" if server else "beispiel-transit.example",
            "hostnames": [DOMAIN] if server else [], "isTor": False, "totalReports": 64 if server else 3,
            "numDistinctUsers": 23 if server else 2, "lastReportedAt": "2026-10-05T04:11:00+00:00" if server else "2026-08-14T09:00:00+00:00",
            "reports": [{"reportedAt": "2026-10-05T04:11:00+00:00", "comment": "Phishing-Seite, Nachbau eines Kundenportals", "categories": [7, 21], "reporterCountryCode": "CH"},
                        {"reportedAt": "2026-09-30T12:02:00+00:00", "comment": "Spam mit Link auf Phishing", "categories": [11, 7], "reporterCountryCode": "DE"}] if server else []}})
    if host == "api.abuseipdb.com" and pfad.endswith("/reports"):
        return _json(429, {"errors": [{"detail": "Daily rate limit of 100 requests exceeded for this endpoint.", "status": 429}]})
    if host == "www.virustotal.com" and pfad.startswith("/api/v3/urls/"):
        return _json(404, {"error": {"code": "NotFoundError", "message": "URL not found"}})
    if host in KETTENDIENSTE:
        return KETTE.antwort(anfrage)
    inhalt = ANTWORTEN.get((host, pfad))
    if inhalt is None:
        return _json(404, {"fehler": "im Musterfall nicht vorgesehen", "host": host, "pfad": pfad})
    status, koerper = inhalt
    return httpx.Response(status, content=koerper.encode()) if isinstance(koerper, str) else _json(status, koerper)


# --------------------------------------------------------------------------- Ablauf

class Uhr:
    def __init__(self, start: datetime) -> None:
        self.jetzt = start

    def __call__(self) -> datetime:
        return self.jetzt

    def weiter(self, sekunden: int) -> str:
        self.jetzt += timedelta(seconds=sekunden)
        return self.jetzt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hook(ereignis: dict, zeit: str) -> None:
    """Spielt dem Sitzungs-Hook ein Ereignis zu, so wie Claude Code es tun würde."""
    r = subprocess.run([sys.executable, str(PROJEKT / ".claude/hooks/protokoll_hook.py")],
                       input=json.dumps({"session_id": SITZUNG, "cwd": str(PROJEKT), **ereignis}), text=True,
                       encoding="utf-8", capture_output=True, env={**os.environ, "CLAUDE_PROJECT_DIR": str(PROJEKT), "OSINT_TESTZEIT": zeit})
    if r.returncode != 0:
        raise RuntimeError(f"Sitzungs-Hook fehlgeschlagen: {r.stderr}")


async def ermitteln(uhr: Uhr) -> tuple[dict[str, str], dict[str, dict]]:
    """Führt die Abfragen des Musterfalls aus. Rückgabe: Protokoll-IDs je Schritt und die Ergebnisse der
    Blockchain-Werkzeuge, aus denen die Befunde ihre Zahlen nehmen."""
    ids: dict[str, str] = {}
    ergebnisse: dict[str, dict] = {}

    async def schritt(name: str, agent: str, fn, sekunden: int = 7, **argumente) -> dict:
        zeit = uhr.weiter(sekunden)
        ergebnis = await fn(FALL, **argumente)
        ids[name] = ergebnis["protokoll_id"]
        ergebnisse[name] = ergebnis
        hook({"hook_event_name": "PostToolUse", "tool_name": f"mcp__osint__{fn.__name__}", "agent_type": agent,
              "agent_id": f"agent-{agent}", "tool_use_id": f"toolu_muster_{len(ids):03d}",
              "tool_input": {"fall": FALL, **argumente}, "duration_ms": 400 + 37 * len(ids),
              "tool_response": [{"type": "text", "text": json.dumps(ergebnis, ensure_ascii=False)}]}, zeit)
        return ergebnis

    A, M, D, B = "infrastruktur-analyst", "malware-url-analyst", "darkweb-analyst", "blockchain-analyst"
    for agent in (A, M, D, B):
        hook({"hook_event_name": "SubagentStart", "agent_type": agent, "agent_id": f"agent-{agent}"}, uhr.weiter(2))

    await schritt("shodan_server", A, infra.shodan_host, ip=IP_SERVER, zweck="Einliefernder Host aus Rapport Ziff. 5: Dienste und Betreiber klären")
    await schritt("abuse_server", A, infra.abuseipdb_pruefen, ip=IP_SERVER, zweck="Einliefernder Host aus Rapport Ziff. 5: frühere Missbrauchsmeldungen prüfen")
    await schritt("vt_ip_server", A, infra.virustotal_ip, ip=IP_SERVER, zweck="Einliefernder Host aus Rapport Ziff. 5: Einschätzung der Sicherheitsanbieter")
    await schritt("spur_server", A, infra.spur_kontext, ip=IP_SERVER, zweck="Einliefernder Host aus Rapport Ziff. 5: Rechenzentrum oder Anonymisierungsdienst?")
    await schritt("spur_login", A, infra.spur_kontext, ip=IP_LOGIN, zweck="Anmelde-IP aus Rapport Ziff. 3: VPN, Proxy oder Privatanschluss?")
    await schritt("abuse_login", A, infra.abuseipdb_pruefen, ip=IP_LOGIN, zweck="Anmelde-IP aus Rapport Ziff. 3: frühere Missbrauchsmeldungen prüfen")
    await schritt("internetdb_login", A, infra.shodan_internetdb, ip=IP_LOGIN, zweck="Anmelde-IP aus Rapport Ziff. 3: offene Dienste als Hinweis auf VPN-Knoten")
    await schritt("abuse_meldungen", A, infra.abuseipdb_meldungen, ip=IP_SERVER, zweck="Einzelmeldungen zum Server für die Zeitachse abrufen")
    await schritt("vt_aufloesungen", A, infra.virustotal_beziehungen, typ="ip", wert=IP_SERVER, beziehung="resolutions",
                  zweck="Pivot: Welche weiteren Domains zeigten auf den Server aus Ziff. 5?")
    await schritt("webcheck_dns", A, web.webcheck_passiv, ziel=DOMAIN, pruefung="dns", zweck="DNS-Einträge der Phishing-Domain aus Rapport Ziff. 2 festhalten")

    await schritt("vt_domain", M, infra.virustotal_domain, domain=DOMAIN, zweck="Absender- und Linkdomain aus Rapport Ziff. 2: Alter und Einschätzung")
    await schritt("vt_url", M, infra.virustotal_url, url=URL, zweck="Phishing-Link aus Rapport Ziff. 2: vorhandene Analyse abrufen")
    await schritt("uq_suche", M, web.urlquery_suche, suchtext=DOMAIN, zweck="Phishing-Domain aus Rapport Ziff. 2: Gibt es bereits Sandbox-Berichte?")
    await schritt("uq_bericht", M, web.urlquery_bericht, bericht_id="0f6c2b1e-5d1a-4c7e-9a3b-7e2d5c9b1a44",
                  zweck="Sandbox-Bericht zur Phishing-Seite lesen: Verhalten und Formularziel")
    await schritt("wayback", M, web.wayback_verlauf, url=URL, zweck="Seit wann existiert die Phishing-Seite aus Rapport Ziff. 2?")
    await schritt("vt_datei", M, infra.virustotal_datei, hashwert=DATEI, zweck="Mailanhang aus Rapport Ziff. 4: Ist die Datei als Schadsoftware bekannt?")
    await schritt("vt_datei_ips", M, infra.virustotal_beziehungen, typ="datei", wert=DATEI, beziehung="contacted_ips",
                  zweck="Mailanhang aus Rapport Ziff. 4: Mit welchen Servern spricht die Datei?")
    await schritt("shodan_server_cache", M, infra.shodan_host, ip=IP_SERVER, zweck="Zertifikat des Servers mit jenem der Phishing-Domain vergleichen")
    await schritt("uq_einreichen", M, web.urlquery_einreichen, url=URL, zweck="Aktuellen Stand der Phishing-Seite in der Sandbox prüfen lassen")

    await schritt("rl_gruppe", D, szene.ransomware_gruppe, gruppe=GRUPPE, zweck="Gruppe aus dem Erpresserschreiben, Rapport Ziff. 6: bekannt, und mit welcher Leak-Seite?")
    await schritt("rl_opfer", D, szene.ransomware_opfer, gruppe=GRUPPE, zweck="Opferliste der Gruppe aus Rapport Ziff. 6 sichern, zum Abgleich mit der geschädigten Organisation im Haus")
    await schritt("onion_liste", D, szene.onion_sperrliste, onion_adresse=ONION, zweck="Onion-Adresse aus Rapport Ziff. 6 vor weiterer Verwendung gegen die Sperrliste prüfen")
    await schritt("telegram", D, szene.telegram_kanal, kanal="breachdetect", stichwort="kundenportal",
                  zweck="Breach-Feed nach Hinweisen auf die Phishing-Domain durchsehen")

    await schritt("k_pruefen", B, krypto.krypto_adresse_pruefen, wert=LOESEGELD,
                  zweck="Zahlungsadresse aus Rapport Ziff. 7: Schreibweise und Prüfsumme prüfen, bevor sie abgefragt wird")
    await schritt("k_zahlung", B, krypto.krypto_transaktion, tx=ZAHLUNG, gegenpruefen=True, sekunden=9,
                  zweck="Lösegeldzahlung aus Rapport Ziff. 7: Ist sie so in der Blockchain verzeichnet, bei zwei Quellen?")
    await schritt("k_fluss", B, krypto.krypto_geldfluss, start=ZAHLUNG, adresse=LOESEGELD, sekunden=14,
                  zweck="Lösegeldzahlung aus Rapport Ziff. 7: Wohin ging der Betrag nach dem Eingang bei den Erpressern?")
    await schritt("k_adresse", B, krypto.krypto_adresse, adresse=LOESEGELD, sekunden=11,
                  zweck="Zahlungsadresse aus Rapport Ziff. 7: weitere Eingänge und bekannte Einordnung")

    for agent in (A, M, D, B):
        hook({"hook_event_name": "SubagentStop", "agent_type": agent, "agent_id": f"agent-{agent}"}, uhr.weiter(3))
    return ids, ergebnisse


def befunde(p: dict[str, str], k: dict[str, dict], stand: str) -> dict:
    # Zahlen zur Lösegeldzahlung kommen aus den Ergebnissen der Werkzeuge, nicht aus diesem Skript
    zahlung, fluss, adresse = k["k_zahlung"]["befund"], k["k_fluss"]["befund"], k["k_adresse"]["befund"]
    anteil = {e["art"]: e for e in fluss["verteilung"]}
    boerse = next(e for e in fluss["enden"] if e["art"] == "dienst")
    start = fluss["start"]
    chf = lambda wert: "CHF " + zahl_ch(wert["chf"])      # noqa: E731
    tag = lambda iso: rapport.zeit_zeigen(iso)             # noqa: E731
    return {
        "fall_id": FALL, "stand": stand,
        "zusammenfassung": [
            "Die Phishing-Seite, über die am 29.09.2026 Zugangsdaten der [ORG_01] abgegriffen wurden, lag auf einem gemieteten "
            "Server in den Niederlanden. Die Domain wurde drei Tage vor der Tat registriert. Derselbe Server lieferte die "
            "Phishing-E-Mail ein und ist das Ziel der angehängten Schadsoftware.",
            "Die Anmeldung mit den erbeuteten Zugangsdaten kam über einen kommerziellen VPN-Dienst. Die Adresse führt deshalb "
            "nicht zu einem Anschlussinhaber. Die im Erpresserschreiben genannte Gruppe ist bekannt und betreibt die genannte "
            "Leak-Seite. Ein technischer Zusammenhang zwischen Phishing und Erpressung ist bisher nicht belegt.",
            f"Die Lösegeldzahlung über {start['betrag']} BTC ({chf(start['gegenwert'])} zum Kurs am Tag der Zahlung) ist in der Blockchain "
            f"verzeichnet. Rund {anteil['dienst']['anteil']:.0f} % davon gingen noch am selben Tag an eine Adresse, die einer Börse "
            f"zugeordnet wird. Die Börse kann sagen, welchem Kunden diese Einzahlung gutgeschrieben wurde. Rund "
            f"{anteil['liegt']['anteil']:.0f} % liegen unbewegt auf einer weiteren Adresse, der Rest ging durch einen Mischdienst."],
        "kernaussagen": [
            {"text": "Phishing-Domain, Mailversand und Schadsoftware laufen auf demselben Server zusammen.", "sicherheit": "hoch", "befunde": ["B-01", "B-05", "B-06"]},
            {"text": "Die Domain wurde eigens für die Tat eingerichtet.", "sicherheit": "hoch", "befunde": ["B-02"]},
            {"text": "Die Anmelde-IP ist ein VPN-Ausgang und identifiziert keine Person.", "sicherheit": "mittel", "befunde": ["B-04"]},
            {"text": "Ob Phishing und Erpressung vom selben Täter stammen, ist offen.", "sicherheit": "tief", "befunde": ["B-08"]},
            {"text": f"Rund {anteil['dienst']['anteil']:.0f} % des Lösegelds landeten bei einer Börse. Dort ist ein Editionsbegehren möglich.",
             "sicherheit": "mittel", "befunde": ["B-11"]}],
        "indikatoren": [
            {"id": "I-01", "typ": "domain", "wert": DOMAIN, "herkunft": "Rapport Ziff. 2", "rolle": "Phishing-Domain", "bewertung": "boesartig",
             "kennzahlen": {"vt_boesartig": 14, "vt_gesamt": 93}, "belege": [p["vt_domain"], p["uq_suche"], p["wayback"]]},
            {"id": "I-02", "typ": "url", "wert": URL, "herkunft": "Rapport Ziff. 2", "rolle": "Phishing-Seite", "bewertung": "boesartig",
             "belege": [p["uq_bericht"], p["vt_url"]]},
            {"id": "I-03", "typ": "ip", "wert": IP_SERVER, "herkunft": "Rapport Ziff. 5", "rolle": "Server der Täter", "bewertung": "boesartig",
             "kennzahlen": {"abuse_score": 87, "vt_boesartig": 9, "vt_gesamt": 93, "offene_ports": [22, 25, 80, 443]},
             "belege": [p["shodan_server"], p["abuse_server"], p["vt_ip_server"], p["spur_server"]]},
            {"id": "I-04", "typ": "ip", "wert": IP_LOGIN, "herkunft": "Rapport Ziff. 3", "rolle": "Anmeldung mit erbeuteten Zugangsdaten", "bewertung": "verdaechtig",
             "kennzahlen": {"abuse_score": 12}, "belege": [p["spur_login"], p["abuse_login"], p["internetdb_login"]]},
            {"id": "I-05", "typ": "hash", "wert": DATEI, "herkunft": "Rapport Ziff. 4", "rolle": "Mailanhang", "bewertung": "boesartig",
             "kennzahlen": {"vt_boesartig": 41, "vt_gesamt": 72}, "belege": [p["vt_datei"], p["vt_datei_ips"]]},
            {"id": "I-06", "typ": "email", "wert": f"rechnung@{DOMAIN}", "herkunft": "Rapport Ziff. 2", "rolle": "Absender der Phishing-Mail", "bewertung": "verdaechtig",
             "belege": [p["vt_domain"], p["webcheck_dns"]]},
            {"id": "I-07", "typ": "gruppe", "wert": "MusterLocker", "herkunft": "Rapport Ziff. 6", "rolle": "Unterzeichner des Erpresserschreibens", "bewertung": "boesartig",
             "belege": [p["rl_gruppe"]]},
            {"id": "I-08", "typ": "onion", "wert": ONION, "herkunft": "Rapport Ziff. 6", "rolle": "Im Erpresserschreiben genannte Adresse", "bewertung": "verdaechtig",
             "belege": [p["rl_gruppe"], p["onion_liste"]]},
            {"id": "I-09", "typ": "domain", "wert": DOMAIN2, "herkunft": f"Pivot aus {p['vt_aufloesungen']} (frühere Namensauflösungen von I-03)",
             "rolle": "Weitere Domain auf demselben Server", "bewertung": "verdaechtig", "belege": [p["vt_aufloesungen"]]},
            {"id": "I-10", "typ": "wallet", "wert": LOESEGELD, "herkunft": "Rapport Ziff. 7", "rolle": "Zahlungsadresse aus dem Erpresserschreiben (Bitcoin)",
             "bewertung": "boesartig", "kennzahlen": {"erhalten": f"{adresse['erhalten']} BTC", "guthaben": f"{adresse['guthaben']['betrag']} BTC",
                                                      "transaktionen": adresse["transaktionen"]},
             "belege": [p["k_pruefen"], p["k_adresse"]]},
            {"id": "I-11", "typ": "transaktion", "wert": ZAHLUNG, "herkunft": "Rapport Ziff. 7", "rolle": "Lösegeldzahlung der [ORG_01] (Bitcoin)",
             "bewertung": "unauffaellig", "belege": [p["k_zahlung"]]},
            {"id": "I-12", "typ": "wallet", "wert": EINZAHLUNG, "herkunft": f"Geldfluss {p['k_fluss']} (erste Station nach der Zahlungsadresse)",
             "rolle": "Mutmassliche Einzahlungsadresse bei einer Börse", "bewertung": "verdaechtig", "belege": [p["k_fluss"]]},
            {"id": "I-13", "typ": "wallet", "wert": LIEGT, "herkunft": f"Geldfluss {p['k_fluss']} (zweite Station)",
             "rolle": "Adresse, auf der ein Teil des Lösegelds unbewegt liegt", "bewertung": "verdaechtig", "belege": [p["k_fluss"]]}],
        "befunde": [
            {"id": "B-01", "titel": "Die Phishing-Domain zeigt auf den Server 203.0.113.7", "art": "feststellung", "sicherheit": "hoch", "quellenbewertung": "B1",
             "text": f"Der DNS-Eintrag der Domain {DOMAIN} verweist auf {IP_SERVER}. Der Server meldet unter dieser Adresse den Hostnamen "
                     "der Domain und liefert auf Port 443 ein TLS-Zertifikat aus, das auf die Domain ausgestellt ist. Die DNS-Abfrage über die "
                     "eigene Web-Check-Instanz bestätigt die Zuordnung.",
             "erlaeuterung": "Eine Domain ist wie ein Name im Telefonbuch, die IP-Adresse die Nummer dahinter. Drei voneinander unabhängige "
                             "Stellen nennen für diesen Namen dieselbe Nummer. Die Phishing-Seite lag also auf diesem Server.",
             "indikatoren": ["I-01", "I-03"], "belege": [p["vt_domain"], p["shodan_server"], p["webcheck_dns"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-02", "titel": "Die Domain wurde drei Tage vor der Tat registriert", "art": "bewertung", "sicherheit": "hoch", "quellenbewertung": "B2",
             "text": "Die Domain wurde am 26.09.2026 registriert. Die erste Archivaufnahme der Anmeldeseite stammt vom 28.09.2026, die "
                     "Phishing-E-Mail vom 29.09.2026. Der Sandbox-Dienst stuft die Domain als jünger als sieben Tage ein. Eine frühere, "
                     "unverdächtige Nutzung ist nicht ersichtlich.",
             "erlaeuterung": "Die Internetadresse gab es vor der Tat praktisch nicht. Sie wurde kurz davor angelegt und sofort mit der gefälschten "
                             "Anmeldeseite bestückt. Das spricht dafür, dass sie eigens für diesen Zweck eingerichtet wurde und nicht einer "
                             "gehackten, sonst harmlosen Website gehört.",
             "indikatoren": ["I-01", "I-02"], "belege": [p["vt_domain"], p["wayback"], p["uq_bericht"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-03", "titel": "Der Server steht bei einem Hosting-Anbieter und ist mehrfach als missbräuchlich gemeldet", "art": "feststellung",
             "sicherheit": "hoch", "quellenbewertung": "B2",
             "text": f"{IP_SERVER} gehört zum Netz der Beispiel Hosting AG (AS64500, Niederlande) und wird übereinstimmend als "
                     "Rechenzentrumsadresse geführt, nicht als Anonymisierungsdienst. Bei AbuseIPDB liegen 64 Meldungen von 23 Meldern vor, "
                     "Abuse-Score 87 von 100, zuletzt am 05.10.2026 wegen Phishing. Offen sind die Ports 22, 25, 80 und 443.",
             "erlaeuterung": "Der Server ist ein gemieteter Rechner in einem Rechenzentrum. Der Vermieter kennt seinen Kunden. Über ihn führt der "
                             "direkteste Weg zum Betreiber. Der Server ist auch anderen schon negativ aufgefallen, was gegen einen Zufall spricht.",
             "indikatoren": ["I-03"], "belege": [p["shodan_server"], p["abuse_server"], p["spur_server"], p["vt_ip_server"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-04", "titel": "Die Anmelde-IP ist der Ausgang eines VPN-Dienstes", "art": "bewertung", "sicherheit": "mittel", "quellenbewertung": "B2",
             "text": f"{IP_LOGIN} wird als Ausgangsknoten des VPN-Dienstes «BEISPIEL_VPN» geführt (anonymisierend, rund 214 beobachtete "
                     "Geräte aus 31 Ländern). Offen sind die Ports 443 und 1194, wie für VPN-Knoten üblich. Missbrauchsmeldungen gibt es wenige "
                     "(Score 12 von 100). Die Einstufung als VPN stammt von einem einzelnen Anbieter.",
             "erlaeuterung": "Wer über einen VPN-Dienst ins Internet geht, tritt nach aussen mit der Adresse des Dienstes auf, zusammen mit "
                             "Hunderten anderer Kunden. Die Adresse aus dem Serverprotokoll gehört also dem VPN-Anbieter und nicht dem Täter. "
                             "Eine Anfrage beim Anschlussanbieter würde ins Leere laufen.",
             "indikatoren": ["I-04"], "belege": [p["spur_login"], p["internetdb_login"], p["abuse_login"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-05", "titel": "Der Mailanhang ist als Schadsoftware bekannt und kontaktiert denselben Server", "art": "feststellung",
             "sicherheit": "mittel", "quellenbewertung": "B2",
             "text": "41 von 72 Sicherheitsprodukten erkennen die Datei als bösartig, überwiegend als Trojaner der Familie «MusterStealer», "
                     "einer Software zum Abgreifen gespeicherter Zugangsdaten. Die Datei wurde erstmals am 27.09.2026 bei VirusTotal "
                     f"eingereicht. Als kontaktierte Adresse ist {IP_SERVER} verzeichnet.",
             "erlaeuterung": "Die Datei tarnt sich als Rechnung, ist aber ein Programm, das auf dem Rechner gespeicherte Passwörter sammelt und "
                             "an die Täter schickt. Sie meldet sich bei demselben Server, auf dem auch die gefälschte Anmeldeseite lag.",
             "indikatoren": ["I-05", "I-03"], "belege": [p["vt_datei"], p["vt_datei_ips"]], "gegenpruefung": "eingeschraenkt",
             "gegenpruefung_notiz": "Die Zuordnung zur Familie beruht auf den Bezeichnungen der Scanner, nicht auf einer eigenen Analyse der Datei. "
                                    "Erkennungsrate und kontaktierte Adresse sind in den Rohdaten nachvollziehbar."},
            {"id": "B-06", "titel": "Die Seite ahmt eine Anmeldemaske nach und sendet Eingaben an ein Sammelskript", "art": "feststellung",
             "sicherheit": "mittel", "quellenbewertung": "B2",
             "text": "Der Sandbox-Bericht vom 30.09.2026 zeigt eine Seite mit dem Titel «Kundenportal – Anmeldung». Das Formular sendet die "
                     f"Eingaben an /gate.php auf {IP_SERVER}. Das Skript ist als Bestandteil eines bekannten Phishing-Baukastens erkannt. "
                     "Bei VirusTotal lag zur genauen URL keine Analyse vor.",
             "erlaeuterung": "Die Seite sah aus wie das echte Kundenportal. Was dort eingetippt wurde, ging aber nicht an die [ORG_01], sondern "
                             "an ein kleines Programm der Täter, das Benutzername und Passwort einsammelt.",
             "indikatoren": ["I-02", "I-03"], "belege": [p["uq_bericht"], p["uq_suche"], p["vt_url"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-07", "titel": "Die Gruppe MusterLocker ist bekannt und führt die genannte Onion-Adresse als Leak-Seite", "art": "feststellung",
             "sicherheit": "mittel", "quellenbewertung": "C2",
             "text": "ransomware.live führt eine Gruppe dieses Namens. Als deren Leak-Seite ist genau die Onion-Adresse verzeichnet, die im "
                     "Erpresserschreiben steht. Die Gruppe nennt dort derzeit zwei Opfer, zuletzt am 12.09.2026. Die Onion-Adresse steht "
                     "nicht auf der Sperrliste von Ahmia. Im Breach-Feed fand sich kein Hinweis auf die Phishing-Domain.",
             "erlaeuterung": "Die Absender des Erpresserschreibens verwenden den Namen und die Adresse einer Gruppe, die es tatsächlich gibt. "
                             "Ob das Schreiben wirklich von dieser Gruppe stammt oder jemand nur deren Namen benutzt, lässt sich daraus "
                             "nicht ablesen. Ob die [ORG_01] auf der Opferliste steht, muss im Haus mit dem echten Namen geprüft werden.",
             "indikatoren": ["I-07", "I-08"], "belege": [p["rl_gruppe"], p["rl_opfer"], p["onion_liste"], p["telegram"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-08", "titel": "Phishing und Erpressung könnten vom selben Akteur stammen", "art": "hypothese", "sicherheit": "tief",
             "text": "Zwischen dem Abgriff der Zugangsdaten (29.09.2026) und dem Erpresserschreiben (01.10.2026) liegen zwei Tage. Ein "
                     "technischer Zusammenhang ist nicht belegt: Weder der Server noch die Domains tauchen im Umfeld der Gruppe auf.",
             "erlaeuterung": "Es liegt nahe, dass dieselben Täter erst die Zugangsdaten gestohlen und dann erpresst haben. Bewiesen ist das nicht. "
                             "Die zeitliche Nähe ist das einzige Indiz. Denkbar ist auch, dass die Zugangsdaten weiterverkauft wurden.",
             "indikatoren": ["I-03", "I-07"], "belege": [], "gegenpruefung": "bestaetigt"},
            {"id": "B-09", "titel": "Auf demselben Server lag eine zweite, ähnlich benannte Domain", "art": "feststellung", "sicherheit": "mittel",
             "quellenbewertung": "B3",
             "text": f"Laut den bei VirusTotal verzeichneten Namensauflösungen zeigte am 19.09.2026 auch die Domain {DOMAIN2} auf "
                     f"{IP_SERVER}, eine Woche vor der Registrierung der Phishing-Domain.",
             "erlaeuterung": "Die Täter haben auf demselben Server vermutlich schon vorher eine ähnliche Falle betrieben. Das kann auf weitere "
                             "Geschädigte hinweisen und ist ein zusätzlicher Ansatzpunkt beim Hosting-Anbieter.",
             "indikatoren": ["I-09", "I-03"], "belege": [p["vt_aufloesungen"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-10", "titel": f"Die Lösegeldzahlung über {start['betrag']} BTC ist in der Blockchain verzeichnet", "art": "feststellung",
             "sicherheit": "hoch", "quellenbewertung": "A1",
             "text": f"Die Transaktion aus Rapport Ziff. 7 wurde am {tag(zahlung['zeit'])} in Block {zahlung['block']} bestätigt. Sie überträgt "
                     f"{start['betrag']} BTC an die im Erpresserschreiben genannte Adresse. Der Gegenwert am Tag der Zahlung betrug "
                     f"{chf(start['gegenwert'])} (Kurs laut DefiLlama, umgerechnet zum Referenzkurs der Europäischen Zentralbank). "
                     f"mempool.space und {zahlung['gegenpruefung']['quelle']} zeigen Block, Zeit, Absender, Empfänger und Beträge übereinstimmend.",
             "erlaeuterung": "Eine Blockchain ist ein öffentliches Kassenbuch: Jede Zahlung steht für immer darin, aber ohne Namen. Die Zahlung "
                             "der [ORG_01] steht dort genau so, wie der Auszug der Handelsplattform sie nennt. Zwei unabhängige Auskunftsdienste "
                             "zeigen denselben Eintrag. Damit steht fest, wann, wie viel und an welche Adresse gezahlt wurde.",
             "indikatoren": ["I-11", "I-10"], "belege": [p["k_zahlung"]], "gegenpruefung": "bestaetigt"},
            {"id": "B-11", "titel": f"Rund {anteil['dienst']['anteil']:.0f} % des Lösegelds gingen an eine Adresse, die einer Börse zugeordnet wird",
             "art": "bewertung", "sicherheit": "mittel", "quellenbewertung": "B3",
             "text": f"Die Zahlungsadresse leitete den Betrag am {tag(fluss['fluesse'][0]['zeit'])} in einer Transaktion an zwei Adressen weiter. "
                     f"{boerse['betrag']} BTC ({anteil['dienst']['anteil']} %, {chf(anteil['dienst']['gegenwert'])}) gingen an {EINZAHLUNG}. Von dort "
                     f"wurden sie in einer Sammeltransaktion mit Guthaben von elf weiteren Adressen zusammengelegt, wie es Börsen mit den "
                     f"Einzahlungen ihrer Kunden tun. WalletExplorer ordnet die Adresse dem Dienst «{boerse['name']}» zu. "
                     f"{anteil['liegt']['betrag']} BTC ({anteil['liegt']['anteil']} %) liegen unbewegt auf {LIEGT}, "
                     f"{anteil['mischer']['betrag']} BTC ({anteil['mischer']['anteil']} %) gingen in eine Transaktion mit dem Muster eines "
                     "Mischdienstes. Wo eine Transaktion mehrere Eingänge zusammenlegt, ist der verfolgte Betrag im Verhältnis der "
                     "Ausgänge aufgeteilt (anteilige Zuordnung).",
             "erlaeuterung": "Das Lösegeld blieb nicht bei den Erpressern liegen. Der grössere Teil wurde an eine Adresse überwiesen, die sich wie "
                             "das Einzahlungskonto eines Kunden bei einer Börse verhält. Eine Börse kennt ihre Kunden, so wie eine Bank ihre "
                             "Kontoinhaber kennt. Sie kann auf ein Editionsbegehren hin sagen, wem diese Einzahlung gutgeschrieben wurde. Das ist "
                             "der direkteste Weg vom Geld zu einer Person.",
             "indikatoren": ["I-10", "I-12", "I-13"], "belege": [p["k_fluss"]], "gegenpruefung": "eingeschraenkt",
             "gegenpruefung_notiz": "Die einzelnen Zahlungen stehen in den Rohdaten. Dass die Adresse zu einer Börse gehört, ist die Angabe eines "
                                    "einzelnen Dienstes (WalletExplorer) und stützt sich zusätzlich auf das Muster der Sammeltransaktion. "
                                    "Der Name der Börse ist erst mit ihrer Antwort gesichert."},
            {"id": "B-12", "titel": "Die Zahlungsadresse ist als Lösegeld-Adresse von MusterLocker verzeichnet", "art": "feststellung",
             "sicherheit": "mittel", "quellenbewertung": "C3",
             "text": f"Der Datensatz Ransomwhere führt die Adresse {LOESEGELD} unter der Familie «{adresse['etiketten'][0]['name']}». Auf den "
                     f"Sanktionslisten (OFAC, TRM Labs) steht sie nicht. Die Adresse hat bisher {adresse['zahlungseingaenge']} Eingang über "
                     f"{adresse['erhalten']} BTC erhalten und nichts mehr als Guthaben ({adresse['guthaben']['betrag']} BTC).",
             "erlaeuterung": "Freiwillige sammeln Adressen, an die Opfer von Erpressungssoftware gezahlt haben. Die Adresse aus dem "
                             "Erpresserschreiben steht in dieser Sammlung unter demselben Gruppennamen. Das stützt den Bezug zur Gruppe, "
                             "beweist ihn aber nicht: Die Einträge stammen von Dritten und sind ungeprüft.",
             "indikatoren": ["I-10", "I-07"], "belege": [p["k_adresse"]], "gegenpruefung": "bestaetigt"}],
        "beziehungen": [
            {"von": "I-01", "nach": "I-03", "art": "zeigt auf", "sicherheit": "hoch", "belege": [p["vt_domain"], p["shodan_server"]]},
            {"von": "I-02", "nach": "I-01", "art": "liegt auf", "sicherheit": "hoch", "belege": [p["uq_bericht"]]},
            {"von": "I-06", "nach": "I-01", "art": "Absenderdomain", "sicherheit": "mittel", "quelle": "Rapport Ziff. 2"},
            {"von": "I-05", "nach": "I-03", "art": "kontaktiert", "sicherheit": "mittel", "belege": [p["vt_datei_ips"]]},
            {"von": "I-09", "nach": "I-03", "art": "zeigte auf", "sicherheit": "mittel", "belege": [p["vt_aufloesungen"]]},
            {"von": "I-04", "nach": "I-02", "art": "Anmeldung nach Abgriff", "sicherheit": "mittel", "quelle": "Rapport Ziff. 3"},
            {"von": "I-08", "nach": "I-07", "art": "Leak-Seite von", "sicherheit": "mittel", "belege": [p["rl_gruppe"]]},
            {"von": "I-07", "nach": "I-03", "art": "Betreiber?", "sicherheit": "tief"},
            {"von": "I-11", "nach": "I-10", "art": "zahlt an", "sicherheit": "hoch", "belege": [p["k_zahlung"]]},
            {"von": "I-10", "nach": "I-12", "art": "leitet weiter an", "sicherheit": "mittel", "belege": [p["k_fluss"]]},
            {"von": "I-10", "nach": "I-13", "art": "leitet anteilig weiter an", "sicherheit": "mittel", "belege": [p["k_fluss"]]},
            {"von": "I-10", "nach": "I-07", "art": "Zahlungsadresse von", "sicherheit": "mittel", "belege": [p["k_adresse"]]}],
        "geldfluesse": [
            {"beleg": p["k_fluss"], "titel": f"Verbleib der Lösegeldzahlung vom {tag(zahlung['zeit'])[:10]}", "befunde": ["B-11"],
             "text": "Das Bild folgt dem bezahlten Betrag von der Adresse der Erpresser bis dorthin, wo sich die Spur mit offenen Quellen "
                     "nicht weiter verfolgen lässt."}],
        "zeitachse": [
            {"zeit": "2026-09-19T15:22:00Z", "ereignis": f"{DOMAIN2} zeigt auf den Server {IP_SERVER}.", "belege": [p["vt_aufloesungen"]]},
            {"zeit": "2026-09-26T07:41:00Z", "ereignis": f"Registrierung der Domain {DOMAIN}.", "belege": [p["vt_domain"]]},
            {"zeit": "2026-09-27T11:02:00Z", "ereignis": "Die Schaddatei wird erstmals bei VirusTotal eingereicht.", "belege": [p["vt_datei"]]},
            {"zeit": "2026-09-28T10:15:00Z", "ereignis": "Erste Archivaufnahme der gefälschten Anmeldeseite.", "belege": [p["wayback"]]},
            {"zeit": "2026-09-29T07:14:00Z", "ereignis": "[PERSON_02] erhält die Phishing-E-Mail.", "quelle": "Rapport Ziff. 2"},
            {"zeit": "2026-09-29T07:31:00Z", "ereignis": f"Anmeldung am Kundenportal von {IP_LOGIN} (VPN).", "quelle": "Rapport Ziff. 3"},
            {"zeit": "2026-09-30T06:18:00Z", "ereignis": "Sandbox-Bericht von urlquery stuft die Seite als Phishing ein.", "belege": [p["uq_bericht"]]},
            {"zeit": "2026-10-01", "ereignis": "Erpresserschreiben im Namen von «MusterLocker» trifft ein.", "quelle": "Rapport Ziff. 6"},
            {"zeit": "2026-10-02", "ereignis": "[PERSON_01] meldet den Vorfall.", "quelle": "Rapport Ziff. 1"},
            {"zeit": zahlung["zeit"], "ereignis": f"Die [ORG_01] zahlt {start['betrag']} BTC an die Adresse aus dem Erpresserschreiben.", "belege": [p["k_zahlung"]]},
            {"zeit": fluss["fluesse"][0]["zeit"], "ereignis": "Das Lösegeld wird in zwei Teilen weitergeleitet, der grössere an eine Börse.", "belege": [p["k_fluss"]]},
            {"zeit": "2026-10-05T04:11:00Z", "ereignis": "Jüngste Missbrauchsmeldung zum Server bei AbuseIPDB (Phishing).", "belege": [p["abuse_server"]]}],
        "luecken": [
            "Wer den Server gemietet hat, ist aus offenen Quellen nicht ersichtlich. Das weiss nur der Hosting-Anbieter.",
            "Hinter der Anmelde-IP steht ein VPN-Dienst. Ob er Verbindungsdaten führt, ist nicht bekannt.",
            f"Der aktuelle Zustand der Phishing-Seite wurde nicht geprüft. Die Freigabe für aktive Massnahmen fehlte, eine Einreichung bei urlquery wurde deshalb abgelehnt ({p['uq_einreichen']}).",
            f"Die Einzelmeldungen von AbuseIPDB waren wegen des Tageskontingents nicht abrufbar ({p['abuse_meldungen']}). Die Zeitachse stützt sich auf die Kurzübersicht.",
            "Die Schaddatei wurde nicht selbst untersucht. Die Einordnung beruht auf den Angaben von VirusTotal.",
            f"Ob die [ORG_01] auf der Leak-Seite genannt ist, liess sich nicht prüfen, weil ihr Name pseudonymisiert ist. Die Opferliste der Gruppe liegt in den Rohdaten ({p['rl_opfer']}) und ist im Haus mit dem Klarnamen abzugleichen.",
            "Eine Recherche auf der Leak-Seite selbst fand nicht statt (Freigabe darkweb nicht erteilt).",
            "Wem die Einzahlungsadresse bei der Börse gehört, steht nicht in der Blockchain. Das weiss nur die Börse.",
            f"{anteil['mischer']['betrag']} BTC gingen durch eine Transaktion mit dem Muster eines Mischdienstes. Dahinter ist die Zuordnung mit "
            "offenen Quellen nicht belastbar.",
            "Ob weitere Geschädigte an dieselbe Adresse gezahlt haben, ist nicht ersichtlich: Sie hat bisher nur diesen einen Eingang."],
        "empfehlungen": [
            {"text": "Editionsbegehren an die Beispiel Hosting AG zu Kundendaten, Zahlungsmitteln und Zugriffsprotokollen des Servers 203.0.113.7, über den Rechtshilfeweg.", "prioritaet": "hoch"},
            {"text": f"Registrar um Sperrung von {DOMAIN} und {DOMAIN2} ersuchen und Registrierungsdaten sichern.", "prioritaet": "hoch"},
            {"text": f"Editionsbegehren an die Börse «{boerse['name']}»: Welchem Kundenkonto wurde die Einzahlung von {boerse['betrag']} BTC auf "
                     f"{EINZAHLUNG} gutgeschrieben (Sammeltransaktion {boerse['tx']})? Kundendaten, Anmeldeprotokolle und Auszahlungen sichern lassen.",
             "prioritaet": "hoch"},
            {"text": f"Die Adresse {LIEGT} beobachten. Bewegt sich das dort liegende Guthaben, die Verfolgung fortsetzen.", "prioritaet": "mittel"},
            {"text": "Zugangsdaten des Kundenportals zurücksetzen und die Anmeldungen seit dem 29.09.2026 auswerten. Rechner von [PERSON_02] forensisch sichern, falls der Anhang geöffnet wurde.", "prioritaet": "hoch"},
            {"text": f"Abklären, ob zu {DOMAIN2} weitere Anzeigen vorliegen.", "prioritaet": "mittel"},
            {"text": "Freigabe für aktive Massnahmen und Dark-Web-Recherche prüfen, um den Stand der Phishing-Seite und der Leak-Seite zu dokumentieren.", "prioritaet": "mittel"},
            {"text": "Indikatoren (Anhang indikatoren.csv) an die zuständige Meldestelle und die IT-Sicherheit der [ORG_01] weitergeben.", "prioritaet": "tief"}],
        "glossar": [
            {"begriff": "AS / ASN", "erklaerung": "Autonomes System: das Netz eines Anbieters. Die Nummer zeigt, wem ein Adressbereich gehört."},
            {"begriff": "Abuse-Score", "erklaerung": "Kennzahl von AbuseIPDB von 0 bis 100. Je höher, desto häufiger und aktueller wurde eine IP-Adresse als missbräuchlich gemeldet."},
            {"begriff": "Anteilige Zuordnung", "erklaerung": "Verfahren beim Verfolgen von Bitcoin: Legt eine Transaktion mehrere Beträge zusammen, wird der verfolgte Betrag im Verhältnis der Ausgänge aufgeteilt."},
            {"begriff": "Bitcoin-Adresse (Wallet)", "erklaerung": "Kontonummer in der Blockchain. Sie nennt keinen Inhaber. Wer den zugehörigen geheimen Schlüssel hat, verfügt über das Guthaben."},
            {"begriff": "Blockchain", "erklaerung": "Öffentliches, unveränderliches Kassenbuch einer Kryptowährung. Jede Zahlung ist für alle einsehbar, aber ohne Namen."},
            {"begriff": "Börse (Handelsplattform)", "erklaerung": "Unternehmen, bei dem Kunden Kryptowährungen kaufen, verkaufen und verwahren. Es kennt seine Kunden und führt für jeden eigene Einzahlungsadressen."},
            {"begriff": "Editionsbegehren", "erklaerung": "Aufforderung einer Behörde an ein Unternehmen, bestimmte Unterlagen oder Daten herauszugeben."},
            {"begriff": "Hash (SHA-256)", "erklaerung": "Digitaler Fingerabdruck einer Datei. Gleicher Hash bedeutet gleiche Datei, unabhängig vom Dateinamen."},
            {"begriff": "Infostealer", "erklaerung": "Schadsoftware, die gespeicherte Passwörter, Sitzungsdaten und Ähnliches vom Rechner sammelt und an die Täter schickt."},
            {"begriff": "Mischdienst", "erklaerung": "Dienst oder Verfahren, bei dem viele Beteiligte gleich hohe Beträge zusammenlegen und neu verteilen, damit sich nicht mehr sagen lässt, welches Geld von wem kam."},
            {"begriff": "Leak-Seite", "erklaerung": "Website einer Erpressergruppe, auf der sie Opfer nennt und gestohlene Daten veröffentlicht, um Druck aufzubauen."},
            {"begriff": "Onion-Adresse", "erklaerung": "Adresse einer Website im Tor-Netz. Betreiber und Standort des Servers sind dabei verschleiert."},
            {"begriff": "Phishing", "erklaerung": "Täuschung mit nachgebauten Websites oder E-Mails, um Zugangsdaten zu erbeuten."},
            {"begriff": "Sandbox", "erklaerung": "Abgeschottete Umgebung, in der eine verdächtige Seite oder Datei gefahrlos geöffnet und beobachtet wird."},
            {"begriff": "Sammeltransaktion", "erklaerung": "Zahlung, mit der ein Dienst die Einzahlungen vieler Kunden auf eine eigene Adresse zusammenzieht."},
            {"begriff": "TLS-Zertifikat", "erklaerung": "Digitaler Ausweis einer Website für verschlüsselte Verbindungen. Er nennt, für welchen Namen er ausgestellt wurde."},
            {"begriff": "Transaktions-ID", "erklaerung": "Eindeutige Kennung einer Zahlung in der Blockchain, vergleichbar mit einer Buchungsnummer."},
            {"begriff": "VPN", "erklaerung": "Dienst, der den Datenverkehr über eigene Server umleitet. Nach aussen ist nur die Adresse des Dienstes sichtbar."}]}


def main() -> int:
    pfad = FAELLE / FALL
    plattform.baum_loeschen(pfad)       # die Rohdaten des vorigen Laufs sind schreibgeschützt
    for alt in list(SITZUNGEN.glob(f"{SITZUNG}*")) if SITZUNGEN.is_dir() else []:
        plattform.baum_loeschen(alt) if alt.is_dir() else alt.unlink()
    pfad.mkdir(parents=True)

    # 1. Fallakte anlegen und das Eingangsdokument durch die PII-Prüfung schicken
    for name in fallwerkzeug.UNTERORDNER:
        (pfad / name).mkdir()
    fallwerkzeug.schreiben(pfad / "fall.json", {
        "fall_id": FALL, "muster": True, "titel": "Phishing gegen Kundenportal mit anschliessender Erpressung (Musterfall)",
        "auftrag": "Infrastruktur hinter der Phishing-Seite und der Anmeldung klären, die angehängte Datei einordnen, prüfen, "
                   "ob ein Bezug zur im Erpresserschreiben genannten Gruppe besteht, und den Verbleib der Lösegeldzahlung klären.",
        "sachbearbeiter": "MUS", "klassifizierung": "MUSTER", "eroeffnet": "2026-11-12T08:55:00+01:00",
        "freigaben": {n: {"erteilt": False, "durch": "", "am": "", "vermerk": ""} for n in ("aktiv", "darkweb", "personenbezug")}})
    fallwerkzeug.jetzt = lambda: "2026-11-12T08:56:00+01:00"
    quelle = pfad / "eingang" / "rapport_pseudonymisiert.md"
    plattform.text_schreiben(quelle, EINGANG)
    if not fallwerkzeug.aufnehmen(FALL, [str(quelle)], None, None):
        print("FEHLER: Das Musterdokument besteht die PII-Prüfung nicht.", file=sys.stderr)
        return 1

    # 2. Ermitteln, mit vorgefertigten Antworten und gestellter Uhr
    uhr = Uhr(datetime(2026, 11, 12, 8, 2, 0, tzinfo=timezone.utc))
    kern.uhr, kern.transport = uhr, httpx.MockTransport(antworten)
    zufall, stand = random.Random(7), [0.0]

    def stoppuhr() -> float:      # gestellte Antwortzeiten, bei jedem Lauf dieselben
        stand[0] += zufall.uniform(0.09, 0.42)
        return stand[0]
    kern.stoppuhr = stoppuhr
    hook({"hook_event_name": "UserPromptSubmit", "prompt": f"/ermittlung {FALL}"}, uhr.weiter(5))
    ids, ergebnisse = asyncio.run(ermitteln(uhr))

    # 3. Befunde schreiben, Rapport und Protokoll erzeugen
    plattform.text_schreiben(pfad / "befunde.json", json.dumps(befunde(ids, ergebnisse, uhr.weiter(240)), ensure_ascii=False, indent=2) + "\n")
    hook({"hook_event_name": "PostToolUse", "tool_name": "Write", "agent_type": "rapportfuehrer", "agent_id": "agent-rapportfuehrer",
          "tool_use_id": "toolu_muster_900", "tool_input": {"file_path": f"faelle/{FALL}/befunde.json", "content": "…"},
          "tool_response": {"type": "create"}, "duration_ms": 12}, uhr.weiter(1))
    os.environ["OSINT_TESTZEIT"] = uhr.weiter(45)
    print()
    code = rapport.main([FALL])
    code = protokoll.main([FALL]) or code
    print(f"\nMusterfall fertig: faelle/{FALL}/rapport/Abschlussrapport.html")
    return code


if __name__ == "__main__":
    sys.exit(main())
