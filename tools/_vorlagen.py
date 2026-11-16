"""Antworten der Quellen in echter Form, mit erfundenem Inhalt. Grundlage der Selbsttests ohne Netz.

Feldnamen, Verschachtelung und Typen stammen aus den Antworten der echten Dienste, gesehen am 16.11.2026 über
das Gateway (Fallakte SELBSTTEST, tools/pruefen.py --live und Einzelaufrufe je Werkzeug). Die Inhalte sind
ersetzt: Adressen aus den Dokumentationsnetzen (203.0.113.0/24, 198.51.100.0/24), Domains unter example.org,
erfundene Namen. Es steht hier kein Opfername, kein Konto und kein Beitrag eines echten Dritten.

Wozu: Die Fehler der Live-Prüfung lagen nie in der Rechnung, sondern in der Form: ein Feld heisst anders, ein
Zähler steht woanders, ein Fehlschlag kommt mit HTTP 200. Ein Selbsttest, der gegen eine frei erfundene Form
läuft, findet das nicht. Ändert ein Dienst seine Antwort, wird die Vorlage hier nachgeführt und der Selbsttest
zeigt, was im Gateway nachzuziehen ist.

Für die Blockchain-Quellen gibt es die erfundene Kette in tools/_kryptowelt.py.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx

KONTO = "sachbearbeiter@behoerde.example"      # was ransomware.live im Feld «client» wiederholt: die E-Mail des eigenen Kontos
ONION = "musterlockerabcdefghijklmnopqrstuvwxyz234567abcdefghijklmn.onion"


def _json(inhalt: object, status: int = 200, kopf: dict | None = None) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(inhalt).encode(), headers={"content-type": "application/json", **(kopf or {})})


# --------------------------------------------------------------------------- ransomware.live, API PRO

def _rl_opfer(nr: int) -> dict:
    """Ein Eintrag aus /victims/ und /victims/recent."""
    return {"id": f"TXVzdGVyb3BmZXIg{nr:04d}", "discovered": f"2026-10-{1 + nr % 28:02d}T08:39:11.427184+00:00",
            "website": f"firma{nr}.example.org", "country": "CH", "activity": "Manufacturing",
            "description": f"Erfundene Beschreibung zu Musteropfer {nr}.", "post_url": f"http://{ONION}/post/{nr}",
            "ransom": None, "data_size": "50GB" if nr % 7 == 0 else None,
            "screenshot": f"https://images.ransomware.live/victims/{nr:032x}.png",
            "infostealer": ({"update": "2026-10-09T14:36:21.059496", "employees": 0, "users": 14, "thirdparties": 0,
                             "employees_url": 0, "users_url": 4, "last_employee_compromised": None,
                             "last_user_compromised": None, "infostealer_stats": {}} if nr % 9 == 0 else ""),
            "press": None, "permalink": f"https://www.ransomware.live/id/TXVzdGVyb3BmZXIg{nr:04d}",
            "attackdate": f"2026-10-{1 + nr % 28:02d}T08:38:51.646848+00:00", "victim": f"Musteropfer {nr} AG",
            "group": "musterlocker"}


def rl_opfer_liste(anzahl: int, land: str | None = None, gruppe: str | None = None) -> dict:
    """GET /victims/?country=… oder ?group=… . «count» nennt alle Einträge, die Liste enthält alle."""
    return {"client": KONTO, "filters": {"group": gruppe, "sector": None, "country": land, "year": None, "month": None,
                                         "date": "discovered"},
            "count": anzahl, "victims": [_rl_opfer(n) for n in range(anzahl)]}


def rl_aktuell(anzahl: int = 100) -> dict:
    """GET /victims/recent"""
    return {"client": KONTO, "count": anzahl, "order": "discovered", "victims": [_rl_opfer(n) for n in range(anzahl)]}


def rl_suche(stichwort: str) -> dict:
    """GET /victims/search?q=… . Die Treffer tragen andere Feldnamen als die Listen: post_title, group_name, published."""
    return {"client": KONTO, "query": stichwort, "group": None, "sector": None, "country": None, "order": "discovered",
            "count": 2, "victims": [
                {"id": f"U3VjaGUg{n}", "discovered": "2026-09-14 11:02:17.000000", "website": f"{stichwort}{n}.example.org",
                 "country": "", "activity": "Not Found", "description": "", "post_url": "", "ransom": None,
                 "data_size": None, "screenshot": "", "infostealer": "", "press": None,
                 "permalink": f"https://www.ransomware.live/id/U3VjaGUg{n}", "published": "2026-09-14 10:58:00.000000",
                 "post_title": f"{stichwort} Muster {n}", "group_name": "musterlocker"} for n in (1, 2)]}


def rl_gruppe(gruppe: str = "musterlocker", seiten: int = 38) -> dict:
    """GET /groups/{gruppe}"""
    return {"client": KONTO, "group": gruppe, "added_date": "2022-06-29",
            "description": "Erfundene Gruppe für den Selbsttest. Betreibt eine Leak-Seite und veröffentlicht dort Namen.",
            "victims": 2016, "firstseen": "2021-12-26T00:00:00+00:00", "lastseen": "2025-12-05T10:16:00+00:00",
            "ttps": [], "vulnerabilities": [],
            "tools": {"CredentialTheft": ["Mimikatz", "LaZagne"], "Exfiltration": ["Rclone"], "RMM-Tools": ["AnyDesk"]},
            "locations": [{"fqdn": f"seite{n:02d}{ONION[7:]}", "title": "Title", "slug": f"http://seite{n:02d}{ONION[7:]}",
                           "type": "DLS", "available": False, "captcha": False, "seized": n < 4} for n in range(seiten)],
            "has_negotiations": True, "negotiation_count": 45, "has_ransomnote": True, "ransomnotes_count": 5,
            "victims_hidden": False, "url": f"https://www.ransomware.live/group/{gruppe}"}


def rl_iocs(gruppe: str = "musterlocker") -> dict:
    """GET /iocs/{gruppe}"""
    return {"client": KONTO, "group": gruppe, "filter_type": None, "ioc_types": ["ip", "md5"],
            "iocs": {"ip": ["203.0.113.10", "203.0.113.11"], "md5": ["f954f24e6eb85ef1b64e315491dad816"]}}


# --------------------------------------------------------------------------- VirusTotal

def vt_beziehungen(domain: str = "example.org", geliefert: int = 2, gesamt: int = 49) -> dict:
    """GET /domains/{domain}/resolutions. «meta.count» nennt alle, «data» höchstens limit."""
    return {"data": [{"id": f"203.0.113.{n}{domain}", "type": "resolution",
                      "links": {"self": f"https://www.virustotal.com/api/v3/resolutions/203.0.113.{n}{domain}"},
                      "attributes": {"ip_address": f"203.0.113.{n}", "date": 1794646560 - n * 86400, "host_name": domain,
                                     "ip_address_last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 62,
                                                                        "harmless": 30, "timeout": 0},
                                     "host_name_last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 32,
                                                                       "harmless": 60, "timeout": 0},
                                     "resolver": "VirusTotal"}} for n in range(1, geliefert + 1)],
            "meta": {"count": gesamt, "cursor": "Cl4KEQoEZGF0ZRIJ"},
            "links": {"self": f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit={geliefert}",
                      "next": f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit={geliefert}&cursor=Cl4KEQoEZGF0ZRIJ"}}


# --------------------------------------------------------------------------- Shodan

SHODAN_OHNE_MITGLIEDSCHAFT = {"error": "Requires membership or higher to access"}      # GET /dns/domain/{d}, HTTP 403, kostenloses Konto


# --------------------------------------------------------------------------- Web-Check (eigene Instanz)

# Eine Prüfung, die scheitert, antwortet mit HTTP 200 und «error», eine ausgelassene mit «skipped». So gesehen am
# 16.11.2026 an einer Instanz, deren Container die befragten Dienste nicht erreichte.
WEBCHECK = {
    "archives": (200, {"error": "Error fetching Wayback data: fetch failed"}),
    "breaches": (200, {"error": "Have I Been Pwned failed: fetch failed"}),
    "rank": (200, {"error": "Tranco rank lookup failed: fetch failed"}),
    "subdomains": (200, {"error": "Subdomain lookup is temporarily unavailable for this domain", "retryable": True}),
    "dnssec": (500, {"error": "fetch failed"}),
    "shodan": (200, {"skipped": "Shodan requires SHODAN_API_KEY to be set"}),
    "threats": (200, {"skipped": "No threat sources returned data for this host"}),
    "txt-records": (200, {"skipped": "No TXT records for this host"}),
    "whois": (200, {"skipped": "No WHOIS data available for this domain"}),
    "caa-records": (200, {"domain": "example.org", "records": []}),
    "get-ip": (200, {"ip": "203.0.113.7", "family": 4}),
    "dns": (200, {"A": ["203.0.113.7", "203.0.113.8"], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": [], "SOA": None,
                  "SRV": [], "PTR": []}),
    "block-lists": (200, {"blocklists": [{"server": "AdGuard", "serverIp": "176.103.130.130", "isBlocked": False},
                                         {"server": "CloudFlare", "serverIp": "1.1.1.1", "isBlocked": False},
                                         {"server": "Quad9", "serverIp": "9.9.9.9", "isBlocked": True}]}),
}


# --------------------------------------------------------------------------- Telegram (Web-Vorschau)

def telegram_vorschau(kanal: str = "musterkanal", beitraege: int = 2) -> str:
    """GET t.me/s/{kanal} bei einem Kanal mit Web-Vorschau."""
    teile = [f"<!DOCTYPE html><html><head><title>Musterkanal – Telegram</title>"
             f'<meta property="og:title" content="Musterkanal"></head><body><section class="tgme_channel_history js-message_history">']
    for n in range(1, beitraege + 1):
        teile.append(
            '<div class="tgme_widget_message_wrap js-widget_message_wrap">'
            f'<div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="{kanal}/{440 + n}" data-view="eyJjIjotMTAw">'
            '<div class="tgme_widget_message_bubble">'
            f'<div class="tgme_widget_message_text js-message_text" dir="auto">Erfundener Beitrag {n}.<br/>Zweite Zeile mit '
            f'<a href="https://example.org/meldung/{n}" target="_blank" rel="noopener">Verweis</a></div>'
            f'<div class="tgme_widget_message_footer compact js-message_footer"><a class="tgme_widget_message_date" href="https://t.me/{kanal}/{440 + n}">'
            f'<time datetime="2026-05-14T16:0{n}:31+00:00" class="time">16:0{n}</time></a></div></div></div></div>')
    return "".join(teile) + "</section></body></html>"


def telegram_kanalseite(kanal: str = "ohnevorschau") -> str:
    """Was t.me/s/{kanal} liefert, wenn der Kanal keine Web-Vorschau hat: Telegram leitet auf t.me/{kanal} um, HTTP 200."""
    return ('<!DOCTYPE html><html><head><title>Telegram: View @' + kanal + '</title>'
            '<meta property="og:title" content="Muster Leak Monitor">'
            '<meta property="og:description" content="Erfundene Beschreibung des Kanals &amp; Kontaktangabe">'
            '</head><body><div class="tgme_page_wrap"><div class="tgme_body_wrap"><div class="tgme_page">'
            '<div class="tgme_page_title" dir="auto"> <span dir="auto">Muster Leak Monitor</span> </div>'
            '<div class="tgme_page_extra">27 470 subscribers</div>'
            '<div class="tgme_page_description" dir="auto">Erfundene Beschreibung des Kanals</div>'
            f'<div class="tgme_page_action"><a class="tgme_action_button_new shine" href="tg://resolve?domain={kanal}">View in Telegram</a></div>'
            f'<div class="tgme_page_context_link_wrap"><a class="tgme_page_context_link" href="/s/{kanal}">Preview channel</a></div>'
            '</div></div></div></body></html>')


# --------------------------------------------------------------------------- Gegenstelle für die Selbsttests

def antwort(anfrage: httpx.Request) -> httpx.Response | None:
    """Antwortet wie der echte Dienst, in der Form der Vorlagen. None: Diese Gegenstelle kennt die Adresse nicht."""
    host, pfad = anfrage.url.host, anfrage.url.path
    frage = {k: v[0] for k, v in parse_qs(anfrage.url.query.decode()).items()}
    if host == "api-pro.ransomware.live":
        if anfrage.headers.get("X-API-KEY") is None:
            return _json({"error": "Missing API key"}, 401)
        if pfad == "/victims/recent":
            return _json(rl_aktuell())
        if pfad == "/victims/search":
            return _json(rl_suche(frage.get("q", "")))
        if pfad == "/victims/":
            return _json(rl_opfer_liste(2016 if frage.get("group") else 264, frage.get("country"), frage.get("group")))
        if pfad.startswith("/groups/"):
            return _json(rl_gruppe(pfad.rsplit("/", 1)[1]))
        if pfad.startswith("/iocs/"):
            return _json(rl_iocs(pfad.rsplit("/", 1)[1]))
    if host == "www.virustotal.com" and pfad.endswith("/resolutions"):
        return _json(vt_beziehungen(pfad.split("/")[-2], int(frage.get("limit", 2))))
    if host == "api.shodan.io" and pfad.startswith("/dns/domain/"):
        return _json(SHODAN_OHNE_MITGLIEDSCHAFT, 403)
    if host == "127.0.0.1" and pfad.startswith("/api/"):
        status, inhalt = WEBCHECK.get(pfad.rsplit("/", 1)[1], (404, {"error": "Not found"}))
        return _json(inhalt, status)
    if host == "t.me" and pfad.startswith("/s/"):
        kanal = pfad.rsplit("/", 1)[1]
        return httpx.Response(200, text=telegram_kanalseite(kanal) if kanal == "ohnevorschau" else telegram_vorschau(kanal),
                              headers={"content-type": "text/html; charset=utf-8"})
    if host == "web.archive.org" and pfad == "/cdx/search/cdx":
        return _json([] if "ohne-aufnahme" in frage.get("url", "") else
                     [["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
                      ["20240115093000", "https://example.org/", "200", "text/html", "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ", "1256"]])
    return None
