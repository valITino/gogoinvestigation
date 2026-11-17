"""Web-Quellen: urlquery, Wayback Machine, Web-Check.

Hier gibt es passive und aktive Werkzeuge. Aktiv heisst: Die Zielseite wird
tatsächlich aufgerufen (von einem Dritten oder von eurer Web-Check-Instanz) und
kann das bemerken. Aktive Werkzeuge brauchen die Freigabe 'aktiv' in fall.json.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import Field

from .kern import (DOMAIN_RE, FREMD, Abbruch, Fall, Zweck, abfrage, einstellung, entschaerfen, html_text, nimm,
                   pruef_muster, pruef_url, saeubern, schluessel, werkzeug)

# --------------------------------------------------------------------------- urlquery

UQ = "https://api.urlquery.net/public/v1"


def _uq_kopf() -> dict:
    return {"x-apikey": schluessel("URLQUERY_API_KEY", "urlquery")}


def _uq_bericht(b: dict) -> dict:
    final = b.get("final") or {}
    # Die Alarme stehen je Sensorgruppe unter «detection» (ids, analyzer, urlquery). Ältere Antworten führten dafür stats.alert_count.
    erkennung = b.get("detection") if isinstance(b.get("detection"), dict) else {}
    alarme = {gruppe: len(liste) for gruppe, liste in erkennung.items() if isinstance(liste, list)} \
        or (b.get("stats") or {}).get("alert_count")
    return {**nimm(b, "report_id", "status", "date", "tags"),
            "url": (b.get("url") or {}).get("addr"),
            "ip": nimm(b.get("ip"), "addr", "asn", "as", "country_code"),
            "end_url": (final.get("url") or {}).get("addr"), "titel": saeubern(final.get("title"), 160),
            "alarme": alarme}


_UQ_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$")
UQ_ARTEN = ("auto", "domain", "ip", "url", "hash", "text")


def _uq_phrase(wert: str) -> str:
    return '"' + wert.replace("\\", "\\\\").replace('"', '\\"') + '"'


def uq_abfrage(suchtext: str, art: str = "auto") -> tuple[str, str]:
    """Baut die Abfrage in der Feldsyntax von urlquery (https://urlquery.net/help/search) und gibt (Abfrage, Art) zurück.
    Ohne Feldnamen sucht urlquery im Volltext der Berichte: Wer «example.com» sucht, bekommt jeden Bericht, in dem die
    Zeichenkette irgendwo vorkommt, und die neuesten zuerst. Am 16.11.2026 hatten die obersten Treffer mit der Domain
    nichts zu tun. Deshalb fragt das Werkzeug die Felder ab, in denen eine Domain, IP, URL steht."""
    q = suchtext.strip()
    if art == "auto":
        try:
            ipaddress.ip_address(q)
            art = "ip"
        except ValueError:
            if _UQ_HASH.match(q.lower()):
                art = "hash"
            elif "://" in q or "/" in q:
                art = "url"
            elif DOMAIN_RE.match(q.lower().rstrip(".")):
                art = "domain"
            else:
                art = "text"
    if art == "ip":
        return f"(ip.addr:{_uq_phrase(q)} OR http.ip.addr:{_uq_phrase(q)})", art
    if art == "hash":
        return q.lower(), art              # ein nackter Hash sucht laut Hilfe die üblichen Stellen (Antworten, Skripte, Dateien)
    if art == "url":
        adresse = _uq_phrase(q.split("://", 1)[-1])          # die Felder .addr führen Host, Pfad und Abfrage ohne Schema
        return f"(url.addr:{adresse} OR final.url.addr:{adresse} OR http.url.addr:{adresse})", art
    if art == "domain":
        d = _uq_phrase(q.lower().rstrip("."))
        felder = ("url.domain", "url.fqdn", "final.url.domain", "final.url.fqdn", "http.url.domain", "http.url.fqdn")
        return "(" + " OR ".join(f"{feld}:{d}" for feld in felder) + ")", art
    return q, "text"


@werkzeug
async def urlquery_suche(fall: Fall, zweck: Zweck,
                         suchtext: Annotated[str, Field(description="URL, Domain, IP oder Hash")],
                         limit: Annotated[int, Field(ge=1, le=50)] = 10,
                         art: Annotated[str, Field(description=(
                             "auto (Standard: wird am Suchtext erkannt) | domain | ip | url | hash | text. "
                             "'text' sucht im Volltext aller Berichte und liefert auch Berichte ohne Bezug zum Ziel."))] = "auto") -> dict:
    """urlquery: vorhandene Sandbox-Berichte zu einer URL, Domain oder IP suchen. Passiv.
    Gesucht wird in den Feldern der Berichte (eingereichte Adresse, Endadresse, nachgeladene Adressen), neueste
    zuerst. Vor jeder Einreichung zuerst hier nachsehen, ob es bereits einen Bericht gibt. Einen Treffer immer am
    Bericht bestätigen (urlquery_bericht): Die Suche sagt, dass der Wert im Bericht vorkommt, nicht in welcher Rolle."""
    q = entschaerfen(suchtext)
    if len(q) < 4:
        raise Abbruch("Suchtext zu kurz.")
    if art not in UQ_ARTEN:
        raise Abbruch(f"art muss eines sein von: {', '.join(UQ_ARTEN)}.")
    abfrage_text, art = uq_abfrage(q, art)
    a = await abfrage(fall, zweck, werkzeug="urlquery_suche", quelle="urlquery", ziel=q, ziel_typ="suchtext",
                      url=f"{UQ}/search/reports/", params={"query": abfrage_text, "limit": limit, "offset": 0},
                      kopf=_uq_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    berichte = (a.daten or {}).get("reports") or []
    befund = {"gesamt": (a.daten or {}).get("total_hits"), "anzahl": len(berichte), "art": art, "abfrage": abfrage_text,
              "berichte": [_uq_bericht(b) for b in berichte]}
    if art == "text":
        befund["hinweis"] = ("Volltextsuche: Die Berichte enthalten den Suchtext irgendwo, sie müssen das Ziel nicht betreffen. "
                             "Für eine Domain, IP, URL oder einen Hash die passende art wählen.")
    return a.als_dict(befund, hinweis=FREMD)


@werkzeug
async def urlquery_bericht(fall: Fall, zweck: Zweck, bericht_id: str) -> dict:
    """urlquery: einen Sandbox-Bericht abrufen. Zeigt, was die Seite beim Aufruf tat:
    Weiterleitungen, nachgeladene Dateien, erkannte Phishing-Kits, IDS-Alarme. Passiv."""
    bid = pruef_muster(bericht_id, r"[A-Za-z0-9-]{8,64}", "bericht_id")
    a = await abfrage(fall, zweck, werkzeug="urlquery_bericht", quelle="urlquery", ziel=bid,
                      ziel_typ="bericht", url=f"{UQ}/report/{bid}", kopf=_uq_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    b = a.daten or {}
    # Form des Berichts, gesehen am 16.11.2026: Alarme unter detection.{urlquery,analyzer,ids}, je Aufruf ein Eintrag unter
    # http (url, ip, request.method, response.status_code, response.data), Dateien unter artifacts.files, je Host eine
    # Zeile unter summary. Die älteren Namen (sensors, files) bleiben als zweite Wahl stehen.
    erkennung = b.get("detection") if isinstance(b.get("detection"), dict) else (b.get("sensors") or {})
    alarme = [{k: w for k, w in {
        "gruppe": gruppe, "sensor": s.get("sensor_name"), "alarm": saeubern(s.get("alert"), 80), "urteil": s.get("verdict"),
        "schwere": s.get("severity"), "ausloeser": saeubern(s.get("trigger"), 120),
        "kommentar": saeubern(s.get("comment"), 160)}.items() if w}
        for gruppe in ("urlquery", "analyzer", "ids") for s in (erkennung.get(gruppe) or [])[:15] if isinstance(s, dict)]
    aufrufe = [h for h in (b.get("http") or []) if isinstance(h, dict)]
    anfragen = []
    for h in aufrufe[:40]:
        antwort, daten = h.get("response") or {}, (h.get("response") or {}).get("data") or {}
        anfragen.append({k: w for k, w in {
            "url": (h.get("url") or {}).get("addr"), "ip": (h.get("ip") or {}).get("addr"),
            "methode": (h.get("request") or {}).get("method"), "status": antwort.get("status_code"),
            "art": h.get("resource_type"), "mime": daten.get("mime_type"), "sha256": daten.get("sha256")}.items() if w})
    artefakte = b.get("artifacts") if isinstance(b.get("artifacts"), dict) else {}
    dateien = [nimm(f, "sha256", "md5", "magic", "mime_type", "size", "filename", "url")
               for f in (artefakte.get("files") or b.get("files") or [])[:20] if isinstance(f, dict)]
    hosts = [{k: w for k, w in {
        "host": s.get("fqdn"), "ip": (s.get("ip") or {}).get("addr"), "domain_registriert": s.get("domain_registered"),
        "alarme": s.get("alert_count"), "anfragen": s.get("request_count"), "tags": s.get("tags"),
        "technik": [saeubern(f.get("name"), 40) for f in (s.get("fingerprints") or [])[:8] if isinstance(f, dict)]}.items()
        if w not in (None, "", [], {})} if isinstance(s, dict) else saeubern(str(s), 200)
        for s in (b.get("summary") or [])[:25]]
    return a.als_dict({**_uq_bericht(b), "alarme_anzahl": len(alarme), "alarme": alarme, "hosts": hosts,
                       "http_anfragen_anzahl": len(aufrufe), "http_anfragen": anfragen, "dateien": dateien}, hinweis=FREMD)


@werkzeug
async def urlquery_reputation(fall: Fall, zweck: Zweck, url: str) -> dict:
    """urlquery: Kurzurteil zu einer URL (z. B. phishing, malware, unbekannt). Passiv."""
    u = pruef_url(url)
    a = await abfrage(fall, zweck, werkzeug="urlquery_reputation", quelle="urlquery", ziel=u, ziel_typ="url",
                      url=f"{UQ}/reputation/check/", params={"query": u}, kopf=_uq_kopf())
    return a.als_dict(a.daten if a.ergebnis == "ok" else None)


@werkzeug
async def urlquery_einreichen(fall: Fall, zweck: Zweck, url: str) -> dict:
    """AKTIV. urlquery ruft die URL in seiner Sandbox auf. Der Betreiber der Zielseite sieht
    einen Besuch von urlquery und kann daraus schliessen, dass jemand die URL prüft. Nur nach
    ausdrücklicher Zustimmung des Sachbearbeiters. Eingereicht wird immer mit dem Zugriff «private»:
    Ein öffentlicher Bericht würde die Adresse für alle sichtbar machen. Ergebnis später mit urlquery_status holen."""
    u = pruef_url(url)
    a = await abfrage(fall, zweck, werkzeug="urlquery_einreichen", quelle="urlquery", ziel=u, ziel_typ="url",
                      url=f"{UQ}/submit/url", methode="POST", json_koerper={"url": u, "access": "private"},
                      kopf=_uq_kopf(), art="aktiv", freigabe="aktiv", cache_h=0)
    return a.als_dict(nimm(a.daten, "queue_id", "report_id", "status", "access") if a.ergebnis == "ok" else None)


@werkzeug
async def urlquery_status(fall: Fall, zweck: Zweck, queue_id: str) -> dict:
    """urlquery: Stand einer Einreichung abfragen. Liefert die report_id, sobald der Bericht fertig ist."""
    qid = pruef_muster(queue_id, r"[A-Za-z0-9-]{8,64}", "queue_id")
    a = await abfrage(fall, zweck, werkzeug="urlquery_status", quelle="urlquery", ziel=qid,
                      ziel_typ="einreichung", url=f"{UQ}/submit/status/{qid}", kopf=_uq_kopf(), cache_h=0)
    return a.als_dict(nimm(a.daten, "queue_id", "report_id", "status") if a.ergebnis == "ok" else None)


# --------------------------------------------------------------------------- Wayback Machine

WB = "https://web.archive.org"


def _cdx_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """Die CDX-Schnittstelle antwortet auch ohne Aufnahmen mit HTTP 200: mit einer leeren Liste oder nur der
    Kopfzeile. Das ist «kein Treffer», und so steht es dann auch im Protokoll."""
    if status != 200:
        return None
    if daten is None and (text or "").strip():
        return "fehler", "Die Wayback Machine hat kein lesbares JSON geliefert. Details in den Rohdaten."
    if not isinstance(daten, list) or len(daten) < 2:
        return "kein_treffer", None
    return None


@werkzeug
async def wayback_verlauf(fall: Fall, zweck: Zweck,
                          url: Annotated[str, Field(description="URL oder Domain")],
                          mit_unterseiten: Annotated[bool, Field(description="Auch alle Pfade unterhalb erfassen")] = False,
                          von: Annotated[str | None, Field(description="Ab JJJJ oder JJJJMMTT")] = None,
                          bis: Annotated[str | None, Field(description="Bis JJJJ oder JJJJMMTT")] = None,
                          limit: Annotated[int, Field(ge=1, le=300)] = 60) -> dict:
    """Wayback Machine: Wann wurde eine Seite archiviert, mit welchem Status und Inhaltshash?
    Zeigt, seit wann eine Seite existiert und wann sich ihr Inhalt änderte. Passiv."""
    ziel = entschaerfen(url)
    for wert in (von, bis):
        if wert:
            pruef_muster(wert, r"\d{4}(\d{2}){0,5}", "von/bis")
    a = await abfrage(fall, zweck, werkzeug="wayback_verlauf", quelle="Wayback Machine", ziel=ziel,
                      ziel_typ="url", url=f"{WB}/cdx/search/cdx",
                      params={"url": ziel, "output": "json", "limit": limit, "collapse": "digest",
                              "fl": "timestamp,original,statuscode,mimetype,digest,length",
                              "matchType": "prefix" if mit_unterseiten else None, "from": von, "to": bis},
                      deutung=_cdx_deutung)
    if a.ergebnis == "kein_treffer":
        return a.als_dict({"anzahl": 0, "aufnahmen": []})
    if a.ergebnis != "ok":
        return a.als_dict()
    kopf, *rest = a.daten
    aufnahmen = [dict(zip(kopf, z)) for z in rest]
    return a.als_dict({"anzahl": len(aufnahmen), "erste": aufnahmen[0]["timestamp"],
                       "letzte": aufnahmen[-1]["timestamp"], "aufnahmen": aufnahmen})


@werkzeug
async def wayback_abruf(fall: Fall, zweck: Zweck, url: str,
                        zeitstempel: Annotated[str, Field(description="JJJJMMTThhmmss aus wayback_verlauf")]) -> dict:
    """Wayback Machine: archivierten Stand einer Seite als Text lesen. Passiv, die Zielseite wird
    nicht kontaktiert. Das Original-HTML liegt in den Rohdaten."""
    u = pruef_url(url)
    ts = pruef_muster(zeitstempel, r"\d{8,14}", "zeitstempel")
    a = await abfrage(fall, zweck, werkzeug="wayback_abruf", quelle="Wayback Machine", ziel=f"{u} @ {ts}",
                      ziel_typ="url", url=f"{WB}/web/{ts}id_/{u}", endung="html", cache_h=720)
    if a.ergebnis != "ok":
        return a.als_dict()
    return a.als_dict({"zeitstempel": ts, "url": u, "text": html_text(a.text or "")}, hinweis=FREMD)


@werkzeug
async def wayback_sichern(fall: Fall, zweck: Zweck, url: str) -> dict:
    """AKTIV und ÖFFENTLICH. Lässt die Wayback Machine die Seite jetzt abrufen und dauerhaft
    öffentlich archivieren. Der Betreiber sieht einen Besuch von archive.org, und die Aufnahme
    ist für alle auffindbar. Zur Beweissicherung, nur nach ausdrücklicher Zustimmung."""
    u = pruef_url(url)
    a = await abfrage(fall, zweck, werkzeug="wayback_sichern", quelle="Wayback Machine", ziel=u,
                      ziel_typ="url", url=f"{WB}/save/{u}", endung="html", art="aktiv", freigabe="aktiv",
                      cache_h=0, zeitlimit=120)
    return a.als_dict({"gesichert": a.ergebnis == "ok",
                       "hinweis": "Aufnahme mit wayback_verlauf prüfen."} if a.ergebnis == "ok" else None)


# --------------------------------------------------------------------------- Web-Check (selbst betrieben)

# Prüfungen, die nur Dritte oder das DNS befragen. Der Webserver des Ziels wird nicht kontaktiert.
WEBCHECK_PASSIV = ("archives", "block-lists", "breaches", "caa-records", "dns", "dnssec", "get-ip", "rank",
                   "shodan", "subdomains", "threats", "txt-records", "whois")
# Prüfungen, bei denen eure Web-Check-Instanz (oder ein von ihr beauftragter Dienst) das Ziel aufruft.
WEBCHECK_AKTIV = ("carbon", "cookies", "dns-server", "firewall", "headers", "hsts", "http-security",
                  "linked-pages", "location", "mail-config", "mixed-content", "ports", "quality", "redirects",
                  "robots-txt", "screenshot", "security-txt", "sitemap", "social-presence", "social-tags", "ssl",
                  "status", "tech-stack", "tls-connection", "tls-labs", "trace-route", "trackers")


_WC_NICHT_EINGERICHTET = re.compile(r"requires|api[_ -]?key|not (?:set|configured)|missing", re.I)
_WC_OHNE_ANTWORT = re.compile(r"no \w+ sources? returned|returned no data|unavailable|timed? ?out", re.I)


def _wc_teilquellen(daten: dict) -> tuple[list[str], dict[str, str]]:
    """Manche Prüfungen befragen mehrere Stellen und antworten je Stelle (threats: safeBrowsing, urlHaus, phishTank,
    cloudmersive, netApi). Gibt zurück, welche geantwortet haben und welche nicht, mit dem Grund. Eine Stelle, die
    nur «error» oder «skipped» meldet, hat nicht geantwortet."""
    mit, ohne = [], {}
    for name, wert in daten.items():
        if isinstance(wert, dict) and (wert.get("error") or wert.get("skipped")) and set(wert) <= {"error", "skipped", "retryable"}:
            ohne[name] = saeubern(str(wert.get("error") or wert.get("skipped")), 160)
        else:
            mit.append(name)
    return (mit, ohne) if ohne else (list(daten), {})


def _webcheck_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """Web-Check meldet eine gescheiterte Prüfung mit HTTP 200 und dem Feld «error», eine ausgelassene mit dem
    Feld «skipped» (gesehen am 16.11.2026: «Error fetching Wayback data: fetch failed», «No TXT records for this
    host», «Shodan requires SHODAN_API_KEY to be set»). Ohne diese Deutung gälte beides als Treffer.
    «error» ist ein Fehlschlag: nicht geprüft. «skipped» heisst in der Regel, dass es nichts gab (kein Treffer).
    Fehlt der Instanz dafür ein Schlüssel oder hat keine der befragten Stellen geantwortet («No threat sources
    returned data»), ist auch das ein Fehlschlag: Aus «niemand hat geantwortet» wird kein «nichts gefunden»."""
    if isinstance(daten, dict):
        if daten.get("error"):
            return "fehler", (f"Web-Check konnte diese Prüfung nicht ausführen: «{saeubern(str(daten['error']), 200)}». "
                              "Das Ziel ist damit nicht geprüft. Häufige Ursache: Die Instanz erreicht den Dienst nicht, "
                              "den die Prüfung befragt (Netz, DNS, Proxy des Containers).")
        if daten.get("skipped"):
            grund = saeubern(str(daten["skipped"]), 200)
            if _WC_NICHT_EINGERICHTET.search(grund):
                return "fehler", (f"Web-Check hat diese Prüfung ausgelassen: «{grund}». Sie ist in der Instanz nicht "
                                  "eingerichtet. Das Ziel ist damit nicht geprüft.")
            if _WC_OHNE_ANTWORT.search(grund):
                return "fehler", (f"Web-Check hat diese Prüfung ausgelassen: «{grund}». Die befragten Stellen haben nicht "
                                  "geantwortet. Das Ziel ist damit nicht geprüft.")
            return "kein_treffer", None
        if daten and not _wc_teilquellen(daten)[0]:
            return "fehler", ("Web-Check: Keine der befragten Stellen hat geantwortet ("
                              + "; ".join(f"{name}: {grund}" for name, grund in _wc_teilquellen(daten)[1].items())[:300]
                              + "). Das Ziel ist damit nicht geprüft.")
    if status == 200 and daten is None:
        return "fehler", "Web-Check hat kein lesbares JSON geliefert. Details in den Rohdaten."
    if status >= 500:
        return "fehler", f"Web-Check meldet einen Fehler bei dieser Prüfung (HTTP {status}). Details in den Rohdaten."
    return None


async def _webcheck(fall: str, zweck: str, ziel: str, pruefung: str, aktiv: bool) -> dict:
    z = entschaerfen(ziel)
    host = urlsplit(z if "://" in z else f"https://{z}").hostname or ""
    pruef_url(f"https://{host}")
    basis = einstellung("WEBCHECK_URL", "http://127.0.0.1:3000").rstrip("/")
    a = await abfrage(fall, zweck, werkzeug="webcheck_aktiv" if aktiv else "webcheck_passiv",
                      quelle="Web-Check", ziel=f"{z} ({pruefung})", ziel_typ="domain",
                      url=f"{basis}/api/{pruefung}", params={"url": z},
                      art="aktiv" if aktiv else "passiv", freigabe="aktiv" if aktiv else None,
                      cache_h=0 if aktiv else 24, zeitlimit=90, deutung=_webcheck_deutung,
                      hilfe="Läuft Web-Check? Start: 'docker compose up -d webcheck'. Adresse: WEBCHECK_URL in .env.")
    if a.ergebnis != "ok":
        grund = a.daten.get("skipped") if isinstance(a.daten, dict) else None
        return a.als_dict(**({"grund": f"Web-Check: «{saeubern(str(grund), 200)}»", "hinweis": FREMD} if grund and a.ergebnis == "kein_treffer" else {}))
    befund = a.daten
    if isinstance(befund, dict) and pruefung == "screenshot":
        befund = {"hinweis": "Bildschirmfoto liegt base64-kodiert in den Rohdaten."}
    ohne = _wc_teilquellen(befund)[1] if isinstance(befund, dict) else {}
    if ohne:        # ein Teil der befragten Stellen hat nicht geantwortet: Das Ergebnis gilt nur für die übrigen
        return a.als_dict(befund, hinweis=FREMD, teilweise_nicht_geprueft=ohne)
    return a.als_dict(befund, hinweis=FREMD)


@werkzeug
async def webcheck_passiv(fall: Fall, zweck: Zweck,
                          ziel: Annotated[str, Field(description="Domain oder URL")],
                          pruefung: Annotated[str, Field(description=" | ".join(WEBCHECK_PASSIV))]) -> dict:
    """Web-Check, passive Prüfungen: DNS, WHOIS/RDAP, Zertifikatstransparenz-Subdomains,
    Sperrlisten, Bedrohungslisten, bekannte Datenlecks, Rang, Archivstände. Der Webserver des
    Ziels wird nicht aufgerufen. Läuft über eure eigene Web-Check-Instanz."""
    if pruefung not in WEBCHECK_PASSIV:
        raise Abbruch(f"'{pruefung}' ist keine passive Prüfung. Passiv: {', '.join(WEBCHECK_PASSIV)}. "
                      "Alles andere geht nur über webcheck_aktiv und braucht die Freigabe 'aktiv'.")
    return await _webcheck(fall, zweck, ziel, pruefung, aktiv=False)


@werkzeug
async def webcheck_aktiv(fall: Fall, zweck: Zweck,
                         ziel: Annotated[str, Field(description="Domain oder URL")],
                         pruefung: Annotated[str, Field(description=" | ".join(WEBCHECK_AKTIV))]) -> dict:
    """AKTIV. Web-Check ruft das Ziel direkt auf (Header, TLS, Ports, Cookies, Technologien,
    Bildschirmfoto usw.). Der Betreiber sieht die IP eurer Web-Check-Instanz in seinen Logs.
    Nur nach ausdrücklicher Zustimmung des Sachbearbeiters und über eine Infrastruktur,
    die nicht auf eure Organisation zurückführt."""
    if pruefung not in WEBCHECK_AKTIV:
        raise Abbruch(f"Unbekannte aktive Prüfung '{pruefung}'. Möglich: {', '.join(WEBCHECK_AKTIV)}.")
    return await _webcheck(fall, zweck, ziel, pruefung, aktiv=True)
