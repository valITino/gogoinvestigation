"""Web-Quellen: urlquery, Wayback Machine, Web-Check.

Hier gibt es passive und aktive Werkzeuge. Aktiv heisst: Die Zielseite wird
tatsächlich aufgerufen (von einem Dritten oder von eurer Web-Check-Instanz) und
kann das bemerken. Aktive Werkzeuge brauchen die Freigabe 'aktiv' in fall.json.
"""
from __future__ import annotations

from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field

from .kern import (FREMD, Abbruch, Fall, Zweck, abfrage, einstellung, entschaerfen, html_text, nimm,
                   pruef_muster, pruef_url, saeubern, schluessel, werkzeug)

# --------------------------------------------------------------------------- urlquery

UQ = "https://api.urlquery.net/public/v1"


def _uq_kopf() -> dict:
    return {"x-apikey": schluessel("URLQUERY_API_KEY", "urlquery")}


def _uq_bericht(b: dict) -> dict:
    final = b.get("final") or {}
    return {**nimm(b, "report_id", "status", "date", "tags"),
            "url": (b.get("url") or {}).get("addr"),
            "ip": nimm(b.get("ip"), "addr", "asn", "as", "country_code"),
            "end_url": (final.get("url") or {}).get("addr"), "titel": saeubern(final.get("title"), 160),
            "alarme": (b.get("stats") or {}).get("alert_count")}


@werkzeug
async def urlquery_suche(fall: Fall, zweck: Zweck,
                         suchtext: Annotated[str, Field(description="URL, Domain, IP oder Hash")],
                         limit: Annotated[int, Field(ge=1, le=50)] = 10) -> dict:
    """urlquery: vorhandene Sandbox-Berichte zu einer URL, Domain oder IP suchen. Passiv.
    Vor jeder Einreichung zuerst hier nachsehen, ob es bereits einen Bericht gibt."""
    q = entschaerfen(suchtext)
    if len(q) < 4:
        raise Abbruch("Suchtext zu kurz.")
    a = await abfrage(fall, zweck, werkzeug="urlquery_suche", quelle="urlquery", ziel=q, ziel_typ="suchtext",
                      url=f"{UQ}/search/reports/", params={"query": q, "limit": limit, "offset": 0},
                      kopf=_uq_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    berichte = (a.daten or {}).get("reports") or []
    return a.als_dict({"gesamt": (a.daten or {}).get("total_hits"), "anzahl": len(berichte),
                       "berichte": [_uq_bericht(b) for b in berichte]})


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
    sensoren = b.get("sensors") or {}
    alarme = [{"sensor": s.get("sensor_name"), "urteil": s.get("verdict"), "ausloeser": saeubern(s.get("trigger"), 120),
               "kommentar": saeubern(s.get("comment"), 160)}
              for gruppe in ("urlquery", "analyzer", "ids") for s in (sensoren.get(gruppe) or [])[:15]]
    anfragen = [{"url": ((h.get("url") or {}).get("addr")), "ip": ((h.get("ip") or {}).get("addr"))}
                for h in (b.get("http") or [])[:40]]
    dateien = [nimm(f, "sha256", "magic", "size") for f in (b.get("files") or [])[:20]]
    return a.als_dict({**_uq_bericht(b), "zusammenfassung": (b.get("summary") or [])[:25],
                       "alarme": alarme, "http_anfragen": anfragen, "dateien": dateien}, hinweis=FREMD)


@werkzeug
async def urlquery_reputation(fall: Fall, zweck: Zweck, url: str) -> dict:
    """urlquery: Kurzurteil zu einer URL (z. B. phishing, malware, unbekannt). Passiv."""
    u = pruef_url(url)
    a = await abfrage(fall, zweck, werkzeug="urlquery_reputation", quelle="urlquery", ziel=u, ziel_typ="url",
                      url=f"{UQ}/reputation/check/", params={"query": u}, kopf=_uq_kopf())
    return a.als_dict(a.daten if a.ergebnis == "ok" else None)


@werkzeug
async def urlquery_einreichen(fall: Fall, zweck: Zweck, url: str,
                              sichtbarkeit: Annotated[str, Field(description=(
                                  "private (nur ihr), protected (eingeschränkt) oder public "
                                  "(für alle sichtbar). Standard: private."))] = "private") -> dict:
    """AKTIV. urlquery ruft die URL in seiner Sandbox auf. Der Betreiber der Zielseite sieht
    einen Besuch von urlquery und kann daraus schliessen, dass jemand die URL prüft. Nur nach
    ausdrücklicher Zustimmung des Sachbearbeiters. Ergebnis später mit urlquery_status holen."""
    u = pruef_url(url)
    if sichtbarkeit not in ("private", "protected", "public"):
        raise Abbruch("sichtbarkeit muss private, protected oder public sein.")
    a = await abfrage(fall, zweck, werkzeug="urlquery_einreichen", quelle="urlquery", ziel=u, ziel_typ="url",
                      url=f"{UQ}/submit/url", methode="POST", json_koerper={"url": u, "access": sichtbarkeit},
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
                              "matchType": "prefix" if mit_unterseiten else None, "from": von, "to": bis})
    if a.ergebnis != "ok":
        return a.als_dict()
    zeilen = a.daten or []
    if not zeilen or len(zeilen) < 2:
        return a.als_dict({"anzahl": 0, "aufnahmen": []}, ergebnis="kein_treffer")
    kopf, *rest = zeilen
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


async def _webcheck(fall: str, zweck: str, ziel: str, pruefung: str, aktiv: bool) -> dict:
    z = entschaerfen(ziel)
    host = urlsplit(z if "://" in z else f"https://{z}").hostname or ""
    pruef_url(f"https://{host}")
    basis = einstellung("WEBCHECK_URL", "http://127.0.0.1:3000").rstrip("/")
    a = await abfrage(fall, zweck, werkzeug="webcheck_aktiv" if aktiv else "webcheck_passiv",
                      quelle="Web-Check", ziel=f"{z} ({pruefung})", ziel_typ="domain",
                      url=f"{basis}/api/{pruefung}", params={"url": z},
                      art="aktiv" if aktiv else "passiv", freigabe="aktiv" if aktiv else None,
                      cache_h=0 if aktiv else 24, zeitlimit=90,
                      hilfe="Läuft Web-Check? Start: 'docker compose up -d webcheck'. Adresse: WEBCHECK_URL in .env.")
    befund = a.daten if a.ergebnis == "ok" else None
    if isinstance(befund, dict) and pruefung == "screenshot":
        befund = {"hinweis": "Bildschirmfoto liegt base64-kodiert in den Rohdaten."}
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
