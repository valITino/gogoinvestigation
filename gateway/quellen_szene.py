"""Szene-Quellen: ransomware.live, Ahmia-Sperrliste, Telegram, 4chan, Mastodon.

Die Abfragen sind passiv. Personenbezogene Kontoabfragen (Mastodon-Konto,
Telegram-Entität) brauchen zusätzlich die Freigabe 'personenbezug' in fall.json.
Alle Inhalte aus diesen Quellen sind Fremdtext und werden gesäubert und gekürzt.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Annotated, Any
from urllib.parse import quote, urlsplit

from pydantic import Field

from .kern import (FREMD, Abbruch, Fall, Zweck, abfrage, einstellung, entschaerfen, html_text, nimm,
                   pruef_domain, pruef_muster, saeubern, schluessel, werkzeug)


def kappen(obj: Any, tiefe: int = 4, eintraege: int = 30, laenge: int = 300) -> Any:
    """Kürzt Antworten mit unbekanntem Aufbau auf ein für den Agenten verdauliches Mass."""
    if isinstance(obj, str):
        return saeubern(obj, laenge)
    if tiefe <= 0:
        return "…"
    if isinstance(obj, list):
        return [kappen(x, tiefe - 1, eintraege, laenge) for x in obj[:eintraege]]
    if isinstance(obj, dict):
        return {k: kappen(v, tiefe - 1, eintraege, laenge) for k, v in list(obj.items())[:60]
                if v not in (None, "", [], {})}
    return obj


# --------------------------------------------------------------------------- ransomware.live

RL_PRO = "https://api-pro.ransomware.live"
RL_V2 = "https://api.ransomware.live/v2"


def _rl() -> tuple[str, dict, bool]:
    key = einstellung("RANSOMWARE_LIVE_API_KEY")
    if key:
        return RL_PRO, {"X-API-KEY": key}, True
    if einstellung("RANSOMWARE_LIVE_V2") == "1":
        return RL_V2, {}, False
    raise Abbruch(
        "ransomware.live: RANSOMWARE_LIVE_API_KEY fehlt in .env (kostenloser PRO-Schlüssel unter "
        "my.ransomware.live). Die schlüssellose API v2 ist laut Anbieter nur für private Nutzung "
        "gedacht. Wer sie nutzen darf, setzt RANSOMWARE_LIVE_V2=1.")


def _opfer(daten: Any) -> list[dict]:
    if isinstance(daten, dict):
        daten = daten.get("victims") or daten.get("results") or daten.get("data") or []
    liste = []
    for v in (daten or [])[:60]:
        if not isinstance(v, dict):
            continue
        liste.append({k: w for k, w in {
            "opfer": saeubern(v.get("victim") or v.get("post_title"), 120),
            "gruppe": v.get("group") or v.get("group_name"),
            "entdeckt": v.get("discovered"),
            "angriff": v.get("attackdate") or v.get("published"),
            "land": v.get("country"),
            "branche": v.get("activity") or v.get("sector"),
            "domain": v.get("domain") or v.get("website"),
            "beschreibung": saeubern(v.get("description"), 240),
            "fundstelle": v.get("claim_url") or v.get("post_url") or v.get("url"),
        }.items() if w})
    return liste


@werkzeug
async def ransomware_opfer(fall: Fall, zweck: Zweck,
                           stichwort: Annotated[str | None, Field(description="Name oder Domain der Organisation")] = None,
                           gruppe: Annotated[str | None, Field(description="Name der Ransomware-Gruppe")] = None,
                           land: Annotated[str | None, Field(description="ISO-Ländercode, z. B. CH")] = None) -> dict:
    """ransomware.live: Wurde eine Organisation auf einer Leak-Seite genannt? Oder: Welche Opfer
    führt eine Gruppe, welche gibt es in einem Land? Genau eines der drei Kriterien angeben."""
    gesetzt = [x for x in (stichwort, gruppe, land) if x]
    if len(gesetzt) != 1:
        raise Abbruch("Genau eines angeben: stichwort, gruppe oder land.")
    basis, kopf, pro = _rl()
    if stichwort:
        s = " ".join(stichwort.split())
        if len(s) < 3:
            raise Abbruch("Stichwort zu kurz.")
        url, params, ziel, typ = ((f"{basis}/victims/search", {"q": s}) if pro
                                  else (f"{basis}/searchvictims/{quote(s, safe='')}", None)) + (s, "stichwort")
    elif gruppe:
        g = pruef_muster(gruppe.lower(), r"[a-z0-9 ._-]{2,40}", "gruppe")
        url, params, ziel, typ = ((f"{basis}/victims/", {"group": g}) if pro
                                  else (f"{basis}/groupvictims/{g}", None)) + (g, "gruppe")
    else:
        cc = pruef_muster((land or "").upper(), r"[A-Z]{2}", "land")
        url, params, ziel, typ = ((f"{basis}/victims/", {"country": cc}) if pro
                                  else (f"{basis}/countryvictims/{cc}", None)) + (cc, "land")
    a = await abfrage(fall, zweck, werkzeug="ransomware_opfer", quelle="ransomware.live", ziel=ziel,
                      ziel_typ=typ, url=url, params=params, kopf=kopf, cache_h=6)
    if a.ergebnis != "ok":
        return a.als_dict()
    opfer = _opfer(a.daten)
    return a.als_dict({"anzahl": len(opfer), "opfer": opfer}, hinweis=FREMD)


@werkzeug
async def ransomware_gruppe(fall: Fall, zweck: Zweck, gruppe: str) -> dict:
    """ransomware.live: Steckbrief einer Ransomware-Gruppe mit Beschreibung und bekannten
    Leak-Seiten (Onion-Adressen, Erreichbarkeit, letzter Stand)."""
    g = pruef_muster(gruppe.lower(), r"[a-z0-9 ._-]{2,40}", "gruppe")
    basis, kopf, pro = _rl()
    a = await abfrage(fall, zweck, werkzeug="ransomware_gruppe", quelle="ransomware.live", ziel=g,
                      ziel_typ="gruppe", url=f"{basis}/groups/{g}" if pro else f"{basis}/group/{g}",
                      kopf=kopf, cache_h=6)
    if a.ergebnis != "ok":
        return a.als_dict()
    d = a.daten[0] if isinstance(a.daten, list) and a.daten else a.daten
    if not isinstance(d, dict):
        return a.als_dict(ergebnis="kein_treffer")
    d = d.get("group") if isinstance(d.get("group"), dict) else d
    seiten = [nimm(s, "fqdn", "slug", "title", "available", "updated", "lastscrape", "type")
              for s in (d.get("locations") or [])[:25] if isinstance(s, dict)]
    return a.als_dict({"name": d.get("name") or g, "beschreibung": saeubern(d.get("description"), 900),
                       "leak_seiten": seiten, "weiteres": kappen(nimm(d, "profile", "meta", "stats"), 2, 10, 200)},
                      hinweis=FREMD)


@werkzeug
async def ransomware_iocs(fall: Fall, zweck: Zweck, gruppe: str) -> dict:
    """ransomware.live: veröffentlichte Indikatoren (IPs, Domains, Hashes, Wallets, E-Mails) einer
    Gruppe. Zum Abgleich mit den Indikatoren des Falls. Braucht den PRO-Schlüssel."""
    g = pruef_muster(gruppe.lower(), r"[a-z0-9 ._-]{2,40}", "gruppe")
    basis, kopf, pro = _rl()
    if not pro:
        raise Abbruch("ransomware_iocs gibt es nur mit RANSOMWARE_LIVE_API_KEY (API PRO).")
    a = await abfrage(fall, zweck, werkzeug="ransomware_iocs", quelle="ransomware.live", ziel=g,
                      ziel_typ="gruppe", url=f"{basis}/iocs/{g}", kopf=kopf, cache_h=6)
    return a.als_dict(kappen(a.daten, 4, 150, 200) if a.ergebnis == "ok" else None, hinweis=FREMD)


@werkzeug
async def ransomware_aktuell(fall: Fall, zweck: Zweck) -> dict:
    """ransomware.live: die zuletzt auf Leak-Seiten veröffentlichten Opfer, gruppenübergreifend."""
    basis, kopf, pro = _rl()
    a = await abfrage(fall, zweck, werkzeug="ransomware_aktuell", quelle="ransomware.live", ziel="neueste Opfer",
                      ziel_typ="uebersicht", url=f"{basis}/victims/recent" if pro else f"{basis}/recentvictims",
                      kopf=kopf, cache_h=1)
    if a.ergebnis != "ok":
        return a.als_dict()
    opfer = _opfer(a.daten)
    return a.als_dict({"anzahl": len(opfer), "opfer": opfer}, hinweis=FREMD)


# --------------------------------------------------------------------------- Ahmia-Sperrliste

@werkzeug
async def onion_sperrliste(fall: Fall, zweck: Zweck,
                           onion_adresse: Annotated[str, Field(description="Onion-Adresse oder -URL")]) -> dict:
    """Prüft, ob eine Onion-Adresse auf der Sperrliste von Ahmia steht (dort landen vor allem
    Seiten mit Missbrauchsdarstellungen). PFLICHT vor jedem Öffnen einer Onion-Seite. Steht die
    Adresse auf der Liste: nicht öffnen, dem Sachbearbeiter melden. Die Adresse verlässt das Haus
    nicht: Die Liste wird geladen und lokal verglichen."""
    roh = entschaerfen(onion_adresse).lower()
    host = urlsplit(roh if "://" in roh else f"http://{roh}").hostname or ""
    if not re.fullmatch(r"([a-z2-7]{16}|[a-z2-7]{56})\.onion", host):
        raise Abbruch(f"'{onion_adresse}' ist keine gültige Onion-Adresse.")
    a = await abfrage(fall, zweck, werkzeug="onion_sperrliste", quelle="Ahmia", ziel=host, ziel_typ="onion",
                      url="https://ahmia.fi/blacklist/banned/", endung="txt", cache_h=24)
    if a.ergebnis != "ok":
        return a.als_dict()
    liste = set(re.findall(r"\b[a-f0-9]{32}\b", a.text or ""))
    if not liste:
        return a.als_dict(ergebnis="fehler",
                          fehler="Sperrliste nicht im erwarteten Format. Onion-Seite vorsichtshalber NICHT öffnen.")
    varianten = [host, f"http://{host}", f"http://{host}/"]
    gesperrt = any(hashlib.md5(v.encode()).hexdigest() in liste for v in varianten)
    return a.als_dict({"onion": host, "gesperrt": gesperrt, "eintraege_in_liste": len(liste),
                       "anweisung": "NICHT öffnen. Dem Sachbearbeiter melden." if gesperrt
                       else "Nicht auf der Sperrliste. Das ist keine Unbedenklichkeitserklärung."})


# --------------------------------------------------------------------------- Telegram

class _Kanalleser(HTMLParser):
    """Liest die öffentliche Web-Vorschau eines Telegram-Kanals (t.me/s/<kanal>)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.beitraege: list[dict] = []
        self._tiefe = 0          # Verschachtelung innerhalb des Textblocks
        self._text: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        klasse = a.get("class") or ""
        if a.get("data-post"):
            self.beitraege.append({"beitrag": a["data-post"], "zeit": None, "text": "", "links": []})
        if not self.beitraege:
            return
        if self._text is not None:
            if tag == "div":
                self._tiefe += 1
            elif tag == "br":
                self._text.append("\n")
            elif tag == "a" and a.get("href", "").startswith("http"):
                self.beitraege[-1]["links"].append(a["href"])
        elif tag == "div" and "tgme_widget_message_text" in klasse:
            self._text, self._tiefe = [], 1
        elif tag == "time" and a.get("datetime") and not self.beitraege[-1]["zeit"]:
            self.beitraege[-1]["zeit"] = a["datetime"]

    def handle_endtag(self, tag: str) -> None:
        if self._text is not None and tag == "div":
            self._tiefe -= 1
            if self._tiefe == 0:
                self.beitraege[-1]["text"] = saeubern("".join(self._text), 700)
                self._text = None

    def handle_data(self, data: str) -> None:
        if self._text is not None:
            self._text.append(data)


@werkzeug
async def telegram_kanal(fall: Fall, zweck: Zweck,
                         kanal: Annotated[str, Field(description="Öffentlicher Kanalname ohne @, z. B. breachdetect")] = "breachdetect",
                         stichwort: Annotated[str | None, Field(description="Nur Beiträge mit diesem Wort (lokal gefiltert)")] = None,
                         vor: Annotated[int | None, Field(description="Ältere Beiträge vor dieser Beitragsnummer")] = None) -> dict:
    """Telegram: die neuesten Beiträge eines öffentlichen Kanals über dessen Web-Vorschau lesen,
    ohne Telegram-Konto. Standard ist 'breachdetect', der Kanal hinter dem Telegram Breach Monitor
    (Meldungen zu neuen Datenlecks). Das Stichwort wird lokal gefiltert und nicht übermittelt."""
    k = pruef_muster(kanal.lstrip("@"), r"[A-Za-z][A-Za-z0-9_]{3,31}", "kanal")
    a = await abfrage(fall, zweck, werkzeug="telegram_kanal", quelle="Telegram (Web-Vorschau)",
                      ziel=f"@{k}" + (f" / Stichwort '{stichwort}' lokal gefiltert" if stichwort else ""),
                      ziel_typ="kanal", url=f"https://t.me/s/{k}", params={"before": vor}, endung="html",
                      cache_h=0.5)
    if a.ergebnis != "ok":
        return a.als_dict()
    leser = _Kanalleser()
    leser.feed(a.text or "")
    beitraege = [b for b in leser.beitraege if b["text"] or b["links"]]
    if not beitraege:
        return a.als_dict({"anzahl": 0, "beitraege": []}, ergebnis="kein_treffer",
                          hinweis="Kanal existiert nicht, ist privat oder hat keine Web-Vorschau.")
    if stichwort:
        s = stichwort.lower()
        beitraege = [b for b in beitraege if s in b["text"].lower() or any(s in l.lower() for l in b["links"])]
    for b in beitraege:
        b["links"] = b["links"][:8]
    return a.als_dict({"kanal": k, "anzahl": len(beitraege), "beitraege": beitraege[-40:]}, hinweis=FREMD)


def _rapid(host: str) -> dict:
    return {"x-rapidapi-key": schluessel("RAPIDAPI_KEY", "RapidAPI (Telegram)"), "x-rapidapi-host": host}


@werkzeug
async def telegram_kanalinfo(fall: Fall, zweck: Zweck, kanal: str) -> dict:
    """Telegram: Stammdaten eines öffentlichen Kanals (Titel, Beschreibung, Abonnentenzahl) über
    den Drittanbieter 'Telegram Channel' auf RapidAPI. Der Anbieter sieht den Kanalnamen."""
    k = pruef_muster(kanal.lstrip("@"), r"[A-Za-z][A-Za-z0-9_]{3,31}", "kanal")
    host = "telegram-channel.p.rapidapi.com"
    a = await abfrage(fall, zweck, werkzeug="telegram_kanalinfo", quelle="RapidAPI Telegram Channel",
                      ziel=f"@{k}", ziel_typ="kanal", url=f"https://{host}/channel/info",
                      params={"channel": k}, kopf=_rapid(host))
    return a.als_dict(kappen(a.daten) if a.ergebnis == "ok" else None, hinweis=FREMD)


@werkzeug
async def telegram_entitaet(fall: Fall, zweck: Zweck,
                            name: Annotated[str, Field(description="Benutzer-, Gruppen- oder Kanalname ohne @")]) -> dict:
    """PERSONENBEZUG. Telegram: öffentliche Angaben zu einem Benutzer, einer Gruppe oder einem Kanal
    über den Drittanbieter 'Telegram Scraper API' auf RapidAPI. Der Anbieter sieht den Namen.
    Braucht die Freigabe 'personenbezug'. Suche nach Telefonnummern ist bewusst nicht eingebaut."""
    n = pruef_muster(name.lstrip("@"), r"[A-Za-z][A-Za-z0-9_]{3,31}", "name")
    host = "telegram-scraper-api.p.rapidapi.com"
    a = await abfrage(fall, zweck, werkzeug="telegram_entitaet", quelle="RapidAPI Telegram Scraper",
                      ziel=f"@{n}", ziel_typ="konto", url=f"https://{host}/entity/fetch",
                      params={"peer": n}, kopf=_rapid(host), freigabe="personenbezug")
    return a.als_dict(kappen(a.daten) if a.ergebnis == "ok" else None, hinweis=FREMD)


@werkzeug
async def telegram_suche(fall: Fall, zweck: Zweck, suchtext: str,
                         limit: Annotated[int, Field(ge=1, le=20)] = 10) -> dict:
    """PERSONENBEZUG. Telegram: globale Suche nach Benutzern, Gruppen und Kanälen über den
    Drittanbieter 'Telegram Scraper API' auf RapidAPI. Braucht die Freigabe 'personenbezug'."""
    q = " ".join(suchtext.split())
    if len(q) < 3:
        raise Abbruch("Suchtext zu kurz.")
    host = "telegram-scraper-api.p.rapidapi.com"
    a = await abfrage(fall, zweck, werkzeug="telegram_suche", quelle="RapidAPI Telegram Scraper", ziel=q,
                      ziel_typ="suchtext", url=f"https://{host}/entity/search", params={"q": q, "limit": limit},
                      kopf=_rapid(host), freigabe="personenbezug")
    return a.als_dict(kappen(a.daten) if a.ergebnis == "ok" else None, hinweis=FREMD)


# --------------------------------------------------------------------------- 4chan

def _zeit(sekunden: Any) -> str | None:
    if not isinstance(sekunden, (int, float)):
        return None
    return datetime.fromtimestamp(sekunden, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@werkzeug
async def chan_katalog(fall: Fall, zweck: Zweck,
                       board: Annotated[str, Field(description="Board-Kürzel ohne Schrägstriche, z. B. g, pol, biz")],
                       stichwort: Annotated[str | None, Field(description="Nur Threads mit diesem Wort in Betreff oder Text")] = None) -> dict:
    """4chan: laufende Threads eines Boards über die offizielle Lese-API. Das Stichwort wird lokal
    gefiltert und nicht an 4chan übermittelt. Ohne Stichwort: die meistdiskutierten Threads."""
    b = pruef_muster(board.strip("/").lower(), r"[a-z0-9]{1,6}", "board")
    a = await abfrage(fall, zweck, werkzeug="chan_katalog", quelle="4chan",
                      ziel=f"/{b}/" + (f" / Stichwort '{stichwort}' lokal gefiltert" if stichwort else ""),
                      ziel_typ="board", url=f"https://a.4cdn.org/{b}/catalog.json", cache_h=0.25)
    if a.ergebnis != "ok":
        return a.als_dict()
    threads = [t for seite in (a.daten or []) for t in seite.get("threads") or []]
    if stichwort:
        s = stichwort.lower()
        threads = [t for t in threads if s in f"{t.get('sub', '')} {t.get('com', '')}".lower()]
    else:
        threads = sorted(threads, key=lambda t: t.get("replies", 0), reverse=True)
    liste = [{"nummer": t.get("no"), "zeit": _zeit(t.get("time")), "betreff": saeubern(html_text(t.get("sub") or ""), 120),
              "text": saeubern(html_text(t.get("com") or ""), 300), "antworten": t.get("replies"),
              "url": f"https://boards.4chan.org/{b}/thread/{t.get('no')}"} for t in threads[:40]]
    return a.als_dict({"board": b, "anzahl": len(threads), "threads": liste}, hinweis=FREMD)


@werkzeug
async def chan_thread(fall: Fall, zweck: Zweck, board: str,
                      nummer: Annotated[int, Field(ge=1, description="Thread-Nummer aus chan_katalog")]) -> dict:
    """4chan: einen Thread mit allen Beiträgen sichern und lesen. Threads verschwinden nach kurzer
    Zeit, die Rohdaten bleiben in der Fallakte erhalten."""
    b = pruef_muster(board.strip("/").lower(), r"[a-z0-9]{1,6}", "board")
    a = await abfrage(fall, zweck, werkzeug="chan_thread", quelle="4chan", ziel=f"/{b}/thread/{nummer}",
                      ziel_typ="thread", url=f"https://a.4cdn.org/{b}/thread/{nummer}.json", cache_h=0.25)
    if a.ergebnis != "ok":
        return a.als_dict()
    posts = (a.daten or {}).get("posts") or []
    liste = [{k: w for k, w in {
        "nr": p.get("no"), "zeit": _zeit(p.get("time")), "name": saeubern(p.get("name"), 40),
        "tripcode": p.get("trip"), "poster_id": p.get("id"), "land": p.get("country"),
        "text": saeubern(html_text(p.get("com") or ""), 600),
        "datei": f"{p.get('filename')}{p.get('ext')}" if p.get("filename") else None,
        "datei_md5_b64": p.get("md5")}.items() if w} for p in posts[:150]]
    return a.als_dict({"board": b, "thread": nummer, "beitraege_gesamt": len(posts), "beitraege": liste},
                      hinweis=FREMD)


# --------------------------------------------------------------------------- Mastodon

def _konto(k: dict) -> dict:
    return {**nimm(k, "acct", "display_name", "url", "created_at", "followers_count", "following_count",
                   "statuses_count", "last_status_at", "bot", "group", "locked", "discoverable"),
            "bio": saeubern(html_text(k.get("note") or ""), 400),
            "profilfelder": [{"name": saeubern(f.get("name"), 40), "wert": saeubern(html_text(f.get("value") or ""), 160),
                              "verifiziert": bool(f.get("verified_at"))} for f in (k.get("fields") or [])[:8]]}


@werkzeug
async def mastodon_instanz(fall: Fall, zweck: Zweck,
                           instanz: Annotated[str, Field(description="Domain der Instanz, z. B. mastodon.social")]) -> dict:
    """Mastodon/Fediverse: öffentliche Angaben zu einer Instanz (Betreiber, Kontakt, Version,
    Registrierung, Grösse). Funktioniert auch bei Instanzen, die sich nicht auffindbar machen."""
    d = pruef_domain(instanz)
    a = await abfrage(fall, zweck, werkzeug="mastodon_instanz", quelle="Mastodon", ziel=d, ziel_typ="instanz",
                      url=f"https://{d}/api/v2/instance")
    if a.ergebnis == "kein_treffer":            # ältere Server kennen nur v1
        a = await abfrage(fall, zweck, werkzeug="mastodon_instanz", quelle="Mastodon", ziel=d,
                          ziel_typ="instanz", url=f"https://{d}/api/v1/instance")
    if a.ergebnis != "ok" or not isinstance(a.daten, dict):
        return a.als_dict()
    i = a.daten
    kontakt = i.get("contact") or {}
    admin = kontakt.get("account") or i.get("contact_account") or {}
    return a.als_dict({**nimm(i, "domain", "uri", "title", "version", "languages"),
                       "beschreibung": saeubern(html_text(i.get("description") or i.get("short_description") or ""), 400),
                       "kontakt_email": kontakt.get("email") or i.get("email"),
                       "registrierung": i.get("registrations"),
                       "nutzung": i.get("usage") or i.get("stats"),
                       "admin": _konto(admin) if admin else None}, hinweis=FREMD)


@werkzeug
async def mastodon_konto(fall: Fall, zweck: Zweck,
                         benutzername: Annotated[str, Field(description="Name ohne @, oder name@instanz für ein bestimmtes Konto")],
                         instanz: Annotated[str, Field(description="Instanz, über die gesucht wird")] = "mastodon.social") -> dict:
    """PERSONENBEZUG. Mastodon/Fediverse: öffentliche Konten zu einem Benutzernamen finden, mit
    Erstelldatum, Aktivität, Bio und Profilfeldern. Braucht die Freigabe 'personenbezug'."""
    name = benutzername.strip().lstrip("@")
    pruef_muster(name, r"[A-Za-z0-9_.-]{2,40}(@[A-Za-z0-9.-]{4,80})?", "benutzername")
    d = pruef_domain(instanz)
    if "@" in name:
        a = await abfrage(fall, zweck, werkzeug="mastodon_konto", quelle="Mastodon", ziel=f"@{name}",
                          ziel_typ="konto", url=f"https://{d}/api/v1/accounts/lookup", params={"acct": name},
                          freigabe="personenbezug")
        return a.als_dict({"konten": [_konto(a.daten)]} if a.ergebnis == "ok" else None, hinweis=FREMD)
    a = await abfrage(fall, zweck, werkzeug="mastodon_konto", quelle="Mastodon", ziel=f"@{name} via {d}",
                      ziel_typ="konto", url=f"https://{d}/api/v2/search",
                      params={"q": name, "type": "accounts", "limit": 20}, freigabe="personenbezug")
    if a.ergebnis != "ok":
        return a.als_dict()
    konten = (a.daten or {}).get("accounts") or []
    genau = [k for k in konten if (k.get("username") or "").lower() == name.lower()]
    return a.als_dict({"gesucht": name, "genaue_treffer": len(genau), "konten": [_konto(k) for k in genau],
                       "aehnliche": [k.get("acct") for k in konten if k not in genau][:15]}, hinweis=FREMD)
