"""Einordnung einer IP-Adresse: Netz und Inhaber, Art des Anschlusses, und ob die Adresse der Ausgang eines
Anonymisierungsdienstes ist (VPN, Proxy, Tor, Residential Proxy).

Warum das zählt: Hinter der IP eines Privatanschlusses kann ein Unbeteiligter stehen, über dessen Gerät ein
Residential Proxy läuft. Ein Editionsbegehren an den Zugangsanbieter träfe dann den Falschen. Bevor eine IP einem
Anschluss zugeschrieben wird, gehört deshalb geklärt, was die Quellen über sie wissen, und was nicht.

Ein Werkzeug, mehrere Stimmen. ``ip_einordnung`` befragt, was eingerichtet ist:

    proxycheck.io   Erkennungen (VPN, Proxy, Tor, kompromittiert), Betreiber des Dienstes, zuerst und zuletzt gesehen,
                    Löschung aus der Liste. Mit Schlüssel. Fenster der Historie: 60 Tage.
    ipapi.is        zweite Stimme: Art des Anschlusses (Zugangsanbieter, Rechenzentrum, Firma) und eigene Merkmale
                    für VPN, Proxy, Tor. Mit Schlüssel. Ohne Schlüssel liefert der Dienst die Merkmale nicht.
    RIPEstat        was die Register sagen: Präfix, AS und Inhaber, Meldestelle für Missbrauch. Mit Tatzeit: wer das
                    Netz damals ankündigte, und wem es zugeteilt war (nur für die RIPE-Datenbank). Ohne Schlüssel.
    AbuseIPDB       Nutzungsart des Anschlusses, Tor-Ausgang ja oder nein. Mit Schlüssel.
    Spur            falls ein Token eingetragen ist. Nie gegen den echten Dienst geprüft.

Das Ergebnis nennt für den Anonymisierungsdienst genau einen von drei Werten:

    ja              Mindestens eine Quelle führt die Adresse. Sind die Quellen uneinig, steht das dabei.
    kein Hinweis    Mindestens eine Quelle hat geantwortet, keine führt die Adresse. Das ist kein «nein».
    nicht geprüft   Keine Quelle eingerichtet, oder keine hat geantwortet.

Jede Teilabfrage steht einzeln im Protokoll (Werkzeug ``ip_abruf``), die Auswertung als eigener Eintrag mit
Verweis darauf. Die Auskunft gilt für den Abfragezeitpunkt. Die Tat lag früher: Liegt die Tatzeit im Fenster der
Historie von proxycheck.io, zählt die Historie für diesen Zeitraum, sonst sagt das Ergebnis, dass es nur den
heutigen Stand kennt. Eine Person benennt das Werkzeug nie: Eine IP-Adresse identifiziert niemanden.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from pydantic import Field

from . import kern
from .akte import IP_VORBEHALT as VORBEHALT, IP_WERTE as WERTE
from .kern import FREMD, Abbruch, Antwort, Fall, Vorgang, Zweck, einstellung, pruef_ip, saeubern, werkzeug

ABRUF = "ip_abruf"
QUELLEN = ("proxycheck", "ipapi", "ripestat", "abuseipdb", "spur")
PC_FENSTER = 60                 # Tage, die proxycheck.io zurückreicht (Parameter days, höchstens 60)
RESIDENTIAL_NETZ = ("Residential", "Wireless")
_ART_IPAPI = {"isp": "Zugangsanbieter", "hosting": "Rechenzentrum", "business": "Firma", "education": "Bildungseinrichtung",
              "government": "Behörde", "banking": "Bank"}
_ART_PC = {"Residential": "Privatanschluss", "Wireless": "Mobilfunk", "Business": "Firma", "Hosting": "Rechenzentrum"}


# --------------------------------------------------------------------------- Zeit

def zeit_lesen(text: str | None) -> datetime | None:
    """Tatzeit als UTC. Erlaubt: 2026-10-02, 2026-10-02T14:10:00Z, mit Zeitzone. Ohne Zeitzone gilt UTC."""
    if not text or not str(text).strip():
        return None
    t = str(text).strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(t + "T12:00:00+00:00" if len(t) == 10 else t)
    except ValueError as e:
        raise Abbruch(f"'{text}' ist keine lesbare Zeit. Format: 2026-10-02 oder 2026-10-02T14:10:00Z.") from e
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(d: datetime | None) -> str | None:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _zeit(wert: Any) -> datetime | None:
    """Zeitangabe einer Quelle (ISO-Text oder Unix-Millisekunden) als UTC, oder None."""
    if isinstance(wert, (int, float)) and wert > 0:
        return datetime.fromtimestamp(wert / 1000 if wert > 1e11 else wert, timezone.utc)
    if isinstance(wert, str) and wert.strip():
        try:
            d = datetime.fromisoformat(wert.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    return None


def _stimme(quelle: str, a: Antwort | None = None, grund: str = "") -> dict:
    """Was eine Quelle zur Adresse sagt, in einheitlicher Form. ``fuehrt``: True, False, oder None (äussert sich nicht dazu)."""
    return {"quelle": quelle, "beleg": a.id if a else None, "geantwortet": bool(a and a.ergebnis == "ok"),
            **({"grund": grund or (a.fehler if a else "") or "keine verwertbare Antwort"} if not (a and a.ergebnis == "ok") else {}),
            "fuehrt": None, "arten": [], "netz": {}}


# --------------------------------------------------------------------------- proxycheck.io

def _pc_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """proxycheck.io nennt den Ausgang im Feld «status»: ok, warning (Antwort mit Hinweis), denied, error."""
    if isinstance(daten, dict) and daten.get("status") in ("denied", "error"):
        return "fehler", f"proxycheck.io lehnt die Abfrage ab: «{saeubern(str(daten.get('message') or daten['status']), 200)}»"
    if status == 200 and not isinstance(daten, dict):
        return "fehler", "proxycheck.io hat kein lesbares JSON geliefert. Details in den Rohdaten."
    return None


def pc_lesen(ip: str, daten: dict, s: dict, tat: datetime | None, im_fenster: bool) -> dict:
    """Liest die Antwort von proxycheck.io (Schnittstelle v3, Form gesehen am 16.11.2026). Die Erkennungen stehen unter
    detections, das Risiko ebenfalls dort. detection_history nennt, ob und wann der Eintrag gelöscht wurde oder wird."""
    e = daten.get(ip) if isinstance(daten.get(ip), dict) else {}
    netz, erk = e.get("network") or {}, e.get("detections") or {}
    hist, betreiber = e.get("detection_history") or {}, e.get("operator") if isinstance(e.get("operator"), dict) else None
    ort = e.get("location") or {}
    arten = [name for feld, name in (("tor", "Tor"), ("vpn", "VPN"), ("proxy", "Proxy"), ("compromised", "kompromittiertes Gerät"))
             if erk.get(feld) is True]
    aktuell = bool(arten) or betreiber is not None or erk.get("anonymous") is True
    # Ein gelöschter Eintrag zählt: Die Quelle hat die Adresse geführt, und die Tat kann in diese Zeit fallen.
    frueher = hist.get("delisted") is True
    fuehrt = aktuell or frueher
    geloescht = _zeit(hist.get("delist_datetime") or hist.get("date"))
    angebote = [saeubern(str(x), 40) for x in (betreiber or {}).get("services") or []]
    s.update(fuehrt=fuehrt, arten=arten, anschlussart=_ART_PC.get(netz.get("type"), netz.get("type")),
             netz={k: w for k, w in {"as": netz.get("asn"), "praefix": netz.get("range"), "betreiber": saeubern(netz.get("provider"), 80),
                                     "organisation": saeubern(netz.get("organisation"), 80), "hostname": saeubern(netz.get("hostname"), 100),
                                     "land": ort.get("country_code"), "ort": saeubern(ort.get("city_name"), 60)}.items() if w})
    if betreiber:
        s["dienst"] = saeubern(betreiber.get("name"), 60)
        s["angebote"] = angebote
        weitere = [saeubern(str(x), 60) for x in betreiber.get("additional_operators") or []]
        if weitere:
            s["weitere_dienste"] = weitere
    if fuehrt:
        s["zuerst"], s["zuletzt"] = _iso(_zeit(erk.get("first_seen"))), _iso(_zeit(erk.get("last_seen")))
        s["risiko"], s["sicherheit_der_quelle"] = erk.get("risk"), erk.get("confidence")
        # Ein Privat- oder Mobilfunkanschluss, den die Quelle als Proxy führt: Der Inhaber ist voraussichtlich unbeteiligt.
        s["residential"] = netz.get("type") in RESIDENTIAL_NETZ
        s["heute"] = "geführt" if aktuell else "gelöscht"
        if frueher:
            s["geloescht_am"] = _iso(geloescht)
        elif geloescht:
            s["austrag_geplant"] = _iso(geloescht)
        if "residential_proxies" in angebote and not s["residential"]:
            s.setdefault("hinweise", []).append("Die Quelle nennt für diese Adresse Angebote von Residential Proxies, führt das Netz selbst aber "
                                                f"als «{netz.get('type') or 'ohne Angabe'}».")
        if aktuell and not arten and not betreiber:
            s.setdefault("hinweise", []).append("Die Quelle führt die Adresse als anonym, nennt aber weder die Art noch einen Dienst.")
        if aktuell and frueher:
            s.setdefault("hinweise", []).append(f"Die Quelle nennt zugleich eine Löschung des Eintrags am {_iso(geloescht)}. Beides steht so in der Antwort.")
        if frueher and not aktuell:
            s.setdefault("hinweise", []).append(f"Die Quelle hat die Adresse früher geführt und den Eintrag am {_iso(geloescht)} gelöscht. "
                                                "Art und Dienst nennt sie für gelöschte Einträge nur, wenn die Tatzeit im Fenster der Historie liegt.")
    angriffe = e.get("attack_history") if isinstance(e.get("attack_history"), dict) else {}
    if angriffe:
        s["angriffsmeldungen"] = {saeubern(str(k), 40): v for k, v in list(angriffe.items())[:12] if isinstance(v, int)}
    if tat:
        if not im_fenster:
            s["zur_tatzeit"] = (f"Die Tatzeit liegt vor dem Fenster der Historie ({PC_FENSTER} Tage). Die Auskunft gilt für heute.")
        else:
            erst, letzt = _zeit(erk.get("first_seen")), _zeit(erk.get("last_seen"))
            if fuehrt and erst and letzt and erst <= tat <= letzt:
                s["zur_tatzeit"], s["tatzeit_gedeckt"] = (f"Die Tatzeit liegt zwischen der ersten ({_iso(erst)}) und der letzten Sichtung "
                                                           f"({_iso(letzt)}): Die Adresse war zur Tatzeit geführt."), True
            elif fuehrt and erst and tat < erst:
                s["zur_tatzeit"] = f"Die Quelle hat die Adresse erst nach der Tatzeit zuerst gesehen ({_iso(erst)}). Für die Tatzeit sagt sie nichts."
            elif fuehrt:
                s["zur_tatzeit"] = "Die Quelle führt die Adresse im abgefragten Zeitraum, nennt aber keine Sichtung, die die Tatzeit einschliesst."
            else:
                s["zur_tatzeit"], s["tatzeit_gedeckt"] = (f"Im abgefragten Zeitraum, der die Tatzeit einschliesst, führt die Quelle die Adresse nicht, "
                                                           "auch nicht als inzwischen gelöschten Eintrag."), True
    return s


async def _proxycheck(v: Vorgang, ip: str, tat: datetime | None) -> dict:
    key = einstellung("PROXYCHECK_API_KEY")
    if not key:
        return _stimme("proxycheck.io", grund="PROXYCHECK_API_KEY fehlt")
    # tag=0: Die Quelle soll die Abfrage nicht in ihrem Erkennungslog des Kontos ablegen. Ohne das bliebe eine Adresse mit
    # Treffer dort 180 Tage lang stehen. Mit Tatzeit im Fenster: days und history, damit auch gelöschte Einträge erscheinen.
    params: dict[str, Any] = {"key": key, "tag": "0"}
    im_fenster = False
    if tat:
        tage = math.ceil((kern.uhr() - tat).total_seconds() / 86400) + 1
        if 0 < tage <= PC_FENSTER:
            params.update(days=tage, history=1)
            im_fenster = True
    a = await v.hole("proxycheck.io", ip, "ip", f"https://proxycheck.io/v3/{ip}", schritt="Erkennungen und Betreiber", params=params,
                     geheim=("key",), deutung=_pc_deutung, cache_h=1)
    s = _stimme("proxycheck.io", a)
    if a.ergebnis != "ok" or not isinstance(a.daten, dict) or not isinstance(a.daten.get(ip), dict):
        if a.ergebnis == "ok":
            s.update(geantwortet=False, grund="Die Antwort enthält keinen Eintrag zur Adresse.")
        return s
    if a.daten.get("status") == "warning" and a.daten.get("message"):
        s.setdefault("hinweise", []).append(f"Hinweis der Quelle: «{saeubern(str(a.daten['message']), 160)}»")
    return pc_lesen(ip, a.daten, s, tat, im_fenster)


# --------------------------------------------------------------------------- ipapi.is

def ipapi_lesen(daten: dict, s: dict) -> dict:
    """Liest die Antwort von ipapi.is (Form gesehen am 16.11.2026). Die Merkmale is_* gibt es nur mit Schlüssel. Die Kontaktperson
    der Meldestelle (abuse.name, address, phone) wird nicht weitergegeben: Sie ist eine Person, keine Angabe zum Netz."""
    firma, asn = daten.get("company") if isinstance(daten.get("company"), dict) else {}, daten.get("asn") if isinstance(daten.get("asn"), dict) else {}
    ort, vpn = daten.get("location") or {}, daten.get("vpn") if isinstance(daten.get("vpn"), dict) else {}
    ausgang = daten.get("egress_service") if isinstance(daten.get("egress_service"), dict) else {}
    meldestelle = (daten.get("abuse") or {}).get("email") if isinstance(daten.get("abuse"), dict) else None
    s["netz"] = {k: w for k, w in {"as": f"AS{asn['asn']}" if asn.get("asn") else None, "praefix": asn.get("route"),
                                   "betreiber": saeubern(asn.get("org"), 80), "organisation": saeubern(firma.get("name"), 80),
                                   "netzname": saeubern(firma.get("netname"), 60), "bereich": firma.get("network"),
                                   "land": ort.get("country_code") or str(asn.get("country") or "").upper() or None,
                                   "ort": saeubern(ort.get("city"), 60), "register": daten.get("rir"),
                                   "meldestelle": saeubern(meldestelle, 100)}.items() if w}
    if "is_vpn" not in daten and "is_proxy" not in daten:       # gekürzte Antwort ohne Schlüssel: nur Netzangaben als Text
        s["netz"] = {k: saeubern(str(daten[q]), 100) for k, q in (("organisation", "company"), ("betreiber", "asn"), ("land", "country")) if daten.get(q)}
        s["hinweise"] = ["Ohne Schlüssel liefert ipapi.is keine Merkmale für VPN, Proxy und Tor. Die Quelle äussert sich dazu nicht."]
        return s
    arten = [name for feld, name in (("is_tor", "Tor"), ("is_vpn", "VPN"), ("is_proxy", "Proxy")) if daten.get(feld)]
    if vpn and "VPN" not in arten:
        arten.append("VPN")
    if ausgang:
        arten.append("Relay- oder Gateway-Dienst")
    art = firma.get("type") or asn.get("type")
    s.update(fuehrt=bool(arten), arten=arten, anschlussart=_ART_IPAPI.get(art, art))
    if vpn or ausgang:
        s["dienst"] = saeubern(vpn.get("service") or ausgang.get("provider") or ausgang.get("type"), 60)
        s["zuletzt"] = _iso(_zeit(vpn.get("last_seen_str") or vpn.get("last_seen")))
    if s["fuehrt"]:
        s["heute"] = "geführt"
        s["residential"] = art == "isp" or daten.get("is_mobile") is True      # ein Anschluss beim Zugangsanbieter, der als Proxy geführt ist
    merkmale = [text for feld, text in (("is_datacenter", "Rechenzentrum"), ("is_mobile", "Mobilfunk"), ("is_satellite", "Satellit"),
                                        ("is_anycast", "Anycast: dieselbe Adresse an vielen Standorten"),
                                        ("is_abuser", "als missbräuchlich aufgefallen")) if daten.get(feld) is True]
    if daten.get("is_crawler"):
        merkmale.append(f"Suchmaschinen-Bot ({saeubern(str(daten['is_crawler']), 40)})")
    if merkmale:
        s["merkmale"] = merkmale
    return s


def _ipapi_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """ipapi.is kann einen Fehler mit HTTP 200 melden (Feld error)."""
    if status == 200 and isinstance(daten, dict) and daten.get("error") and "ip" not in daten:
        return "fehler", f"ipapi.is meldet: «{saeubern(str(daten['error']), 200)}»"
    return None


async def _ipapi(v: Vorgang, ip: str) -> dict:
    key = einstellung("IPAPI_API_KEY")
    if not key:
        # Ohne Schlüssel antwortet der Dienst seit dem 1.9.2026 nur noch gekürzt (30 Abfragen am Tag, keine Merkmale für VPN,
        # Proxy und Tor) und sperrt einen Anschluss, der nach einer Abweisung weiterfragt, für 24 Stunden. Das lohnt die Abfrage nicht.
        return _stimme("ipapi.is", grund="IPAPI_API_KEY fehlt (ohne Schlüssel liefert der Dienst keine Merkmale für VPN, Proxy und Tor)")
    # Als POST: So steht der Schlüssel im Körper der Anfrage und nicht in der Adresse. Nach einer Abweisung nicht wiederholen.
    a = await v.hole("ipapi.is", ip, "ip", "https://api.ipapi.is", schritt="Art des Anschlusses, zweite Stimme", methode="POST",
                     json_koerper={"q": ip, "key": key}, geheim=("key",), deutung=_ipapi_deutung, cache_h=1, nochmal=False)
    s = _stimme("ipapi.is", a)
    return ipapi_lesen(a.daten, s) if a.ergebnis == "ok" and isinstance(a.daten, dict) else s


# --------------------------------------------------------------------------- AbuseIPDB, Spur

async def _abuseipdb(v: Vorgang, ip: str) -> dict:
    key = einstellung("ABUSEIPDB_API_KEY")
    if not key:
        return _stimme("AbuseIPDB", grund="ABUSEIPDB_API_KEY fehlt")
    a = await v.hole("AbuseIPDB", ip, "ip", "https://api.abuseipdb.com/api/v2/check", schritt="Nutzungsart des Anschlusses",
                     params={"ipAddress": ip, "maxAgeInDays": 90}, kopf={"Key": key})
    s = _stimme("AbuseIPDB", a)
    d = (a.daten or {}).get("data") if a.ergebnis == "ok" and isinstance(a.daten, dict) else None
    if not isinstance(d, dict):
        return s
    s.update(anschlussart=saeubern(d.get("usageType"), 60) or None,
             netz={k: w for k, w in {"betreiber": saeubern(d.get("isp"), 80), "land": d.get("countryCode")}.items() if w})
    if d.get("isTor") is True:          # AbuseIPDB äussert sich nur zu Tor. Ein «nein» dort ist keine Aussage über VPN und Proxy
        s.update(fuehrt=True, arten=["Tor"], heute="geführt")
    s["meldungen_90_tage"] = d.get("totalReports")
    return s


async def _spur(v: Vorgang, ip: str, tat: datetime | None) -> dict:
    token = einstellung("SPUR_TOKEN")
    if not token:
        return _stimme("Spur", grund="SPUR_TOKEN fehlt")
    a = await v.hole("Spur", ip, "ip", f"https://api.spur.us/v2/context/{ip}", schritt="Anonymisierungsdienst und Nutzerverhalten",
                     params={"dt": tat.strftime("%Y%m%d") if tat else None}, kopf={"Token": token})
    s = _stimme("Spur", a)
    d = a.daten if a.ergebnis == "ok" and isinstance(a.daten, dict) else None
    if d is None:
        return s
    tunnel = [t for t in d.get("tunnels") or [] if isinstance(t, dict)]
    kunde = d.get("client") if isinstance(d.get("client"), dict) else {}
    risiken = [str(r) for r in d.get("risks") or []]
    arten = list(dict.fromkeys({"VPN": "VPN", "PROXY": "Proxy", "TOR": "Tor"}.get(str(t.get("type")).upper(), str(t.get("type"))) for t in tunnel))
    proxys = [saeubern(str(p), 40) for p in kunde.get("proxies") or []]
    if proxys or "CALLBACK_PROXY" in risiken:
        arten.append("Residential Proxy")
    s.update(fuehrt=bool(arten), arten=arten, anschlussart=saeubern(d.get("infrastructure"), 40) or None,
             netz={k: w for k, w in {"as": f"AS{(d.get('as') or {}).get('number')}" if (d.get("as") or {}).get("number") else None,
                                     "betreiber": saeubern((d.get("as") or {}).get("organization"), 80),
                                     "organisation": saeubern(d.get("organization"), 80),
                                     "land": (d.get("location") or {}).get("country")}.items() if w})
    if s["fuehrt"]:
        s["heute"] = "geführt" if not tat else None
        s["dienst"] = saeubern(next((t.get("operator") for t in tunnel if t.get("operator")), None) or (proxys[0] if proxys else None), 60)
        # Als Anschluss eines Unbeteiligten gilt die Adresse nur, wenn Spur sie nicht selbst einem Rechenzentrum zuordnet
        s["residential"] = "Residential Proxy" in arten and str(d.get("infrastructure") or "").upper() != "DATACENTER"
        if tat:
            s["zur_tatzeit"], s["tatzeit_gedeckt"] = f"Stand der Quelle am {tat.strftime('%d.%m.%Y')} (historische Abfrage).", True
    return s


# --------------------------------------------------------------------------- RIPEstat

RIPESTAT = "https://stat.ripe.net/data"


def _ripe_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if status == 200 and isinstance(daten, dict) and daten.get("status") not in (None, "ok"):
        meldung = "; ".join(saeubern(str(m[1] if isinstance(m, list) and len(m) > 1 else m), 120) for m in (daten.get("messages") or [])[:2])
        return "fehler", f"RIPEstat meldet «{daten.get('status')}»" + (f": {meldung}" if meldung else "")
    return None


async def _ripe(v: Vorgang, call: str, ziel: str, schritt: str, **params: Any) -> tuple[Antwort, dict]:
    """Ein Aufruf von RIPEstat. ``sourceapp`` nennt die Anwendung, wie es die Nutzungsregeln des Dienstes verlangen."""
    a = await v.hole("RIPEstat", f"{ziel} ({call})", "ip", f"{RIPESTAT}/{call}/data.json", schritt=schritt,
                     params={**params, "sourceapp": einstellung("OSINT_RIPESTAT_APP", "osint-gateway")}, deutung=_ripe_deutung, cache_h=24)
    daten = (a.daten or {}).get("data") if a.ergebnis == "ok" and isinstance(a.daten, dict) else None
    return a, daten if isinstance(daten, dict) else {}


# Register nennen dieselbe Angabe verschieden (RIPE: inetnum, netname, country. ARIN: NetRange, NetName, Country).
_WHOIS_FELDER = {"bereich": ("inetnum", "inet6num", "netrange", "cidr"), "netzname": ("netname",),
                 "inhaber": ("org-name", "orgname", "organization", "owner", "descr"), "organisation": ("org", "orgid"),
                 "land": ("country",), "status": ("status", "nettype"), "registriert": ("created", "regdate"),
                 "geaendert": ("last-modified", "updated")}
_WHOIS_KONTAKT = ("person", "role", "admin-c", "tech-c", "abuse-c", "phone", "address", "e-mail", "nic-hdl")


def whois_lesen(saetze: list) -> dict:
    """Angaben zum Netz aus den Whois-Sätzen. Sätze zu Kontaktpersonen (person, role, OrgTech, OrgAbuse) bleiben draussen:
    Gebraucht wird, wem das Netz gehört, nicht wer dort arbeitet."""
    ergebnis: dict[str, str] = {}
    for satz in saetze or []:
        felder = [(str(f.get("key") or "").lower(), str(f.get("value") or "").strip()) for f in satz if isinstance(f, dict)]
        namen = {k for k, _ in felder}
        if namen & {"person", "role", "nic-hdl"} or any(k.startswith(("orgtech", "orgabuse", "orgnoc", "rtech", "rabuse", "rnoc")) for k in namen):
            continue
        for ziel, quellen in _WHOIS_FELDER.items():
            if ziel not in ergebnis:
                wert = next((w for k, w in felder if k in quellen and w), None)
                if wert:
                    ergebnis[ziel] = saeubern(wert, 100)
    return ergebnis


async def _ripestat(v: Vorgang, ip: str, tat: datetime | None) -> dict:
    a, info = await _ripe(v, "network-info", ip, "Präfix und AS", resource=ip)
    s = _stimme("RIPEstat", a)
    if a.ergebnis != "ok":
        return s
    s["belege"] = [a.id]
    praefix = info.get("prefix")
    netz: dict[str, Any] = {k: w for k, w in {"praefix": praefix, "as": ", ".join(f"AS{x}" for x in info.get("asns") or []) or None}.items() if w}
    b, ueber = await _ripe(v, "prefix-overview", ip, "Inhaber des AS", resource=praefix or ip)
    if b.ergebnis == "ok":
        s["belege"].append(b.id)
        netz.update({k: w for k, w in {"as_inhaber": "; ".join(saeubern(x.get("holder"), 80) for x in ueber.get("asns") or [] if isinstance(x, dict)) or None,
                                       "angekuendigt": ueber.get("announced")}.items() if w is not None})
    c, whois = await _ripe(v, "whois", ip, "Registereintrag", resource=ip)
    register: list[str] = []
    if c.ergebnis == "ok":
        s["belege"].append(c.id)
        register = [str(x).lower() for x in whois.get("authorities") or []]
        netz.update(whois_lesen(whois.get("records") or []))
        if register:
            netz["register"] = ", ".join(r.upper() for r in register)
    d, missbrauch = await _ripe(v, "abuse-contact-finder", ip, "Meldestelle für Missbrauch", resource=ip)
    if d.ergebnis == "ok":
        s["belege"].append(d.id)
        stellen = [saeubern(str(x), 100) for x in missbrauch.get("abuse_contacts") or []][:3]
        if stellen:
            netz["meldestelle"] = stellen
    s["netz"] = netz
    if tat:
        s["zur_tatzeit"] = await _ripe_damals(v, s, ip, netz, register, tat)
    return s


async def _ripe_damals(v: Vorgang, s: dict, ip: str, netz: dict, register: list[str], tat: datetime) -> dict:
    """Wer das Netz zur Tatzeit ankündigte (Routing-Daten von RIPE RIS, für alle Register) und wem es zugeteilt war
    (frühere Fassungen des Registereintrags gibt es nur für die RIPE-Datenbank)."""
    damals: dict[str, Any] = {"tatzeit": _iso(tat)}
    a, weg = await _ripe(v, "routing-history", ip, "Wer kündigte das Netz zur Tatzeit an?", resource=ip,
                         starttime=(tat - timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S"),
                         endtime=(tat + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S"))
    if a.ergebnis == "ok":
        s["belege"].append(a.id)
        damals["angekuendigt_von"] = [{"as": f"AS{o.get('origin')}", "praefix": p.get("prefix"),
                                       "von": (p.get("timelines") or [{}])[0].get("starttime"), "bis": (p.get("timelines") or [{}])[-1].get("endtime")}
                                      for o in (weg.get("by_origin") or [])[:5] if isinstance(o, dict)
                                      for p in (o.get("prefixes") or [])[:3] if isinstance(p, dict)]
        if not damals["angekuendigt_von"]:
            damals["hinweis_routing"] = "Für den Tag der Tat zeigen die Routing-Daten keine Ankündigung des Netzes."
    else:
        damals["hinweis_routing"] = f"Routing-Geschichte nicht abrufbar: {a.fehler or 'keine Daten'}"
    bereich = netz.get("bereich")
    if "ripe" not in register or not bereich:
        damals["zuteilung"] = ("Die frühere Zuteilung gibt es nur für die RIPE-Datenbank. Dieses Netz führt "
                               f"{netz.get('register') or 'ein anderes Register'}: Dort ist der heutige Eintrag der einzige, den die Quelle kennt.")
        return damals
    b, alt = await _ripe(v, "historical-whois", bereich, "Fassungen des Registereintrags", resource=bereich)
    if b.ergebnis != "ok":
        damals["zuteilung"] = f"Frühere Fassungen des Registereintrags nicht abrufbar: {b.fehler or 'keine Daten'}"
        return damals
    s["belege"].append(b.id)
    tatzeit = tat.strftime("%Y-%m-%dT%H:%M:%S")
    fassung = next((x for x in alt.get("versions") or [] if isinstance(x, dict) and str(x.get("from_time") or "") <= tatzeit < str(x.get("to_time") or "9")), None)
    if not fassung:
        damals["zuteilung"] = "Für die Tatzeit kennt die RIPE-Datenbank keine Fassung dieses Eintrags: Er entstand später."
        return damals
    objekt = next((o for o in alt.get("objects") or [] if isinstance(o, dict)), {})
    if objekt.get("version") != fassung.get("version"):        # die Fassung von damals eigens holen
        c, alt2 = await _ripe(v, "historical-whois", bereich, "Registereintrag zur Tatzeit", resource=bereich, version=fassung.get("version"))
        if c.ergebnis == "ok":
            s["belege"].append(c.id)
            objekt = next((o for o in alt2.get("objects") or [] if isinstance(o, dict)), objekt)
    attribute = {str(x.get("attribute") or "").lower(): str(x.get("value") or "") for x in objekt.get("attributes") or [] if isinstance(x, dict)}
    damals["zuteilung"] = {k: w for k, w in {"gueltig_von": fassung.get("from_time"), "gueltig_bis": fassung.get("to_time"),
                                             "fassung": fassung.get("version"), "fassungen_gesamt": alt.get("num_versions"),
                                             "netzname": saeubern(attribute.get("netname"), 60), "organisation": saeubern(attribute.get("org"), 60),
                                             "land": attribute.get("country"), "status": attribute.get("status")}.items() if w}
    return damals


# --------------------------------------------------------------------------- Zusammenführung

def urteil(stimmen: list[dict]) -> dict:
    """Führt die Stimmen zum Wert zusammen. Eine Quelle zählt für die Frage nur, wenn sie sich dazu äussert (fuehrt True oder False)."""
    mit = [s for s in stimmen if s["geantwortet"] and s["fuehrt"] is not None]
    ja, nein = [s for s in mit if s["fuehrt"]], [s for s in mit if not s["fuehrt"]]
    offen = [{"quelle": s["quelle"], "grund": s.get("grund") or "äussert sich zu dieser Frage nicht"}
             for s in stimmen if not (s["geantwortet"] and s["fuehrt"] is not None) and s["quelle"] != "RIPEstat"]
    wert = "ja" if ja else "kein Hinweis" if nein else "nicht geprüft"
    ergebnis: dict[str, Any] = {"wert": wert, "geantwortet": [s["quelle"] for s in mit], "nicht_geantwortet": offen}
    if ja and nein:
        ergebnis["vermerk"] = "Quellen uneinig"
    if ja:
        ergebnis["aussagen"] = [{k: s[k] for k in ("quelle", "arten", "dienst", "angebote", "weitere_dienste", "zuerst", "zuletzt", "heute",
                                                   "geloescht_am", "austrag_geplant", "residential", "hinweise", "beleg") if s.get(k) not in (None, [], "")}
                                for s in ja]
        ergebnis["residential"] = any(s.get("residential") for s in ja)
        ergebnis["dienste"] = list(dict.fromkeys(s["dienst"] for s in ja if s.get("dienst")))
        ergebnis["arten"] = list(dict.fromkeys(a for s in ja for a in s["arten"]))
    if nein:
        ergebnis["ohne_eintrag"] = [{"quelle": s["quelle"], "beleg": s["beleg"]} for s in nein]
    return ergebnis


def _aufzaehlung(namen: list[str]) -> str:
    return namen[0] if len(namen) == 1 else ", ".join(namen[:-1]) + " und " + namen[-1] if namen else ""


def erklaerung(ip: str, u: dict, stimmen: list[dict], tat: datetime | None, jetzt: datetime) -> str:
    """Die Einordnung in einfachen Worten. Nie eine Person: Eine IP-Adresse identifiziert niemanden."""
    zeit = jetzt.astimezone(kern.zeitzone()).strftime("%d.%m.%Y, %H:%M")
    if u["wert"] == "ja":
        wer = _aufzaehlung([a["quelle"] for a in u["aussagen"]])
        was = ", ".join(u.get("arten") or [])
        dienst = f" Als Dienst genannt: {', '.join(u['dienste'])}." if u.get("dienste") else ""
        if not was and not dienst:      # geführt, aber ohne Art und ohne Dienst: genau so wiedergeben, nicht ausschmücken
            t = (f"{wer} führt die Adresse {ip} als anonym, nennt aber weder die Art noch einen Dienst. Mehr sagt die Quelle nicht. "
                 "Trifft der Eintrag zu, gehen über die Adresse die Verbindungen vieler Unbekannter.")
        else:
            t = (f"Die Adresse {ip} ist laut {wer} der Ausgang eines Anonymisierungsdienstes ({was or 'ohne Angabe der Art'}).{dienst} "
                 "Über einen solchen Ausgang gehen die Verbindungen vieler Unbekannter.")
        if not was and not dienst:
            pass
        elif "Tor" in (u.get("arten") or []):
            t += (" Beim Tor-Netz kennt auch der Betreiber des Ausgangs die Herkunft einer Verbindung nicht: Sie läuft über mehrere "
                  "Stationen, von denen jede nur die nächste kennt.")
        else:
            t += " Wer zur Tatzeit über diese Adresse kam, weiss nur der Betreiber des Dienstes, wenn überhaupt."
        if u.get("residential"):
            t += (" Die Adresse gehört zu einem Privat- oder Mobilfunkanschluss: Bei einem Residential Proxy läuft der Dienst über das Gerät "
                  "eines Anschlussinhabers, der davon in der Regel nichts weiss. Er ist voraussichtlich unbeteiligt.")
        if u.get("vermerk"):
            ohne = _aufzaehlung([s["quelle"] for s in u["ohne_eintrag"]])
            t += f" Die Quellen sind uneinig: {ohne} {'führen' if len(u['ohne_eintrag']) > 1 else 'führt'} die Adresse nicht."
    elif u["wert"] == "kein Hinweis":
        t = (f"Keine der befragten Quellen ({', '.join(u['geantwortet'])}) führt die Adresse {ip} als Ausgang eines VPN, eines Proxys oder des "
             f"Tor-Netzes. Das ist kein «nein». {VORBEHALT}")
    else:
        gruende = "; ".join(f"{o['quelle']}: {o['grund']}" for o in u["nicht_geantwortet"]) or "keine Quelle zu dieser Frage befragt"
        t = (f"Ob die Adresse {ip} zu einem Anonymisierungsdienst gehört, ist nicht geprüft ({gruende}). {VORBEHALT} "
             "Die Abklärung lässt sich nachholen: mit einem eingerichteten Schlüssel, oder von Hand über tools/beleg.py.")
    t += f" Die Auskunft gilt für den Abfragezeitpunkt ({zeit})."
    if tat:
        damals = [f"{s['quelle']}: {s['zur_tatzeit']}" for s in stimmen if isinstance(s.get("zur_tatzeit"), str)]
        t += f" Die Tat lag früher ({tat.astimezone(kern.zeitzone()).strftime('%d.%m.%Y, %H:%M')}). "
        t += " ".join(damals) if damals else "Für die Tatzeit selbst sagen die Quellen zum Anonymisierungsdienst nichts."
    return t + " Eine IP-Adresse identifiziert niemanden."


def _netzbetreiber(netz: dict) -> str:
    """Name des Netzinhabers für den Ansatzpunkt. Ein blosses Kürzel des Registers (ORG-…) ist kein Name."""
    for feld in ("inhaber", "as_inhaber", "betreiber", "organisation", "netzname"):
        wert = str(netz.get(feld) or "")
        if wert and not wert.upper().startswith("ORG-"):
            return wert
    return "Inhaber des Netzes laut Register"


_RECHENZENTRUM = ("rechenzentrum", "datacenter", "data center", "hosting")
_ANSCHLUSS = ("privatanschluss", "mobilfunk", "zugangsanbieter", "isp", "residential", "mobile")


def ansatz(ip: str, u: dict, netz: dict, anschlussart: list[dict] | None = None) -> str:
    """Wo ein Editionsbegehren ansetzen kann, mit dem Vorbehalt, der zum Wert gehört."""
    anbieter = _netzbetreiber(netz)
    if u["wert"] == "ja":
        if "Tor" in (u.get("arten") or []):
            t = (f"Die Adresse {ip} ist ein Ausgang des Tor-Netzes. Ein Editionsbegehren an den Netzbetreiber ({anbieter}) oder an den "
                 "Betreiber des Ausgangs führt nicht zum Nutzer: Der Ausgang kennt die Herkunft der Verbindungen nicht.")
        else:
            dienste = ", ".join(u.get("dienste") or []) or "des Dienstes (von den Quellen nicht benannt)"
            t = (f"Zuerst an den Betreiber {dienste}: Nur er kann wissen, wer zur Tatzeit über die Adresse {ip} kam. "
                 f"Ein Editionsbegehren an den Netzbetreiber ({anbieter}) nennt nur den Kunden, dem die Adresse zugeteilt ist.")
        if u.get("residential"):
            t += " Bei einem Residential Proxy ist der Anschlussinhaber voraussichtlich unbeteiligt. Das gehört ins Begehren und in die Würdigung der Antwort."
        if u.get("vermerk"):
            t += " Die Quellen sind uneinig, siehe Einordnung."
        return t
    arten = [str(a.get("art") or "").lower() for a in anschlussart or []]
    im_rechenzentrum = any(w in a for a in arten for w in _RECHENZENTRUM) and not any(w in a for a in arten for w in _ANSCHLUSS)
    if im_rechenzentrum:
        # Eine Adresse im Rechenzentrum gehört keinem Privatanschluss. Der Betreiber des Netzes kennt den Kunden, der sie gemietet hat
        t = (f"Editionsbegehren an den Betreiber des Netzes ({anbieter}) zur Adresse {ip} und zur Tatzeit: Die Adresse liegt laut den "
             "Quellen in einem Rechenzentrum, der Betreiber kennt den Kunden, dem sie zugeteilt war. Vorbehalt: Auch ein gemieteter "
             "Server kann als Weiterleitung dienen (VPN, Proxy), ohne dass eine Quelle ihn führt.")
    else:
        t = f"Editionsbegehren an den Zugangsanbieter ({anbieter}) zur Adresse {ip} und zur Tatzeit. Vorbehalt: {VORBEHALT}"
    if u["wert"] == "nicht geprüft":
        t += " Die Abklärung, ob die Adresse zu einem Anonymisierungsdienst gehört, vorher nachholen."
    return t


_NETZ_VORRANG = ("RIPEstat", "ipapi.is", "proxycheck.io", "Spur", "AbuseIPDB")


@werkzeug
async def ip_einordnung(fall: Fall, zweck: Zweck, ip: str,
                        tatzeit: Annotated[str | None, Field(description=(
                            "Zeitpunkt der Tat, z. B. 2026-10-02T14:10:00Z oder 2026-10-02. Mit Tatzeit: wer das Netz damals ankündigte "
                            "und hielt, und ob die Adresse damals als Anonymisierungsdienst geführt war (Fenster: 60 Tage)."))] = None,
                        quellen: Annotated[list[str] | None, Field(description=(
                            f"Nur diese Quellen fragen ({', '.join(QUELLEN)}). Ohne Angabe alle eingerichteten."))] = None) -> dict:
    """Ordnet eine IP-Adresse ein: Netz (Präfix, AS, Inhaber, Land, Meldestelle), Art des Anschlusses je Quelle, und ob die
    Adresse der Ausgang eines Anonymisierungsdienstes ist (VPN, Proxy, Tor, Residential Proxy). Der Wert dazu ist genau einer
    von: «ja», «kein Hinweis» (kein «nein»!), «nicht geprüft». Für jede IP eines Falls aufrufen, bevor sie einem Anschluss
    zugeschrieben wird: Hinter einem Privatanschluss kann ein Unbeteiligter stehen, über dessen Gerät ein Residential Proxy
    läuft. Der Abschlussrapport verlangt den Wert für jede IP. Bündelt mehrere Abfragen: 'protokoll_id' belegt die Auswertung."""
    ip = pruef_ip(ip)
    tat = zeit_lesen(tatzeit)
    jetzt = kern.uhr()
    if tat and tat > jetzt + timedelta(minutes=5):
        raise Abbruch("Die Tatzeit liegt in der Zukunft.")
    nur = {q.strip().lower() for q in quellen or [] if q and q.strip()}
    if nur - set(QUELLEN):
        raise Abbruch(f"Unbekannte Quelle(n): {', '.join(sorted(nur - set(QUELLEN)))}. Möglich: {', '.join(QUELLEN)}.")
    v = Vorgang(fall, zweck, "ip_einordnung", abruf=ABRUF)
    stimmen: list[dict] = []
    for name, aufruf in (("proxycheck", lambda: _proxycheck(v, ip, tat)), ("ipapi", lambda: _ipapi(v, ip)),
                         ("ripestat", lambda: _ripestat(v, ip, tat)), ("abuseipdb", lambda: _abuseipdb(v, ip)),
                         ("spur", lambda: _spur(v, ip, tat))):
        if not nur or name in nur:
            stimmen.append(await aufruf())
    u = urteil(stimmen)
    je = {s["quelle"]: s for s in stimmen}
    netz: dict[str, Any] = {}
    for quelle in _NETZ_VORRANG:                       # die Register zuerst, dann die übrigen Stimmen für das, was fehlt
        for feld, wert in (je.get(quelle, {}).get("netz") or {}).items():
            netz.setdefault(feld, wert)
    damals = (je.get("RIPEstat") or {}).get("zur_tatzeit")
    befund = {
        "ip": ip, "abfragezeit": _iso(jetzt), **({"tatzeit": _iso(tat)} if tat else {}),
        "netz": {**netz, **({"zur_tatzeit": damals} if isinstance(damals, dict) else {})},
        "anschlussart": [{"quelle": s["quelle"], "art": s["anschlussart"], **({"merkmale": s["merkmale"]} if s.get("merkmale") else {})}
                         for s in stimmen if s.get("anschlussart")],
        "anonymisierung": u,
        "erklaerung": erklaerung(ip, u, stimmen, tat, jetzt),
        "ansatzpunkt": ansatz(ip, u, netz, [{"art": s["anschlussart"]} for s in stimmen if s.get("anschlussart")]),
        "quellenstand": {s["quelle"]: ({"ergebnis": "ok", "beleg": s["beleg"]} if s["geantwortet"]
                                       else {"ergebnis": "aus" if "fehlt" in str(s.get("grund")) else "fehler", "hinweis": s.get("grund"),
                                             **({"beleg": s["beleg"]} if s.get("beleg") else {})}) for s in stimmen},
    }
    hinweise = [f"{s['quelle']}: {h}" for s in stimmen for h in s.get("hinweise") or []]
    if hinweise:
        befund["hinweise"] = hinweise
    return v.abschluss(ip, "ip", befund, quellen=[s["quelle"] for s in stimmen if s["geantwortet"]],
                       parameter={"ip": ip, "tatzeit": _iso(tat), "quellen": sorted(nur) or None},
                       details={"stimmen": stimmen}, hinweis=FREMD)
