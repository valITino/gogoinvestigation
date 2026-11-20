"""Darsteller: ordnen die Rohantwort eines Werkzeugs festen Abschnitten und Feldern zu. Nur Standardbibliothek.

Jede Angabe, die die Oberfläche zeigt, stammt aus der Rohdatei und trägt die Stelle, an der sie dort steht
(ein JSON-Zeiger wie /data/attributes/country). Was ein Darsteller nicht zuordnet, geht nicht verloren: Es
steht unter «Weitere Angaben der Quelle». Für ein Werkzeug ohne eigenen Darsteller zeigt der allgemeine
Darsteller die ganze Antwort auf diese Weise.

    blatt = darstellen(eintrag, roh)          eintrag: Protokolleintrag, roh: gelesene Rohdatei
    blatt.abschnitte                          [(Titel, [Angabe | Liste, ...]), ...]
    blatt.weitere                             [(Stelle, Wert), ...]: alles, was nicht zugeordnet ist
    blatt.gesamt, blatt.zugeordnet            Zahl der Angaben in der Rohantwort und davon zugeordnet

Eine «Angabe der Rohantwort» ist jeder einzelne Wert darin: jede Zeichenkette, Zahl, jedes ja/nein, jedes leere
Feld, jede leere Liste. Die Selbsttests zählen sie je Vorlage und prüfen, dass jede in der Oberfläche erscheint.

Ein Darsteller deutet nichts. Er benennt Felder, setzt Einheiten und rechnet Zeiten in die Zeitzone des
Arbeitsplatzes um, der Originalwert steht daneben.

Robin (Dark Web) antwortet als Text, nicht als JSON. Für die Anzeige wird der Text in seine Teile zerlegt (gateway/robin.py,
lesen): Stand, Treffer, gelesene Seiten. Die Stellen beziehen sich dann auf diese Zerlegung, der Wortlaut steht in der Rohdatei.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from gateway import robin


# --------------------------------------------------------------------------- Bausteine einer Beschreibung

@dataclass(frozen=True)
class F:
    """Ein Feld: Bezeichnung, Pfad in der Rohantwort (* steht für jeden Eintrag), Art, Schlüssel im Datenblatt."""
    name: str
    pfad: str
    art: str = "text"       # text | zahl | zeit | zeit_s | zeit_ms | bytes | ja_nein | prozent | liste | lang
    s: str = ""             # Feld im Datenblatt des Indikators, zum Beispiel «netz.as»
    e: str = ""             # Einheit
    h: str = ""             # Erklärung in einfachen Worten
    ep: str = ""            # Einheit aus der Antwort: Pfad zum Feld, das sie nennt (in Tabellen je Zeile, mit / davor ab der Wurzel)


@dataclass(frozen=True)
class T:
    """Eine Tabelle: Pfad zu einer Liste (oder einem Objekt, dessen Einträge die Zeilen sind) und ihre Spalten.
    Spaltenpfade gelten je Zeile. «» ist der Eintrag selbst, «#» sein Schlüssel oder seine Nummer."""
    name: str
    pfad: str
    spalten: tuple
    s: str = ""
    h: str = ""


@dataclass(frozen=True)
class A:
    titel: str
    teile: tuple


@dataclass(frozen=True)
class Darsteller:
    werkzeug: str
    titel: str
    typen: tuple                    # Indikatortypen, zu denen das Werkzeug etwas sagt
    abschnitte: tuple
    wurzel: str = ""                # gebündelte Werkzeuge legen ihr Ergebnis unter «befund» ab
    eigen: bool = True              # False beim allgemeinen Darsteller


@dataclass
class Angabe:
    name: str
    wert: Any
    anzeige: str
    stelle: str
    art: str = "text"
    einheit: str = ""
    hilfe: str = ""
    schluessel: str = ""
    original: str = ""              # bei Zeiten: der Wert, wie ihn die Quelle schreibt
    einheit_stelle: str = ""        # nennt die Antwort die Einheit selbst: die Stelle, an der sie steht


@dataclass
class Liste:
    name: str
    spalten: list
    zeilen: list                    # je Zeile eine Liste von Angabe | None
    stelle: str
    hilfe: str = ""
    schluessel: str = ""


@dataclass
class Blatt:
    werkzeug: str
    titel: str
    eigen: bool
    abschnitte: list = field(default_factory=list)
    weitere: list = field(default_factory=list)        # (Stelle, Wert)
    gesamt: int = 0
    zugeordnet: int = 0
    form: str = "json"                                  # json | text | csv | bild | leer
    inhalt: Any = None                                  # nur bei zerlegtem Text (Robin): was zerlegt wurde. Die Stellen beziehen sich darauf
    zerlegt: bool = False

    def angaben(self) -> Iterator[Angabe]:
        for _, teile in self.abschnitte:
            for teil in teile:
                if isinstance(teil, Angabe):
                    yield teil
                else:
                    for zeile in teil.zeilen:
                        yield from (z for z in zeile if z is not None)


# --------------------------------------------------------------------------- Rohantwort durchlaufen

def _teil(schluessel: object) -> str:
    return str(schluessel).replace("~", "~0").replace("/", "~1")


def skalar(wert: object) -> bool:
    return wert is None or isinstance(wert, (str, int, float, bool))


def angaben_zaehlen(o: object, zeiger: str = "") -> Iterator[tuple[str, object]]:
    """Jede einzelne Angabe einer Rohantwort mit ihrer Stelle. Leere Listen und Objekte zählen als eine Angabe."""
    if isinstance(o, dict):
        if not o:
            yield zeiger, o
        for k, v in o.items():
            yield from angaben_zaehlen(v, f"{zeiger}/{_teil(k)}")
    elif isinstance(o, list):
        if not o:
            yield zeiger, o
        for i, v in enumerate(o):
            yield from angaben_zaehlen(v, f"{zeiger}/{i}")
    else:
        yield zeiger, o


def aufloesen(o: object, pfad: str, zeiger: str = "") -> list[tuple[str, object]]:
    """Folgt einem Pfad wie «data.attributes.names» oder «data.*.port». Liefert (Stelle, Wert) je Treffer."""
    if not pfad:
        return [(zeiger, o)]
    kopf, _, rest = pfad.partition(".")
    if kopf == "*":
        if isinstance(o, dict):
            return [t for k, v in o.items() for t in aufloesen(v, rest, f"{zeiger}/{_teil(k)}")]
        if isinstance(o, list):
            return [t for i, v in enumerate(o) for t in aufloesen(v, rest, f"{zeiger}/{i}")]
        return []
    if isinstance(o, dict) and kopf in o:
        return aufloesen(o[kopf], rest, f"{zeiger}/{_teil(kopf)}")
    if isinstance(o, list) and kopf.isdigit() and int(kopf) < len(o):
        return aufloesen(o[int(kopf)], rest, f"{zeiger}/{kopf}")
    return []


def an_stelle(o: object, zeiger: str) -> object:
    """Der Wert an einer Stelle der Rohantwort. Die Selbsttests prüfen damit jede gezeigte Angabe nach."""
    for teil in zeiger.split("/")[1:]:
        teil = teil.replace("~1", "/").replace("~0", "~")
        o = o[int(teil)] if isinstance(o, list) else o[teil]
    return o


# --------------------------------------------------------------------------- Anzeige: Zahlen genau, Zeiten mit Original

ZONE: Any = timezone.utc        # setzt die Datenschicht auf die Zeitzone des Arbeitsplatzes


def zahl(wert: object) -> str:
    """Eine Zahl ohne Rundungsverlust. Ganze Zahlen ab fünf Stellen bekommen das Schweizer Tausenderzeichen."""
    if isinstance(wert, bool):
        return "ja" if wert else "nein"
    if isinstance(wert, int):
        return f"{wert:,}".replace(",", "'") if abs(wert) >= 10000 else str(wert)
    if isinstance(wert, float):
        return repr(wert)
    return str(wert)


def zeit(wert: object, art: str = "zeit") -> tuple[str, str]:
    """Liefert (Zeit in der Zeitzone des Arbeitsplatzes, Originalwert). Lässt sich der Wert nicht lesen: (Original, «»)."""
    original = json.dumps(wert) if not isinstance(wert, str) else wert
    try:
        if art in ("zeit_s", "zeit_ms") or isinstance(wert, (int, float)):
            sekunden = float(wert) / (1000 if art == "zeit_ms" else 1)
            if not 0 < sekunden < 4e9:
                return original, ""
            d = datetime.fromtimestamp(sekunden, tz=timezone.utc)
        else:
            text = str(wert).strip()
            if re.fullmatch(r"\d{4}-\d\d-\d\d", text):
                return datetime.strptime(text, "%Y-%m-%d").strftime("%d.%m.%Y"), original
            text = re.sub(r"\.(\d{6})\d+", r".\1", text.replace(" ", "T", 1) if re.match(r"\d{4}-\d\d-\d\d \d", text) else text)
            d = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return original, ""
    return d.astimezone(ZONE).strftime("%d.%m.%Y %H:%M:%S"), original


def groesse(n: object) -> str:
    if not isinstance(n, (int, float)) or isinstance(n, bool):
        return str(n)
    if n < 1024:
        return f"{zahl(n)} Bytes"
    return f"{zahl(n)} Bytes ({n / 1024:.1f} kB)" if n < 1 << 20 else f"{zahl(n)} Bytes ({n / (1 << 20):.1f} MB)"


def anzeigen(wert: object, art: str, einheit: str = "") -> tuple[str, str]:
    """Der Wert, wie er in der Oberfläche steht, und bei Zeiten der Originalwert. Gedeutet wird nichts."""
    if wert is None:
        return "leer (die Quelle nennt keinen Wert)", ""
    if isinstance(wert, list):
        if not wert:
            return "keine Einträge", ""
        return ", ".join(anzeigen(w, "text" if art == "liste" else art)[0] for w in wert), ""
    if isinstance(wert, dict):
        return "keine Einträge" if not wert else json.dumps(wert, ensure_ascii=False), ""
    if isinstance(wert, bool):
        return ("ja" if wert else "nein"), ""
    if art in ("zeit", "zeit_s", "zeit_ms"):
        lokal, original = zeit(wert, art)
        return lokal, original
    if art == "bytes":
        return groesse(wert), ""
    if isinstance(wert, (int, float)):
        return zahl(wert) + (f" {einheit}" if einheit else ""), ""
    return str(wert) + (f" {einheit}" if einheit and str(wert) else ""), ""


# --------------------------------------------------------------------------- Die Beschreibungen je Werkzeug

_VT_PRODUKTE = (F("Produkt", "#"), F("Einstufung", "category"), F("Ergebnis", "result"), F("Verfahren", "method"), F("Name", "engine_name"),
                F("Version", "engine_version"), F("Stand der Signaturen", "engine_update"))
VT_STAND = "Wie viele Sicherheitsprodukte bei VirusTotal den Indikator so einstufen. Wenige Treffer können Fehlalarme sein."


def _vt_urteil(basis: str) -> tuple:
    return (F("Als bösartig eingestuft von", f"{basis}.malicious", "zahl", "ruf.vt_boesartig", "Produkten", VT_STAND),
            F("Als verdächtig eingestuft von", f"{basis}.suspicious", "zahl", "ruf.vt_verdaechtig", "Produkten"),
            F("Als harmlos eingestuft von", f"{basis}.harmless", "zahl", "ruf.vt_harmlos", "Produkten"),
            F("Ohne Befund bei", f"{basis}.undetected", "zahl", "ruf.vt_unentdeckt", "Produkten"),
            F("Zeitüberschreitung bei", f"{basis}.timeout", "zahl", e="Produkten"), F("Als bösartig bestätigt von", f"{basis}.confirmed-timeout", "zahl", e="Produkten"),
            F("Nicht unterstützt von", f"{basis}.type-unsupported", "zahl", e="Produkten"), F("Fehlgeschlagen bei", f"{basis}.failure", "zahl", e="Produkten"),
            T("Urteile der einzelnen Produkte", f"{basis.rsplit('.', 1)[0]}.last_analysis_results", _VT_PRODUKTE, "ruf.vt_produkte",
              "Jede Zeile ist ein Sicherheitsprodukt. «undetected» heisst: Das Produkt hat nichts gefunden."))


_VT_ZERT = (F("Zertifikat ausgestellt auf", "data.attributes.last_https_certificate.subject.CN", s="zert.cn"),
            F("Aussteller", "data.attributes.last_https_certificate.issuer.O", s="zert.aussteller"),
            F("Aussteller (Name)", "data.attributes.last_https_certificate.issuer.CN"),
            F("Gültig ab", "data.attributes.last_https_certificate.validity.not_before", "zeit", "zert.gueltig_ab"),
            F("Gültig bis", "data.attributes.last_https_certificate.validity.not_after", "zeit", "zert.gueltig_bis"),
            F("Fingerabdruck (SHA-256)", "data.attributes.last_https_certificate.thumbprint_sha256", s="zert.fingerabdruck"),
            F("Weitere Namen im Zertifikat", "data.attributes.last_https_certificate.extensions.subject_alternative_name", "liste", "zert.namen"),
            F("Zertifikat gesehen am", "data.attributes.last_https_certificate_date", "zeit_s"))

_RL_OPFER = (F("Opfer", "victim"), F("Gruppe", "group"), F("Land", "country"), F("Branche", "activity"),
             F("Entdeckt", "discovered", "zeit"), F("Angriff laut Gruppe", "attackdate", "zeit"), F("Website", "website"),
             F("Beschreibung", "description", "lang"), F("Eintrag auf der Leak-Seite", "post_url"), F("Dauerlink", "permalink"))

_KETTE = "Auf welcher Blockchain die Adresse oder Zahlung liegt."
_QUELLENSTAND = T("Stand der befragten Quellen", "quellenstand", (
    F("Quelle", "#"), F("Stand", "status"), F("Ergebnis", "ergebnis"), F("Beleg", "beleg"), F("Adressen in der Liste", "adressen_in_liste", "zahl"),
    F("Stand der Liste", "stand"), F("Datum der Liste", "datum", "zeit"), F("Umfang", "umfang"), F("Einträge", "eintraege", "zahl"), F("Prüfsumme der Liste", "sha256"),
    F("Hinweis", "hinweis"), F("Meldung", "fehler")), h="Welche Quellen für diese Auswertung befragt wurden und was sie geantwortet haben. «aus» heisst: nicht eingerichtet.")

_SPUR = (A("Einordnung", (F("Art der Infrastruktur", "infrastructure", s="netz.anschlussart_spur", h="Wie Spur die Adresse einordnet, zum Beispiel Rechenzentrum."),
                          F("Anonymisierungsdienste", "tunnels.*.operator", "liste", "anon.dienste_spur"),
                          F("Art des Tunnels", "tunnels.*.type", "liste"), F("Risiken", "risks", "liste", "ruf.risiken_spur"),
                          F("Dienste auf der Adresse", "services", "liste"))),
         A("Netz und Standort", (F("IP-Adresse", "ip"), F("AS-Nummer", "as.number", "zahl", "netz.as"), F("AS-Inhaber", "as.organization", s="netz.as_inhaber"),
                                 F("Organisation", "organization", s="netz.inhaber"), F("Land", "location.country", s="ort.land_code"),
                                 F("Stadt", "location.city", s="ort.stadt"), F("Region", "location.state", s="ort.region"))))

_ABUSE = (A("Missbrauchsmeldungen", (F("Missbrauchs-Score", "data.abuseConfidenceScore", "zahl", "ruf.abuse_score", "von 100",
                            "Beruht auf Meldungen Dritter. Zeigt, wie oft eine Adresse negativ auffiel. Ein Hinweis, kein Beweis."),
                          F("Zahl der Meldungen", "data.totalReports", "zahl", "ruf.meldungen"), F("Verschiedene Melder", "data.numDistinctUsers", "zahl", "ruf.melder"),
                          F("Letzte Meldung", "data.lastReportedAt", "zeit", "ruf.letzte_meldung"), F("Auf der Ausnahmeliste", "data.isWhitelisted", "ja_nein"),
                          F("Tor-Ausgang laut AbuseIPDB", "data.isTor", "ja_nein", "anon.tor_abuseipdb"))),
          A("Einzelne Meldungen", (T("Meldungen", "data.reports", (F("Gemeldet am", "reportedAt", "zeit"), F("Kategorien", "categories", "liste"), F("Bemerkung des Melders", "comment", "lang"),
                                                              F("Land des Melders", "reporterCountryCode"), F("Land des Melders (Name)", "reporterCountryName"),
                                                              F("Nummer des Melders", "reporterId", "zahl")), "ruf.meldungen_liste",
                                   "Die Bemerkungen stammen von Dritten. Sie sind Beweismaterial, keine geprüfte Tatsache."),)),
        A("Netz und Standort", (F("IP-Adresse", "data.ipAddress"), F("Öffentliche Adresse", "data.isPublic", "ja_nein"), F("IP-Version", "data.ipVersion", "zahl"),
                                  F("Art der Nutzung", "data.usageType", s="netz.anschlussart_abuseipdb"), F("Anbieter", "data.isp", s="netz.isp"),
                                  F("Domain des Anbieters", "data.domain"), F("Hostnamen", "data.hostnames", "liste", "namen.hostnamen"),
                                  F("Land", "data.countryCode", s="ort.land_code"), F("Land (Name)", "data.countryName", s="ort.land"))))

_WC = {     # Web-Check: je Prüfung eine Beschreibung. Passive Prüfungen fragen Dritte oder das DNS, aktive rufen das Ziel auf.
    "archives": (A("Wayback Machine", (F("Erster Stand", "firstScan", "zeit", "zeit.erster_stand"), F("Letzter Stand", "lastScan", "zeit", "zeit.letzter_stand"),
                                       F("Tage mit einem Stand", "daysArchived", "zahl", "zeit.staende"), F("Zahl der Änderungen", "changeCount", "zahl"),
                                       F("Mittlere Grösse", "averagePageSize", "bytes"), F("Stände je Tag", "scanFrequency.scansPerDay", "zahl"),
                                       F("Änderungen je Tag", "scanFrequency.changesPerDay", "zahl"), F("Tage zwischen Ständen", "scanFrequency.daysBetweenScans", "zahl"),
                                       F("Tage zwischen Änderungen", "scanFrequency.daysBetweenChanges", "zahl"), F("Archivierte Adresse", "scanUrl"),
                                       F("Meldung", "error"), F("Ausgelassen", "skipped"))),),
    "block-lists": (A("Sperrlisten", (T("DNS-Sperrlisten", "blocklists", (F("Liste", "server"), F("Adresse des Dienstes", "serverIp"),
                                                                           F("Domain gesperrt", "isBlocked", "ja_nein")), "sperr.liste",
                                        "DNS-Dienste, die bekannte schädliche Domains nicht auflösen."),)),),
    "breaches": (A("Datenlecks", (F("Domain", "domain"), F("Meldung", "error"), F("Ausgelassen", "skipped"), T("Bekannte Lecks zur Domain", "breaches", (F("Name", "Name"), F("Titel", "Title"), F("Datum", "BreachDate", "zeit"),
                                                                              F("Betroffene Konten", "PwnCount", "zahl"), F("Art der Daten", "DataClasses", "liste")), "ruf.lecks"),)),),
    "caa-records": (A("CAA-Einträge", (F("Domain", "domain"), T("Einträge", "records", (F("Kennzeichen", "flags", "zahl"), F("Art", "tag"), F("Wert", "value")), "dns.caa",
                                                                 "CAA legt fest, welche Stellen für die Domain Zertifikate ausstellen dürfen."))),),
    "dns": (A("DNS-Einträge", (F("A (IPv4-Adressen)", "A", "liste", "dns.a"), F("AAAA (IPv6-Adressen)", "AAAA", "liste", "dns.aaaa"),
                               T("MX (Mailserver)", "MX", (F("Server", "exchange"), F("Vorrang", "priority", "zahl")), "dns.mx"),
                               F("NS (Nameserver)", "NS", "liste", "dns.ns"), F("TXT", "TXT.*", "liste", "dns.txt"), F("CNAME", "CNAME", "liste", "dns.cname"),
                               F("SOA: Hauptserver", "SOA.nsname", s="dns.soa"), F("SOA: Zuständig", "SOA.hostmaster"), F("SOA: Seriennummer", "SOA.serial", "zahl"),
                               F("SOA: Auffrischen nach", "SOA.refresh", "zahl", e="Sekunden"), F("SOA: Erneut versuchen nach", "SOA.retry", "zahl", e="Sekunden"),
                               F("SOA: Verfällt nach", "SOA.expire", "zahl", e="Sekunden"), F("SOA: Mindest-TTL", "SOA.minttl", "zahl", e="Sekunden"), F("SOA", "SOA"),
                               F("SRV", "SRV", "liste"), F("PTR", "PTR", "liste"))),),
    "dnssec": (A("DNSSEC", (F("DNSKEY vorhanden", "DNSKEY.isFound", "ja_nein", "dns.dnssec", h="DNSSEC sichert DNS-Antworten mit Unterschriften ab."),
                            F("DS vorhanden", "DS.isFound", "ja_nein"), F("RRSIG vorhanden", "RRSIG.isFound", "ja_nein"),
                            T("DNSKEY", "DNSKEY.answer", (F("Name", "name"), F("Typ", "type", "zahl"), F("TTL", "TTL", "zahl", e="Sekunden"), F("Daten", "data", "lang"))),
                            T("DS", "DS.answer", (F("Name", "name"), F("Typ", "type", "zahl"), F("TTL", "TTL", "zahl", e="Sekunden"), F("Daten", "data", "lang"))))),),
    "get-ip": (A("Adresse", (F("IP-Adresse", "ip", s="host.ip"), F("IP-Version", "family", "zahl"))),),
    "rank": (A("Rang", (F("Domain", "domain"), F("Meldung", "error"), F("Ausgelassen", "skipped"), T("Tranco-Rang", "ranks", (F("Datum", "date", "zeit"), F("Rang", "rank", "zahl")), "ruf.rang",
                                                  "Tranco reiht Domains nach Bekanntheit. Eine frisch registrierte Domain hat keinen Rang."))),),
    "shodan": (A("Shodan über Web-Check", (F("Ausgelassen", "skipped"), F("Meldung", "error"), F("Hostnamen", "hostnames", "liste"), F("Ports", "ports", "liste"), F("Organisation", "org"), F("Land", "country_name"))),),
    "subdomains": (A("Subdomains", (F("Domain", "domain"), F("Gefundene Subdomains", "subdomains", "liste", "verwandt.subdomains"), F("Zahl", "count", "zahl"),
                                    F("Liste gekürzt", "truncated", "ja_nein"), F("Quelle", "source"), F("Meldung", "error"), F("Erneuter Versuch sinnvoll", "retryable", "ja_nein"))),),
    "threats": (A("Bedrohungslisten", (F("PhishTank: in der Liste", "phishTank.url0.in_database", s="sperr.phishtank"), F("PhishTank: geprüft", "phishTank.url0.verified"),
                                        F("PhishTank: Nummer", "phishTank.url0.phish_id"), F("PhishTank: Adresse", "phishTank.url0.url"),
                                        F("NetAPI: heute gelistet", "netApi.listed_now", "ja_nein", "sperr.netapi"), F("NetAPI: je gelistet", "netApi.listed_ever", "ja_nein"),
                                        F("NetAPI: erstmals", "netApi.first_seen", "zeit"), F("NetAPI: zuletzt", "netApi.last_seen", "zeit"), F("NetAPI: Grund", "netApi.block_reason"),
                                        F("NetAPI: Bemerkung", "netApi.note"), F("URLhaus: Status", "urlHaus.query_status", s="sperr.urlhaus"), F("URLhaus: Meldung", "urlHaus.error"),
                                        F("Safe Browsing: unsicher", "safeBrowsing.unsafe", "ja_nein", "sperr.safebrowsing"), F("Safe Browsing: ausgelassen", "safeBrowsing.skipped"),
                                        F("Cloudmersive: sauber", "cloudmersive.CleanResult", "ja_nein"), F("Cloudmersive: ausgelassen", "cloudmersive.skipped"),
                                        F("Ausgelassen", "skipped"))),),
    "txt-records": (A("TXT-Einträge", (F("Ausgelassen", "skipped"), T("Einträge", "", (F("Name", "#"), F("Wert", "")), "dns.txt_liste"))),),
    "whois": (A("Registrierung", (F("Domain", "domain"), F("Registrar", "registrar", s="reg.registrar"), F("Registriert am", "created", "zeit", "reg.erstellt"),
                                  F("Läuft ab am", "expires", "zeit", "reg.ablauf"), F("Geändert am", "updated", "zeit", "reg.geaendert"),
                                  F("Status", "status", "liste", "reg.status"), F("Nameserver", "nameservers", "liste", "reg.nameserver"), F("DNSSEC", "dnssec", s="reg.dnssec"),
                                  F("Adresse des Registrars", "registrarUrl"), F("Nummer des Registrars (IANA)", "registrarIanaId"), F("Whois-Server", "registrarWhoisServer"),
                                  F("Kennung im Register", "registryDomainId"), F("Ausgelassen", "skipped"), F("Meldung", "error"))),),
    # ---- aktive Prüfungen: Web-Check ruft das Ziel auf
    "carbon": (A("Grösse der Seite", (F("Übertragene Bytes", "statistics.adjustedBytes", "zahl", e="Bytes"), F("Energie", "statistics.energy", "zahl", e="kWh"),
                                      F("CO₂ je Aufruf", "statistics.co2.grid.grams", "zahl", e="g"), F("Sauberer als", "cleanerThan", "zahl"), F("Grüner Anbieter", "green", "ja_nein"))),),
    "cookies": (A("Cookies", (T("Cookies aus der Antwort", "headerCookies", (F("Cookie", ""),), "seite.cookies"),
                              T("Cookies im Browser", "clientCookies", (F("Name", "name"), F("Domain", "domain"), F("Pfad", "path"), F("Läuft ab", "expires", "zeit_s"),
                                                                        F("Nur HTTP", "httpOnly", "ja_nein"), F("Nur verschlüsselt", "secure", "ja_nein"), F("SameSite", "sameSite"))))),),
    "dns-server": (A("Nameserver", (F("Domain", "domain"), T("Server", "dns", (F("Adresse", "address"), F("Hostnamen", "hostname", "liste"), F("DNS über HTTPS", "dohDirectSupports", "ja_nein")), "dns.server"))),),
    "firewall": (A("Schutzdienst", (F("Schutzdienst erkannt", "hasWaf", "ja_nein", "host.waf", h="Ein vorgeschalteter Dienst, der Angriffe filtert und die echte Adresse des Servers verbergen kann."),
                                    F("Name des Dienstes", "waf", s="host.waf_name"))),),
    "headers": (A("Antwort des Servers", (T("Kopfzeilen", "", (F("Kopfzeile", "#"), F("Wert", "")), "seite.kopfzeilen", "Was der Webserver über sich und die Seite mitteilt."),)),),
    "hsts": (A("HSTS", (F("Vorgabe erfüllt", "compatible", "ja_nein"), F("Meldung", "message"), F("Kopfzeile", "hstsHeader"))),),
    "http-security": (A("Sicherheits-Kopfzeilen", (F("Strict-Transport-Security", "strictTransportPolicy", "ja_nein"), F("X-Frame-Options", "xFrameOptions", "ja_nein"),
                                                   F("X-Content-Type-Options", "xContentTypeOptions", "ja_nein"), F("X-XSS-Protection", "xXSSProtection", "ja_nein"),
                                                   F("Content-Security-Policy", "contentSecurityPolicy", "ja_nein"))),),
    "linked-pages": (A("Verweise der Seite", (F("Verweise nach innen", "internal", "liste", "seite.verweise_innen"), F("Verweise nach aussen", "external", "liste", "seite.verweise_aussen"))),),
    "location": (A("Standort des Servers", (F("Stadt", "city", s="ort.stadt"), F("Region", "region", s="ort.region"), F("Land", "country_name", s="ort.land"),
                                             F("Land (Kürzel)", "country_code", s="ort.land_code"), F("Postleitzahl", "postal"), F("Breite", "latitude", "zahl"), F("Länge", "longitude", "zahl"),
                                             F("Zeitzone", "timezone"), F("Organisation", "org", s="netz.inhaber"), F("AS", "asn", s="netz.as"), F("IP-Adresse", "ip", s="host.ip"))),),
    "mail-config": (A("Mail-Einrichtung", (T("MX (Mailserver)", "mxRecords", (F("Server", "exchange"), F("Vorrang", "priority", "zahl")), "dns.mx"),
                                           F("TXT-Einträge zur Mail", "txtRecords", "liste"), T("Erkannte Maildienste", "mailServices", (F("Dienst", "provider"), F("Wert", "value"))))),),
    "mixed-content": (A("Gemischte Inhalte", (F("Unverschlüsselt geladene Teile", "mixedContent", "liste"),)),),
    "ports": (A("Ports", (F("Offene Ports", "openPorts", "liste", "dienste.ports"), F("Geschlossene oder gefilterte Ports", "failedPorts", "liste"))),),
    "quality": (A("Qualität laut Lighthouse", (F("Leistung", "categories.performance.score", "zahl"), F("Zugänglichkeit", "categories.accessibility.score", "zahl"),
                                                F("Gute Praxis", "categories.best-practices.score", "zahl"), F("Auffindbarkeit", "categories.seo.score", "zahl"))),),
    "redirects": (A("Weiterleitungen", (F("Kette der Adressen", "redirects", "liste", "seite.weiterleitung"),)),),
    "robots-txt": (A("robots.txt", (T("Regeln", "robots", (F("Art", "lbl"), F("Wert", "val"))),)),),
    "screenshot": (A("Bildschirmfoto", (F("Bild (Base64)", "image", "lang", h="Das Bild liegt als Text in der Rohdatei. Die Oberfläche zeigt es in der Rohdaten-Ansicht."),)),),
    "security-txt": (A("security.txt", (F("Vorhanden", "isPresent", "ja_nein"), F("Gefunden unter", "foundIn"), F("Inhalt", "content", "lang"),
                                        F("Signiert", "isPgpSigned", "ja_nein"), T("Felder", "fields", (F("Feld", "#"), F("Wert", ""))))),),
    "sitemap": (A("Sitemap", (T("Seiten", "urlset.url", (F("Adresse", "loc.0"), F("Geändert", "lastmod.0", "zeit"), F("Häufigkeit", "changefreq.0"), F("Gewicht", "priority.0"))),)),),
    "social-presence": (A("Konten in sozialen Medien", (T("Verweise", "", (F("Plattform", "#"), F("Adresse", ""))),)),),
    "social-tags": (A("Angaben für soziale Medien", (F("Titel", "title", s="seite.titel"), F("Beschreibung", "description", "lang", "seite.beschreibung"), F("Stichwörter", "keywords"),
                                                     F("Adresse laut Seite", "canonicalUrl"), F("Titel (Open Graph)", "ogTitle"), F("Beschreibung (Open Graph)", "ogDescription", "lang"),
                                                     F("Bild (Open Graph)", "ogImage"), F("Seitenname", "ogSiteName"), F("Verfasser", "author"), F("Erzeugt mit", "generator", s="seite.technik"))),),
    "ssl": (A("Zertifikat", (F("Ausgestellt auf", "subject.CN", s="zert.cn"), F("Aussteller", "issuer.O", s="zert.aussteller"), F("Aussteller (Name der Stelle)", "issuer.CN", s="zert.aussteller_name"),
                             F("Gültig ab", "valid_from", "zeit", "zert.gueltig_ab"), F("Gültig bis", "valid_to", "zeit", "zert.gueltig_bis"),
                             F("Weitere Namen", "subjectaltname", s="zert.namen"), F("Fingerabdruck (SHA-256)", "fingerprint256", s="zert.fingerabdruck"),
                             F("Seriennummer", "serialNumber"), F("Schlüssellänge", "bits", "zahl", e="Bit"))),),
    "status": (A("Erreichbarkeit", (F("Erreichbar", "isUp", "ja_nein", "seite.erreichbar"), F("HTTP-Status", "responseCode", "zahl", "seite.status"),
                                    F("Dauer der DNS-Abfrage", "dnsLookupTime", "zahl", e="ms"), F("Antwortzeit", "responseTime", "zahl", e="ms"))),),
    "tech-stack": (A("Technik der Seite", (T("Erkannte Technik", "technologies", (F("Name", "name"), F("Version", "version"), F("Sicherheit", "confidence", "zahl", e="%"),
                                                                                  F("Beschreibung", "description", "lang"), F("Kategorien", "categories.*.name", "liste")), "seite.technik_liste"),)),),
    "tls-connection": (A("TLS-Verbindung", (F("Protokoll", "protocol"), F("Verschlüsselung", "cipher.name"), F("Version der Verschlüsselung", "cipher.version"),
                                             F("Ausgestellt auf", "certificate.subject.CN", s="zert.cn"), F("Aussteller", "certificate.issuer.O", s="zert.aussteller"),
                                             F("Gültig bis", "certificate.valid_to", "zeit", "zert.gueltig_bis"))),),
    "tls-labs": (A("TLS-Prüfung (SSL Labs)", (F("Host", "host"), F("Status", "status"), T("Endpunkte", "endpoints", (F("Adresse", "ipAddress"), F("Note", "grade"), F("Status", "statusMessage"))))),),
    "trace-route": (A("Weg zum Server", (T("Stationen", "result", (F("Nr.", "#"), F("Station", "")), h="Jede Station ist ein Router auf dem Weg vom Web-Check zum Ziel."),
                                         F("Dauer", "timeTaken", "zahl", e="ms"), F("Meldung", "message"))),),
    "trackers": (A("Tracker", (T("Erkannte Tracker", "trackers", (F("Name", "name"), F("Kategorie", "category"), F("Adresse", "url"))), F("Zahl", "count", "zahl"))),),
}
WEBCHECK_PASSIV = ("archives", "block-lists", "breaches", "caa-records", "dns", "dnssec", "get-ip", "rank", "shodan", "subdomains", "threats", "txt-records", "whois")

_D = (
    # ---- Infrastruktur
    Darsteller("shodan_host", "Shodan: Dienste und Betreiber einer IP", ("ip",), (
        A("Netz und Inhaber", (F("AS-Nummer", "asn", s="netz.as"), F("Organisation", "org", s="netz.inhaber"), F("Anbieter", "isp", s="netz.isp"),
                               F("Hostnamen", "hostnames", "liste", "namen.hostnamen"), F("Domains", "domains", "liste", "namen.domains"))),
        A("Standort", (F("Land", "country_name", s="ort.land"), F("Land (Kürzel)", "country_code", s="ort.land_code"), F("Region", "region_code", s="ort.region"),
                       F("Stadt", "city", s="ort.stadt"), F("Breite", "latitude", "zahl"), F("Länge", "longitude", "zahl"))),
        A("Dienste und Ports", (F("Offene Ports", "ports", "liste", "dienste.ports", h="Ein Port ist eine Tür am Server. Hinter jeder offenen Tür antwortet ein Dienst."),
                                F("Betriebssystem", "os", s="dienste.betriebssystem"), F("Merkmale", "tags", "liste", "dienste.merkmale"),
                                F("Bekannte Schwachstellen", "vulns", "liste", "dienste.schwachstellen"), F("Stand bei Shodan", "last_update", "zeit", "zeit.letzte_sichtung"),
                                T("Dienste", "data", (F("Port", "port", "zahl"), F("Protokoll", "transport"), F("Software", "product"), F("Version", "version"),
                                                      F("Titel der Seite", "http.title"), F("Server", "http.server"), F("Zertifikat für", "ssl.cert.subject.CN"),
                                                      F("Aussteller", "ssl.cert.issuer.CN"), F("Zertifikat bis", "ssl.cert.expires"), F("Gesehen", "timestamp", "zeit")), "dienste.liste"))),
    )),
    Darsteller("shodan_internetdb", "Shodan InternetDB: Schnellübersicht einer IP", ("ip",), (
        A("Dienste und Ports", (F("IP-Adresse", "ip"), F("Offene Ports", "ports", "liste", "dienste.ports"), F("Hostnamen", "hostnames", "liste", "namen.hostnamen"),
                                F("Merkmale", "tags", "liste", "dienste.merkmale"), F("Bekannte Schwachstellen", "vulns", "liste", "dienste.schwachstellen"),
                                F("Erkannte Software (CPE)", "cpes", "liste", "dienste.software"))),)),
    Darsteller("shodan_dns", "Shodan: DNS-Einträge und Subdomains", ("domain",), (
        A("DNS", (F("Domain", "domain"), F("Subdomains", "subdomains", "liste", "verwandt.subdomains"), F("Merkmale", "tags", "liste"),
                  T("Einträge", "data", (F("Subdomain", "subdomain"), F("Typ", "type"), F("Wert", "value"), F("Zuletzt gesehen", "last_seen", "zeit")), "dns.eintraege"),
                  F("Weitere Einträge vorhanden", "more", "ja_nein"))),)),
    Darsteller("shodan_suche", "Shodan: Suche", ("ip", "domain", "hash", "sonstiges"), (
        A("Treffer", (F("Zahl der Treffer", "total", "zahl"),
                      T("Hosts", "matches", (F("IP-Adresse", "ip_str"), F("Port", "port", "zahl"), F("Organisation", "org"), F("Hostnamen", "hostnames", "liste"),
                                             F("Land", "location.country_name"), F("Software", "product"), F("Gesehen", "timestamp", "zeit")), "verwandt.hosts"))),
        A("Verteilung", (T("Nach Land", "facets.country", (F("Land", "value"), F("Hosts", "count", "zahl"))),
                         T("Nach Port", "facets.port", (F("Port", "value"), F("Hosts", "count", "zahl"))),
                         T("Nach Organisation", "facets.org", (F("Organisation", "value"), F("Hosts", "count", "zahl"))))),
    )),
    Darsteller("spur_kontext", "Spur: VPN, Proxy, Tor", ("ip",), _SPUR),
    Darsteller("abuseipdb_pruefen", "AbuseIPDB: Missbrauchsmeldungen zu einer IP", ("ip",), _ABUSE),
    Darsteller("abuseipdb_meldungen", "AbuseIPDB: einzelne Meldungen", ("ip",), (
        A("Meldungen", (F("Zahl der Meldungen", "data.total", "zahl", "ruf.meldungen"), F("Seite", "data.page", "zahl"), F("Meldungen auf dieser Seite", "data.count", "zahl"),
                        F("Meldungen je Seite", "data.perPage", "zahl"), F("Letzte Seite", "data.lastPage", "zahl"),
                        T("Einzelne Meldungen", "data.results", (F("Gemeldet am", "reportedAt", "zeit"), F("Kategorien", "categories", "liste"), F("Bemerkung des Melders", "comment", "lang"),
                                                                 F("Land des Melders", "reporterCountryCode"), F("Land des Melders (Name)", "reporterCountryName"),
                                                                 F("Nummer des Melders", "reporterId", "zahl")), "ruf.meldungen_liste",
                          "Die Bemerkungen stammen von Dritten. Sie sind Beweismaterial, keine geprüfte Tatsache."))),)),
    Darsteller("ip_einordnung", "Einordnung einer IP: Netz, Inhaber, Anonymisierungsdienst", ("ip",), (
        A("Anonymisierungsdienst", (F("Ausgang eines Anonymisierungsdienstes", "anonymisierung.wert", s="anon.wert",
                                      h="«ja», «kein Hinweis» oder «nicht geprüft». «Kein Hinweis» ist kein «nein»: Die Quellen erkennen Residential Proxies nur lückenhaft."),
                                    F("Genannte Dienste", "anonymisierung.dienste", "liste", "anon.dienste"), F("Arten", "anonymisierung.arten", "liste", "anon.arten"),
                                    F("Residential Proxy", "anonymisierung.residential", "ja_nein", "anon.residential",
                                      h="Ein Dienst, der den Verkehr über private Anschlüsse Unbeteiligter leitet."),
                                    F("Geantwortet haben", "anonymisierung.geantwortet", "liste"),
                                    T("Nicht geantwortet haben", "anonymisierung.nicht_geantwortet", (F("Quelle", "quelle"), F("Grund", "grund"))),
                                    T("Aussagen der Quellen", "anonymisierung.aussagen", (F("Quelle", "quelle"), F("Anonymisierungsdienst", "anonymisierung"), F("Arten", "arten", "liste"),
                                                                                          F("Dienst", "dienst"), F("Residential", "residential", "ja_nein"), F("Erste Sichtung", "erste_sichtung", "zeit"),
                                                                                          F("Letzte Sichtung", "letzte_sichtung", "zeit"), F("Zur Tatzeit", "zur_tatzeit"), F("Beleg", "beleg")), "anon.stimmen"),
                                    F("Erklärung", "erklaerung", "lang", "anon.erklaerung"), F("Ansatzpunkt", "ansatzpunkt", "lang", "anon.ansatzpunkt"),
                                    F("Hinweise", "hinweise", "liste"))),
        A("Netz und Inhaber", (F("IP-Adresse", "ip"), F("Abfragezeit", "abfragezeit", "zeit"), F("Tatzeit", "tatzeit", "zeit", "anon.tatzeit"),
                               F("Präfix", "netz.praefix", s="netz.praefix", h="Der Adressbereich, zu dem die IP gehört."),
                               F("AS-Nummer", "netz.as", s="netz.as", h="Autonomes System: das Netz eines Anbieters."), F("AS-Inhaber", "netz.as_inhaber", s="netz.as_inhaber"),
                               F("Im Internet angekündigt", "netz.angekuendigt", "ja_nein"), F("Bereich im Register", "netz.bereich"), F("Netzname", "netz.netzname", s="netz.netzname"),
                               F("Organisation", "netz.organisation", s="netz.organisation"), F("Inhaber", "netz.inhaber", s="netz.inhaber"), F("Betreiber", "netz.betreiber", s="netz.betreiber"),
                               F("Land laut Register", "netz.land", s="netz.land"), F("Status im Register", "netz.status"), F("Registriert", "netz.registriert", "zeit"),
                               F("Geändert", "netz.geaendert", "zeit"), F("Register", "netz.register", s="netz.register"), F("Meldestelle", "netz.meldestelle", "liste", "netz.meldestelle"),
                               T("Art des Anschlusses", "anschlussart", (F("Quelle", "quelle"), F("Art", "art")), "netz.anschlussart"),
                               T("Zur Tatzeit", "netz.zur_tatzeit", (F("Angabe", "#"), F("Wert", ""))))),
        A("Stand der Quellen", (T("Befragte Quellen", "quellenstand", (F("Quelle", "#"), F("Stand", "status"), F("Beleg", "beleg"), F("Meldung", "fehler"))),)),
    ), wurzel="befund"),
    # ---- VirusTotal
    Darsteller("virustotal_ip", "VirusTotal: IP-Adresse", ("ip",), (
        A("Einschätzung", (*_vt_urteil("data.attributes.last_analysis_stats"), F("Ruf laut Gemeinschaft", "data.attributes.reputation", "zahl", "ruf.vt_ruf"),
                           F("Stimmen bösartig", "data.attributes.total_votes.malicious", "zahl"), F("Stimmen harmlos", "data.attributes.total_votes.harmless", "zahl"),
                           F("Merkmale", "data.attributes.tags", "liste"), F("Zuletzt geprüft", "data.attributes.last_analysis_date", "zeit_s", "zeit.letzte_pruefung"))),
        A("Netz und Inhaber", (F("AS-Nummer", "data.attributes.asn", "zahl", "netz.as"), F("AS-Inhaber", "data.attributes.as_owner", s="netz.as_inhaber"),
                               F("Netz", "data.attributes.network", s="netz.praefix"), F("Land", "data.attributes.country", s="ort.land_code"), F("Kontinent", "data.attributes.continent"),
                               F("Register", "data.attributes.regional_internet_registry", s="netz.register"), F("Whois vom", "data.attributes.whois_date", "zeit_s"),
                               F("Whois", "data.attributes.whois", "lang"))),
        A("Zertifikat", (*_VT_ZERT, F("JARM-Fingerabdruck", "data.attributes.jarm", s="zert.jarm", h="Ein Fingerabdruck der TLS-Einstellungen eines Servers. Gleiche Werte deuten auf gleiche Einrichtung."))),
        A("Geschichte", (F("Erstmals gesehen", "data.attributes.first_seen_date", "zeit_s", "zeit.erste_sichtung"), F("Eintrag geändert", "data.attributes.last_modification_date", "zeit_s"))),
    )),
    Darsteller("virustotal_domain", "VirusTotal: Domain", ("domain",), (
        A("Einschätzung", (*_vt_urteil("data.attributes.last_analysis_stats"), F("Ruf laut Gemeinschaft", "data.attributes.reputation", "zahl", "ruf.vt_ruf"),
                           F("Kategorien", "data.attributes.categories.*", "liste", "ruf.kategorien"), F("Merkmale", "data.attributes.tags", "liste"),
                           F("Zuletzt geprüft", "data.attributes.last_analysis_date", "zeit_s", "zeit.letzte_pruefung"),
                           T("Rang", "data.attributes.popularity_ranks", (F("Liste", "#"), F("Rang", "rank", "zahl"), F("Stand", "timestamp", "zeit_s")), "ruf.rang"))),
        A("Registrierung", (F("Registrar", "data.attributes.registrar", s="reg.registrar"), F("Registriert am", "data.attributes.creation_date", "zeit_s", "reg.erstellt"),
                            F("Läuft ab am", "data.attributes.expiration_date", "zeit_s", "reg.ablauf"), F("Geändert am", "data.attributes.last_update_date", "zeit_s", "reg.geaendert"),
                            F("Endung", "data.attributes.tld"), F("Whois vom", "data.attributes.whois_date", "zeit_s"), F("Whois", "data.attributes.whois", "lang"))),
        A("DNS", (T("DNS-Einträge", "data.attributes.last_dns_records", (F("Typ", "type"), F("Wert", "value"), F("TTL", "ttl", "zahl", e="Sekunden"), F("Vorrang", "priority", "zahl")), "dns.eintraege"),
                  F("DNS gelesen am", "data.attributes.last_dns_records_date", "zeit_s"))),
        A("Zertifikat", (*_VT_ZERT, F("JARM-Fingerabdruck", "data.attributes.jarm", s="zert.jarm"))),
        A("Geschichte", (F("Eintrag geändert", "data.attributes.last_modification_date", "zeit_s"),)),
    )),
    Darsteller("virustotal_url", "VirusTotal: URL", ("url",), (
        A("Einschätzung", (*_vt_urteil("data.attributes.last_analysis_stats"), F("Ruf laut Gemeinschaft", "data.attributes.reputation", "zahl", "ruf.vt_ruf"),
                           F("Kategorien", "data.attributes.categories.*", "liste", "ruf.kategorien"), F("Namen der Bedrohung", "data.attributes.threat_names", "liste", "ruf.bedrohung"),
                           F("Merkmale", "data.attributes.tags", "liste"), F("Zuletzt geprüft", "data.attributes.last_analysis_date", "zeit_s", "zeit.letzte_pruefung"))),
        A("Inhalt der Seite", (F("Adresse", "data.attributes.url"), F("Endadresse nach Weiterleitungen", "data.attributes.last_final_url", s="seite.endadresse"),
                               F("Titel", "data.attributes.title", s="seite.titel"), F("HTTP-Status", "data.attributes.last_http_response_code", "zahl", "seite.status"),
                               F("Grösse der Antwort", "data.attributes.last_http_response_content_length", "bytes"),
                               F("Prüfsumme der Antwort (SHA-256)", "data.attributes.last_http_response_content_sha256", s="seite.sha256"),
                               T("Kopfzeilen der Antwort", "data.attributes.last_http_response_headers", (F("Kopfzeile", "#"), F("Wert", "")), "seite.kopfzeilen"),
                               F("Weiterleitungen", "data.attributes.redirection_chain", "liste", "seite.weiterleitung"), F("Nachgeahmte Marke", "data.attributes.targeted_brand.*", "liste"))),
        A("Geschichte", (F("Erstmals eingereicht", "data.attributes.first_submission_date", "zeit_s", "zeit.erste_sichtung"),
                         F("Zuletzt eingereicht", "data.attributes.last_submission_date", "zeit_s", "zeit.letzte_sichtung"), F("Zahl der Einreichungen", "data.attributes.times_submitted", "zahl"))),
    )),
    Darsteller("virustotal_datei", "VirusTotal: Datei", ("hash",), (
        A("Erkennung", (*_vt_urteil("data.attributes.last_analysis_stats"), F("Vorgeschlagene Bezeichnung", "data.attributes.popular_threat_classification.suggested_threat_label", s="ruf.familie"),
                        T("Familien laut Scannern", "data.attributes.popular_threat_classification.popular_threat_name", (F("Name", "value"), F("Nennungen", "count", "zahl"))),
                        T("Kategorien laut Scannern", "data.attributes.popular_threat_classification.popular_threat_category", (F("Kategorie", "value"), F("Nennungen", "count", "zahl"))),
                        F("Ruf laut Gemeinschaft", "data.attributes.reputation", "zahl", "ruf.vt_ruf"), F("Merkmale", "data.attributes.tags", "liste", "datei.merkmale"),
                        F("Zuletzt geprüft", "data.attributes.last_analysis_date", "zeit_s", "zeit.letzte_pruefung"))),
        A("Datei", (F("Gebräuchlicher Name", "data.attributes.meaningful_name", s="datei.name"), F("Alle Namen", "data.attributes.names", "liste", "datei.namen"),
                    F("Grösse", "data.attributes.size", "bytes", "datei.groesse"), F("Typ", "data.attributes.type_description", s="datei.typ"), F("Typ (Kürzel)", "data.attributes.type_tag"),
                    F("Dateiendung", "data.attributes.type_extension"), F("Magic", "data.attributes.magic"), F("MD5", "data.attributes.md5", s="datei.md5"),
                    F("SHA-1", "data.attributes.sha1", s="datei.sha1"), F("SHA-256", "data.attributes.sha256", s="datei.sha256"), F("SSDEEP", "data.attributes.ssdeep"), F("TLSH", "data.attributes.tlsh"))),
        A("Geschichte", (F("Erstmals eingereicht", "data.attributes.first_submission_date", "zeit_s", "zeit.erste_sichtung"),
                         F("Zuletzt eingereicht", "data.attributes.last_submission_date", "zeit_s", "zeit.letzte_sichtung"), F("Zahl der Einreichungen", "data.attributes.times_submitted", "zahl"),
                         F("Erstellt laut Datei", "data.attributes.creation_date", "zeit_s"), F("Erstmals in freier Wildbahn", "data.attributes.first_seen_itw_date", "zeit_s"))),
    )),
    Darsteller("virustotal_beziehungen", "VirusTotal: Verknüpfungen", ("ip", "domain", "url", "hash"), (
        A("Verknüpfte Einträge", (F("Zahl insgesamt", "meta.count", "zahl"),
                                  T("Einträge", "data", (F("Kennung", "id"), F("Art", "type"), F("IP-Adresse", "attributes.ip_address"), F("Hostname", "attributes.host_name"),
                                                         F("Datum", "attributes.date", "zeit_s"), F("Adresse", "attributes.url"), F("Name", "attributes.meaningful_name"),
                                                         F("Bösartig laut", "attributes.last_analysis_stats.malicious", "zahl"), F("Auflöser", "attributes.resolver")), "verwandt.vt"),
                                  F("Weitere Einträge ab", "meta.cursor"))),)),
    # ---- Websites
    Darsteller("urlquery_suche", "urlquery: vorhandene Berichte", ("domain", "url", "ip"), (
        A("Treffer", (F("Suchtext", "query"), F("Zahl der Treffer", "total_hits", "zahl"), F("Dauer", "time_used"),
                      T("Berichte", "reports", (F("Bericht", "report_id"), F("Datum", "date", "zeit"), F("Status", "status"), F("Adresse", "url.addr"), F("Domain", "url.fqdn"),
                                                F("IP-Adresse", "ip.addr"), F("AS", "ip.as"), F("Land", "ip.country"), F("Titel", "final.title"), F("Merkmale", "tags", "liste")), "zeit.berichte"))),)),
    Darsteller("urlquery_bericht", "urlquery: Bericht der Sandbox", ("url", "domain"), (
        A("Inhalt der Seite", (F("Bericht", "report_id"), F("Datum", "date", "zeit", "zeit.letzte_pruefung"), F("Status", "status"), F("Aufgerufene Adresse", "url.addr"),
                               F("Endadresse", "final.url.addr", s="seite.endadresse"), F("Titel", "final.title", s="seite.titel"), F("Grösse der Seite", "final.dom.size", "bytes"),
                               F("Typ", "final.dom.mime_type"), F("Prüfsumme der Seite (SHA-256)", "final.dom.sha256", s="seite.sha256"),
                               F("Seite erstmals gesehen", "final.dom.first_seen", "zeit", "zeit.erste_sichtung"), F("Seite zuletzt gesehen", "final.dom.last_seen", "zeit", "zeit.letzte_sichtung"),
                               F("Wie oft gesehen", "final.dom.times_seen", "zahl"), F("Merkmale", "tags", "liste"))),
        A("Hosting", (F("IP-Adresse", "ip.addr", s="host.ip"), F("AS-Nummer", "ip.asn", "zahl", "netz.as"), F("AS", "ip.as", s="netz.as_inhaber"), F("Land", "ip.country", s="ort.land"),
                      F("Land (Kürzel)", "ip.country_code", s="ort.land_code"))),
        A("Alarme", (T("Alarme der Sensoren", "detection.analyzer", (F("Sensor", "sensor_name"), F("Alarm", "alert"), F("Urteil", "verdict"), F("Auslöser", "trigger"),
                                                                     F("Beschreibung", "description", "lang"), F("Datum", "date", "zeit")), "ruf.alarme"),
                     T("Alarme der Netzüberwachung", "detection.ids", (F("Alarm", "alert"), F("Stufe", "severity"), F("Datum", "date", "zeit"))),
                     T("Alarme von urlquery", "detection.urlquery", (F("Alarm", "alert"), F("Urteil", "verdict"))))),
        A("Aufrufe der Seite", (T("Kontaktierte Hosts", "summary", (F("Host", "fqdn"), F("IP-Adresse", "ip.addr"), F("Land", "ip.country"), F("Domain registriert", "domain_registered", "zeit"),
                                                                   F("Rang", "domain_rank", "zahl"), F("Alarme", "alert_count", "zahl"), F("Aufrufe", "request_count", "zahl"),
                                                                   F("Empfangen", "received_data", "bytes"), F("Gesendet", "sent_data", "bytes")), "seite.hosts"),)),
        A("Einstellungen des Aufrufs", (F("Sichtbarkeit", "settings.access"), F("Gerät", "settings.device_type"), F("Browserkennung", "settings.useragent", "lang"),
                                        F("Ausgang", "settings.exit_node"), F("Läuft ab", "settings.expires_at", "zeit"))),
    )),
    Darsteller("urlquery_reputation", "urlquery: Ruf einer URL", ("url",), (
        A("Ruf", (F("Adresse", "url"), F("Urteil", "verdict", s="ruf.urlquery"), F("Einzelheiten", "details"))),)),
    Darsteller("urlquery_einreichen", "urlquery: Einreichung (aktiv)", ("url",), (
        A("Einreichung", (F("Kennung der Einreichung", "queue_id"), F("Status", "status"), F("Bericht", "report_id"), F("Adresse", "url.addr"), F("Sichtbarkeit", "settings.access"))),)),
    Darsteller("urlquery_status", "urlquery: Stand einer Einreichung", ("url",), (
        A("Stand", (F("Kennung der Einreichung", "queue_id"), F("Status", "status"), F("Bericht", "report_id"), F("Adresse", "url.addr"))),)),
    Darsteller("urlscan_suche", "urlscan.io: vorhandene Scans", ("domain", "url", "ip", "hash"), (
        A("Treffer", (F("Zahl der Treffer", "total", "zahl"), F("Dauer", "took", "zahl", e="ms"), F("Weitere Treffer vorhanden", "has_more", "ja_nein"),
                      F("Durchsuchter Zeitraum", "search_date_limit_days", "zahl", e="Tage"),
                      T("Scans", "results", (F("Scan", "_id"), F("Zeit", "task.time", "zeit"), F("Adresse", "page.url"), F("Domain", "page.domain"), F("IP-Adresse", "page.ip"),
                                             F("AS", "page.asnname"), F("Land", "page.country"), F("Server", "page.server"), F("Titel", "page.title"), F("Status", "page.status"),
                                             F("Sichtbarkeit", "task.visibility"), F("Eingereicht über", "task.method"), F("Aufrufe", "stats.requests", "zahl")), "zeit.scans"))),)),
    Darsteller("urlscan_ergebnis", "urlscan.io: Ergebnis eines Scans", ("url", "domain"), (
        A("Inhalt der Seite", (F("Scan", "uuid"), F("Zeit des Scans", "zeit", "zeit", "zeit.letzte_pruefung"), F("Sichtbarkeit", "sichtbarkeit"), F("Eingereicht über", "methode"),
                               F("Eingereichte Adresse", "eingereicht"), F("Adresse der Seite", "seite.url", s="seite.endadresse"), F("Titel", "seite.titel", s="seite.titel"),
                               F("HTTP-Status", "seite.status", s="seite.status"), F("Server", "seite.server", s="seite.server"), F("Umgeleitet", "seite.umgeleitet", s="seite.weiterleitung"),
                               F("Bildschirmfoto", "bildschirmfoto.rohdaten", s="seite.bildschirmfoto", h="Das Bild liegt in den Rohdaten des Falls. Die Seite selbst wurde nicht aufgerufen."),
                               F("Beleg des Bildschirmfotos", "bildschirmfoto.beleg"), F("Hinweis zum Bild", "bildschirmfoto.hinweis"),
                               F("Seitentext", "seitentext.text", "lang", "seite.text", h="Der Text der Seite, wie der Scanner ihn sah. Fremdinhalt, als Text gezeigt."),
                               F("Rohdatei des Seitentexts", "seitentext.rohdaten"), F("Beleg des Seitentexts", "seitentext.beleg"), F("Hinweis zum Seitentext", "seitentext.hinweis"),
                               F("Zahl der Aufrufe", "anfragen_anzahl", "zahl"), F("Zahl der Cookies", "cookies_anzahl", "zahl"), F("Meldungen der Konsole", "konsole_anzahl", "zahl"),
                               F("Zahl der Verweise", "links_anzahl", "zahl"), T("Verweise", "links", (F("Adresse", "href"), F("Text", "text"))))),
        A("Hosting", (F("Domain", "seite.domain"), F("IP-Adresse", "seite.ip", s="host.ip"), F("AS-Nummer", "seite.asn", s="netz.as"), F("Netz", "seite.netz", s="netz.as_inhaber"),
                      F("Land", "seite.land", s="ort.land_code"), F("Ort", "seite.ort", s="ort.stadt"), F("Alter der Domain", "seite.domain_alter_tage", "zahl", "reg.alter_tage", "Tage"),
                      F("Zertifikat ausgestellt von (Name der Stelle)", "seite.tls_aussteller", s="zert.aussteller_name"), F("Zertifikat gültig für", "seite.tls_gueltig_tage", "zahl", e="Tage"),
                      F("Alter des Zertifikats", "seite.tls_alter_tage", "zahl", "zert.alter_tage", "Tage"))),
        A("Urteil", (F("Gesamturteil: bösartig", "urteil.gesamt.boesartig", "ja_nein", "ruf.urlscan"), F("Gesamturteil: Punkte", "urteil.gesamt.punkte", "zahl"),
                     F("urlscan: bösartig", "urteil.urlscan.boesartig", "ja_nein"), F("urlscan: Punkte", "urteil.urlscan.punkte", "zahl"),
                     T("Prüfdienste", "urteil.pruefdienste", (F("Angabe", "#"), F("Wert", ""))), T("Gemeinschaft", "urteil.gemeinschaft", (F("Angabe", "#"), F("Wert", ""))))),
        A("Was die Seite kontaktierte", (F("IP-Adressen", "kontaktiert.ips", "liste", "seite.kontakt_ips"), F("Domains", "kontaktiert.domains", "liste", "seite.kontakt_domains"),
                                         F("AS", "kontaktiert.asns", "liste"), F("Server", "kontaktiert.servers", "liste"), F("Adressen", "kontaktiert.urls", "liste"),
                                         F("Domains der Verweise", "kontaktiert.linkDomains", "liste"), F("Zahl der IP-Adressen", "kontaktiert.ips_anzahl", "zahl"),
                                         F("Zahl der Domains", "kontaktiert.domains_anzahl", "zahl"), T("Zähler", "zaehler", (F("Angabe", "#"), F("Wert", ""))))),
    ), wurzel="befund"),
    Darsteller("urlscan_kontingent", "urlscan.io: Kontingent", ("sonstiges",), (
        A("Kontingent", (F("Geltung", "geltung"), F("Kurz", "kurz"), T("Stand", "stand", (F("Aktion", "#"), F("Heute verbraucht", "heute.used", "zahl"), F("Heute Grenze", "heute.limit", "zahl"), F("Heute übrig", "heute.remaining", "zahl"),
                                               F("Stunde verbraucht", "diese Stunde.used", "zahl"), F("Stunde Grenze", "diese Stunde.limit", "zahl"),
                                               F("Stunde übrig", "diese Stunde.remaining", "zahl"), F("Minute verbraucht", "diese Minute.used", "zahl"),
                                               F("Minute Grenze", "diese Minute.limit", "zahl"), F("Minute übrig", "diese Minute.remaining", "zahl")),
                           h="Wie viele Suchen, Abrufe und Scans das Konto bei urlscan.io noch frei hat."))),), wurzel="befund"),
    Darsteller("urlscan_einreichen", "urlscan.io: Einreichung (aktiv)", ("url",), (
        A("Einreichung", (F("Scan", "uuid"), F("Sichtbarkeit", "sichtbarkeit"), F("Adresse", "url"), F("Meldung", "meldung"), F("Ergebnis abrufbar unter", "ergebnis"),
                          F("Hinweise", "hinweise", "liste"))),), wurzel="befund"),
    Darsteller("wayback_verlauf", "Wayback Machine: frühere Stände", ("url", "domain"), (
        A("Stände im Archiv", (T("Stände", "", (F("Zeitstempel", "0"), F("Adresse", "1"), F("Typ", "2"), F("HTTP-Status", "3"), F("Prüfsumme", "4"), F("Grösse", "5")), "zeit.wayback",
                                 "Jede Zeile ist ein gespeicherter Stand. Die erste Zeile nennt die Spalten, so liefert es das Archiv."),)),)),
    Darsteller("wayback_abruf", "Wayback Machine: gespeicherter Stand", ("url", "domain"), ()),
    Darsteller("wayback_sichern", "Wayback Machine: Sicherung (aktiv)", ("url",), (
        A("Sicherung", (F("Adresse im Archiv", "url"), F("Kennung des Auftrags", "job_id"), F("Meldung", "message"), F("Status", "status"))),)),
    # ---- Szene
    Darsteller("ransomware_gruppe", "ransomware.live: Profil einer Gruppe", ("gruppe",), (
        A("Profil", (F("Gruppe", "group", s="gruppe.name"), F("Beschreibung", "description", "lang", "gruppe.beschreibung"), F("Zahl der Opfer", "victims", "zahl", "gruppe.opfer"),
                     F("Erstmals gesehen", "firstseen", "zeit", "zeit.erste_sichtung"), F("Zuletzt gesehen", "lastseen", "zeit", "zeit.letzte_sichtung"),
                     F("Aufgenommen am", "added_date", "zeit"), F("Verhandlungen bekannt", "has_negotiations", "ja_nein"), F("Zahl der Verhandlungen", "negotiation_count", "zahl"),
                     F("Erpresserschreiben bekannt", "has_ransomnote", "ja_nein"), F("Vorgehen (TTP)", "ttps", "liste"), F("Ausgenutzte Schwachstellen", "vulnerabilities", "liste"))),
        A("Leak-Seiten", (T("Seiten der Gruppe", "locations", (F("Adresse", "fqdn"), F("Titel", "title"), F("Art", "type"), F("Erreichbar", "available", "ja_nein"),
                                                              F("Captcha", "captcha", "ja_nein"), F("Beschlagnahmt", "seized", "ja_nein")), "gruppe.seiten",
                            "Adressen im Tor-Netz. Sie stehen hier als Text und werden von der Oberfläche nie aufgerufen."),)),
        A("Werkzeuge", (T("Werkzeuge nach Zweck", "tools", (F("Zweck", "#"), F("Werkzeuge", "", "liste")), "gruppe.werkzeuge"),)),
    )),
    Darsteller("ransomware_opfer", "ransomware.live: Opferliste", ("gruppe", "domain", "sonstiges"), (
        A("Opfer", (F("Zahl der Einträge", "count", "zahl"), F("Filter: Gruppe", "filters.group"), F("Filter: Land", "filters.country"), F("Filter: Branche", "filters.sector"),
                    F("Filter: Jahr", "filters.year"), F("Filter: Monat", "filters.month"), F("Filter: Datum", "filters.date"), T("Einträge", "victims", _RL_OPFER, "gruppe.opfer_liste"))),)),
    Darsteller("ransomware_aktuell", "ransomware.live: neueste Opfer", ("sonstiges",), (
        A("Neueste Einträge", (F("Zahl der Einträge", "count", "zahl"), F("Reihenfolge", "order"), T("Einträge", "victims", _RL_OPFER))),)),
    Darsteller("ransomware_iocs", "ransomware.live: Indikatoren einer Gruppe", ("gruppe",), (
        A("Indikatoren der Gruppe", (F("Gruppe", "group"), F("Arten", "ioc_types", "liste"), T("Indikatoren nach Art", "iocs", (F("Art", "#"), F("Werte", "", "liste")), "gruppe.iocs"))),)),
    Darsteller("onion_sperrliste", "Ahmia: Sperrliste für Onion-Adressen", ("onion",), ()),
    Darsteller("telegram_kanal", "Telegram: Web-Vorschau eines Kanals", ("konto", "sonstiges"), ()),
    Darsteller("telegram_kanalinfo", "Telegram: Stammdaten eines Kanals", ("konto",), (
        A("Stammdaten", (F("Name", "title", s="konto.name"), F("Benutzername", "username", s="konto.kennung"), F("Beschreibung", "description", "lang", "konto.beschreibung"),
                         F("Abonnenten", "subscribers", "zahl", "konto.folgende"), F("Geprüft", "verified", "ja_nein"), F("Kennung", "id"))),)),
    Darsteller("telegram_entitaet", "Telegram: Konto oder Kanal (Personenbezug)", ("konto",), (
        A("Stammdaten", (F("Art", "type"), F("Name", "title", s="konto.name"), F("Benutzername", "username", s="konto.kennung"), F("Beschreibung", "about", "lang", "konto.beschreibung"),
                         F("Kennung", "id"), F("Geprüft", "verified", "ja_nein"), F("Als Betrug markiert", "scam", "ja_nein"))),)),
    Darsteller("telegram_suche", "Telegram: Suche (Personenbezug)", ("konto", "sonstiges"), (
        A("Treffer", (T("Kanäle und Konten", "results", (F("Name", "title"), F("Benutzername", "username"), F("Art", "type"), F("Abonnenten", "subscribers", "zahl"))),)),)),
    Darsteller("chan_katalog", "4chan: Katalog eines Boards", ("sonstiges",), (
        A("Threads", (T("Threads", "*.threads", (F("Nummer", "no", "zahl"), F("Betreff", "sub"), F("Text", "com", "lang"), F("Zeit", "time", "zeit_s"), F("Zeit laut Forum", "now"),
                                               F("Name", "name"), F("Antworten", "replies", "zahl"), F("Bilder", "images", "zahl"), F("Letzte Änderung", "last_modified", "zeit_s"),
                                               F("Kurzadresse", "semantic_url"), F("Dateiname", "filename"), F("Endung", "ext"), F("Prüfsumme des Bildes (MD5)", "md5"))),)),)),
    Darsteller("chan_thread", "4chan: gesicherter Thread", ("sonstiges",), (
        A("Beiträge", (T("Beiträge", "posts", (F("Nummer", "no", "zahl"), F("Zeit", "time", "zeit_s"), F("Name", "name"), F("Betreff", "sub"), F("Text", "com", "lang"),
                                               F("Dateiname", "filename"), F("Endung", "ext"), F("Prüfsumme des Bildes (MD5)", "md5"), F("Antwort auf", "resto", "zahl")), "konto.beitraege",
                         "Texte Dritter aus einem öffentlichen Forum. Beweismaterial, keine geprüfte Tatsache."),)),)),
    Darsteller("mastodon_instanz", "Mastodon: Instanz", ("domain", "konto"), (
        A("Instanz", (F("Domain", "domain"), F("Titel", "title", s="konto.name"), F("Software-Version", "version", s="seite.technik"), F("Beschreibung", "description", "lang", "konto.beschreibung"),
                      F("Aktive Konten im Monat", "usage.users.active_month", "zahl", "konto.folgende"), F("Sprachen", "languages", "liste"),
                      F("Anmeldung offen", "registrations.enabled", "ja_nein"), F("Anmeldung mit Freigabe", "registrations.approval_required", "ja_nein"),
                      F("Kontakt-E-Mail", "contact.email"), T("Regeln", "rules", (F("Nr.", "id"), F("Regel", "text", "lang"))))),)),
    Darsteller("mastodon_konto", "Mastodon: Konto (Personenbezug)", ("konto",), (
        A("Stammdaten", (F("Benutzername", "acct", s="konto.kennung"), F("Anzeigename", "display_name", s="konto.name"), F("Beschreibung", "note", "lang", "konto.beschreibung"),
                         F("Erstellt am", "created_at", "zeit", "zeit.erste_sichtung"), F("Folgende", "followers_count", "zahl", "konto.folgende"), F("Folgt", "following_count", "zahl"),
                         F("Beiträge", "statuses_count", "zahl"), F("Letzter Beitrag", "last_status_at", "zeit", "zeit.letzte_sichtung"), F("Automatisches Konto", "bot", "ja_nein"),
                         F("Gesperrt", "locked", "ja_nein"), T("Felder des Profils", "fields", (F("Feld", "name"), F("Wert", "value"), F("Geprüft am", "verified_at", "zeit"))))),)),
    # ---- Blockchain
    Darsteller("krypto_adresse_pruefen", "Adresse oder Transaktions-ID prüfen", ("wallet", "transaktion"), (
        A("Prüfung der Schreibweise", (F("Eingabe", "eingabe"), F("Art", "art", s="krypto.art"), F("Format", "format", s="krypto.format"), F("Familie", "familie"),
                                       F("Prüfsumme", "pruefsumme", s="krypto.pruefsumme", h="Viele Adressen enthalten eine Prüfziffer. Stimmt sie nicht, ist die Adresse falsch abgeschrieben."),
                                       F("Abfragbar", "abfragbar", "ja_nein"), F("Mögliche Blockchains", "ketten", "liste", "krypto.ketten"), F("Einheitliche Schreibweise", "schreibweise"),
                                       F("Hinweise", "hinweise", "liste"))),), wurzel="befund"),
    Darsteller("krypto_adresse", "Stand einer Adresse", ("wallet",), (
        A("Guthaben und Bewegungen", (
            F("Adresse", "adresse"), F("Blockchain", "kette", s="krypto.kette", h=_KETTE), F("Guthaben", "guthaben.betrag", s="krypto.guthaben", ep="guthaben.einheit"),
            F("Gegenwert heute", "guthaben.gegenwert_heute.chf", e="CHF"), F("Gegenwert heute (Euro)", "guthaben.gegenwert_heute.eur", e="EUR"),
            F("Gegenwert heute (US-Dollar)", "guthaben.gegenwert_heute.usd", e="USD"),
            F("Insgesamt erhalten", "erhalten", s="krypto.erhalten", ep="guthaben.einheit"), F("Insgesamt ausgegeben", "ausgegeben", s="krypto.ausgegeben", ep="guthaben.einheit"),
            F("Zahl der Transaktionen", "transaktionen", "zahl", "krypto.transaktionen"), F("Zahlungseingänge", "zahlungseingaenge", "zahl"),
            F("Davon ausgegeben", "davon_ausgegeben", "zahl"), F("Letzte Bewegung", "letzte_bewegung", "zeit", "zeit.letzte_sichtung"),
            F("Erste Bewegung", "erste_bewegung", "zeit", "zeit.erste_sichtung"), F("Ist ein Programm", "ist_programm", "ja_nein"), F("Name des Programms", "name"))),
        A("Zuordnung", (T("Etiketten", "etiketten", (F("Quelle", "quelle"), F("Art", "art"), F("Name", "name"), F("Einzelheiten", "detail"), F("Beleg", "beleg"),
                                                     F("Dienst", "dienst", "ja_nein"), F("Hinweis", "hinweis")), "zuordnung.etiketten",
                          "Etiketten sind Angaben Dritter: wer eine Adresse wem zuschreibt. Sie geben den Stand ihres Datums wieder."),
                        F("Auffällig", "auffaellig", "liste", "zuordnung.auffaellig"), F("Hinweise", "hinweise", "liste"), _QUELLENSTAND)),
    ), wurzel="befund"),
    Darsteller("krypto_transaktionen", "Zahlungen einer Adresse", ("wallet",), (
        A("Zahlungen", (F("Adresse", "adresse"), F("Blockchain", "kette", s="krypto.kette"), F("Wert", "wert.symbol"), F("Blockchain des Werts", "wert.kette"),
                        F("Vertrag des Werts", "wert.vertrag"), F("Echter Vertrag", "wert.echt", "ja_nein"), F("Herausgeber", "wert.emittent"),
                        T("Zahlungen", "zahlungen", (F("Zeit", "zeit", "zeit"), F("Richtung", "richtung"), F("Betrag", "betrag", ep="einheit"), F("Von", "von"), F("An", "an"),
                                                     F("Transaktion", "tx"), F("Vertrag des Werts", "vertrag"), F("Gegenwert", "gegenwert.chf", e="CHF")), "krypto.zahlungen"),
                        T("Gegenparteien", "gegenparteien", (F("Adresse", "adresse"), F("Eingang", "eingang", ep="einheit"), F("Abgang", "abgang", ep="einheit"),
                                                             F("Zahlungen", "zahlungen", "zahl"), F("Etiketten", "etiketten", "liste")), "verwandt.gegenparteien"),
                        F("Hinweise", "hinweise", "liste"), _QUELLENSTAND)),), wurzel="befund"),
    Darsteller("krypto_transaktion", "Eine Transaktion", ("transaktion",), (
        A("Transaktion", (
            F("Transaktions-ID", "tx"), F("Blockchain", "kette", s="krypto.kette"), F("Zeit", "zeit", "zeit", "tx.zeit"), F("Block", "block", "zahl", "tx.block"),
            F("Bestätigt", "bestaetigt", "ja_nein"), F("Erfolgreich", "erfolgreich", "ja_nein", "tx.erfolgreich"), F("Von", "von", s="tx.von"), F("An", "an", s="tx.an"),
            F("Summe", "summe", s="tx.summe", ep="einheit"), F("Gegenwert der Summe", "gegenwert_summe.chf", s="tx.gegenwert_chf", e="CHF"),
            F("Gegenwert der Summe (Euro)", "gegenwert_summe.eur", e="EUR"), F("Gegenwert der Summe (US-Dollar)", "gegenwert_summe.usd", e="USD"),
            F("Gebühr", "gebuehr.betrag", s="tx.gebuehr", ep="gebuehr.einheit"), F("Gebühr", "gebuehr", s="tx.gebuehr", ep="einheit"),
            F("An ist ein Programm", "an_ist_programm", "ja_nein"), F("Name des Programms", "an_name"), F("Aufruf", "aufruf"),
            F("Eingänge (Anzahl)", "eingaenge.anzahl", "zahl"), F("Adressen in den Eingängen", "eingaenge.adressen", "zahl"),
            T("Grösste Eingänge", "eingaenge.groesste", (F("Adresse", "adresse"), F("Betrag", "betrag", ep="/einheit")), "tx.eingaenge"),
            T("Ausgänge", "ausgaenge", (F("Nr.", "nr", "zahl"), F("Adresse", "adresse"), F("Betrag", "betrag", ep="/einheit"), F("Verbleib", "verbleib"),
                                        F("Weitergeleitet in", "weitergeleitet_in"), F("Weitergeleitet am", "weitergeleitet_am", "zeit"), F("Gegenwert", "gegenwert.chf", e="CHF"),
                                        F("Gegenwert (Euro)", "gegenwert.eur", e="EUR"), F("Gegenwert (US-Dollar)", "gegenwert.usd", e="USD")), "tx.ausgaenge"),
            T("Zahlungen", "zahlungen", (F("Zeit", "zeit", "zeit"), F("Von", "von"), F("An", "an"), F("Betrag", "betrag", ep="einheit"), F("Transaktion", "tx"),
                                         F("Vertrag des Werts", "vertrag"), F("Gegenwert", "gegenwert.chf", e="CHF"), F("Gegenwert (Euro)", "gegenwert.eur", e="EUR"),
                                         F("Gegenwert (US-Dollar)", "gegenwert.usd", e="USD")), "tx.zahlungen"))),
        A("Gegenprüfung und Kurs", (
            F("Gegengeprüft bei", "gegenpruefung.quelle"), F("Beleg der Gegenprüfung", "gegenpruefung.beleg"),
            F("Ergebnis der Gegenprüfung", "gegenpruefung.ergebnis", s="tx.gegenpruefung"), F("Verglichen wurde", "gegenpruefung.verglichen"),
            F("Abweichungen", "gegenpruefung.abweichungen", "liste"), F("Kurs am Tag", "kurs_am_tag.chf", e="CHF je Einheit"), F("Kurs am Tag (Euro)", "kurs_am_tag.eur", e="EUR je Einheit"),
            F("Kurs am Tag (US-Dollar)", "kurs_am_tag.usd", e="USD je Einheit"), F("Kurs vom", "kurs_am_tag.stand", "zeit"),
            F("Wechselkurs vom", "kurs_am_tag.wechselkurs_vom", "zeit"), F("Quellen des Kurses", "kurs_am_tag.quellen", "liste"),
            T("Etiketten der beteiligten Adressen", "etiketten", (F("Adresse", "#"), F("Etiketten", "", "liste")), "zuordnung.etiketten_tx"), F("Hinweise", "hinweise", "liste"))),
    ), wurzel="befund"),
    Darsteller("krypto_geldfluss", "Geldfluss über mehrere Stationen", ("transaktion", "wallet"), (
        A("Ausgangspunkt", (
            F("Art des Starts", "start.art"), F("Startzahlung", "start.tx"), F("Startadresse", "start.adresse"), F("Zahlung von", "start.von"),
            F("Zeit der Startzahlung", "start.zeit", "zeit"), F("Eingänge am Start", "start.eingaenge", "zahl"), F("Betrag der Startzahlung", "start.betrag", ep="start.einheit"),
            F("Startbetrag", "startbetrag", s="fluss.startbetrag", ep="einheit"), F("Gegenwert am Tag der Zahlung", "start.gegenwert.chf", e="CHF"),
            F("Gegenwert am Tag der Zahlung (Euro)", "start.gegenwert.eur", e="EUR"), F("Gegenwert am Tag der Zahlung (US-Dollar)", "start.gegenwert.usd", e="USD"),
            F("Kurs am Tag", "start.kurs.chf", e="CHF je Einheit"), F("Kurs am Tag (Euro)", "start.kurs.eur", e="EUR je Einheit"),
            F("Kurs am Tag (US-Dollar)", "start.kurs.usd", e="USD je Einheit"), F("Kurs vom", "start.kurs.stand", "zeit"),
            F("Wechselkurs vom", "start.kurs.wechselkurs_vom", "zeit"), F("Quellen des Kurses", "start.kurs.quellen", "liste"),
            F("Hinweis zum Gegenwert", "start.gegenwert_hinweis"), F("Blockchain", "kette", s="krypto.kette"), F("Wert", "wert.symbol"), F("Blockchain des Werts", "wert.kette"),
            F("Vertrag des Werts", "wert.vertrag"), F("Echter Vertrag", "wert.echt", "ja_nein"), F("Herausgeber", "wert.emittent"), F("Methode", "methode", "lang", "fluss.methode"),
            F("Summe geht auf", "summe_geht_auf", "ja_nein", "fluss.summe", h="Ob die Enden zusammen genau den Startbetrag ergeben."))),
        A("Verbleib", (
            T("Verteilung des Startbetrags", "verteilung", (F("Verbleib", "bezeichnung"), F("Art", "art"), F("Betrag", "betrag", ep="/einheit"), F("Anteil", "anteil", "zahl", e="%"),
                                                            F("Gegenwert", "gegenwert.chf", e="CHF"), F("Gegenwert (Euro)", "gegenwert.eur", e="EUR"),
                                                            F("Gegenwert (US-Dollar)", "gegenwert.usd", e="USD")), "fluss.verteilung"),
            T("Enden", "enden", (F("Art", "art"), F("Bezeichnung", "bezeichnung"), F("Adresse", "adresse"), F("Name", "name"), F("Betrag", "betrag", ep="/einheit"),
                                 F("Anteil", "anteil", "zahl", e="%"), F("Station", "station", "zahl"), F("Grund", "grund"), F("Transaktion", "tx"),
                                 F("Etiketten", "etiketten", "liste")), "fluss.enden"),
            F("Weitere Enden (nur in den Einzelheiten)", "weitere_enden", "zahl"), F("Ansatzpunkte", "ansatzpunkte", "liste", "fluss.ansatzpunkte"))),
        A("Weg", (
            T("Stationen", "stationen", (F("Nr.", "nr", "zahl"), F("Adresse", "adresse"), F("Art", "art"), F("Name", "name"), F("Betrag", "betrag", ep="/einheit"),
                                         F("Anteil", "anteil", "zahl", e="%"), F("Tiefe", "tiefe", "zahl"), F("Programm", "programm", "ja_nein"), F("Etiketten", "etiketten", "liste"),
                                         F("Auffällig", "auffaellig", "liste"), F("Hinweise", "hinweise", "liste"), F("Mitgenutzt von", "mitgenutzt", "liste")), "fluss.stationen"),
            T("Flüsse", "fluesse", (F("Von Station", "von", "zahl"), F("Nach Station", "nach", "zahl"), F("Betrag", "betrag", ep="/einheit"), F("Anteil", "anteil", "zahl", e="%"),
                                    F("Transaktionen", "tx", "liste"), F("Zeit", "zeit", "zeit"), F("Passgenau", "passgenau", "ja_nein")), "fluss.fluesse"))),
        A("Aufwand", (F("Abfragen ausgeführt", "abfragen.ausgefuehrt", "zahl"), F("Davon aus dem Fall-Cache", "abfragen.aus_fall_cache", "zahl"), F("Budget", "abfragen.budget", "zahl"),
                      F("Budget aufgebraucht", "abfragen.budget_aufgebraucht", "ja_nein", "fluss.budget"), F("Fortsetzung ab", "fortsetzung"), F("Hinweise", "hinweise", "liste"),
                      _QUELLENSTAND)),
    ), wurzel="befund"),
    Darsteller("krypto_zuordnung", "Zuordnung von Adressen", ("wallet",), (
        A("Zuordnung", (T("Adressen", "adressen", (F("Adresse", "adresse"), F("Blockchain", "kette"), F("Auffällig", "auffaellig", "liste"), F("Hinweise", "hinweise", "liste")), "zuordnung.adressen"),
                        T("Etiketten", "adressen.*.etiketten", (F("Quelle", "quelle"), F("Art", "art"), F("Name", "name"), F("Einzelheiten", "detail"), F("Beleg", "beleg"),
                                                                F("Dienst", "dienst", "ja_nein"), F("Hinweis", "hinweis")), "zuordnung.etiketten"),
                        F("Geprüft bei", "geprueft", "liste", "zuordnung.geprueft"), _QUELLENSTAND)),), wurzel="befund"),
    Darsteller("krypto_kurs", "Kurs und Gegenwert", ("transaktion", "wallet", "sonstiges"), (
        A("Gegenwert", (F("Wert", "wert.symbol"), F("Blockchain des Werts", "wert.kette"), F("Zeitpunkt", "zeitpunkt", "zeit"), F("Menge", "betrag.menge", ep="betrag.einheit"),
                        F("Gegenwert", "gegenwert.chf", s="tx.gegenwert_chf", e="CHF"), F("Gegenwert (Euro)", "gegenwert.eur", e="EUR"), F("Gegenwert (US-Dollar)", "gegenwert.usd", e="USD"),
                        F("Kurs je Einheit", "kurs_je_einheit.chf", e="CHF"), F("Kurs je Einheit (Euro)", "kurs_je_einheit.eur", e="EUR"),
                        F("Kurs je Einheit (US-Dollar)", "kurs_je_einheit.usd", e="USD"), F("Kurs vom", "kurs_je_einheit.stand", "zeit"),
                        F("Wechselkurs vom", "kurs_je_einheit.wechselkurs_vom", "zeit"), F("Quellen", "kurs_je_einheit.quellen", "liste"))),
    ), wurzel="befund"),
)

# Teilabfragen gebündelter Werkzeuge: Sie tragen den Namen der Quelle
_TEIL = {
    ("ip_abruf", "AbuseIPDB"): ("AbuseIPDB (Teilabfrage)", ("ip",), _ABUSE, ""),
    ("ip_abruf", "Spur"): ("Spur (Teilabfrage)", ("ip",), _SPUR, ""),
    ("ip_abruf", "proxycheck.io"): ("proxycheck.io: Erkennungen zu einer IP", ("ip",), (
        A("Erkennungen", (F("Status der Abfrage", "status"), F("Proxy", "*.detections.proxy", "ja_nein"), F("VPN", "*.detections.vpn", "ja_nein"), F("Tor", "*.detections.tor", "ja_nein"),
                          F("Übernommenes Gerät", "*.detections.compromised", "ja_nein"), F("Automatischer Abruf", "*.detections.scraper", "ja_nein"),
                          F("Rechenzentrum", "*.detections.hosting", "ja_nein"), F("Anonym", "*.detections.anonymous", "ja_nein"), F("Risiko", "*.detections.risk", "zahl", e="von 100"),
                          F("Zuversicht", "*.detections.confidence", "zahl", e="von 100"), F("Erste Sichtung", "*.detections.first_seen", "zeit"),
                          F("Letzte Sichtung", "*.detections.last_seen", "zeit"), F("Wie oft gesehen", "*.detections.times_seen"), F("Betreiber: Name", "*.operator.name"),
                          F("Betreiber: Adresse", "*.operator.url"), F("Betreiber: Anonymität", "*.operator.anonymity"), F("Betreiber: Bekanntheit", "*.operator.popularity"),
                          F("Eintrag gelöscht", "*.detection_history.delisted", "ja_nein"), F("Gelöscht am", "*.detection_history.delist_datetime", "zeit"),
                          F("Stand des Eintrags", "*.last_updated", "zeit"), F("Dauer der Abfrage", "query_time", "zahl", e="ms"))),
        A("Netz und Standort", (F("AS-Nummer", "*.network.asn"), F("Bereich", "*.network.range"), F("Hostname", "*.network.hostname"), F("Anbieter", "*.network.provider"),
                                F("Organisation", "*.network.organisation"), F("Art des Netzes", "*.network.type"), F("Land", "*.location.country_name"),
                                F("Land (Kürzel)", "*.location.country_code"), F("Region", "*.location.region_name"), F("Stadt", "*.location.city_name"),
                                F("Postleitzahl", "*.location.postal_code"), F("Breite", "*.location.latitude", "zahl"), F("Länge", "*.location.longitude", "zahl"),
                                F("Zeitzone", "*.location.timezone"), F("Geräte hinter der Adresse (Schätzung)", "*.device_estimate.address", "zahl"),
                                F("Geräte im Netz (Schätzung)", "*.device_estimate.subnet", "zahl"))),), ""),
    ("ip_abruf", "ipapi.is"): ("ipapi.is: Merkmale einer IP", ("ip",), (
        A("Merkmale", (F("IP-Adresse", "ip"), F("Register", "rir"), F("VPN", "is_vpn", "ja_nein"), F("Proxy", "is_proxy", "ja_nein"), F("Tor", "is_tor", "ja_nein"),
                       F("Rechenzentrum", "is_datacenter", "ja_nein"), F("Mobilfunk", "is_mobile", "ja_nein"), F("Satellit", "is_satellite", "ja_nein"),
                       F("Automatischer Abruf", "is_crawler", "ja_nein"), F("Missbrauch gemeldet", "is_abuser", "ja_nein"), F("Nicht zugeteilt", "is_bogon", "ja_nein"),
                       F("Anycast", "is_anycast", "ja_nein"), F("VPN-Dienst", "vpn.service"), F("VPN: erste Sichtung", "vpn.first_seen", "zeit_ms"), F("VPN: letzte Sichtung", "vpn.last_seen", "zeit_ms"))),
        A("Netz und Standort", (F("Firma", "company.name"), F("Art der Firma", "company.type"), F("Domain der Firma", "company.domain"), F("Netz der Firma", "company.network"),
                                F("Netzname", "company.netname"), F("Rechenzentrum", "datacenter.datacenter"), F("Netz des Rechenzentrums", "datacenter.network"),
                                F("AS-Nummer", "asn.asn", "zahl"), F("AS-Organisation", "asn.org"), F("AS-Route", "asn.route"), F("Art des AS", "asn.type"),
                                F("Land", "location.country"), F("Land (Kürzel)", "location.country_code"), F("Region", "location.state"), F("Stadt", "location.city"),
                                F("Zeitzone", "location.timezone"), F("Dauer der Abfrage", "elapsed_ms", "zahl", e="ms"))),), ""),
    ("ip_abruf", "RIPEstat"): ("RIPEstat: Auskunft der Register", ("ip",), (
        A("Auskunft", (F("Abfrage", "data_call_name"), F("Status", "data_call_status"), F("Zeit der Auskunft", "time", "zeit"), F("Aus dem Zwischenspeicher", "cached", "ja_nein"),
                       F("AS-Nummern", "data.asns", "liste"), F("Präfix", "data.prefix"), F("Bereich", "data.resource"), F("Angekündigt", "data.announced", "ja_nein"),
                       F("Blockgrösse", "data.block.resource"), F("Blockname", "data.block.name"), F("Block: Beschreibung", "data.block.desc"),
                       T("AS", "data.asns", (F("AS-Nummer", "asn", "zahl"), F("Inhaber", "holder"))), F("Meldestelle", "data.abuse_contacts", "liste"),
                       T("Whois-Einträge", "data.records.*", (F("Feld", "key"), F("Wert", "value"))),
                       T("Ankündigungen", "data.by_origin.*.prefixes.*.timelines", (F("Von", "starttime", "zeit"), F("Bis", "endtime", "zeit"), F("Sichtbar bei", "full_peers_seeing", "zahl"))),
                       T("Fassungen", "data.versions", (F("Von", "from_time", "zeit"), F("Bis", "to_time", "zeit"), F("Fassung", "version", "zahl"))))),), ""),
    ("krypto_abruf", "mempool.space"): ("mempool.space: Bitcoin", ("wallet", "transaktion"), (
        A("Adresse", (F("Adresse", "address"), F("Eingänge (Anzahl)", "chain_stats.funded_txo_count", "zahl"), F("Eingänge (Summe)", "chain_stats.funded_txo_sum", "zahl", e="Satoshi"),
                      F("Ausgänge (Anzahl)", "chain_stats.spent_txo_count", "zahl"), F("Ausgänge (Summe)", "chain_stats.spent_txo_sum", "zahl", e="Satoshi"),
                      F("Transaktionen", "chain_stats.tx_count", "zahl"), F("Unbestätigte Transaktionen", "mempool_stats.tx_count", "zahl"))),
        A("Transaktion", (F("Transaktions-ID", "txid"), F("Gebühr", "fee", "zahl", e="Satoshi"), F("Grösse", "size", "bytes"), F("Bestätigt", "status.confirmed", "ja_nein"),
                          F("Block", "status.block_height", "zahl"), F("Zeit des Blocks", "status.block_time", "zeit_s"),
                          T("Eingänge", "vin", (F("Aus Transaktion", "txid"), F("Ausgang Nr.", "vout", "zahl"), F("Adresse", "prevout.scriptpubkey_address"), F("Betrag", "prevout.value", "zahl", e="Satoshi"))),
                          T("Ausgänge", "vout", (F("Adresse", "scriptpubkey_address"), F("Betrag", "value", "zahl", e="Satoshi"), F("Art", "scriptpubkey_type"))))),
        A("Transaktionen der Adresse", (T("Transaktionen", "", (F("Transaktions-ID", "txid"), F("Gebühr", "fee", "zahl", e="Satoshi"), F("Grösse", "size", "bytes"),
                                                             F("Bestätigt", "status.confirmed", "ja_nein"), F("Block", "status.block_height", "zahl"),
                                                             F("Zeit des Blocks", "status.block_time", "zeit_s"), F("Eingänge von", "vin.*.prevout.scriptpubkey_address", "liste"),
                                                             F("Ausgänge an", "vout.*.scriptpubkey_address", "liste"), F("Beträge der Ausgänge", "vout.*.value", "liste"))),))), ""),
}
_TEIL.update({
    ("krypto_abruf", "WalletExplorer"): ("WalletExplorer: Zuordnung einer Bitcoin-Adresse", ("wallet",), (
        A("Zuordnung", (F("Gefunden", "found", "ja_nein"), F("Etikett", "label", h="Name, unter dem WalletExplorer die Geldbörse führt, zum Beispiel eine Börse."),
                        F("Kennung der Geldbörse", "wallet_id"), F("Stand bis Block", "updated_to_block", "zahl"))),), ""),
    ("krypto_abruf", "TRM Labs"): ("TRM Labs: Sanktionsprüfung", ("wallet",), (
        A("Sanktionsprüfung", (T("Geprüfte Adressen", "", (F("Adresse", "address"), F("Sanktioniert", "isSanctioned", "ja_nein")),
                                 h="Ob die Adresse auf einer Sanktionsliste steht, die TRM Labs auswertet."),)),), ""),
    ("krypto_abruf", "Chainabuse"): ("Chainabuse: Meldungen zu einer Adresse", ("wallet",), (
        A("Meldungen", (F("Meldungen insgesamt", "count", "zahl"),
                        T("Meldungen", "reports", (F("Kennung", "id"), F("Gemeldet am", "createdAt", "zeit"), F("Kategorie", "scamCategory"), F("Vertrauenswürdiger Melder", "trusted", "ja_nein"),
                                                   F("Geprüft", "checked", "ja_nein"), F("Adressen", "addresses.*.address", "liste"), F("Blockchain", "addresses.*.chain", "liste"),
                                                   F("Domain", "addresses.*.domain", "liste")),
                          h="Meldungen von Nutzern. Eine Meldung ist ein Hinweis, kein Nachweis."))),), ""),
    ("krypto_abruf", "Blockscout"): ("Blockscout: Etiketten zu Adressen", ("wallet",), (
        A("Etiketten", (T("Etiketten je Adresse", "addresses", (F("Adresse", "#"), F("Etiketten", "tags.*.name", "liste"), F("Art", "tags.*.tagType", "liste"),
                                                               F("Kürzel", "tags.*.slug", "liste"))),)),), ""),
    ("krypto_abruf", "DefiLlama"): ("DefiLlama: Kurse", ("wallet", "transaktion"), (
        A("Kurse", (T("Kurse", "coins", (F("Token", "#"), F("Symbol", "symbol"), F("Kurs", "price", "zahl", e="USD"), F("Stand des Kurses", "timestamp", "zeit_s"),
                                        F("Dezimalstellen", "decimals", "zahl"), F("Zuversicht", "confidence", "zahl"))),)),), ""),
    ("krypto_abruf", "Ransomwhere"): ("Ransomwhere: bekannte Lösegeld-Adressen", ("wallet",), (
        A("Datensatz", (T("Adressen", "result", (F("Adresse", "address"), F("Familie", "family"), F("Blockchain", "blockchain"), F("Saldo", "balance", "zahl", e="Satoshi"),
                                                F("Saldo in USD", "balanceUSD", "zahl"), F("Erfasst", "createdAt", "zeit"), F("Aktualisiert", "updatedAt", "zeit"),
                                                F("Transaktionen", "transactions.*.hash", "liste"))),)),), ""),
})
_TEIL[("krypto_abruf", "Blockstream")] = ("Blockstream: Bitcoin (Gegenprüfung)", ("wallet", "transaktion"), _TEIL[("krypto_abruf", "mempool.space")][2], "")

DARSTELLER = {d.werkzeug: d for d in _D}
# Werkzeuge, deren Ziel im Protokoll eine Kennung ist (Scan, Bericht) und nicht der Indikator selbst: An diesen Stellen der
# Rohantwort steht, worum es geht. Die Datenschicht ordnet den Beleg damit dem Indikator zu.
BEZUG = {"urlscan_ergebnis": ("befund.seite.url", "befund.seite.domain"), "urlquery_bericht": ("url.addr", "url.fqdn", "final.url.addr", "submit.url.addr")}
ALLGEMEIN = Darsteller("", "Allgemeiner Darsteller", (), (), eigen=False)


def pruefung_aus(eintrag: dict) -> str:
    """Bei Web-Check steht die Prüfung in Klammern hinter dem Ziel: «example.com (dns)»."""
    m = re.search(r"\(([a-z-]+)\)\s*$", str(eintrag.get("ziel") or ""))
    if m:
        return m.group(1)
    m = re.search(r"/api/([a-z-]+)\?", str((eintrag.get("anfrage") or {}).get("url") or ""))
    return m.group(1) if m else ""


def darsteller_fuer(eintrag: dict) -> Darsteller:
    werkzeug = str(eintrag.get("werkzeug") or "")
    if werkzeug in ("webcheck_passiv", "webcheck_aktiv"):
        pruefung = pruefung_aus(eintrag)
        if pruefung in _WC:
            art = "passiv" if pruefung in WEBCHECK_PASSIV else "aktiv"
            return Darsteller(werkzeug, f"Web-Check: Prüfung «{pruefung}» ({art})", ("domain", "url"), _WC[pruefung])
        return Darsteller(werkzeug, f"Web-Check: Prüfung «{pruefung or '?'}»", ("domain", "url"), (), eigen=False)
    teil = _TEIL.get((werkzeug, str(eintrag.get("quelle") or "")))
    if teil:
        return Darsteller(werkzeug, teil[0], teil[1], teil[2], wurzel=teil[3])
    if werkzeug in DARSTELLER:
        return DARSTELLER[werkzeug]
    if ist_robin(eintrag):
        kurz = werkzeug.rsplit("__", 1)[-1]
        return Darsteller(werkzeug, f"Robin: {ROBIN_TITEL.get(kurz, kurz.removeprefix('robin_'))} (Dark Web über Tor)", ("onion", "gruppe", "sonstiges"), _ROBIN)
    if werkzeug == "abklaerung_von_hand":
        return Darsteller(werkzeug, "Abklärung von Hand (tools/beleg.py)", ("ip", "domain", "url", "hash", "wallet", "sonstiges"), (
            A("Abklärung", (F("Kennzeichen", "art"), F("Indikator", "indikator"), F("Typ", "indikator_typ"), F("Quelle", "quelle"), F("Abgeklärt am", "abgeklaert_am", "zeit"),
                            F("Erfasst am", "erfasst_am", "zeit"), F("Erfasst durch", "erfasst_durch"), F("Wortlaut der Auskunft", "wortlaut", "lang"), F("Tatzeit", "tatzeit", "zeit"),
                            F("Anonymisierungsdienst", "anonymisierung.wert", s="anon.von_hand"), F("Art", "anonymisierung.art"), F("Dienst", "anonymisierung.dienst"),
                            F("Residential Proxy", "anonymisierung.residential", "ja_nein"))),))
    return ALLGEMEIN


# Robin antwortet als Text. gateway/robin.py zerlegt ihn (lesen), diese Beschreibung benennt die Teile. Was von fremden Seiten stammt
# (Titel, Adressen, Text der Seiten), bleibt Text: Es wird gezeigt, nie ausgeführt.
ROBIN_TITEL = {"robin_search": "Suche", "robin_scrape": "Seiten lesen", "robin_health": "Bereitschaft", "robin_refine": "Suchtext schärfen", "robin_filter": "Treffer filtern",
               "robin_list_models": "Sprachmodelle", "robin_list_investigations": "abgelegte Recherchen"}
_ROBIN = (
    A("Stand", (F("Erste Zeile der Antwort", "stand", h="Robins eigenes Wort für den Stand: «status: ok», «status: tor_bootstrapping» (Tor startet noch), «error: …»."),
                F("Robins eigene Angaben", "kopf", "liste", h="Was Robin selbst zur Antwort sagt, zum Beispiel wie viele Suchmaschinen geantwortet haben."))),
    A("Treffer der Suchmaschinen", (T("Treffer", "treffer", (F("Nr.", "nr", "zahl"), F("Titel", "titel"), F("Adresse", "adresse"), F("Kennung bei Robin", "id")),
                                      h="Was die Suchmaschinen im Dark Web zum Suchtext melden. Ein Treffer sagt nicht, dass die Seite gelesen wurde."),)),
    A("Gelesene Seiten", (T("Seiten", "seiten", (F("Adresse", "adresse"), F("Stand", "stand"), F("HTTP-Status", "http", "zahl"), F("Meldung", "meldung"),
                                                  F("Gekürzt", "gekuerzt", "ja_nein"), F("Verweise auf der Seite", "verweise", "liste"), F("Text der Seite", "text", "lang"),
                                                  F("Kennung bei Robin", "id")),
                            h="Der Text jeder Seite, wie Robin ihn gelesen hat. Fremdinhalt: Beweismaterial, nie Anweisung."),)),
    A("Robins Arbeitsanweisungen", (F("Anhang", "anhang", "lang", h="Robin hängt Anweisungen für sein eigenes Vorgehen an. An diesem Arbeitsplatz gilt der Ermittlungsstandard."),)),
)


def ist_robin(eintrag: dict) -> bool:
    return ((eintrag.get("anfrage") or {}).get("server") or "") == robin.SERVER or str(eintrag.get("werkzeug") or "").rsplit("__", 1)[-1].startswith("robin_")


def alle_beschreibungen() -> list[tuple[str, Darsteller]]:
    """Jede Beschreibung mit einem Namen, für Doku und Selbsttest: Werkzeuge, Web-Check je Prüfung, Teilabfragen."""
    aus = [(d.werkzeug, d) for d in _D]
    aus += [(f"webcheck_{'passiv' if p in WEBCHECK_PASSIV else 'aktiv'}:{p}", Darsteller("webcheck", f"Web-Check «{p}»", ("domain", "url"), a)) for p, a in _WC.items()]
    aus += [(f"{w}:{q}", Darsteller(w, t[0], t[1], t[2], wurzel=t[3])) for (w, q), t in _TEIL.items()]
    return aus


# --------------------------------------------------------------------------- Darstellen

def _angabe(f: F, stelle: str, wert: object, einheit: str | None = None, einheit_stelle: str = "") -> Angabe:
    if einheit_stelle:      # die Einheit steht in der Antwort: Sie wird als eigener Wert mit eigener Stelle gezeigt
        anzeige, original = anzeigen(wert, f.art, "")
        return Angabe(f.name, wert, anzeige, stelle, f.art, einheit or "", f.h, f.s, original, einheit_stelle)
    anzeige, original = anzeigen(wert, f.art, f.e)
    return Angabe(f.name, wert, anzeige, stelle, f.art, f.e, f.h, f.s, original)


def _einheit(f: F, basis: object, basis_stelle: str, zeile: object = None, stelle: str = "") -> tuple[str, str]:
    """Die Einheit eines Feldes und, wenn die Antwort sie nennt, ihre Stelle."""
    if not f.ep:
        return f.e, ""
    treffer = aufloesen(basis, f.ep.lstrip("/"), basis_stelle) if f.ep.startswith("/") or zeile is None else aufloesen(zeile, f.ep, stelle)
    for z, w in treffer:
        if isinstance(w, str) and w:
            return w, z
    return f.e, ""


def _verbrauchen(stelle: str, wert: object, verbraucht: set) -> None:
    for z, _ in angaben_zaehlen(wert, stelle):
        verbraucht.add(z)


def _zelle(f: F, zeile: object, stelle: str, schluessel: str, verbraucht: set, basis: object = None, basis_stelle: str = "") -> Angabe | None:
    if f.pfad == "#":
        return Angabe(f.name, schluessel, schluessel, stelle, "schluessel", "", f.h, "")
    treffer = aufloesen(zeile, f.pfad, stelle) if f.pfad else [(stelle, zeile)]
    einfach = [(z, w) for z, w in treffer if skalar(w) or (isinstance(w, list) and all(skalar(x) for x in w))]
    if not einfach:
        return None
    if len(einfach) == 1:
        z, w = einfach[0]
        _verbrauchen(z, w, verbraucht)
        einheit, einheit_stelle = _einheit(f, basis, basis_stelle, zeile, stelle)
        if einheit_stelle:
            verbraucht.add(einheit_stelle)
        return _angabe(f, z, w, einheit, einheit_stelle)
    werte = []      # mehrere Treffer in einer Zelle (Pfad mit *): als Liste zeigen, Stelle ist die der Zeile
    for z, w in einfach:
        _verbrauchen(z, w, verbraucht)
        werte.extend(w if isinstance(w, list) else [w])
    return Angabe(f.name, werte, anzeigen(werte, "liste")[0], stelle, "liste", "", f.h, "")


def _mit(d: Darsteller, roh: object) -> tuple[list, set]:
    wurzel = aufloesen(roh, d.wurzel)
    if not wurzel:
        return [], set()
    basis_stelle, basis = wurzel[0]
    verbraucht: set[str] = set()
    abschnitte = []
    for a in d.abschnitte:
        teile: list = []
        for teil in a.teile:
            if isinstance(teil, F):
                gruppen = aufloesen(basis, teil.pfad, basis_stelle)
                if teil.art == "liste" and len(gruppen) > 1 and all(skalar(w) for _, w in gruppen):
                    # ein Pfad mit *, der mehrere einzelne Werte trifft: eine Angabe mit allen Werten
                    for z, w in gruppen:
                        verbraucht.add(z)
                    werte = [w for _, w in gruppen]
                    teile.append(Angabe(teil.name, werte, anzeigen(werte, "liste")[0], gruppen[0][0].rsplit("/", 1)[0], "liste", teil.e, teil.h, teil.s))
                    continue
                for z, w in gruppen:
                    if skalar(w) or (isinstance(w, list) and all(skalar(x) for x in w)):
                        if z in verbraucht:
                            continue
                        _verbrauchen(z, w, verbraucht)
                        einheit, einheit_stelle = _einheit(teil, basis, basis_stelle)
                        if einheit_stelle:
                            verbraucht.add(einheit_stelle)
                        teile.append(_angabe(teil, z, w, einheit, einheit_stelle))
            else:
                zeilen = []
                stelle_liste = ""
                for z, behaelter in aufloesen(basis, teil.pfad, basis_stelle):
                    stelle_liste = stelle_liste or z
                    eintraege = list(behaelter.items()) if isinstance(behaelter, dict) else list(enumerate(behaelter)) if isinstance(behaelter, list) else []
                    for schluessel, eintrag in eintraege:
                        stelle = f"{z}/{_teil(schluessel)}"
                        anzeige_schluessel = str(schluessel + 1) if isinstance(schluessel, int) else str(schluessel)
                        zellen = [_zelle(f, eintrag, stelle, anzeige_schluessel, verbraucht, basis, basis_stelle) for f in teil.spalten]
                        if any(c is not None and f.pfad != "#" for c, f in zip(zellen, teil.spalten)):
                            zeilen.append(zellen)
                if zeilen:
                    teile.append(Liste(teil.name, [f.name for f in teil.spalten], zeilen, stelle_liste, teil.h, teil.s))
        if teile:
            abschnitte.append((a.titel, teile))
    return abschnitte, verbraucht


def darstellen(eintrag: dict, roh: object, form: str = "json") -> Blatt:
    """Macht aus Protokolleintrag und Rohantwort ein Blatt. `form` sagt, was die Rohdatei ist: json, text, csv, bild, leer."""
    d = darsteller_fuer(eintrag)
    blatt = Blatt(str(eintrag.get("werkzeug") or ""), d.titel if d.eigen else f"{eintrag.get('werkzeug') or 'Antwort'} (allgemeiner Darsteller)", d.eigen, form=form)
    if ist_robin(eintrag) and form in ("text", "json") and roh is not None:
        # Robin antwortet als Text (ältere Einträge: derselbe Text, von Claude Code in JSON verpackt). Zerlegt wird ohne zu deuten
        roh = {k: v for k, v in robin.lesen(robin.text_aus(roh)).items() if v not in ([], "")}     # leere Teile (keine Treffer, kein Anhang) entfallen
        blatt.form, blatt.inhalt, blatt.zerlegt, form = "json", roh, True, "json"
    if form != "json":
        return blatt
    alle = list(angaben_zaehlen(roh))
    blatt.gesamt = len(alle)
    blatt.abschnitte, verbraucht = _mit(d, roh) if d.abschnitte else ([], set())
    blatt.weitere = [(z, w) for z, w in alle if z not in verbraucht]
    blatt.zugeordnet = blatt.gesamt - len(blatt.weitere)
    return blatt


def baum(roh: object, stellen: set | None = None, zeiger: str = "") -> object:
    """Die Rohantwort als Baum, beschränkt auf die genannten Stellen (None: alles). Für «Weitere Angaben der Quelle»."""
    if isinstance(roh, dict) and roh:
        kinder = {k: baum(v, stellen, f"{zeiger}/{_teil(k)}") for k, v in roh.items()}
        return {k: v for k, v in kinder.items() if v is not _LEER} or _LEER
    if isinstance(roh, list) and roh:
        kinder = [(i, baum(v, stellen, f"{zeiger}/{i}")) for i, v in enumerate(roh)]
        behalten = [(i, v) for i, v in kinder if v is not _LEER]
        return behalten or _LEER
    return (zeiger, roh) if stellen is None or zeiger in stellen else _LEER


_LEER: Any = object()
BAUM_LEER = _LEER
Formatierer = Callable[[object], str]
