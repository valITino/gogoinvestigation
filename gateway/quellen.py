"""Verzeichnis aller Quellen. Eine Stelle für Gateway, Einrichtung, Selbsttest und Doku.

Felder:
  name       Anzeigename, identisch mit 'quelle' im Abfrageprotokoll
  env        Name des Schlüssels in .env, oder None wenn kein Schlüssel nötig ist
  woher      Wo man den Schlüssel bekommt
  werkzeuge  Werkzeugnamen des Gateways
  zweck      Wozu die Quelle dient, in einem Satz
  test       Harmlose Testabfrage für 'tools/pruefen.py --live': (werkzeug, argumente)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Quelle:
    name: str
    env: str | None
    woher: str
    werkzeuge: tuple[str, ...]
    zweck: str
    test: tuple[str, dict] | None = None
    hinweis: str = ""
    freigabe: dict = field(default_factory=dict)   # werkzeug -> nötige Freigabe


QUELLEN: tuple[Quelle, ...] = (
    Quelle("Shodan", "SHODAN_API_KEY", "https://account.shodan.io",
           ("shodan_host", "shodan_dns", "shodan_suche"),
           "Offene Ports, Dienste, Zertifikate und Betreiber von IPs; Pivot über Zertifikat und Favicon.",
           ("shodan_host", {"ip": "8.8.8.8"}),
           "shodan_dns und Trefferlisten von shodan_suche verbrauchen Query-Credits."),
    Quelle("Shodan InternetDB", None, "kein Schlüssel nötig", ("shodan_internetdb",),
           "Schnellübersicht einer IP ohne Schlüssel.", ("shodan_internetdb", {"ip": "8.8.8.8"})),
    Quelle("VirusTotal", "VIRUSTOTAL_API_KEY", "https://www.virustotal.com/gui/my-apikey",
           ("virustotal_ip", "virustotal_domain", "virustotal_datei", "virustotal_url",
            "virustotal_beziehungen"),
           "Einschätzung von IPs, Domains, URLs und Datei-Hashes; Verknüpfungen zwischen Indikatoren.",
           ("virustotal_domain", {"domain": "example.com"}),
           "Nur Abfragen, nie Uploads. Nutzungsbedingungen des öffentlichen Schlüssels beachten "
           "(Behörden und Firmen brauchen in der Regel ein Abo). Drossel über VT_INTERVALL."),
    Quelle("Spur", "SPUR_TOKEN", "https://docs.spur.us/context-api",
           ("spur_kontext",),
           "VPN-, Proxy- und Tor-Erkennung: Lässt sich eine IP überhaupt einem Anschluss zuordnen?",
           ("spur_kontext", {"ip": "8.8.8.8"}), "Kommerzieller Dienst. Historische Abfragen brauchen ein höheres Abo."),
    Quelle("AbuseIPDB", "ABUSEIPDB_API_KEY", "https://www.abuseipdb.com/account/api",
           ("abuseipdb_pruefen", "abuseipdb_meldungen"),
           "Missbrauchsmeldungen zu IPs mit Score, Kategorien und Zeitpunkten.",
           ("abuseipdb_pruefen", {"ip": "8.8.8.8"})),
    Quelle("urlquery", "URLQUERY_API_KEY", "https://urlquery.net",
           ("urlquery_suche", "urlquery_bericht", "urlquery_reputation", "urlquery_einreichen",
            "urlquery_status"),
           "Sandbox-Berichte zu URLs: Was tat die Seite beim Aufruf?",
           ("urlquery_reputation", {"url": "https://example.com/"}),
           freigabe={"urlquery_einreichen": "aktiv"}),
    Quelle("Wayback Machine", None, "kein Schlüssel nötig",
           ("wayback_verlauf", "wayback_abruf", "wayback_sichern"),
           "Frühere Stände von Webseiten: Seit wann gibt es die Seite, was stand dort?",
           ("wayback_verlauf", {"url": "example.com", "limit": 3}),
           freigabe={"wayback_sichern": "aktiv"}),
    Quelle("Web-Check", None, "eigene Instanz per Docker (setup.sh startet sie)",
           ("webcheck_passiv", "webcheck_aktiv"),
           "Rundumblick auf eine Website: DNS, WHOIS, Subdomains, Sperrlisten; aktiv auch Header, TLS, Ports.",
           ("webcheck_passiv", {"ziel": "example.com", "pruefung": "dns"}),
           "Läuft lokal unter WEBCHECK_URL. Aktive Prüfungen verraten die IP der Instanz.",
           freigabe={"webcheck_aktiv": "aktiv"}),
    Quelle("ransomware.live", "RANSOMWARE_LIVE_API_KEY", "https://my.ransomware.live",
           ("ransomware_opfer", "ransomware_gruppe", "ransomware_iocs", "ransomware_aktuell"),
           "Leak-Seiten von Ransomware-Gruppen: Opfer, Gruppenprofile, veröffentlichte Indikatoren.",
           ("ransomware_aktuell", {}),
           "Kostenloser PRO-Schlüssel. Die schlüssellose API v2 ist laut Anbieter nur für private Nutzung."),
    Quelle("Ahmia", None, "kein Schlüssel nötig", ("onion_sperrliste",),
           "Sperrliste für Onion-Adressen. Pflichtprüfung vor dem Öffnen einer Onion-Seite.",
           ("onion_sperrliste", {"onion_adresse": "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"})),
    Quelle("Telegram (Web-Vorschau)", None, "kein Schlüssel nötig", ("telegram_kanal",),
           "Öffentliche Kanäle lesen, z. B. den Breach-Feed 'breachdetect'.",
           ("telegram_kanal", {"kanal": "breachdetect"})),
    Quelle("RapidAPI Telegram", "RAPIDAPI_KEY", "https://rapidapi.com (APIs 'Telegram Channel' und 'Telegram Scraper API' abonnieren)",
           ("telegram_kanalinfo", "telegram_entitaet", "telegram_suche"),
           "Stammdaten zu Telegram-Kanälen und -Konten (Funktionen aus TeleGramSint).",
           None, "Drittanbieter unbekannter Herkunft: Vor dem Einsatz prüfen, ob Selektoren dorthin dürfen.",
           freigabe={"telegram_entitaet": "personenbezug", "telegram_suche": "personenbezug"}),
    Quelle("4chan", None, "kein Schlüssel nötig", ("chan_katalog", "chan_thread"),
           "Threads suchen und sichern (Funktionen aus OSINT-Chan).",
           ("chan_katalog", {"board": "g", "stichwort": "linux"})),
    Quelle("Mastodon", None, "kein Schlüssel nötig", ("mastodon_instanz", "mastodon_konto"),
           "Instanzen und Konten im Fediverse (Funktionen aus Masto).",
           ("mastodon_instanz", {"instanz": "mastodon.social"}),
           freigabe={"mastodon_konto": "personenbezug"}),
)

# Werkzeuge des separaten MCP-Servers Robin (Dark-Web-Suche über Tor im eigenen Container)
ROBIN_WERKZEUGE = ("robin_search", "robin_refine", "robin_filter", "robin_scrape", "robin_investigate",
                   "robin_list_models", "robin_health", "robin_list_investigations",
                   "robin_save_investigation")


def alle_werkzeuge() -> set[str]:
    return {w for q in QUELLEN for w in q.werkzeuge}


def freigabe_fuer(werkzeug: str) -> str | None:
    for q in QUELLEN:
        if werkzeug in q.freigabe:
            return q.freigabe[werkzeug]
    return None
