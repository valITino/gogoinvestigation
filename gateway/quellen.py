"""Verzeichnis aller Quellen. Eine Stelle für Gateway, Einrichtung, Selbsttest und Doku.

Felder:
  name       Anzeigename, identisch mit 'quelle' im Abfrageprotokoll
  env        Name des Schlüssels in .env, oder None wenn kein Schlüssel nötig ist
  woher      Wo man den Schlüssel bekommt
  werkzeuge  Werkzeugnamen des Gateways
  zweck      Wozu die Quelle dient, in einem Satz
  test       Harmlose Testabfrage für 'tools/pruefen.py --live': (werkzeug, argumente)
  auch_ohne  Die Quelle läuft auch ohne Schlüssel, nur gedrosselt. Der Schlüssel ist eine Zugabe.

Die Blockchain-Werkzeuge fragen je nach Kette verschiedene Dienste. Im Abfrageprotokoll steht der Dienst,
der tatsächlich gefragt wurde (zum Beispiel mempool.space). Hier steht, wofür er gebraucht wird.
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
    auch_ohne: bool = False


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
    # ----- Blockchain-Analyse. Testadressen: öffentlich bekannte Adressen (WannaCry, eine Börse, der USDT-Vertrag)
    Quelle("Bitcoin (mempool.space)", None, "kein Schlüssel nötig",
           ("krypto_adresse_pruefen", "krypto_adresse", "krypto_transaktionen", "krypto_transaktion", "krypto_geldfluss"),
           "Bitcoin: Guthaben, Zahlungen und Geldfluss über mehrere Stationen. Ausweichquelle Blockstream.",
           ("krypto_adresse", {"adresse": "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"}),
           "Der Betreiber sieht, welche Adressen abgefragt werden. Eigene Instanz: KRYPTO_BITCOIN_API."),
    Quelle("Ethereum (Blockscout)", "BLOCKSCOUT_API_KEY", "https://dev.blockscout.com (kostenlos)", (),
           "Ethereum-Familie samt USDT und USDC: Guthaben, Zahlungen, Geldfluss, Etiketten von Börsen.",
           ("krypto_transaktion", {"tx": "0x55ae6a400fb41abe493f5f70bba0d6aa4386e2b082ad3ffc851bf22a3dfa7e9b", "kette": "ethereum"}),
           "Läuft auch ohne Schlüssel, dann gedrosselt. Mit Schlüssel auch Base, Arbitrum, Polygon, Gnosis. "
           "Blockscout stellt den Zugang ohne Schlüssel nach eigener Angabe ein.",
           auch_ohne=True),
    Quelle("TRON (TronGrid)", "TRONGRID_API_KEY", "https://www.trongrid.io (kostenlos)", (),
           "TRON samt USDT: Guthaben, Zahlungen, Geldfluss, Sperrliste von Tether.",
           ("krypto_adresse", {"adresse": "TJmmqjb1DK9TTZbQXzRQ2AuA94z4gKAPFh"}),
           "Läuft auch ohne Schlüssel, dann stark gedrosselt. Für Geldflüsse über viele Stationen lohnt sich der Schlüssel.",
           auch_ohne=True),
    Quelle("Krypto-Zuordnung", None, "kein Schlüssel nötig", ("krypto_zuordnung",),
           "Wem gehört eine Adresse? Sanktionslisten (OFAC, TRM Labs), Lösegeld-Adressen (Ransomwhere), WalletExplorer.",
           ("krypto_zuordnung", {"adressen": ["12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"]})),
    Quelle("Krypto-Kurse", None, "kein Schlüssel nötig", ("krypto_kurs",),
           "Gegenwert in CHF, EUR und USD am Tag der Zahlung (DefiLlama, Referenzkurse der EZB).",
           ("krypto_kurs", {"wert": "BTC", "datum": "2024-01-15", "betrag": "0.5"})),
    Quelle("Etherscan", "ETHERSCAN_API_KEY", "https://etherscan.io/apidashboard (kostenlos)", (),
           "Weitere Ketten der Ethereum-Familie (Polygon, Arbitrum, Gnosis) und Gegenprüfung von Ethereum-Transaktionen.",
           ("krypto_adresse", {"adresse": "0x28C6c06298d514Db089934071355E5743bf21d60", "kette": "polygon"}),
           "BNB Smart Chain, Base und Optimism verlangen bei Etherscan ein bezahltes Abo."),
    Quelle("Tronscan", "TRONSCAN_API_KEY", "https://docs.tronscan.org/getting-started/api-keys (kostenlos)", (),
           "Namen von Börsen und Diensten für TRON-Adressen, Risikohinweise.",
           ("krypto_zuordnung", {"adressen": ["TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"], "quellen": ["tronscan"]}),
           "Ohne diesen Schlüssel endet eine Verfolgung auf TRON bei «Sammeladresse, Dienst unbekannt»."),
    Quelle("Chainabuse", "CHAINABUSE_API_KEY", "https://www.chainabuse.com (Profil, API-Schlüssel)", (),
           "Betrugsmeldungen Geschädigter zu einer Adresse.",
           ("krypto_zuordnung", {"adressen": ["12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"], "quellen": ["chainabuse"], "meldungen": True}),
           "Das kostenlose Kontingent ist sehr klein (rund zehn Abfragen im Monat). Wird nur auf ausdrücklichen Wunsch gefragt."),
    Quelle("Iknaio GraphSense", "IKNAIO_API_KEY", "https://www.ikna.io (Zugang für Behörden auf Anfrage)", (),
           "Etiketten und Cluster für Bitcoin, Ethereum und TRON aus der Analyseplattform GraphSense.",
           ("krypto_zuordnung", {"adressen": ["12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"], "quellen": ["iknaio"]})),
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
