"""Das Datenblatt je Indikator: feste Abschnitte in immer gleicher Reihenfolge, je Indikatortyp. Nur Standardbibliothek.

Jeder Darsteller gibt seinen Feldern einen Schlüssel wie «netz.as» oder «zert.gueltig_bis». Der Teil vor dem Punkt
bestimmt den Abschnitt. So landen Angaben verschiedener Quellen zum selben Feld nebeneinander, und die Oberfläche
kann zeigen, wo sie sich widersprechen. Die Abschnitte sind in docs/OBERFLAECHE.md beschrieben.
"""
from __future__ import annotations

import re

# Indikatortyp -> Abschnitte in fester Reihenfolge. Je Abschnitt die Anfänge der Schlüssel, die hineingehören.
ABSCHNITTE: dict[str, list[tuple[str, tuple[str, ...]]]] = {
    "ip": [("Einordnung", ("anon.",)), ("Netz und Inhaber", ("netz.",)), ("Standort", ("ort.",)), ("Dienste und Ports", ("dienste.",)),
           ("Zertifikate", ("zert.",)), ("Domains auf der Adresse", ("namen.",)), ("Ruf und Meldungen", ("ruf.", "sperr.")),
           ("Geschichte", ("zeit.",)), ("Verwandte Indikatoren", ("verwandt.",))],
    "domain": [("Registrierung", ("reg.",)), ("DNS", ("dns.",)), ("Zertifikate", ("zert.",)), ("Hosting", ("host.", "netz.", "ort.")),
               ("Inhalt der Seite", ("seite.",)), ("Ruf und Sperrlisten", ("ruf.", "sperr.")), ("Geschichte", ("zeit.",)),
               ("Verwandte Indikatoren", ("verwandt.", "namen."))],
    "url": [("Inhalt der Seite", ("seite.",)), ("Hosting", ("host.", "netz.", "ort.")), ("Zertifikate", ("zert.",)),
            ("Ruf und Sperrlisten", ("ruf.", "sperr.")), ("Geschichte", ("zeit.",)), ("Verwandte Indikatoren", ("verwandt.",))],
    "hash": [("Datei", ("datei.",)), ("Erkennung", ("ruf.",)), ("Geschichte", ("zeit.",)), ("Verwandte Indikatoren", ("verwandt.",))],
    "wallet": [("Prüfung der Adresse", ("krypto.art", "krypto.format", "krypto.pruefsumme", "krypto.ketten")),
               ("Guthaben und Bewegungen", ("krypto.",)), ("Zuordnung", ("zuordnung.",)), ("Geldfluss", ("fluss.",)),
               ("Geschichte", ("zeit.",)), ("Verwandte Indikatoren", ("verwandt.",))],
    "transaktion": [("Transaktion", ("tx.", "krypto.")), ("Geldfluss", ("fluss.",)), ("Zuordnung", ("zuordnung.",)), ("Geschichte", ("zeit.",))],
    "gruppe": [("Profil", ("gruppe.name", "gruppe.beschreibung", "gruppe.opfer")), ("Leak-Seiten und Werkzeuge", ("gruppe.seiten", "gruppe.werkzeuge")),
               ("Opfer", ("gruppe.opfer_liste",)), ("Indikatoren der Gruppe", ("gruppe.iocs",)), ("Geschichte", ("zeit.",))],
    "onion": [("Sperrliste", ("sperr.",)), ("Inhalt", ("seite.", "konto.")), ("Geschichte", ("zeit.",))],
    "konto": [("Stammdaten", ("konto.",)), ("Geschichte", ("zeit.",))],
    "email": [("Domain der Adresse", ("reg.", "dns.")), ("Ruf und Sperrlisten", ("ruf.", "sperr.")), ("Geschichte", ("zeit.",))],
    "sonstiges": [("Angaben der Quellen", ("",))],
}

# Welche Quelle zu welchem Indikatortyp etwas sagen kann. Für die Abdeckung Indikator × Quelle.
QUELLE_TYPEN: dict[str, tuple[str, ...]] = {
    "Shodan": ("ip", "domain"), "Shodan InternetDB": ("ip",), "VirusTotal": ("ip", "domain", "url", "hash"), "Spur": ("ip",), "AbuseIPDB": ("ip",),
    "RIPEstat": ("ip",), "proxycheck.io": ("ip",), "ipapi.is": ("ip",), "urlquery": ("url", "domain"), "urlscan.io": ("url", "domain", "ip", "hash"),
    "Wayback Machine": ("url", "domain"), "Web-Check": ("domain", "url"), "ransomware.live": ("gruppe",), "Ahmia": ("onion",),
    "Telegram (Web-Vorschau)": ("konto",), "RapidAPI Telegram": ("konto",), "4chan": ("konto",), "Mastodon": ("konto", "domain"),
    "Bitcoin (mempool.space)": ("wallet", "transaktion"), "mempool.space": ("wallet", "transaktion"), "Blockstream": ("wallet", "transaktion"),
    "Ethereum (Blockscout)": ("wallet", "transaktion"), "Blockscout": ("wallet", "transaktion"), "TRON (TronGrid)": ("wallet", "transaktion"),
    "TronGrid": ("wallet", "transaktion"), "Krypto-Zuordnung": ("wallet",), "OFAC": ("wallet",), "TRM Labs": ("wallet",), "Ransomwhere": ("wallet",),
    "WalletExplorer": ("wallet",), "GraphSense TagPacks": ("wallet",), "Krypto-Kurse": ("transaktion",), "DefiLlama": ("transaktion",), "EZB": ("transaktion",),
    "Etherscan": ("wallet", "transaktion"), "Tronscan": ("wallet",), "Chainabuse": ("wallet",), "Iknaio GraphSense": ("wallet",), "Iknaio": ("wallet",),
    "Robin": ("onion", "gruppe"),
}
# Namen im Protokoll, die zu einem Eintrag im Verzeichnis der Quellen gehören
QUELLE_GLEICH = {"mempool.space": "Bitcoin (mempool.space)", "Blockstream": "Bitcoin (mempool.space)", "Blockscout": "Ethereum (Blockscout)",
                 "TronGrid": "TRON (TronGrid)", "Iknaio": "Iknaio GraphSense"}

# Fachbegriffe in einfachen Worten. Gleiche Begriffe, gleiche Erklärung, in jeder Ansicht.
BEGRIFFE = {
    "AS": "Autonomes System: das Netz eines Anbieters. Die Nummer zeigt, wem ein Adressbereich gehört.",
    "Präfix": "Der Adressbereich, zu dem eine IP-Adresse gehört.",
    "DNS": "Das Telefonbuch des Internets: Es übersetzt Namen wie beispiel.ch in IP-Adressen.",
    "Zertifikat": "Ein digitaler Ausweis für eine Website. Er nennt, für welchen Namen er gilt und wer ihn ausgestellt hat.",
    "Port": "Eine Tür am Server. Hinter jeder offenen Tür antwortet ein Dienst, zum Beispiel der Webserver.",
    "Hash": "Der Fingerabdruck einer Datei: eine Prüfsumme, die sich mit jedem veränderten Zeichen ändert.",
    "Sperrliste": "Eine Liste bekannter schädlicher Adressen, die Schutzdienste führen.",
    "Wallet": "Eine Adresse in einer Blockchain, an die bezahlt werden kann.",
    "Etikett": "Die Angabe eines Dritten, wem eine Adresse gehört, zum Beispiel einer Börse.",
    "Beleg": "Ein Eintrag im Abfrageprotokoll (P-0007) oder eine gesicherte Antwort eines weiteren Werkzeugs (X-0002).",
    "Rohdatei": "Die unveränderte Antwort der Quelle, so wie sie eingetroffen ist.",
    "Fall-Cache": "Wird dieselbe Frage im selben Fall noch einmal gestellt, kommt die Antwort aus der Fallakte statt von der Quelle.",
    "Kette": "Jeder Protokolleintrag enthält die Prüfsumme seines Vorgängers. Wird etwas verändert, stimmt die Kette ab dieser Stelle nicht mehr.",
}


def abschnitt_fuer(typ: str, schluessel: str) -> str | None:
    for titel, anfaenge in ABSCHNITTE.get(typ) or ABSCHNITTE["sonstiges"]:
        if any(schluessel.startswith(a) for a in anfaenge):
            return titel
    return None


# Eigene Beobachtungen jeder Quelle (zuerst gesehen, zuletzt geprüft): Verschiedene Werte sind dort kein Widerspruch.
OHNE_VERGLEICH = ("zeit.",)


def vergleichswert(schluessel: str, wert: object, art: str = "text") -> object:
    """Macht Werte verschiedener Quellen vergleichbar: Zahlen als Zahl, Zeiten als Zeitpunkt, Texte ohne Gross- und
    Kleinschreibung und ohne Satzzeichen. «AS64500» und 64500 gelten so als dasselbe."""
    if isinstance(wert, bool) or wert is None:
        return wert
    if art in ("zeit", "zeit_s", "zeit_ms"):
        from .darsteller import zeit
        lokal, original = zeit(wert, art)
        if original:
            return ("zeit", lokal)
    if isinstance(wert, (int, float)):
        return float(wert)
    text = " ".join(str(wert).split()).casefold()
    if schluessel.endswith(".as"):
        ziffern = re.sub(r"\D", "", text)
        if ziffern:
            return float(ziffern)
    try:
        return float(text)
    except ValueError:
        return " ".join(re.findall(r"\w+", text))


def vertraeglich(a: object, b: object) -> bool:
    """Zwei Texte vertragen sich auch, wenn der eine ganz im andern steckt: «Beispiel Hosting AG» und
    «BEISPIEL-HOSTING - Beispiel Hosting AG, NL» nennen denselben Inhaber."""
    if a == b:
        return True
    if isinstance(a, str) and isinstance(b, str) and a and b:
        wa, wb = set(a.split()), set(b.split())
        return wa <= wb or wb <= wa
    return False


def widerspruch(schluessel: str, werte: list[tuple[str, object, str]]) -> bool:
    """Nennen zwei Quellen für dasselbe Feld Verschiedenes? `werte`: je Angabe (Quelle, Wert, Art des Feldes).
    Nicht verglichen werden Listen (jede Quelle sieht einen Ausschnitt), leere Werte und die eigenen
    Beobachtungszeiten der Quellen im Abschnitt «Geschichte»."""
    if any(schluessel.startswith(a) for a in OHNE_VERGLEICH):
        return False
    einzel = [(quelle, vergleichswert(schluessel, wert, art)) for quelle, wert, art in werte
              if wert not in (None, "") and not isinstance(wert, (list, dict))]
    return any(qa != qb and not vertraeglich(a, b) for i, (qa, a) in enumerate(einzel) for qb, b in einzel[i + 1:])
