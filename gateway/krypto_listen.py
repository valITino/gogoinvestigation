"""Etiketten für Krypto-Adressen aus einer lokalen Liste: die GraphSense TagPacks (Iknaio, AIT), MIT-Lizenz.

Die Liste liegt auf dem eigenen Rechner. Eine Adresse wird darin nachgeschlagen wie in einem Buch: Es geht keine
Anfrage hinaus, kein Dritter erfährt, welche Adresse geprüft wurde.

Stand und Prüfsumme sind festgelegt. Das Verzeichnis ``gateway/listen/tagpacks.json`` nennt den Commit der
TagPacks, sein Datum, jede übernommene Datei mit ihrer Prüfsumme und die Prüfsumme der fertigen Tabelle. Das
Gateway liest die Tabelle nur, wenn ihre Prüfsumme stimmt. Ein neuer Stand entsteht nicht von selbst: Er ist ein
bewusster Schritt (``tools/listen.py bauen``) und kommt als Änderung am Verzeichnis ins Repo.

Zwei Teile, nach Grösse getrennt:

    Kern           ``gateway/listen/tagpacks.csv.gz`` im Repo. Börsen, Zahlungsdienste, Mischdienste, Märkte,
                   Lösegeld- und Betrugsadressen. Ohne weiteren Schritt da, auf jedem Rechner gleich.
    Massenlisten   elf sehr grosse Dateien (Reserven einer Börse, Erpresser-Spam, Mining, CoinJoin). Sie kämen
                   auf rund 12 MB und liegen deshalb nicht im Repo. ``tools/listen.py laden`` holt sie einmal,
                   prüft jede Datei gegen das Verzeichnis und legt die Tabelle unter ``listen/`` ab.

Nicht übernommen sind Dateien, die natürliche Personen nennen, die aus Etherscan-Etiketten abgeleitet sind
(dessen Bedingungen die Wiedergabe untersagen) oder die Währungen betreffen, die das Gateway nicht verfolgt.
Das Verzeichnis nennt jede ausgelassene Datei mit Grund.

Ein Etikett ist die Angabe eines Dritten, kein Beweis, und es altert: Die Liste gibt den Stand ihres Datums wieder.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .akte import PROJEKT

ORDNER = Path(__file__).resolve().parent / "listen"
VERZEICHNIS = ORDNER / "tagpacks.json"
KERN = ORDNER / "tagpacks.csv.gz"
GROSS_NAME = "tagpacks_gross.csv.gz"
QUELLE = "GraphSense TagPacks"
SPALTEN = ("kette", "schluessel", "label", "kategorie", "missbrauch", "akteur", "vertrauen", "pack")
KETTEN = {"BTC": "bitcoin", "ETH": "ethereum", "TRX": "tron"}

# Was eine Kategorie der Liste für die Verfolgung von Geld bedeutet. «Dienst» ist nur, was die Liste selbst als Börse,
# Zahlungsdienst oder Verwahrer einstuft: Dort kennt jemand seine Kunden. Ein Name allein macht keinen Dienst.
DIENST = {"exchange", "payment_processor", "wallet_service", "hosted_wallet", "custodian", "otc"}
MISCHER = {"mixing_service", "mixer", "coinjoin"}
GESPERRT = {"black_list", "blacklist"}
MISSBRAUCH = {"ransomware": "Lösegeld-Erpressung", "sextortion": "Erpressung mit angeblichen Aufnahmen", "scam": "Betrug", "phishing": "Phishing",
              "service_hack": "Einbruch bei einem Dienst", "terrorism": "Terrorfinanzierung", "pyramid_scheme": "Schneeballsystem",
              "ponzi_scheme": "Schneeballsystem", "investment_fraud": "Anlagebetrug", "extortion": "Erpressung", "sanction": "Sanktion",
              "darkweb_crime": "Handel im Darknet", "fraud": "Betrug", "theft": "Diebstahl", "hack": "Einbruch", "malware": "Schadsoftware"}
KATEGORIE = {"exchange": "Börse", "payment_processor": "Zahlungsdienst", "wallet_service": "Verwahrer (Wallet-Dienst)", "hosted_wallet": "Verwahrer",
             "custodian": "Verwahrer", "mixing_service": "Mischdienst", "mixer": "Mischdienst", "coinjoin": "CoinJoin", "gambling": "Glücksspiel",
             "market": "Marktplatz", "marketplace": "Marktplatz", "darknet_market": "Darknet-Marktplatz", "miner": "Mining", "mining_pool": "Mining-Pool",
             "defi": "DeFi-Protokoll", "defi_dex": "Tauschprogramm (DEX)", "defi_lending": "Kreditprotokoll", "defi_bridge": "Brücke",
             "service": "Dienst ohne nähere Angabe", "organization": "Organisation", "black_list": "Sperrliste des Emittenten"}
VERTRAUEN = {"service_data": "Angabe des Dienstes selbst", "authority_data": "Angabe einer Behörde", "forensic": "forensische Auswertung",
             "web_crawl": "aus dem Web gesammelt", "ledger_immanent": "steht in der Blockchain", "heuristic": "Schätzverfahren",
             "manual_transaction": "eigene Testzahlung", "untrusted_transaction": "ungeprüfte Zahlung", "forensic_investigation": "forensische Untersuchung"}

_ADRESSE = {"bitcoin": re.compile(r"^(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71})$"),
            "ethereum": re.compile(r"^0x[0-9a-fA-F]{40}$"), "tron": re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")}
_PERSON = re.compile(r"^[A-ZÄÖÜ][A-ZÄÖÜ' -]{2,}, [A-ZÄÖÜ][a-zäöü]+")       # «NACHNAME, Vorname»: so schreiben Sanktionslisten Personen


class Listenfehler(Exception):
    """Die Liste fehlt, passt nicht zu ihrem Verzeichnis oder ist nicht lesbar. Dann gilt sie als «nicht geprüft»."""


def schluessel(adresse: str) -> str:
    """Vergleichsform: Adressen der Ethereum-Familie und Bech32 unabhängig von Gross- und Kleinschreibung."""
    a = adresse.strip()
    return a.lower() if a.lower().startswith(("0x", "bc1")) else a


def _text(wert: Any, laenge: int) -> str:
    return " ".join(str(wert).split())[:laenge] if wert not in (None, "") else ""


def zeilen_aus_pack(name: str, daten: dict) -> tuple[list[tuple], int]:
    """Die Tabellenzeilen eines TagPacks. Angaben im Kopf der Datei gelten für jeden Eintrag, der sie nicht selbst setzt.
    Rückgabe: (Zeilen, Zahl der Einträge der Datei). Übernommen wird nur, was das Gateway verfolgen kann (Bitcoin, Ethereum,
    TRON), mit gültiger Schreibweise der Adresse und ohne Etikett in der Form eines Personennamens."""
    kopf = {k: v for k, v in daten.items() if k != "tags"}
    zeilen: set[tuple] = set()
    eintraege = daten.get("tags") or []
    for e in eintraege:
        if not isinstance(e, dict):
            continue
        tag = {**kopf, **e}
        kette = KETTEN.get(str(tag.get("currency") or "").upper())
        adresse = str(tag.get("address") or "").strip()
        if not kette or not _ADRESSE[kette].match(adresse):
            continue
        konzepte = tag.get("concepts") if isinstance(tag.get("concepts"), list) else []
        kategorie = _text(tag.get("category") or next((k for k in konzepte if k not in MISSBRAUCH), ""), 40).lower()
        missbrauch = _text(tag.get("abuse") or next((k for k in konzepte if k in MISSBRAUCH), ""), 40).lower()
        label = _text(tag.get("label"), 90)
        if not label or _PERSON.match(label):
            continue
        zeilen.add((kette, schluessel(adresse), label, kategorie, missbrauch, _text(tag.get("actor"), 40), _text(tag.get("confidence"), 30), name))
    return sorted(zeilen), len(eintraege)


_KOPFZEILE = re.compile(r"^([A-Za-z_]+): ?(.*)$")
_EINTRAG = re.compile(r"^- address: ?(\S+)$")
_ZUSATZ = re.compile(r"^  ([A-Za-z_]+): ?(.*)$")


def _wert(text: str) -> Any:
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
        return t[1:-1]
    return {"true": True, "false": False}.get(t.lower(), t)


def flach_lesen(text: str) -> dict:
    """Liest ein TagPack in der einfachen Form der Massenlisten: Kopf aus «Name: Wert», dann unter «tags:» je Eintrag
    «- address: …» mit eingerückten Zusatzangaben. Mehr kann dieser Leser nicht und will er nicht können: Alles andere
    bricht ab. Dass er die festgelegten Dateien richtig liest, belegt die Prüfsumme der Tabelle im Verzeichnis."""
    daten: dict[str, Any] = {}
    eintraege: list[dict] = []
    in_tags = False
    for nr, zeile in enumerate(text.splitlines(), 1):
        if not zeile.strip() or zeile.strip() == "---":
            continue
        if not in_tags:
            m = _KOPFZEILE.match(zeile)
            if not m:
                raise Listenfehler(f"Zeile {nr}: im Kopf unerwartet «{zeile[:40]}».")
            if m.group(1) == "tags" and not m.group(2).strip():
                in_tags = True
            else:
                daten[m.group(1)] = _wert(m.group(2))
            continue
        m = _EINTRAG.match(zeile)
        if m:
            eintraege.append({"address": m.group(1)})
            continue
        m = _ZUSATZ.match(zeile)
        if not m or not eintraege:
            raise Listenfehler(f"Zeile {nr}: in der Liste unerwartet «{zeile[:40]}».")
        eintraege[-1][m.group(1)] = _wert(m.group(2))
    daten["tags"] = eintraege
    return daten


def tabelle_bytes(zeilen: Iterable[tuple]) -> bytes:
    """Die Tabelle als gepacktes CSV, bei gleichem Inhalt Byte für Byte gleich (sortiert, ohne Zeitstempel)."""
    puffer = io.StringIO()
    w = csv.writer(puffer, delimiter=";", lineterminator="\n")
    w.writerow(SPALTEN)
    w.writerows(sorted(set(zeilen)))
    roh = io.BytesIO()
    with gzip.GzipFile(fileobj=roh, mode="wb", mtime=0, compresslevel=9, filename="") as f:
        f.write(puffer.getvalue().encode("utf-8"))
    return roh.getvalue()


def ablage() -> Path:
    """Wo die geladenen Massenlisten liegen. OSINT_LISTEN stellt den Ordner um (Musterfall und Tests: ein leerer)."""
    return Path(os.environ.get("OSINT_LISTEN") or PROJEKT / "listen")


def verzeichnis() -> dict:
    try:
        return json.loads(VERZEICHNIS.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise Listenfehler(f"Das Verzeichnis der Etikettenliste fehlt oder ist nicht lesbar ({type(e).__name__}).") from e


class Liste:
    """Die geladene Liste. ``stand`` nennt Commit, Datum, Prüfsumme und Umfang, ``suchen`` schlägt eine Adresse nach."""

    def __init__(self) -> None:
        v = verzeichnis()
        self._tupel: list[tuple] = []
        self._nr: dict[tuple, int] = {}
        # Je Kette: Adresse -> Nummer ihrer Angaben. Fast jede Adresse hat genau einen Eintrag, dann steht dort nur die Zahl.
        # Bei einer halben Million Adressen entscheidet das über den Speicher.
        self._index: dict[str, dict[str, Any]] = {k: {} for k in KETTEN.values()}
        self.eintraege = 0
        self.packs = {name: str(a.get("lastmod") or "") for name, a in {**v["packs"], **v["massenlisten"]["dateien"]}.items()}
        pruefsummen = [self._lesen(KERN, v["tabelle"], "Die Etikettenliste im Repo")]
        self.umfang = "Kern"
        gross = ablage() / GROSS_NAME
        self.hinweis = ""
        if gross.is_file():
            pruefsummen.append(self._lesen(gross, v["massenlisten"]["tabelle"], "Die geladenen Massenlisten"))
            self.umfang = "Kern und Massenlisten"
        else:
            self.hinweis = (f"Die Massenlisten ({v['massenlisten']['tabelle']['eintraege']} Adressen: {v['massenlisten']['inhalt']}) sind nicht geladen. "
                            "Nachholen: python3 tools/listen.py laden")
        self.stand = {"stand": v["commit"][:12], "datum": v["datum"], "lizenz": v["lizenz"], "umfang": self.umfang, "eintraege": self.eintraege,
                      "sha256": pruefsummen[0] if len(pruefsummen) == 1 else hashlib.sha256("".join(pruefsummen).encode()).hexdigest(),
                      "sha256_kern": pruefsummen[0], **({"sha256_massenlisten": pruefsummen[1]} if len(pruefsummen) > 1 else {})}
        self.bytes = KERN.stat().st_size + (gross.stat().st_size if gross.is_file() else 0)

    def _lesen(self, datei: Path, soll: dict, was: str) -> str:
        try:
            inhalt = datei.read_bytes()
        except OSError as e:
            raise Listenfehler(f"{was} ist nicht lesbar ({type(e).__name__}).") from e
        summe = hashlib.sha256(inhalt).hexdigest()
        if summe != soll["sha256"]:
            raise Listenfehler(f"{was} passt nicht zur Prüfsumme im Verzeichnis. Sie wurde verändert oder gehört zu einem anderen Stand. "
                               "Sie wird nicht verwendet.")
        with gzip.open(io.BytesIO(inhalt), "rt", encoding="utf-8", newline="") as f:       # zeilenweise, ohne die ganze Tabelle auszupacken
            zeilen = csv.reader(f, delimiter=";")
            if tuple(next(zeilen, ())) != SPALTEN:
                raise Listenfehler(f"{was} hat nicht den erwarteten Aufbau.")
            n = 0
            for z in zeilen:
                if len(z) != len(SPALTEN) or z[0] not in self._index:
                    raise Listenfehler(f"{was} enthält eine unvollständige Zeile.")
                angaben = tuple(z[2:])
                nr = self._nr.get(angaben)
                if nr is None:
                    nr = self._nr[angaben] = len(self._tupel)
                    self._tupel.append(angaben)
                je_kette = self._index[z[0]]
                alt = je_kette.get(z[1])
                je_kette[z[1]] = nr if alt is None else (*(alt if isinstance(alt, tuple) else (alt,)), nr)
                n += 1
        if n != soll["eintraege"]:
            raise Listenfehler(f"{was} enthält {n} Einträge, das Verzeichnis nennt {soll['eintraege']}.")
        self.eintraege += n
        return summe

    def suchen(self, kette: str, adresse: str) -> list[dict]:
        """Einträge der Liste zu einer Adresse. Ethereum-Einträge gelten nur für Ethereum selbst: Auf einer anderen Kette
        kann dieselbe Adresse jemand anderem gehören (Verträge) oder gar nicht in Gebrauch sein."""
        if kette not in KETTEN.values():
            return []
        treffer = self._index[kette].get(schluessel(adresse), ())
        return [dict(zip(SPALTEN[2:], self._tupel[nr])) for nr in (treffer if isinstance(treffer, tuple) else (treffer,))]


_GELADEN: dict[tuple, Liste] = {}


def laden() -> Liste:
    """Die Liste, einmal je Prozess gelesen. Ändert sich eine der Dateien, wird neu gelesen."""
    gross = ablage() / GROSS_NAME
    marke = tuple((str(d), d.stat().st_mtime_ns, d.stat().st_size) if d.is_file() else (str(d), 0, 0) for d in (VERZEICHNIS, KERN, gross))
    if marke not in _GELADEN:
        _GELADEN.clear()
        _GELADEN[marke] = Liste()
    return _GELADEN[marke]


def einordnen(e: dict, stand_der_datei: str = "") -> dict:
    """Was ein Eintrag der Liste für die Verfolgung bedeutet: Art des Etiketts, Dienst mit Kunden, Mischdienst, und ein Satz dazu.
    Trägt ein Eintrag einen Missbrauch, ist die Adresse nie ein «Dienst», auch wenn daneben eine Kategorie steht: Dann geht es um
    die Adresse eines Täters, nicht um die einer Börse."""
    kategorie, missbrauch = e.get("kategorie") or "", e.get("missbrauch") or ""
    art = ("sanktion" if missbrauch.startswith("sanction") else "ransomware" if missbrauch == "ransomware" else "meldung" if missbrauch
           else "gesperrt" if kategorie in GESPERRT else "name")
    teile = []
    if missbrauch:
        teile.append(f"Missbrauch laut Liste: {MISSBRAUCH.get(missbrauch, missbrauch)}")
    if kategorie:
        teile.append(f"Kategorie laut Liste: {KATEGORIE.get(kategorie, kategorie)}")
    if e.get("vertrauen"):
        teile.append(f"Herkunft der Angabe: {VERTRAUEN.get(e['vertrauen'], e['vertrauen'])}")
    teile.append(f"Datei {e.get('pack')}" + (f" (Stand {stand_der_datei})" if stand_der_datei else ""))
    return {"art": art, "dienst": not missbrauch and kategorie in DIENST, "mischer": not missbrauch and kategorie in MISCHER,
            "betreiber": e.get("akteur") or "" if not missbrauch and kategorie in DIENST else "", "detail": ", ".join(teile)}
