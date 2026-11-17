"""Erkennung für die lokale Pseudonymisierung. Bibliothek ohne Bedienung, ohne Netz, nur Standardbibliothek.

Die Bedienung liegt woanders: am Terminal in tools/pseudonymisieren.py, später in der Oberfläche. Beide rufen
dieselben Funktionen auf. Funde sind Daten, die Bestätigung durch den Menschen ist davon getrennt:

    erk = erkennen(text, zuordnung=bestehende_tabelle)        Schichten 0 bis 5, ändert nichts
    ent = Entscheide()                                        was der Mensch dazu sagt
    ent.eingaben.append(("PERSON", "Anna Beispiel", 4))       Namensliste, bestätigter Kandidat, Ergänzung
    erk = erkennen(text, zuordnung=…, entscheide=ent)         neu rechnen, damit sich die Angabe fortpflanzt
    erg = anwenden(erk, ent)                                  Text mit Platzhaltern und Zuordnungstabelle

Die Schichten, in dieser Reihenfolge (docs/PSEUDONYMISIERUNG.md):

    0  technische Indikatoren schützen       schutz()
    1  Werte hinter den Feldmarken ernten    tools/feldmarken.txt
    2  Fortpflanzung in allen Schreibweisen  jede geerntete oder bestätigte Angabe
    3  Muster mit Prüfsumme                  aus tools/pii_pruefung.py
    4  Namensliste zum Fall                  Entscheide.eingaben
    5  Kandidaten im Fliesstext              Anreden, Titel, Vornamenliste. Ersetzt nie selbst.
    6  Bestätigung                           Entscheide, gesetzt von der Bedienung

Ein weiterer Erkenner (etwa ein lokales Sprachmodell) lässt sich über `erkenner=` anhängen: eine Funktion, die
einen Text nimmt und Kandidaten (Beginn, Ende, Typ, Grund) liefert. Auch sie ersetzt nie selbst.
"""
from __future__ import annotations

import csv
import functools
import ipaddress
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.pii_pruefung import KANTONE, MUSTER, PLATZHALTER  # noqa: E402

ORT = Path(__file__).resolve().parent
FELDMARKEN = ORT / "feldmarken.txt"
VORNAMEN = ORT / "vornamen.txt"

TYPEN = ("PERSON", "ORG", "ADRESSE", "TEL", "EMAIL", "GEBDAT", "AHV", "KONTO", "KFZ", "AUSWEIS", "DOMAIN", "IP")
TEILE = {"PERSON": ("name", "nachname", "vorname", "nachname-vorname", "vorname-nachname", "kuerzel"),
         "ADRESSE": ("adresse", "strasse", "ort")}
BESCHREIBUNG = {"PERSON": "Person", "ORG": "Organisation", "ADRESSE": "Adresse", "TEL": "Telefonnummer", "EMAIL": "E-Mail-Adresse",
                "GEBDAT": "Geburtsdatum", "AHV": "AHV-Nummer", "KONTO": "Bankverbindung", "KFZ": "Kontrollschild",
                "AUSWEIS": "Ausweis- oder Aktennummer", "DOMAIN": "Domain der Geschädigten", "IP": "IP-Adresse der Geschädigten"}
SCHICHT = {0: "Zuordnungstabelle", 1: "Feldmarke", 2: "Fortpflanzung", 3: "Muster", 4: "Namensliste", 5: "Kandidat",
           6: "Ergänzung", 7: "weiterer Erkenner"}


# --------------------------------------------------------------------------- Daten

@dataclass(frozen=True)
class Spanne:
    start: int
    ende: int
    art: str


@dataclass(frozen=True)
class Feldmarke:
    marke: str
    typ: str
    teil: str = ""


@dataclass
class Angabe:
    """Eine Angabe, die einen Platzhalter bekommt: eine Person, eine Adresse, eine Nummer."""
    typ: str
    schluessel: str             # gleiche Angabe, gleicher Schlüssel, gleicher Platzhalter
    wert: str                   # Klartext für die Zuordnungstabelle
    teile: dict = field(default_factory=dict)
    quelle: int = 1             # Schicht, aus der die Angabe stammt (0 Tabelle, 1 Feld, 3 Muster, 4, 5, 6)
    platzhalter: str = ""       # gesetzt, wenn die Angabe schon in der Zuordnungstabelle steht
    unsicher: bool = False      # Vor- und Nachname liessen sich nicht sicher trennen


@dataclass
class Fund:
    """Eine Fundstelle im Text. `sicher` heisst: wird ersetzt, wenn der Mensch nichts anderes sagt."""
    start: int
    ende: int
    typ: str
    schicht: int                # 1 Feld, 2 Fortpflanzung, 3 Muster, 5 Kandidat, 7 weiterer Erkenner
    quelle: int                 # Schicht, aus der die Angabe stammt
    sicher: bool
    angabe: str = ""            # Schlüssel der Angabe, leer bei Kandidaten
    grund: str = ""
    frage: str = ""             # "seite" | "geschuetzt" | "mehrdeutig" | ""
    wert: str = ""              # bei Kandidaten: die Angabe, wie sie aufgenommen würde

    @property
    def id(self) -> str:
        return f"{self.start}:{self.ende}"


@dataclass
class Entscheide:
    """Was der Mensch entschieden hat. Reine Daten, damit Terminal und Oberfläche dasselbe speichern."""
    fund: dict = field(default_factory=dict)        # Fund.id -> True (ersetzen) | False (stehen lassen)
    angabe: dict = field(default_factory=dict)      # Schlüssel der Angabe -> True | False, gilt für alle ihre Fundstellen
    seite: dict = field(default_factory=dict)       # Schlüssel einer E-Mail-Adresse -> "taeter" | "geschaedigte"
    typ: dict = field(default_factory=dict)         # Schlüssel der Angabe -> neuer Typ
    eingaben: list = field(default_factory=list)    # (Typ, Klartext, Schicht 4 | 5 | 6)


@dataclass
class Erkennung:
    text: str
    angaben: dict               # Schlüssel -> Angabe
    funde: list                 # nach Position geordnet, überschneidungsfrei
    geschuetzt: list            # Spannen der technischen Indikatoren
    tabelle: list = field(default_factory=list)     # die bestehende Zuordnungstabelle, unverändert
    verweis: dict = field(default_factory=dict)     # Schlüssel einer Angabe -> Schlüssel der Angabe, in der sie aufging

    def angabe(self, schluessel: str) -> Angabe | None:
        return self.angaben.get(self.verweis.get(schluessel, schluessel))

    def wortlaut(self, f: Fund) -> str:
        return self.text[f.start:f.ende]

    def umgebung(self, f: Fund, breite: int = 60) -> tuple[str, str, str]:
        """Die Fundstelle mit dem Text davor und danach, auf eine Zeile gebracht."""
        davor = re.sub(r"\s+", " ", self.text[max(0, f.start - breite):f.start])
        danach = re.sub(r"\s+", " ", self.text[f.ende:f.ende + breite])
        return davor, re.sub(r"\s+", " ", self.text[f.start:f.ende]), danach


@dataclass
class Ergebnis:
    text: str                   # das pseudonymisierte Dokument
    zuordnung: list             # (Platzhalter, Klartext), bestehende Einträge zuerst
    neu: list                   # davon in diesem Lauf dazugekommen
    klaerung: list              # (Platzhalter, Zeile, Grund): ersetzt, obwohl eine Rückfrage offen war
    ersetzt: dict               # Typ -> Zahl der ersetzten Fundstellen
    offen: int                  # Kandidaten, über die niemand entschieden hat (stehen geblieben)


# --------------------------------------------------------------------------- Hilfen

_UML = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss"})


def falten(s: str) -> str:
    """Schreibweise einebnen: klein, Umlaute als ae/oe/ue, ohne Akzente, Trenner als ein Leerzeichen."""
    s = unicodedata.normalize("NFC", s).casefold().translate(_UML)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return re.sub(r"[\s\-‐–'’.,/]+", " ", s).strip()


WORT = re.compile(r"[^\W\d_]+(?:[-'’][^\W\d_]+)*")
PARTIKEL = frozenset("von van de del della dello di da dos das du des le la zu zur zum vom ab ten ter den der el al bin ben y".split())
RECHTSFORM = (r"(?:AG|GmbH|SA|S\.A\.|Sàrl|Sarl|S\.à\s?r\.l\.|Sagl|SAGL|KlG|KmG|& Co\.?(?: KG)?|& Cie\.?|Ltd\.?|Inc\.?|LLC|"
              r"Genossenschaft|Stiftung|Holding)")
_RECHTSFORM_ENDE = re.compile(rf"(?:\s+|(?<=\S))(?:{RECHTSFORM})\s*$")
TITEL = re.compile(r"(?:(?:Herrn?|Frau|Hrn?\.|Fr\.|Dr\.|Prof\.|med\.|iur\.|lic\.|phil\.|dipl\.|Ing\.|RA|RAin|Wm|Kpl|Gfr|Fw|Adj|Lt|Hptm|Pol|Det|mbA|"
                   r"Mme|Mlle|Me|Sig\.(?:ra|na)?|Dott\.(?:ssa)?|Avv\.)[ \t]+)+")
NICHTS = frozenset("unbekannt unbek keine kein keiner nein dito siehe vgl wie oben nicht na n/a k.a. ka offen pendent folgt "
                   "inconnu inconnue aucun aucune sconosciuto sconosciuta nessuno".split())
ENDE_NAME = frozenset("geb geboren wohnhaft whft heimatort nationalität nationalitaet beruf ledig verheiratet geschieden alias genannt "
                      "né née nato nata domicilié domiciliée residente tel telefon mobile natel email mail".split())
MONATE = {1: ("Januar", "Jan", "janvier", "janv", "gennaio", "gen"), 2: ("Februar", "Feb", "février", "fevrier", "févr", "febbraio"),
          3: ("März", "Maerz", "Mär", "mars", "marzo", "mar"), 4: ("April", "Apr", "avril", "avr", "aprile"),
          5: ("Mai", "maggio", "mag"), 6: ("Juni", "Jun", "juin", "giugno", "giu"),
          7: ("Juli", "Jul", "juillet", "juil", "luglio", "lug"), 8: ("August", "Aug", "août", "aout", "agosto", "ago"),
          9: ("September", "Sept", "Sep", "septembre", "settembre", "set"), 10: ("Oktober", "Okt", "octobre", "oct", "ottobre", "ott"),
          11: ("November", "Nov", "novembre"), 12: ("Dezember", "Dez", "décembre", "decembre", "déc", "dicembre", "dic")}
_MONAT_NR = {falten(n): nr for nr, namen in MONATE.items() for n in namen}
_MONAT_ALT = "|".join(sorted({re.escape(n) for namen in MONATE.values() for n in namen}, key=len, reverse=True))
DATUM = re.compile(rf"(?<!\d)(?:(\d{{1,2}})\s*[./]\s*(\d{{1,2}})\s*[./]\s*(\d{{4}}|\d{{2}})|(\d{{4}})-(\d{{2}})-(\d{{2}})|"
                   rf"(\d{{1,2}})\.?\s+({_MONAT_ALT})\.?\s+(\d{{4}}))(?!\d)", re.I)
EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])")
PLZ_ORT = re.compile(r"(?:CH\s?-\s?)?(\d{4})[ \t]+([^\W\d_](?:[^\d,;/|()\n]|/(?=[^\W\d_]))*)")
FREIE_POST = frozenset("bluewin.ch gmail.com googlemail.com gmx.ch gmx.net gmx.de gmx.at hotmail.com hotmail.ch hotmail.fr hotmail.it "
                       "outlook.com outlook.de outlook.fr live.com msn.com yahoo.com yahoo.de yahoo.fr yahoo.it icloud.com me.com mac.com "
                       "sunrise.ch hispeed.ch protonmail.com proton.me protonmail.ch web.de t-online.de green.ch swissonline.ch bluemail.ch "
                       "libero.it orange.fr free.fr laposte.net ticino.com quickline.ch vtxmail.ch netplus.ch mail.com aol.com".split())


GROSS_PARTIKEL = frozenset("De Del Della Dello Di Da Dos Du Le La Van Von Zu Ten Ter El Al Ben Bin Mc Mac".split())
FUNKTION = frozenset(falten(w) for w in (
    "Der Die Das Den Dem Des Ein Eine Einen Einem Einer Eines Er Sie Es Wir Ihr Ich Du Man Am Im In An Auf Aus Bei Mit Nach Vor Zum "
    "Zur Über Unter Für Gegen Ohne Um Und Oder Aber Als Wenn Weil Dass Da Dann Danach Darauf Dabei Daher Deshalb Gemäss Laut Gestützt "
    "Anschliessend Später Heute Gestern Seit Bis Wie Was Wer Wo Nicht Kein Keine Auch Noch Nur Schon Sehr Dies Diese Dieser Dieses Sein Seine "
    "Ihre Ihren Ihrem Unser Unsere Mein Meine Alle Beide Jeder Jede Hier Dort Nun Zudem Ferner Weiter Insgesamt Zwischen Während Wegen Trotz "
    "Ist Sind War Waren Hat Haben Hatte Wird Wurde Wurden Kann Konnte Soll Sollte Muss Musste Siehe Betreffend Betrifft Sowie Bzw "
    "Les Un Une Il Elle Nous Vous Ils Elles Dans Sur Avec Pour Par Selon Ensuite Mais Donc Car Ce Cette Ces Son Sa Ses Est Sont "
    "Lo Gli Uno Una Nel Nella Con Per Secondo Poi Ma Che Non Questo Questa Suo Sua Sono").split())


def schoen(name: str) -> str:
    """«MUSTER» wird «Muster», «DE LUCA» wird «De Luca». Gemischte Schreibung bleibt, wie sie ist."""
    if not name.isupper() or len(name) < 3:
        return name
    return re.sub(r"[^\W\d_]+", lambda m: m.group().lower() if m.group().casefold() in PARTIKEL and m.start() else m.group().capitalize(), name)


def datum_lesen(s: str) -> date | None:
    m = DATUM.search(s)
    if not m:
        return None
    try:
        if m.group(1):
            jahr = int(m.group(3))
            if jahr < 100:
                jahr += 1900 if jahr > date.today().year % 100 else 2000
            return date(jahr, int(m.group(2)), int(m.group(1)))
        if m.group(4):
            return date(int(m.group(4)), int(m.group(5)), int(m.group(6)))
        return date(int(m.group(9)), _MONAT_NR[falten(m.group(8))], int(m.group(7)))
    except (ValueError, KeyError):
        return None


def tel_schluessel(s: str) -> str:
    z = re.sub(r"[^\d+]", "", s.replace("(0)", ""))
    if z.startswith("00"):
        z = "+" + z[2:]
    if z.startswith("+41"):
        z = "0" + z[3:]
    return z


def vornamen_lesen(datei: Path | None = None) -> frozenset:
    """Die Vornamenliste: Namen durch Leerraum oder Komma getrennt, # leitet einen Kommentar ein."""
    datei = Path(datei) if datei else VORNAMEN
    namen = set()
    for zeile in datei.read_text(encoding="utf-8").splitlines():
        for name in re.split(r"[\s,;]+", zeile.split("#")[0]):
            if name:
                namen.add(falten(name))
    return frozenset(namen)


# --------------------------------------------------------------------------- Feldmarken

def feldmarken_lesen(datei: Path | None = None) -> "Marken":
    """Liest tools/feldmarken.txt: je Zeile «Marke ; Typ ; Teil». Eine andere Liste ersetzt die Datei, der Code bleibt."""
    datei = Path(datei) if datei else FELDMARKEN
    liste: list[Feldmarke] = []
    for nr, zeile in enumerate(datei.read_text(encoding="utf-8-sig").splitlines(), 1):
        zeile = zeile.strip()
        if not zeile or zeile.startswith("#"):
            continue
        spalten = [s.strip() for s in zeile.split(";")]
        if len(spalten) < 2 or not spalten[0]:
            raise ValueError(f"{datei.name}, Zeile {nr}: erwartet «Marke ; Typ» oder «Marke ; Typ ; Teil».")
        marke, typ, teil = spalten[0].rstrip(":").strip(), spalten[1].upper(), (spalten[2].lower() if len(spalten) > 2 else "")
        if typ not in TYPEN:
            raise ValueError(f"{datei.name}, Zeile {nr}: Typ «{spalten[1]}» gibt es nicht. Erlaubt: {', '.join(TYPEN)}.")
        if teil and teil not in TEILE.get(typ, ()):
            raise ValueError(f"{datei.name}, Zeile {nr}: Teil «{teil}» passt nicht zu {typ}. "
                             f"Erlaubt: {', '.join(TEILE.get(typ, ())) or 'keiner'}.")
        liste.append(Feldmarke(marke, typ, teil or (TEILE[typ][0] if typ in TEILE else "")))
    if not liste:
        raise ValueError(f"{datei.name}: keine Feldmarke gefunden.")
    return Marken(liste)


def _mkey(s: str) -> str:
    return re.sub(r"[\s.:]+", "", s).casefold()


def _marke_regex(marke: str) -> str:
    teile = []
    for t in re.split(r"(\s*[/,]\s*|\s+|\.)", marke.strip()):
        if not t:
            continue
        if t == ".":
            teile.append(r"\.?")
        elif "/" in t:
            teile.append(r"[ \t]*/[ \t]*")
        elif "," in t:
            teile.append(r"[ \t]*,[ \t]*")
        elif t.isspace():
            teile.append(r"[ \t]+")
        else:
            teile.append(re.escape(t))
    return "".join(teile)


class Marken:
    def __init__(self, liste: Iterable[Feldmarke]):
        self.liste = list(liste)
        self._nach = {_mkey(m.marke): m for m in self.liste}
        alt = "|".join(_marke_regex(m.marke) for m in sorted(self.liste, key=lambda m: -len(m.marke)))
        self.mit_punkt = re.compile(rf"(?<![\w/.-])(?P<m>{alt})[ \t]*:", re.I)
        self.am_anfang = re.compile(rf"(?P<v>[ \t>*•·–-]*(?:\d{{1,2}}[.)][ \t]+)?)(?P<m>{alt})(?P<t>[ \t]*\.{{3,}}[ \t]*|[ \t]{{2,}}|[ \t]*$|[ ])", re.I)
        self.ganz = re.compile(rf"[ \t]*(?P<m>{alt})[ \t]*:?[ \t]*", re.I)

    def finden(self, s: str) -> Feldmarke | None:
        return self._nach.get(_mkey(s))

    def zelle(self, s: str) -> Feldmarke | None:
        m = self.ganz.fullmatch(s)
        return self.finden(m.group("m")) if m else None

    def nach_typ(self, typ: str, teil: str = "") -> list[Feldmarke]:
        return [m for m in self.liste if m.typ == typ and (not teil or m.teil == teil)]


@functools.lru_cache(maxsize=4)
def _standard_marken() -> Marken:
    return feldmarken_lesen()


@functools.lru_cache(maxsize=4)
def _standard_vornamen() -> frozenset:
    return vornamen_lesen()


# --------------------------------------------------------------------------- Schicht 0: technische Indikatoren

_TLD = ("com net org info biz ch li de at fr it eu uk us ru cn io co me tv cc to xyz top site online shop app dev club live pro vip icu cyou "
        "link click store tech space website work fun win bid onion su ws nl be es pt pl cz sk hu ro bg gr tr ua kz in jp kr br mx ca au nz "
        "za sg hk tw vn th id ph my ae sa il ir pk se no dk fi ee lv lt is ie lu mc mt cy hr si rs ba mk al md by ge am az example test "
        "invalid cloud email network digital world today life news media finance bank money exchange trade capital crypto wallet support "
        "help services solutions group global international swiss zuerich page host hosting center agency company tk ml ga cf gq pw "
        "art blog one monster buzz rest bar cam quest sbs cfd lol mom zip mov")
_PUNKT = r"(?:\.|\[\.\]|\(\.\)|\[dot\])"
_URL = re.compile(r"(?<![\w])(?:https?|hxxps?|ftp|s?ftp|tcp|udp)(?:://|\[:\]//|\[://\])[^\s<>\"«»]+", re.I)
_DOMAIN = re.compile(rf"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?{_PUNKT})+(?:{'|'.join(_TLD.split())}|xn--[a-z0-9]+)"
                     rf"(?::\d{{1,5}})?(?![\w-])(?:/[^\s<>\"«»]*)?", re.I)
_OKTETT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP4 = re.compile(rf"(?<![\w.+]){_OKTETT}(?:{_PUNKT}{_OKTETT}){{3}}(?:/\d{{1,2}}|:\d{{1,5}})?(?![\w]|\.\d)")
_IP6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![\w:])")
_HEX = re.compile(r"(?<![\w])(?:0x)?(?:[0-9a-fA-F]{128}|[0-9a-fA-F]{96}|[0-9a-fA-F]{64}|[0-9a-fA-F]{56}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![\w])")
_WALLET = re.compile(r"(?<![\w])(?:(?:bc1|tb1|ltc1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33}|"
                     r"[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}|[LMDrX][1-9A-HJ-NP-Za-km-z]{25,34}|(?:cosmos|addr|bnb)1[02-9ac-hj-np-z]{20,110})(?![\w])")
_DATEI = re.compile(r"(?<![\w/\\.@-])[\w][\w.+-]{0,80}\.(?:exe|dll|scr|bat|cmd|ps1|vbs|jse?|hta|lnk|iso|img|zip|rar|7z|gz|docm|xlsm|pptm|apk|"
                    r"msi|jar|html?|pdf|docx?|xlsx?|eml|msg|png|jpe?g)(?![\w])", re.I)
_MAIL_WEICH = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+(?:\[at\]|\(at\)|\[@\]|@)[A-Za-z0-9-]+(?:(?:\.|\[\.\]|\(\.\)|\[dot\])[A-Za-z0-9-]+)+(?![\w-])", re.I)
_SCHLUSS = ".,;:!?)]}»\"'’"


def schutz(text: str) -> tuple[list[Spanne], list[Spanne]]:
    """Schicht 0. Liefert die Spannen der technischen Indikatoren und, getrennt davon, die E-Mail-Adressen.

    Geschützt heisst: Keine spätere Schicht ersetzt die Stelle von sich aus. E-Mail-Adressen sind ein Sonderfall.
    Die der Täterseite bleibt stehen, die der Geschädigten wird ersetzt. Das Werkzeug kann die Seite nicht kennen
    und fragt. Eine entschärft geschriebene Adresse (name[at]beispiel[.]ch) gilt als Indikator und ist geschützt."""
    spannen: list[Spanne] = []
    post: list[Spanne] = []
    belegt = bytearray(len(text))

    def nehmen(a: int, e: int, art: str, liste: list) -> None:
        while e > a and text[e - 1] in _SCHLUSS:
            e -= 1
        if e > a and not any(belegt[a:e]):
            belegt[a:e] = b"\x01" * (e - a)
            liste.append(Spanne(a, e, art))

    for m in PLATZHALTER.finditer(text):
        nehmen(m.start(), m.end(), "Platzhalter", spannen)
    for m in _URL.finditer(text):
        nehmen(m.start(), m.end(), "URL", spannen)
    for m in _MAIL_WEICH.finditer(text):
        klar = "@" in m.group() and "[" not in m.group() and "(" not in m.group()
        nehmen(m.start(), m.end(), "E-Mail-Adresse" if klar else "E-Mail-Adresse (entschärft)", post if klar else spannen)
    for m in _IP4.finditer(text):
        nehmen(m.start(), m.end(), "IP-Adresse", spannen)
    for m in _IP6.finditer(text):
        try:
            ipaddress.ip_network(m.group(), strict=False)
        except ValueError:
            continue
        nehmen(m.start(), m.end(), "IP-Adresse", spannen)
    for m in _HEX.finditer(text):
        nehmen(m.start(), m.end(), "Hash oder Transaktions-ID", spannen)
    for m in _WALLET.finditer(text):
        if any(c.isdigit() for c in m.group()):
            nehmen(m.start(), m.end(), "Wallet-Adresse", spannen)
    for m in _DATEI.finditer(text):
        nehmen(m.start(), m.end(), "Dateiname", spannen)
    for m in _DOMAIN.finditer(text):
        tld = re.split(r"\.|\]|\)", re.split(r"[:/]", m.group())[0])[-1]
        if tld[:1].isupper() and not m.group().isupper():
            continue    # «… bei Muster.In der Folge …» ist ein fehlendes Leerzeichen, keine Domain
        nehmen(m.start(), m.end(), "Domain", spannen)
    return sorted(spannen, key=lambda s: s.start), sorted(post, key=lambda s: s.start)


# --------------------------------------------------------------------------- Angaben und ihre Schlüssel

def _ist_partikel(wort: str) -> bool:
    return (wort.islower() and wort in PARTIKEL) or wort in GROSS_PARTIKEL


def _vornamen_teilen(woerter: list[str], vornamen: frozenset, von_links: bool) -> int:
    """Wie viele Wörter am linken (oder rechten) Rand Vornamen sind. Mindestens ein Wort bleibt für den Nachnamen,
    und ein Partikel zieht das Wort danach zum Nachnamen: «Di Stefano Rita» heisst Rita, nicht Stefano Rita."""
    n = 0
    folge = woerter if von_links else woerter[::-1]
    for w in folge[:-1]:
        if all(falten(s) in vornamen for s in w.split("-")) and not _ist_partikel(w):
            n += 1
        else:
            break
    if not von_links:
        while n and _ist_partikel(woerter[-n - 1]):
            n -= 1
    return n


def person(vorname: str, nachname: str, quelle: int, unsicher: bool = False, folge: list | None = None) -> Angabe | None:
    vorname, nachname = schoen(" ".join(vorname.split())), schoen(" ".join(nachname.split()))
    if not falten(vorname + nachname):
        return None
    schluessel = "PERSON:" + " ".join(sorted(falten(f"{vorname} {nachname}").split()))
    teile = {k: v for k, v in (("vorname", vorname), ("nachname", nachname)) if v}
    if unsicher:
        teile["folge"] = " ".join(schoen(w) for w in (folge or f"{vorname} {nachname}".split()))
    return Angabe("PERSON", schluessel, f"{vorname} {nachname}".strip(), teile, quelle, unsicher=unsicher)


def person_aus_text(wert: str, vornamen: frozenset, quelle: int, aufbau: str = "vorname-nachname") -> Angabe | None:
    """Macht aus «Hans Muster», «Muster, Hans» oder «MUSTER Hans» eine Person. `aufbau` nennt, was erwartet wird:
    "vorname-nachname" (Eingabe von Hand, Zuordnungstabelle), "nachname-vorname", "name" (Reihenfolge offen), "vorname", "nachname"."""
    wert = wert.strip()
    m = TITEL.match(wert)
    if m:
        wert = wert[m.end():]
    if aufbau in ("vorname", "nachname"):
        nur = " ".join(WORT.findall(wert))
        return person(nur, "", quelle) if aufbau == "vorname" else person("", nur, quelle)
    if re.search(r"[,/]", wert):
        links, rechts = [" ".join(WORT.findall(s)) for s in re.split(r"[,/]", wert, maxsplit=1)]
        if links and rechts:    # «Muster, Hans» nennt den Nachnamen zuerst. Mit Schrägstrich gilt die Reihenfolge der Marke.
            return person(links, rechts, quelle) if aufbau == "vorname-nachname" and "," not in wert else person(rechts, links, quelle)
        wert = links or rechts
    woerter = WORT.findall(wert)
    if any(len(w) > 1 for w in woerter):
        woerter = [w for w in woerter if len(w) > 1]       # «P. Keller»: Die Initiale sagt nichts, der Nachname zählt
    if not woerter:
        return None
    if len(woerter) == 1:
        return person(woerter[0], "", quelle) if falten(woerter[0]) in vornamen else person("", woerter[0], quelle)
    gross = [w.isupper() and len(w) > 1 for w in woerter]
    if any(gross) and not all(gross):       # «MUSTER Hans», «Hans MUSTER»: Der Nachname steht in Grossbuchstaben
        return person(" ".join(w for w, g in zip(woerter, gross) if not g), " ".join(w for w, g in zip(woerter, gross) if g), quelle)
    links, rechts = _vornamen_teilen(woerter, vornamen, True), _vornamen_teilen(woerter, vornamen, False)
    if _ist_partikel(woerter[0]) and not rechts:
        return person("", " ".join(woerter), quelle)       # «Di Stefano», «von Allmen»: nur ein Nachname
    def mehrere(teil: list[str]) -> bool:       # «Maria Grazia Schmid»: zwei Vornamen oder ein Doppelname ohne Bindestrich?
        return len([w for w in teil if not _ist_partikel(w)]) > 1

    if rechts and (aufbau == "nachname-vorname" or not links):
        return person(" ".join(woerter[-rechts:]), " ".join(woerter[:-rechts]), quelle, unsicher=bool(links) or mehrere(woerter[:-rechts]), folge=woerter)
    if aufbau == "nachname-vorname":
        return person(" ".join(woerter[1:]), woerter[0], quelle, unsicher=len(woerter) > 2, folge=woerter)
    if links:
        return person(" ".join(woerter[:links]), " ".join(woerter[links:]), quelle, folge=woerter,
                      unsicher=mehrere(woerter[links:]) or (bool(rechts) and aufbau == "name"))
    return person(woerter[0], " ".join(woerter[1:]), quelle, unsicher=len(woerter) > 2 or aufbau == "name", folge=woerter)


def organisation(name: str, quelle: int) -> Angabe | None:
    name = " ".join(name.split()).strip(" ,;")
    if not falten(name):
        return None
    kern = _RECHTSFORM_ENDE.sub("", name).strip(" ,;-")
    return Angabe("ORG", "ORG:" + falten(kern or name), name, {"kern": kern} if kern and kern != name else {}, quelle)


def adresse(strasse: str, ort: str, quelle: int) -> Angabe | None:
    strasse, ort = " ".join(strasse.split()).strip(" ,;/"), " ".join(ort.split()).strip(" ,;/.")
    strasse = re.sub(r"^(?:(?:an|in|bei|auf|von|der|die|das|dem|den|im|am|à|au|aux|in|a|al|alla)\s+)+(?=\S)", "", strasse).rstrip(".")
    if not falten(strasse + ort):
        return None
    eben = re.sub(r"str(?:asse|aße|\.)?(?=\s|$)", "strasse", falten(strasse))
    teile = {k: v for k, v in (("strasse", strasse), ("ort", ort)) if v}
    return Angabe("ADRESSE", f"ADRESSE:{eben}|{falten(ort)}", ", ".join(t for t in (strasse, ort) if t), teile, quelle)


def adresse_aus_text(wert: str, quelle: int) -> Angabe | None:
    wert = " ".join(wert.split())
    m = PLZ_ORT.search(wert)
    if not m:
        return adresse(wert, "", quelle)
    ort = re.sub(r"\s+", " ", m.group()).strip(" ,;")
    rest = (wert[:m.start()] + " " + wert[m.end():]).strip(" ,;/")
    return adresse(rest, ort, quelle)


def angabe_aus_text(typ: str, wert: str, quelle: int, vornamen: frozenset = frozenset()) -> Angabe | None:
    """Eine Angabe aus Klartext: für die Namensliste, bestätigte Kandidaten, Ergänzungen und die bestehende Tabelle."""
    wert = " ".join(wert.split())
    if not wert:
        return None
    if typ == "PERSON":
        return person_aus_text(wert, vornamen, quelle)
    if typ == "ORG":
        return organisation(wert, quelle)
    if typ == "ADRESSE":
        return adresse_aus_text(wert, quelle)
    if typ == "TEL":
        return Angabe(typ, "TEL:" + tel_schluessel(wert), wert, {}, quelle) if len(re.sub(r"\D", "", wert)) >= 6 else None
    if typ == "GEBDAT":
        tag = datum_lesen(wert)
        return Angabe(typ, "GEBDAT:" + (tag.isoformat() if tag else falten(wert)), wert, {"datum": tag.isoformat()} if tag else {}, quelle)
    if typ == "EMAIL":
        return Angabe(typ, "EMAIL:" + wert.casefold(), wert, {}, quelle)
    if typ in ("AHV", "KONTO", "KFZ", "AUSWEIS"):
        eben = re.sub(r"[^0-9A-Za-z]", "", wert).upper()
        return Angabe(typ, f"{typ}:{eben}", wert, {}, quelle) if eben else None
    if typ in ("DOMAIN", "IP"):
        return Angabe(typ, f"{typ}:{wert.casefold()}", wert, {}, quelle)
    return None


class Register:
    """Die Angaben eines Falls. Gleiche Angabe, gleicher Schlüssel, gleicher Platzhalter."""

    def __init__(self, vornamen: frozenset, typen: dict | None = None):
        self.angaben: dict[str, Angabe] = {}
        self.vornamen = vornamen
        self.typen = typen or {}
        self.verweis: dict[str, str] = {}

    def aus_zuordnung(self, platzhalter: str, klartext: str) -> None:
        m = PLATZHALTER.fullmatch(platzhalter.strip())
        if not m or m.group(1) not in TYPEN:
            return      # fremder Typ: Die Zeile bleibt in der Tabelle stehen, erkannt wird damit nichts
        a = angabe_aus_text(m.group(1), klartext, 0, self.vornamen)
        if a is None:
            return
        if a.typ == "PERSON" and len(WORT.findall(klartext)) > 2 and "," not in klartext:
            a.unsicher = True       # aus «Hans Peter Müller Meier» lässt sich die Trennung nicht sicher lesen
        a.platzhalter, a.wert = platzhalter.strip(), klartext
        self.angaben.setdefault(a.schluessel, a)

    def aufnehmen(self, a: Angabe | None) -> Angabe | None:
        if a is None:
            return None
        if a.schluessel in self.typen and self.typen[a.schluessel] != a.typ:
            neu = angabe_aus_text(self.typen[a.schluessel], a.wert, a.quelle, self.vornamen)
            if neu is not None:
                self.verweis[a.schluessel] = neu.schluessel
                a = neu
        schluessel = self.verweis.get(a.schluessel, a.schluessel)
        if schluessel in self.angaben:
            return self.angaben[schluessel]
        if a.typ == "PERSON":
            gleich = self._verwandt(a)
            if gleich is not None:
                self.verweis[a.schluessel] = gleich.schluessel
                return gleich
        self.angaben[a.schluessel] = a
        return a

    def _verwandt(self, a: Angabe) -> Angabe | None:
        """«Muster» allein gehört zur einzigen bekannten Person dieses Namens, «Hans» zur einzigen mit diesem Vornamen."""
        v, n = falten(a.teile.get("vorname", "")), falten(a.teile.get("nachname", ""))
        if v and n:
            for b in self.angaben.values():     # eine Person, die bisher nur mit Nachnamen bekannt war
                if b.typ == "PERSON" and not b.teile.get("vorname") and falten(b.teile.get("nachname", "")) == n:
                    b.teile["vorname"] = a.teile["vorname"]
                    if not b.platzhalter:
                        b.wert = a.wert
                    return b
            return None
        teil, wert = ("nachname", n) if n else ("vorname", v)
        passend = [b for b in self.angaben.values() if b.typ == "PERSON" and
                   (falten(b.teile.get(teil, "")) == wert or (teil == "vorname" and falten(b.teile.get(teil, "")).split()[:1] == [wert]))]
        return passend[0] if len(passend) == 1 else None


# --------------------------------------------------------------------------- Schicht 1: Feldmarken

@dataclass
class _Feld:
    marke: Feldmarke
    start: int
    ende: int
    zeile: int
    streng: bool = False        # Marke ohne Doppelpunkt mit nur einem Leerzeichen: Der Wert muss nach seinem Typ aussehen


def _zellen(inhalt: str, trenner: str) -> list[tuple[int, int]]:
    zellen, pos = [], 0
    for stueck in inhalt.split(trenner):
        a, e = pos, pos + len(stueck)
        while a < e and inhalt[a] in " \t":
            a += 1
        while e > a and inhalt[e - 1] in " \t":
            e -= 1
        zellen.append((a, e))
        pos += len(stueck) + len(trenner)
    if trenner == "|":      # | a | b | hat vorn und hinten eine leere Zelle
        if zellen and zellen[0][0] == zellen[0][1]:
            zellen = zellen[1:]
        if zellen and zellen[-1][0] == zellen[-1][1]:
            zellen = zellen[:-1]
    return zellen


def _im_text(seg: str, basis: int, nr: int, marken: Marken) -> tuple[list[_Feld], tuple[Feldmarke, bool] | None]:
    """Sucht in einem Stück Text (Zeile oder Tabellenzelle) nach «Marke: Wert», «Marke   Wert» und «Marke Wert».
    Liefert die Felder und, wenn hinter der letzten Marke nichts mehr steht, diese Marke: Ihr Wert folgt dann darunter."""
    stellen: list[tuple[int, int, Feldmarke, bool]] = []      # (Beginn der Marke, Beginn des Werts, Marke, streng)
    vorn = marken.am_anfang.match(seg)
    kolon = [m for m in marken.mit_punkt.finditer(seg) if marken.finden(m.group("m"))]
    einfach = bool(vorn) and vorn.group("t") == " "
    vorn_mit_punkt = bool(vorn) and any(m.start() == vorn.start("m") for m in kolon)
    # Eine Feldzeile beginnt mit einer Marke. Nur dann zählen weitere Marken mit Doppelpunkt nach einem einzelnen Leerzeichen
    # («Name: Muster Vorname: Hans»). Mitten in einem Satz («… Sitz der Firma: …») ist ein Wort mit Doppelpunkt keine Marke.
    feldzeile = vorn_mit_punkt or (bool(vorn) and not einfach)
    for m in kolon:
        if feldzeile or m.start() == 0 or re.search(r"(?:[ ]{2}|[\t;|])$", seg[:m.start()]) or not seg[:m.start()].strip(" \t>*•·–-"):
            stellen.append((m.start(), m.end(), marken.finden(m.group("m")), False))
    if vorn and not vorn_mit_punkt:
        fm = marken.finden(vorn.group("m"))
        if fm and not (einfach and (not vorn.group("m")[:1].isupper() or ":" in seg[vorn.end():])):
            stellen.append((vorn.start("m"), vorn.end(), fm, einfach))
    stellen.sort(key=lambda s: s[0])
    felder: list[_Feld] = []
    wartet = None
    for i, (_, a, fm, streng) in enumerate(stellen):
        e = stellen[i + 1][0] if i + 1 < len(stellen) else len(seg)
        roh = seg[a:e]
        vorn = len(roh) - len(roh.lstrip(" \t"))
        kern = roh[vorn:]
        danach: list[_Feld] = []
        wartet_danach = None
        luecke = re.search(r"\t|[ ]{3,}", kern)
        if luecke:      # nach einer grossen Lücke beginnt etwas Neues, vielleicht ein weiteres Feld ohne Doppelpunkt
            ab = vorn + luecke.end()
            danach, wartet_danach = _im_text(roh[ab:], basis + a + ab, nr, marken)
            kern = kern[:luecke.start()]
        wert = kern.rstrip(" \t").rstrip(",;")
        if wert:
            felder.append(_Feld(fm, basis + a + vorn, basis + a + vorn + len(wert), nr, streng))
        elif i + 1 == len(stellen) and not danach:
            wartet = (fm, seg[:a].rstrip().endswith(":"))
        felder += danach
        wartet = wartet or wartet_danach
    return felder, wartet


def _felder(text: str, marken: Marken) -> list[_Feld]:
    felder: list[_Feld] = []
    kopf: tuple[str, list] | None = None        # Kopfzeile einer Tabelle: (Trenner, Marke je Spalte)
    wartet: tuple[Feldmarke, int, bool] | None = None    # Marke, deren Wert auf der nächsten Zeile steht (Marke, Zeile, mit Doppelpunkt)
    pos = 0
    zeilen = text.split("\n")
    for nr, inhalt in enumerate(zeilen):
        z0, pos = pos, pos + len(inhalt) + 1
        if not inhalt.strip():
            kopf = None
            continue
        trenner = "|" if inhalt.count("|") >= 2 or inhalt.lstrip().startswith("|") else ("\t" if "\t" in inhalt.strip("\t") else None)
        if trenner:
            zellen = _zellen(inhalt, trenner)
            if trenner == "|" and all(re.fullmatch(r"[\s:-]*", inhalt[a:e]) for a, e in zellen):
                continue        # Trennzeile |---|---|
            ms = [marken.zelle(inhalt[a:e]) if e > a else None for a, e in zellen]
            voll = [i for i, (a, e) in enumerate(zellen) if e > a]
            if len(voll) >= 2 and all(ms[i] for i in voll):
                kopf, wartet = (trenner, ms), None
                continue
            if kopf and kopf[0] == trenner and not any(ms):
                for i, (a, e) in enumerate(zellen):
                    if e > a and i < len(kopf[1]) and kopf[1][i]:
                        felder.append(_Feld(kopf[1][i], z0 + a, z0 + e, nr))
                continue
            kopf = None
            i = 0
            while i < len(zellen):
                a, e = zellen[i]
                if ms[i]:
                    j = i + 1
                    while j < len(zellen) and zellen[j][1] <= zellen[j][0]:
                        j += 1
                    if j < len(zellen) and not ms[j]:
                        felder.append(_Feld(ms[i], z0 + zellen[j][0], z0 + zellen[j][1], nr))
                        i = j + 1
                        continue
                    if j >= len(zellen):
                        wartet = (ms[i], nr, inhalt[a:e].rstrip().endswith(":"))
                elif e > a:
                    neu, offen = _im_text(inhalt[a:e], z0 + a, nr, marken)
                    felder += neu
                    if offen and i + 1 < len(zellen) and zellen[i + 1][1] > zellen[i + 1][0] and not ms[i + 1]:
                        felder.append(_Feld(offen[0], z0 + zellen[i + 1][0], z0 + zellen[i + 1][1], nr))
                        i += 1
                    elif offen:
                        wartet = (offen[0], nr, offen[1])
                i += 1
            continue
        kopf = None
        neu, offen = _im_text(inhalt, z0, nr, marken)
        strassenwort = bool(neu) and wartet is not None and wartet[0].typ == "ADRESSE" and wartet[0].teil != "ort" \
            and neu[0].streng and neu[0].marke.typ == "ADRESSE" and neu[0].marke.teil == "strasse"
        if wartet and not offen and nr - wartet[1] <= 2 and (not neu or strassenwort or (wartet[2] and all(f.streng for f in neu))):
            links = len(inhalt) - len(inhalt.lstrip())
            felder.append(_Feld(wartet[0], z0 + links, z0 + len(inhalt.rstrip()), nr))
            wartet = None
            continue
        felder += neu
        wartet = (offen[0], nr, offen[1]) if offen else None
        # Eine Adresse läuft oft auf der nächsten Zeile weiter: «Adresse: Dorfstrasse 12» und darunter «8000 Zürich»
        if neu and neu[-1].marke.typ == "ADRESSE" and neu[-1].marke.teil in ("adresse", "strasse") and nr + 1 < len(zeilen) \
                and not PLZ_ORT.search(text[neu[-1].start:neu[-1].ende]):
            folge = zeilen[nr + 1]
            m = re.match(r"[ \t]*((?:CH\s?-\s?)?\d{4}[ \t]+[^\W\d_][^\t|:]*?)[ \t]*$", folge)
            if m and not marken.am_anfang.match(folge):
                felder.append(_Feld(Feldmarke(neu[-1].marke.marke, "ADRESSE", "ort"), pos + m.start(1), pos + m.end(1), nr + 1))
    return felder


_TRENNER = re.compile(r"[ \t]*[,/]?[ \t]*")


def _namensspanne(s: str, vornamen: frozenset, zusammengesetzt: bool) -> tuple[int, int, list[tuple[str, str]]] | None:
    """Der Namensteil eines Feldwerts: ohne Titel davor, ohne Geburtsdatum, Rolle oder Wohnort danach.
    Liefert Beginn, Ende und die Wörter mit dem Trenner, der vor ihnen stand."""
    m = TITEL.match(s)
    pos = m.end() if m else 0
    woerter: list[tuple[str, str, int]] = []
    a = None
    schnitte = 0
    while True:
        t = _TRENNER.match(s, pos)
        trenner = t.group()
        w = WORT.match(s, t.end())
        if not w or (woerter and not trenner):
            break
        wort, klein = w.group(), w.group().casefold()
        schnitt = "," in trenner or "/" in trenner
        if schnitt and not woerter:
            break
        schnitte += schnitt
        if schnitte > 1 or klein in ENDE_NAME or klein in NICHTS or (falten(wort) in FUNKTION and klein not in PARTIKEL):
            break
        if not (wort[0].isupper() or klein in PARTIKEL):
            break
        if schnitt and "," in trenner and not zusammengesetzt and (wort.islower() or (len(woerter) > 1 and falten(wort) not in vornamen)):
            break       # «Muster Hans, von Zürich» oder «Muster Hans, Zürich»: Nach dem Komma folgt kein Vorname mehr
        if a is None:
            a = w.start()
        ende = w.end() + (1 if len(wort) == 1 and s[w.end():w.end() + 1] == "." else 0)      # Initiale mit Punkt
        woerter.append((trenner.strip(), wort, ende))
        pos = ende
    while woerter and woerter[-1][1].casefold() in PARTIKEL and woerter[-1][1].islower():
        woerter.pop()
    if not woerter or a is None:
        return None
    return a, woerter[-1][2], [(t, w) for t, w, _ in woerter]


_TEL_FELD = re.compile(r"(?:\+|00)?\d[\d \t./'’()-]{5,}\d")
_AHV_FELD = re.compile(r"(?<!\d)756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}(?!\d)|(?<!\d)\d{3}\.\d{2}\.\d{3}\.\d{3}(?!\d)")
_KFZ_FELD = re.compile(rf"\b(?:{KANTONE})[ ·-]?\d[\d '’]{{1,7}}\d\b|\b(?:{KANTONE})[ ·-]?\d{{2,6}}\b")
_NUMMER = re.compile(r"[A-Z0-9][A-Za-z0-9./ -]{2,40}[A-Za-z0-9]")


def _ernten(text: str, marken: Marken, vornamen: frozenset) -> list[tuple[int, int, Angabe, str]]:
    """Schicht 1. Liefert (Beginn, Ende, Angabe, Marke) für jeden Wert hinter einer Feldmarke."""
    funde: list[tuple[int, int, Angabe, str]] = []
    offen: dict[str, dict] = {}     # je Typ eine Person oder Adresse, von der erst ein Teil gelesen ist

    def schliessen(typ: str) -> None:
        h = offen.pop(typ, None)
        if not h:
            return
        teile = h["teile"]
        if typ == "PERSON":
            v, n = teile.get("vorname"), teile.get("nachname")
            if n and not v and len(WORT.findall(n[2])) > 1:
                a = person_aus_text(n[2], vornamen, 1, "name")      # «Name: Muster Hans» ohne eigenes Feld für den Vornamen
            else:
                a = person(v[2] if v else "", n[2] if n else "", 1)
        else:
            s, o = teile.get("strasse"), teile.get("ort")
            a = adresse(s[2] if s else "", o[2] if o else "", 1)
        if a:
            funde.extend((start, ende, a, marke) for start, ende, _, marke in teile.values())

    def teil_setzen(typ: str, teil: str, start: int, ende: int, zeile: int, marke: str) -> None:
        h = offen.get(typ)
        if h and (teil in h["teile"] or zeile - h["zeile"] > 6):
            schliessen(typ)
            h = None
        if h is None:
            h = offen[typ] = {"teile": {}, "zeile": zeile, "marke": marke}
        h["teile"][teil] = (start, ende, text[start:ende], marke)
        h["zeile"] = zeile
        if len(h["teile"]) == 2:
            schliessen(typ)

    for f in _felder(text, marken):
        wert, fm = text[f.start:f.ende], f.marke
        if falten(wert) in NICHTS or not re.search(r"\w", wert):
            continue
        if fm.typ == "PERSON":
            if fm.teil == "kuerzel":
                m = re.match(r"[^\W\d_]{2,6}(?![^\W_])", wert)
                if m:
                    funde.append((f.start, f.start + m.end(), Angabe("PERSON", "PERSON:kuerzel " + m.group().casefold(), m.group(),
                                                                    {"kuerzel": m.group()}, 1), fm.marke))
                continue
            firma = _RECHTSFORM_WORT.search(wert)
            if firma and fm.teil == "name":     # «Geschädigte: Muster Treuhand AG» ist eine Firma, keine Person
                angabe = organisation(wert[:firma.end()], 1)
                if angabe:
                    funde.append((f.start, f.start + firma.end(), angabe, fm.marke))
                continue
            spanne = _namensspanne(wert, vornamen, fm.teil in ("nachname-vorname", "vorname-nachname") or "/" in fm.marke or "," in fm.marke)
            if not spanne:
                continue
            a, e, woerter = spanne
            if f.streng and (sum(1 for _, w in woerter if not _ist_partikel(w)) > 4 or not re.match(r"[ \t]*(?:[,(].*)?$", wert[e:])):
                continue        # ohne Doppelpunkt zählt nur, was ganz wie ein Name aussieht
            if fm.teil in ("vorname", "nachname"):
                schnitt = next((i for i, (t, _) in enumerate(woerter) if t), None)
                if schnitt is not None:
                    e = a + re.search(r"[ \t]*[,/]", wert[a:e]).start()
                teil_setzen("PERSON", fm.teil, f.start + a, f.start + e, f.zeile, fm.marke)
                continue
            schliessen("PERSON")
            angabe = person_aus_text(wert[a:e], vornamen, 1, fm.teil)
            if angabe:
                funde.append((f.start + a, f.start + e, angabe, fm.marke))
        elif fm.typ == "ADRESSE":
            kurz = re.sub(r"\s*\([^)]*\)\s*$", "", wert).rstrip(" .")
            vorn = re.match(r"(?:[a-zäöüàéè]+[ \t]+)*", kurz).end()       # «Wohnhaft an der Dorfstrasse 12»
            f.start, kurz = f.start + vorn, kurz[vorn:]
            if not kurz or (f.streng and not re.search(r"\d", kurz)):
                continue
            teil = fm.teil
            if teil == "adresse":
                angabe = adresse_aus_text(kurz, 1)
                if angabe and angabe.teile.get("ort"):
                    schliessen("ADRESSE")
                    funde.append((f.start, f.start + len(kurz), angabe, fm.marke))
                    continue
                teil = "strasse"        # ohne PLZ: Der Ort folgt vielleicht auf der nächsten Zeile
            teil_setzen("ADRESSE", teil, f.start, f.start + len(kurz), f.zeile, fm.marke)
        elif fm.typ == "ORG":
            m = re.match(r"[^,;(\t]+", wert)
            name = m.group().rstrip() if m else ""
            if f.streng and not (name[:1].isupper() and len(name.split()) <= 6):
                continue
            angabe = organisation(name, 1)
            if angabe:
                funde.append((f.start, f.start + len(name), angabe, fm.marke))
        else:
            muster = {"TEL": _TEL_FELD, "GEBDAT": DATUM, "EMAIL": EMAIL, "AHV": _AHV_FELD, "KFZ": _KFZ_FELD,
                      "KONTO": MUSTER[1][2], "DOMAIN": _DOMAIN, "IP": _IP4}.get(fm.typ)
            treffer = list(muster.finditer(wert)) if muster else []
            if fm.typ == "KONTO":
                treffer = [m for m in treffer if MUSTER[1][3](m.group())]
            nah, letzte = [], 0
            for m in treffer:       # der Wert steht am Anfang, weitere folgen dicht («P 044 … / G 044 …»)
                if m.start() - letzte > (0 if f.streng else 15):
                    break
                nah.append(m)
                letzte = m.end()
            treffer = nah[:1] if fm.typ == "GEBDAT" else nah
            if not treffer and fm.typ in ("KONTO", "KFZ", "AUSWEIS", "AHV") and re.search(r"\d", wert):
                ganz = _NUMMER.match(wert) if not f.streng else re.fullmatch(r"[A-Z0-9][A-Za-z0-9./-]{3,30}", wert.rstrip(" .,;"))
                treffer = [ganz] if ganz else []
            for m in treffer:
                angabe = angabe_aus_text(fm.typ, m.group(), 1)
                if angabe:
                    funde.append((f.start + m.start(), f.start + m.end(), angabe, fm.marke))
    for typ in list(offen):
        schliessen(typ)
    return funde


# --------------------------------------------------------------------------- Schicht 2: Schreibweisen

_FALT = {"ä": ("ä", "ae", "a"), "ö": ("ö", "oe", "o"), "ü": ("ü", "ue", "u"), "é": ("é", "e"), "è": ("è", "e"), "ê": ("ê", "e"),
         "ë": ("ë", "e"), "à": ("à", "a"), "â": ("â", "a"), "á": ("á", "a"), "ã": ("ã", "a"), "ç": ("ç", "c"), "î": ("î", "i"),
         "ï": ("ï", "i"), "í": ("í", "i"), "ì": ("ì", "i"), "ô": ("ô", "o"), "ó": ("ó", "o"), "ò": ("ò", "o"), "õ": ("õ", "o"),
         "ù": ("ù", "u"), "û": ("û", "u"), "ú": ("ú", "u"), "ñ": ("ñ", "n"), "ć": ("ć", "c"), "č": ("č", "c"), "š": ("š", "s"),
         "ž": ("ž", "z"), "đ": ("đ", "dj", "d"), "ı": ("ı", "i"), "ğ": ("ğ", "g"), "ş": ("ş", "s")}
_DOPPEL = {"ae": ("ae", "ä"), "oe": ("oe", "ö"), "ue": ("ue", "ü"), "ss": ("ss", "ß")}
_TRENN = r"(?:[-­][ \t]*\n\s*)?"       # Silbentrennung am Zeilenende
ZW = r"(?:\s*[-‐–]\s*|\s+)"                  # zwischen zwei Namensteilen: Leerraum, Zeilenumbruch oder Bindestrich
L, R = r"(?<![^\W_])", r"(?![^\W_])"        # links und rechts kein Buchstabe und keine Ziffer
GEN = r"(?:['’]s|s|['’])?"                  # Genitiv: Musters, Muster's, Hans'


def _zeichen(wort: str) -> str:
    """Ein Wort als Muster: Umlaute und Akzente in allen Schreibungen, Silbentrennung am Zeilenende erlaubt."""
    t = unicodedata.normalize("NFC", wort).casefold()
    stuecke, i = [], 0
    while i < len(t):
        if t[i:i + 2] in _DOPPEL:
            zwei, ein = _DOPPEL[t[i:i + 2]]
            mitte = _TRENN if 2 <= i + 1 <= len(t) - 2 else ""
            stuecke.append(f"(?:{re.escape(zwei[0])}{mitte}{re.escape(zwei[1])}|{re.escape(ein)})")
            i += 2
            continue
        elif t[i] in _FALT:
            alt, i = _FALT[t[i]], i + 1
        elif t[i] in "'’":
            alt, i = ("'", "’", ""), i + 1
        else:
            alt, i = (t[i],), i + 1
        stuecke.append(re.escape(alt[0]) if len(alt) == 1 else "(?:" + "|".join(re.escape(x) for x in alt) + ")")
    if len(stuecke) >= 5:
        stuecke = stuecke[:2] + [_TRENN + s for s in stuecke[2:-1]] + stuecke[-1:]
    return "".join(stuecke)


def _folge(text: str) -> str:
    return ZW.join(_zeichen(w) for w in re.split(r"\s*-\s*|\s+", text.strip()) if w)


def _initialen(vorname: str, danach: str = r"\s*") -> str:
    """«H. », «H. P. », «J.-P. »: die erste Initiale muss stehen, weitere dürfen."""
    buchstaben = [w[0] for w in re.split(r"[\s-]+", vorname) if w]
    return re.escape(buchstaben[0]) + r"\." + "".join(rf"(?:\s*-?\s*{re.escape(b)}\.)?" for b in buchstaben[1:]) + danach


_STRASSENWORT = re.compile(r"(?i)strasse|straße|str\.|gasse|weg\b|platz|allee|rain\b|ring\b|quai|gässli|matte\b|\b(?:rue|avenue|chemin|route|via|viale|piazza)\b")


def _strasse_regex(strasse: str) -> list[str]:
    m = re.match(r"^(.*?)[\s,]*(\d+)\s*([A-Za-z])?$", strasse) or None
    vorn = None if m else re.match(r"^(\d+)\s*([A-Za-z])?[\s,]+(.+)$", strasse)
    if m:
        name, nr, zusatz = m.group(1), m.group(2), m.group(3) or ""
    elif vorn:
        name, nr, zusatz = vorn.group(3), vorn.group(1), vorn.group(2) or ""
    else:
        return [L + _folge(strasse) + R] if _STRASSENWORT.search(strasse) else []
    if not falten(name):
        return []
    stamm = re.match(r"^(.*?)[ -]?(?:strasse|straße|str\.?)$", name, re.I)
    if stamm and stamm.group(1):
        name_re = _folge(stamm.group(1)) + r"\s*-?\s*(?:strasse|straße|str\.?)"
    else:
        name_re = _folge(name)
    nummer = rf"{re.escape(nr)}\s?{re.escape(zusatz)}" if zusatz else re.escape(nr) + r"(?:\s?[a-z](?![^\W_]))?"
    return [rf"{L}{name_re}\s*,?\s*{nummer}(?!\d)", rf"(?<!\d){nummer}\s*,?\s*{name_re}{R}"]


def _ort_regex(ort: str) -> str | None:
    m = re.match(r"^(?:CH\s?-\s?)?(\d{4})\s+(.+)$", ort)
    if not m:
        return None
    return rf"(?<![\d.])(?:CH\s?-\s?)?{m.group(1)}\s+{_folge(m.group(2))}{R}(?!/[^\W\d_])"


def _allein(name: str) -> bool:
    """Darf dieser Name allein stehend ohne Rückfrage ersetzt werden? Nicht, wenn er kurz ist oder ein gewöhnliches Wort."""
    eben = falten(name)
    return len(eben) >= 3 and eben not in FUNKTION and not _ist_partikel(name)


def varianten(a: Angabe) -> list[tuple[str, str, str]]:
    """Die Schreibweisen einer Angabe als Muster: (Muster, Bezeichnung, Regel).
    Regel: "sicher", "kandidat", "nachname" (allein stehender Nachname), "vorname" (allein stehender Vorname)."""
    t = a.teile
    if a.typ == "PERSON":
        if t.get("kuerzel"):
            return [(L + re.escape(t["kuerzel"]) + R, "Kürzel", "kuerzel")]
        v, n = t.get("vorname", ""), t.get("nachname", "")
        aus: list[tuple[str, str, str]] = []
        if a.unsicher:      # Trennung unbekannt: jede mögliche annehmen, in beiden Richtungen
            woerter = (t.get("folge") or f"{v} {n}").split()
            aus.append((L + _folge(" ".join(woerter)) + GEN + R, "voller Name", "sicher"))
            for k in range(1, len(woerter)):
                eins, zwei = " ".join(woerter[:k]), " ".join(woerter[k:])
                if _ist_partikel(woerter[k - 1]):
                    continue        # zwischen «Le» und «Coultre» wird nicht getrennt
                aus.append((rf"{L}{_folge(zwei)}\s*,?\s*{_folge(eins)}{R}", "Namensteile umgestellt", "sicher"))
                aus.append((rf"{L}{_initialen(eins)}{_folge(zwei)}{GEN}{R}", "Initiale und Name", "sicher"))
                aus.append((rf"{L}{_initialen(zwei)}{_folge(eins)}{GEN}{R}", "Initiale und Name", "sicher"))
                for stueck in (eins, zwei):
                    aus.append((rf"{L}{_folge(stueck)}{GEN}{R}", "Namensteil allein", "nachname" if _allein(stueck) else "kandidat"))
            return aus
        vs = v.split()
        N, V = (_folge(n) if n else ""), (_folge(v) if v else "")
        erste = [V] + ([_folge(vs[0])] if len(vs) > 1 else [])
        if V and N:
            for vv in erste:
                aus.append((rf"{L}{vv}{ZW}{N}{GEN}{R}", "Vorname Nachname", "sicher"))
                aus.append((rf"{L}{N}\s*,?\s*{vv}{R}", "Nachname Vorname", "sicher"))
            aus.append((rf"{L}{_initialen(v)}{N}{GEN}{R}", "Initiale und Nachname", "sicher"))
            aus.append((rf"{L}{N}\s*,?\s+{_initialen(v, '')}", "Nachname und Initiale", "sicher"))
        if N:
            # Ist kein Vorname bekannt, gehört eine Initiale davor dazu: «K. Weber»
            davor = "" if V else r"(?:[^\W\d_]\.\s?(?:-?\s?[^\W\d_]\.\s?)?)?"
            aus.append((rf"{L}{davor}{N}{GEN}{R}", "Nachname allein", "nachname" if _allein(n) else "kandidat"))
            stuecke = [s for s in re.split(r"\s*-\s*|\s+", n) if s and not _ist_partikel(s)]
            if len(stuecke) > 1:
                for i, s in enumerate(stuecke):
                    if _allein(s):      # der letzte Teil eines Namens ohne Bindestrich steht oft allein: «Meier» für «Müller Meier»
                        regel = "nachname" if i == len(stuecke) - 1 and "-" not in n else "kandidat"
                        aus.append((rf"{L}{_zeichen(s)}{GEN}{R}(?!\s*-\s*\w)", "Teil eines Doppelnamens", regel))
        if V:
            for vv, wort in zip(erste, [v] + vs[:1]):
                if _allein(wort):
                    aus.append((rf"{L}{vv}{GEN}{R}", "Vorname allein", "vorname"))
        return aus
    if a.typ == "ORG":
        form = rf"(?:{ZW}{RECHTSFORM}{R})?"
        aus = [(L + _folge(a.wert) + R + form, "Name der Organisation", "sicher")]
        kern = t.get("kern", "")
        if kern and len(falten(kern)) >= 4:
            regel = "nachname" if len(kern.split()) > 1 or len(kern) >= 6 else "kandidat"
            aus.append((L + _folge(kern) + GEN + R + form, "Name ohne Rechtsform", regel))
        return aus
    if a.typ == "ADRESSE":
        aus = []
        strassen = _strasse_regex(t["strasse"]) if t.get("strasse") else []
        ort = _ort_regex(t["ort"]) if t.get("ort") else None
        for s in strassen:
            if ort:
                aus.append((rf"{s}\s*[,/|]?\s*{ort}", "Adresse", "sicher"))
                aus.append((rf"{ort}\s*[,/|]?\s*{s}", "Adresse", "sicher"))
            aus.append((s, "Strasse und Nummer", "sicher"))
        if ort:
            aus.append((ort, "PLZ und Ort", "sicher"))
        return aus
    if a.typ == "TEL":
        k = a.schluessel.split(":", 1)[1]
        sep = r"[\s./'’-]*"
        if k.startswith("0"):
            kopf, rest = rf"(?:(?:\+|00)\s*41{sep}(?:\(0\))?|0)", k[1:]
        elif k.startswith("+"):
            kopf, rest = r"(?:\+|00)", k[1:]
        else:
            kopf, rest = "", k
        if len(rest) < 5:
            return []
        return [(rf"(?<![\w+]){kopf}{sep}{sep.join(rest)}(?!\d)", "Telefonnummer", "sicher")]
    if a.typ == "GEBDAT":
        if not t.get("datum"):
            return [(L + re.escape(a.wert) + R, "Geburtsdatum", "sicher")]
        tag = date.fromisoformat(t["datum"])
        namen = "|".join(re.escape(x) for x in MONATE[tag.month])
        return [(rf"(?<![\d.])0?{tag.day}\s*[./]\s*0?{tag.month}\s*[./]\s*(?:{tag.year}|{tag.year % 100:02d})(?![\d])", "Geburtsdatum", "sicher"),
                (rf"(?<!\d){tag.year}-{tag.month:02d}-{tag.day:02d}(?!\d)", "Geburtsdatum", "sicher"),
                (rf"(?<![\d.])0?{tag.day}\.?\s+(?:{namen})\.?\s+{tag.year}(?!\d)", "Geburtsdatum", "sicher")]
    if a.typ in ("AHV", "KONTO", "KFZ", "AUSWEIS"):
        eben = a.schluessel.split(":", 1)[1]
        if len(eben) < 4:
            return []
        return [(L + r"[\s.'’·/-]?".join(re.escape(c) for c in eben) + R, BESCHREIBUNG[a.typ], "sicher")]
    if a.typ == "EMAIL":
        return [(r"(?<![\w.%+-])" + re.escape(a.wert) + r"(?![\w-])", "E-Mail-Adresse", "sicher")]
    if a.typ == "DOMAIN":
        return [(r"(?<![\w@-])(?:[\w-]+\.)*" + re.escape(a.wert) + r"(?![\w-])", "Domain", "sicher")]
    if a.typ == "IP":
        return [(r"(?<![\w.])" + re.escape(a.wert) + r"(?![\w]|\.\d)", "IP-Adresse", "sicher")]
    return []


@functools.lru_cache(maxsize=20000)
def _re(muster: str) -> re.Pattern:
    return re.compile(muster, re.I)


# --------------------------------------------------------------------------- Schicht 5: Kandidaten

ANREDE = re.compile(r"(?<![^\W_])(?:Herrn?|Frau|Hrn?\.|Fr\.|Familie|Fam\.|Eheleute|Ehepaar|Geschwister|Dr\.|Prof\.|RA|RAin|Rechtsanwalt|"
                    r"Rechtsanwältin|Monsieur|Madame|Mademoiselle|M\.|Mme|Mlle|Me|Maître|Signor|Signora|Signorina|Sig\.ra|Sig\.na|Sig\.|"
                    r"Dott\.ssa|Dott\.|Avv\.|Mr\.?|Mrs\.?|Ms\.?|Wm|Kpl|Gfr|Fw|Adj|Lt|Hptm|Pol|Det)[ \t]+")
_TITEL_DANACH = re.compile(r"(?:(?:Dr\.|Prof\.|med\.|iur\.|lic\.|phil\.|dipl\.|Ing\.|mbA)[ \t]+)*")
FIRMENWORT = re.compile(r"(?<![^\W_])(?:Firma|Fa\.|Garage|Restaurant|Hotel|Bäckerei|Metzgerei|Schreinerei|Praxis|Kanzlei|Coiffeur|Boulangerie|"
                        r"Ristorante|Pizzeria|Café|Apotheke|Drogerie|Treuhandbüro|Société|Ditta|Carrosserie|Malergeschäft)[ \t]+")
_RECHTSFORM_WORT = re.compile(rf"(?<![^\W_]){RECHTSFORM}(?![^\W_])")
_WORT_DAVOR = re.compile(r"(?<![^\s(«\"„/])([^\W\d_][\w'’.-]*|&|\+)[ \t]+$")
VERBINDER = frozenset("und et e für pour de du des della di per & +".split())
STOPP = FUNKTION | frozenset(falten(w) for w in (
    "Anzeige Strafanzeige Rapport Polizei Kantonspolizei Stadtpolizei Staatsanwaltschaft Staatsanwalt Staatsanwältin Richter Richterin Bank "
    "Konto Betrag Zahlung Überweisung Mail Telefon Nachricht Link Webseite Website Seite Internet Geld Franken Bitcoin Ether Wallet Adresse "
    "Datum Uhr Zeit Montag Dienstag Mittwoch Donnerstag Freitag Samstag Sonntag Januar Februar März April Mai Juni Juli August September "
    "Oktober November Dezember Herr Frau Doktor Direktor Direktorin Präsident Präsidentin Kollege Kollegin Verteidiger Verteidigerin "
    "Unbekannt Unbekannte Unbekannter Täter Täterschaft Geschädigte Geschädigter Beschuldigte Beschuldigter Zeuge Zeugin Auskunftsperson "
    "Sachbearbeiter Sachbearbeiterin Kanton Gemeinde Stadt Schweiz Sachverhalt Massnahmen Beilagen Feststellungen Ermittlungen Hinweis "
    "Firma Kunde Kundin Kunden Mitarbeiter Mitarbeiterin Absender Empfänger Betreff Kopie Beilage Frage Antwort").split())
GROSSWORT = frozenset(falten(w) for w in "CHF EUR USD USDT USDC BTC ETH IBAN AHV PIN TAN SMS URL IP ID PDF MD5 SHA AG SA GmbH RAPPORT "
                      "RAPPORTO KANTONSPOLIZEI STADTPOLIZEI POLICE POLIZIA STAATSANWALTSCHAFT WM KPL GFR DNS VPN TOR API CEO IT EDV PLZ".split())
MEHRDEUTIG = frozenset(falten(w) for w in "August Mark Rose Florence Paris Wolf Viola Iris Linde Mai April Juli Juni Bill Will Hope "
                       "Grace Angel Jesus Mercedes Sun Can Eden Luna Sole Stella Alba Aurora Flora Olive Franca Marina Dante Gloria".split())


_DANACH = re.compile(r"\.?[ \t]+|\.?[ \t]*\n[ \t]*")


def _name_ab(text: str, pos: int, vornamen: frozenset, mit_vorname: bool = True) -> tuple[int, int] | None:
    """Liest ab `pos` einen Namen: Vornamen aus der Liste oder Initialen, Partikel, dann ein gross geschriebenes Wort."""
    pos = _TITEL_DANACH.match(text, pos).end()
    start = None
    while True:
        w = WORT.match(text, pos)
        if not w:
            return None
        wort = w.group()
        if start is None:
            start = w.start()
        danach = _DANACH.match(text, w.end())
        weiter = WORT.match(text, danach.end()) if danach else None
        folgt_name = bool(weiter) and (weiter.group()[0].isupper() or weiter.group().casefold() in PARTIKEL) and falten(weiter.group()) not in STOPP
        initiale = len(wort) == 1 and wort.isupper() and text[w.end():w.end() + 1] == "."
        if mit_vorname and folgt_name and (initiale or (wort[0].isupper() and all(falten(s) in vornamen for s in wort.split("-")))):
            pos = danach.end()
            continue
        if folgt_name and ((wort.islower() and wort in PARTIKEL) or wort in GROSS_PARTIKEL):
            pos = danach.end()
            continue
        if not wort[0].isupper() or len(wort) < 2 or falten(wort) in STOPP:
            return None
        return start, w.end()


def _firmen(text: str, vornamen: frozenset) -> list[tuple[int, int, str]]:
    """Was nach einer Firma aussieht: Wörter vor einer Rechtsform («Muster Treuhand AG») oder nach «Firma», «Garage», «Bäckerei»."""
    aus: list[tuple[int, int, str]] = []
    for m in _RECHTSFORM_WORT.finditer(text):
        a, woerter = m.start(), 0
        while woerter < 5:
            davor = _WORT_DAVOR.search(text, max(0, a - 50), a)
            if not davor:
                break
            wort = davor.group(1)
            if wort.casefold() not in VERBINDER and (not wort[0].isupper() or falten(wort) in STOPP):
                break
            a, woerter = davor.start(1), woerter + 1
        while True:     # ein Verbindungswort am linken Rand gehört nicht zum Namen
            k = re.match(r"(\S+)[ \t]+", text[a:m.start()])
            if not k or k.group(1).casefold() not in VERBINDER:
                break
            a += k.end()
        if a < m.start() and not re.search(r"\d{4}[ \t]+$", text[max(0, a - 6):a]):     # «5000 Aarau AG» ist ein Ort mit Kanton
            aus.append((a, m.end(), f"Rechtsform «{m.group()}»"))
    for m in FIRMENWORT.finditer(text):
        spanne = _name_ab(text, m.end(), vornamen, mit_vorname=True)
        if spanne:
            a = spanne[0] if m.group().strip().casefold().rstrip(".") in ("firma", "fa", "société", "ditta") else m.start()
            aus.append((a, spanne[1], f"nach «{m.group().strip()}»"))
    return aus


def kandidaten(text: str, vornamen: frozenset, frei: Callable[[int, int], bool]) -> list[Fund]:
    """Schicht 5. Legt vor, was nach einem Namen oder einer Firma aussieht. Ersetzt wird davon nichts ohne Bestätigung."""
    funde: list[Fund] = []
    belegt: list[tuple[int, int]] = []

    def vorlegen(a: int, e: int, typ: str, grund: str) -> None:
        if e > a and frei(a, e) and not any(x < e and a < y for x, y in belegt):
            belegt.append((a, e))
            funde.append(Fund(a, e, typ, 5, 5, False, "", grund, wert=" ".join(text[a:e].split())))

    for m in ANREDE.finditer(text):
        spanne = _name_ab(text, m.end(), vornamen)
        if spanne:
            vorlegen(spanne[0], spanne[1], "PERSON", f"nach «{m.group().strip()}»")
    for a, e, grund in _firmen(text, vornamen):
        vorlegen(a, e, "ORG", grund)
    for m in WORT.finditer(text):
        wort = m.group()
        if not wort[0].isupper() or len(wort) < 2:
            continue
        if not all(falten(t) in vornamen for t in wort.split("-")) or wort.casefold() in PARTIKEL:
            if wort.isupper() and len(wort) >= 3:       # «MUSTER Hans»
                danach = re.compile(r",?[ \t]+").match(text, m.end())
                v = WORT.match(text, danach.end()) if danach else None
                if v and v.group()[0].isupper() and not v.group().isupper() and falten(wort) not in GROSSWORT \
                        and (falten(v.group()) in vornamen or falten(v.group()) not in STOPP):
                    vorlegen(m.start(), v.end(), "PERSON", "Wort in Grossbuchstaben und ein Name danach")
            continue
        spanne = _name_ab(text, m.start(), vornamen)
        if spanne and spanne[1] > m.end():
            vorlegen(spanne[0], spanne[1], "PERSON", "Vorname aus der Liste und ein Name danach")
            continue
        davor = re.compile(r"([^\W\d_][\w'’-]+),[ \t]+$").search(text, max(0, m.start() - 40), m.start())
        if davor and davor.group(1)[0].isupper() and falten(davor.group(1)) not in STOPP:
            vorlegen(davor.start(1), m.end(), "PERSON", "Name, Komma, Vorname aus der Liste")
            continue
        if falten(wort) not in MEHRDEUTIG and falten(wort) not in STOPP and len(wort) >= 3:
            vorlegen(m.start(), m.end(), "PERSON", "Vorname aus der Liste, allein stehend")
    for m in re.finditer(r"(?<![\w.])[A-ZÄÖÜ]\.[ \t]?(?:-?[A-ZÄÖÜ]\.[ \t]?)?(?=[^\W\d_])", text):
        spanne = _name_ab(text, m.end(), vornamen, mit_vorname=False)
        if spanne:
            vorlegen(m.start(), spanne[1], "PERSON", "Initiale und ein Name danach")
    return funde


# --------------------------------------------------------------------------- Erkennen

_ART_TYP = {"AHV-Nummer": "AHV", "IBAN": "KONTO", "Telefonnummer": "TEL", "Geburtsdatum": "GEBDAT", "Kontrollschild": "KFZ",
            "Kreditkartennummer": "KONTO", "E-Mail-Adresse": "EMAIL", "Strassenadresse": "ADRESSE"}
_ORT_DANACH = re.compile(r"[ \t]*[,/]?[ \t]*(?:CH\s?-\s?)?\d{4}[ \t]+(?:(?:La|Le|Les|St\.|Sankt|San|Santa|Bad)[ \t])?[^\W\d_][\w’'.-]*(?:/[^\W\d_][\w’'-]*)?"
                         r"(?:[ \t](?:am|an der|bei|b\.|im|ob|sur|sous|di|del|de|la|le|les|a\.)[ \t][^\W\d_][\w’'.-]*)?"
                         rf"(?:[ \t](?:{KANTONE})(?![^\W_]))?")
_DATUM_IM_FUND = re.compile(r"\d{1,2}\.\s?\d{1,2}\.\s?(?:19|20)\d{2}")


class _Belegung:
    def __init__(self) -> None:
        self.funde: list[Fund] = []

    def frei(self, a: int, e: int) -> bool:
        return not any(f.start < e and a < f.ende for f in self.funde)

    def gleich(self, a: int, e: int) -> Fund | None:
        return next((f for f in self.funde if f.start == a and f.ende == e), None)

    def dazu(self, f: Fund) -> bool:
        if not self.frei(f.start, f.ende):
            return False
        self.funde.append(f)
        return True


def _ueberschneidet(spannen: list[Spanne], a: int, e: int) -> Spanne | None:
    return next((s for s in spannen if s.start < e and a < s.ende), None)


def _nachbarn(text: str, a: int, e: int) -> tuple[str, str]:
    """Das Wort unmittelbar davor und danach, wenn nur Leerzeichen dazwischen stehen."""
    davor = re.compile(r"([^\W\d_][\w'’-]*\.?)[ \t]+$").search(text, max(0, a - 40), a)
    danach = re.compile(r"[ \t]+([^\W\d_][\w'’-]*)").match(text, e)
    return (davor.group(1) if davor else ""), (danach.group(1) if danach else "")


def _fortpflanzen(text: str, angaben: list[Angabe], geschuetzt: list[Spanne], post: list[Spanne], bel: _Belegung,
                  vornamen: frozenset, alle: dict, firmen: list) -> None:
    """Schicht 2. Sucht jede Angabe in allen Schreibweisen. Längere Treffer gehen vor, sichere vor Kandidaten."""
    treffer: list[tuple[int, int, int, Angabe, str, str]] = []
    for a in angaben:
        for muster, form, regel in varianten(a):
            try:
                gefunden = (re.compile(muster) if regel == "kuerzel" else _re(muster)).finditer(text)
            except re.error:
                continue
            for m in gefunden:
                if m.end() > m.start():
                    rang = 0 if regel == "sicher" else 1 if regel in ("nachname", "vorname") else 2
                    treffer.append((rang, -(m.end() - m.start()), m.start(), a, form, regel))
    treffer.sort(key=lambda t: (t[0], t[1], t[2]))
    for _, minus, start, a, form, regel in treffer:
        ende = start - minus
        wortlaut = text[start:ende]
        sicher, frage, grund = regel not in ("kandidat", "kuerzel"), "", form
        if regel in ("nachname", "vorname"):
            if wortlaut == wortlaut.lower() and not (len(wortlaut) >= 4 and _ueberschneidet(geschuetzt, start, ende)):
                continue        # klein geschrieben ist «frei» ein Wort und kein Name. In einer URL wird er vorgelegt.
            davor, danach = _nachbarn(text, start, ende)
            eigene = set(falten(a.wert).split())
            if a.typ == "PERSON" and any(x <= start and ende <= y and (x, y) != (start, ende) for x, y in firmen):
                continue        # «Favre Consulting & Cie»: Der Name steckt in einem Firmennamen. Schicht 5 legt die Firma vor.
            if regel == "nachname" and a.typ == "PERSON":
                fremd = davor.rstrip(".")
                if fremd and fremd[0].isupper() and falten(fremd) not in eigene and not ANREDE.match(davor + " ") \
                        and (falten(fremd) in vornamen or len(fremd) == 1):
                    continue    # «Anna Muster» ist eine andere Person als «Hans Muster». Schicht 5 legt sie vor.
            if regel == "vorname":
                fremd_danach = danach[:1].isupper() and falten(danach) not in eigene and falten(danach) not in STOPP
                fremd_davor = davor.isupper() and len(davor) >= 3 and falten(davor) not in eigene
                if fremd_danach or fremd_davor or falten(re.sub(r"['’]?s$|['’]$", "", wortlaut)) in MEHRDEUTIG:
                    sicher, grund = False, form + ", vielleicht eine andere Person oder ein Wort"
        hindernis = _ueberschneidet(geschuetzt, start, ende)
        if hindernis and a.typ not in ("DOMAIN", "IP") and not (a.typ == "EMAIL" and hindernis.art.startswith("E-Mail")):
            if not sicher:
                continue
            sicher, frage, grund = False, "geschuetzt", f"{form}, steht in einer geschützten Angabe ({hindernis.art})"
        elif a.typ != "EMAIL" and _ueberschneidet(post, start, ende):
            continue            # über E-Mail-Adressen entscheidet Schicht 3 als Ganzes
        gleich = bel.gleich(start, ende)
        if gleich is not None and gleich.angabe != a.schluessel and gleich.typ == a.typ and gleich.schicht == 2:
            gleich.frage = gleich.frage or "mehrdeutig"
            anderer = alle.get(gleich.angabe)
            gleich.grund += f" (passt auch auf {a.wert})" if anderer is not None and "passt auch" not in gleich.grund else ""
            continue
        bel.dazu(Fund(start, ende, a.typ, 2, a.quelle, sicher, a.schluessel, grund, frage, wert="" if sicher else a.wert))


def erkennen(text: str, *, marken: Marken | None = None, vornamen: frozenset | None = None, zuordnung: Iterable = (),
             entscheide: Entscheide | None = None, erkenner: Iterable[Callable] = ()) -> Erkennung:
    """Schichten 0 bis 5. Ändert nichts am Text. `zuordnung` ist die bestehende Tabelle des Falls, `entscheide`
    enthält, was der Mensch schon eingegeben oder bestätigt hat."""
    marken = marken or _standard_marken()
    vornamen = _standard_vornamen() if vornamen is None else vornamen
    ent = entscheide or Entscheide()
    text = unicodedata.normalize("NFC", text)
    geschuetzt, post = schutz(text)
    reg = Register(vornamen, ent.typ)
    tabelle = [(p, k) for p, k in zuordnung]
    for platzhalter, klartext in tabelle:
        reg.aus_zuordnung(platzhalter, klartext)
    bel = _Belegung()

    # Schicht 1: Feldmarken
    for start, ende, angabe, marke in _ernten(text, marken, vornamen):
        a = reg.aufnehmen(angabe)
        if a:
            bel.dazu(Fund(start, ende, a.typ, 1, 1, True, a.schluessel, f"Feld «{marke}»"))
    # Schicht 4, bestätigte Kandidaten und Ergänzungen
    for typ, wert, quelle in ent.eingaben:
        reg.aufnehmen(angabe_aus_text(typ, wert, quelle, vornamen))
    # Schicht 2
    firmen = [(a, e) for a, e, _ in _firmen(text, vornamen)]
    _fortpflanzen(text, list(reg.angaben.values()), geschuetzt, post, bel, vornamen, reg.angaben, firmen)

    # Schicht 3: Muster mit Prüfsumme
    neue: list[Angabe] = []
    bekannt = {falten(w) for a in reg.angaben.values() if a.typ in ("PERSON", "ORG") for w in WORT.findall(a.wert) if len(w) >= 4}
    treffer = [(art, m) for art, _, muster, zusatz in MUSTER for m in muster.finditer(text) if not zusatz or zusatz(m.group())]
    # Der längere Treffer geht vor: Eine Kartennummer ist keine Telefonnummer mit Ziffern davor
    for art, m in sorted(treffer, key=lambda am: (-(am[1].end() - am[1].start()), am[1].start())):
        typ = _ART_TYP[art]
        start, ende = m.span()
        if art == "Geburtsdatum":
            d = _DATUM_IM_FUND.search(m.group())
            if not d:
                continue
            start, ende = m.start() + d.start(), m.start() + d.end()
        elif art == "Strassenadresse":
            ort = _ORT_DANACH.match(text, ende)
            if ort:
                ende = ort.end()
                while text[ende - 1] in ".,;":
                    ende -= 1
        elif art == "Kontrollschild":
            gruppe = re.compile(r"[ '’]\d{3}(?!\d)").match(text, ende)
            if gruppe and ende - start <= 6:
                ende = gruppe.end()
        if not bel.frei(start, ende):
            if art != "Strassenadresse" or not bel.frei(m.start(), m.end()):
                continue
            start, ende = m.span()      # der Ort dahinter ist schon ersetzt, die Strasse noch nicht
        frage, grund = "", art
        if art == "E-Mail-Adresse":
            if _ueberschneidet(geschuetzt, start, ende):
                continue        # entschärft geschrieben oder Teil einer URL: bleibt als Indikator stehen
            lokal = falten(m.group().split("@")[0])
            if not (set(lokal.split()) & bekannt or any(b in lokal.replace(" ", "") for b in bekannt)):
                frage, grund = "seite", "E-Mail-Adresse: Täterseite (bleibt stehen) oder Geschädigte (wird ersetzt)?"
            else:
                grund = "E-Mail-Adresse mit dem Namen einer bekannten Person oder Organisation"
        elif _ueberschneidet(geschuetzt, start, ende):
            continue
        a = reg.aufnehmen(angabe_aus_text(typ, text[start:ende], 3, vornamen))
        if a and bel.dazu(Fund(start, ende, a.typ, 3, a.quelle, True, a.schluessel, grund, frage)):
            neue.append(a)
    _fortpflanzen(text, neue, geschuetzt, post, bel, vornamen, reg.angaben, firmen)

    # Domain einer E-Mail-Adresse der Geschädigten: verrät die Firma, wird vorgelegt
    for a in list(reg.angaben.values()):
        if a.typ == "EMAIL" and "@" in a.wert and (a.quelle in (0, 1, 4, 6) or ent.seite.get(a.schluessel) == "geschaedigte"):
            domain = a.wert.rsplit("@", 1)[1].casefold()
            if domain in FREIE_POST or f"DOMAIN:{domain}" in reg.angaben:
                continue
            for m in re.finditer(r"(?<![\w@.-])(?:[\w-]+\.)*" + re.escape(domain) + r"(?![\w-])", text, re.I):
                bel.dazu(Fund(m.start(), m.end(), "DOMAIN", 5, 5, False, "", "Domain einer E-Mail-Adresse der Geschädigten", "geschuetzt",
                              wert=domain))

    # Schicht 5: Kandidaten. Weitere Erkenner hängen sich hier an.
    def frei(a: int, e: int) -> bool:
        return bel.frei(a, e) and not _ueberschneidet(geschuetzt, a, e) and not _ueberschneidet(post, a, e)

    for f in kandidaten(text, vornamen, frei):
        if not marken.zelle(text[f.start:f.ende]):      # «N. AVS» ist eine Feldmarke, kein Name
            bel.dazu(f)
    for fn in erkenner:
        for start, ende, typ, grund in fn(text):
            if typ in TYPEN and 0 <= start < ende <= len(text) and frei(start, ende):
                bel.dazu(Fund(start, ende, typ, 7, 7, False, "", grund, wert=" ".join(text[start:ende].split())))
    return Erkennung(text, reg.angaben, sorted(bel.funde, key=lambda f: f.start), geschuetzt, tabelle, dict(reg.verweis))


# --------------------------------------------------------------------------- Anwenden

def stand(f: Fund, ent: Entscheide | None) -> bool | None:
    """Wird die Fundstelle ersetzt? True ja, False nein, None noch offen (ein Kandidat, über den niemand entschieden hat)."""
    ent = ent or Entscheide()
    if f.id in ent.fund:
        return ent.fund[f.id]
    if f.angabe and f.angabe in ent.angabe:
        return ent.angabe[f.angabe]
    if f.frage == "seite" and f.angabe in ent.seite:
        return ent.seite[f.angabe] != "taeter"
    return True if f.sicher else None


def platzhalter_stand(*texte: str) -> dict[str, int]:
    """Die höchste Nummer je Typ unter den Platzhaltern, die in den Texten schon stehen: {"PERSON": 7, "ORG": 2}."""
    hoechste: dict[str, int] = {}
    for text in texte:
        for m in PLATZHALTER.finditer(text or ""):
            hoechste[m.group(1)] = max(hoechste.get(m.group(1), 0), int(m.group(2)))
    return hoechste


def anwenden(erk: Erkennung, ent: Entscheide | None = None, belegt: dict | None = None) -> Ergebnis:
    """Schreibt die Platzhalter. Kandidaten ohne Entscheid bleiben stehen. Eine E-Mail-Adresse, deren Seite niemand
    geklärt hat, wird ersetzt und unter «Zur Klärung» genannt (Regel 4 der Anweisung in docs/PSEUDONYMISIERUNG.md).
    `belegt` nennt je Typ die höchste Nummer, die anderswo im Fall schon vergeben ist: in anderen Dokumenten, auch von
    anderer Hand pseudonymisiert. Neue Platzhalter zählen dahinter weiter, damit eine Nummer nie zwei Personen meint."""
    ent = ent or Entscheide()
    hoechste: dict[str, int] = {str(typ): int(nr) for typ, nr in (belegt or {}).items()}
    zuordnung: list[tuple[str, str]] = list(erk.tabelle)
    for platzhalter, _ in zuordnung:
        m = PLATZHALTER.fullmatch(platzhalter)
        if m:
            hoechste[m.group(1)] = max(hoechste.get(m.group(1), 0), int(m.group(2)))
    for m in PLATZHALTER.finditer(erk.text):        # Platzhalter, die schon im Dokument stehen, behalten ihre Nummer für sich
        hoechste[m.group(1)] = max(hoechste.get(m.group(1), 0), int(m.group(2)))
    stuecke, pos = [], 0
    neu: list[tuple[str, str]] = []
    klaerung: list[tuple[str, int, str]] = []
    ersetzt: dict[str, int] = {}
    vergeben: dict[str, str] = {}
    offen = 0
    for f in erk.funde:
        urteil = stand(f, ent)
        if urteil is None:
            offen += 1
        if not urteil or f.start < pos:
            continue
        a = erk.angaben.get(f.angabe)
        if a is None:
            continue        # ein Kandidat ohne Angabe wird erst nach der Aufnahme (Entscheide.eingaben) ersetzt
        platzhalter = a.platzhalter or vergeben.get(a.schluessel)
        if not platzhalter:
            hoechste[a.typ] = hoechste.get(a.typ, 0) + 1
            platzhalter = vergeben[a.schluessel] = f"[{a.typ}_{hoechste[a.typ]:02d}]"
            neu.append((platzhalter, a.wert))
        if f.frage == "seite" and f.angabe not in ent.seite and f.id not in ent.fund and f.angabe not in ent.angabe:
            klaerung.append((platzhalter, erk.text.count("\n", 0, f.start) + 1, "Seite der E-Mail-Adresse nicht geklärt"))
        stuecke += [erk.text[pos:f.start], platzhalter]
        pos = f.ende
        ersetzt[a.typ] = ersetzt.get(a.typ, 0) + 1
    stuecke.append(erk.text[pos:])
    return Ergebnis("".join(stuecke), zuordnung + neu, neu, klaerung, ersetzt, offen)


# --------------------------------------------------------------------------- Vorgang: derselbe Ablauf für Terminal und Oberfläche

class Vorgang:
    """Ein Dokument auf dem Weg durch die Bestätigung. Hält Text, Entscheide und die aktuelle Erkennung zusammen.
    Jede Eingabe rechnet neu, damit sich eine bestätigte oder ergänzte Angabe im ganzen Dokument fortpflanzt."""

    def __init__(self, text: str, *, zuordnung: Iterable = (), namensliste: Iterable = (), marken: Marken | None = None,
                 vornamen: frozenset | None = None, erkenner: Iterable[Callable] = (), belegt: dict | None = None):
        self.text = text
        self.zuordnung = list(zuordnung)
        self.belegt = dict(belegt or {})        # höchste Nummer je Typ, die anderswo im Fall schon vergeben ist
        self.marken, self.vornamen, self.erkenner = marken, vornamen, tuple(erkenner)
        self.ent = Entscheide()
        for eintrag in namensliste:
            typ, wert = eintrag if isinstance(eintrag, (tuple, list)) else ("PERSON", eintrag)
            self.ent.eingaben.append((typ, wert, 4))
        self.erk = self._rechnen()

    def _rechnen(self) -> Erkennung:
        self.erk = erkennen(self.text, marken=self.marken, vornamen=self.vornamen, zuordnung=self.zuordnung, entscheide=self.ent,
                            erkenner=self.erkenner)
        return self.erk

    def aufnehmen(self, wert: str, typ: str = "PERSON", schicht: int = 6) -> int:
        """Eine Angabe ergänzen (Schicht 6) oder einen Kandidaten bestätigen (Schicht 5). Liefert die Zahl ihrer Fundstellen."""
        if typ not in TYPEN:
            raise ValueError(f"Typ «{typ}» gibt es nicht.")
        a = angabe_aus_text(typ, wert, schicht, self.vornamen if self.vornamen is not None else _standard_vornamen())
        if a is None:
            return 0
        self.ent.eingaben.append((typ, wert, schicht))
        self._rechnen()
        ziel = self.erk.angabe(a.schluessel)
        eigene = [f for f in self.erk.funde if ziel is not None and f.sicher and f.angabe == ziel.schluessel]
        if schicht == 6:        # wer eine Angabe von Hand ergänzt, nimmt ein früheres Nein zu derselben Stelle zurück
            for f in eigene:
                if self.ent.fund.get(f.id) is False:
                    del self.ent.fund[f.id]
        return len(eigene)

    def bestaetigen(self, f: Fund, typ: str | None = None, wert: str | None = None) -> int:
        """Einen Kandidaten annehmen. Gehört er schon zu einer Angabe, wird die Stelle ersetzt. Sonst wird er zur Angabe
        und pflanzt sich im ganzen Dokument fort. Liefert die Zahl der Fundstellen."""
        if f.angabe and not typ and not wert:
            self.ent.fund[f.id] = True
            return 1
        return self.aufnehmen(wert or f.wert or self.erk.wortlaut(f), typ or f.typ, 5)

    def verwerfen(self, f: Fund) -> None:
        self.ent.fund[f.id] = False

    def angabe_entscheiden(self, schluessel: str, ersetzen: bool) -> None:
        self.ent.angabe[schluessel] = ersetzen

    def seite(self, schluessel: str, seite: str) -> None:
        if seite not in ("taeter", "geschaedigte"):
            raise ValueError("Seite ist «taeter» oder «geschaedigte».")
        self.ent.seite[schluessel] = seite
        self._rechnen()

    def typ_aendern(self, schluessel: str, typ: str) -> None:
        if typ not in TYPEN:
            raise ValueError(f"Typ «{typ}» gibt es nicht.")
        self.ent.typ[schluessel] = typ
        self._rechnen()

    def fragen(self) -> list[Angabe]:
        """E-Mail-Adressen, deren Seite noch niemand genannt hat."""
        offen = {f.angabe for f in self.erk.funde if f.frage == "seite" and f.angabe not in self.ent.seite
                 and f.angabe not in self.ent.angabe and f.id not in self.ent.fund}
        return [self.erk.angaben[s] for s in sorted(offen)]

    def kandidaten(self) -> list[Fund]:
        return [f for f in self.erk.funde if stand(f, self.ent) is None]

    def ergebnis(self) -> Ergebnis:
        return anwenden(self.erk, self.ent, self.belegt)

    def als_dict(self) -> dict:
        """Der Stand als einfache Daten, für die Oberfläche."""
        funde = []
        for f in self.erk.funde:
            davor, wortlaut, danach = self.erk.umgebung(f)
            a = self.erk.angaben.get(f.angabe)
            funde.append({"id": f.id, "start": f.start, "ende": f.ende, "typ": f.typ, "schicht": f.schicht, "quelle": f.quelle,
                          "sicher": f.sicher, "angabe": f.angabe, "angabe_wert": a.wert if a else f.wert, "grund": f.grund, "frage": f.frage,
                          "stand": stand(f, self.ent), "davor": davor, "wortlaut": wortlaut, "danach": danach,
                          "zeile": self.erk.text.count("\n", 0, f.start) + 1})
        return {"funde": funde, "fragen": [{"angabe": a.schluessel, "wert": a.wert} for a in self.fragen()],
                "geschuetzt": [{"start": s.start, "ende": s.ende, "art": s.art} for s in self.erk.geschuetzt],
                "typen": list(TYPEN)}


# --------------------------------------------------------------------------- Zuordnungstabelle

def zuordnung_lesen(datei: Path) -> list[tuple[str, str]]:
    """Liest die Tabelle im Format von tools/reidentifizieren.py: [TYP_01];Klartext, Strichpunkt, keine Kopfzeile."""
    paare: list[tuple[str, str]] = []
    with open(datei, newline="", encoding="utf-8-sig") as f:
        for nr, zeile in enumerate(csv.reader(f, delimiter=";"), 1):
            if not zeile or not zeile[0].strip() or zeile[0].lstrip().startswith("#"):
                continue
            if len(zeile) < 2 or not PLATZHALTER.fullmatch(zeile[0].strip()):
                raise ValueError(f"Zeile {nr} der Zuordnung hat nicht die Form [TYP_01];Klartext.")
            paare.append((zeile[0].strip(), zeile[1].strip()))
    return paare


def zuordnung_schreiben(datei: Path, paare: Iterable[tuple[str, str]]) -> None:
    datei = Path(datei)
    with open(datei, "w", newline="", encoding="utf-8") as f:
        schreiber = csv.writer(f, delimiter=";", lineterminator="\n")
        for platzhalter, klartext in paare:
            schreiber.writerow([platzhalter, klartext])
    try:
        os.chmod(datei, 0o600)
    except OSError:
        pass
