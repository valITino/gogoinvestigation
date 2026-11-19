"""Das Fehlerprotokoll der Oberfläche: was schiefging, an einem Ort, zum Ansehen, Kopieren und Speichern.

Wozu: Wer einen Fehler meldet oder mit einem Sprachmodell bespricht, braucht den Wortlaut. Bisher stand er im Terminal,
in dem die Oberfläche läuft, oder nirgends.

Was hineinkommt:
  - unerwartete Fehler des Servers, mit der Aufrufliste
  - Absagen an eine Aktion: dass es sie gab, und bei den Aktionen in MIT_WORTLAUT die Meldung, die auch im Fenster stand
  - Fehler einer Ermittlung: was Claude Code am Fehlerkanal meldet, ein Ende mit Fehler, eine Abfrage mit Fehlschlag
  - Werkzeuge des Projekts, die die Oberfläche startet und die mit einem Fehler enden
  - Fehler aus dem Browserfenster

Was nie hineinkommt: ein Schlüssel, das Geheimnis der Oberfläche, der Benutzerordner, der Name des Rechners. Jeder Eintrag
wird beim Eintragen bereinigt (bereinigen): Werte bekannter Schlüssel sind durch den Namen ihrer Variablen ersetzt, Pfade
gekürzt, und was die PII-Prüfung als Angabe erkennt (Rufnummer, IBAN, AHV-Nummer …), ist durch seine Art ersetzt.
Namen erkennt niemand. Deshalb steht der Wortlaut einer Absage nur da, wenn die Aktion keinen Dateinamen und keine Eingabe
des Sachbearbeiters nennen kann: Was aus dem Akten-Eingang, vom lokalen Bildschirm für Klartext, vom Zurückführen oder aus
der PII-Prüfung einer Nachricht kommt, steht ohne Wortlaut da. Und die Seite sagt, dass vor dem Weitergeben durchzusehen ist.

Wo es liegt: im Speicher des Servers und als Datei in der Ablage ausserhalb des Projekts (fehlerprotokoll.jsonl, nur für
den Benutzer lesbar). So übersteht es das Ende der Oberfläche. Im Projekt und in einer Fallakte steht davon nichts.

Bibliothek ohne Netz, nur Standardbibliothek. Geschrieben wird nur in die Ablage.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import socket
import tempfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

from gateway import plattform
from gateway.akte import PROJEKT
from gateway.quellen import QUELLEN
from tools.pii_pruefung import MUSTER

DATEI = "fehlerprotokoll.jsonl"
IM_SPEICHER = 500               # so viele Einträge behält der Server im Speicher
DATEI_GROESSE = 2 * 1024 * 1024     # wird die Datei grösser, fallen die ältesten Zeilen weg
IN_DER_DATEI = 2000                 # so viele Zeilen bleiben dann höchstens, die neuesten
MELDUNG_LAENGE, EINZELHEITEN_LAENGE = 2000, 8000
EINZELHEITEN_ANFANG = 1500      # von zu langen Einzelheiten bleiben der Anfang und das Ende: Bei einer Aufrufliste steht der Fehler am Ende
STUFEN = {"fehler": "Fehler", "hinweis": "Hinweis"}
BEREICHE = ("Oberfläche", "Aktion", "Ermittlung", "Werkzeug", "Browser")
# Aktionen, deren Absage im Wortlaut festgehalten wird: Ihre Meldungen nennen weder einen Dateinamen noch eine Eingabe des
# Sachbearbeiters. Alles andere steht ohne Wortlaut da, auch jede Aktion, die später dazukommt und hier nicht eingetragen ist.
MIT_WORTLAUT = ("anmelden", "rueckfrage", "fall_loeschen", "freigabe", "pflichtquellen", "dokumente", "quelle_", "abschalten", "fehler_", "ermittlung_")
GEHEIM_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSW|AUTH|CREDENTIAL|GEHEIM", re.I)
SCHLUESSELDATEI = ".env"        # im Projektordner. Gelesen werden hier nur die Namen der Einstellungen
# Was nach einem Schlüssel aussieht, auch wenn sein Wert hier nicht bekannt ist: in einer Adresse, in einer Kopfzeile, als Zuweisung
GEHEIM_MUSTER = (
    (re.compile(r"(?i)([?&](?:api[-_]?key|key|token|access[-_]token|auth|secret|passwor[dt]|pw)=)[^&\s\"'<>]+"), r"\1‹entfernt›"),
    (re.compile(r"(?i)\b((?:proxy-)?authorization\"?\s*[:=]\s*\"?(?:bearer|basic|token)?\s*)[A-Za-z0-9._~+/=-]{8,}"), r"\1‹entfernt›"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1‹entfernt›"),
    (re.compile(r"(?i)\b((?:x-)?(?:api[-_]?key|auth[-_]?token|access[-_]?token|secret)\"?\s*[:=]\s*\"?)[A-Za-z0-9._~+/=-]{8,}"), r"\1‹entfernt›"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "‹Schlüssel›"),
)
# Namen von Benutzer oder Rechner, die auch ein gewöhnliches Wort sind: Sie zu ersetzen, machte das Protokoll unlesbar und verriete nichts
_ALLTAGSNAMEN = {"root", "user", "admin", "runner", "ubuntu", "kali", "debian", "test", "home", "osint", "localhost", "linux", "windows", "server", "desktop", "laptop", "claude", "python"}


_GEMERKT: dict = {"zeit": 0.0, "paare": []}
MERKDAUER = 30.0                # Sekunden: so lange gelten die gelesenen Schlüsselwerte, damit nicht jeder Eintrag die Schlüsseldatei liest


def _namen_der_schluesseldatei() -> list[str]:
    """Die Namen der Einstellungen in der Schlüsseldatei des Projekts. Nur die Namen: Die Werte liest plattform.einstellung."""
    try:
        zeilen = (Path(os.environ.get("OSINT_PROJEKT") or PROJEKT) / SCHLUESSELDATEI).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [z.partition("=")[0].strip() for z in zeilen if "=" in z and not z.lstrip().startswith("#")]


def schluesselwerte() -> list[tuple[str, str]]:
    """(Wert, Name der Variablen) für alles, was ein Schlüssel sein kann. Nur für das Ersetzen: Ein Wert verlässt diese Funktion
    nie in eine Ausgabe.
      - die Schlüssel der Quellen, aus der Umgebung oder der Schlüsseldatei
      - jede Einstellung der Schlüsseldatei und jede Variable der Umgebung, deren Name nach einem Geheimnis klingt. Aus der
        Umgebung nur Werte, die kein blosses Wort sind: «false» oder «keyring» sind keine Schlüssel
      - Zugangsdaten in der Adresse des Proxys (OSINT_PROXY)"""
    jetzt = time.monotonic()
    if _GEMERKT["zeit"] and jetzt - _GEMERKT["zeit"] < MERKDAUER:
        return _GEMERKT["paare"]
    paare: dict[str, str] = {}
    for name in [q.env for q in QUELLEN if q.env] + [n for n in _namen_der_schluesseldatei() if GEHEIM_NAME.search(n)]:
        wert = plattform.einstellung(name).strip()
        if len(wert) >= 6:
            paare.setdefault(wert, name)
    for name, wert in os.environ.items():
        wert = wert.strip()
        if GEHEIM_NAME.search(name) and len(wert) >= 8 and not wert.isalpha():
            paare.setdefault(wert, name)
    proxy = plattform.einstellung("OSINT_PROXY")
    if "@" in proxy:        # socks5h://benutzer:passwort@rechner:1080
        paare.setdefault(proxy, "OSINT_PROXY")
        zugang = proxy.rpartition("@")[0].rpartition("//")[2]
        if len(zugang) >= 6:
            paare.setdefault(zugang, "Zugangsdaten in OSINT_PROXY")
    _GEMERKT.update(zeit=jetzt, paare=sorted(paare.items(), key=lambda p: -len(p[0])))
    return _GEMERKT["paare"]


def _benutzer() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):         # ein Konto ohne Eintrag im System
        return ""


def _orte(ablage: Path | None) -> list[tuple[str, str]]:
    """(Pfad, Ersatz), längste zuerst: Projektordner, Ablage, Benutzerordner, Ordner für Zwischendateien. In beiden Schreibweisen."""
    paare = [(str(PROJEKT), "<Projekt>"), (str(Path.home()), "~"), (tempfile.gettempdir(), "<Temp>")]
    if ablage is not None:
        paare.append((str(ablage), "<Ablage>"))
    alle = []
    for pfad, ersatz in paare:
        echt = os.path.realpath(pfad)       # derselbe Ort ohne Verweise und Kurznamen: Eine Meldung kann die eine oder die andere Form nennen
        for form in {pfad, pfad.replace("\\", "/"), echt, echt.replace("\\", "/")}:
            if len(form) > 3:
                alle.append((form, ersatz))
    return sorted(set(alle), key=lambda p: -len(p[0]))


def kuerzen(text: str, laenge: int = EINZELHEITEN_LAENGE, anfang: int = EINZELHEITEN_ANFANG) -> str:
    """Kürzt lange Einzelheiten so, dass Anfang und Ende bleiben."""
    if len(text) <= laenge:
        return text
    marke = "\n[… gekürzt …]\n"
    return text[:anfang] + marke + text[-(laenge - anfang - len(marke)):]


def bereinigen(text: object, geheim: tuple[str, ...] = (), ablage: Path | None = None) -> str:
    """Ein Text, wie er ins Fehlerprotokoll darf: ohne Schlüssel, ohne das Geheimnis der Oberfläche, ohne Benutzerordner und
    Rechnernamen, und ohne die Angaben, die die PII-Prüfung erkennt. Technische Indikatoren bleiben stehen (IP, Domain, Hash)."""
    t = str(text or "")
    for wert in sorted((g for g in geheim if g and len(g) >= 6), key=len, reverse=True):
        t = t.replace(wert, "‹Geheimnis der Oberfläche›")
    for wert, name in schluesselwerte():
        t = t.replace(wert, f"‹{name}›")
    for muster, ersatz in GEHEIM_MUSTER:
        t = muster.sub(ersatz, t)
    for pfad, ersatz in _orte(ablage):       # nur ganze Pfade: /root wird ersetzt, /rootfs nicht
        t = re.sub(re.escape(pfad) + r"(?![\w.-])", lambda _m, ersatz=ersatz: ersatz, t)
    for name, ersatz in ((_benutzer(), "‹Benutzer›"), (socket.gethostname(), "‹Rechner›")):
        if name and len(name) >= 3 and name.casefold() not in _ALLTAGSNAMEN:
            t = re.sub(rf"(?<![\w-]){re.escape(name)}(?![\w-])", ersatz, t)
    for art, _stufe, muster, pruefer in MUSTER:
        t = muster.sub(lambda m, art=art, pruefer=pruefer: f"‹{art}›" if pruefer is None or pruefer(m.group(0)) else m.group(0), t)
    return t


def kopfzeile(e: dict) -> str:
    """Ein Eintrag in einer Zeile, wie er im Text zum Kopieren und Speichern steht. Die Einzelheiten folgen eingerückt darunter."""
    return (f"[{e['zeit']}] {STUFEN[e['stufe']].upper()} · {e['bereich']}" + (f" · Fall {e['fall']}" if e["fall"] else "") + f": {e['meldung']}"
            + (f" (insgesamt {e['mal']} mal, zuletzt {e['zuletzt']})" if e.get("mal") else ""))


class Fehlerbuch:
    """Die Einträge eines Laufs der Oberfläche und, aus der Datei, die der Läufe davor."""

    def __init__(self, ablage: Path | None, lauf: str, geheim=lambda: ()):
        self.ablage, self.lauf, self.geheim = ablage, lauf, geheim
        self.sperre = threading.Lock()
        self.eintraege: list[dict] = []
        self.nummer = 0
        self.schreibfehler = ""
        self.zaehler = {"fehler": 0, "hinweis": 0}      # Einträge dieses Laufs, jede Wiederholung mitgezählt: für die Navigation
        self._zuletzt: dict[str, float] = {}
        self._rechte = False
        self._laden()

    @property
    def datei(self) -> Path | None:
        return self.ablage / DATEI if self.ablage is not None else None

    def _laden(self) -> None:
        """Die Einträge früherer Läufe aus der Datei: Sie stehen im Protokoll, als «früher» gekennzeichnet."""
        if self.datei is None or not self.datei.is_file():
            return
        try:
            zeilen = self.datei.read_text(encoding="utf-8", errors="replace").splitlines()[-IM_SPEICHER:]
        except OSError:
            return
        for zeile in zeilen:
            try:
                e = json.loads(zeile)
            except ValueError:
                continue
            if isinstance(e, dict) and e.get("meldung"):
                self.nummer += 1
                self.eintraege.append({"nr": self.nummer, "zeit": str(e.get("zeit") or ""), "lauf": str(e.get("lauf") or ""), "bereich": str(e.get("bereich") or ""),
                                       "stufe": e.get("stufe") if e.get("stufe") in STUFEN else "hinweis", "fall": str(e.get("fall") or ""),
                                       "meldung": str(e["meldung"]), "einzelheiten": str(e.get("einzelheiten") or "")})

    def eintragen(self, bereich: str, stufe: str, meldung: object, einzelheiten: object = "", fall: str = "") -> dict:
        """Ein Eintrag. Meldung und Einzelheiten werden bereinigt, bevor sie irgendwo stehen. Das Eintragen selbst scheitert nie:
        Lässt sich ein Text nicht bereinigen, steht statt seiner nur da, dass es so war."""
        try:
            geheim = tuple(self.geheim())
            meldung = bereinigen(" ".join(str(meldung or "").split())[:4 * MELDUNG_LAENGE], geheim, self.ablage)[:MELDUNG_LAENGE]
            einzelheiten = kuerzen(bereinigen(kuerzen(str(einzelheiten or "").strip(), 4 * EINZELHEITEN_LAENGE, 2 * EINZELHEITEN_ANFANG), geheim, self.ablage))
        except Exception as e:      # nie darf ein Fehler beim Festhalten eines Fehlers den Server treffen
            meldung, einzelheiten = f"Ein Eintrag liess sich nicht bereinigen und wurde deshalb nicht festgehalten ({type(e).__name__}).", ""
        eintrag = {"zeit": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "lauf": self.lauf, "bereich": bereich if bereich in BEREICHE else "Oberfläche",
                   "stufe": stufe if stufe in STUFEN else "hinweis", "fall": str(fall or ""), "meldung": meldung, "einzelheiten": einzelheiten}
        with self.sperre:
            self.zaehler[eintrag["stufe"]] += 1
            letzter = self.eintraege[-1] if self.eintraege else None
            if letzter is not None and all(letzter[k] == eintrag[k] for k in ("lauf", "bereich", "stufe", "fall", "meldung", "einzelheiten")):
                # Dieselbe Meldung gleich noch einmal: Sie wird gezählt, nicht wiederholt. So füllt eine Schleife das Protokoll nicht
                letzter["mal"] = int(letzter.get("mal") or 1) + 1
                letzter["zuletzt"] = eintrag["zeit"]
                return dict(letzter)
            self.nummer += 1
            eintrag = {"nr": self.nummer, **eintrag}
            self.eintraege.append(eintrag)
            del self.eintraege[:-IM_SPEICHER]
            self._anhaengen(eintrag)
        return dict(eintrag)

    def sauber(self, text: object) -> str:
        """Ein Text, bereinigt wie ein Eintrag, aber ohne ihn einzutragen: für Meldungen, die die Oberfläche anderswo zeigt
        (etwa die Zeile, die Claude Code am Fehlerkanal gemeldet hat, über dem Chat). Scheitert nie."""
        try:
            return bereinigen(text, tuple(self.geheim()), self.ablage)
        except Exception:
            return "(Die Meldung liess sich nicht bereinigen und wird deshalb nicht gezeigt.)"

    def ausnahme(self, bereich: str, was: str, fehler: BaseException, fall: str = "") -> dict:
        """Ein unerwarteter Fehler, mit seiner Aufrufliste."""
        liste = "".join(traceback.format_exception(type(fehler), fehler, fehler.__traceback__))
        return self.eintragen(bereich, "fehler", f"{was}: {type(fehler).__name__}: {fehler}", liste, fall)

    def _anhaengen(self, eintrag: dict) -> None:
        if self.datei is None:
            return
        try:
            orte = []
            if not self.ablage.is_dir():        # eine Ablage, die erst hier entsteht, ist nur für den Benutzer zugänglich
                self.ablage.mkdir(parents=True, exist_ok=True)
                orte.append((self.ablage, 0o700))
            # Die Datei entsteht schon mit den Rechten «nur für den Benutzer»: So ist sie in keinem Augenblick für andere lesbar
            with os.fdopen(os.open(self.datei, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a", encoding="utf-8") as f:
                f.write(json.dumps({k: w for k, w in eintrag.items() if k not in ("nr", "mal", "zuletzt")}, ensure_ascii=False) + "\n")
            if not self._rechte:                # einmal je Lauf auch für eine Datei, die es schon gab (von früher, zurückkopiert)
                self._rechte = True
                orte.append((self.datei, 0o600))
            for ort, rechte in orte:
                try:
                    os.chmod(ort, rechte)
                except OSError:
                    pass
            if self.datei.stat().st_size > DATEI_GROESSE:       # die Datei wächst nicht ohne Ende: Die ältesten Zeilen fallen weg
                zeilen = self.datei.read_text(encoding="utf-8", errors="replace").splitlines()[-IN_DER_DATEI:]
                while len(zeilen) > 1 and sum(len(z.encode("utf-8")) + 1 for z in zeilen) > DATEI_GROESSE // 2:
                    zeilen = zeilen[len(zeilen) // 2:]      # auch bei sehr langen Einträgen bleibt danach Luft bis zum nächsten Kürzen
                self.datei.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
            self.schreibfehler = ""
        except OSError as e:
            self.schreibfehler = type(e).__name__      # ohne die Datei bleibt das Protokoll im Speicher

    def selten(self, was: str, abstand: float = 60.0) -> bool:
        """Wahr höchstens einmal je `abstand` Sekunden. Für Meldungen, die sich von aussen beliebig oft auslösen lassen (eine
        Anfrage ohne Geheimnis, eine Anfrage von fremder Seite): Sie sollen das Protokoll nicht füllen."""
        jetzt = time.monotonic()
        with self.sperre:
            if was in self._zuletzt and jetzt - self._zuletzt[was] < abstand:
                return False
            self._zuletzt[was] = jetzt
            return True

    def leeren(self) -> int:
        """Löscht alle Einträge, im Speicher und in der Datei."""
        with self.sperre:
            zahl = len(self.eintraege)
            self.eintraege = []
            self.zaehler = {"fehler": 0, "hinweis": 0}
            if self.datei is not None:
                try:
                    self.datei.unlink(missing_ok=True)
                except OSError as e:
                    self.schreibfehler = type(e).__name__
        return zahl

    def liste(self) -> list[dict]:
        with self.sperre:
            return [dict(e) for e in self.eintraege]

    def zahl(self) -> dict:
        """Wie oft in diesem Lauf etwas eingetragen wurde, je Stufe, und welcher Lauf das ist: für die Zahl in der Navigation."""
        with self.sperre:
            return {"fehler": self.zaehler["fehler"], "hinweise": self.zaehler["hinweis"], "lauf": self.lauf}

    def text(self, kopf: str = "") -> str:
        """Das Protokoll als Text, zum Kopieren und Speichern: neueste Einträge zuletzt, frühere Läufe gekennzeichnet."""
        zeilen = [kopf.rstrip(), ""] if kopf else []
        lauf = None
        for e in self.liste():
            if e["lauf"] != lauf:
                lauf = e["lauf"]
                zeilen += ["", f"== Lauf der Oberfläche {lauf or 'unbekannt'}" + (" (dieser)" if lauf == self.lauf else " (früher)"), ""]
            zeilen.append(kopfzeile(e))
            if e["einzelheiten"]:
                zeilen += ["    " + z for z in e["einzelheiten"].splitlines()]
        return "\n".join(zeilen).strip() + "\n"
