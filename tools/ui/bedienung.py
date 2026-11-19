"""Bedienung der Oberfläche: alles, was etwas ändert. Der Sachbearbeiter soll ohne Terminal arbeiten können.

Grundsätze:
  - Jede Funktion hier läuft nur, wenn die Anfrage das Geheimnis des Starts trägt (prüft der Server, bevor er sie aufruft).
    Das Geheimnis entsteht beim Start, liegt nur im Speicher des Servers und im Browser des Sachbearbeiters, steht in
    keiner Datei und nicht in der Umgebung der Sitzungen, die der Server startet.
  - Die Oberfläche schreibt nie selbst in Protokoll, Rohdaten oder fall.json. Sie ruft die bestehenden Werkzeuge auf:
    tools/fall.py, tools/beleg.py, tools/rapport.py, tools/protokoll.py, tools/anhang.py, tools/pdf.py,
    tools/audit_pruefen.py. Das Sitzungsprotokoll schreibt der Hook, der es immer schreibt.
  - Klartext bearbeitet nur dieser Server, nie eine Claude-Sitzung. Er liegt im Speicher, die Zuordnungstabelle und der
    zurückgeführte Rapport in der Ablage ausserhalb des Projektordners. Nichts davon steht in einem Protokoll.

Der Akten-Eingang («Korb»): Hochgeladene Dateien liegen im Speicher, bis der Sachbearbeiter sie in einen Fall aufnimmt
oder entfernt. Je Datei entsteht eine Textfassung. Geprüft, pseudonymisiert und aufgenommen wird die Textfassung, nie das
Original: In einem Original können Angaben stecken, die niemand sieht (Verfasser, eingebettete Bilder, Änderungsverlauf).
Was sich nicht lesen lässt (Bilder, Ton, alte Formate), lässt sich nicht prüfen und bleibt beim Sachbearbeiter.
"""
from __future__ import annotations

import contextlib
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime
from pathlib import Path

from gateway import plattform
from gateway.akte import FALL_RE, FREIGABE_TEXT, FREIGABEN, PROJEKT, eingang_stand, fall_daten, fall_pfad
from gateway.quellen import QUELLEN
from tools import _pseudo as ps, beleg as belegwerkzeug, fall as fallwerkzeug, reidentifizieren as rueck
from tools.pii_pruefung import GEWANDELT, NichtLesbar, bericht as pii_bericht, mail_lesen, pruefen as pii_pruefen, text_aus, text_lesen
from tools.ui import fehlerbuch

DATEI_GROESSE = 60 * 1024 * 1024        # grösste einzelne Datei im Akten-Eingang
KORB_GROESSE = 600 * 1024 * 1024        # alles zusammen, was ein Akten-Eingang im Speicher hält
KORB_EINTRAEGE = 2000
AUSPACK_TIEFE = 2                       # ZIP im ZIP, Anhang in der E-Mail: so tief wird ausgepackt
UEBERGEHEN = ("__MACOSX/", ".DS_Store", "Thumbs.db", "desktop.ini")     # was Betriebssysteme in Archive legen
TICKET_SEKUNDEN = 120
ROLLEN = {"rapport": "Rapport", "beilage": "Beilage"}
WERKZEUGE = {       # was «Dokumente» auslösen kann: Name -> (Bezeichnung, Befehle nach dem Interpreter)
    "rapport": ("Abschlussrapport erzeugen", [["tools/rapport.py", "{fall}"]]),
    "protokoll": ("Ermittlungsprotokoll erzeugen", [["tools/protokoll.py", "{fall}"]]),
    "anhang": ("Datenblätter erzeugen", [["tools/anhang.py", "{fall}", "--ohne-pdf"]]),
    "pdf": ("PDF erzeugen", [["tools/pdf.py", "{fall}"], ["tools/anhang.py", "{fall}"]]),
    "kette": ("Protokollkette prüfen", [["tools/audit_pruefen.py", "{fall}"]]),
    "alles": ("Alle Dokumente neu erzeugen", [["tools/rapport.py", "{fall}"], ["tools/protokoll.py", "{fall}"], ["tools/pdf.py", "{fall}"], ["tools/anhang.py", "{fall}"]]),
    # nach einer Ermittlung: Der Rapport steht schon, das Protokoll bekommt die letzten Einträge, PDF und Datenblätter kommen dazu
    "abschluss": ("Unterlagen nach der Ermittlung erzeugen", [["tools/protokoll.py", "{fall}"], ["tools/pdf.py", "{fall}"], ["tools/anhang.py", "{fall}"]]),
}


class Fehler(Exception):
    """Eine Bedienung, die so nicht geht. Der Text ist für den Sachbearbeiter und nennt nie Klartext.
    `mehr`: Angaben, die das Fenster neben dem Text braucht, etwa dass sich eine gesperrte Nachricht bewusst doch senden lässt.
    `heikel`: Der Text beschreibt eine Eingabe des Sachbearbeiters (etwa die Stelle, die die PII-Prüfung gesperrt hat). Er steht
    im Fenster, aber nicht im Fehlerprotokoll."""

    def __init__(self, text: str, status: int = 400):
        super().__init__(text)
        self.status = status
        self.mehr: dict = {}
        self.heikel = False


def innerhalb(pfad: Path) -> bool:
    try:
        Path(pfad).expanduser().resolve().relative_to(PROJEKT.resolve())
        return True
    except ValueError:
        return False


def python() -> str:
    venv = plattform.venv_python(PROJEKT)
    return str(venv) if venv.is_file() else sys.executable


def umgebung() -> dict:
    """Die Umgebung für Werkzeuge, die der Server startet. Das Geheimnis steht nie in der Umgebung, hier ist also nichts zu entfernen.
    Die Kennzeichen von Claude Code fallen weg: Der Server ist kein Agent, auch wenn er einmal aus einer Sitzung heraus getestet wird."""
    return {**{k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")},
            "OSINT_PROJEKT": str(PROJEKT), "CLAUDE_PROJECT_DIR": str(PROJEKT), "PYTHONIOENCODING": "utf-8"}


def werkzeug_lauf(argumente: list[str], zeit: int = 600) -> tuple[int, str]:
    """Startet ein Werkzeug des Projekts im Projektordner und gibt Rückgabewert und Ausgabe zurück."""
    try:
        r = subprocess.run([python(), "-X", "utf8", *argumente], cwd=str(PROJEKT), env=umgebung(), capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=zeit, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return 124, f"Abgebrochen nach {zeit} Sekunden."
    return r.returncode, (r.stdout + (("\n" + r.stderr) if r.stderr.strip() else "")).strip()


def sauberer_name(roh: object) -> tuple[str, str]:
    """Aus dem Namen einer hochgeladenen Datei (mit Ordnern, aus einem Archiv, aus einer E-Mail) werden ein Dateiname und ein
    Ordner zur Anzeige. Nichts davon kann aus einem Ordner hinausführen: Trenner, «..» und Sonderzeichen fallen weg."""
    teile = [t for t in re.split(r"[\\/]+", str(roh or "")) if t.strip() and t.strip() not in (".", "..")]
    teile = [re.sub(r"[^A-Za-z0-9._ äöüÄÖÜéèàçâêîôûÉÈÀ()+-]", "_", t).strip(" .")[:120] or "_" for t in teile]
    return (teile[-1] if teile else "dokument.txt"), "/".join(teile[:-1])[:200]


class Zwischenablage:
    """Ein Ordner ausserhalb des Projekts, nur für diesen Benutzer lesbar, der nach Gebrauch verschwindet."""

    def __enter__(self) -> Path:
        self.ordner = Path(tempfile.mkdtemp(prefix="osint-oberflaeche-"))
        if innerhalb(self.ordner):
            shutil.rmtree(self.ordner, ignore_errors=True)
            raise Fehler("Der Ordner für Zwischendateien liegt im Projektordner. Bitte TMPDIR auf einen Ordner ausserhalb setzen.")
        try:
            os.chmod(self.ordner, 0o700)
        except OSError:
            pass
        return self.ordner

    def __exit__(self, *_) -> None:
        shutil.rmtree(self.ordner, ignore_errors=True)


class Eintrag:
    """Eine Datei im Akten-Eingang. Original und Textfassung liegen im Speicher des Servers, nirgends sonst."""

    def __init__(self, name: str, ordner: str, inhalt: bytes, summe: str):
        self.id = secrets.token_urlsafe(8)
        self.name, self.ordner = name, ordner
        self.inhalt: bytes | None = inhalt      # das Original. Nach der Pseudonymisierung verlässt es den Speicher
        self.groesse, self.sha256 = len(inhalt), summe
        self.text: str | None = None            # die Textfassung: Sie wird geprüft, pseudonymisiert und aufgenommen
        self.grund = ""                         # warum sich die Datei nicht lesen lässt
        self.sperren = self.hinweise = self.platzhalter = 0
        self.bericht = ""                       # Bericht der PII-Prüfung, Fundstellen maskiert
        self.rolle = "beilage"
        self.vorgang: str | None = None         # Kennung einer laufenden Pseudonymisierung
        self.ersetzt: int | None = None         # Zahl der ersetzten Fundstellen, sobald eine Pseudonymisierung übernommen ist
        self.risiko: dict | None = None         # {"durch", "grund"}: Der Sachbearbeiter nimmt die Datei trotz Sperrfund auf
        self.statt: dict | None = None          # {"name", "durch"}: zum Nachbessern aus dem Fall geholt. Aufgenommen, ersetzt sie dort das Dokument dieses Namens

    @property
    def stand(self) -> str:
        if self.text is None:
            return "nicht_lesbar"
        return "risiko" if self.sperren and self.risiko else "personendaten" if self.sperren else "sauber"

    @property
    def endung(self) -> str:
        return Path(self.name).suffix.lower()

    def kurz(self) -> dict:
        return {"id": self.id, "name": self.name, "ordner": self.ordner, "groesse": self.groesse, "endung": self.endung, "stand": self.stand, "grund": self.grund,
                "sperren": self.sperren, "hinweise": self.hinweise, "platzhalter": self.platzhalter, "rolle": self.rolle, "ersetzt": self.ersetzt,
                "vorgang": self.vorgang or "", "risiko": bool(self.risiko), "statt": (self.statt or {}).get("name", "")}


class Korb:
    """Der Akten-Eingang zu einem Ziel: zu einem neuen Fall oder zu einem bestehenden."""

    def __init__(self, zuordnung: list | tuple = ()):
        self.eintraege: dict[str, Eintrag] = {}
        self.zuordnung = list(zuordnung)        # (Platzhalter, Klartext): wächst mit jedem Dokument, das hier pseudonymisiert wird

    def groesse(self) -> int:
        return sum(len(e.inhalt or b"") + len((e.text or "").encode("utf-8")) for e in self.eintraege.values())

    def belegt(self, *weitere: str) -> dict:
        """Die höchste Nummer je Typ unter allen Platzhaltern, die in diesem Eingang, in seiner Zuordnung und in den weiteren
        Texten (den Dokumenten, die schon im Fall liegen) stehen."""
        return ps.platzhalter_stand(*(e.text or "" for e in self.eintraege.values()), *(p for p, _ in self.zuordnung), *weitere)


class Pseudo:
    """Ein Dokument des Akten-Eingangs auf dem Weg durch die Bestätigung. Lebt nur im Speicher des Servers."""

    def __init__(self, name: str, text: str, zuordnung: list, belegt: dict, ziel: str, eintrag: str):
        self.name, self.ziel, self.eintrag = name, ziel, eintrag
        self.vorgang = ps.Vorgang(text, zuordnung=zuordnung, belegt=belegt)
        self.beruehrt = time.time()


class Bedienung:
    def __init__(self, ablage: Path | None = None):
        self.geheimnis = secrets.token_urlsafe(32)
        self.startcode: str | None = secrets.token_urlsafe(18)      # gilt genau einmal: Der Browser tauscht ihn gegen das Geheimnis
        eigen = os.environ.get("OSINT_ABLAGE", "").strip()       # eine eigene Ablage. Die Vorgabe sperren die Einstellungen des Projekts für Agenten
        self.ablage = Path(ablage or eigen).expanduser() if (ablage or eigen) else Path.home() / "OSINT-Ablage"
        if innerhalb(self.ablage):
            raise Fehler("Die Ablage für Klartext muss ausserhalb des Projektordners liegen.")
        self.koerbe: dict[str, Korb] = {}       # Ziel -> Akten-Eingang. "" ist der Eingang für einen neuen Fall
        self.pseudo: dict[str, Pseudo] = {}
        self.tickets: dict[str, tuple[Path, float]] = {}
        self.sitzung = "oberflaeche-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        self.sperre = threading.RLock()
        self.ermittlungen: dict = {}        # Fall-ID -> Sitzung (tools/ui/sitzung.py)
        # Das Fehlerprotokoll: im Speicher und in der Ablage ausserhalb des Projekts. Was hineinkommt, wird beim Eintragen bereinigt
        # Geheim sind hier: das Geheimnis der Oberfläche, der Startcode und die Karten der Sitzungen (sie taugen nur zum Fragen)
        self.fehlerbuch = fehlerbuch.Fehlerbuch(self.ablage, self.sitzung, lambda: (
            self.geheimnis, self.startcode or "", *(str(getattr(s, "karte", "") or "") for s in list(self.ermittlungen.values()))))

    # ---- Geheimnis
    def anmelden(self, startcode: str) -> str:
        """Tauscht den Startcode aus der Adresse gegen das Geheimnis. Das geht genau einmal."""
        with self.sperre:
            if not self.startcode or not hmac.compare_digest(str(startcode or "").encode(), self.startcode.encode()):
                raise Fehler("Dieser Startcode gilt nicht (mehr). Die Oberfläche lässt sich nur aus dem Browserfenster bedienen, das sie beim Start "
                             "geöffnet hat. Zum Bedienen in einem anderen Fenster: Oberfläche beenden und neu starten.", 403)
            self.startcode = None
            return self.geheimnis

    def berechtigt(self, geheimnis: str | None) -> bool:
        return bool(geheimnis) and hmac.compare_digest(str(geheimnis).encode(), self.geheimnis.encode())

    # ---- Sitzungsprotokoll: Der Hook schreibt es, wie für jede Sitzung von Claude Code
    def vermerken(self, fall: str, schritt: str, angabe: str = "", sitzung: str | None = None) -> None:
        # Je Fall ein eigenes Sitzungsprotokoll der Oberfläche: Im Ermittlungsprotokoll eines Falls stehen so nur seine eigenen Schritte
        ereignis = {"hook_event_name": "Oberflaeche", "session_id": sitzung or f"{self.sitzung}-{fall}", "cwd": str(PROJEKT), "fall": fall, "schritt": schritt,
                    "angabe": angabe}
        subprocess.run([python(), "-X", "utf8", str(PROJEKT / ".claude" / "hooks" / "protokoll_hook.py")], input=json.dumps(ereignis, ensure_ascii=False),
                       cwd=str(PROJEKT), env=umgebung(), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)

    def _fall_id(self, fall: str) -> str:
        if not FALL_RE.match(fall or ""):
            raise Fehler("Die Fall-ID besteht aus Buchstaben, Ziffern, Punkt, Strich und Unterstrich (3 bis 64 Zeichen).")
        return fall

    def zuordnung_pfad(self, fall: str) -> Path:
        return self.ablage / self._fall_id(fall) / "zuordnung.csv"

    # ---- 1. Akten-Eingang: hochladen, prüfen, ordnen
    def korb(self, ziel: object) -> Korb:
        """Der Akten-Eingang zu einem Ziel. Zu einem bestehenden Fall kennt er dessen Zuordnungstabelle: Dieselbe Angabe bekommt
        denselben Platzhalter."""
        ziel = str(ziel or "").strip()
        with self.sperre:
            if ziel:
                self._fall_id(ziel)
                fall_daten(ziel)        # den Fall muss es geben
            if ziel not in self.koerbe:
                zuordnung: list = []
                tabelle = self.zuordnung_pfad(ziel) if ziel else None
                if tabelle is not None and tabelle.is_file():
                    try:
                        zuordnung = ps.zuordnung_lesen(tabelle)
                    except (ValueError, OSError) as e:
                        raise Fehler(f"Die Zuordnungstabelle zu Fall {ziel} lässt sich nicht lesen: {e}") from e
                self.koerbe[ziel] = Korb(zuordnung)
            return self.koerbe[ziel]

    def _im_fall(self, ziel: str) -> list[str]:
        """Die Texte der geprüften Dokumente, die im Eingang eines Falls liegen. Aus ihnen liest die Pseudonymisierung, welche
        Platzhalter schon vergeben sind: Eine Nummer meint nie zwei Personen, auch wenn sie von anderer Hand stammt."""
        if not ziel:
            return []
        eingang, texte = fall_pfad(ziel) / "eingang", []
        for name in eingang_stand(fall_pfad(ziel))[0]:
            datei = eingang / name
            if datei.suffix.lower() not in GEWANDELT and datei.stat().st_size < DATEI_GROESSE:
                texte.append(datei.read_text(encoding="utf-8", errors="replace"))
        return texte

    def _eintrag(self, korb: Korb, kennung: object) -> Eintrag:
        e = korb.eintraege.get(str(kennung or ""))
        if e is None:
            raise Fehler("Diese Datei liegt nicht mehr im Akten-Eingang.", 404)
        return e

    def _auswahl(self, korb: Korb, d: dict, alle: bool = False) -> list[Eintrag]:
        """Die gewählten Dateien. Ist nichts gewählt, gilt das nur beim Aufnehmen als «alle»: Entfernen und Ordnen brauchen eine Auswahl."""
        kennungen = d.get("ids")
        if isinstance(kennungen, str):
            kennungen = [k for k in kennungen.split(",") if k]
        if not kennungen:
            if alle:
                return list(korb.eintraege.values())
            raise Fehler("Bitte zuerst Dateien auswählen.")
        return [self._eintrag(korb, k) for k in dict.fromkeys(str(k) for k in kennungen)]

    def _lesen(self, e: Eintrag) -> None:
        """Die Textfassung einer Datei und ihre PII-Prüfung. Was sich nicht lesen lässt, bekommt den Grund."""
        e.text, e.grund = None, ""
        try:
            e.text = text_aus(e.name, e.inhalt or b"")
        except NichtLesbar as f:
            grund = str(f)
            if e.endung == ".pdf" and "pdftotext meldet" in grund:       # nicht jede Fassung von pdftotext liest von der Standardeingabe
                try:
                    with Zwischenablage() as ordner:
                        (ordner / "dokument.pdf").write_bytes(e.inhalt or b"")
                        e.text = text_lesen(ordner / "dokument.pdf")
                except NichtLesbar as zweiter:
                    grund = str(zweiter).replace("dokument.pdf", e.name)
            if e.text is None:
                e.grund = grund.split(": ", 1)[-1]
        self._pruefen(e)

    def _pruefen(self, e: Eintrag) -> None:
        e.sperren = e.hinweise = e.platzhalter = 0
        e.bericht = ""
        if e.text is None:
            return
        funde, platzhalter = pii_pruefen(e.text)
        e.sperren = sum(1 for f in funde if f.stufe == "sperre")
        e.hinweise = sum(1 for f in funde if f.stufe == "hinweis")
        e.platzhalter = sum(platzhalter.values())
        e.bericht = pii_bericht(e.name, funde, platzhalter)
        if not e.sperren:
            e.risiko = None         # wo nichts mehr gesperrt ist, gibt es kein Risiko zu übernehmen

    def _einlegen(self, korb: Korb, name: str, ordner: str, inhalt: bytes, tiefe: int, neu: list, meldungen: list) -> None:
        if not inhalt:
            meldungen.append(f"{name}: leer, nicht angenommen.")
            return
        if len(inhalt) > DATEI_GROESSE:
            meldungen.append(f"{name}: grösser als {DATEI_GROESSE // (1024 * 1024)} MB, nicht angenommen.")
            return
        endung = Path(name).suffix.lower()
        if endung == ".zip" and tiefe < AUSPACK_TIEFE:
            self._auspacken(korb, name, ordner, inhalt, tiefe, neu, meldungen)
            return
        summe = hashlib.sha256(inhalt).hexdigest()
        if any(e.sha256 == summe for e in korb.eintraege.values()):
            meldungen.append(f"{name}: liegt mit demselben Inhalt schon im Akten-Eingang.")
            return
        if len(korb.eintraege) >= KORB_EINTRAEGE:
            meldungen.append(f"{name}: Der Akten-Eingang fasst höchstens {KORB_EINTRAEGE} Dateien.")
            return
        if korb.groesse() + len(inhalt) > KORB_GROESSE:
            meldungen.append(f"{name}: Der Akten-Eingang ist voll ({KORB_GROESSE // (1024 * 1024)} MB). Bitte zuerst aufnehmen oder entfernen.")
            return
        e = Eintrag(name, ordner, inhalt, summe)
        self._lesen(e)
        if e.text is not None and not any(x.rolle == "rapport" for x in korb.eintraege.values()) and not self._ist_fall(korb):
            e.rolle = "rapport"     # das erste lesbare Dokument zu einem neuen Fall gilt als Rapport, bis der Sachbearbeiter es anders ordnet
        korb.eintraege[e.id] = e
        neu.append(e)
        if endung == ".eml" and tiefe < AUSPACK_TIEFE:      # Anhänge einer E-Mail sind eigene Dokumente
            try:
                anhaenge = mail_lesen(inhalt)[1]
            except NichtLesbar:
                anhaenge = []
            for an_name, an_inhalt in anhaenge:
                self._einlegen(korb, sauberer_name(an_name)[0], "/".join(x for x in (ordner, name) if x), an_inhalt, tiefe + 1, neu, meldungen)

    def _ist_fall(self, korb: Korb) -> bool:
        return any(k is korb and ziel for ziel, k in self.koerbe.items())

    def _auspacken(self, korb: Korb, name: str, ordner: str, inhalt: bytes, tiefe: int, neu: list, meldungen: list) -> None:
        try:
            archiv = zipfile.ZipFile(io.BytesIO(inhalt))
        except (zipfile.BadZipFile, OSError):
            meldungen.append(f"{name}: kein gültiges ZIP-Archiv, nicht angenommen.")
            return
        with archiv:
            teile = [i for i in archiv.infolist() if not i.is_dir()]
            if len(teile) > KORB_EINTRAEGE:
                meldungen.append(f"{name}: Das Archiv enthält mehr als {KORB_EINTRAEGE} Dateien, nicht angenommen.")
                return
            entpackt = 0
            for info in teile:
                teil_name, teil_ordner = sauberer_name(info.filename)
                if any(u in info.filename for u in UEBERGEHEN) or Path(info.filename).name.startswith("._"):
                    continue
                if info.flag_bits & 0x1:
                    meldungen.append(f"{teil_name} (aus {name}): mit einem Passwort geschützt, nicht entpackt.")
                    continue
                entpackt += info.file_size
                if info.file_size > DATEI_GROESSE or entpackt > KORB_GROESSE:
                    meldungen.append(f"{teil_name} (aus {name}): entpackt zu gross, nicht angenommen.")
                    continue
                try:
                    daten = archiv.read(info)
                except (RuntimeError, zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
                    meldungen.append(f"{teil_name} (aus {name}): liess sich nicht entpacken.")
                    continue
                self._einlegen(korb, teil_name, "/".join(x for x in (ordner, name, teil_ordner) if x), daten, tiefe + 1, neu, meldungen)

    def hochladen(self, ziel: object, pfadname: object, inhalt: bytes) -> dict:
        """Eine Datei kommt in den Akten-Eingang: ein Dokument, eine Beilage, ein ZIP-Archiv (wird entpackt) oder eine E-Mail
        (ihre Anhänge werden eigene Dokumente). Jede Datei wird sofort gelesen und geprüft. In einen Fall kommt hier noch nichts."""
        korb = self.korb(ziel)
        name, ordner = sauberer_name(pfadname)
        neu: list[Eintrag] = []
        meldungen: list[str] = []
        with self.sperre:
            self._einlegen(korb, name, ordner, inhalt, 0, neu, meldungen)
        return {"neu": len(neu), "eintraege": [e.kurz() for e in neu], "meldungen": meldungen,
                "meldung": (f"{len(neu)} Datei(en) im Akten-Eingang." if neu else "Nichts angenommen.") + (" " + " ".join(meldungen) if meldungen else "")}

    def korb_entfernen(self, d: dict) -> dict:
        korb = self.korb(d.get("ziel"))
        with self.sperre:
            weg = self._auswahl(korb, d)
            for e in weg:
                if e.vorgang:
                    self.pseudo.pop(e.vorgang, None)
                korb.eintraege.pop(e.id, None)
            if not korb.eintraege:      # ein leerer Eingang vergisst auch, was in ihm pseudonymisiert wurde
                self.koerbe.pop(str(d.get("ziel") or "").strip(), None)
        return {"meldung": f"{len(weg)} Datei(en) aus dem Akten-Eingang entfernt. Sie sind aus dem Speicher der Oberfläche gelöscht."}

    def korb_rolle(self, d: dict) -> dict:
        korb, rolle = self.korb(d.get("ziel")), str(d.get("rolle") or "")
        if rolle not in ROLLEN:
            raise Fehler("Diese Rolle gibt es nicht.")
        with self.sperre:
            auswahl = self._auswahl(korb, d)
            for e in auswahl:
                e.rolle = rolle
        return {"meldung": f"{len(auswahl)} Datei(en) als {ROLLEN[rolle]} geordnet."}

    def korb_verschieben(self, d: dict) -> dict:
        """Legt gewählte Dateien in den Akten-Eingang eines anderen Falls oder des neuen Falls. Was hier schon pseudonymisiert
        wurde, bleibt liegen: Seine Platzhalter gehören zur Zuordnung dieses Eingangs und könnten dort etwas anderes meinen."""
        quelle, nach = str(d.get("ziel") or "").strip(), str(d.get("nach") or "").strip()
        if quelle == nach:
            raise Fehler("Die Dateien liegen schon in diesem Akten-Eingang.")
        korb, anderer = self.korb(quelle), self.korb(nach)
        with self.sperre:
            auswahl = self._auswahl(korb, d)
            fest = [e for e in auswahl if e.ersetzt is not None or e.vorgang]
            doppelt = 0
            for e in (e for e in auswahl if e not in fest):
                korb.eintraege.pop(e.id, None)
                if any(x.sha256 == e.sha256 for x in anderer.eintraege.values()):
                    doppelt += 1        # liegt dort mit demselben Inhalt schon
                    continue
                # Zu einem bestehenden Fall ist ein neues Dokument eine Beilage. Zu einem neuen Fall wird das erste lesbare der Rapport
                e.rolle = "beilage" if nach or e.text is None or any(x.rolle == "rapport" for x in anderer.eintraege.values()) else "rapport"
                anderer.eintraege[e.id] = e
            if not korb.eintraege:
                self.koerbe.pop(quelle, None)
            if not anderer.eintraege:
                self.koerbe.pop(nach, None)
        verschoben = len(auswahl) - len(fest) - doppelt
        wohin = f"den Akten-Eingang von Fall {nach}" if nach else "den Akten-Eingang für einen neuen Fall"
        return {"verschoben": verschoben, "nach": nach,
                "meldung": f"{verschoben} Datei(en) in {wohin} gelegt."
                           + (f" {doppelt} lagen dort mit demselben Inhalt schon." if doppelt else "")
                           + (f" {len(fest)} bleiben hier: Sie wurden in diesem Eingang pseudonymisiert und gehören zu seiner Zuordnung." if fest else "")}

    def korb_umbenennen(self, d: dict) -> dict:
        korb = self.korb(d.get("ziel"))
        e = self._eintrag(korb, d.get("id"))
        name = sauberer_name(d.get("name"))[0]
        if Path(name).suffix.lower() != e.endung:
            name += e.endung        # die Endung sagt, wie die Datei gelesen wird: Sie bleibt
        if any(f for f in pii_pruefen(name, "streng")[0] if f.stufe == "sperre"):
            raise Fehler("In diesem Namen steckt eine Angabe, die nach Personendaten aussieht. Bitte einen anderen Namen wählen.")
        e.name = name
        return {"meldung": "Umbenannt."}

    def korb_risiko(self, d: dict) -> dict:
        """Der Sachbearbeiter übernimmt das Risiko: Die gewählten Dateien gehen trotz Sperrfund der PII-Prüfung in den Fall, so
        wie sie sind (Entscheid des Eigentümers vom 19.11.2026). Das verlangt sein Kürzel und eine Begründung. Beides steht
        danach im Register des Falls und im Sitzungsprotokoll. Mit «zurueck» nimmt er den Entscheid wieder zurück."""
        korb = self.korb(d.get("ziel"))
        zurueck = str(d.get("zurueck") or "") not in ("", "0", "false")
        durch, grund = " ".join(str(d.get("durch") or "").split()), " ".join(str(d.get("grund") or "").split())
        if not zurueck:
            if not durch or len(grund) < 5:
                raise Fehler("Wer das Risiko übernimmt, nennt sein Kürzel und eine Begründung in ein paar Worten.")
            if len(durch) > 60 or len(grund) > 400:
                raise Fehler("Kürzel (bis 60 Zeichen) und Begründung (bis 400 Zeichen) bitte kürzer fassen.")
            if any(f.stufe == "sperre" for f in pii_pruefen(f"{durch}\n{grund}", "streng")[0]):
                raise Fehler("Kürzel und Begründung stehen im Register des Falls und im Protokoll. Darin steckt eine Angabe, die nach Personendaten aussieht.")
        with self.sperre:
            auswahl = [e for e in self._auswahl(korb, {"ids": d.get("ids") or d.get("namen")}) if e.sperren and e.text is not None]
            if not auswahl:
                raise Fehler("Keine der gewählten Dateien ist gesperrt. Was bereit ist, braucht diesen Schritt nicht.")
            if any(e.vorgang for e in auswahl):
                raise Fehler("Eine der gewählten Dateien wird gerade pseudonymisiert. Bitte zuerst übernehmen oder abbrechen.")
            for e in auswahl:
                e.risiko = None if zurueck else {"durch": durch, "grund": grund}
        if zurueck:
            return {"meldung": f"Zurückgenommen für {len(auswahl)} Datei(en): Sie gelten wieder als gesperrt."}
        return {"meldung": f"Risiko übernommen für {len(auswahl)} Datei(en). Sie gehen beim Aufnehmen so in den Fall, wie sie sind: "
                           f"{sum(e.sperren for e in auswahl)} Fundstelle(n) bleiben im Klartext."}

    # ---- Klartext: der lokale Bildschirm der Pseudonymisierung
    def korb_pseudo(self, d: dict) -> dict:
        """Beginnt die Pseudonymisierung einer Datei des Akten-Eingangs. Sie kennt, was im selben Eingang und im Fall schon
        ersetzt wurde, und zählt neue Platzhalter hinter allen weiter, die dort schon stehen (auch von anderer Hand vergeben)."""
        ziel = str(d.get("ziel") or "").strip()
        korb = self.korb(ziel)
        e = self._eintrag(korb, d.get("id"))
        if e.text is None:
            raise Fehler(f"{e.name} lässt sich nicht lesen und deshalb nicht pseudonymisieren: {e.grund}")
        with self.sperre:
            for alt in [k for k, v in self.pseudo.items() if time.time() - v.beruehrt > 6 * 3600]:
                del self.pseudo[alt]
            if e.vorgang and e.vorgang in self.pseudo:
                return {"vorgang": e.vorgang, "bekannt": len(korb.zuordnung)}
            kennung = secrets.token_urlsafe(12)
            self.pseudo[kennung] = Pseudo(e.name, e.text, list(korb.zuordnung), korb.belegt(*self._im_fall(ziel)), ziel, e.id)
            e.vorgang = kennung
        return {"vorgang": kennung, "bekannt": len(korb.zuordnung)}

    def pseudo_holen(self, kennung: object) -> Pseudo:
        p = self.pseudo.get(str(kennung or ""))
        if p is None:
            raise Fehler("Dieses Dokument ist nicht mehr in Arbeit. Bitte im Akten-Eingang erneut «pseudonymisieren» wählen.", 404)
        p.beruehrt = time.time()
        return p

    def pseudo_entscheid(self, d: dict) -> dict:
        """Annehmen, verwerfen, ergänzen, Typ ändern, Seite einer E-Mail-Adresse. Jede Eingabe rechnet neu."""
        p = self.pseudo_holen(d.get("vorgang"))
        v, art = p.vorgang, str(d.get("art") or "")
        with self.sperre:       # ein Entscheid nach dem andern: Jede Eingabe rechnet das Dokument neu
            return self._entscheid(v, art, d)

    def _entscheid(self, v: "ps.Vorgang", art: str, d: dict) -> dict:
        fund = next((f for f in v.erk.funde if f.id == d.get("fund")), None)
        try:
            if art == "annehmen" and fund is not None:
                v.bestaetigen(fund, d.get("typ") or None)
            elif art == "verwerfen" and fund is not None:
                v.verwerfen(fund)
            elif art == "alle_verwerfen":       # was nach der Durchsicht noch offen ist, bleibt stehen: ein Entscheid für alle
                for offen in v.kandidaten():
                    v.verwerfen(offen)
            elif art == "angabe":
                v.angabe_entscheiden(str(d.get("angabe") or ""), bool(d.get("ersetzen")))
            elif art == "ergaenzen":
                wert = " ".join(str(d.get("wert") or "").split())
                if len(wert) < 2:
                    raise Fehler("Bitte die Angabe eintragen, die ersetzt werden soll.")
                if not v.aufnehmen(wert, str(d.get("typ") or "PERSON")):
                    raise Fehler("Diese Angabe kommt im Dokument nicht vor oder passt nicht zum gewählten Typ.")
            elif art == "typ":
                v.typ_aendern(str(d.get("angabe") or ""), str(d.get("typ") or ""))
            elif art == "seite":
                v.seite(str(d.get("angabe") or ""), str(d.get("seite") or ""))
            else:
                raise Fehler("Diese Eingabe kennt die Oberfläche nicht.")
        except ValueError as e:
            raise Fehler(str(e)) from e
        return {"vorgang": d.get("vorgang")}

    def pseudo_uebernehmen(self, d: dict) -> dict:
        """Das Ergebnis ersetzt die Datei im Akten-Eingang. Der Klartext verlässt den Speicher, die neuen Paare kommen zur Zuordnung
        des Eingangs. Findet die PII-Prüfung im Ergebnis noch Personendaten, bleibt alles, wie es ist."""
        p = self.pseudo_holen(d.get("vorgang"))
        korb = self.korb(p.ziel)
        e = korb.eintraege.get(p.eintrag)
        if e is None:
            with self.sperre:
                self.pseudo.pop(str(d.get("vorgang")), None)
            raise Fehler("Diese Datei liegt nicht mehr im Akten-Eingang.", 404)
        ergebnis = p.vorgang.ergebnis()
        funde, platzhalter = pii_pruefen(ergebnis.text)
        if any(f.stufe == "sperre" for f in funde):
            return {"uebernommen": False, "ausgabe": pii_bericht(e.name, funde, platzhalter),
                    "meldung": "Die PII-Prüfung findet im Ergebnis noch Personendaten. Bitte die genannten Stellen im Dokument ergänzen. Es wurde nichts übernommen."}
        with self.sperre:
            # Paare aus Dokumenten, die seit dem Beginn übernommen wurden, bleiben erhalten: Die Tabelle des Eingangs wächst nur
            bekannt = {platzhalter_ for platzhalter_, _ in korb.zuordnung}
            korb.zuordnung += [paar for paar in ergebnis.zuordnung if paar[0] not in bekannt]
            e.text, e.inhalt = ergebnis.text, None
            e.ersetzt = (e.ersetzt or 0) + sum(ergebnis.ersetzt.values())
            e.vorgang = None
            self._pruefen(e)
            self.pseudo.pop(str(d.get("vorgang")), None)        # der Klartext verlässt den Speicher
        return {"uebernommen": True, "ziel": p.ziel, "ersetzt": sum(ergebnis.ersetzt.values()), "neu": len(ergebnis.neu), "offen": ergebnis.offen,
                "klaerung": len(ergebnis.klaerung),
                "meldung": f"Übernommen: {sum(ergebnis.ersetzt.values())} Fundstellen ersetzt." + (f" {ergebnis.offen} Kandidaten blieben stehen." if ergebnis.offen else "")}

    def pseudo_verwerfen(self, d: dict) -> dict:
        with self.sperre:
            p = self.pseudo.pop(str(d.get("vorgang") or ""), None)
            if p is not None:
                e = self.koerbe.get(p.ziel, Korb()).eintraege.get(p.eintrag)
                if e is not None:
                    e.vorgang = None
        return {"meldung": "Abgebrochen. Die Datei liegt unverändert im Akten-Eingang.", "ziel": p.ziel if p is not None else ""}

    # ---- In den Fall aufnehmen: über tools/fall.py, das selbst noch einmal prüft
    def _zielname(self, e: Eintrag, neutral: bool, zaehler: dict, vergeben: set) -> str:
        """Der Name, unter dem die Textfassung in den Eingang des Falls kommt. Neutral heisst: Der Name der Datei sagt nichts
        über ihren Inhalt (rapport-01.txt). Ein Dateiname nennt sonst leicht eine Person, und er steht in jedem Protokoll."""
        text_endung = e.endung if e.endung in (".md", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".log", ".yaml", ".yml") else ".txt"
        if neutral:
            while True:
                zaehler[e.rolle] = zaehler.get(e.rolle, 0) + 1
                name = f"{e.rolle}-{zaehler[e.rolle]:02d}{text_endung}"
                if name.lower() not in vergeben:
                    break
        else:
            # Eine Textdatei behält ihren Namen. Aus rapport.docx wird rapport.docx.txt, wie tools/fall.py seine Lesefassung nennt
            stamm = Path(e.name).stem if e.endung == text_endung else e.name
            if e.ersetzt is not None:
                stamm = Path(e.name).stem + "_pseudonymisiert"
            name, nr = f"{stamm}{text_endung}", 1
            while name.lower() in vergeben:
                nr += 1
                name = f"{stamm} ({nr}){text_endung}"
        vergeben.add(name.lower())
        return name

    def korb_aufnehmen(self, d: dict) -> dict:
        """Nimmt Dateien des Akten-Eingangs in einen Fall auf: einen neuen (Fall-ID, Titel) oder den, zu dem der Eingang gehört.
        Aufgenommen wird die Textfassung, und nur, wenn die PII-Prüfung nichts findet. Was Personendaten enthält oder sich nicht
        lesen lässt, bleibt im Eingang und wird beim Namen genannt. tools/fall.py prüft jede Datei selbst noch einmal."""
        ziel = str(d.get("ziel") or "").strip()
        korb = self.korb(ziel)
        fall = self._fall_id(ziel or str(d.get("fall") or "").strip())
        neu = not ziel
        if neu and (fall_pfad(fall) / "fall.json").exists():
            raise Fehler(f"Den Fall «{fall}» gibt es schon. Weitere Dokumente lassen sich im Fall unter «Akten» nachziehen.")
        if neu and not str(d.get("titel") or "").strip():
            raise Fehler("Ein neuer Fall braucht einen Titel.")
        for feld in ("titel", "auftrag", "kuerzel"):
            if any(f.stufe == "sperre" for f in pii_pruefen(str(d.get(feld) or ""), "streng")[0]):
                raise Fehler("Titel, Auftrag und Kürzel stehen in jedem Dokument der Akte. Darin steckt eine Angabe, die nach Personendaten aussieht.")
        neutral = str(d.get("neutral", "1")) not in ("", "0", "false")
        with self.sperre:
            auswahl = self._auswahl(korb, d, alle=True)
            if not auswahl:
                raise Fehler("Der Akten-Eingang ist leer. Bitte zuerst Dateien hineinziehen.")
            if any(e.vorgang for e in auswahl):
                raise Fehler("Eine der gewählten Dateien wird gerade pseudonymisiert. Bitte zuerst übernehmen oder abbrechen.")
            # bereit ist, was die Prüfung besteht, und was der Sachbearbeiter trotz Sperrfund aufnimmt (er hat das Risiko übernommen)
            bereit = sorted((e for e in auswahl if e.stand in ("sauber", "risiko")), key=lambda e: e.rolle != "rapport")
            zurueck = [e for e in auswahl if e.stand not in ("sauber", "risiko")]
            if not bereit:
                return {"aufgenommen": False, "fall": fall, "anzahl": 0, "zurueck": [e.kurz() for e in zurueck],
                        "meldung": "Keine der gewählten Dateien lässt sich aufnehmen: Sie enthalten Personendaten oder lassen sich nicht lesen. Es wurde nichts angelegt."}
            vergeben = {n.lower() for n in sum(eingang_stand(fall_pfad(fall)), [])} if not neu else set()
            zaehler: dict = {}
            if neutral and not neu:     # neutrale Namen zählen hinter denen weiter, die im Fall schon liegen
                for name in vergeben:
                    m = re.fullmatch(r"(rapport|beilage)-(\d+)\.\w+", name)
                    if m:
                        zaehler[m.group(1)] = max(zaehler.get(m.group(1), 0), int(m.group(2)))
            namen = {e.id: self._zielname(e, neutral, zaehler, vergeben) for e in bereit}
            if not neutral:
                for e in bereit:
                    if any(f.stufe == "sperre" for f in pii_pruefen(namen[e.id], "streng")[0]):
                        raise Fehler("Im Namen einer Datei steckt eine Angabe, die nach Personendaten aussieht. Bitte neutrale Dateinamen verwenden oder umbenennen.")
            gewagt = [e for e in bereit if e.stand == "risiko"]
            with Zwischenablage() as ordner:
                dateien = []
                for e in bereit:
                    datei = ordner / namen[e.id]
                    datei.write_text(e.text or "", encoding="utf-8")
                    if e not in gewagt:
                        dateien.append(str(datei))
                ausgabe = ""
                if neu:
                    befehl = ["tools/fall.py", "neu", fall, "--titel", " ".join(str(d.get("titel") or fall).split())] + (["--rapport", *dateien] if dateien else [])
                    for schalter, feld in (("--auftrag", "auftrag"), ("--kuerzel", "kuerzel"), ("--klassifizierung", "klassifizierung")):
                        if str(d.get(feld) or "").strip():
                            befehl += [schalter, " ".join(str(d[feld]).split())]
                    code, ausgabe = self.werkzeug(befehl, 600)
                elif dateien:
                    code, ausgabe = self.werkzeug(["tools/fall.py", "aufnehmen", fall, *dateien], 600)
                # Was der Sachbearbeiter trotz Sperrfund aufnimmt: über dieselbe Funktion wie am Terminal, mit seinem Kürzel und seiner
                # Begründung. Am Terminal bestätigt er von Hand, hier hat seine Anfrage das Geheimnis getragen.
                if gewagt and (fall_pfad(fall) / "fall.json").is_file():
                    for e in gewagt:
                        puffer = io.StringIO()
                        try:
                            with contextlib.redirect_stdout(puffer):
                                fallwerkzeug.aufnehmen(fall, [str(ordner / namen[e.id])], e.risiko["grund"], e.risiko["durch"], weg="Oberfläche")
                        except (fallwerkzeug.Fehler, OSError) as fehler:
                            puffer.write(f"FEHLER: {fehler}\n")
                        ausgabe += ("\n" if ausgabe else "") + puffer.getvalue().strip()
                ausgabe = ausgabe.replace(str(ordner) + os.sep, "").replace(str(ordner), "(Zwischenablage)")
            if not (fall_pfad(fall) / "fall.json").is_file():
                return {"aufgenommen": False, "fall": fall, "anzahl": 0, "ausgabe": ausgabe, "meldung": "Der Fall liess sich nicht anlegen."}
            im_fall = set(eingang_stand(fall_pfad(fall))[0])
            drin = [e for e in bereit if namen[e.id] in im_fall]
            tabelle, tabelle_hinweis = self._zuordnung_sichern(fall, korb) if drin and korb.zuordnung else (None, "")
            namensliste = self._dateinamen_sichern(fall, [(namen[e.id], e.name, e.ordner) for e in drin]) if drin else None
            for e in drin:
                korb.eintraege.pop(e.id, None)
            # Der Eingang zum neuen Fall wird der Eingang dieses Falls: Was noch darin liegt, gehört jetzt zu ihm
            neu = neu and (fall_pfad(fall) / "fall.json").is_file()
            if neu:
                self.koerbe.pop("", None)
                if korb.eintraege:
                    self.koerbe[fall] = korb
                    for p in self.pseudo.values():      # eine Pseudonymisierung, die noch läuft, zieht mit um
                        if p.ziel == "":
                            p.ziel = fall
        # Eine nachgebesserte Fassung ersetzt im Fall das Dokument, aus dem sie entstand: Die neue liegt jetzt dort, die alte wird
        # entfernt. Das Register hält fest, was wodurch ersetzt wurde. Überschrieben wird nie.
        ersetzt_im_fall: list[str] = []
        for e in drin:
            if e.statt and e.statt["name"] != namen[e.id] and (fall_pfad(fall) / "eingang" / e.statt["name"]).is_file():
                try:
                    fallwerkzeug.entfernen(fall, [e.statt["name"]], durch=e.statt["durch"], grund=f"ersetzt durch die nachgebesserte Fassung {namen[e.id]}", weg="Oberfläche")
                except (fallwerkzeug.Fehler, FileNotFoundError, ValueError) as fehler:
                    ausgabe += f"\n{e.statt['name']} liess sich nicht entfernen: {fehler}"
                    continue
                ersetzt_im_fall.append(f"{e.statt['name']} durch {namen[e.id]}")
                self.vermerken(fall, "Dokument nachgebessert", f"{e.statt['name']} ersetzt durch {namen[e.id]}, durch {e.statt['durch']}")
        lokal = sum(1 for e in drin if e.ersetzt is not None)
        bleibt = [e for e in zurueck if e.stand == "nicht_lesbar"]
        arten: dict = {}
        for e in bleibt:
            arten[e.endung or "ohne Endung"] = arten.get(e.endung or "ohne Endung", 0) + 1
        angabe = (f"{len(drin)} Dokument(e): {len(drin) - lokal} geschwärzt angeliefert, {lokal} lokal pseudonymisiert ohne Sprachmodell"
                  + (f". Nicht lesbar und nicht übergeben: {', '.join(f'{n} × {a}' for a, n in sorted(arten.items()))}" if arten else "")
                  + (f". {len(zurueck) - len(bleibt)} mit Personendaten zurückgehalten" if len(zurueck) > len(bleibt) else ""))
        if drin:
            self.vermerken(fall, "Fall angelegt" if neu else "Dokumente aufgenommen", angabe)
        for e in drin:
            if e in gewagt:     # wer das Risiko übernommen hat und warum: gehört ins Protokoll des Falls, nicht nur ins Register
                self.vermerken(fall, "Dokument trotz Sperrfund aufgenommen",
                               f"{namen[e.id]}: {e.sperren} Fundstelle(n) der PII-Prüfung bleiben im Klartext. Risiko übernommen durch {e.risiko['durch']}. "
                               f"Begründung: {e.risiko['grund']}")
        return {"aufgenommen": bool(drin), "angelegt": neu, "fall": fall, "anzahl": len(drin), "namen": [namen[e.id] for e in drin], "ausgabe": ausgabe,
                "zurueck": [e.kurz() for e in zurueck], "bleibt": len(korb.eintraege), "zuordnung": str(tabelle) if tabelle is not None else "",
                "dateinamen": str(namensliste) if namensliste is not None else "",
                "meldung": ((f"Fall {fall} angelegt, " if neu else "") + f"{len(drin)} Dokument(e) aufgenommen."
                            + (f" Davon {sum(1 for e in drin if e in gewagt)} trotz Sperrfund: Das Risiko ist übernommen und im Protokoll vermerkt."
                               if any(e in gewagt for e in drin) else "")
                            + (f" Ersetzt im Fall: {'; '.join(ersetzt_im_fall)}. Läuft dazu eine Ermittlung, sag ihr im Chat, dass sie das Dokument neu lesen soll."
                               if ersetzt_im_fall else "")
                            + (f" {len(zurueck)} bleiben im Akten-Eingang: Personendaten oder nicht lesbar." if zurueck else "")
                            + (f" {tabelle_hinweis}" if tabelle_hinweis else "")) if drin
                else (f"Fall {fall} ist angelegt, aber kein Dokument wurde aufgenommen, siehe Ausgabe. Die Dateien liegen im Akten-Eingang dieses Falls."
                      if neu else "Nichts aufgenommen, siehe Ausgabe.")}

    def _ablage_ordner(self, fall: str) -> Path:
        """Der Ordner eines Falls in der Ablage ausserhalb des Projekts, nur für diesen Benutzer lesbar."""
        ordner = self.ablage / self._fall_id(fall)
        ordner.mkdir(parents=True, exist_ok=True)
        for o in (self.ablage, ordner):
            try:
                os.chmod(o, 0o700)
            except OSError:
                pass
        return ordner

    def _dateinamen_sichern(self, fall: str, paare: list[tuple[str, str, str]]) -> Path:
        """Hält in der Ablage fest, welche hochgeladene Datei unter welchem Namen im Fall liegt. Im Fall steht nur der neue Name:
        Der ursprüngliche kann eine Person nennen, und er stünde sonst in jedem Protokoll."""
        datei = self._ablage_ordner(fall) / "dateinamen.csv"
        neu = not datei.is_file()

        def zelle(wert: str) -> str:        # eine Tabellenkalkulation hält sonst für eine Formel, was mit = + - @ beginnt
            return "'" + wert if wert[:1] in ("=", "+", "-", "@") else wert
        with open(datei, "a", newline="", encoding="utf-8") as f:
            schreiber = csv.writer(f, delimiter=";", lineterminator="\n")
            if neu:
                schreiber.writerow(["im_fall", "hochgeladen_als", "aus", "aufgenommen"])
            for im_fall, original, ordner in paare:
                schreiber.writerow([im_fall, zelle(original), zelle(ordner), datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        try:
            os.chmod(datei, 0o600)
        except OSError:
            pass
        return datei

    def _zuordnung_sichern(self, fall: str, korb: Korb) -> tuple[Path, str]:
        """Schreibt die Zuordnung des Akten-Eingangs in die Tabelle des Falls, in der Ablage ausserhalb des Projekts. Steht dort schon
        eine Tabelle, bleibt jedes ihrer Paare erhalten. Meint ein Platzhalter dort etwas anderes (die Tabelle wurde ausserhalb der
        Oberfläche geändert) oder lässt sie sich nicht lesen, entsteht eine eigene Datei daneben: Überschrieben wird nichts."""
        tabelle = self._ablage_ordner(fall) / "zuordnung.csv"
        bestehend: list | None = []
        if tabelle.is_file():
            try:
                bestehend = ps.zuordnung_lesen(tabelle)
            except (ValueError, OSError):
                bestehend = None
        if bestehend is None or any(dict(bestehend).get(platzhalter, klar) != klar for platzhalter, klar in korb.zuordnung):
            eigene = tabelle.with_name(f"zuordnung-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv")
            ps.zuordnung_schreiben(eigene, korb.zuordnung)
            return eigene, ("Die Zuordnungstabelle des Falls passt nicht zu diesem Akten-Eingang: Sie wurde ausserhalb der Oberfläche geändert oder lässt sich "
                            "nicht lesen. Die Paare aus diesem Eingang stehen deshalb in einer eigenen Datei daneben. Beim Zurückführen bitte beide beachten.")
        bekannt = {platzhalter for platzhalter, _ in bestehend}
        ps.zuordnung_schreiben(tabelle, bestehend + [paar for paar in korb.zuordnung if paar[0] not in bekannt])
        return tabelle, ""

    # ---- Der Eingang eines Falls: entfernen, verschieben, von Hand Kopiertes prüfen
    def _durch(self, d: dict) -> str:
        durch = " ".join(str(d.get("durch") or "").split())
        if not durch:
            raise Fehler("Bitte angeben, wer das veranlasst (Feld «Durch»).")
        return durch

    def _namen(self, d: dict) -> list[str]:
        namen = d.get("namen")
        if isinstance(namen, str):
            namen = [n for n in namen.split("\n") if n]
        if not namen or not all(isinstance(n, str) for n in namen):
            raise Fehler("Bitte zuerst Dokumente auswählen.")
        return namen

    def eingang_entfernen(self, d: dict) -> dict:
        fall, namen, durch = self._fall_id(str(d.get("fall") or "")), self._namen(d), self._durch(d)
        grund = " ".join(str(d.get("grund") or "").split())
        if not grund:
            raise Fehler("Bitte angeben, warum die Dokumente entfernt werden (Feld «Grund»).")
        try:
            entfernt = fallwerkzeug.entfernen(fall, [n for n in namen if (fall_pfad(fall) / "eingang" / n).is_file()], durch=durch, grund=grund, weg="Oberfläche")
        except (fallwerkzeug.Fehler, FileNotFoundError, ValueError) as e:
            raise Fehler(str(e).replace("--durch", "«Durch»").replace("--grund", "«Grund»")) from e
        self.vermerken(fall, "Dokumente aus dem Eingang entfernt", f"{len(entfernt)} Datei(en), durch {durch}, Grund: {grund}")
        return {"meldung": f"{len(entfernt)} Datei(en) aus dem Eingang von Fall {fall} entfernt. Das Register der PII-Prüfung hält fest, was entfernt wurde.", "entfernt": entfernt}

    def eingang_nachbessern(self, d: dict) -> dict:
        """Holt Dokumente, die schon im Fall liegen, in den Akten-Eingang dieses Falls: zum Nachbessern auf dem lokalen Bildschirm
        (nochmals pseudonymisieren). Im Fall bleibt jedes liegen, bis seine nachgebesserte Fassung aufgenommen ist. Erst dann wird
        die alte Fassung entfernt. Anlass: Die Ermittlung meldet eine geschützte Angabe, die noch im Klartext dasteht."""
        fall, namen, durch = self._fall_id(str(d.get("fall") or "")), self._namen(d), self._durch(d)
        fall_daten(fall)
        sitzung = self.ermittlungen.get(fall)
        eingang = fall_pfad(fall) / "eingang"
        im_fall = set(sum(eingang_stand(fall_pfad(fall)), []))
        korb = self.korb(fall)
        geholt: list[Eintrag] = []
        meldungen: list[str] = []
        with self.sperre:
            for n in dict.fromkeys(namen):
                if n not in im_fall or Path(n).name != n:
                    continue
                if Path(n).suffix.lower() in GEWANDELT:
                    meldungen.append(f"{n}: Das ist ein Original. Nachbessern lässt sich seine Textfassung.")
                    continue
                if any(e.statt and e.statt["name"] == n for e in korb.eintraege.values()):
                    meldungen.append(f"{n}: liegt schon zum Nachbessern im Akten-Eingang.")
                    continue
                neu: list[Eintrag] = []
                self._einlegen(korb, n, "", (eingang / n).read_bytes(), AUSPACK_TIEFE, neu, meldungen)
                for e in neu:
                    e.statt = {"name": n, "durch": durch}
                    e.rolle = "rapport" if n.lower().startswith("rapport") else "beilage"
                geholt += neu
        if not geholt:
            with self.sperre:
                if not korb.eintraege:      # kein leerer Akten-Eingang bleibt zurück, wenn nichts geholt wurde
                    self.koerbe.pop(fall, None)
            raise Fehler("Keines der gewählten Dokumente liess sich zum Nachbessern holen." + (" " + " ".join(meldungen) if meldungen else ""))
        self.vermerken(fall, "Dokumente zum Nachbessern geholt", f"{len(geholt)} Datei(en), durch {durch}: {', '.join(e.statt['name'] for e in geholt)}",
                       sitzung=getattr(sitzung, "kennung", None))
        return {"ziel": fall, "eintraege": [e.kurz() for e in geholt], "meldungen": meldungen,
                "meldung": f"{len(geholt)} Dokument(e) liegen jetzt im Akten-Eingang dieses Falls. Dort «pseudonymisieren» wählen, die Stellen ersetzen und danach "
                           "aufnehmen: Die nachgebesserte Fassung ersetzt dann die alte." + (" " + " ".join(meldungen) if meldungen else "")}

    def eingang_pruefen(self, d: dict) -> dict:
        """Ein Dokument, das von Hand in den Eingang kopiert wurde, geht nachträglich durch die PII-Prüfung. Besteht es, gilt es als geprüft."""
        fall, namen = self._fall_id(str(d.get("fall") or "")), self._namen(d)
        fall_daten(fall)
        eingang = fall_pfad(fall) / "eingang"
        ungeprueft = set(eingang_stand(fall_pfad(fall))[1])
        dateien = [str(eingang / n) for n in namen if n in ungeprueft]
        if not dateien:
            raise Fehler("Keines der gewählten Dokumente ist ungeprüft.")
        code, ausgabe = self.werkzeug(["tools/fall.py", "aufnehmen", fall, *dateien], 600)
        jetzt = eingang_stand(fall_pfad(fall))
        geprueft = [n for n in namen if n in jetzt[0]]
        if geprueft:
            self.vermerken(fall, "Dokumente nachträglich geprüft", f"{len(geprueft)} von Hand kopierte Datei(en) haben die PII-Prüfung bestanden")
        return {"gelungen": code == 0, "ausgabe": ausgabe.replace(str(PROJEKT) + os.sep, ""),
                "meldung": f"{len(geprueft)} von {len(dateien)} Dokument(en) haben die PII-Prüfung bestanden." + ("" if code == 0 else " Die übrigen enthalten Personendaten: bitte entfernen und pseudonymisiert neu aufnehmen.")}

    def eingang_verschieben(self, d: dict) -> dict:
        """Verschiebt geprüfte Dokumente in einen anderen Fall: dort aufnehmen (mit PII-Prüfung), hier entfernen."""
        fall, ziel, namen, durch = self._fall_id(str(d.get("fall") or "")), self._fall_id(str(d.get("nach") or "")), self._namen(d), self._durch(d)
        if ziel == fall:
            raise Fehler("Quelle und Ziel sind derselbe Fall.")
        fall_daten(fall)
        fall_daten(ziel)
        eingang = fall_pfad(fall) / "eingang"
        geprueft = set(eingang_stand(fall_pfad(fall))[0])
        # Von einem Paar aus Original und Lesefassung wandert die Lesefassung: Agenten lesen immer sie
        waehlbar: list[str] = []
        for n in namen:
            if Path(n).suffix.lower() in GEWANDELT and (eingang / f"{n}.txt").is_file():
                n = f"{n}.txt"
            if n in geprueft and n not in waehlbar:
                waehlbar.append(n)
        if not waehlbar:
            raise Fehler("Keines der gewählten Dokumente lässt sich verschieben. Ungeprüfte Dokumente bitte zuerst prüfen.")
        # Liegt im Zielfall schon ein Dokument gleichen Namens, kommt das verschobene unter dem nächsten freien Namen an.
        # Mit neutralen Namen ist das die Regel: Jeder Fall hat sein beilage-01.txt. Überschrieben wird nie
        vorher = {n.lower() for n in sum(eingang_stand(fall_pfad(ziel)), [])}
        vergeben, plan = set(vorher), {}
        for n in waehlbar:
            neutral, neu, nr = re.fullmatch(r"(rapport|beilage)-(\d+)(\.\w+)", n), n, 1
            while neu.lower() in vergeben:
                nr += 1
                neu = f"{neutral.group(1)}-{int(neutral.group(2)) + nr - 1:02d}{neutral.group(3)}" if neutral else f"{Path(n).stem} ({nr}){Path(n).suffix}"
            vergeben.add(neu.lower())
            plan[n] = neu
        with Zwischenablage() as ordner:
            for n, neu in plan.items():
                shutil.copyfile(eingang / n, ordner / neu)
            code, ausgabe = self.werkzeug(["tools/fall.py", "aufnehmen", ziel, *[str(ordner / neu) for neu in plan.values()]], 600)
            ausgabe = ausgabe.replace(str(ordner) + os.sep, "").replace(str(ordner), "(Zwischenablage)")
        dort = set(eingang_stand(fall_pfad(ziel))[0])
        angekommen = [n for n, neu in plan.items() if neu in dort and neu.lower() not in vorher]
        umbenannt = [f"{n} liegt dort als {plan[n]}" for n in angekommen if plan[n] != n]
        if angekommen:
            fallwerkzeug.entfernen(fall, angekommen, durch=durch, grund=f"verschoben nach Fall {ziel}", weg="Oberfläche")
            self.vermerken(fall, "Dokumente verschoben", f"{len(angekommen)} Datei(en) nach Fall {ziel}, durch {durch}" + (f" ({'; '.join(umbenannt)})" if umbenannt else ""))
            self.vermerken(ziel, "Dokumente aufgenommen", f"{len(angekommen)} Datei(en) verschoben aus Fall {fall}, durch {durch}")
        return {"gelungen": bool(angekommen), "ausgabe": ausgabe.replace(str(PROJEKT) + os.sep, ""), "namen": {n: plan[n] for n in angekommen},
                "meldung": f"{len(angekommen)} von {len(waehlbar)} Dokument(en) nach Fall {ziel} verschoben."
                           + (" Dort lag schon ein Dokument gleichen Namens: " + "; ".join(umbenannt) + "." if umbenannt else "")
                           + ("" if len(angekommen) == len(waehlbar) else " Die übrigen haben die PII-Prüfung nicht bestanden, siehe Ausgabe.")}

    def fall_loeschen(self, d: dict) -> dict:
        """Löscht einen Fall, in dem noch nichts abgefragt wurde. Ein Fall mit Protokolleinträgen bleibt: Er ist Beweismaterial."""
        fall, durch = self._fall_id(str(d.get("fall") or "")), self._durch(d)
        sitzung = self.ermittlungen.get(fall)
        if sitzung is not None and sitzung.als_dict()["status"] in ("laeuft", "wartet"):
            raise Fehler("Zu diesem Fall läuft eine Ermittlung. Bitte zuerst anhalten.")
        try:
            grund = fallwerkzeug.loeschbar(fall)        # zuerst, was grundsätzlich dagegen spricht: Abfragen, Befunde, der Musterfall
            if grund:
                raise Fehler(grund)
            if fall in self.koerbe and self.koerbe[fall].eintraege:
                raise Fehler("Im Akten-Eingang dieses Falls liegen noch Dateien, die nicht aufgenommen sind. Bitte zuerst unter «Akten» aufnehmen oder entfernen.")
            fallwerkzeug.loeschen(fall, durch=durch, weg="Oberfläche")
        except (fallwerkzeug.Fehler, FileNotFoundError, ValueError) as e:
            raise Fehler(str(e).replace("--durch", "«Durch»")) from e
        with self.sperre:
            self.koerbe.pop(fall, None)
            self.ermittlungen.pop(fall, None)
        self.vermerken(fall, "Fall gelöscht", f"durch {durch}, abgefragt war darin noch nichts")
        return {"meldung": f"Fall {fall} gelöscht.", "geloescht": fall}

    # ---- 3. Freigaben
    def freigabe(self, d: dict) -> dict:
        fall, art = self._fall_id(str(d.get("fall") or "")), str(d.get("art") or "")
        if art not in FREIGABEN:
            raise Fehler("Diese Freigabe gibt es nicht.")
        try:
            if d.get("entziehen"):
                fallwerkzeug.freigabe_setzen(fall, art, entziehen=True, weg="Oberfläche")
                self.vermerken(fall, f"Freigabe entzogen: {art}")
                return {"meldung": f"Freigabe «{art}» entzogen."}
            eintrag = fallwerkzeug.freigabe_setzen(fall, art, durch=str(d.get("durch") or ""), vermerk=str(d.get("vermerk") or ""), weg="Oberfläche")
        except (fallwerkzeug.Fehler, FileNotFoundError) as e:
            raise Fehler(str(e).replace("--durch", "«Durch»").replace("--vermerk", "«Grundlage»")) from e
        self.vermerken(fall, f"Freigabe erteilt: {art}", f"durch {eintrag['durch']}, Grundlage: {eintrag['vermerk']}")
        return {"meldung": f"Freigabe «{art}» erteilt durch {eintrag['durch']}. {FREIGABE_TEXT[art]}"}

    def pflichtquellen(self, d: dict) -> dict:
        """Gibt die Pflichtquellen eines Falls vor oder hebt die Vorgabe auf (leere Liste): Was vorgegeben ist, muss die Ermittlung
        abfragen. Das entscheidet der Sachbearbeiter, wie eine Freigabe. Während die Ermittlung arbeitet, bleibt die Vorgabe stehen."""
        fall = self._fall_id(str(d.get("fall") or ""))
        namen = d.get("quellen")
        if not isinstance(namen, list) or not all(isinstance(n, str) for n in namen):
            raise Fehler("Die Auswahl hat nicht die erwartete Form.")
        sitzung = self.ermittlungen.get(fall)
        if sitzung is not None and sitzung.als_dict()["status"] in ("laeuft", "wartet"):
            raise Fehler("Die Ermittlung arbeitet gerade. Die Pflichtquellen lassen sich ändern, sobald sie angehalten oder beendet ist.")
        try:
            eintrag = fallwerkzeug.pflichtquellen_setzen(fall, namen, weg="Oberfläche")
        except (fallwerkzeug.Fehler, FileNotFoundError) as e:
            raise Fehler(str(e)) from e
        quellen = eintrag.get("quellen") or []
        self.vermerken(fall, "Pflichtquellen vorgegeben" if quellen else "Pflichtquellen aufgehoben", ", ".join(quellen))
        return {"quellen": quellen, "meldung": (f"{len(quellen)} Pflichtquelle{'n' if len(quellen) != 1 else ''} gespeichert: {', '.join(quellen)}." if quellen
                                                else "Keine Pflichtquellen: Das Team wählt die Quellen selbst.")}

    # ---- 4. Abklärung von Hand
    def beleg(self, d: dict) -> dict:
        fall = self._fall_id(str(d.get("fall") or ""))
        zone = plattform.zeitzone()
        try:
            tatzeit = belegwerkzeug.zeit_lesen(str(d["tatzeit"]), zone) if str(d.get("tatzeit") or "").strip() else None
            e = belegwerkzeug.erfassen(
                fall, indikator=str(d.get("indikator") or ""), typ=str(d.get("typ") or ""), quelle=str(d.get("quelle") or ""),
                abgeklaert=belegwerkzeug.zeit_lesen(str(d.get("abgeklaert") or ""), zone), wortlaut=str(d.get("wortlaut") or ""),
                durch=str(d.get("durch") or ""), anonymisierung=str(d.get("anonymisierung") or "") or None, art=str(d.get("anon_art") or "") or None,
                dienst=str(d.get("dienst") or "") or None, residential=bool(d.get("residential")), tatzeit=tatzeit, weg="Oberfläche")
        except (belegwerkzeug.Fehler, FileNotFoundError) as e:
            raise Fehler(str(e).replace("(--durch)", "(Feld «Durch»)")) from e
        self.vermerken(fall, f"Beleg von Hand erfasst: {e['id']}", f"{e['ziel']} · {e['quelle']}")
        return {"meldung": f"Beleg {e['id']} erfasst. Er steht in der Kette und ist überall als «von Hand erfasst» gekennzeichnet.", "beleg": e["id"]}

    # ---- 5. Dokumente erzeugen, Kette prüfen
    def dokumente(self, d: dict) -> dict:
        fall, was = self._fall_id(str(d.get("fall") or "")), str(d.get("was") or "")
        fall_daten(fall)
        if was not in WERKZEUGE:
            raise Fehler("Diesen Schritt kennt die Oberfläche nicht.")
        titel, befehle = WERKZEUGE[was]
        ausgaben, code = [], 0
        for befehl in befehle:
            c, ausgabe = self.werkzeug([teil.replace("{fall}", fall) for teil in befehl])
            ausgaben.append(ausgabe)
            code = code or c
            if c and was == "alles":        # ohne Rapport kein PDF: Der erste Fehler sagt, woran es liegt
                break
        self.vermerken(fall, titel, "ohne Fehler" if code == 0 else f"Rückgabewert {code}")
        return {"gelungen": code == 0, "ausgabe": "\n\n".join(a for a in ausgaben if a), "meldung": f"{titel}: {'erledigt' if code == 0 else 'mit Meldungen, siehe Ausgabe'}."}

    # ---- 6. Zurückführen
    def zurueckfuehren(self, d: dict) -> dict:
        """Der Rapport mit echten Angaben, lokal. Zuordnungstabelle und Ergebnis liegen in der Ablage ausserhalb des Projekts."""
        fall = self._fall_id(str(d.get("fall") or ""))
        tabelle = Path(str(d.get("zuordnung") or "")).expanduser() if str(d.get("zuordnung") or "").strip() else self.zuordnung_pfad(fall)
        ausgabe = self.ablage / fall / "zurueckgefuehrt"
        try:
            ergebnis = rueck.zurueckfuehren(fall, tabelle, ausgabe)
        except rueck.Fehler as e:
            raise Fehler(str(e)) from e
        self.vermerken(fall, "Rapport zurückgeführt", f"{ergebnis['ersetzt']} Platzhalter ersetzt, Ergebnis in der Ablage ausserhalb des Projekts")
        return {"ersetzt": ergebnis["ersetzt"], "ungenutzt": ergebnis["ungenutzt"], "offen": ergebnis["offen"], "ordner": str(ausgabe),
                "dateien": [{"name": p.name, "ticket": self.ticket(p)} for p in ergebnis["dateien"]],
                "meldung": f"{ergebnis['ersetzt']} Platzhalter ersetzt." + (f" {len(ergebnis['offen'])} blieben stehen, weil die Zuordnung sie nicht kennt." if ergebnis["offen"] else "")}

    def ticket(self, pfad: Path) -> str:
        """Eine Karte für genau einen Abruf einer Datei aus der Ablage, zwei Minuten gültig. So steht das Geheimnis nie in einer Adresse."""
        with self.sperre:
            jetzt = time.time()
            for alt in [k for k, (_, bis) in self.tickets.items() if bis < jetzt]:
                del self.tickets[alt]
            karte = secrets.token_urlsafe(24)
            self.tickets[karte] = (Path(pfad), jetzt + TICKET_SEKUNDEN)
            return karte

    def ticket_einloesen(self, karte: str) -> Path:
        with self.sperre:
            pfad, bis = self.tickets.pop(str(karte or ""), (None, 0))
        if pfad is None or bis < time.time() or not pfad.is_file() or innerhalb(pfad):
            raise Fehler("Diese Datei lässt sich so nicht mehr abrufen. Bitte den Schritt in der Oberfläche wiederholen.", 404)
        return pfad

    # ---- 7. Quellen
    def quelle_testen(self, d: dict) -> dict:
        """Eine harmlose Testabfrage bei einer Quelle, über das Gateway und in der Fallakte SELBSTTEST, wie tools/pruefen.py --live."""
        from tools import pruefen
        q = next((q for q in QUELLEN if q.name == d.get("quelle")), None)
        if q is None or not (q.test or d.get("kontingent")):
            raise Fehler("Für diese Quelle gibt es keine Testabfrage.")
        plan = [{"quelle": q.name, "werkzeug": "urlscan_kontingent", "argumente": {}}] if d.get("kontingent") else \
            [{"quelle": q.name, "werkzeug": q.test[0], "argumente": q.test[1]}]
        r = subprocess.run([python(), "-X", "utf8", "-c", pruefen.LIVE_SKRIPT, str(PROJEKT), json.dumps(plan)], cwd=str(PROJEKT), env=umgebung(),
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, stdin=subprocess.DEVNULL)
        try:
            e = json.loads((r.stdout.strip().splitlines() or ["{}"])[-1])
        except json.JSONDecodeError:
            e = {}
        if not e:
            raise Fehler("Die Testabfrage liess sich nicht ausführen: " + ((r.stderr.strip().splitlines() or ["ohne Meldung"])[-1])[:300], 500)
        gut = e.get("ergebnis") in ("ok", "kein_treffer")
        if not gut:     # was die Quelle gemeldet hat, gehört ins Fehlerprotokoll: Daran lässt sich ablesen, ob Schlüssel, Kontingent oder Netz fehlt
            self.fehlerbuch.eintragen("Werkzeug", "hinweis", f"Testabfrage {q.name}: {e.get('fehler') or 'keine verwertbare Antwort'}",
                                      f"Werkzeug {plan[0]['werkzeug']}" + (f", Beleg {e['id']} in der Fallakte SELBSTTEST" if e.get("id") else ""))
        return {"gelungen": gut, "beleg": e.get("id"), "kurz": e.get("kurz") or "",
                "meldung": (f"{q.name} antwortet ({e.get('ergebnis')}, {e.get('id')} in der Fallakte SELBSTTEST)." + (f" {e['kurz']}" if e.get("kurz") else ""))
                if gut else f"{q.name}: {e.get('fehler') or 'keine verwertbare Antwort'}"}


    # ---- 8. Fehlerprotokoll
    def werkzeug(self, argumente: list[str], zeit: int = 600) -> tuple[int, str]:
        """Startet ein Werkzeug des Projekts (werkzeug_lauf). Endet es mit einem Fehler, steht das im Fehlerprotokoll."""
        code, ausgabe = werkzeug_lauf(argumente, zeit)
        if code != 0:
            self._werkzeug_fehler(argumente, code, ausgabe)
        return code, ausgabe

    def _werkzeug_fehler(self, argumente: list[str], code: int, ausgabe: str) -> None:
        """Ein Werkzeug des Projekts endete mit einem Fehler. Von tools/fall.py steht nur das da: Seine Ausgabe nennt die Namen der
        Dokumente, und ein Name kann eine Person nennen. Von den anderen Werkzeugen stehen die letzten Zeilen der Ausgabe da."""
        werkzeug = next((a for a in argumente if a.startswith("tools/")), "Werkzeug")
        befehl = " ".join(a for a in argumente[:3] if a.startswith(("tools/", "--")) or FALL_RE.match(a))
        fall = next((a for a in argumente if FALL_RE.match(a) and (fall_pfad(a) / "fall.json").is_file()), "")
        heikel = werkzeug == "tools/fall.py"
        # Rückgabewert 1 heisst bei den Werkzeugen des Projekts meist «die Prüfung hat etwas gefunden». Ein Absturz ist ein Fehler
        absturz = code != 1 or "Traceback (most recent call last)" in ausgabe
        if heikel and not absturz:
            return          # tools/fall.py meldet so, dass die PII-Prüfung ein Dokument nicht annimmt: Das steht im Fenster und ist kein Fehler
        self.fehlerbuch.eintragen("Werkzeug", "fehler" if absturz else "hinweis", f"{befehl or werkzeug} endete mit Rückgabewert {code}."
                                  + (" Die Ausgabe ist nicht festgehalten: Sie nennt die Namen der Dokumente." if heikel else ""),
                                  "" if heikel else "\n".join(ausgabe.splitlines()[-40:]), fall)

    def fehler_melden(self, d: dict) -> dict:
        """Ein Fehler aus dem Browserfenster: Das Skript der Oberfläche meldet ihn, damit er nicht nur in der Konsole des Browsers steht."""
        meldung = " ".join(str(d.get("meldung") or "").split())[:600]
        if not meldung:
            raise Fehler("Die Meldung ist leer.")
        self.fehlerbuch.eintragen("Browser", "fehler", meldung, str(d.get("einzelheiten") or "")[:4000], str(d.get("fall") or "") if FALL_RE.match(str(d.get("fall") or "")) else "")
        return {"meldung": "Im Fehlerprotokoll festgehalten."}

    def fehler_leeren(self, d: dict) -> dict:
        zahl = self.fehlerbuch.leeren()
        return {"meldung": f"Das Fehlerprotokoll ist geleert ({zahl} {'Eintrag' if zahl == 1 else 'Einträge'}), im Speicher und in der Ablage."}

    # ---- 9. Arbeitsplatz: alles abschalten
    def alles_anhalten(self, grund: str = "") -> list[str]:
        """Hält jede laufende Ermittlung an und vermerkt es im Sitzungsprotokoll ihres Falls, mit dem Grund. Sie lässt sich
        später fortsetzen. Gibt die Fälle zurück, die es betraf. Aufgerufen auch, wenn die Oberfläche endet: Eine Sitzung
        ohne Oberfläche könnte niemanden mehr fragen."""
        with self.sperre:
            laufend = [(fall, sitzung) for fall, sitzung in self.ermittlungen.items() if sitzung.laeuft()]
        betroffen = []
        for fall, sitzung in laufend:
            try:
                sitzung.anhalten()
            except Fehler:
                continue        # in der Zwischenzeit von selbst zu Ende gegangen
            betroffen.append(fall)
            try:
                self.vermerken(fall, "Ermittlung angehalten", grund, sitzung=getattr(sitzung, "kennung", None))
            except (OSError, subprocess.SubprocessError):
                pass            # das Anhalten zählt. Der Verlauf im Arbeitsstand des Falls hält es ebenfalls fest
        return betroffen

    def abschalten(self, d: dict) -> dict:
        """Schaltet ab, was zum Arbeitsplatz gehört: hält laufende Ermittlungen an, stoppt Robin und Web-Check. Danach beendet
        sich die Oberfläche selbst: Der Server stösst das an, sobald diese Antwort draussen ist. Gelöscht wird nichts.
        Tor läuft weiter: Es gehört zum System, und ein Browser kann nicht nach dem Passwort fragen."""
        from tools import dienste
        faelle = self.alles_anhalten("«Alles abschalten» in der Oberfläche")
        zeilen, gelungen = dienste.aus(mit_tor=False)
        punkte = ([f"Ermittlung angehalten: {', '.join(faelle)}. Sie lässt sich später fortsetzen."] if faelle else []) + [f"{was}: {wie}" for _, was, wie in zeilen]
        return {"abgeschaltet": True, "gelungen": gelungen, "punkte": punkte, "start": f"{plattform.PY} tools/oberflaeche.py",
                "meldung": "Die Oberfläche ist beendet. Gelöscht wurde nichts: Fallakten, Schlüssel und Einstellungen sind, wie sie waren."}


AKTIONEN = ("korb_entfernen", "korb_rolle", "korb_verschieben", "korb_umbenennen", "korb_risiko", "korb_pseudo", "korb_aufnehmen", "pseudo_entscheid", "pseudo_uebernehmen", "pseudo_verwerfen",
            "eingang_entfernen", "eingang_pruefen", "eingang_verschieben", "eingang_nachbessern", "fall_loeschen", "freigabe", "pflichtquellen", "beleg", "dokumente",
            "zurueckfuehren", "quelle_testen", "fehler_melden", "fehler_leeren", "abschalten")
