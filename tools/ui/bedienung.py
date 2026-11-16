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
"""
from __future__ import annotations

import base64
import binascii
import hmac
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
from datetime import datetime
from pathlib import Path

from gateway import plattform
from gateway.akte import FALL_RE, FREIGABE_TEXT, FREIGABEN, PROJEKT, fall_daten, fall_pfad
from gateway.quellen import QUELLEN
from tools import _pseudo as ps, beleg as belegwerkzeug, fall as fallwerkzeug, reidentifizieren as rueck
from tools.pii_pruefung import NichtLesbar, bericht as pii_bericht, pruefen as pii_pruefen, text_lesen

ENDUNGEN = (".txt", ".md", ".docx", ".pdf")
GROESSE = 25 * 1024 * 1024          # grösstes Dokument, das die Oberfläche annimmt
TICKET_SEKUNDEN = 120
WERKZEUGE = {       # was «Dokumente» auslösen kann: Name -> (Bezeichnung, Befehle nach dem Interpreter)
    "rapport": ("Abschlussrapport erzeugen", [["tools/rapport.py", "{fall}"]]),
    "protokoll": ("Ermittlungsprotokoll erzeugen", [["tools/protokoll.py", "{fall}"]]),
    "anhang": ("Datenblätter erzeugen", [["tools/anhang.py", "{fall}", "--ohne-pdf"]]),
    "pdf": ("PDF erzeugen", [["tools/pdf.py", "{fall}"], ["tools/anhang.py", "{fall}"]]),
    "kette": ("Protokollkette prüfen", [["tools/audit_pruefen.py", "{fall}"]]),
}


class Fehler(Exception):
    """Eine Bedienung, die so nicht geht. Der Text ist für den Sachbearbeiter und nennt nie Klartext."""

    def __init__(self, text: str, status: int = 400):
        super().__init__(text)
        self.status = status


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


class Dokument:
    """Ein hochgeladenes Dokument. Der Inhalt liegt im Speicher. Auf die Platte kommt er nur kurz und nur ausserhalb des Projekts."""

    def __init__(self, name: str, inhalt_b64: str):
        self.name = re.sub(r"[^A-Za-z0-9._ äöüÄÖÜ-]", "_", Path(str(name or "")).name).strip() or "dokument.txt"
        if Path(self.name).suffix.lower() not in ENDUNGEN:
            raise Fehler(f"Dieses Format nimmt die Oberfläche nicht an. Möglich: {', '.join(ENDUNGEN)}.")
        try:
            self.inhalt = base64.b64decode(inhalt_b64 or "", validate=True)
        except (binascii.Error, ValueError) as e:
            raise Fehler("Das Dokument kam beschädigt an. Bitte noch einmal hineinziehen.") from e
        if not self.inhalt:
            raise Fehler("Das Dokument ist leer.")
        if len(self.inhalt) > GROESSE:
            raise Fehler(f"Das Dokument ist grösser als {GROESSE // (1024 * 1024)} MB.")

    def text(self) -> str:
        if Path(self.name).suffix.lower() in (".txt", ".md"):
            return self.inhalt.decode("utf-8-sig", "replace")
        with Zwischenablage() as ordner:        # Word und PDF brauchen eine Datei, um gelesen zu werden
            datei = ordner / self.name
            datei.write_bytes(self.inhalt)
            try:
                return text_lesen(datei)
            except NichtLesbar as e:
                raise Fehler(str(e)) from e


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


class Pseudo:
    """Ein Klartext-Dokument auf dem Weg durch die Bestätigung. Lebt nur im Speicher des Servers."""

    def __init__(self, name: str, text: str, zuordnung: list):
        self.name = name
        self.vorgang = ps.Vorgang(text, zuordnung=zuordnung)
        self.beruehrt = time.time()


class Bedienung:
    def __init__(self, ablage: Path | None = None):
        self.geheimnis = secrets.token_urlsafe(32)
        self.startcode: str | None = secrets.token_urlsafe(18)      # gilt genau einmal: Der Browser tauscht ihn gegen das Geheimnis
        eigen = os.environ.get("OSINT_ABLAGE", "").strip()       # dieselbe Variable liest der Wächter, um die Ablage für Agenten zu sperren
        self.ablage = Path(ablage or eigen).expanduser() if (ablage or eigen) else Path.home() / "OSINT-Ablage"
        if innerhalb(self.ablage):
            raise Fehler("Die Ablage für Klartext muss ausserhalb des Projektordners liegen.")
        self.pseudo: dict[str, Pseudo] = {}
        self.tickets: dict[str, tuple[Path, float]] = {}
        self.sitzung = "oberflaeche-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        self.sperre = threading.RLock()
        self.ermittlungen: dict = {}        # Fall-ID -> Sitzung (tools/ui/sitzung.py)

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

    # ---- 1. Fall anlegen, Dokumente aufnehmen
    def _fall_id(self, fall: str) -> str:
        if not FALL_RE.match(fall or ""):
            raise Fehler("Die Fall-ID besteht aus Buchstaben, Ziffern, Punkt, Strich und Unterstrich (3 bis 64 Zeichen).")
        return fall

    def dokument_pruefen(self, d: dict) -> dict:
        """Die PII-Prüfung für ein Dokument, das schon geschwärzt sein soll. Nimmt nichts auf."""
        dok = Dokument(d.get("name"), d.get("inhalt"))
        funde, platzhalter = pii_pruefen(dok.text())
        sperren = [f for f in funde if f.stufe == "sperre"]
        return {"sauber": not sperren, "sperren": len(sperren), "hinweise": sum(1 for f in funde if f.stufe == "hinweis"),
                "platzhalter": sum(platzhalter.values()), "bericht": pii_bericht(dok.name, funde, platzhalter)}

    def _aufnehmen(self, fall: str, name: str, inhalt: bytes, neu: dict | None) -> dict:
        """Schreibt das Dokument kurz in die Zwischenablage und übergibt es tools/fall.py. Das Werkzeug prüft selbst noch einmal."""
        with Zwischenablage() as ordner:
            datei = ordner / name
            datei.write_bytes(inhalt)
            if neu is not None:
                befehl = ["tools/fall.py", "neu", fall, "--titel", neu.get("titel") or fall, "--rapport", str(datei)]
                for schalter, feld in (("--auftrag", "auftrag"), ("--kuerzel", "kuerzel"), ("--klassifizierung", "klassifizierung")):
                    if str(neu.get(feld) or "").strip():
                        befehl += [schalter, " ".join(str(neu[feld]).split())]
            else:
                befehl = ["tools/fall.py", "aufnehmen", fall, str(datei)]
            code, ausgabe = werkzeug_lauf(befehl, 180)
        ausgabe = ausgabe.replace(str(ordner), "(Zwischenablage)")
        return {"aufgenommen": code == 0, "ausgabe": ausgabe, "fall": fall}

    def fall_anlegen(self, d: dict) -> dict:
        """Weg «Dokument ist schon geschwärzt»: PII-Prüfung, dann tools/fall.py neu. Bei Sperrfunden entsteht nichts."""
        fall = self._fall_id(str(d.get("fall") or "").strip())
        if (fall_pfad(fall) / "fall.json").exists():
            raise Fehler(f"Den Fall «{fall}» gibt es schon. Weitere Dokumente lassen sich im Fall nachziehen.")
        dok = Dokument(d.get("name"), d.get("inhalt"))
        pruefung = self.dokument_pruefen(d)
        if not pruefung["sauber"]:
            return {"aufgenommen": False, "fall": fall, "ausgabe": pruefung["bericht"],
                    "meldung": "Die PII-Prüfung hat Personendaten gefunden. Es wurde nichts angelegt und nichts aufgenommen."}
        ergebnis = self._aufnehmen(fall, dok.name, dok.inhalt, {k: d.get(k) for k in ("titel", "auftrag", "kuerzel", "klassifizierung")})
        if ergebnis["aufgenommen"]:
            self.vermerken(fall, "Fall angelegt", f"Dokument {dok.name}, geschwärzt angeliefert")
        return {**ergebnis, "meldung": f"Fall {fall} angelegt." if ergebnis["aufgenommen"] else "Der Fall liess sich nicht anlegen."}

    def dokument_aufnehmen(self, d: dict) -> dict:
        fall = self._fall_id(str(d.get("fall") or ""))
        fall_daten(fall)
        dok = Dokument(d.get("name"), d.get("inhalt"))
        pruefung = self.dokument_pruefen(d)
        if not pruefung["sauber"]:
            return {"aufgenommen": False, "fall": fall, "ausgabe": pruefung["bericht"],
                    "meldung": "Die PII-Prüfung hat Personendaten gefunden. Das Dokument wurde nicht aufgenommen."}
        ergebnis = self._aufnehmen(fall, dok.name, dok.inhalt, None)
        if ergebnis["aufgenommen"]:
            self.vermerken(fall, "Dokument aufgenommen", f"{dok.name}, geschwärzt angeliefert")
        return {**ergebnis, "meldung": "Dokument aufgenommen." if ergebnis["aufgenommen"] else "Das Dokument wurde nicht aufgenommen."}

    # ---- Klartext: der lokale Bildschirm der Pseudonymisierung
    def zuordnung_pfad(self, fall: str) -> Path:
        return self.ablage / self._fall_id(fall) / "zuordnung.csv"

    def pseudo_beginnen(self, d: dict) -> dict:
        dok = Dokument(d.get("name"), d.get("inhalt"))
        fall = str(d.get("fall") or "").strip()
        zuordnung = []
        if fall and self.zuordnung_pfad(fall).is_file():        # weiteres Dokument zum selben Fall: gleiche Angabe, gleicher Platzhalter
            zuordnung = ps.zuordnung_lesen(self.zuordnung_pfad(fall))
        with self.sperre:
            for alt in [k for k, v in self.pseudo.items() if time.time() - v.beruehrt > 6 * 3600]:
                del self.pseudo[alt]
            kennung = secrets.token_urlsafe(12)
            self.pseudo[kennung] = Pseudo(dok.name, dok.text(), zuordnung)
        return {"vorgang": kennung, "bekannt": len(zuordnung)}

    def pseudo_holen(self, kennung: str) -> Pseudo:
        p = self.pseudo.get(str(kennung or ""))
        if p is None:
            raise Fehler("Dieses Dokument ist nicht mehr im Speicher. Bitte noch einmal hineinziehen.", 404)
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

    def pseudo_abschliessen(self, d: dict) -> dict:
        """Das Ergebnis geht in die PII-Prüfung und in den Fall. Die Zuordnungstabelle geht in die Ablage ausserhalb des Projekts."""
        p = self.pseudo_holen(d.get("vorgang"))
        fall = self._fall_id(str(d.get("fall") or "").strip())
        neu = not (fall_pfad(fall) / "fall.json").exists()
        ergebnis = p.vorgang.ergebnis()
        funde, platzhalter = pii_pruefen(ergebnis.text)
        name = f"{Path(p.name).stem}_pseudonymisiert.txt"
        if any(f.stufe == "sperre" for f in funde):
            return {"aufgenommen": False, "fall": fall, "ausgabe": pii_bericht(name, funde, platzhalter),
                    "meldung": "Die PII-Prüfung findet im Ergebnis noch Personendaten. Bitte die genannten Stellen im Dokument ergänzen. Es wurde nichts aufgenommen."}
        aufnahme = self._aufnehmen(fall, name, ergebnis.text.encode("utf-8"),
                                   {k: d.get(k) for k in ("titel", "auftrag", "kuerzel", "klassifizierung")} if neu else None)
        if not aufnahme["aufgenommen"]:
            return {**aufnahme, "meldung": "Das Ergebnis wurde nicht aufgenommen."}
        tabelle = self.zuordnung_pfad(fall)
        tabelle.parent.mkdir(parents=True, exist_ok=True)
        for ordner in (self.ablage, tabelle.parent):
            try:
                os.chmod(ordner, 0o700)
            except OSError:
                pass
        ps.zuordnung_schreiben(tabelle, ergebnis.zuordnung)
        with self.sperre:
            self.pseudo.pop(str(d.get("vorgang")), None)        # der Klartext verlässt den Speicher
        self.vermerken(fall, "Fall angelegt" if neu else "Dokument aufgenommen", f"Dokument {name}, lokal pseudonymisiert ohne Sprachmodell")
        return {**aufnahme, "ersetzt": sum(ergebnis.ersetzt.values()), "platzhalter": len(ergebnis.zuordnung), "neu": len(ergebnis.neu),
                "offen": ergebnis.offen, "klaerung": len(ergebnis.klaerung), "zuordnung": str(tabelle),
                "meldung": f"Fall {fall} angelegt." if neu else "Dokument aufgenommen."}

    def pseudo_verwerfen(self, d: dict) -> dict:
        with self.sperre:
            self.pseudo.pop(str(d.get("vorgang") or ""), None)
        return {"meldung": "Das Dokument ist aus dem Speicher entfernt."}

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
            c, ausgabe = werkzeug_lauf([teil.replace("{fall}", fall) for teil in befehl])
            ausgaben.append(ausgabe)
            code = code or c
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
        return {"gelungen": gut, "beleg": e.get("id"), "kurz": e.get("kurz") or "",
                "meldung": (f"{q.name} antwortet ({e.get('ergebnis')}, {e.get('id')} in der Fallakte SELBSTTEST)." + (f" {e['kurz']}" if e.get("kurz") else ""))
                if gut else f"{q.name}: {e.get('fehler') or 'keine verwertbare Antwort'}"}


AKTIONEN = ("dokument_pruefen", "fall_anlegen", "dokument_aufnehmen", "pseudo_beginnen", "pseudo_entscheid", "pseudo_abschliessen", "pseudo_verwerfen",
            "freigabe", "beleg", "dokumente", "zurueckfuehren", "quelle_testen")
