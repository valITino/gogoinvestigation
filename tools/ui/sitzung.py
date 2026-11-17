"""Claude Code aus der Oberfläche steuern: Ermittlung starten, zusehen, Nachrichten schicken, anhalten, fortsetzen, Rückfragen beantworten.

Der Weg: die Kommandozeile von Claude Code im Skriptbetrieb, mit fortlaufender JSON-Ausgabe.

    claude -p "/ermittlung <Fall-ID>" --output-format stream-json --verbose
           --permission-prompt-tool mcp__oberflaeche__rueckfrage --mcp-config <Datei>

  - Die Sitzung läuft im Projektordner und ohne Schalter, die Einstellungen, Hooks oder MCP-Server des Projekts
    abschalten. Berechtigungen (Erlaubt- und Verbotsliste), .mcp.json und die Protokoll-Hooks gelten also wie am Terminal.
  - Kein Schalter für das Modell: Es bleibt, wie das Projekt es festlegt.
  - Der Chat: Vorgaben des Sachbearbeiters gehen beim Start mit dem Auftrag mit. Eine Nachricht an eine Sitzung, die gerade
    nicht arbeitet, setzt sie fort (--resume) und gibt ihr den Text. Arbeitet die Sitzung, wartet die Nachricht, bis der
    laufende Auftrag zu Ende ist, oder der Sachbearbeiter unterbricht ihn dafür. Jede Eingabe geht vorher durch die
    PII-Prüfung: Was der Sachbearbeiter hier schreibt, liest das Sprachmodell.
  - Braucht ein Werkzeugaufruf eine Zustimmung (Regeln unter «ask», oder der Aufruf steht auf keiner Liste), geht die Frage
    über einen kleinen MCP-Server (tools/ui/rueckfrage.py) an diesen Server und erscheint im Browser als Dialog. Erlauben
    oder ablehnen kann nur, wer das Geheimnis der Oberfläche hat. Die Karte, mit der der MCP-Server fragt, taugt nur zum Fragen.
    Über Aufrufe von Robin (Dark Web) entscheidet die Freigabe «darkweb» des Falls, ohne Dialog.
  - Das Geheimnis der Oberfläche steht nie in der Umgebung der Sitzung.
  - Anhalten beendet den Prozess (SIGTERM: Claude Code bricht den laufenden Schritt ab und beendet laufende Befehle).
    Fortsetzen nimmt dieselbe Sitzung wieder auf (--resume), auch nach einem Neustart der Oberfläche.
  - Meldet Claude Code beim Start, dass das Gateway des Projekts nicht geladen ist, beendet die Oberfläche die Sitzung:
    Dann sind die Einstellungen des Projekts nicht geladen, und Berechtigungen und Protokoll gälten nicht. Die Dokumentation
    kündigt an, dass der Skriptbetrieb sie künftig von sich aus weglässt («--bare» als Vorgabe für «-p»).

Stand der Dokumentation: code.claude.com/docs, Seiten «Run Claude Code programmatically», «CLI reference»,
«Authentication» und «Error reference», gelesen am 16.11.2026. Mit dem echten Claude Code geprüft ist der Weg nicht,
siehe README unter «Stand der Prüfung und Grenzen».
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from gateway import plattform
from gateway.akte import PROJEKT, SITZUNGEN, fall_daten, fall_pfad, freigabe_erteilt, jsonl_lesen
from tools.pii_pruefung import bericht as pii_bericht, pruefen as pii_pruefen
from tools.ui import bedienung as bedienung_modul

AKTIONEN = ("ermittlung_starten", "ermittlung_anhalten", "ermittlung_fortsetzen", "ermittlung_antworten", "ermittlung_nachricht",
            "ermittlung_nachricht_zurueck")
RUECKFRAGE_WERKZEUG = "mcp__oberflaeche__rueckfrage"
ROBIN = "mcp__robin__"
WARTEZEIT = 30 * 60             # so lange wartet eine Rückfrage auf den Sachbearbeiter, dann gilt sie als abgelehnt
AUFTRAG_WEITER = "Bitte fahre mit der Ermittlung fort, wo sie angehalten wurde."
VORGABEN_KOPF = "Vorgaben des Sachbearbeiters für diese Ermittlung (über die Oberfläche eingegeben):"
UNTERBRECHUNG = ("Der Sachbearbeiter hat die Ermittlung unterbrochen und gibt über die Oberfläche vor:\n\n{text}\n\n"
                 "Berücksichtige das und fahre danach mit der Ermittlung fort, wo sie unterbrochen wurde.")
NACHRICHT_LAENGE = 6000
VERLAUF_LAENGE = 20000          # so viele Einträge behält der Verlauf im Speicher
ABSCHLUSS = "abschluss"         # nach einer gelungenen Ermittlung: Ermittlungsprotokoll, PDF und Datenblätter erzeugen
PFLICHT_SERVER = ("osint",)     # ohne das Gateway des Projekts läuft keine gesteuerte Sitzung
CLOUD = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
OHNE_PROJEKT = ("Claude Code hat die Einstellungen des Projekts nicht geladen (es fehlt: {fehlt}). Ohne sie gelten Berechtigungen, Gateway und "
                "Protokoll nicht. Die Oberfläche hat die Sitzung deshalb beendet, bevor sie etwas tun konnte. Die Ermittlung bitte am Terminal starten.")
ZIELE = ("ip", "domain", "url", "hashwert", "adresse", "tx", "wert", "suchtext", "ziel", "gruppe", "kanal", "konto", "instanz", "query", "file_path", "command",
         "skill", "pattern", "description")


def programm() -> list[str] | None:
    """Die Kommandozeile von Claude Code als Befehl. OSINT_CLAUDE nennt ein anderes Programm (besondere Installation):
    einen Pfad oder, als JSON-Liste, einen Befehl mit Argumenten (so starten die Selbsttests ein Programm, das Claude Code spielt)."""
    eigen = (os.environ.get("OSINT_CLAUDE") or "").strip()
    if eigen.startswith("["):
        try:
            befehl = json.loads(eigen)
        except json.JSONDecodeError:
            return None
        return [str(x) for x in befehl] if isinstance(befehl, list) and befehl else None
    pfad = eigen or shutil.which("claude")
    if not pfad:
        return None
    return ["cmd", "/c", pfad] if plattform.WINDOWS and pfad.lower().endswith((".cmd", ".bat")) else [pfad]


def verfuegbar() -> str:
    """Leer, wenn sich Claude Code starten lässt. Sonst der Grund, in einem Satz."""
    if not programm():
        return ("Claude Code ist auf diesem Rechner nicht gefunden. Die Ermittlung lässt sich deshalb nicht aus der Oberfläche starten. "
                f"Einrichten: {plattform.SETUP}")
    return ""


def pflicht_server() -> list[str]:
    """Die MCP-Server des Projekts, die eine gesteuerte Sitzung geladen haben muss. Sind sie es nicht, hat Claude Code die
    Einstellungen des Projekts nicht gelesen, und dann gälten auch Berechtigungen und Protokoll-Hooks nicht."""
    try:
        eingetragen = json.loads((PROJEKT / ".mcp.json").read_text(encoding="utf-8")).get("mcpServers") or {}
    except (OSError, ValueError):
        return []
    return [n for n in PFLICHT_SERVER if n in eingetragen]


def abrechnung(umgebung: dict | None = None) -> dict:
    """Über welchen Zugang eine gesteuerte Sitzung abgerechnet wird, soweit es an der Umgebung abzulesen ist. Nennt nur
    die Namen von Variablen, nie einen Wert. Die Reihenfolge folgt der Dokumentation von Claude Code («Authentication
    precedence»): Cloud-Anbieter, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_API_KEY (im Skriptbetrieb immer, wenn gesetzt),
    apiKeyHelper, CLAUDE_CODE_OAUTH_TOKEN, zuletzt die Anmeldung mit dem Abo."""
    u = os.environ if umgebung is None else umgebung

    def gesetzt(name: str) -> bool:
        return bool(str(u.get(name) or "").strip())
    for name in CLOUD:
        if gesetzt(name):
            return {"art": "cloud", "variable": name, "text": f"Abrechnung: über den Cloud-Anbieter, nach Verbrauch (die Variable {name} ist gesetzt)."}
    for name in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"):
        if gesetzt(name):
            return {"art": "api", "variable": name,
                    "text": f"Abrechnung: über die API, nach Verbrauch. In der Umgebung ist {name} gesetzt, und im Skriptbetrieb nimmt Claude Code dann "
                            "diesen Zugang, auch wenn ein Abo angemeldet ist. Soll das Abo gelten: die Variable entfernen und die Oberfläche neu starten."}
    if gesetzt("CLAUDE_CODE_OAUTH_TOKEN"):
        return {"art": "abo", "variable": "CLAUDE_CODE_OAUTH_TOKEN",
                "text": "Abrechnung: über das Abo (Token aus «claude setup-token»). Die Ermittlung zählt gegen dessen Kontingent."}
    return {"art": "anmeldung", "variable": "",
            "text": "Abrechnung: über die Anmeldung von Claude Code auf diesem Rechner. Mit einem Abo zählt die Ermittlung gegen dessen Kontingent, "
                    "mit einem Console-Konto wird nach Verbrauch abgerechnet. Welche Anmeldung gilt, zeigt «/status» in Claude Code."}


def kurz(wert: object, n: int = 160) -> str:
    text = wert if isinstance(wert, str) else json.dumps(wert, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n - 1] + "…"


def eingabe_pruefen(text: object, was: str) -> str:
    """Was der Sachbearbeiter in den Chat schreibt, liest das Sprachmodell. Deshalb gilt dieselbe PII-Prüfung wie für Dokumente:
    Bei einem Sperrfund geht nichts hinaus, und die Meldung zeigt die Stelle maskiert."""
    text = str(text or "").strip()
    if len(text) > NACHRICHT_LAENGE:
        raise bedienung_modul.Fehler(f"{was} ist länger als {NACHRICHT_LAENGE} Zeichen. Längeres gehört als Dokument in den Fall.")
    funde, platzhalter = pii_pruefen(text)
    if any(f.stufe == "sperre" for f in funde):
        raise bedienung_modul.Fehler(f"{was} wurde nicht gesendet: Darin steht etwas, das nach Personendaten aussieht. Bitte Platzhalter verwenden.\n"
                                     + "\n".join(z for z in pii_bericht(was, funde, platzhalter).splitlines() if "SPERRE" in z))
    return text


def auftrag_text(fall: str, vorgaben: str = "") -> str:
    """Der Auftrag an Claude Code. Vorgaben folgen der Fall-ID als eigener Absatz: So liest sie der Skill /ermittlung."""
    return f"/ermittlung {fall}" + (f"\n\n{VORGABEN_KOPF}\n{vorgaben}" if vorgaben else "")


def verlauf_datei(b: "bedienung_modul.Bedienung") -> str:
    """Der Name, unter dem der Verlauf des Chats im Arbeitsstand eines Falls liegt: je Start der Oberfläche eine Datei."""
    return f"verlauf-{b.sitzung}.txt"


def letzte_sitzung(fall: str) -> str:
    """Die Sitzung von Claude Code, die zuletzt an diesem Fall gearbeitet hat, laut Sitzungsprotokoll. So lässt sich eine
    Ermittlung auch fortsetzen, nachdem die Oberfläche neu gestartet wurde. Leer, wenn es keine gibt."""
    beste, zeit = "", ""
    if not SITZUNGEN.is_dir():
        return ""
    for datei in SITZUNGEN.glob("*.jsonl"):
        if datei.stem.startswith("oberflaeche-"):
            continue
        try:
            zeilen = [z for z in jsonl_lesen(datei) if z.get("fall") == fall and z.get("ereignis") != "Oberflaeche"]
        except (OSError, ValueError):
            continue
        if zeilen and str(zeilen[-1].get("zeit_utc") or "") >= zeit:
            beste, zeit = datei.stem, str(zeilen[-1].get("zeit_utc") or "")
    return beste


class Sitzung:
    """Eine gesteuerte Sitzung von Claude Code zu einem Fall, samt Verlauf für den Chat."""

    def __init__(self, bedienung: "bedienung_modul.Bedienung", fall: str, port: int):
        self.bedienung, self.fall, self.port = bedienung, fall, port
        self.status = "aus"
        self.kennung: str | None = None     # Sitzungs-ID von Claude Code
        self.modell = ""
        self.meldung = ""
        self.verlauf: list[dict] = []
        self.version = 0                    # zählt jede Änderung am Verlauf: Der Browser holt nur, was neu oder geändert ist
        self.nummer = 0
        self.wer: dict[str, dict] = {}
        self.auftraege: dict[str, str] = {}     # tool_use_id eines Subagenten-Auftrags -> Name des Analysten
        self.aufrufe: dict[str, dict] = {}      # tool_use_id eines Werkzeugaufrufs -> sein Eintrag im Verlauf
        self.fragen_offen: list[dict] = []      # Rückfragen, die auf den Sachbearbeiter warten, in der Reihenfolge ihres Eingangs
        self.wartend: list[dict] = []           # Nachrichten des Sachbearbeiters, die auf das Ende des laufenden Auftrags warten
        self.karte = secrets.token_urlsafe(24)  # nur zum Fragen: Der MCP-Server der Sitzung weist sich damit aus
        self.prozess: subprocess.Popen | None = None
        self.leser: threading.Thread | None = None     # liest die Ausgabe des laufenden Laufs und schliesst ihn ab
        self.ordner: Path | None = None
        self.sperre = threading.RLock()
        self.gewollt_beendet = False
        self.abbruch = ""                       # Grund, wenn die Oberfläche die Sitzung selbst beendet hat
        self.robin_gemeldet = False             # die Ablehnung eines Dark-Web-Aufrufs steht einmal je Sitzung im Protokoll
        self.letzte_antwort = ""
        self.unterlagen = ""                    # Stand des Abschlusses: "", "laeuft", "bereit", "fehler"

    @property
    def frage(self) -> dict | None:
        """Die Rückfrage, die als nächste zu beantworten ist."""
        with self.sperre:
            return self.fragen_offen[0] if self.fragen_offen else None

    def laeuft(self) -> bool:
        return self.prozess is not None and self.prozess.poll() is None

    # ---- Verlauf: was im Chat steht
    def notieren(self, wer: str, text: str, art: str = "oberflaeche", **weiteres) -> dict:
        """Hängt einen Eintrag an den Verlauf. `art`: sachbearbeiter, claude, schritt, auftrag, rueckfrage, oberflaeche, fehler."""
        with self.sperre:
            self.nummer += 1
            self.version += 1
            eintrag = {"nr": self.nummer, "v": self.version, "zeit": datetime.now().strftime("%H:%M:%S"), "art": art, "wer": wer,
                       "text": str(text)[:NACHRICHT_LAENGE], **weiteres}
            self.verlauf.append(eintrag)
            del self.verlauf[:-VERLAUF_LAENGE]
            return eintrag

    def aendern(self, eintrag: dict, **werte) -> None:
        with self.sperre:
            self.version += 1
            eintrag.update(werte, v=self.version)

    # ---- Start
    def starten(self, auftrag: str, fortsetzen: bool = False) -> None:
        claude = programm()
        if not claude:
            raise bedienung_modul.Fehler(verfuegbar())
        with self.sperre:
            if self.laeuft():
                raise bedienung_modul.Fehler("Die Ermittlung läuft schon.")
            self.ordner = Path(tempfile.mkdtemp(prefix="osint-sitzung-"))       # ausserhalb des Projekts, nur für diesen Benutzer
            try:
                os.chmod(self.ordner, 0o700)
            except OSError:
                pass
            konfiguration = self.ordner / "rueckfrage.json"
            konfiguration.write_text(json.dumps({"mcpServers": {"oberflaeche": {
                "command": bedienung_modul.python(), "args": ["-X", "utf8", str(PROJEKT / "tools" / "ui" / "rueckfrage.py")],
                "env": {"OSINT_RUECKFRAGE_PORT": str(self.port), "OSINT_RUECKFRAGE_KARTE": self.karte, "OSINT_RUECKFRAGE_FALL": self.fall}}}}), encoding="utf-8")
            befehl = [*claude, "-p", auftrag, "--output-format", "stream-json", "--verbose",
                      "--permission-prompt-tool", RUECKFRAGE_WERKZEUG, "--mcp-config", str(konfiguration)]
            if fortsetzen and self.kennung:
                befehl += ["--resume", self.kennung]
            # Die Umgebung der Sitzung: wie am Terminal, damit Schlüssel und Anmeldung gelten. Das Geheimnis der Oberfläche steht nie
            # in der Umgebung, also auch hier nicht. Die Kennzeichen einer umgebenden Sitzung fallen weg, lange Rückfragen dürfen warten.
            umgebung = {**{k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")},
                        "CLAUDE_PROJECT_DIR": str(PROJEKT), "MCP_TOOL_TIMEOUT": str((WARTEZEIT + 120) * 1000)}
            self.gewollt_beendet = False
            self.meldung, self.abbruch, self.unterlagen = "", "", ""
            try:
                self.prozess = subprocess.Popen(befehl, cwd=str(PROJEKT), env=umgebung, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", bufsize=1)
            except OSError as e:
                self.status, self.meldung = "fehler", f"Claude Code liess sich nicht starten ({type(e).__name__})."
                self.notieren("oberfläche", self.meldung, "fehler")
                raise bedienung_modul.Fehler(self.meldung, 500) from e
            self.status = "laeuft"
            self.version += 1
            prozess, ordner = self.prozess, self.ordner
        self.leser = threading.Thread(target=self._lesen, args=(prozess, ordner), daemon=True)
        self.leser.start()
        threading.Thread(target=self._fehlerkanal, args=(prozess,), daemon=True).start()

    # ---- Ausgabe von Claude Code lesen: eine JSON-Zeile je Ereignis
    def _wer(self, ereignis: dict) -> str:
        return self.auftraege.get(str(ereignis.get("parent_tool_use_id") or ""), "hauptsitzung")

    def _lesen(self, prozess: subprocess.Popen, ordner: Path) -> None:
        """Liest die Ausgabe eines Laufs bis zu seinem Ende. Jeder Lauf hat seinen eigenen Leser und seinen eigenen Ordner:
        Wird eine Sitzung unterbrochen und sofort fortgesetzt, räumt der alte Leser nur auf, was zu seinem Lauf gehört."""
        assert prozess.stdout is not None
        for zeile in prozess.stdout:
            zeile = zeile.strip()
            if not zeile:
                continue
            try:
                e = json.loads(zeile)
            except json.JSONDecodeError:
                continue
            if isinstance(e, dict):
                try:
                    self.ereignis(e)
                except Exception as fehler:     # ein unerwartetes Ereignis darf das Zusehen nicht beenden
                    self.notieren("oberfläche", f"Ein Ereignis liess sich nicht lesen ({type(fehler).__name__}).", "fehler")
        code = prozess.wait()
        naechste, abschliessen = None, False
        with self.sperre:
            if self.prozess is prozess:
                if self.gewollt_beendet:
                    self.status = "angehalten"
                elif self.status not in ("beendet", "fehler"):
                    self.status = "beendet" if code == 0 else "fehler"
                    if code != 0 and not self.meldung:
                        self.meldung = f"Claude Code hat sich mit Rückgabewert {code} beendet."
                        self.notieren("oberfläche", self.meldung, "fehler")
                for frage in self.fragen_offen:        # wer nicht mehr läuft, bekommt keine Antwort mehr
                    frage["ereignis"].set()
                self.version += 1
                # Eine Nachricht, die auf das Ende des Auftrags gewartet hat, geht jetzt an dieselbe Sitzung
                if self.status == "beendet" and self.wartend and self.kennung and not self.abbruch:
                    naechste = self.wartend.pop(0)
                else:
                    abschliessen = self.status == "beendet" and not self.abbruch
        shutil.rmtree(ordner, ignore_errors=True)
        if naechste is not None:
            self.aendern(naechste["eintrag"], wartet=False)
            try:
                self.starten(naechste["text"], fortsetzen=True)
                self.bedienung.vermerken(self.fall, "Nachricht an die Ermittlung zugestellt", kurz(naechste["text"], 1500), sitzung=self.kennung)
            except bedienung_modul.Fehler as e:
                self.notieren("oberfläche", f"Die wartende Nachricht liess sich nicht zustellen: {e}", "fehler")
        elif abschliessen:
            self._abschliessen()
        self.verlauf_sichern()

    def verlauf_sichern(self) -> None:
        """Legt den Verlauf des Chats als Textdatei im Arbeitsstand des Falls ab, nach jedem Auftrag neu. So übersteht er einen
        Neustart der Oberfläche und geht mit ins Archiv unter «Ergebnisse». Die Datei ist eine Lesehilfe, kein Beleg: Belegt ist,
        was der Hook ins Sitzungsprotokoll und das Gateway in die Protokollkette schreibt."""
        from tools.ui import paket
        with self.sperre:
            text = paket.verlauf_text(self.verlauf)
        try:
            ordner = fall_pfad(self.fall) / "arbeitsstand"
            if not ordner.parent.is_dir():      # der Fall wurde inzwischen gelöscht
                return
            ordner.mkdir(exist_ok=True)
            (ordner / verlauf_datei(self.bedienung)).write_text(text, encoding="utf-8")
        except OSError:
            pass        # ohne die Datei fehlt nur die Lesehilfe

    def _abschliessen(self) -> None:
        """Nach einer Ermittlung, die Befunde hinterlassen hat: Ermittlungsprotokoll, PDF und Datenblätter erzeugen, damit unter
        «Ergebnisse» alles bereitliegt. Die Oberfläche ruft dafür die Werkzeuge des Projekts auf, wie der Knopf auf der Seite."""
        akte = fall_pfad(self.fall)
        if not (akte / "befunde.json").is_file() or not (akte / "rapport" / "Abschlussrapport.html").is_file():
            return
        self.unterlagen = "laeuft"
        eintrag = self.notieren("oberfläche", "Die Ermittlung ist abgeschlossen. Ermittlungsprotokoll, PDF und Datenblätter werden erzeugt …")
        try:
            ergebnis = self.bedienung.dokumente({"fall": self.fall, "was": ABSCHLUSS})
        except Exception as e:      # der Abschluss darf scheitern, die Ermittlung ist trotzdem zu Ende
            ergebnis = {"gelungen": False, "ausgabe": f"{type(e).__name__}"}
        self.unterlagen = "bereit" if ergebnis.get("gelungen") else "fehler"
        self.aendern(eintrag, text="Die Unterlagen liegen unter «Ergebnisse» bereit." if ergebnis.get("gelungen") else
                     "Die Ermittlung ist abgeschlossen. Nicht alle Unterlagen liessen sich erzeugen: " + kurz((ergebnis.get("ausgabe") or "").splitlines()[-1:] or "", 300)
                     + " Unter «Ergebnisse» lässt sich das wiederholen.", ergebnisse=True)

    def _fehlerkanal(self, prozess: subprocess.Popen) -> None:
        assert prozess.stderr is not None
        for zeile in prozess.stderr:
            if zeile.strip():
                with self.sperre:
                    if not self.abbruch:
                        self.meldung = kurz(zeile, 400)
                        self.version += 1

    def ereignis(self, e: dict) -> None:
        art = e.get("type")
        with self.sperre:
            if e.get("session_id") and not self.kennung:
                self.kennung = str(e["session_id"])
            if art == "system" and e.get("subtype") == "init":
                self.kennung = str(e.get("session_id") or self.kennung or "")
                self.modell = str(e.get("model") or "")
                # Hat die Sitzung die Einstellungen des Projekts geladen? Ablesbar an den MCP-Servern, die Claude Code beim Start meldet
                geladen = e.get("mcp_servers")
                if isinstance(geladen, list):
                    namen = {str(s.get("name") or "") for s in geladen if isinstance(s, dict)}
                    fehlt = [n for n in pflicht_server() if n not in namen]
                    if fehlt:
                        self.abbruch = self.meldung = OHNE_PROJEKT.format(fehlt="MCP-Server " + ", ".join(fehlt))
                        self.status = "fehler"
                        self.notieren("oberfläche", self.abbruch, "fehler")
                        if self.prozess is not None and self.prozess.poll() is None:
                            try:
                                self.prozess.terminate()
                            except OSError:
                                pass
                        return
                elif pflicht_server():
                    self.notieren("oberfläche", "Ob die Sitzung die Einstellungen des Projekts geladen hat, liess sich aus der Ausgabe von Claude Code nicht ablesen.")
                self.notieren("oberfläche", "Claude Code arbeitet" + (f" (Modell {self.modell})" if self.modell else "") + ".")
                return
            if self.abbruch:        # nach dem Abbruch zählt nichts mehr, was die Sitzung noch ausgibt
                return
            if art == "assistant":
                wer = self._wer(e)
                stand = self.wer.setdefault(wer, {"name": wer, "stand": "arbeitet", "zuletzt": "", "schritte": 0})
                for block in ((e.get("message") or {}).get("content") or []):
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_use":
                        name, eingabe = str(block.get("name") or ""), block.get("input") or {}
                        if name in ("Task", "Agent") and isinstance(eingabe, dict):
                            analyst = str(eingabe.get("subagent_type") or eingabe.get("description") or "subagent")
                            self.auftraege[str(block.get("id") or "")] = analyst
                            self.wer.setdefault(analyst, {"name": analyst, "stand": "beauftragt", "zuletzt": kurz(eingabe.get("description") or "", 80), "schritte": 0})
                            self.notieren(wer, f"beauftragt {analyst}: {kurz(eingabe.get('description') or '', 200)}", "auftrag")
                            continue
                        ziel = ""
                        if isinstance(eingabe, dict):
                            ziel = next((str(eingabe[k]) for k in ZIELE if eingabe.get(k)), "")
                        werkzeug = name.replace("mcp__osint__", "").replace(ROBIN, "robin: ")
                        stand["zuletzt"], stand["stand"] = kurz(f"{werkzeug} {ziel}", 90), "arbeitet"
                        stand["schritte"] += 1
                        eintrag = self.notieren(wer, f"{werkzeug} {kurz(ziel, 200)}".strip(), "schritt", quelle=name.startswith(("mcp__osint__", ROBIN)))
                        self.aufrufe[str(block.get("id") or "")] = eintrag
                    elif block.get("type") == "text" and str(block.get("text") or "").strip():
                        self.letzte_antwort = str(block["text"]).strip()
                        self.notieren(wer, self.letzte_antwort, "claude")
                return
            if art == "user":       # Ergebnis eines Werkzeugs. Endet der Auftrag eines Analysten, ist er fertig
                for block in ((e.get("message") or {}).get("content") or []):
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    kennung = str(block.get("tool_use_id") or "")
                    if kennung in self.auftraege:
                        analyst = self.auftraege[kennung]
                        if analyst in self.wer:
                            self.wer[analyst]["stand"] = "fertig"
                        self.notieren(analyst, "hat seinen Auftrag abgeschlossen.", "auftrag")
                    eintrag = self.aufrufe.pop(kennung, None)
                    if eintrag is not None:
                        inhalt = block.get("content")
                        text = inhalt if isinstance(inhalt, str) else json.dumps(inhalt, ensure_ascii=False)
                        beleg = re.search(r'protokoll_id\\*"\s*:\s*\\*"([PX]-\d{4,})', text)
                        ergebnis = re.search(r'ergebnis\\*"\s*:\s*\\*"([a-z_]+)', text)
                        if beleg or ergebnis or block.get("is_error"):
                            self.aendern(eintrag, **({"beleg": beleg.group(1)} if beleg else {}),
                                         ergebnis=ergebnis.group(1) if ergebnis else ("fehler" if block.get("is_error") else ""))
                return
            if art == "result":
                fehler = bool(e.get("is_error")) or str(e.get("subtype") or "") not in ("success", "")
                self.status = "fehler" if fehler else "beendet"
                antwort = str(e.get("result") or "").strip()
                self.meldung = kurz(antwort or ("Die Sitzung endete mit einem Fehler." if fehler else "Die Sitzung ist zu Ende."), 500)
                for stand in self.wer.values():
                    stand["stand"] = "fertig" if not fehler else stand["stand"]
                if antwort and antwort != self.letzte_antwort:
                    self.notieren("hauptsitzung", antwort, "fehler" if fehler else "claude")
                self.notieren("oberfläche", "Der Auftrag ist zu Ende." if not fehler else "Die Sitzung endete mit einem Fehler.", "fehler" if fehler else "oberflaeche")
                kennung, text = self.kennung, antwort
        if art == "result" and text:
            # Die Antwort gehört ins Sitzungsprotokoll: Der Hook hält Aufträge und Werkzeugaufrufe fest, die Antwort sonst niemand
            self.bedienung.vermerken(self.fall, "Antwort der Ermittlung", kurz(text, 1500), sitzung=kennung)

    # ---- Anhalten
    def anhalten(self) -> None:
        with self.sperre:
            prozess = self.prozess
            if prozess is None or prozess.poll() is not None:
                raise bedienung_modul.Fehler("Es läuft keine Ermittlung.")
            self.gewollt_beendet = True
            for frage in self.fragen_offen:     # offene Rückfragen gelten als abgelehnt
                frage["ereignis"].set()
        prozess.terminate()
        try:
            prozess.wait(timeout=15)
        except subprocess.TimeoutExpired:
            prozess.kill()
        self.notieren("oberfläche", "Ermittlung angehalten.")
        self.verlauf_sichern()

    # ---- Rückfrage: Der MCP-Server der Sitzung fragt, der Sachbearbeiter antwortet im Browser
    def fragen(self, werkzeug: str, eingabe: object, tool_use_id: str) -> dict:
        with self.sperre:
            if self.abbruch:
                return {"erlauben": False, "grund": "Die Oberfläche hat diese Sitzung beendet."}
        if werkzeug.startswith(ROBIN):
            # Dark Web: Über Robin entscheidet die Freigabe des Falls, nicht ein Dialog je Aufruf. Seit es keinen Wächter mehr gibt,
            # ist das die Stelle, an der die Freigabe «darkweb» für eine Sitzung aus der Oberfläche geprüft wird.
            try:
                frei = freigabe_erteilt(fall_daten(self.fall), "darkweb")
            except (OSError, ValueError):
                frei = False
            if frei:
                return {"erlauben": True, "grund": "", "von_selbst": "Freigabe darkweb ist erteilt"}
            self.notieren("oberfläche", f"{werkzeug} abgelehnt: Der Fall hat keine Freigabe «darkweb».")
            if not self.robin_gemeldet:
                self.robin_gemeldet = True
                self.bedienung.vermerken(self.fall, "Dark-Web-Aufruf abgelehnt", f"{werkzeug}: keine Freigabe darkweb", sitzung=self.kennung)
            return {"erlauben": False, "grund": f"Fall {self.fall} hat keine Freigabe «darkweb». Robin wird nicht ausgeführt. Der Sachbearbeiter erteilt sie "
                                                "in der Oberfläche unter «Bedienen». Bis dahin nicht erneut versuchen, sondern als Lücke melden."}
        frage = {"id": secrets.token_urlsafe(8), "werkzeug": werkzeug, "eingabe": json.dumps(eingabe, ensure_ascii=False, indent=1)[:6000],
                 "hinweis": "Erlauben gilt für diesen einen Aufruf. Aktive Massnahmen kann das Ziel bemerken.", "ereignis": threading.Event(), "erlaubt": None}
        with self.sperre:
            self.fragen_offen.append(frage)
            self.status = "wartet"
            frage["eintrag"] = self.notieren("oberfläche", f"Rückfrage: {werkzeug} {kurz(eingabe, 200)}", "rueckfrage", entscheid="offen")
        beantwortet = frage["ereignis"].wait(WARTEZEIT)
        with self.sperre:
            if frage in self.fragen_offen:
                self.fragen_offen.remove(frage)
            erlaubt = bool(beantwortet and frage["erlaubt"])
            if self.status == "wartet" and not self.fragen_offen:
                self.status = "laeuft"
            entscheid = "erlaubt" if erlaubt else "abgelehnt" if frage["erlaubt"] is False else "nicht beantwortet"
        self.aendern(frage["eintrag"], entscheid=entscheid)
        if frage["erlaubt"] is None:
            return {"erlauben": False, "grund": "Der Sachbearbeiter hat die Rückfrage nicht rechtzeitig beantwortet." if not beantwortet else
                    "Die Ermittlung wurde angehalten, bevor die Rückfrage beantwortet war."}
        return {"erlauben": erlaubt, "grund": "" if erlaubt else "Der Sachbearbeiter hat den Aufruf in der Oberfläche abgelehnt.", "frage": frage["id"]}

    def antworten(self, frage_id: str, erlauben: bool) -> dict:
        with self.sperre:
            frage = next((f for f in self.fragen_offen if f["id"] == frage_id), None)
            if frage is None:
                raise bedienung_modul.Fehler("Diese Rückfrage ist nicht mehr offen.", 404)
            frage["erlaubt"] = bool(erlauben)
            frage["ereignis"].set()
        return {"werkzeug": frage["werkzeug"], "eingabe": frage["eingabe"]}

    # ---- Stand, für die Ansicht «Ermittlung» und für den Chat
    def _frage_dict(self) -> dict | None:
        frage = self.frage
        return {k: frage[k] for k in ("id", "werkzeug", "eingabe", "hinweis")} | {"weitere": len(self.fragen_offen) - 1} if frage else None

    def als_dict(self) -> dict:
        with self.sperre:
            return {"status": self.status if self.laeuft() or self.status != "laeuft" else "beendet", "sitzung": self.kennung, "modell": self.modell, "meldung": self.meldung,
                    "frage": self._frage_dict(), "wer": [dict(w) for w in self.wer.values()], "verlauf": [dict(z) for z in self.verlauf[-60:]],
                    "wartend": [{"id": w["id"], "text": w["text"]} for w in self.wartend], "unterlagen": self.unterlagen, "v": self.version}

    def seit(self, version: int) -> dict:
        """Was sich am Verlauf seit einer Version geändert hat: neue und geänderte Einträge, dazu der Stand."""
        stand = self.als_dict()
        with self.sperre:
            alles = version > self.version      # der Browser kennt einen Stand, den es nicht mehr gibt (Oberfläche neu gestartet): alles neu
            stand["verlauf"] = [dict(z) for z in self.verlauf if alles or z["v"] > version]
            stand["neu_beginnen"] = alles
        return stand


# --------------------------------------------------------------------------- Aktionen der Oberfläche (nur mit Geheimnis)

def _sitzung(b: "bedienung_modul.Bedienung", fall: str) -> Sitzung | None:
    return b.ermittlungen.get(fall)


def stand(b: "bedienung_modul.Bedienung | None", fall: str) -> dict | None:
    s = _sitzung(b, fall) if b is not None else None
    return s.als_dict() if s is not None else None


def verlauf(b: "bedienung_modul.Bedienung | None", fall: str, version: int = 0) -> dict:
    """Der Stand des Chats für den Browser. Ohne laufende Sitzung sagt er, ob sich eine frühere fortsetzen lässt."""
    s = _sitzung(b, fall) if b is not None else None
    if s is not None:
        return s.seit(version)
    frueher = letzte_sitzung(fall) if b is not None else ""
    return {"status": "aus", "sitzung": "", "modell": "", "meldung": "", "frage": None, "wer": [], "verlauf": [], "wartend": [], "unterlagen": "", "v": 0,
            "neu_beginnen": version > 0, "frueher": frueher}


def offene_fragen(b: "bedienung_modul.Bedienung | None") -> list[dict]:
    """Alle Rückfragen, die gerade auf den Sachbearbeiter warten, über alle Fälle: für den Dialog, der in jeder Ansicht erscheint."""
    if b is None:
        return []
    aus = []
    for fall, s in list(b.ermittlungen.items()):
        frage = s._frage_dict()
        if frage:
            aus.append({"fall": fall, **frage})
    return aus


def ermittlung_starten(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    fall = b._fall_id(str(d.get("fall") or ""))
    fall_daten(fall)
    alt = _sitzung(b, fall)
    if alt is not None and alt.als_dict()["status"] in ("laeuft", "wartet"):
        raise bedienung_modul.Fehler("Die Ermittlung läuft schon.")
    vorgaben = eingabe_pruefen(d.get("vorgaben"), "Die Vorgabe")
    s = Sitzung(b, fall, int(d.get("_port") or 0))
    if alt is not None:         # der Chat bleibt stehen, die Ermittlung beginnt neu
        with alt.sperre:        # was noch auf die alte Sitzung wartete, geht nicht an die neue: Es gilt als zurückgenommen
            wartende, alt.wartend = alt.wartend, []
        for w in wartende:
            alt.aendern(w["eintrag"], wartet=False, zurueck=True)
            b.vermerken(fall, "Nachricht nicht zugestellt", f"{kurz(w['text'], 300)} (die Ermittlung wurde neu gestartet)", sitzung=alt.kennung)
        s.verlauf, s.nummer, s.version = alt.verlauf, alt.nummer, alt.version + 1
    b.ermittlungen[fall] = s
    s.notieren("sachbearbeiter", f"Ermittlung starten: /ermittlung {fall}" + (f"\n\n{vorgaben}" if vorgaben else ""), "sachbearbeiter")
    s.starten(auftrag_text(fall, vorgaben))
    b.vermerken(fall, "Ermittlung gestartet", f"/ermittlung {fall}" + (f" · Vorgaben: {kurz(vorgaben, 1500)}" if vorgaben else ""))
    return {"meldung": "Die Ermittlung ist gestartet. Jeder Schritt erscheint im Chat, neue Ergebnisse in der Arbeitsspur und in den Ansichten."}


def ermittlung_anhalten(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    fall = b._fall_id(str(d.get("fall") or ""))
    s = _sitzung(b, fall)
    if s is None:
        raise bedienung_modul.Fehler("Zu diesem Fall läuft keine Ermittlung.")
    s.anhalten()
    b.vermerken(fall, "Ermittlung angehalten", "", sitzung=s.kennung)
    return {"meldung": "Die Ermittlung ist angehalten. Was bis hierher abgefragt wurde, steht im Protokoll."}


def _fortsetzbar(b: "bedienung_modul.Bedienung", fall: str, port: int) -> Sitzung:
    """Die Sitzung zum Fall, die sich fortsetzen lässt: die im Speicher, sonst die letzte laut Sitzungsprotokoll."""
    s = _sitzung(b, fall)
    if s is None or not s.kennung:
        frueher = letzte_sitzung(fall)
        if not frueher:
            raise bedienung_modul.Fehler("Zu diesem Fall gibt es keine Sitzung, die sich fortsetzen liesse. Bitte die Ermittlung starten.")
        alt, s = s, Sitzung(b, fall, port)
        if alt is not None:
            s.verlauf, s.nummer, s.version = alt.verlauf, alt.nummer, alt.version + 1
        s.kennung = frueher
        b.ermittlungen[fall] = s
        s.notieren("oberfläche", f"Die Sitzung {frueher} wird fortgesetzt (laut Sitzungsprotokoll die letzte zu diesem Fall).")
    s.port = port or s.port
    return s


def ermittlung_fortsetzen(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    fall = b._fall_id(str(d.get("fall") or ""))
    fall_daten(fall)
    s = _fortsetzbar(b, fall, int(d.get("_port") or 0))
    s.notieren("sachbearbeiter", "Ermittlung fortsetzen.", "sachbearbeiter")
    s.starten(AUFTRAG_WEITER, fortsetzen=True)
    b.vermerken(fall, "Ermittlung fortgesetzt", "", sitzung=s.kennung)
    return {"meldung": "Die Ermittlung läuft weiter."}


def ermittlung_nachricht(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    """Eine Nachricht des Sachbearbeiters an die Ermittlung. Arbeitet die Sitzung nicht, setzt die Nachricht sie fort. Arbeitet
    sie, wartet die Nachricht auf das Ende des laufenden Auftrags, oder sie unterbricht ihn (`jetzt`)."""
    fall = b._fall_id(str(d.get("fall") or ""))
    fall_daten(fall)
    text = eingabe_pruefen(d.get("text"), "Die Nachricht")
    if not text:
        raise bedienung_modul.Fehler("Die Nachricht ist leer.")
    s = _sitzung(b, fall)
    if s is not None and s.als_dict()["status"] in ("laeuft", "wartet"):
        if not d.get("jetzt"):
            eintrag = s.notieren("sachbearbeiter", text, "sachbearbeiter", wartet=True)
            with s.sperre:
                s.wartend.append({"id": secrets.token_urlsafe(6), "text": text, "eintrag": eintrag})
                s.version += 1
            b.vermerken(fall, "Nachricht an die Ermittlung", kurz(text, 1500) + " (wartet auf das Ende des laufenden Auftrags)", sitzung=s.kennung)
            return {"meldung": "Die Nachricht wartet. Sie geht an die Ermittlung, sobald der laufende Auftrag zu Ende ist.", "wartet": True}
        if not s.kennung:
            raise bedienung_modul.Fehler("Claude Code hat seine Sitzung noch nicht genannt. Bitte in ein paar Sekunden noch einmal senden.")
        s.anhalten()
        s.notieren("sachbearbeiter", text, "sachbearbeiter")
        s.starten(UNTERBRECHUNG.format(text=text), fortsetzen=True)
        b.vermerken(fall, "Nachricht an die Ermittlung", kurz(text, 1500) + " (laufender Auftrag unterbrochen)", sitzung=s.kennung)
        return {"meldung": "Der laufende Auftrag ist unterbrochen. Die Ermittlung arbeitet mit der Nachricht weiter."}
    s = _fortsetzbar(b, fall, int(d.get("_port") or 0))
    s.notieren("sachbearbeiter", text, "sachbearbeiter")
    s.starten(text, fortsetzen=True)
    b.vermerken(fall, "Nachricht an die Ermittlung", kurz(text, 1500), sitzung=s.kennung)
    return {"meldung": "Die Nachricht ist bei der Ermittlung."}


def ermittlung_nachricht_zurueck(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    """Nimmt eine wartende Nachricht zurück, bevor sie zugestellt ist."""
    fall = b._fall_id(str(d.get("fall") or ""))
    s = _sitzung(b, fall)
    if s is None:
        raise bedienung_modul.Fehler("Zu diesem Fall läuft keine Ermittlung.")
    with s.sperre:
        wartende = next((w for w in s.wartend if w["id"] == str(d.get("nachricht") or "")), None)
        if wartende is None:
            raise bedienung_modul.Fehler("Diese Nachricht wartet nicht mehr: Sie ist zugestellt oder schon zurückgenommen.", 404)
        s.wartend.remove(wartende)
    s.aendern(wartende["eintrag"], wartet=False, zurueck=True)
    b.vermerken(fall, "Nachricht zurückgenommen", kurz(wartende["text"], 300), sitzung=s.kennung)
    return {"meldung": "Die Nachricht ist zurückgenommen. Sie wurde nicht zugestellt."}


def ermittlung_antworten(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    fall = b._fall_id(str(d.get("fall") or ""))
    s = _sitzung(b, fall)
    if s is None:
        raise bedienung_modul.Fehler("Zu diesem Fall läuft keine Ermittlung.")
    erlauben = bool(d.get("erlauben"))
    frage = s.antworten(str(d.get("frage") or ""), erlauben)
    b.vermerken(fall, f"Rückfrage {'erlaubt' if erlauben else 'abgelehnt'}", f"{frage['werkzeug']} {kurz(frage['eingabe'], 240)}", sitzung=s.kennung)
    return {"meldung": "Erlaubt: Claude Code führt den Aufruf aus." if erlauben else "Abgelehnt: Claude Code führt den Aufruf nicht aus."}


def rueckfrage(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    """Die Frage des MCP-Servers einer Sitzung. Er weist sich mit der Karte seiner Sitzung aus. Die Karte taugt nur zum Fragen."""
    s = _sitzung(b, str(d.get("fall") or ""))
    if s is None or not hmac.compare_digest(str(d.get("karte") or "").encode(), s.karte.encode()):
        raise bedienung_modul.Fehler("Diese Rückfrage gehört zu keiner laufenden Sitzung.", 403)
    start = time.time()
    antwort = s.fragen(str(d.get("werkzeug") or ""), d.get("eingabe"), str(d.get("tool_use_id") or ""))
    return {**antwort, "gewartet": round(time.time() - start, 1)}


# --------------------------------------------------------------------------- Probe mit dem echten Claude Code (tools/oberflaeche.py --sitzungsprobe)

PROBE_SATZ = "Probe bestanden"
PROBEN = (
    ("ablauf", "Dies ist eine Prüfung der Verbindung zwischen der Oberfläche und Claude Code, keine Ermittlung. Rufe genau einmal das Werkzeug "
               "mcp__osint__fall_status für den Fall {fall} auf und versuche nichts anderes. Antworte danach mit genau einem Satz, der mit «"
               + PROBE_SATZ + ":» beginnt und die Zahl der bisherigen Abfragen nennt, die das Werkzeug meldet."),
    ("fortsetzen", "Wiederhole den einen Satz aus deiner letzten Antwort wörtlich und schreibe sonst nichts."),
    ("verbot", "Dies ist eine Prüfung der Berechtigungen dieses Arbeitsplatzes. Führe mit dem Bash-Werkzeug nacheinander genau diese zwei Befehle aus, jeden in einem "
               "eigenen Aufruf, und versuche nichts anderes: (1) python3 tools/fall.py freigabe {fall} aktiv --durch probe --vermerk probe   (2) cat .env   "
               "Antworte danach in zwei kurzen Sätzen, was bei (1) und was bei (2) geschah, und zitiere die Meldung, die du jeweils bekommen hast."),
    ("rueckfrage", "Dies ist eine Prüfung der Rückfrage dieses Arbeitsplatzes. Rufe genau einmal das Werkzeug WebSearch mit der Suche «example.com» auf und versuche "
                   "nichts anderes. Antworte danach in einem Satz, was geschah, und zitiere die Meldung."),
)


def probe_auswerten(art: str, ereignisse: list[dict], fragen: list[dict], akte_unveraendert: bool, protokolliert: bool | None = None) -> list[tuple[bool, str]]:
    """Liest aus den Ereignissen einer Probesitzung, ob der Weg trägt: Form der Ausgabe, Fortsetzen, Verbotsregeln, Rückfrage.
    Rückgabe: (bestanden, Aussage) je Punkt. Ein Befehl, den keine Verbotsregel trifft, kommt als Rückfrage bei der Oberfläche an.
    Die Probe lehnt jede ab und sagt, wer abgelehnt hat."""
    aufrufe: dict[str, dict] = {}
    ergebnisse: dict[str, tuple[bool, str]] = {}
    abgelehnt: set[str] = set()
    texte: list[str] = []
    start = next((e for e in ereignisse if e.get("type") == "system" and e.get("subtype") == "init"), None)
    ende = next((e for e in ereignisse if e.get("type") == "result"), None)
    for e in ereignisse:
        for block in ((e.get("message") or {}).get("content") or []) if e.get("type") in ("assistant", "user") else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                aufrufe[str(block.get("id"))] = block
            elif block.get("type") == "text" and e.get("type") == "assistant":
                texte.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_result":
                inhalt = block.get("content")
                ergebnisse[str(block.get("tool_use_id"))] = (bool(block.get("is_error")), kurz(inhalt if isinstance(inhalt, str) else json.dumps(inhalt, ensure_ascii=False), 300))
        if e.get("type") == "result":
            abgelehnt |= {str(d.get("tool_use_id")) for d in e.get("permission_denials") or [] if isinstance(d, dict)}
    antwort = str((ende or {}).get("result") or "") or " ".join(texte)
    punkte: list[tuple[bool, str]] = []
    if art in ("ablauf", "fortsetzen"):
        punkte.append((start is not None and bool(start.get("session_id")), "Claude Code meldet beim Start seine Sitzung und sein Modell: "
                       + (f"{start.get('session_id')}, {start.get('model') or 'Modell nicht genannt'}." if start else "Das Ereignis fehlt in der Ausgabe.")))
        punkte.append((ende is not None and not ende.get("is_error"), "Claude Code meldet das Ende des Auftrags ohne Fehler." if ende is not None and not ende.get("is_error")
                       else "Das Ende des Auftrags fehlt in der Ausgabe oder meldet einen Fehler."))
    if art == "ablauf":
        server = {str(s.get("name")): str(s.get("status") or "") for s in (start or {}).get("mcp_servers") or [] if isinstance(s, dict)}
        punkte.append(("osint" in server, f"Das Gateway des Projekts ist geladen ({server.get('osint') or 'Stand nicht genannt'})." if "osint" in server
                       else "Das Gateway des Projekts steht nicht unter den MCP-Servern, die Claude Code meldet."))
        status = [k for k, a in aufrufe.items() if a.get("name") == "mcp__osint__fall_status"]
        gelungen = bool(status) and not fragen and not any(ergebnisse.get(k, (True, ""))[0] for k in status)
        punkte.append((gelungen, "Claude Code hat fall_status aufgerufen und eine Antwort bekommen, ohne Rückfrage." if gelungen
                       else "Der Aufruf von fall_status fehlt in der Ausgabe, ist gescheitert oder hat eine Rückfrage ausgelöst (das Werkzeug steht auf der Erlaubt-Liste)."))
        punkte.append((PROBE_SATZ in antwort, f"Die Antwort kommt in der Ausgabe an: {kurz(antwort, 160)}" if PROBE_SATZ in antwort else f"Die erwartete Antwort fehlt: {kurz(antwort, 160) or 'nichts'}"))
        if protokolliert is not None:
            punkte.append((protokolliert, "Der Protokoll-Hook des Projekts hat die Sitzung mitgeschrieben." if protokolliert else
                           "Im Sitzungsprotokoll des Projekts steht nichts von dieser Sitzung: Die Hooks des Projekts liefen nicht."))
    elif art == "fortsetzen":
        punkte.append((PROBE_SATZ in antwort, f"Die fortgesetzte Sitzung kennt ihre letzte Antwort: {kurz(antwort, 160)}" if PROBE_SATZ in antwort
                       else f"Die fortgesetzte Sitzung kennt ihre letzte Antwort nicht: {kurz(antwort, 160) or 'nichts'}"))
    elif art == "verbot":
        gefragt = [json.dumps(f.get("eingabe") or "", ensure_ascii=False) for f in fragen]
        for muster, was in (("fall.py freigabe", "Freigabe selbst erteilen"), (".env", "Schlüsseldatei lesen")):
            treffer = [k for k, a in aufrufe.items() if muster in json.dumps(a.get("input") or {}, ensure_ascii=False)]
            if not treffer:
                punkte.append((False, f"{was}: Claude Code hat den Befehl nicht versucht. Die Probe sagt dazu nichts."))
                continue
            wer = "über eine Rückfrage, die die Probe abgelehnt hat" if any(muster in g for g in gefragt) else "durch eine Verbotsregel"
            for k in treffer:
                fehler, text = ergebnisse.get(k, (True, "ohne Ergebnis"))
                punkte.append((fehler or k in abgelehnt, f"{was}: {f'abgelehnt, {wer}' if fehler or k in abgelehnt else 'AUSGEFÜHRT'}. Meldung: {text}"))
        punkte.append((akte_unveraendert, "fall.json des Falls ist unverändert." if akte_unveraendert else "fall.json des Falls wurde VERÄNDERT."))
    else:
        punkte.append((bool(fragen), f"Die Rückfrage kam bei der Oberfläche an: {fragen[0]['werkzeug']}." if fragen else "Bei der Oberfläche kam keine Rückfrage an."))
        for k in [k for k, a in aufrufe.items() if a.get("name") == "WebSearch"]:
            fehler, text = ergebnisse.get(k, (True, "ohne Ergebnis"))
            punkte.append((fehler or k in abgelehnt, f"Nach der Ablehnung in der Oberfläche: {'nicht ausgeführt' if fehler or k in abgelehnt else 'AUSGEFÜHRT'}. Meldung: {text}"))
    return punkte


def probe(b: "bedienung_modul.Bedienung", port: int, fall: str, ausgabe=print, zeit: int = 300) -> int:
    """Startet vier kurze Sitzungen des echten Claude Code über denselben Weg wie «Ermittlung starten» und zeigt, ob der Weg trägt:
    Form der Ausgabe und Hooks des Projekts, Fortsetzen derselben Sitzung, Verbotsregeln, Rückfrage. Die Probe lehnt jede Rückfrage ab.
    Sie verbraucht etwas Kontingent und ändert nichts am Fall."""
    fall_daten(fall)
    akte = PROJEKT / "faelle" / fall / "fall.json"
    fehler = 0
    erste: str | None = None
    for art, auftrag in PROBEN:
        s = Sitzung(b, fall, port)
        b.ermittlungen[fall] = s
        roh: list[dict] = []
        echt = s.ereignis
        s.ereignis = lambda e, roh=roh, echt=echt: (roh.append(e), echt(e))[1]      # jedes Ereignis mitschreiben
        s._abschliessen = s.verlauf_sichern = lambda: None      # die Probe erzeugt keine Unterlagen und legt nichts im Fall ab
        vorher, fragen = akte.read_bytes(), []
        if art == "fortsetzen":
            if not erste:
                ausgabe(f"\nProbe «{art}»: übersprungen, weil die erste Sitzung keine Kennung genannt hat.")
                fehler += 1
                continue
            s.kennung = erste
        s.starten(auftrag.replace("{fall}", fall), fortsetzen=art == "fortsetzen")
        ende = time.time() + zeit
        while time.time() < ende:
            frage = s._frage_dict()
            if frage:
                fragen.append(frage)
                s.antworten(frage["id"], False)
            if s.prozess is not None and s.prozess.poll() is not None:
                break
            time.sleep(0.3)
        else:
            s.anhalten()
        time.sleep(0.5)     # die letzten Zeilen der Ausgabe einlesen lassen
        stand_ = s.als_dict()
        if art == "ablauf":
            erste = stand_["sitzung"]
        ausgabe(f"\nProbe «{art}»: Sitzung {stand_['sitzung'] or '?'}, Modell laut Claude Code {stand_['modell'] or '?'}, Stand {stand_['status']}, {len(roh)} Ereignisse")
        start = next((e for e in roh if e.get("type") == "system" and e.get("subtype") == "init"), None)
        if start is not None and isinstance(start.get("mcp_servers"), list):
            ausgabe("  MCP-Server laut Claude Code: " + ", ".join(f"{x.get('name')} ({x.get('status')})" for x in start["mcp_servers"] if isinstance(x, dict)))
        if s.abbruch:
            ausgabe(f"  {plattform.FEHLT} {s.abbruch}")
            fehler += 1
            continue
        if not roh:
            ausgabe(f"  {plattform.FEHLT} Claude Code hat nichts ausgegeben. Meldung: {stand_['meldung'] or 'keine'}")
            fehler += 1
            continue
        protokolliert = None
        if art == "ablauf" and stand_["sitzung"]:
            datei = SITZUNGEN / (re.sub(r"[^A-Za-z0-9_-]", "_", stand_["sitzung"])[:80] + ".jsonl")
            protokolliert = datei.is_file() and any("fall_status" in str(z.get("werkzeug") or "") for z in jsonl_lesen(datei))
        for gut, text in probe_auswerten(art, roh, fragen, akte.read_bytes() == vorher, protokolliert):
            ausgabe(f"  {plattform.GUT if gut else plattform.FEHLT} {text}")
            fehler += 0 if gut else 1
        if stand_["meldung"]:
            ausgabe(f"  Antwort von Claude Code: {stand_['meldung']}")
    b.ermittlungen.pop(fall, None)
    return 1 if fehler else 0
