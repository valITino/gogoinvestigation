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
  - Der Dialog sagt in Worten, was Claude Code tun will und warum es fragt (tools/ui/worte.py). Stellt die Ermittlung dem
    Sachbearbeiter eine Frage (Werkzeug AskUserQuestion), kommt sie auf demselben Weg an und lässt sich im Dialog beantworten:
    mit einer Auswahl oder einer eigenen Antwort. Die Antwort geht als «answers» in der Eingabe des Werkzeugs zurück.
  - Fragt Claude Code bei einem Werkzeug, das beim Namen auf der Erlaubt-Liste des Projekts steht, wendet es die Liste nicht
    an (es vertraut dem Projektordner noch nicht). Die Oberfläche sagt das und bietet an, für den Rest dieser Ermittlung bei
    Werkzeugen der Erlaubt-Liste nicht mehr zu fragen. Das entscheidet der Sachbearbeiter, mit dem Geheimnis. Aktive
    Massnahmen und alles ausserhalb der Liste fragen weiter einzeln.
  - Das Geheimnis der Oberfläche steht nie in der Umgebung der Sitzung.
  - Anhalten beendet den Prozess (SIGTERM: Claude Code bricht den laufenden Schritt ab und beendet laufende Befehle).
    Fortsetzen nimmt dieselbe Sitzung wieder auf (--resume), auch nach einem Neustart der Oberfläche.
  - Meldet Claude Code beim Start, dass das Gateway des Projekts nicht geladen ist, beendet die Oberfläche die Sitzung:
    Dann sind die Einstellungen des Projekts nicht geladen, und Berechtigungen und Protokoll gälten nicht. Die Dokumentation
    kündigt an, dass der Skriptbetrieb sie künftig von sich aus weglässt («--bare» als Vorgabe für «-p»).

Stand der Dokumentation: code.claude.com/docs, Seiten «Run Claude Code programmatically», «CLI reference»,
«Authentication» und «Error reference», gelesen am 16.11.2026. Zur Frage an den Sachbearbeiter (AskUserQuestion) und zum
Vertrauen in den Projektordner: dieselbe Dokumentation, nachgelesen am 19.11.2026. Sie beschreibt die Form der Antwort auf
AskUserQuestion für Programme, die Zustimmungen selbst behandeln. Dass Claude Code sie über --permission-prompt-tool
ebenso annimmt, ist daraus geschlossen. Mit dem echten Claude Code geprüft ist der Weg nicht, siehe README unter «Stand
der Prüfung und Grenzen».
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

from gateway import pflichtquellen, plattform
from gateway.akte import PROJEKT, SITZUNGEN, fall_daten, fall_pfad, freigabe_erteilt, jsonl_lesen
from tools import schutzumfang
from tools.pii_pruefung import bericht as pii_bericht, pruefen as pii_pruefen
from tools.ui import bedienung as bedienung_modul, worte

AKTIONEN = ("ermittlung_starten", "ermittlung_anhalten", "ermittlung_fortsetzen", "ermittlung_antworten", "ermittlung_nachricht",
            "ermittlung_nachricht_zurueck")
RUECKFRAGE_WERKZEUG = "mcp__oberflaeche__rueckfrage"
ROBIN = worte.ROBIN
# So meldet Claude Code am Fehlerkanal, dass es die Erlaubt-Liste des Projekts übergeht, weil es dem Ordner nicht vertraut
LISTE_RUHT = re.compile(r"permissions\.allow.{0,200}trust|trust.{0,200}permissions\.allow|has not been trusted|workspace trust", re.I | re.S)
OHNE_ANTWORT = ("Der Sachbearbeiter hat die Frage nicht beantwortet. Frag nicht noch einmal dasselbe. Triff eine vertretbare Annahme, "
                "nenne sie in deiner Antwort und im Rapport als Annahme, und fahre fort.")
VON_SELBST = "steht auf der Erlaubt-Liste des Projekts"
WARTEZEIT = 30 * 60             # so lange wartet eine Rückfrage auf den Sachbearbeiter, dann gilt sie als abgelehnt
AUFTRAG_WEITER = "Bitte fahre mit der Ermittlung fort, wo sie angehalten wurde."
VORGABEN_KOPF = "Vorgaben des Sachbearbeiters für diese Ermittlung (über die Oberfläche eingegeben):"
UNTERBRECHUNG = ("Der Sachbearbeiter hat die Ermittlung unterbrochen und gibt über die Oberfläche vor:\n\n{text}\n\n"
                 "Berücksichtige das und fahre danach mit der Ermittlung fort, wo sie unterbrochen wurde.")
NACHRICHT_LAENGE = 6000
VERLAUF_LAENGE = 20000          # so viele Einträge behält der Verlauf im Speicher
ABSCHLUSS = "abschluss"         # nach einer gelungenen Ermittlung: Ermittlungsprotokoll, PDF und Datenblätter erzeugen
FEHLERKANAL_PAUSE = 1.5         # Sekunden: Was Claude Code in dieser Zeit am Fehlerkanal meldet, wird ein Eintrag im Fehlerprotokoll
FEHLERKANAL_ZEILEN = 80         # so viele Zeilen behält ein solcher Eintrag höchstens, die letzten
PFLICHT_SERVER = ("osint",)     # ohne das Gateway des Projekts läuft keine gesteuerte Sitzung
CLOUD = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
OHNE_PROJEKT = ("Claude Code hat die Einstellungen des Projekts nicht geladen (es fehlt: {fehlt}). Ohne sie gelten Berechtigungen, Gateway und "
                "Protokoll nicht. Die Oberfläche hat die Sitzung deshalb beendet, bevor sie etwas tun konnte. Die Ermittlung bitte am Terminal starten.")


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
    # Auch dort suchen, wohin der Installer Claude Code legt (~/.local/bin): Gleich nach der Einrichtung kennt das Terminal,
    # aus dem die Oberfläche startet, diesen Ordner oft noch nicht im PATH.
    pfad = eigen or plattform.programm("claude")
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


def ergebnis_lesen(inhalt: object) -> dict:
    """Das Ergebnis eines Werkzeugs als Wörterbuch, wenn es eines ist: Das Gateway antwortet in JSON, Claude Code reicht es als
    Text oder als Liste von Textblöcken weiter. Sonst ein leeres Wörterbuch."""
    texte = [inhalt] if isinstance(inhalt, str) else [b.get("text") for b in inhalt if isinstance(b, dict)] if isinstance(inhalt, list) else []
    for text in texte:
        try:
            d = json.loads(text)
        except (TypeError, ValueError):
            continue
        if isinstance(d, dict):
            return d
    return {}


def sperrfunde(text: str) -> int:
    """Wie viele Stellen eines Textes die strenge PII-Prüfung sperrt. Eine Nachricht hat keine Abschnitte: Jede Angabe, die nach
    Personendaten aussieht, zählt."""
    return sum(1 for f in pii_pruefen(text, "streng")[0] if f.stufe == "sperre")


def eingabe_pruefen(text: object, was: str, trotzdem: bool = False) -> str:
    """Was der Sachbearbeiter in den Chat schreibt, liest das Sprachmodell. Deshalb gilt dieselbe PII-Prüfung wie für Dokumente:
    Bei einem Sperrfund geht nichts hinaus, und die Meldung zeigt die Stelle maskiert. Die Prüfung kann einer Nachricht nicht
    ansehen, zu wem eine Angabe gehört. Gehört sie zur Täterseite, kann der Sachbearbeiter die Nachricht bewusst doch senden
    (`trotzdem`): Angaben der Täterseite braucht die Ermittlung. Wer das tut, steht mit der Zahl der Fundstellen im Sitzungsprotokoll."""
    text = str(text or "").strip()
    if len(text) > NACHRICHT_LAENGE:
        raise bedienung_modul.Fehler(f"{was} ist länger als {NACHRICHT_LAENGE} Zeichen. Längeres gehört als Dokument in den Fall.")
    funde, platzhalter = pii_pruefen(text, "streng")
    streng = schutzumfang.modus() == "streng"       # OSINT_SCHUTZ=streng: Dann gibt es kein «trotzdem», wie bis zum 19.11.2026
    if any(f.stufe == "sperre" for f in funde) and (streng or not trotzdem):
        fehler = bedienung_modul.Fehler(f"{was} wurde nicht gesendet: Darin steht etwas, das nach Personendaten aussieht.\n"
                                        + "\n".join(z for z in pii_bericht(was, funde, platzhalter).splitlines() if "SPERRE" in z)
                                        + ("\nBitte Platzhalter verwenden." if streng else
                                           "\nGehört die Angabe zu einer geschädigten Person, zur Verfasserin oder zum Verfasser oder zur Dienststelle: bitte den "
                                           "Platzhalter verwenden. Gehört sie zur Täterseite, lässt sich der Text trotzdem senden."))
        fehler.mehr = {} if streng else {"sperrfund": True}
        fehler.heikel = True        # der Text zeigt die gesperrte Stelle maskiert: Er steht im Fenster, nicht im Fehlerprotokoll
        raise fehler
    return text


_ORDNER: dict = {"zeit": 0.0, "wert": None}


def ordner_stand() -> bool | None:
    """Vertraut Claude Code dem Projektordner? True, False oder None (nicht feststellbar). Höchstens alle zehn Sekunden neu
    gelesen: Der Chat fragt jede Sekunde nach dem Stand, und die Datei von Claude Code kann gross sein."""
    jetzt = time.monotonic()
    if not _ORDNER["zeit"] or jetzt - _ORDNER["zeit"] > 10:
        _ORDNER.update(zeit=jetzt, wert=plattform.ordner_vertraut(PROJEKT))
    return _ORDNER["wert"]


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
        self.liste_ruht = False                 # Claude Code fragt bei Werkzeugen der Erlaubt-Liste: Es wendet sie nicht an
        self.ohne_nachfrage = False             # der Sachbearbeiter hat entschieden: bei Werkzeugen der Erlaubt-Liste nicht mehr fragen
        self.von_selbst: dict | None = None     # der eine Eintrag im Verlauf, der zählt, was danach von selbst erlaubt wurde
        self.schritte = 0                       # Werkzeugaufrufe seit dem Start dieser Sitzung, über alle Analysten
        self.fehlerzeilen: list[str] = []       # was Claude Code am Fehlerkanal meldet und noch nicht im Fehlerprotokoll steht
        self.fehleruhr: threading.Timer | None = None
        self.abgelehnte: set[str] = set()       # Aufrufe, die die Oberfläche abgelehnt hat: Ihr Ausbleiben ist kein Fehlschlag

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

    def festhalten(self, stufe: str, meldung: str, einzelheiten: str = "", fehler: BaseException | None = None) -> None:
        """Ins Fehlerprotokoll der Oberfläche, was bei dieser Ermittlung schiefging. Dort wird es bereinigt. Das Festhalten
        selbst wird nie zum Fehler der Ermittlung."""
        try:
            buch = self.bedienung.fehlerbuch
            if fehler is not None:
                buch.ausnahme("Ermittlung", meldung, fehler, self.fall)
            else:
                buch.eintragen("Ermittlung", stufe, meldung, einzelheiten, self.fall)
        except Exception:
            pass

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
                self.festhalten("fehler", "Claude Code liess sich nicht starten", fehler=e)
                raise bedienung_modul.Fehler(self.meldung, 500) from e
            self.status = "laeuft"
            self.version += 1
            prozess, ordner = self.prozess, self.ordner
        fehlerleser = threading.Thread(target=self._fehlerkanal, args=(prozess,), daemon=True)
        self.leser = threading.Thread(target=self._lesen, args=(prozess, ordner, fehlerleser), daemon=True)
        fehlerleser.start()
        self.leser.start()

    # ---- Ausgabe von Claude Code lesen: eine JSON-Zeile je Ereignis
    def _wer(self, ereignis: dict) -> str:
        return self.auftraege.get(str(ereignis.get("parent_tool_use_id") or ""), "hauptsitzung")

    def _lesen(self, prozess: subprocess.Popen, ordner: Path, fehlerleser: threading.Thread | None = None) -> None:
        """Liest die Ausgabe eines Laufs bis zu seinem Ende. Jeder Lauf hat seinen eigenen Leser und seinen eigenen Ordner:
        Wird eine Sitzung unterbrochen und sofort fortgesetzt, räumt der alte Leser nur auf, was zu seinem Lauf gehört.
        `fehlerleser`: der Faden, der den Fehlerkanal desselben Laufs liest."""
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
                    self.festhalten("fehler", f"Ein Ereignis von Claude Code liess sich nicht lesen (Art {kurz(str(e.get('type') or 'unbekannt'), 40)})", fehler=fehler)
        code = prozess.wait()
        naechste, abschliessen, melden = None, False, False
        with self.sperre:
            if self.prozess is prozess:
                if self.gewollt_beendet:
                    self.status = "angehalten"
                elif self.status not in ("beendet", "fehler"):
                    self.status = "beendet" if code == 0 else "fehler"
                    if code != 0 and not self.meldung:
                        self.meldung = f"Claude Code hat sich mit Rückgabewert {code} beendet."
                        self.notieren("oberfläche", self.meldung, "fehler")
                # Ein Ende mit Fehler gehört ins Fehlerprotokoll. Nicht, wenn die Sitzung angehalten oder von der Oberfläche beendet wurde
                melden = code != 0 and not self.gewollt_beendet and not self.abbruch
                for frage in self.fragen_offen:        # wer nicht mehr läuft, bekommt keine Antwort mehr
                    frage["ereignis"].set()
                self.version += 1
                # Eine Nachricht, die auf das Ende des Auftrags gewartet hat, geht jetzt an dieselbe Sitzung
                if self.status == "beendet" and self.wartend and self.kennung and not self.abbruch:
                    naechste = self.wartend.pop(0)
                else:
                    abschliessen = self.status == "beendet" and not self.abbruch
        shutil.rmtree(ordner, ignore_errors=True)
        # Zuerst, was Claude Code am Fehlerkanal gemeldet hat: Der Grund für ein Ende steht meist dort. Sein Leser endet mit dem Lauf
        if fehlerleser is not None:
            fehlerleser.join(timeout=3)
        self._fehlerkanal_festhalten()
        if melden:
            self.festhalten("fehler", f"Claude Code hat sich mit Rückgabewert {code} beendet.",
                            "Was Claude Code dazu am Fehlerkanal gemeldet hat, steht in einem eigenen Eintrag derselben Zeit («Claude Code meldet am Fehlerkanal»). "
                            "Gibt es keinen, hat Claude Code nichts gemeldet.")
        if naechste is not None:
            self.aendern(naechste["eintrag"], wartet=False)
            try:
                self.starten(naechste["text"], fortsetzen=True)
                self.bedienung.vermerken(self.fall, "Nachricht an die Ermittlung zugestellt", kurz(naechste["text"], 1500), sitzung=self.kennung)
            except bedienung_modul.Fehler as e:
                self.notieren("oberfläche", f"Die wartende Nachricht liess sich nicht zustellen: {e}", "fehler")
                self.festhalten("fehler", f"Eine wartende Nachricht liess sich nicht zustellen: {e}")
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
            self.festhalten("fehler", "Die Unterlagen nach der Ermittlung liessen sich nicht erzeugen", fehler=e)
        self.unterlagen = "bereit" if ergebnis.get("gelungen") else "fehler"
        self.aendern(eintrag, text="Die Unterlagen liegen unter «Ergebnisse» bereit." if ergebnis.get("gelungen") else
                     "Die Ermittlung ist abgeschlossen. Nicht alle Unterlagen liessen sich erzeugen: " + kurz((ergebnis.get("ausgabe") or "").splitlines()[-1:] or "", 300)
                     + " Unter «Ergebnisse» lässt sich das wiederholen.", ergebnisse=True)

    def _fehlerkanal(self, prozess: subprocess.Popen) -> None:
        assert prozess.stderr is not None
        for zeile in prozess.stderr:
            if zeile.strip():
                with self.sperre:
                    # Über dem Chat steht die erste Zeile einer Meldung: Sie sagt, worum es geht, was folgt, ist meist die Aufrufliste.
                    # Bereinigt wie ein Eintrag im Fehlerprotokoll: Claude Code kann einen Pfad oder einen Schlüssel nennen
                    if not self.abbruch and not self.fehlerzeilen:
                        self.meldung = kurz(self.bedienung.fehlerbuch.sauber(zeile), 400)
                        self.version += 1
                    # Fürs Fehlerprotokoll: Zeilen, die kurz nacheinander kommen, werden ein Eintrag (eine Aufrufliste hat viele Zeilen)
                    self.fehlerzeilen.append(zeile.rstrip()[:2000])
                    del self.fehlerzeilen[:-FEHLERKANAL_ZEILEN]
                    if self.fehleruhr is None:
                        self.fehleruhr = threading.Timer(FEHLERKANAL_PAUSE, self._fehlerkanal_festhalten)
                        self.fehleruhr.daemon = True
                        self.fehleruhr.start()
                if LISTE_RUHT.search(zeile):
                    self._liste_ruht_melden()
        self._fehlerkanal_festhalten()

    def _fehlerkanal_festhalten(self) -> None:
        """Was Claude Code am Fehlerkanal gemeldet hat und noch nirgends steht, als ein Eintrag ins Fehlerprotokoll."""
        with self.sperre:
            zeilen, self.fehlerzeilen = self.fehlerzeilen, []
            uhr, self.fehleruhr = self.fehleruhr, None
        if uhr is not None:
            uhr.cancel()
        if zeilen:
            weitere = len(zeilen) - 1
            self.festhalten("hinweis", "Claude Code meldet am Fehlerkanal: " + kurz(zeilen[0], 300)
                            + (f" (und {weitere} weitere {'Zeile' if weitere == 1 else 'Zeilen'})" if weitere else ""),
                            "\n".join(zeilen) if weitere or len(zeilen[0]) > 300 else "")

    def _liste_ruht_melden(self) -> None:
        """Einmal je Sitzung: Claude Code wendet die Erlaubt-Liste des Projekts nicht an. Was das heisst und wie es sich beheben lässt."""
        with self.sperre:
            if self.liste_ruht:
                return
            self.liste_ruht = True
        self.notieren("oberfläche", worte.OHNE_VERTRAUEN, "oberflaeche", wichtig=True)
        self.bedienung.vermerken(self.fall, "Erlaubt-Liste nicht angewendet", "Claude Code fragt bei Werkzeugen der Erlaubt-Liste des Projekts nach", sitzung=self.kennung)

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
                        self.festhalten("fehler", self.abbruch, "Claude Code meldet beim Start diese MCP-Server: " + (", ".join(sorted(namen)) or "keinen"))
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
                        # Der Schritt in Worten: welche Quelle, was sie gefragt wird, zu welchem Ziel. Der Name des Werkzeugs steht daneben
                        w = worte.schritt(name, eingabe)
                        stand["zuletzt"], stand["stand"] = kurz(w["text"], 110), "arbeitet"
                        stand["schritte"] += 1
                        self.schritte += 1
                        eintrag = self.notieren(wer, w["text"], "schritt", quelle=w["art"] in ("quelle", "robin"), technik=w["technik"],
                                                **({"zweck": w["zweck"]} if w["zweck"] else {}))
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
                        # Eine Abfrage mit Fehlschlag gehört ins Fehlerprotokoll: das Werkzeug, der Beleg, was die Quelle gemeldet hat.
                        # Nur Abfragen (Gateway, Robin), nicht jeder Befehl des Agenten. Und nicht, was der Sachbearbeiter abgelehnt hat.
                        gescheitert = (ergebnis.group(1) if ergebnis else "") in ("fehler", "nicht_ausgefuehrt") or bool(block.get("is_error"))
                        if gescheitert and eintrag.get("quelle") and kennung not in self.abgelehnte:
                            grund = str(ergebnis_lesen(inhalt).get("fehler") or "") or (kurz(text, 600) if block.get("is_error") else "")
                            self.festhalten("hinweis", f"Abfrage {eintrag.get('technik') or ''} ({worte.team(eintrag.get('wer') or 'hauptsitzung')}): Fehlschlag"
                                            + (f", Beleg {beleg.group(1)}" if beleg else "") + (f". {kurz(grund, 600)}" if grund else "."))
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
                if fehler:
                    self.festhalten("fehler", "Claude Code meldet das Ende der Sitzung mit einem Fehler"
                                    + (f" ({kurz(e.get('subtype'), 60)})" if e.get("subtype") else "") + ".", kurz(antwort, 1500))
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
        # Eine Frage der Ermittlung an den Sachbearbeiter: Sie braucht eine Antwort, keine Zustimmung
        gestellt = worte.fragen_lesen(eingabe) if werkzeug == worte.FRAGE_WERKZEUG else []

        def wer_fragt() -> str:
            """Welcher Analyst den Aufruf macht. Das steht im Ereignis, mit dem Claude Code den Aufruf ankündigt. Es kommt über einen
            anderen Kanal als die Rückfrage und kann einen Augenblick später eintreffen: Der Dialog wartet kurz darauf."""
            ende = time.monotonic() + 0.6
            while True:
                with self.sperre:
                    eintrag = self.aufrufe.get(tool_use_id)
                if eintrag is not None or not tool_use_id or time.monotonic() >= ende:
                    return (eintrag or {}).get("wer") or ""
                time.sleep(0.03)
        if gestellt:
            wer = wer_fragt()
            frage = {"id": secrets.token_urlsafe(8), "art": "frage", "werkzeug": werkzeug, "eingabe": json.dumps(eingabe, ensure_ascii=False, indent=1)[:6000],
                     "fragen": gestellt, "wer": wer, "ereignis": threading.Event(), "erlaubt": None, "antworten": None}
            text = "Die Ermittlung fragt: " + kurz(gestellt[0]["frage"], 300) + (f" (und {len(gestellt) - 1} weitere)" if len(gestellt) > 1 else "")
        else:
            z = worte.zustimmung(werkzeug, eingabe)
            if z["art"] == "erlaubt":
                # Claude Code fragt bei einem Werkzeug der Erlaubt-Liste: Es wendet sie nicht an. Hat der Sachbearbeiter für diese
                # Ermittlung entschieden, dabei nicht mehr gefragt zu werden, gilt die Liste des Projekts.
                self._liste_ruht_melden()
                with self.sperre:
                    if self.ohne_nachfrage:
                        if self.von_selbst is None:
                            self.von_selbst = self.notieren("oberfläche", "", "oberflaeche", zahl=0)
                        zahl = int(self.von_selbst.get("zahl") or 0) + 1
                        self.aendern(self.von_selbst, zahl=zahl, text=f"Ohne Rückfrage erlaubt, weil auf der Erlaubt-Liste des Projekts: {zahl} "
                                                                       f"{'Aufruf' if zahl == 1 else 'Aufrufe'}. Jeder steht als Schritt im Verlauf.")
                        return {"erlauben": True, "grund": "", "von_selbst": VON_SELBST}
            wer = wer_fragt()
            frage = {"id": secrets.token_urlsafe(8), "art": "zustimmung", "werkzeug": werkzeug, "eingabe": json.dumps(eingabe, ensure_ascii=False, indent=1)[:6000],
                     "worte": z, "wer": wer, "ereignis": threading.Event(), "erlaubt": None}
            text = "Zustimmung nötig: " + kurz(z["satz"], 300)
        with self.sperre:
            self.fragen_offen.append(frage)
            self.status = "wartet"
            frage["eintrag"] = self.notieren("oberfläche", text, "rueckfrage", entscheid="offen")
        beantwortet = frage["ereignis"].wait(WARTEZEIT)
        with self.sperre:
            if frage in self.fragen_offen:
                self.fragen_offen.remove(frage)
            erlaubt = bool(beantwortet and frage["erlaubt"])
            if self.status == "wartet" and not self.fragen_offen:
                self.status = "laeuft"
            if frage["art"] == "frage":
                entscheid = "beantwortet" if erlaubt else "nicht beantwortet"
            else:
                entscheid = "erlaubt" if erlaubt else "abgelehnt" if frage["erlaubt"] is False else "nicht beantwortet"
        self.aendern(frage["eintrag"], entscheid=entscheid)
        if frage["art"] == "frage":
            if erlaubt and frage["antworten"]:
                return {"erlauben": True, "grund": "", "antworten": frage["antworten"], "frage": frage["id"]}
            return {"erlauben": False, "grund": OHNE_ANTWORT if frage["erlaubt"] is False or not beantwortet else
                    "Die Ermittlung wurde angehalten, bevor die Frage beantwortet war."}
        if frage["erlaubt"] is None:
            return {"erlauben": False, "grund": "Der Sachbearbeiter hat die Rückfrage nicht rechtzeitig beantwortet." if not beantwortet else
                    "Die Ermittlung wurde angehalten, bevor die Rückfrage beantwortet war."}
        return {"erlauben": erlaubt, "grund": "" if erlaubt else "Der Sachbearbeiter hat den Aufruf in der Oberfläche abgelehnt.", "frage": frage["id"]}

    def offene_frage(self, frage_id: str) -> dict:
        with self.sperre:
            frage = next((f for f in self.fragen_offen if f["id"] == frage_id), None)
        if frage is None:
            raise bedienung_modul.Fehler("Diese Rückfrage ist nicht mehr offen.", 404)
        return frage

    def antworten(self, frage_id: str, erlauben: bool, antworten: dict | None = None, merken: bool = False) -> dict:
        """Die Entscheidung des Sachbearbeiters. `antworten`: bei einer Frage der Ermittlung, je Frage die Antwort.
        `merken`: bei Werkzeugen der Erlaubt-Liste für den Rest dieser Ermittlung nicht mehr fragen. Das gilt nur,
        wenn die beantwortete Rückfrage selbst ein solches Werkzeug betraf."""
        with self.sperre:
            frage = next((f for f in self.fragen_offen if f["id"] == frage_id), None)
            if frage is None:
                raise bedienung_modul.Fehler("Diese Rückfrage ist nicht mehr offen.", 404)
            gemerkt = bool(merken and erlauben and frage["art"] == "zustimmung" and frage["worte"].get("merkbar"))
            if gemerkt:
                self.ohne_nachfrage = True
            if frage["art"] == "frage":
                frage["antworten"] = dict(antworten or {}) if erlauben else None
            frage["erlaubt"] = bool(erlauben)
            frage["ereignis"].set()
        return {"art": frage["art"], "werkzeug": frage["werkzeug"], "eingabe": frage["eingabe"], "gemerkt": gemerkt,
                "satz": frage["worte"]["satz"] if frage["art"] == "zustimmung" else frage["fragen"][0]["frage"]}

    # ---- Stand, für die Ansicht «Ermittlung» und für den Chat
    def _frage_dict(self) -> dict | None:
        frage = self.frage
        if not frage:
            return None
        return ({k: frage[k] for k in ("id", "art", "werkzeug", "eingabe", "wer")} | {k: frage[k] for k in ("worte", "fragen") if k in frage}
                | {"weitere": len(self.fragen_offen) - 1})

    def lage(self, status: str) -> str:
        """Der Stand der Ermittlung in einem Satz, für die Zeile über dem Chat."""
        if status == "wartet":
            frage = self.frage
            return ("Die Ermittlung wartet auf dich: Sie hat eine Frage." if frage and frage["art"] == "frage" else
                    "Die Ermittlung wartet auf dich: Ein Schritt braucht deine Zustimmung.")
        if status == "laeuft":
            aktiv = [w for w in self.wer.values() if w["stand"] == "arbeitet" and w["zuletzt"]]
            gerade = f" Gerade: {worte.team(aktiv[-1]['name'])}, {aktiv[-1]['zuletzt']}." if aktiv else ""
            return f"Die Ermittlung läuft. {self.schritte} {'Schritt' if self.schritte == 1 else 'Schritte'} bisher.{gerade}"
        if status == "angehalten":
            return "Die Ermittlung ist angehalten. «Fortsetzen» nimmt sie wieder auf, eine Nachricht auch."
        if status == "beendet":
            return {"laeuft": "Der Auftrag ist zu Ende. Die Unterlagen werden erzeugt.", "bereit": "Die Ermittlung ist abgeschlossen. Die Unterlagen liegen unter «Ergebnisse».",
                    "fehler": "Die Ermittlung ist abgeschlossen. Nicht alle Unterlagen liessen sich erzeugen: unter «Ergebnisse» wiederholen."}.get(
                        self.unterlagen, "Der Auftrag ist zu Ende. Eine Nachricht setzt die Ermittlung fort.")
        if status == "fehler":
            return "Die Ermittlung ist abgebrochen. " + (self.meldung or "Der Grund steht im Verlauf.")
        return ""

    def als_dict(self) -> dict:
        with self.sperre:
            status = self.status if self.laeuft() or self.status != "laeuft" else "beendet"
            return {"status": status, "sitzung": self.kennung, "modell": self.modell, "meldung": self.meldung, "lage": self.lage(status),
                    "frage": self._frage_dict(), "wer": [dict(w) for w in self.wer.values()], "verlauf": [dict(z) for z in self.verlauf[-60:]],
                    "wartend": [{"id": w["id"], "text": w["text"]} for w in self.wartend], "unterlagen": self.unterlagen, "v": self.version,
                    "liste_ruht": self.liste_ruht, "ohne_nachfrage": self.ohne_nachfrage}

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
    ordner = ordner_stand() if b is not None else None
    if s is not None:
        return {**s.seit(version), "ordner": ordner}
    frueher = letzte_sitzung(fall) if b is not None else ""
    return {"status": "aus", "sitzung": "", "modell": "", "meldung": "", "lage": "", "frage": None, "wer": [], "verlauf": [], "wartend": [], "unterlagen": "", "v": 0,
            "neu_beginnen": version > 0, "frueher": frueher, "ordner": ordner, "liste_ruht": False, "ohne_nachfrage": False}


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
    trotzdem = bool(d.get("trotzdem"))
    vorgaben = eingabe_pruefen(d.get("vorgaben"), "Die Vorgabe", trotzdem)
    s = Sitzung(b, fall, int(d.get("_port") or 0))
    if alt is not None:         # der Chat bleibt stehen, die Ermittlung beginnt neu
        with alt.sperre:        # was noch auf die alte Sitzung wartete, geht nicht an die neue: Es gilt als zurückgenommen
            wartende, alt.wartend = alt.wartend, []
        for w in wartende:
            alt.aendern(w["eintrag"], wartet=False, zurueck=True)
            b.vermerken(fall, "Nachricht nicht zugestellt", f"{kurz(w['text'], 300)} (die Ermittlung wurde neu gestartet)", sitzung=alt.kennung)
        s.verlauf, s.nummer, s.version = alt.verlauf, alt.nummer, alt.version + 1
    b.ermittlungen[fall] = s
    pflicht = pflichtquellen.vorgabe(fall_daten(fall))      # sie stehen in fall.json. Die Ermittlung liest sie mit fall_status
    s.notieren("sachbearbeiter", f"Ermittlung starten: /ermittlung {fall}" + (f"\n\n{vorgaben}" if vorgaben else "")
               + (f"\n\nPflichtquellen: {', '.join(pflicht)}" if pflicht else ""), "sachbearbeiter")
    s.starten(auftrag_text(fall, vorgaben))
    b.vermerken(fall, "Ermittlung gestartet", f"/ermittlung {fall}" + (f" · Vorgaben: {kurz(vorgaben, 1500)}" if vorgaben else "")
                + (f" · Pflichtquellen: {', '.join(pflicht)}" if pflicht else ""))
    _trotzdem_vermerken(b, s, fall, vorgaben, trotzdem, "Vorgabe")
    return {"meldung": "Die Ermittlung ist gestartet. Jeder Schritt erscheint im Chat, neue Ergebnisse in der Arbeitsspur und in den Ansichten."}


def _trotzdem_vermerken(b: "bedienung_modul.Bedienung", s: Sitzung, fall: str, text: str, trotzdem: bool, was: str) -> None:
    """Hat der Sachbearbeiter einen Text bewusst gesendet, obwohl die Prüfung darin etwas sperrt, steht das im Sitzungsprotokoll
    und im Verlauf: wer es war, weiss die Oberfläche nicht, aber dass es so entschieden wurde und wie viele Stellen es betraf."""
    zahl = sperrfunde(text) if trotzdem else 0
    if zahl:
        b.vermerken(fall, f"{was} trotz Sperrfund gesendet", f"{zahl} Fundstelle(n) der PII-Prüfung. Der Sachbearbeiter hat entschieden: Die Angabe gehört zur Täterseite.",
                    sitzung=s.kennung)
        s.notieren("oberfläche", f"{was} bewusst gesendet, obwohl die Prüfung {zahl} {'Stelle' if zahl == 1 else 'Stellen'} sperrt (Angabe der Täterseite). "
                                 "Das steht im Sitzungsprotokoll.")


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
    trotzdem = bool(d.get("trotzdem"))
    text = eingabe_pruefen(d.get("text"), "Die Nachricht", trotzdem)
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
            _trotzdem_vermerken(b, s, fall, text, trotzdem, "Nachricht")
            return {"meldung": "Die Nachricht wartet. Sie geht an die Ermittlung, sobald der laufende Auftrag zu Ende ist.", "wartet": True}
        if not s.kennung:
            raise bedienung_modul.Fehler("Claude Code hat seine Sitzung noch nicht genannt. Bitte in ein paar Sekunden noch einmal senden.")
        s.anhalten()
        s.notieren("sachbearbeiter", text, "sachbearbeiter")
        s.starten(UNTERBRECHUNG.format(text=text), fortsetzen=True)
        b.vermerken(fall, "Nachricht an die Ermittlung", kurz(text, 1500) + " (laufender Auftrag unterbrochen)", sitzung=s.kennung)
        _trotzdem_vermerken(b, s, fall, text, trotzdem, "Nachricht")
        return {"meldung": "Der laufende Auftrag ist unterbrochen. Die Ermittlung arbeitet mit der Nachricht weiter."}
    s = _fortsetzbar(b, fall, int(d.get("_port") or 0))
    s.notieren("sachbearbeiter", text, "sachbearbeiter")
    s.starten(text, fortsetzen=True)
    b.vermerken(fall, "Nachricht an die Ermittlung", kurz(text, 1500), sitzung=s.kennung)
    _trotzdem_vermerken(b, s, fall, text, trotzdem, "Nachricht")
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
    kennung = str(d.get("frage") or "")
    offen = s.offene_frage(kennung)
    if offen["art"] == "frage":
        # Eine Frage der Ermittlung. Die Antwort liest das Sprachmodell: Eigene Antworten gehen durch dieselbe Prüfung wie eine Nachricht
        antworten: dict[str, str] = {}
        trotzdem = bool(d.get("trotzdem"))
        if erlauben:
            for i, f in enumerate(offen["fragen"]):
                eigen = eingabe_pruefen(d.get(f"frei_{i}"), "Die Antwort", trotzdem)
                if f["mehrere"]:
                    wert = ", ".join([w["name"] for j, w in enumerate(f["wahl"]) if d.get(f"wahl_{i}_{j}")] + ([eigen] if eigen else []))
                else:
                    nummer = str(d.get(f"wahl_{i}") or "")
                    wert = eigen or (f["wahl"][int(nummer)]["name"] if nummer.isdigit() and int(nummer) < len(f["wahl"]) else "")
                if not wert:
                    raise bedienung_modul.Fehler(f"Frage {i + 1} ist noch offen: bitte eine Auswahl treffen oder eine eigene Antwort schreiben."
                                                 if len(offen["fragen"]) > 1 else "Bitte eine Auswahl treffen oder eine eigene Antwort schreiben.")
                antworten[f["frage"]] = wert
        s.antworten(kennung, erlauben, antworten)
        if erlauben:
            text = "\n".join(f"{frage}\n→ {antwort}" for frage, antwort in antworten.items())
            s.notieren("sachbearbeiter", text, "sachbearbeiter")
            b.vermerken(fall, "Frage der Ermittlung beantwortet", kurz(text, 1500), sitzung=s.kennung)
            _trotzdem_vermerken(b, s, fall, "\n".join(antworten.values()), trotzdem, "Antwort")
            return {"meldung": "Die Antwort ist bei der Ermittlung."}
        b.vermerken(fall, "Frage der Ermittlung nicht beantwortet", kurz(offen["fragen"][0]["frage"], 300), sitzung=s.kennung)
        return {"meldung": "Nicht beantwortet: Die Ermittlung trifft selbst eine Annahme und nennt sie."}
    frage = s.antworten(kennung, erlauben, merken=bool(d.get("merken")))
    b.vermerken(fall, f"Rückfrage {'erlaubt' if erlauben else 'abgelehnt'}", f"{frage['werkzeug']} {kurz(frage['eingabe'], 240)}"
                + (" · bei Werkzeugen der Erlaubt-Liste für diese Ermittlung nicht mehr fragen" if frage["gemerkt"] else ""), sitzung=s.kennung)
    if frage["gemerkt"]:
        s.notieren("oberfläche", "Entschieden: Bei Werkzeugen, die auf der Erlaubt-Liste des Projekts stehen, fragt die Oberfläche für den Rest dieser Ermittlung "
                                 "nicht mehr. Aktive Massnahmen und alles, was auf keiner Liste steht, fragen weiter einzeln.")
        return {"meldung": "Erlaubt. Bei Werkzeugen der Erlaubt-Liste fragt die Oberfläche in dieser Ermittlung nicht mehr."}
    return {"meldung": "Erlaubt: Claude Code führt den Aufruf aus." if erlauben else "Abgelehnt: Claude Code führt den Aufruf nicht aus."}


def rueckfrage(b: "bedienung_modul.Bedienung", d: dict) -> dict:
    """Die Frage des MCP-Servers einer Sitzung. Er weist sich mit der Karte seiner Sitzung aus. Die Karte taugt nur zum Fragen."""
    s = _sitzung(b, str(d.get("fall") or ""))
    if s is None or not hmac.compare_digest(str(d.get("karte") or "").encode(), s.karte.encode()):
        raise bedienung_modul.Fehler("Diese Rückfrage gehört zu keiner laufenden Sitzung.", 403)
    start = time.time()
    antwort = s.fragen(str(d.get("werkzeug") or ""), d.get("eingabe"), str(d.get("tool_use_id") or ""))
    if not antwort.get("erlauben") and d.get("tool_use_id"):
        with s.sperre:      # ein abgelehnter Aufruf bleibt aus: Das ist ein Entscheid und kein Fehlschlag fürs Fehlerprotokoll
            s.abgelehnte.add(str(d["tool_use_id"]))
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
    ("frage", "Dies ist eine Prüfung der Fragen an den Sachbearbeiter, keine Ermittlung. Rufe genau einmal das Werkzeug AskUserQuestion auf, mit genau einer Frage im "
              "Wortlaut «{frage}», der Überschrift «Probe» und genau zwei Antworten zur Auswahl: «{erste}» und «{zweite}». Versuche nichts anderes. Antworte danach mit "
              "genau einem Satz, der mit «" + PROBE_SATZ + ":» beginnt und die Antwort wörtlich nennt, die du bekommen hast."),
)
# Die Frage der fünften Probe. Die Probe wählt die zweite Antwort: Ein Modell, das ohne Antwort rät, nennt eher die erste
PROBE_FRAGE, PROBE_WAHL = "Welche Farbe soll die Probe nennen?", ("Blau", "Rot")


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
    elif art == "frage":
        # Eine Frage der Ermittlung an den Sachbearbeiter: Kommt sie an, nimmt Claude Code die Antwort an, und erreicht sie das Modell?
        gestellt = [k for k, a in aufrufe.items() if a.get("name") == worte.FRAGE_WERKZEUG]
        angekommen = next((f for f in fragen if f.get("art") == "frage"), None)
        if not gestellt:
            punkte.append((False, "Claude Code hat keine Frage gestellt: Das Werkzeug AskUserQuestion fehlt in der Ausgabe. Vielleicht bietet diese Fassung von Claude Code "
                                  "es im Skriptbetrieb nicht an. Die Probe sagt dann nichts darüber, ob sich eine Frage beantworten lässt."))
            return punkte
        punkte.append((angekommen is not None, "Die Frage kam bei der Oberfläche an: " + kurz(angekommen["fragen"][0]["frage"], 120) + " ("
                       + ", ".join(w["name"] for w in angekommen["fragen"][0]["wahl"]) + ")." if angekommen is not None else
                       "Claude Code hat eine Frage gestellt, aber sie kam bei der Oberfläche nicht als Frage an"
                       + (f" (angekommen ist: {fragen[0].get('werkzeug')})." if fragen else ": Es kam gar keine Rückfrage an.")))
        if angekommen is None:
            return punkte
        gewaehlt = str(angekommen.get("gewaehlt") or "")
        for k in gestellt:
            fehler, text = ergebnisse.get(k, (True, "ohne Ergebnis"))
            punkte.append((not fehler and k not in abgelehnt, ("Claude Code hat die Antwort der Oberfläche angenommen." if not fehler and k not in abgelehnt else
                                                             "Claude Code hat die Antwort der Oberfläche NICHT angenommen.") + f" Meldung des Werkzeugs: {text}"))
        punkte.append((bool(gewaehlt) and gewaehlt in antwort and PROBE_SATZ in antwort,
                       f"Die Antwort «{gewaehlt}» hat das Modell erreicht: {kurz(antwort, 160)}" if gewaehlt and gewaehlt in antwort and PROBE_SATZ in antwort
                       else f"Die Antwort «{gewaehlt}» steht nicht in dem, was das Modell danach sagt: {kurz(antwort, 160) or 'nichts'}"))
    else:
        punkte.append((bool(fragen), f"Die Rückfrage kam bei der Oberfläche an: {fragen[0]['werkzeug']}." if fragen else "Bei der Oberfläche kam keine Rückfrage an."))
        for k in [k for k, a in aufrufe.items() if a.get("name") == "WebSearch"]:
            fehler, text = ergebnisse.get(k, (True, "ohne Ergebnis"))
            punkte.append((fehler or k in abgelehnt, f"Nach der Ablehnung in der Oberfläche: {'nicht ausgeführt' if fehler or k in abgelehnt else 'AUSGEFÜHRT'}. Meldung: {text}"))
    return punkte


def probe(b: "bedienung_modul.Bedienung", port: int, fall: str, ausgabe=print, zeit: int = 300) -> int:
    """Startet fünf kurze Sitzungen des echten Claude Code über denselben Weg wie «Ermittlung starten» und zeigt, ob der Weg trägt:
    Form der Ausgabe und Hooks des Projekts, Fortsetzen derselben Sitzung, Verbotsregeln, Rückfrage, Frage an den Sachbearbeiter.
    Die Probe lehnt jede Rückfrage ab. Die Frage der fünften Sitzung beantwortet sie selbst, mit der zweiten Antwort zur Auswahl.
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
        s.starten(auftrag.replace("{fall}", fall).replace("{frage}", PROBE_FRAGE).replace("{erste}", PROBE_WAHL[0]).replace("{zweite}", PROBE_WAHL[1]),
                  fortsetzen=art == "fortsetzen")
        ende = time.time() + zeit
        while time.time() < ende:
            frage = s._frage_dict()
            if frage:
                fragen.append(frage)
                wahl = frage["fragen"][0]["wahl"] if art == "frage" and frage.get("art") == "frage" else []
                if wahl:        # die Frage der Probe: Die Probe antwortet selbst, mit der letzten Antwort zur Auswahl
                    frage["gewaehlt"] = wahl[-1]["name"]
                    s.antworten(frage["id"], True, {frage["fragen"][0]["frage"]: wahl[-1]["name"]})
                    continue
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
