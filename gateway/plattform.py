"""Was je Betriebssystem anders ist, steht an dieser einen Stelle. Nur Standardbibliothek.

Gebraucht von Gateway, Hooks und den Werkzeugen unter tools/:

    start()            Ein- und Ausgabe auf UTF-8 stellen, bei Bedarf in das Python der .venv wechseln
    venv_python()      Interpreter der .venv (Linux/macOS: bin/python, Windows: Scripts\\python.exe)
    dateisperre()      exklusive Sperre, damit zwei Prozesse eine Hash-Kette nicht gleichzeitig fortschreiben
    zeitzone()         Zeitzone für die Zeitangaben in Rapport und Protokoll
    text_schreiben()   Textdatei mit festen Zeilenenden, damit Hashes auf jedem System gleich ausfallen
    baum_loeschen()    Ordner samt schreibgeschützter Dateien entfernen

Linux, macOS und WSL verhalten sich gleich. Windows weicht in fünf Punkten ab: Der Interpreter heisst
`python` statt `python3`, die .venv liegt unter Scripts\\, Textdateien bekämen ohne Vorgabe \\r\\n und
die Kodierung des Systems, Dateisperren laufen über msvcrt statt fcntl, und Zeitzonendaten bringt nur
das Paket tzdata in der .venv mit.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import time
from datetime import tzinfo
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
try:
    import msvcrt
except ImportError:  # Linux, macOS
    msvcrt = None

WINDOWS = os.name == "nt"
PROJEKT = Path(__file__).resolve().parents[1]

# So heissen die Befehle in Meldungen an den Menschen am Terminal.
PY = "python" if WINDOWS else "python3"
SETUP = ".\\setup.cmd" if WINDOWS else "./setup.sh"

# Schlichte Zeichen für die alte Windows-Konsole, deren Schrift Haken und Kreuz nicht kennt.
_SCHLICHT = WINDOWS and not os.environ.get("WT_SESSION")
GUT, NEU, AUS, FEHLT = ("ok", "+", "-", "!!") if _SCHLICHT else ("✓", "+", "–", "✗")


class Zeitzonenfehler(RuntimeError):
    pass


def venv_python(projekt: Path = PROJEKT) -> Path:
    return Path(projekt) / ".venv" / ("Scripts/python.exe" if WINDOWS else "bin/python")


def in_venv(projekt: Path = PROJEKT) -> bool:
    try:
        return Path(sys.prefix).resolve() == (Path(projekt) / ".venv").resolve()
    except OSError:
        return False


def utf8() -> None:
    """Stellt Ein- und Ausgabe auf UTF-8. Unter Windows gälte sonst die Kodierung des Systems:
    Umlaute aus Claude Code kämen verstümmelt an, und ein Haken in der Ausgabe liesse das Skript abbrechen."""
    for strom, fehler in ((sys.stdin, "strict"), (sys.stdout, "replace"), (sys.stderr, "replace")):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            strom.reconfigure(encoding="utf-8", errors=fehler)


def start(venv: bool | None = None, projekt: Path = PROJEKT) -> None:
    """Am Anfang jedes Einstiegspunkts aufrufen.

    venv=None   unter Windows in das Python der .venv wechseln (dort liegen die Zeitzonendaten), sonst bleiben
    venv=True   immer in die .venv wechseln (für alles, was die Pakete des Gateways braucht)
    venv=False  nie wechseln (Hooks: Sie sollen schnell sein und brauchen nur die Standardbibliothek)
    """
    utf8()
    if os.environ.pop("OSINT_NEUSTART", None) == "1":      # wurde eben neu gestartet: nicht noch einmal
        return
    if venv is False or (venv is None and not WINDOWS):
        return
    ziel = venv_python(projekt)
    if in_venv(projekt) or not ziel.is_file():
        return
    befehl = [str(ziel), *sys.argv]
    umgebung = {**os.environ, "OSINT_NEUSTART": "1"}
    if WINDOWS:     # os.exec ersetzt den Prozess unter Windows nicht sauber: Die Shell kehrte sofort zurück
        try:
            sys.exit(subprocess.call(befehl, env=umgebung))
        except KeyboardInterrupt:
            sys.exit(130)
    os.execve(str(ziel), befehl, umgebung)


@contextlib.contextmanager
def dateisperre(datei: Path, warten: float = 30.0):
    """Exklusive Sperre über die Nebendatei <datei ohne Endung>.lock.

    Mehrere Prozesse schreiben an denselben Protokollen: das Gateway und, wenn Subagenten gleichzeitig
    arbeiten, mehrere Hooks. Jeder Eintrag enthält den Hash des vorigen. Ohne Sperre läsen zwei Prozesse
    denselben Vorgänger und die Kette wäre gebrochen."""
    with open(Path(datei).with_suffix(".lock"), "a+b") as sperre:
        if fcntl is not None:
            fcntl.flock(sperre, fcntl.LOCK_EX)
        elif msvcrt is not None:
            ende = time.monotonic() + warten
            while True:
                try:
                    sperre.seek(0)
                    msvcrt.locking(sperre.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > ende:
                        raise TimeoutError(f"Sperre auf {datei} nach {warten:.0f} Sekunden nicht erhalten.") from None
                    time.sleep(0.02)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(sperre, fcntl.LOCK_UN)
            elif msvcrt is not None:
                with contextlib.suppress(OSError):
                    sperre.seek(0)
                    msvcrt.locking(sperre.fileno(), msvcrt.LK_UNLCK, 1)


def einstellung(name: str, standard: str = "") -> str:
    """Wert einer Einstellung: zuerst die Umgebung, dann die Datei .env im Projekt, sonst der Standard.
    So gilt etwa OSINT_ZEITZONE aus .env für Gateway, Hooks und Werkzeuge gleichermassen."""
    wert = os.environ.get(name, "").strip()
    if wert:
        return wert
    datei = Path(os.environ.get("OSINT_PROJEKT") or PROJEKT) / ".env"
    try:
        for zeile in datei.read_text(encoding="utf-8").splitlines():
            schluessel, trenner, wert = zeile.strip().partition("=")
            if trenner and schluessel.strip() == name and not zeile.lstrip().startswith("#"):
                wert = wert.strip().strip("\"'")
                if wert:
                    return wert
    except OSError:
        pass
    return standard


def zeitzone(name: str | None = None) -> tzinfo:
    """Zeitzone für Zeitangaben. Fehlen die Zeitzonendaten, wird abgebrochen statt mit einer
    geratenen Ortszeit weitergearbeitet: Eine um eine Stunde falsche Zeit im Rapport wäre schlimmer."""
    name = (name or einstellung("OSINT_ZEITZONE", "Europe/Zurich")).strip()
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception as e:
        raise Zeitzonenfehler(
            f"Zeitzone '{name}' ist auf diesem Rechner nicht verfügbar ({type(e).__name__}). "
            f"Unter Windows liefert die .venv die Zeitzonendaten: {SETUP} ausführen. "
            "Sonst OSINT_ZEITZONE in .env prüfen (Beispiel: Europe/Zurich).") from e


def text_schreiben(datei: Path, text: str) -> None:
    """Schreibt UTF-8 mit \\n als Zeilenende, auf jedem System. Dateien der Fallakte werden gehasht."""
    with open(datei, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def zeile_anhaengen(datei: Path, zeile: str) -> None:
    """Hängt eine Zeile an ein Protokoll an und zwingt sie auf die Platte."""
    with open(datei, "a", encoding="utf-8", newline="\n") as f:
        f.write(zeile + "\n")
        f.flush()
        os.fsync(f.fileno())


def baum_loeschen(pfad: Path) -> None:
    """Wie shutil.rmtree, kommt aber auch an schreibgeschützten Dateien vorbei (Rohdaten sind es mit Absicht)."""
    def nochmal(funktion, ziel, _fehler):
        os.chmod(ziel, stat.S_IWRITE | stat.S_IREAD)
        funktion(ziel)

    if not Path(pfad).exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(pfad, onexc=nochmal)
    else:
        shutil.rmtree(pfad, onerror=nochmal)


def programm(name: str) -> str | None:
    """Sucht ein Programm im PATH und an den Orten, an die Installer es legen, bevor ein neues
    Terminal den PATH kennt (Claude Code: ~/.local/bin, winget: WinGet\\Links)."""
    gefunden = shutil.which(name)
    if gefunden:
        return gefunden
    orte = [Path.home() / ".local" / "bin"]
    if WINDOWS:
        orte.append(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links")
    for ort in orte:
        for endung in ((".exe", ".cmd", "") if WINDOWS else ("",)):
            kandidat = ort / f"{name}{endung}"
            if kandidat.is_file():
                return str(kandidat)
    return None
