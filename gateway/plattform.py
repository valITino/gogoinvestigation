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
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from datetime import tzinfo
from pathlib import Path
from urllib.parse import urlsplit

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
# Die nächsten Schritte, wenn der Arbeitsplatz eingerichtet ist. Die Einrichtung und tools/pruefen.py nennen dieselben: weiter()
IN_DER_OBERFLAECHE = (
    "Dort «Neuer Fall»: Akten hineinziehen (einzeln, als Ordner oder als ZIP). Wo die erste Schwärzung im Haus etwas übersehen hat, "
    "auf dem lokalen Bildschirm nachbessern. Fall-ID und Titel eintragen, Fall anlegen.",
    "«Ermittlung»: Wer will, wählt Pflichtquellen an. Vorgaben in den Chat schreiben, wenn es welche gibt, und starten. Zusehen, "
    "Rückfragen beantworten.",
    "«Ergebnisse»: Rapport, Protokoll und Datenblätter ansehen und herunterladen.",
)

# Schlichte Zeichen für die alte Windows-Konsole, deren Schrift Haken und Kreuz nicht kennt.
_SCHLICHT = WINDOWS and not os.environ.get("WT_SESSION")
GUT, NEU, AUS, FEHLT = ("ok", "+", "-", "!!") if _SCHLICHT else ("✓", "+", "–", "✗")

# Proxy für die Abfragen des Gateways (OSINT_PROXY). Was dazu an mehreren Stellen gleich lauten muss, steht hier.
TOR_PROXY = "socks5h://127.0.0.1:9050"          # Tor auf diesem Rechner, so wie das Paket tor es einrichtet
RAT_VERBINDUNG = "Netzwerk, Proxy (OSINT_PROXY) und Erreichbarkeit prüfen."     # hängt das Gateway an einen Verbindungsfehler an
PROXY_STUMM = "Der Proxy (OSINT_PROXY) antwortet nicht. Jede Abfrage ginge über ihn, also kommt keine durch."
TOR_PROBE = ("check.torproject.org", 443)       # dorthin öffnet die Prüfung über Tor eine Verbindung und schliesst sie, ohne etwas zu senden


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


def terminal(*stroeme: object) -> bool:
    """True, wenn jeder der Ströme an einem echten Terminal hängt. Daran erkennen die Werkzeuge, die nur ein Mensch
    bedienen darf, dass kein Agent und kein Skript sie aufruft.

    ``isatty()`` allein genügt unter Windows nicht: Für das Gerät NUL meldet es True (gesehen in der CI am 17.11.2026,
    ein Prozess mit stdin=NUL galt als «am Terminal»). Dort entscheidet, ob Windows für den Griff einen Konsolenmodus kennt.
    """
    if not stroeme:
        return False
    for strom in stroeme:
        try:
            if not strom.isatty():
                return False
            if WINDOWS:
                import ctypes
                from ctypes import wintypes
                modus = wintypes.DWORD()
                if not ctypes.windll.kernel32.GetConsoleMode(wintypes.HANDLE(msvcrt.get_osfhandle(strom.fileno())), ctypes.byref(modus)):
                    return False
        except Exception:       # im Zweifel kein Terminal: Die Prüfung schützt, sie darf nicht an einem Sonderfall aufgehen
            return False
    return True


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


# Das Abbild von Robin, auf eine Prüfsumme festgelegt (Stand bei Docker Hub vom 3.10.2026). Dieselbe Angabe steht in
# .mcp.json, ein Selbsttest hält beide gleich. Ein neuer Stand ist ein bewusster Schritt, per Pull Request.
ROBIN_ABBILD = "apurvsg/robin@sha256:579aae11b9100078ecd0d700f4057117e3ded6f37a37d7dfdf773bfcceded5c0"


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


def wsl() -> bool:
    """Linux unter WSL. Dort gibt es keinen eigenen Browser, wohl aber den von Windows."""
    if sys.platform != "linux":
        return False
    return "microsoft" in platform.release().lower() or bool(os.environ.get("WSL_DISTRO_NAME"))


# Erst wenn der Mensch dem Projektordner in Claude Code vertraut, wendet Claude Code die Erlaubnisse aus .claude/settings.json an.
# So steht es in der Dokumentation von Claude Code («Project allow rules and workspace trust»). Dieser Satz steht überall gleich.
OHNE_VERTRAUEN = "Erst mit diesem Ja gelten die Erlaubnisse des Projekts. Ohne sie fragt Claude Code bei jeder Abfrage einzeln nach."


def ordner_vertraut(projekt: Path = PROJEKT) -> bool | None:
    """Hat der Mensch den Vertrauensdialog von Claude Code für diesen Ordner mit Ja beantwortet? Claude Code hält das in seiner
    eigenen Datei fest: ~/.claude.json, unter projects[<Ordner>].hasTrustDialogAccepted (so nennt es seine Dokumentation).
    Hier wird nur gelesen, und nur diese eine Angabe. Die Antwort gibt der Mensch im Dialog, nie die Einrichtung.
    True: bestätigt. False: keine Bestätigung gefunden. None: Die Datei lässt sich nicht lesen."""
    def gleich(pfad: str) -> str:       # Windows schreibt denselben Ordner mit / oder \ und in beliebiger Grossschreibung
        pfad = pfad.replace("\\", "/").rstrip("/")
        return pfad.lower() if WINDOWS else pfad

    gesucht = {gleich(str(projekt))}
    with contextlib.suppress(OSError, RuntimeError):
        gesucht.add(gleich(str(projekt.resolve())))
    orte = [Path.home() / ".claude.json"]
    eigen = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if eigen:
        orte.insert(0, Path(eigen).expanduser() / ".claude.json")
    unlesbar = False
    for ort in orte:
        if not ort.is_file():
            continue
        try:
            daten = json.loads(ort.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            unlesbar = True
            continue
        projekte = daten.get("projects") if isinstance(daten, dict) else None
        for pfad, eintrag in (projekte.items() if isinstance(projekte, dict) else ()):
            if gleich(str(pfad)) in gesucht and isinstance(eintrag, dict) and eintrag.get("hasTrustDialogAccepted") is True:
                return True
    return None if unlesbar else False


def windows_administrator() -> bool | None:
    """Läuft dieses WSL-Fenster unter Windows mit Administratorrechten? True oder False, None wenn es sich nicht feststellen
    lässt (kein WSL, oder Programme von Windows lassen sich von hier nicht starten). Gefragt wird das Windows-Programm whoami
    nach der Verbindlichkeitsstufe des Fensters: S-1-16-12288 heisst hoch (als Administrator gestartet), S-1-16-8192 mittel
    (gewöhnlich gestartet). Die Kennungen sind in jeder Sprache von Windows gleich.
    Wozu: In einem Fenster mit Administratorrechten zeigt WSL die Snaps nicht, die systemd eingehängt hat. So berichtet es
    microsoft/WSL#9097, dort zuletzt bestätigt im Januar 2026 (gelesen am 18.11.2026)."""
    if not wsl():
        return None
    try:
        antwort = subprocess.run([shutil.which("whoami.exe") or "/mnt/c/Windows/System32/whoami.exe", "/groups"],
                                 capture_output=True, timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (antwort.stdout or b"").decode("ascii", errors="replace")
    if "S-1-16-12288" in text or "S-1-16-16384" in text:
        return True
    return False if "S-1-16-8192" in text or "S-1-16-4096" in text else None


def _wslpath(schalter: str, pfad: str) -> str | None:
    """Fragt wslpath: -w übersetzt einen Ort von Linux in die Schreibweise von Windows, -u umgekehrt. None, wenn es nicht geht."""
    try:
        antwort = subprocess.run([shutil.which("wslpath") or "/usr/bin/wslpath", schalter, pfad], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    ort = antwort.stdout.strip()
    return ort if antwort.returncode == 0 and ort else None


def windows_laufwerk() -> Path | None:
    """Unter WSL: der Ort, an dem das Laufwerk C: von Windows eingehängt ist, meist /mnt/c. None ausserhalb von WSL und wenn
    das Laufwerk nicht eingehängt ist."""
    if not wsl():
        return None
    laufwerk = Path(_wslpath("-u", "C:\\") or "/mnt/c")
    return laufwerk if laufwerk.is_dir() else None


def windows_pfad(pfad: Path | str) -> str | None:
    """Unter WSL: derselbe Ort in der Schreibweise von Windows. Ein Ort auf einem Laufwerk von Windows heisst dann C:\\…, einer
    im Dateisystem von WSL \\\\wsl.localhost\\<Distribution>\\…. Der Ort muss bestehen. None, wenn es sich nicht übersetzen lässt."""
    return _wslpath("-w", str(pfad)) if wsl() else None


def windows_ordner(variable: str = "TEMP") -> Path | None:
    """Unter WSL: ein Ordner aus der Umgebung von Windows, etwa TEMP, so wie Linux ihn erreicht (/mnt/c/…). None, wenn sich
    Programme von Windows von hier nicht starten lassen oder der Ordner nicht zu erreichen ist.
    Gefragt wird cmd.exe mit /u: Die Antwort kommt dann in UTF-16, und ein Name mit Umlaut übersteht den Weg."""
    laufwerk = windows_laufwerk()
    if laufwerk is None:
        return None
    try:
        antwort = subprocess.run([shutil.which("cmd.exe") or str(laufwerk / "Windows" / "System32" / "cmd.exe"), "/u", "/c", "echo",
                                  f"%{variable}%"], capture_output=True, timeout=15, stdin=subprocess.DEVNULL, cwd=str(laufwerk))
    except (OSError, subprocess.SubprocessError):
        return None
    zeilen = (antwort.stdout or b"").decode("utf-16-le", errors="replace").lstrip("\ufeff").strip().splitlines()
    if not zeilen or zeilen[-1].strip().startswith("%"):      # eine Variable, die es nicht gibt, lässt cmd unverändert stehen
        return None
    ort = _wslpath("-u", zeilen[-1].strip())
    return Path(ort) if ort and Path(ort).is_dir() else None


def schritt_terminal(neues_terminal: tuple[str, ...] | list[str]) -> str:
    """Der Schritt «neues Terminal», mit dem, was erst dort gilt. Derselbe Wortlaut, ob der Arbeitsplatz schon einsatzbereit
    ist oder noch etwas fehlt."""
    text = (("Dieses WSL-Fenster schliessen und ein neues öffnen" if wsl() else "Dieses Terminal schliessen und ein neues öffnen")
            + f", dort in den Projektordner wechseln: cd {PROJEKT}   Erst im neuen Fenster gilt: " + " und ".join(neues_terminal) + ".")
    # Eine neue Gruppe gilt ab der nächsten Anmeldung, und ein Snap ist erst in einem Fenster zu sehen, das nach ihm geöffnet wurde.
    # Unter WSL ist das nicht in jedem Fall schon das nächste Fenster: Dann hilft es, WSL ganz neu zu starten.
    proben = []
    if any("Gruppe docker" in grund for grund in neues_terminal):
        proben.append("docker ps meldet dort «permission denied»")
    if any("Chromium" in grund for grund in neues_terminal):
        proben.append(f"{SETUP} meldet Chromium dort wieder so")
        if wsl():       # die bekannte Ursache dafür, dass ein WSL-Fenster einen eingehängten Snap nicht sieht: siehe windows_administrator()
            text += (" Das neue Fenster gewöhnlich öffnen, nicht über «Als Administrator ausführen»: In Fenstern mit Administratorrechten "
                     "zeigt WSL keine Snaps (ein bekannter Fehler von WSL).")
    if wsl() and proben:
        text += " Reicht das neue Fenster nicht (" + ", oder ".join(proben) + "): in PowerShell wsl --shutdown ausführen und WSL neu öffnen."
    return text


def schritt_ordner(ordner: bool | None) -> str:
    """Der Schritt «Projektordner in Claude Code bestätigen». None: Ob es schon geschehen ist, liess sich nicht ablesen."""
    return (("Falls noch nicht geschehen: im " if ordner is None else "Im ")
            + "Projektordner einmal Claude Code starten, mit dem Befehl: claude   Claude Code fragt, ob es dem Ordner "
            "vertrauen soll. Mit Ja bestätigen, dann mit /exit beenden. " + OHNE_VERTRAUEN)


def weiter(neues_terminal: tuple[str, ...] | list[str] = (), ordner: bool | None = None) -> list[str]:
    """Was nach der Einrichtung zu tun ist, vollständig und in der Reihenfolge, in der es zu tun ist: vom Terminal bis zu den
    Ergebnissen. Niemand soll einen Schritt erraten müssen.

    neues_terminal   was erst in einem neuen Terminal gilt (leer: Dieses Terminal genügt)
    ordner           True: Claude Code vertraut dem Projektordner schon, der Schritt entfällt. False: keine Bestätigung
                     gefunden. None: unbekannt, der Schritt steht mit «falls noch nicht geschehen» da. Siehe ordner_vertraut()."""
    schritte: list[str] = []
    if neues_terminal:
        schritte.append(schritt_terminal(neues_terminal))
    if not ordner:
        schritte.append(schritt_ordner(ordner))
    schritte.append(f"Oberfläche starten: {PY} tools/oberflaeche.py   "
                    + ("Der Browser von Windows öffnet sich von selbst." if wsl() else "Der Browser öffnet sich von selbst.")
                    + " Öffnet sich keiner, steht die Adresse im Terminal: einmal im Browser öffnen.")
    return schritte + list(IN_DER_OBERFLAECHE)


def proxy_zeigen(adresse: str) -> str:
    """Die Adresse eines Proxys für die Anzeige, ein Passwort darin unkenntlich."""
    return re.sub(r"(^|://)([^:/@\s]+):[^@/\s]*@", r"\1\2:***@", adresse)


def proxy_ziel(adresse: str) -> tuple[str, int] | None:
    """Rechner und Port, unter denen ein Proxy erreichbar sein muss. None, wenn sich die Adresse nicht lesen lässt."""
    try:
        teile = urlsplit(adresse if "://" in adresse else "http://" + adresse)
        port = teile.port or {"http": 80, "https": 443}.get(teile.scheme, 1080)
    except ValueError:
        return None
    return (teile.hostname, port) if teile.hostname else None


def proxy_ist_tor(adresse: str) -> bool:
    """Zeigt die Adresse auf Tor auf diesem Rechner (Port 9050)?"""
    ziel = proxy_ziel(adresse)
    return ziel is not None and ziel[0] in ("127.0.0.1", "localhost", "::1") and ziel[1] == 9050


def proxy_antwortet(adresse: str, zeit: float = 1.5) -> bool | None:
    """Nimmt der Proxy Verbindungen an? None: Die Adresse lässt sich nicht lesen. Geöffnet und gleich wieder geschlossen
    wird nur eine Verbindung zum Proxy selbst. Hindurch geht nichts."""
    ziel = proxy_ziel(adresse)
    if ziel is None:
        return None
    try:
        with socket.create_connection(ziel, timeout=zeit):
            return True
    except OSError:
        return False


def systemd() -> bool:
    """Läuft dieses System mit systemd? Unter WSL und in Containern ist das nicht selbstverständlich."""
    return Path("/run/systemd/system").is_dir()


TOR_ORTE = ("/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor")
OHNE_PROXY = f"Oder ohne Proxy arbeiten: {SETUP}, dort «Einstellungen ändern» und «Proxy»."


def tor_installiert() -> bool:
    """Liegt das Programm tor auf diesem Rechner? Der PATH kennt /usr/sbin nicht bei jedem Konto, deshalb auch die festen Orte."""
    return bool(shutil.which("tor")) or any(Path(ort).is_file() for ort in TOR_ORTE)


def tor_starten_befehl() -> str:
    """So startet ein Mensch Tor auf diesem System von Hand."""
    if sys.platform == "darwin":
        return "brew services start tor"
    if systemd():
        return "sudo systemctl start tor"
    return "sudo service tor start"


def proxy_rat(adresse: str) -> str:
    """Was zu tun ist, wenn der Proxy nicht antwortet. Bei Tor auf diesem Rechner je nachdem, ob es nur nicht läuft oder ganz fehlt."""
    if not proxy_ist_tor(adresse):
        return f"Den Proxy starten oder seine Adresse prüfen. {OHNE_PROXY}"
    if tor_installiert():
        return f"Tor ist auf diesem Rechner installiert, läuft aber nicht. Starten: {tor_starten_befehl()}   {OHNE_PROXY}"
    return (f"Tor ist auf diesem Rechner nicht installiert. {SETUP} ausführen und «Prüfen und auffrischen» wählen: Die Einrichtung "
            f"installiert und startet Tor, oder sie sagt, warum sie es nicht kann. {OHNE_PROXY}")


def _genau(verbindung: socket.socket, anzahl: int) -> bytes:
    daten = b""
    while len(daten) < anzahl:
        stueck = verbindung.recv(anzahl - len(daten))
        if not stueck:
            break
        daten += stueck
    return daten


def tor_verbindet(adresse: str = TOR_PROXY, zeit: float = 15.0, ziel: tuple[str, int] = TOR_PROBE) -> bool:
    """Baut Tor schon Verbindungen ins Netz auf? Der offene Port allein sagt das nicht: Kurz nach dem Start braucht Tor
    bis zu zwei Minuten. Die Probe öffnet über den SOCKS-Port eine Verbindung zu einem bekannten Rechner und schliesst sie
    wieder, ohne etwas zu senden."""
    proxy = proxy_ziel(adresse)
    if proxy is None:
        return False
    try:
        name = ziel[0].encode("idna")
        with socket.create_connection(proxy, timeout=min(zeit, 5.0)) as s:
            s.settimeout(zeit)
            s.sendall(b"\x05\x01\x00")                      # SOCKS5, eine Methode: ohne Anmeldung
            if _genau(s, 2) != b"\x05\x00":
                return False
            # Verbinden mit einem Namen, nicht mit einer Adresse: Tor löst ihn selbst auf, dieser Rechner fragt kein DNS
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + ziel[1].to_bytes(2, "big"))
            antwort = _genau(s, 4)
            return len(antwort) == 4 and antwort[1] == 0
    except (OSError, UnicodeError, ValueError):
        return False


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
