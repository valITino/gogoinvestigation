#!/usr/bin/env python3
"""Richtet den OSINT-Ermittlungsarbeitsplatz ein. Beliebig oft wiederholbar.

Aufruf über die Startskripte. Sie sorgen zuerst für ein brauchbares Python und übergeben dann hierher:

    ./setup.sh [Optionen]         Linux, macOS, WSL
    .\\setup.cmd [Optionen]        Windows (startet setup.ps1)

Im Terminal führt ein Assistent durch die Einrichtung. Er fragt nach Mythos, Schlüsseln, Proxy und Diensten,
zeigt eine Übersicht und richtet erst nach der Bestätigung ein. Ohne Terminal (CI, Skript, Umleitung in eine
Datei) oder mit --ohne-rueckfragen läuft alles ohne Fragen durch. Dann gelten die Optionen und die Werte aus .env.

Optionen:
    --ohne-rueckfragen        nichts fragen (für Skripte und das Ausrollen auf viele Arbeitsplätze). Kurz: --ja, -y
    --schlicht                Fragen als nummerierte Listen statt mit Pfeiltasten, ohne Laufanzeige
                              (Bildschirmleser, sehr alte Terminals)
    --vorschau                Fragen stellen und die Übersicht zeigen, aber nichts verändern
    --nur-pruefen             nur zeigen, was vorhanden ist und was fehlt. Es wird nichts verändert.
    --nichts-installieren     nichts am System installieren (Pakete, Claude Code), nur das Projekt einrichten
    --docker-installieren     Docker mitinstallieren (Debian, Ubuntu, Kali; braucht root oder sudo)
    --ohne-docker             Web-Check und Robin auslassen
    --ohne-webcheck           nur Web-Check auslassen
    --ohne-robin              nur Robin (Dark Web) auslassen
    --mythos                  erklären: Dieses Konto darf Claude Mythos 5.2 nutzen. Die Ermittlung schaltet dann
                              von selbst darauf um, der Abschluss bleibt auf Claude Fable 5.2.
    --ohne-mythos             die Erklärung zurücknehmen: alles läuft auf Claude Fable 5.2
    --env-von DATEI           Schlüssel aus einer vorbereiteten Datei nach .env übernehmen
    --testen                  am Ende je eingerichteter Quelle eine harmlose Testabfrage senden
    --hilfe                   diese Hilfe

Im Assistenten sind die Optionen die Vorgaben der Fragen. Auf einem schon eingerichteten Arbeitsplatz
wird mit einer Option, die etwas einstellt (etwa --mythos), nicht nachgefragt.

Ablauf:
    1. Voraussetzungen prüfen und Fehlendes installieren (Python-venv, Claude Code, pdftotext,
       unter Windows Git for Windows)
    2. Python-Umgebung .venv anlegen, Pakete installieren
    3. Schlüsseldatei .env und Ordner anlegen
    4. Web-Check starten und Robin-Abbild laden, wenn Docker läuft
    5. Claude Code: MCP-Server freischalten, Mythos freischalten (wenn erklärt), Anmeldung prüfen
    6. Musterfall bauen und Einrichtung prüfen
    Auf Wunsch danach: Anmeldung bei Claude Code, Testabfragen an die Quellen

Rückgabewert 0: einsatzbereit. 1: etwas Nötiges fehlt oder ist fehlgeschlagen. 2: falscher Aufruf.
130: abgebrochen.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("FEHLER: Python %d.%d ist zu alt. Nötig ist 3.10 oder neuer." % sys.version_info[:2])

import argparse  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import urllib.request  # noqa: E402
from pathlib import Path  # noqa: E402
from urllib.parse import urlsplit  # noqa: E402

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402
from gateway.plattform import AUS, FEHLT, GUT, NEU, PY, SETUP, WINDOWS  # noqa: E402
from gateway.quellen import QUELLEN  # noqa: E402
from tools._oberflaeche import Abbruch, Oberflaeche  # noqa: E402

MODELLE = {"fable": "claude-fable-5-2", "mythos": "claude-mythos-5-2"}
JA, NEIN = {"ja", "j", "yes", "y", "true", "1", "an"}, {"nein", "n", "no", "false", "0", "aus"}
CLAUDE_MIN = (2, 1, 295)        # ab dieser Version sperrt Claude Code, wenn der Wächter-Hook selbst ausfällt
LOGS = Path(tempfile.gettempdir()) / "osint-setup"
VENV = plattform.venv_python(PROJEKT)
TOR = "socks5h://127.0.0.1:9050"
SCHLUESSELQUELLEN = tuple(q for q in QUELLEN if q.env)     # Quellen, die einen Schlüssel brauchen
ui = Oberflaeche()

# Paketnamen je Paketverwaltung
PAKETE = {
    "venv": {"apt": ["python3-venv"], "dnf": ["python3-pip"], "yum": ["python3-pip"], "pacman": ["python-pip"],
             "zypper": ["python3-pip"], "apk": ["py3-pip"]},
    "pdftotext": {"apt": ["poppler-utils"], "dnf": ["poppler-utils"], "yum": ["poppler-utils"], "pacman": ["poppler"],
                  "zypper": ["poppler-tools"], "apk": ["poppler-utils"], "brew": ["poppler"],
                  "winget": ["oschwartz10612.Poppler"]},
    "git": {"winget": ["Git.Git"]},
}
INSTALLIEREN = {
    "apt": ["apt-get", "install", "-y", "--no-install-recommends"], "dnf": ["dnf", "install", "-y"],
    "yum": ["yum", "install", "-y"], "pacman": ["pacman", "-S", "--noconfirm", "--needed"],
    "zypper": ["zypper", "--non-interactive", "install"], "apk": ["apk", "add"], "brew": ["brew", "install"],
}


class Stand:
    """Was diese Einrichtung getan hat und was offen bleibt."""

    def __init__(self) -> None:
        self.neu: list[str] = []            # installiert oder angelegt
        self.offen: list[str] = []          # das muss der Mensch noch tun
        self.noetig: list[str] = []         # fehlt und verhindert den Betrieb
        self.neues_terminal: list[str] = []     # was erst in einem neuen Terminal gilt
        self.apt_aktuell = False
        self.sudo_gemeldet = False
        self.assistent = False              # der Mensch hat die Fragen des Assistenten beantwortet


stand = Stand()
HINWEIS_ANMELDEN = ("Bei Claude Code anmelden: im Projektordner 'claude' starten und der Anmeldung im Browser folgen. "
                    "(Läuft Claude Code bei euch über einen API-Schlüssel oder Cloud-Anbieter, entfällt das.)")


# --------------------------------------------------------------------------- Ausgabe und Befehle

def zeile(zeichen: str, was: str, wie: str = "") -> None:
    ui.zeile(zeichen, was, wie)


def schritt(nr: int, titel: str) -> None:
    ui.schritt(nr, 6, titel)


def lauf(befehl: list[str], zeit: int = 900, log: str | None = None, env: dict | None = None,
         cwd: str | None = None, anzeige: str | None = None) -> tuple[int, str]:
    """Führt einen Befehl aus. Gibt Rückgabewert und Ausgabe zurück, 127 wenn es das Programm nicht gibt.
    Mit anzeige läuft währenddessen eine Zeile mit, die sagt, was gerade geschieht."""
    if befehl[:1] == ["sudo"] and befehl[1:2] != ["-n"]:
        anzeige = None      # sudo fragt vielleicht nach dem Passwort: Die Laufanzeige würde die Frage übermalen
    try:
        with ui.arbeit(anzeige):
            r = subprocess.run(befehl, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=zeit,
                               env=env, cwd=cwd, stdin=subprocess.DEVNULL)
        code, text = r.returncode, (r.stdout + r.stderr).strip()
    except FileNotFoundError:
        code, text = 127, f"Programm nicht gefunden: {befehl[0]}"
    except subprocess.TimeoutExpired:
        code, text = 124, f"Nach {zeit} Sekunden abgebrochen: {' '.join(befehl[:3])} …"
    except OSError as e:
        code, text = 126, f"{type(e).__name__}: {e}"
    if log:
        LOGS.mkdir(parents=True, exist_ok=True)
        with open(LOGS / log, "a", encoding="utf-8") as f:
            f.write(f"$ {' '.join(befehl)}\n{text}\n[Rückgabewert {code}]\n\n")
    return code, text


def letzte_zeilen(text: str, n: int = 4) -> str:
    return "\n".join("      " + z for z in text.strip().splitlines()[-n:])


# --------------------------------------------------------------------------- System

def system() -> dict:
    """Betriebssystem und Paketverwaltung."""
    if WINDOWS:
        return {"art": "windows", "name": f"Windows {platform.release()} (Build {platform.version()})",
                "paketverwaltung": "winget" if shutil.which("winget") else None, "wsl": False}
    if sys.platform == "darwin":
        return {"art": "macos", "name": f"macOS {platform.mac_ver()[0]}",
                "paketverwaltung": "brew" if shutil.which("brew") else None, "wsl": False}
    name = "Linux"
    try:
        for z in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if z.startswith("PRETTY_NAME="):
                name = z.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    wsl = "microsoft" in platform.release().lower() or bool(os.environ.get("WSL_DISTRO_NAME"))
    verwaltung = next((kurz for kurz, programm in (("apt", "apt-get"), ("dnf", "dnf"), ("yum", "yum"), ("pacman", "pacman"),
                                                   ("zypper", "zypper"), ("apk", "apk")) if shutil.which(programm)), None)
    return {"art": "linux", "name": name + (" unter WSL" if wsl else ""), "paketverwaltung": verwaltung, "wsl": wsl}


def root_praefix(wofuer: str) -> list[str] | None:
    """Vorspann für Befehle, die root brauchen: [] als root, ['sudo', …] mit sudo, None wenn es nicht geht."""
    if WINDOWS or os.geteuid() == 0:
        return []
    if not shutil.which("sudo"):
        return None
    if lauf(["sudo", "-n", "true"], 15)[0] == 0:
        return ["sudo", "-n"]
    if sys.stdin.isatty():
        if not stand.sudo_gemeldet:
            stand.sudo_gemeldet = True
            ui.text(f"Für {wofuer} braucht es einmal euer Passwort (sudo).", einzug=4)
            subprocess.call(["sudo", "-v"])     # fragt jetzt, in Ruhe, bevor etwas anderes auf dem Bildschirm läuft
            if lauf(["sudo", "-n", "true"], 15)[0] == 0:
                return ["sudo", "-n"]
        return ["sudo"]
    return None


def paket_installieren(was: str, sysinfo: dict, namen: dict[str, list[str]] | None = None) -> tuple[bool, str]:
    """Installiert ein Systempaket. Gibt (versucht, Hinweis) zurück. Ob es geklappt hat, prüft der Aufrufer."""
    verwaltung = sysinfo["paketverwaltung"]
    pakete = (namen or PAKETE[was]).get(verwaltung or "")
    if not verwaltung or not pakete:
        return False, "keine passende Paketverwaltung gefunden"
    anzeige = f"{' '.join(pakete)} wird installiert ({verwaltung})"
    if verwaltung == "winget":
        for paket in pakete:
            basis = ["winget", "install", "--id", paket, "-e", "--source", "winget", "--silent",
                     "--accept-package-agreements", "--accept-source-agreements"]
            # ältere winget-Versionen kennen --disable-interactivity nicht: dann ohne
            if lauf(basis + ["--disable-interactivity"], 900, "pakete.log", anzeige=anzeige)[0] != 0:
                lauf(basis, 900, "pakete.log", anzeige=anzeige)
        return True, "winget install --id " + " ".join(pakete)
    if verwaltung == "brew":
        if os.geteuid() == 0:
            return False, "Homebrew läuft nicht als root: brew install " + " ".join(pakete)
        lauf(INSTALLIEREN["brew"] + pakete, 1800, "pakete.log", anzeige=anzeige)
        return True, "brew install " + " ".join(pakete)
    befehl = INSTALLIEREN[verwaltung] + pakete
    vor = root_praefix(f"die Installation von {' '.join(pakete)}")
    if vor is None:
        return False, "sudo " + " ".join(befehl)
    umgebung = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    if verwaltung == "apt" and not stand.apt_aktuell:
        lauf(vor + ["apt-get", "update", "-qq"], 600, "pakete.log", umgebung, anzeige="Paketlisten werden aktualisiert (apt)")
        stand.apt_aktuell = True
    # sudo gibt eine veränderte Umgebung nicht weiter, deshalb über env
    code, _ = lauf(vor + (["env", "DEBIAN_FRONTEND=noninteractive"] if vor else []) + befehl, 1800, "pakete.log", umgebung,
                   anzeige=anzeige)
    return True, ("sudo " if vor else "") + " ".join(befehl) + ("" if code == 0 else f"   (Details: {LOGS / 'pakete.log'})")


# --------------------------------------------------------------------------- Schritt 1: Voraussetzungen

def git_bash() -> str | None:
    """Git Bash unter Windows. Claude Code führt darin die Hooks und Shell-Befehle aus."""
    kandidaten = [os.environ.get("CLAUDE_CODE_GIT_BASH_PATH", "")]
    for ort in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        if os.environ.get(ort):
            kandidaten.append(str(Path(os.environ[ort]) / "Git" / "bin" / "bash.exe"))
    if os.environ.get("LOCALAPPDATA"):
        kandidaten.append(str(Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Git" / "bin" / "bash.exe"))
    git = shutil.which("git")
    if git:
        kandidaten.append(str(Path(git).resolve().parents[1] / "bin" / "bash.exe"))
    return next((k for k in kandidaten if k and Path(k).is_file()), None)


def claude_stand() -> tuple[str | None, tuple[int, ...] | None, str]:
    pfad = plattform.programm("claude")
    if not pfad:
        return None, None, ""
    code, text = lauf([pfad, "--version"], 60)
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return pfad, (tuple(map(int, m.groups())) if m and code == 0 else None), (text.splitlines() or [""])[0]


def claude_installieren() -> str | None:
    """Installiert Claude Code mit dem Installer des Herstellers. Gibt None zurück oder die Fehlermeldung."""
    if WINDOWS:
        # Ohne PSModulePath: Aus PowerShell 7 heraus erbt Windows PowerShell 5.1 sonst dessen Module und
        # kann die eigenen Befehle nicht mehr laden. Der Installer bräche dann ab.
        umgebung = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
        code, text = lauf(["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                           "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                           "irm https://claude.ai/install.ps1 | iex"], 900, "claude.log", umgebung,
                          anzeige="Claude Code wird installiert")
    else:
        LOGS.mkdir(parents=True, exist_ok=True)
        skript = LOGS / "claude-install.sh"
        if shutil.which("curl"):
            code, text = lauf(["curl", "-fsSL", "https://claude.ai/install.sh", "-o", str(skript)], 120, "claude.log",
                              anzeige="Installer von Claude Code wird geladen")
        else:
            try:
                with urllib.request.urlopen("https://claude.ai/install.sh", timeout=60) as antwort:
                    skript.write_bytes(antwort.read())
                code, text = 0, ""
            except OSError as e:
                code, text = 1, f"{type(e).__name__}: {e}"
        if code != 0:
            return f"Der Installer liess sich nicht laden ({text.splitlines()[-1] if text else 'kein Netz?'}). Proxy prüfen (HTTPS_PROXY)."
        anfang = skript.read_bytes()[:200].lstrip()
        if not anfang.startswith(b"#!"):
            return "claude.ai lieferte kein Installationsskript (Region, Proxy oder Filter?)."
        code, text = lauf(["bash", str(skript)], 900, "claude.log", anzeige="Claude Code wird installiert")
    if code != 0:
        return f"Der Installer meldet einen Fehler. Details: {LOGS / 'claude.log'}"
    return None


def docker_stand() -> dict:
    """installiert, laeuft, compose (Befehl als Liste oder None), vor (Vorspann sudo, falls nur so erreichbar)."""
    d = {"installiert": bool(shutil.which("docker")), "laeuft": False, "compose": None, "vor": []}
    if not d["installiert"]:
        return d
    if lauf(["docker", "info"], 30)[0] == 0:
        d["laeuft"] = True
    elif not WINDOWS and os.geteuid() != 0 and shutil.which("sudo") and lauf(["sudo", "-n", "docker", "info"], 30)[0] == 0:
        d["laeuft"], d["vor"] = True, ["sudo", "-n"]       # Dienst läuft, aber das Konto ist noch nicht in der Gruppe docker
    if lauf(d["vor"] + ["docker", "compose", "version"], 30)[0] == 0:
        d["compose"] = d["vor"] + ["docker", "compose"]
    elif shutil.which("docker-compose"):
        d["compose"] = d["vor"] + ["docker-compose"]
    return d


def docker_installieren(sysinfo: dict) -> str:
    """Installiert Docker aus den Paketquellen der Distribution und startet den Dienst. Gibt einen Hinweis zurück."""
    if sysinfo["paketverwaltung"] != "apt":
        return "Die automatische Installation gibt es für Debian, Ubuntu und Kali. Sonst: https://docs.docker.com/engine/install/"
    versucht, befehl = paket_installieren("docker", sysinfo, {"apt": ["docker.io"]})
    if not versucht:
        return f"Ohne root oder sudo nicht möglich. Von Hand: {befehl}"
    for compose in ("docker-compose-v2", "docker-compose-plugin", "docker-compose"):    # je nach Distribution heisst es anders
        paket_installieren("docker", sysinfo, {"apt": [compose]})
        if lauf(["docker", "compose", "version"], 30)[0] == 0 or shutil.which("docker-compose"):
            break
    vor = root_praefix("den Start von Docker") or []
    if Path("/run/systemd/system").is_dir():
        lauf(vor + ["systemctl", "enable", "--now", "docker"], 120, "docker.log")
    else:
        lauf(vor + ["service", "docker", "start"], 120, "docker.log")
    benutzer = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
    if benutzer and benutzer != "root":
        lauf(vor + ["usermod", "-aG", "docker", benutzer], 30, "docker.log")
        return f"Konto {benutzer} in die Gruppe docker aufgenommen. Das gilt ab der nächsten Anmeldung."
    return ""


def voraussetzungen(a: argparse.Namespace, sysinfo: dict) -> dict:
    schritt(1, "Voraussetzungen")
    darf = not (a.nur_pruefen or a.nichts_installieren)
    v = sys.version_info
    zeile(GUT, "Python", f"{v.major}.{v.minor}.{v.micro}   ({sys.executable})")

    # venv und pip: unter Debian und Ubuntu ein eigenes Paket
    def venv_ok() -> bool:
        return lauf([sys.executable, "-c", "import ensurepip, venv"], 60)[0] == 0
    if venv_ok():
        zeile(GUT, "venv und pip", "vorhanden")
    else:
        versucht, hinweis = paket_installieren("venv", sysinfo) if darf else (False, "")
        if versucht and not venv_ok() and sysinfo["paketverwaltung"] == "apt":     # Python neben dem der Distribution
            paket_installieren("venv", sysinfo, {"apt": [f"python{v.major}.{v.minor}-venv"]})
        if venv_ok():
            zeile(NEU, "venv und pip", "installiert")
            stand.neu.append("Systempaket für venv und pip")
        else:
            paket = (PAKETE["venv"].get(sysinfo["paketverwaltung"] or "") or ["python3-venv"])[0]
            zeile(FEHLT, "venv und pip", f"fehlt (Paket {paket})")
            stand.noetig.append("venv und pip")
            stand.offen.append(f"Paket für venv installieren: {hinweis or 'sudo apt install python3-venv'}, dann {SETUP} erneut")

    # Git for Windows: Claude Code führt Hooks und Befehle in Git Bash aus
    if WINDOWS:
        bash = git_bash()
        if not bash and darf:
            paket_installieren("git", sysinfo)
            bash = git_bash()
            if bash:
                stand.neu.append("Git for Windows")
        if bash:
            zeile(NEU if "Git for Windows" in stand.neu else GUT, "Git for Windows", f"Git Bash: {bash}")
        else:
            zeile(FEHLT, "Git for Windows", "fehlt. Ohne Git Bash laufen Wächter und Protokoll nicht.")
            stand.noetig.append("Git for Windows")
            stand.offen.append(f"Git for Windows installieren (winget install --id Git.Git -e), dann {SETUP} erneut")

    # Claude Code
    pfad, version, text = claude_stand()
    frisch = False
    if not pfad and darf:
        fehler = claude_installieren()
        pfad, version, text = claude_stand()
        frisch = bool(pfad)
        if not pfad:
            zeile(FEHLT, "Claude Code", fehler or "nach der Installation nicht gefunden")
    if pfad:
        hinweis = text or "installiert"
        if version and version < CLAUDE_MIN:
            hinweis += "   veraltet: 'claude update' ausführen"
            stand.offen.append(f"Claude Code aktualisieren (claude update). Erst ab {'.'.join(map(str, CLAUDE_MIN))} sperrt es "
                               "Werkzeugaufrufe, wenn der Wächter selbst ausfällt.")
        zeile(NEU if frisch else GUT, "Claude Code", hinweis)
        if frisch:
            stand.neu.append("Claude Code")
        if not shutil.which("claude"):
            ordner = Path(pfad).parent
            stand.neues_terminal.append(f"der Befehl 'claude' (liegt in {ordner}"
                                        + (")" if WINDOWS else f'. Falls er dann noch fehlt: export PATH="{ordner}:$PATH" in ~/.bashrc oder ~/.zshrc)'))
    else:
        if not darf:
            zeile(FEHLT, "Claude Code", "nicht installiert")
        stand.noetig.append("Claude Code")
        stand.offen.append("Claude Code installieren: "
                           + ("irm https://claude.ai/install.ps1 | iex   (in PowerShell)" if WINDOWS
                              else "curl -fsSL https://claude.ai/install.sh | bash"))

    # pdftotext: nur nötig, wenn Rapporte als PDF kommen
    if plattform.programm("pdftotext"):
        zeile(GUT, "pdftotext", "PDF-Dokumente können aufgenommen werden")
    else:
        versucht, hinweis = paket_installieren("pdftotext", sysinfo) if darf else (False, "")
        if plattform.programm("pdftotext"):
            zeile(NEU, "pdftotext", "installiert")
            stand.neu.append("pdftotext (Poppler)")
        else:
            paket = (PAKETE["pdftotext"].get(sysinfo["paketverwaltung"] or "") or ["poppler-utils"])[0]
            zeile(AUS, "pdftotext", f"fehlt (Paket {paket}). PDF-Rapporte lassen sich so nicht aufnehmen, .txt .md .docx schon.")

    # Browser: nur für die Umwandlung der Ergebnisse in PDF
    from tools.pdf import browser_finden
    browser = browser_finden()
    zeile(GUT if browser else AUS, "Browser für PDF",
          Path(browser).name if browser else "kein Chrome, Chromium, Edge oder Brave. PDF dann über 'Drucken' im Browser.")

    # Docker: für Web-Check und Robin
    docker = {"installiert": False, "laeuft": False, "compose": None, "vor": []}
    if a.ohne_docker:
        zeile(AUS, "Docker", "übersprungen (--ohne-docker)")
        return docker
    docker = docker_stand()
    if not docker["installiert"] and a.docker_installieren and not a.nur_pruefen:
        if sysinfo["art"] != "linux":
            zeile(AUS, "Docker", "--docker-installieren gibt es nur unter Linux. Hier Docker Desktop von Hand installieren.")
        else:
            hinweis = docker_installieren(sysinfo)
            docker = docker_stand()
            if docker["installiert"]:
                stand.neu.append("Docker")
            if hinweis:
                stand.offen.append(hinweis)
    if docker["laeuft"]:
        zeile(NEU if "Docker" in stand.neu else GUT, "Docker",
              "läuft" + (", Zugriff vorerst über sudo" if docker["vor"] else "") + ("" if docker["compose"] else ", aber Compose fehlt"))
        if not docker["compose"]:
            stand.offen.append("Docker Compose installieren (Paket docker-compose-v2 oder docker-compose-plugin), dann "
                               f"{SETUP} erneut. Ohne Compose bleibt Web-Check aus.")
    elif docker["installiert"]:
        zeile(AUS, "Docker", "installiert, aber der Dienst läuft nicht oder euer Konto hat keinen Zugriff")
        if not stand.assistent:     # im Assistenten war «ohne Docker weiter» eine bewusste Entscheidung
            stand.offen.append(("Docker Desktop starten" if sysinfo["art"] != "linux" or sysinfo["wsl"] else
                                "Docker starten (sudo systemctl start docker) und das Konto in die Gruppe docker aufnehmen")
                               + f", dann {SETUP} erneut. Bis dahin bleiben Web-Check und Robin aus.")
    else:
        if sysinfo["art"] == "linux" and sysinfo["paketverwaltung"] == "apt":
            wie = f"Nachholen: {SETUP} --docker-installieren"
        elif sysinfo["art"] == "linux":
            wie = "Installation: https://docs.docker.com/engine/install/"
        else:
            wie = "Docker Desktop von Hand installieren (Lizenz beachten, siehe README)"
        zeile(AUS, "Docker", f"nicht installiert. Web-Check und Robin bleiben aus, alles andere läuft. {wie}")
    return docker


# --------------------------------------------------------------------------- Schritt 2: Python-Umgebung

def python_umgebung() -> bool:
    schritt(2, "Python-Umgebung")
    fremd = PROJEKT / ".venv" / ("bin/python" if WINDOWS else "Scripts/python.exe")
    if fremd.exists() and not VENV.exists():
        woher = "unter Linux oder WSL" if WINDOWS else "unter Windows"
        zeile(FEHLT, ".venv", f"Dieser Ordner wurde {woher} eingerichtet. Beide Einrichtungen vertragen sich nicht im selben Ordner.")
        stand.noetig.append(".venv")
        stand.offen.append("Für dieses System einen eigenen Klon des Repositories verwenden. "
                           f"Oder den Ordner .venv löschen und {SETUP} erneut starten (die andere Einrichtung ist dann weg).")
        return False
    if VENV.is_file() and lauf([str(VENV), "-c", "import sys"], 60)[0] == 0:
        zeile(GUT, ".venv", "vorhanden")
    else:
        code, text = lauf([sys.executable, "-m", "venv", "--clear", str(PROJEKT / ".venv")], 600, "venv.log",
                          anzeige="Python-Umgebung .venv wird angelegt")
        if code != 0 or not VENV.is_file():
            zeile(FEHLT, ".venv", "liess sich nicht anlegen")
            print(letzte_zeilen(text))
            stand.noetig.append(".venv")
            stand.offen.append(f"Meldung oben beheben, dann {SETUP} erneut. Vollständig: {LOGS / 'venv.log'}")
            return False
        zeile(NEU, ".venv", "angelegt")
        stand.neu.append("Python-Umgebung .venv")

    anforderungen = PROJEKT / "requirements.txt"
    marke = PROJEKT / ".venv" / ".osint-pakete"
    soll = hashlib.sha256(anforderungen.read_bytes()).hexdigest()
    pruefung = [str(VENV), "-c", "import mcp, httpx, pydantic, socksio, zoneinfo; zoneinfo.ZoneInfo('Europe/Zurich')"]
    if marke.is_file() and marke.read_text(encoding="utf-8").strip() == soll and lauf(pruefung, 120)[0] == 0:
        zeile(GUT, "Pakete", "mcp, httpx, pydantic sind installiert")
        return True
    befehl = [str(VENV), "-m", "pip", "install", "--disable-pip-version-check", "--quiet", "-r", str(anforderungen)]
    code, text = lauf(befehl, 1800, "pip.log", anzeige="Pakete werden installiert (mcp, httpx, pydantic)")
    if code != 0:      # ein zweiter Versuch fängt kurze Netzstörungen ab
        code, text = lauf(befehl, 1800, "pip.log", anzeige="Pakete werden installiert, zweiter Versuch")
    if code != 0 or lauf(pruefung, 120)[0] != 0:
        zeile(FEHLT, "Pakete", "liessen sich nicht installieren")
        print(letzte_zeilen(text))
        stand.noetig.append("Python-Pakete")
        stand.offen.append("Internetzugang und Proxy prüfen (HTTPS_PROXY, bei eigener Zertifizierungsstelle PIP_CERT), "
                           f"dann {SETUP} erneut. Vollständig: {LOGS / 'pip.log'}")
        return False
    plattform.text_schreiben(marke, soll + "\n")
    zeile(NEU, "Pakete", "installiert (mcp, httpx, pydantic)")
    stand.neu.append("Python-Pakete")
    return True


# --------------------------------------------------------------------------- Schritt 3: Konfiguration

ZUWEISUNG = re.compile(r"^\s*(#\s*)?([A-Z][A-Z0-9_]*)\s*=(.*)$")


def env_lesen(datei: Path) -> dict[str, str]:
    werte: dict[str, str] = {}
    if datei.is_file():
        for z in datei.read_text(encoding="utf-8-sig").splitlines():
            m = ZUWEISUNG.match(z)
            if m and not m.group(1):
                wert = m.group(3).strip().strip("\"'")
                if wert:
                    werte[m.group(2)] = wert
    return werte


def env_setzen(datei: Path, werte: dict[str, str]) -> list[str]:
    """Trägt Werte in .env ein, an der Stelle, an der der Name schon steht. Ein leerer Wert nimmt die
    Einstellung zurück. Gibt die geänderten Namen zurück."""
    zeilen = datei.read_text(encoding="utf-8").splitlines()
    geaendert = []
    for name, wert in werte.items():
        aktiv = next((i for i, z in enumerate(zeilen) if (m := ZUWEISUNG.match(z)) and m.group(2) == name and not m.group(1)), None)
        auskommentiert = next((i for i, z in enumerate(zeilen) if (m := ZUWEISUNG.match(z)) and m.group(2) == name and m.group(1)), None)
        neu = f"{name}={wert}"
        if not wert and aktiv is None:
            continue                    # nichts da, was zurückzunehmen wäre
        if aktiv is not None:
            if zeilen[aktiv].strip() == neu:
                continue
            if not wert and auskommentiert is not None:
                del zeilen[aktiv]       # die auskommentierte Zeile der Vorlage bleibt als Gedächtnisstütze stehen
            else:
                zeilen[aktiv] = neu
        elif auskommentiert is not None:
            zeilen.insert(auskommentiert + 1, neu)
        else:
            zeilen.append(neu)
        geaendert.append(name)
    if geaendert:
        plattform.text_schreiben(datei, "\n".join(zeilen) + "\n")
    return geaendert


def nur_fuer_mich(datei: Path) -> None:
    """Schlüsseldatei nur für das eigene Konto lesbar machen."""
    if not WINDOWS:
        os.chmod(datei, 0o600)
        return
    konto = "\\".join(t for t in (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")) if t)
    if konto:
        lauf(["icacls", str(datei), "/inheritance:r", "/grant:r", f"{konto}:(F)"], 30, "env.log")


def aus_datei(quelle: Path) -> tuple[dict[str, str], list[str]]:
    """Einstellungen aus einer vorbereiteten Datei: (übernommene Werte, Namen die .env.example nicht kennt)."""
    vorlage = PROJEKT / ".env.example"
    bekannt = {m.group(2) for z in vorlage.read_text(encoding="utf-8").splitlines() if (m := ZUWEISUNG.match(z))}
    bekannt.add("OSINT_MYTHOS")
    alle = env_lesen(quelle)
    return {k: w for k, w in alle.items() if k in bekannt}, sorted(set(alle) - bekannt)


def konfiguration(a: argparse.Namespace) -> None:
    schritt(3, "Schlüsseldatei und Ordner")
    datei, vorlage = PROJEKT / ".env", PROJEKT / ".env.example"
    if datei.is_file():
        zeile(GUT, ".env", "vorhanden, bleibt erhalten")
    else:
        shutil.copyfile(vorlage, datei)
        nur_fuer_mich(datei)
        zeile(NEU, ".env", "aus .env.example angelegt, nur für euer Konto lesbar")
        stand.neu.append("Schlüsseldatei .env")
    if a.env_von:
        quelle = Path(a.env_von).expanduser()
        werte, fremd = aus_datei(quelle)
        geaendert = env_setzen(datei, werte)
        zeile(NEU if geaendert else GUT, "Übernahme", f"{len(geaendert)} Einstellung(en) aus {quelle.name} eingetragen"
              + (f": {', '.join(geaendert)}" if geaendert else " (alles schon aktuell)")
              + (f". Unbekannt und ausgelassen: {', '.join(fremd)}" if fremd else ""))
    if a.werte:         # Antworten aus dem Assistenten. Sie gelten vor der Datei. Werte erscheinen nie in der Ausgabe.
        geaendert = env_setzen(datei, a.werte)
        gesetzt = [n for n in geaendert if a.werte[n]]
        entfernt = [n for n in geaendert if not a.werte[n]]
        if geaendert:
            zeile(NEU, "Eingaben", "; ".join(t for t in (f"eingetragen: {', '.join(gesetzt)}" if gesetzt else "",
                                                           f"entfernt: {', '.join(entfernt)}" if entfernt else "") if t))
    for ordner in ("faelle", "protokoll/sitzungen"):
        (PROJEKT / ordner).mkdir(parents=True, exist_ok=True)
    gesetzt = env_lesen(datei)
    vorhanden = [q.name for q in SCHLUESSELQUELLEN if gesetzt.get(q.env)]
    ohne = len(QUELLEN) - len(SCHLUESSELQUELLEN)
    zeile(GUT if vorhanden else AUS, "Schlüssel", f"{len(vorhanden)} von {len(SCHLUESSELQUELLEN)} eingetragen"
          + ("" if len(vorhanden) == len(SCHLUESSELQUELLEN) else f". Jede Quelle ist für sich optional, {ohne} brauchen keinen Schlüssel."))
    if len(vorhanden) < len(SCHLUESSELQUELLEN) and not stand.assistent:     # im Assistenten war das eine bewusste Entscheidung
        stand.offen.append(f"Schlüssel eintragen: {SETUP} im Terminal starten und «Einstellungen ändern» wählen, oder direkt "
                           f"in .env. Welche fehlen, steht oben bei «Ohne Schlüssel». Danach testen: {PY} tools/pruefen.py --live")


# --------------------------------------------------------------------------- Schritt 4: Dienste

def dienste(a: argparse.Namespace, docker: dict) -> bool:
    """Startet Web-Check und lädt das Robin-Abbild. Gibt zurück, ob Robin bereitsteht."""
    schritt(4, "Web-Check und Robin (Docker)")
    if a.ohne_docker:
        zeile(AUS, "Docker", "übersprungen (--ohne-docker)")
        return False
    if not docker["laeuft"]:
        zeile(AUS, "Docker", "läuft nicht: Web-Check und Robin bleiben aus. Alles andere funktioniert.")
        return False
    env = {**os.environ, **{k: v for k, v in env_lesen(PROJEKT / ".env").items() if k in ("WEBCHECK_PORT", "ROBIN_IMAGE")}}
    if a.ohne_webcheck:
        zeile(AUS, "Web-Check", "übersprungen")
    elif docker["compose"]:
        code, text = lauf(docker["compose"] + ["-f", str(PROJEKT / "docker-compose.yml"), "up", "-d", "webcheck"], 1800, "docker.log", env,
                          anzeige="Web-Check wird gestartet (beim ersten Mal lädt Docker das Abbild)")
        if code == 0:
            zeile(GUT, "Web-Check", f"läuft auf 127.0.0.1:{env.get('WEBCHECK_PORT', '3000')}")
        else:
            zeile(AUS, "Web-Check", f"liess sich nicht starten (Port belegt? Dann WEBCHECK_PORT setzen). Details: {LOGS / 'docker.log'}")
    else:
        zeile(AUS, "Web-Check", "braucht Docker Compose")
    if a.ohne_robin:
        zeile(AUS, "Robin", "übersprungen")
        return False
    abbild = env.get("ROBIN_IMAGE") or "apurvsg/robin:latest"
    if lauf(docker["vor"] + ["docker", "image", "inspect", abbild], 60)[0] == 0:
        zeile(GUT, "Robin", f"Abbild bereit ({abbild})")
        return True
    if lauf(docker["vor"] + ["docker", "pull", abbild], 3600, "docker.log", anzeige=f"Robin-Abbild wird geladen ({abbild})")[0] == 0:
        zeile(NEU, "Robin", f"Abbild geladen ({abbild})")
        stand.neu.append("Robin-Abbild")
        return True
    zeile(AUS, "Robin", f"Abbild {abbild} liess sich nicht laden. Dark-Web-Suche bleibt aus. Details: {LOGS / 'docker.log'}")
    return False


# --------------------------------------------------------------------------- Schritt 5: Claude Code

# Modelle je Phase. Die Zuteilung steht fest in den Dateien des Projekts:
#
#   /ermittlung und die vier Analysten verlangen   claude-mythos-5-2    (model: im Kopf von Skill und Agenten)
#   gegenpruefer, rapportfuehrer, /abschlussrapport, /protokoll verlangen   claude-fable-5-2
#
# Ob Mythos tatsächlich läuft, entscheidet die Liste availableModels in den Einstellungen von Claude Code.
# Das Projekt lässt nur Fable 5.2 zu (.claude/settings.json). Verlangt ein Skill oder Agent ein Modell ausserhalb
# der Liste, übergeht Claude Code das und nimmt das Modell der Sitzung. Ohne weiteres Zutun läuft also alles auf
# Fable 5.2. Wer Mythos hat, erklärt das einmal (--mythos oder OSINT_MYTHOS=ja in .env). Die Einrichtung trägt
# Mythos dann in die lokale Liste ein (.claude/settings.local.json). Claude Code fügt die Listen zusammen, und von
# da an schalten Skill und Agenten von selbst um.

def mythos_wunsch(a: argparse.Namespace) -> bool | None:
    """Was zu Mythos erklärt wurde: True (vorhanden), False (nicht vorhanden), None (nichts gesagt, es bleibt wie es ist).
    Die Option gilt vor OSINT_MYTHOS aus .env."""
    if a.mythos and a.ohne_mythos:
        raise SystemExit("FEHLER: --mythos und --ohne-mythos schliessen sich aus.")
    if a.mythos or a.ohne_mythos:
        return bool(a.mythos)
    wert = env_lesen(PROJEKT / ".env").get("OSINT_MYTHOS", "").strip().lower()
    if not wert:
        return None
    if wert in JA | NEIN:
        return wert in JA
    raise SystemExit(f"FEHLER: OSINT_MYTHOS={wert} in .env ist weder ja noch nein.")


def einstellungen(datei: Path) -> dict:
    try:
        daten = json.loads(datei.read_text(encoding="utf-8"))
        return daten if isinstance(daten, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def kopfmodelle(muster: str) -> dict[str, str]:
    """Das Feld model aus dem Kopf der Agenten- oder Skill-Dateien. Fehlt es, gilt das Modell der Sitzung."""
    modelle = {}
    for datei in sorted((PROJEKT / ".claude").glob(muster)):
        m = re.search(r"^model:\s*(\S+)\s*$", datei.read_text(encoding="utf-8").split("---")[1], re.M)
        modelle[datei.parent.name if datei.name == "SKILL.md" else datei.stem] = m.group(1) if m else "inherit"
    return modelle


def agentenmodelle() -> dict[str, str]:
    return kopfmodelle("agents/*.md")


def skillmodelle() -> dict[str, str]:
    return kopfmodelle("skills/*/SKILL.md")


def erlaubt(modell: str, liste: list) -> bool:
    """Ob availableModels das Modell zulässt. Ein Eintrag ist eine Modell-ID, ein Versionsanfang
    (claude-fable-5 lässt auch 5.2 zu) oder eine Familie (fable). Eine leere Liste schränkt nichts ein."""
    if not liste:
        return True
    return any(modell == e or modell.startswith((e + "-", e + "[", f"claude-{e}-")) for e in liste if isinstance(e, str))


def modellzuteilung() -> dict:
    """Welches Modell in welcher Phase läuft, aus den Dateien gelesen, so wie Claude Code sie zusammensetzt:
    Die Listen availableModels aus Projekt, lokalen Einstellungen und Benutzerkonto werden zusammengefügt.
    (Verwaltete Einstellungen einer Organisation gingen vor. Die sieht dieses Werkzeug nicht.)"""
    projekt = einstellungen(PROJEKT / ".claude" / "settings.json")
    lokal = einstellungen(PROJEKT / ".claude" / "settings.local.json")
    konto = einstellungen(Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "settings.json")
    liste = [m for quelle in (projekt, lokal, konto) for m in (quelle.get("availableModels") or []) if isinstance(m, str)]
    sitzung = lokal.get("model") or projekt.get("model") or ""

    def wirksam(verlangt: str) -> str:
        return verlangt if verlangt != "inherit" and erlaubt(verlangt, liste) else sitzung
    agenten = {name: wirksam(m) for name, m in agentenmodelle().items()}
    skills = {name: wirksam(m) for name, m in skillmodelle().items() if m != "inherit"}
    mythos = MODELLE["mythos"]
    verlangen_mythos = [f"/{n}" for n, m in skillmodelle().items() if m == mythos] + [n for n, m in agentenmodelle().items() if m == mythos]
    return {"sitzung": sitzung, "liste": liste, "mythos_frei": bool(liste) and erlaubt(mythos, liste),
            "agenten": agenten, "skills": skills, "ermittlung": verlangen_mythos,
            "abschluss": [n for n, m in agentenmodelle().items() if m == MODELLE["fable"]]
                         + [f"/{n}" for n, m in skillmodelle().items() if m == MODELLE["fable"]]}


def lokale_einstellungen(robin: bool, mythos: bool | None) -> tuple[list[str], bool, bool]:
    """Schreibt .claude/settings.local.json: freigeschaltete MCP-Server und, wenn erklärt, Mythos in availableModels.
    Fremde Einträge bleiben erhalten. Gibt (freigeschaltete Server, Datei neu angelegt, Altlast entfernt) zurück."""
    datei = PROJEKT / ".claude" / "settings.local.json"
    erstmals = not datei.is_file()
    daten = einstellungen(datei)
    an = [s for s in daten.get("enabledMcpjsonServers", []) if s not in ("osint", "robin")] + ["osint"] + (["robin"] if robin else [])
    ab = [s for s in daten.get("disabledMcpjsonServers", []) if s not in ("osint", "robin")] + ([] if robin else ["robin"])
    daten["enabledMcpjsonServers"], daten["disabledMcpjsonServers"] = an, ab

    liste = [m for m in daten.get("availableModels") or [] if isinstance(m, str)] if isinstance(daten.get("availableModels"), list) else []
    if mythos is True and MODELLE["mythos"] not in liste:
        liste.append(MODELLE["mythos"])
    elif mythos is False:
        liste = [m for m in liste if m != MODELLE["mythos"]]
    if liste:
        daten["availableModels"] = liste
    else:
        daten.pop("availableModels", None)
    # Altlast: Eine frühere Fassung stellte die ganze Sitzung auf Mythos. Jetzt schaltet /ermittlung selbst um,
    # und ausserhalb der Ermittlung soll Fable 5.2 laufen.
    altlast = daten.get("model") == MODELLE["mythos"]
    if altlast:
        daten.pop("model")
    plattform.text_schreiben(datei, json.dumps(daten, indent=2, ensure_ascii=False) + "\n")
    return an, erstmals, altlast


def modell_testen(modell: str) -> tuple[str, str]:
    """Ein kurzer Testaufruf über Claude Code, ausserhalb des Projekts: Darf dieses Konto das Modell nutzen?
    Gibt ("ok" | "anderes" | "fehler" | "unbekannt", Erklärung) zurück. Verbraucht einen kleinen Aufruf."""
    pfad = plattform.programm("claude")
    if not pfad:
        return "unbekannt", "Claude Code fehlt"
    with tempfile.TemporaryDirectory(prefix="osint-modelltest-") as ordner:    # leerer Ordner: keine Hooks, kein Gateway
        code, text = lauf([pfad, "-p", "Antworte nur mit dem Wort OK.", "--model", modell, "--output-format", "json",
                           "--no-session-persistence"], 180, cwd=ordner)
    try:
        antwort = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except ValueError:
        return "unbekannt", (text.strip().splitlines() or [f"keine Antwort (Rückgabewert {code})"])[-1][:200]
    benutzt = sorted(antwort.get("modelUsage") or {})
    if antwort.get("is_error") or code != 0:
        return "fehler", str(antwort.get("result") or f"Rückgabewert {code}").strip().splitlines()[0][:200]
    if any(m.startswith(modell) for m in benutzt):
        return "ok", "antwortet"
    if benutzt:     # Claude Code hat ein anderes Modell genommen, etwa weil eine Liste des Kontos dieses nicht zulässt
        return "anderes", "geantwortet hat stattdessen " + ", ".join(benutzt)
    return "unbekannt", "Antwort erhalten, aber ohne Angabe des Modells"


def benutzervariable(name: str) -> str:
    """Wert einer Umgebungsvariablen des Windows-Benutzerkontos (gilt für neu gestartete Programme)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as schluessel:
            return str(winreg.QueryValueEx(schluessel, name)[0])
    except (ImportError, OSError):
        return ""


def gateway_python() -> None:
    """Windows: .mcp.json startet das Gateway mit ${OSINT_PYTHON:-python3}. Ein python3 gibt es unter Windows
    nicht, also bekommt das Benutzerkonto die Variable OSINT_PYTHON mit dem Python der .venv.
    Claude Code liest sie aus seiner Umgebung, sobald es aus einem neuen Terminal gestartet wird."""
    soll = str(VENV)
    if benutzervariable("OSINT_PYTHON") != soll:
        code, text = lauf(["setx", "OSINT_PYTHON", soll], 60, "env.log")
        if code != 0 or benutzervariable("OSINT_PYTHON") != soll:
            zeile(FEHLT, "Python fürs Gateway", "Die Umgebungsvariable OSINT_PYTHON liess sich nicht setzen.")
            stand.noetig.append("OSINT_PYTHON")
            stand.offen.append(f'Umgebungsvariable von Hand setzen:  setx OSINT_PYTHON "{soll}"   dann ein neues Terminal öffnen')
            return
        zeile(NEU, "Python fürs Gateway", f"Umgebungsvariable OSINT_PYTHON gesetzt ({soll})")
        stand.neu.append("Umgebungsvariable OSINT_PYTHON")
    else:
        zeile(GUT, "Python fürs Gateway", f"OSINT_PYTHON zeigt auf {soll}")
    if os.environ.get("OSINT_PYTHON") != soll:
        stand.neues_terminal.append("die Variable OSINT_PYTHON, über die Claude Code das Gateway startet")


def anmeldung() -> tuple[bool | None, str]:
    """Ob Claude Code angemeldet ist: (ja oder nein, auf welchem Weg). None, wenn Claude Code fehlt."""
    pfad = plattform.programm("claude")
    if not pfad:
        return None, ""
    code, text = lauf([pfad, "auth", "status", "--json"], 60)
    try:
        status = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except ValueError:
        status = {}
    if status.get("loggedIn"):
        return True, str(status.get("authMethod") or "Konto")
    ueber_umgebung = [n for n in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
                                  "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY") if os.environ.get(n)]
    if ueber_umgebung:
        return True, "über die Umgebung gesetzt: " + ", ".join(ueber_umgebung)
    return False, ""


def claude_code(a: argparse.Namespace, robin: bool) -> None:
    schritt(5, "Claude Code")
    vorher = modellzuteilung()["mythos_frei"]
    an, erstmals, altlast = lokale_einstellungen(robin, mythos_wunsch(a))
    zeile(GUT, "MCP-Server", "freigeschaltet: " + ", ".join(an) + ("" if robin else "   (robin aus: kein Docker, kein Abbild oder abgewählt)"))
    if WINDOWS:
        gateway_python()
    z = modellzuteilung()
    fable, mythos = MODELLE["fable"], MODELLE["mythos"]
    if z["mythos_frei"]:
        zeile(GUT if vorher else NEU, "Mythos 5.2", "freigeschaltet. Die Ermittlung schaltet von selbst um, der Abschluss bleibt auf Fable 5.2.")
        if not vorher:
            stand.neu.append("Mythos 5.2 für die Ermittlung freigeschaltet")
            if not a.testen:
                stand.offen.append(f"Prüfen, ob euer Konto Mythos 5.2 nutzen darf (zwei kurze Testaufrufe): {PY} tools/pruefen.py --live   "
                                   f"Falls nicht: {SETUP} --ohne-mythos")
    else:
        zeile(AUS, "Mythos 5.2", f"nicht freigeschaltet, alles läuft auf Fable 5.2. Wer Mythos hat: {SETUP} --mythos")
    zeile(GUT, "Modell Ermittlung", f"{mythos if z['mythos_frei'] else z['sitzung']}   ({', '.join(z['ermittlung'])})")
    zeile(GUT, "Modell Abschluss", f"{fable}   ({', '.join(z['abschluss'])}, und alles ausserhalb der Ermittlung)")
    if altlast:
        zeile(NEU, "Sitzungsmodell", f"zurück auf {z['sitzung']}. Auf Mythos schaltet jetzt /ermittlung selbst um.")

    angemeldet, wie = anmeldung()
    if angemeldet is None:
        zeile(AUS, "Anmeldung", "nicht prüfbar, Claude Code fehlt")
        return
    if angemeldet:
        zeile(GUT, "Anmeldung", f"angemeldet ({wie})")
    elif a.anmelden:
        zeile(AUS, "Anmeldung", "noch nicht angemeldet. Die Anmeldung startet gleich, nach der Prüfung.")
    else:
        zeile(AUS, "Anmeldung", "keine Anmeldung gefunden")
        stand.offen.append(HINWEIS_ANMELDEN)
    if erstmals:
        stand.offen.append("Beim ersten Start von 'claude' im Projektordner fragt Claude Code einmal, ob es dem Ordner "
                           "vertrauen soll. Mit Ja bestätigen: Erst dann gelten Wächter, Protokoll und MCP-Server.")


# --------------------------------------------------------------------------- Schritt 6: Musterfall und Prüfung

def pruefung() -> tuple[int, str]:
    """Baut den Musterfall und prüft die Einrichtung. Gibt (Rückgabewert, Fazit in einem Satz) zurück."""
    schritt(6, "Musterfall und Prüfung")
    code, text = lauf([str(VENV), str(PROJEKT / "tools" / "musterfall.py")], 600, "muster.log", anzeige="Musterfall wird gebaut")
    if code != 0:
        zeile(FEHLT, "Musterfall", "liess sich nicht bauen")
        print(letzte_zeilen(text, 6), flush=True)
        stand.noetig.append("Musterfall")
        stand.offen.append(f"Meldung oben beheben. Vollständig: {LOGS / 'muster.log'}")
        return 1, ""
    zeile(GUT, "Musterfall", "gebaut: faelle/MUSTER-2026-001/rapport/Abschlussrapport.html")
    # Die Prüfung meldet ihr Ergebnis als eine Zeile JSON. Gezeigt wird die Kurzfassung, ausführlich: tools/pruefen.py
    code, text = lauf([str(VENV), str(PROJEKT / "tools" / "pruefen.py"), "--eingebettet"], 1200, "pruefung.log",
                      anzeige="Einrichtung wird geprüft (Einstellungen, Quellen, Selbsttests)")
    ergebnis = None
    for z in reversed(text.splitlines()):
        if z.startswith('{"osint_pruefung"'):
            with contextlib.suppress(json.JSONDecodeError):
                ergebnis = json.loads(z)
            break
    if not isinstance(ergebnis, dict):
        zeile(FEHLT, "Prüfung", "lieferte kein Ergebnis")
        print(letzte_zeilen(text, 6), flush=True)
        stand.noetig.append("Prüfung der Einrichtung")
        stand.offen.append(f"Von Hand prüfen: {PY} tools/pruefen.py   Vollständig: {LOGS / 'pruefung.log'}")
        return 1, ""
    art = {"gut": GUT, "aus": AUS, "fehlt": FEHLT}
    for kind, was, wie in ergebnis.get("zeilen", []):
        zeile(art.get(kind, AUS), was, wie)
    for was in ergebnis.get("fehlt", []):
        stand.noetig.append(was)
    if ergebnis.get("fehlt"):
        stand.offen.append(f"Einzelheiten zu den Fehlern oben: {PY} tools/pruefen.py")
    return (1 if ergebnis.get("fehlt") or code else 0), f"mit {ergebnis.get('bereit')} von {ergebnis.get('quellen')} Quellen"


# --------------------------------------------------------------------------- Auf Wunsch danach: Anmeldung, Testabfragen

def anmelden(a: argparse.Namespace) -> None:
    """Startet die Anmeldung bei Claude Code. Sie läuft im Vordergrund und führt selbst durch den Browser."""
    pfad = plattform.programm("claude")
    if not a.anmelden or not pfad or anmeldung()[0]:
        return
    ui.abschnitt("Anmeldung bei Claude Code")
    ui.text("Claude Code öffnet den Browser. Dort anmelden, danach geht es hier von selbst weiter. Überspringen mit Strg+C.", "matt")
    ui.leer()
    try:
        subprocess.call([pfad, "auth", "login", "--console" if a.anmelden == "console" else "--claudeai"])
    except KeyboardInterrupt:
        ui.leer()
    angemeldet, wie = anmeldung()
    if angemeldet:
        zeile(GUT, "Anmeldung", f"angemeldet ({wie})")
        stand.neu.append("Anmeldung bei Claude Code")
    else:
        zeile(AUS, "Anmeldung", "nicht abgeschlossen")
        stand.offen.append(HINWEIS_ANMELDEN)


def testabfragen(a: argparse.Namespace) -> bool:
    """Je eingerichteter Quelle eine harmlose Abfrage, je Modell ein kurzer Aufruf. Die Ausgabe kommt von
    tools/pruefen.py. Gibt zurück, ob alles durchkam (auch dann, wenn nichts zu testen war)."""
    if not a.testen:
        return True
    sys.stdout.flush()
    try:
        code = subprocess.call([str(VENV), str(PROJEKT / "tools" / "pruefen.py"), "--nur-live"])
    except KeyboardInterrupt:
        ui.leer()
        code = 130
    if code == 130:
        stand.offen.append(f"Die Testabfragen wurden abgebrochen. Nachholen: {PY} tools/pruefen.py --live")
    elif code:
        stand.offen.append("Nicht jede Testabfrage kam durch (Zeilen mit " + FEHLT + " oben). Schlüssel, Netz und Proxy prüfen, "
                           f"dann erneut: {PY} tools/pruefen.py --live")
    return code == 0


def abschluss(code: int, fazit: str = "", tests_ok: bool = True) -> int:
    if stand.neues_terminal:
        stand.offen.insert(0, "Ein neues Terminal öffnen, bevor ihr 'claude' startet. Erst dort gilt: "
                           + " und ".join(stand.neues_terminal) + ".")
    bereit = not (stand.noetig or code)
    ui.leer()
    ui.linie()
    if bereit and tests_ok:
        ui.erledigt("Einsatzbereit", fazit, breit=0)
    elif bereit:        # eingerichtet ist alles, aber «einsatzbereit» wäre zu viel gesagt, solange Quellen nicht antworten
        ui.erledigt("Eingerichtet", fazit + ". Nicht jede Testabfrage kam durch, siehe oben.", AUS, breit=0)
    else:
        ui.erledigt("NICHT einsatzbereit.", ("Es fehlt: " + ", ".join(dict.fromkeys(stand.noetig)) + "." if stand.noetig
                                             else "Die Prüfung oben meldet Fehler."), FEHLT, breit=0)
    ui.liste("Neu eingerichtet", stand.neu)
    ui.liste("Noch offen" if bereit else "Das ist zu tun", list(dict.fromkeys(stand.offen)), nummeriert=True)
    if not bereit:
        return 1
    ui.paare("Loslegen", [
        ("Musterfall ansehen", "faelle/MUSTER-2026-001/rapport/Abschlussrapport.html"),
        ("Fall anlegen", f"{PY} tools/fall.py neu 2026-0001 --titel \"…\" --rapport <Dokument>"),
        ("Ermitteln", "claude   und dort   /ermittlung 2026-0001"),
        ("Stand prüfen", f"{PY} tools/pruefen.py"),
        ("Einstellungen ändern", SETUP),
    ])
    return 0


# --------------------------------------------------------------------------- Assistent

THEMEN = ("installieren", "modelle", "schluessel", "proxy", "dienste", "anmeldung", "testen")
TITEL = {"installieren": "Installieren", "modelle": "Modelle", "schluessel": "Schlüssel", "proxy": "Proxy",
         "dienste": "Dienste", "anmeldung": "Anmeldung", "testen": "Testabfragen"}


def bestand(a: argparse.Namespace, sysinfo: dict) -> dict:
    """Was auf diesem Rechner und in diesem Ordner schon da ist. Verändert nichts. Daraus ergeben sich die Fragen."""
    verwaltung = sysinfo["paketverwaltung"] or ""
    fehlend: list[tuple[str, str]] = []        # (was fehlt, wie es installiert würde)
    if lauf([sys.executable, "-c", "import ensurepip, venv"], 60)[0] != 0:
        pakete = PAKETE["venv"].get(verwaltung)
        fehlend.append(("venv und pip", f"Paket {pakete[0]} über {verwaltung}" if pakete else "von Hand, keine Paketverwaltung gefunden"))
    if WINDOWS and not git_bash():
        fehlend.append(("Git for Windows", "über winget" if verwaltung == "winget" else "von Hand, winget fehlt"))
    claude = claude_stand()[0]
    if not claude:
        fehlend.append(("Claude Code", "mit dem Installer von Anthropic (claude.ai/install)"))
    if not plattform.programm("pdftotext") and PAKETE["pdftotext"].get(verwaltung):
        fehlend.append(("pdftotext", f"Paket {PAKETE['pdftotext'][verwaltung][0]} über {verwaltung}"))
    return {
        "fehlend": fehlend,
        "braucht_sudo": (not WINDOWS and os.geteuid() != 0 and verwaltung not in ("", "brew")
                         and any(was in ("venv und pip", "pdftotext") for was, _ in fehlend)),
        "claude": bool(claude),
        "angemeldet": anmeldung()[0],
        "docker": None if a.ohne_docker else docker_stand(),
        "env": env_lesen(PROJEKT / ".env"),
        "mythos_frei": modellzuteilung()["mythos_frei"],
        "eingerichtet": VENV.is_file() and (PROJEKT / ".env").is_file() and (PROJEKT / ".claude" / "settings.local.json").is_file(),
    }


def schluessel_pruefen(wert: str) -> str | None:
    """Fängt ab, was beim Einfügen eines Schlüssels typischerweise schiefgeht. Ob er gilt, zeigt erst die Testabfrage."""
    if re.match(r"[A-Z][A-Z0-9_]*=", wert):
        return "Nur den Schlüssel selbst einfügen, ohne den Namen und das Gleichheitszeichen davor."
    if re.search(r"\s", wert):
        return "Ein Schlüssel enthält keine Leerzeichen. Bitte noch einmal einfügen."
    if not wert.isascii() or not wert.isprintable() or any(z in wert for z in "\"'#"):
        return "Das enthält Zeichen, die in einem Schlüssel nicht vorkommen. Bitte noch einmal einfügen."
    if len(wert) < 8:
        return "Das ist für einen Schlüssel zu kurz. Bitte prüfen."
    return None


def proxy_pruefen(adresse: str) -> str | None:
    try:
        teile = urlsplit(adresse)
        teile.port      # eine unsinnige Portangabe fällt erst beim Zugriff auf
    except ValueError:
        return "Das ist keine gültige Adresse. Beispiel: http://proxy.intern:3128"
    if teile.scheme not in ("http", "https", "socks5", "socks5h"):
        return "Die Adresse beginnt mit http://, https://, socks5:// oder socks5h://"
    if not teile.hostname or re.search(r"\s", adresse):
        return "Es fehlt der Name oder die Adresse des Proxys. Beispiel: http://proxy.intern:3128"
    return None


def proxy_zeigen(adresse: str) -> str:
    """Die Adresse eines Proxys für die Anzeige, ein Passwort darin unkenntlich."""
    return re.sub(r"(://[^:/@]+):[^@]*@", r"\1:***@", adresse)


def pfad_aus_eingabe(text: str) -> Path:
    """Ein eingetippter oder ins Terminal gezogener Pfad. Beim Hineinziehen setzt das Terminal ihn oft in Anführungszeichen."""
    return Path(text.strip().strip("\"'").replace("\\ ", " ")).expanduser()


def port_offen(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


class Assistent:
    """Führt im Terminal durch die Einrichtung: fragen, Übersicht zeigen, bestätigen lassen.
    Verändert selbst nichts. Am Ende stehen die Antworten in den Optionen (a), so als wären sie auf der
    Befehlszeile mitgegeben worden. Die sechs Schritte danach laufen ohne weitere Fragen."""

    def __init__(self, a: argparse.Namespace, sysinfo: dict, b: dict) -> None:
        self.a, self.sysinfo, self.b = a, sysinfo, b
        wunsch = mythos_wunsch(a)
        erstmals = not b["eingerichtet"]
        self.w = {
            "installieren": not a.nichts_installieren,
            "mythos": b["mythos_frei"] if wunsch is None else wunsch,
            "werte": {},                        # neu eingegebene Schlüssel je Name in .env. Leer heisst: entfernen
            "env_von": a.env_von,
            "proxy": b["env"].get("OSINT_PROXY", ""),
            "docker_installieren": a.docker_installieren,
            "webcheck": not a.ohne_webcheck,
            "robin": not a.ohne_robin,
            "anmelden": "claudeai" if erstmals else "",     # "", "claudeai" (Abo) oder "console"
            "testen": a.testen or erstmals,
        }

    # ----------------------------------------------------------------------- Stand der Antworten

    def themen(self) -> list[str]:
        b = self.b
        return [t for t in THEMEN if {"installieren": bool(b["fehlend"]), "dienste": b["docker"] is not None,
                                      "anmeldung": not b["angemeldet"]}.get(t, True)]

    def datei_werte(self) -> dict[str, str]:
        if not self.w["env_von"]:
            return {}
        return aus_datei(pfad_aus_eingabe(self.w["env_von"]))[0]

    def hat_schluessel(self, q) -> bool:
        if self.w["werte"].get(q.env) or self.datei_werte().get(q.env) or os.environ.get(q.env, "").strip():
            return True
        return bool(self.b["env"].get(q.env)) and q.env not in self.w["werte"]

    def schluessel_stand(self, q) -> tuple[str, str]:
        """Zustand eines Schlüssels für die Liste: (Text, Stil). Der Schlüssel selbst erscheint nie."""
        if q.env in self.w["werte"]:
            wert = self.w["werte"][q.env]
            return (f"neu eingegeben ({len(wert)} Zeichen)", "gut") if wert else ("wird entfernt", "warn")
        if self.datei_werte().get(q.env):
            return "aus der Datei", "gut"
        if self.b["env"].get(q.env):
            return "eingetragen", "gut"
        # Das Gateway nimmt einen Schlüssel auch aus der Umgebung, und die gilt dort vor .env
        return ("in der Umgebung gesetzt", "gut") if os.environ.get(q.env, "").strip() else ("fehlt", "matt")

    def antwort(self, thema: str) -> str:
        """Die Antwort auf ein Thema in einer Zeile, für die Übersicht."""
        w, b = self.w, self.b
        if thema == "installieren":
            namen = ", ".join(was for was, _ in b["fehlend"])
            return namen if w["installieren"] else f"nichts. Es fehlt weiterhin: {namen}"
        if thema == "modelle":
            return "Ermittlung auf Mythos 5.2, Abschluss auf Fable 5.2" if w["mythos"] else "alles auf Fable 5.2"
        if thema == "schluessel":
            text = f"{sum(1 for q in SCHLUESSELQUELLEN if self.hat_schluessel(q))} von {len(SCHLUESSELQUELLEN)} Quellen mit Schlüssel"
            neu = [q.name for q in SCHLUESSELQUELLEN if w["werte"].get(q.env)]
            weg = [q.name for q in SCHLUESSELQUELLEN if w["werte"].get(q.env) == ""]
            return (text + (f", neu: {', '.join(neu)}" if neu else "") + (f", entfernt: {', '.join(weg)}" if weg else "")
                    + (f", Datei {pfad_aus_eingabe(w['env_von']).name}" if w["env_von"] else ""))
        if thema == "proxy":
            if not w["proxy"]:
                return "keiner. Die Quellen sehen die Internetadresse dieses Rechners"
            return ("Tor, " if w["proxy"] == TOR else "") + proxy_zeigen(w["proxy"])
        if thema == "dienste":
            docker = b["docker"]
            if docker["laeuft"]:
                return ", ".join(n for n, an in (("Web-Check", w["webcheck"]), ("Robin", w["robin"])) if an) or "keine"
            if w["docker_installieren"]:
                return "Docker installieren, dann Web-Check und Robin"
            return "ohne Docker. Web-Check und Robin bleiben aus"
        if thema == "anmeldung":
            return {"claudeai": "am Ende, mit dem Claude-Abo", "console": "am Ende, mit der Anthropic Console", "": "später, von Hand"}[w["anmelden"]]
        return "am Ende jede eingerichtete Quelle einmal abfragen" if w["testen"] else "keine"

    # ----------------------------------------------------------------------- Fragen

    def fragen(self, thema: str, fortschritt: str = "") -> None:
        getattr(self, "frage_" + thema)(fortschritt)

    def frage_installieren(self, f: str) -> None:
        fehlend = self.b["fehlend"]
        nr = ui.auswahl(TITEL["installieren"], f"Auf diesem Rechner fehlt noch: {', '.join(was for was, _ in fehlend)}. "
                        "Soll die Einrichtung das installieren?",
                        [("Ja, installieren", ""), ("Nein, nichts am System verändern", "nur das Projekt einrichten")],
                        0 if self.w["installieren"] else 1,
                        [f"{was}: {wie}" for was, wie in fehlend]
                        + (["Die Paketverwaltung braucht dafür einmal euer Passwort (sudo)."] if self.b["braucht_sudo"] else []), f)
        self.w["installieren"] = nr == 0

    def frage_modelle(self, f: str) -> None:
        nr = ui.auswahl(TITEL["modelle"], "Darf euer Konto Claude Mythos 5.2 nutzen?",
                        [("Nein", "alles läuft auf Fable 5.2"), ("Ja", "die Ermittlung schaltet von selbst auf Mythos 5.2")],
                        1 if self.w["mythos"] else 0,
                        ["Mythos 5.2 steht nur Organisationen offen, die Anthropic verifiziert hat. Der Abschluss (Gegenprüfung, "
                         "Rapport, Protokoll) läuft in jedem Fall auf Fable 5.2.",
                         "Im Zweifel Nein. Die Antwort lässt sich jederzeit ändern."], f)
        self.w["mythos"] = nr == 1

    def frage_schluessel(self, f: str) -> None:
        w = self.w
        ohne = [q.name for q in QUELLEN if not q.env]
        stelle = 0 if not any(self.hat_schluessel(q) for q in SCHLUESSELQUELLEN) else None
        while True:
            eintraege = [(q.name, *self.schluessel_stand(q)) for q in SCHLUESSELQUELLEN]
            eintraege += [("", "", ""), ("Aus einer Datei übernehmen …" + (f"  ({pfad_aus_eingabe(w['env_von']).name})" if w["env_von"] else ""), "", ""),
                          ("Weiter", "", "")]
            weiter = len(eintraege) - 1
            nr, taste = ui.menue(TITEL["schluessel"], "Welche Quellen sollen einen Schlüssel bekommen?", eintraege,
                                 weiter if stelle is None or not ui.bewegt else stelle,     # mit Nummern ist Enter immer «Weiter»
                                 [f"Jede Quelle ist für sich optional. Keinen Schlüssel brauchen {len(ohne)} Quellen: {', '.join(ohne)}.",
                                  "Eingaben bleiben unsichtbar und stehen danach nur in der Datei .env auf diesem Rechner."],
                                 f, "Entf entfernen")
            if nr == weiter:
                return
            if nr == weiter - 1:
                pfad = ui.eingabe("Schlüssel aus einer Datei", "Pfad zu einer ausgefüllten Kopie von .env.example:", vorgabe=w["env_von"] or "",
                                  erklaerung=["Übernommen werden nur Einstellungen, die .env.example kennt. Was ihr hier von Hand eingebt, geht vor.",
                                              "Die Datei lässt sich auch ins Terminal ziehen."],
                                  pruefung=lambda t: None if pfad_aus_eingabe(t).is_file() else "Diese Datei gibt es nicht.")
                if pfad:
                    w["env_von"] = str(pfad_aus_eingabe(pfad))
                stelle = None
                continue
            q = SCHLUESSELQUELLEN[nr]
            if taste == "entf":
                if q.env in w["werte"]:
                    del w["werte"][q.env]               # eine eben gemachte Eingabe zurücknehmen
                elif self.b["env"].get(q.env):
                    w["werte"][q.env] = ""              # einen eingetragenen Schlüssel aus .env entfernen
                stelle = nr
                continue
            wert = ui.eingabe(q.name, f"Schlüssel für {q.name} einfügen oder eintippen:", verdeckt=True, pruefung=schluessel_pruefen,
                              erklaerung=[q.zweck, f"Woher: {q.woher}"] + ([q.hinweis] if q.hinweis else []))
            if wert:
                w["werte"][q.env] = wert
            stelle = nr + 1 if wert and nr + 1 < len(SCHLUESSELQUELLEN) else None if wert else nr

    def frage_proxy(self, f: str) -> None:
        w = self.w
        while True:
            eigener = w["proxy"] if w["proxy"] not in ("", TOR) else ""
            nr = ui.auswahl(TITEL["proxy"], "Sollen die Abfragen an die Quellen über einen Proxy laufen?",
                            [("Kein Proxy", "die Quellen sehen die Internetadresse dieses Rechners"),
                             ("Tor auf diesem Rechner", TOR + (", Tor antwortet" if port_offen(9050) else ", dort antwortet gerade nichts")),
                             ("Eigener Proxy …", proxy_zeigen(eigener) if eigener else "Adresse eingeben")],
                            0 if not w["proxy"] else 1 if w["proxy"] == TOR else 2,
                            ["Das betrifft nur die Abfragen des Gateways, nicht Claude Code selbst."], f)
            if nr == 0:
                w["proxy"] = ""
            elif nr == 1:
                w["proxy"] = TOR
            else:
                adresse = ui.eingabe(TITEL["proxy"], "Adresse des Proxys:", vorgabe=eigener, pruefung=proxy_pruefen,
                                     erklaerung=["Beispiele: http://proxy.intern:3128   socks5h://127.0.0.1:9050"])
                if not adresse:
                    continue
                w["proxy"] = adresse
            return

    def frage_dienste(self, f: str) -> None:
        w = self.w
        ohne = ("Ohne Docker weiter", "Web-Check und Robin bleiben aus, alles andere läuft")
        while True:
            docker = self.b["docker"]
            if docker["laeuft"]:
                wahl = ui.mehrfach(TITEL["dienste"], "Welche Dienste sollen über Docker laufen?",
                                   [("Web-Check", "eigene Instanz für Website-Prüfungen, nur auf diesem Rechner erreichbar"),
                                    ("Robin", "Suche im Dark Web über Tor. Jede Abfrage braucht zusätzlich eine Freigabe im Fall")],
                                   {nr for nr, an in enumerate((w["webcheck"], w["robin"])) if an},
                                   ["Beim ersten Mal lädt Docker die Abbilder. Das kann einige Minuten dauern."]
                                   + ([] if docker["compose"] else ["Docker Compose fehlt: Web-Check lässt sich so nicht starten."]), f)
                w["webcheck"], w["robin"], w["docker_installieren"] = 0 in wahl, 1 in wahl, False
                return
            if not docker["installiert"] and self.sysinfo["art"] == "linux" and self.sysinfo["paketverwaltung"] == "apt":
                nr = ui.auswahl(TITEL["dienste"], "Docker ist nicht installiert. Web-Check und Robin brauchen es.",
                                [ohne, ("Docker installieren", "Paket docker.io über apt, braucht sudo")],
                                1 if w["docker_installieren"] else 0, [], f)
                w["docker_installieren"] = nr == 1
                return
            if docker["installiert"]:
                lage = "Docker ist installiert, aber der Dienst läuft nicht oder euer Konto hat keinen Zugriff."
                wie = ("Docker Desktop starten." if self.sysinfo["art"] != "linux" or self.sysinfo["wsl"]
                       else "Starten: sudo systemctl start docker   Zugriff: das Konto in die Gruppe docker aufnehmen.")
            else:
                lage = "Docker ist nicht installiert."
                wie = ("Installation: https://docs.docker.com/engine/install/" if self.sysinfo["art"] == "linux"
                       else "Docker Desktop von Hand installieren. Lizenz beachten, siehe README.")
            nr = ui.auswahl(TITEL["dienste"], lage + " Web-Check und Robin brauchen es.",
                            [ohne, ("Erneut prüfen", "nachdem Docker läuft")], 0, [wie], f)
            if nr == 0:
                return
            with ui.arbeit("Docker wird geprüft"):
                self.b["docker"] = docker_stand()

    def frage_anmeldung(self, f: str) -> None:
        fehlt = "" if self.b["claude"] else " (sobald es installiert ist)"
        nr = ui.auswahl(TITEL["anmeldung"], f"Claude Code ist auf diesem Rechner noch nicht angemeldet{fehlt}. "
                        "Soll die Einrichtung am Ende die Anmeldung starten?",
                        [("Ja, mit dem Claude-Abo", "Pro, Max, Team oder Enterprise"),
                         ("Ja, mit der Anthropic Console", "Abrechnung nach Verbrauch"),
                         ("Nein, später", "beim ersten Start von 'claude'")],
                        {"claudeai": 0, "console": 1, "": 2}[self.w["anmelden"]],
                        ["Die Anmeldung öffnet den Browser. Hier im Terminal wird kein Passwort eingegeben.",
                         "Läuft Claude Code bei euch über einen API-Schlüssel oder einen Cloud-Anbieter: Nein."], f)
        self.w["anmelden"] = ("claudeai", "console", "")[nr]

    def frage_testen(self, f: str) -> None:
        nr = ui.auswahl(TITEL["testen"], "Soll die Einrichtung am Ende jede eingerichtete Quelle einmal abfragen?",
                        [("Ja, testen", "zeigt sofort, ob Schlüssel, Netz und Proxy stimmen"),
                         ("Nein, später", f"{PY} tools/pruefen.py --live")],
                        0 if self.w["testen"] else 1,
                        ["Je Quelle geht eine harmlose Abfrage hinaus (8.8.8.8, example.com). Sie verbraucht einen Abruf aus eurem "
                         "Kontingent und wird in der Fallakte SELBSTTEST protokolliert.",
                         "Ist Claude Code angemeldet, kommt je Modell ein kurzer Testaufruf dazu."], f)
        self.w["testen"] = nr == 0

    # ----------------------------------------------------------------------- Ablauf

    def uebersicht(self, bestaetigen: str) -> bool:
        """Alle Antworten als Liste. Eine Zeile öffnen, um sie zu ändern. Gibt zurück, ob eingerichtet werden soll."""
        while True:
            themen = self.themen()
            eintraege = [(TITEL[t], self.antwort(t), "") for t in themen]
            eintraege += [("", "", ""), (bestaetigen, "", ""), ("Abbrechen", "es wird nichts verändert", "matt")]
            nr, _ = ui.menue("Übersicht", "So wird eingerichtet. Zum Ändern eine Zeile öffnen.", eintraege, len(themen) + 1,
                             bedenkzeit=0.5)
            if nr >= len(themen):
                return nr == len(themen) + 1
            with contextlib.suppress(Abbruch):      # Esc in einer Frage führt zurück zur Übersicht
                self.fragen(themen[nr])

    def uebernehmen(self) -> None:
        """Schreibt die Antworten in die Optionen. Ab hier verhält sich die Einrichtung wie mit diesen Optionen gestartet."""
        a, w, b = self.a, self.w, self.b
        if b["fehlend"]:
            a.nichts_installieren = not w["installieren"]
        a.mythos, a.ohne_mythos = w["mythos"], not w["mythos"]
        a.env_von = w["env_von"]
        a.werte = dict(w["werte"])
        if w["proxy"] != b["env"].get("OSINT_PROXY", ""):
            a.werte["OSINT_PROXY"] = w["proxy"]
        # Steht OSINT_MYTHOS in .env (etwa aus der Datei fürs Ausrollen), muss es zur Antwort passen.
        # Sonst nähme der nächste Lauf ohne Rückfragen die Antwort wieder zurück.
        kuenftig = {**b["env"], **self.datei_werte()}.get("OSINT_MYTHOS", "").strip().lower()
        if kuenftig and (kuenftig in JA) != w["mythos"]:
            a.werte["OSINT_MYTHOS"] = "ja" if w["mythos"] else "nein"
        if b["docker"] is not None:
            a.docker_installieren = w["docker_installieren"]
            a.ohne_webcheck, a.ohne_robin = not w["webcheck"], not w["robin"]
        a.anmelden = w["anmelden"] if "anmeldung" in self.themen() else ""
        a.testen = w["testen"]
        stand.assistent = True

    def kurzstand(self) -> str:
        w = self.w
        return " · ".join(("Ermittlung auf Mythos 5.2" if w["mythos"] else "alles auf Fable 5.2",
                           f"{sum(1 for q in SCHLUESSELQUELLEN if self.hat_schluessel(q))} von {len(SCHLUESSELQUELLEN)} Schlüsseln",
                           "Proxy " + (proxy_zeigen(w["proxy"]) if w["proxy"] else "keiner")))

    def fuehren(self) -> bool | int:
        """True: einrichten. Eine Zahl: mit diesem Rückgabewert enden. Abbruch: Der Mensch hat abgebrochen."""
        a, b = self.a, self.b
        if b["eingerichtet"]:
            gezielt = any((a.mythos, a.ohne_mythos, a.env_von, a.docker_installieren, a.ohne_docker, a.ohne_webcheck, a.ohne_robin,
                           a.nichts_installieren, a.testen))
            if gezielt and not a.vorschau:
                ui.text("Dieser Arbeitsplatz ist schon eingerichtet. Die Optionen werden ohne Rückfragen übernommen.", "matt")
                return True
            nr = ui.auswahl("Schon eingerichtet", "Dieser Arbeitsplatz ist bereits eingerichtet. Was soll geschehen?",
                            [("Prüfen und auffrischen", "nichts fragen, die Einstellungen bleiben"),
                             ("Einstellungen ändern", "Mythos, Schlüssel, Proxy, Dienste"),
                             ("Nur den Stand zeigen", "verändert nichts"),
                             ("Beenden", "")], 0, ["Derzeit: " + self.kurzstand()])
            if nr == 0:
                return True
            if nr == 2:
                return subprocess.call([str(VENV), str(PROJEKT / "tools" / "pruefen.py")])
            if nr == 3:
                return 0
            bestaetigen = "Änderungen übernehmen"
        else:
            ui.text("Ein paar Fragen, dann eine Übersicht. Verändert wird erst etwas, wenn ihr sie bestätigt.", "matt")
            ui.leer()
            themen = self.themen()
            for nr, thema in enumerate(themen, 1):
                self.fragen(thema, f"{nr} von {len(themen)}")
                ui.erledigt(TITEL[thema], self.antwort(thema))
            ui.zurueck(len(themen))         # die Antworten erscheinen gleich wieder, als Übersicht zum Ändern
            bestaetigen = "Einrichten"
        if not self.uebersicht(bestaetigen):
            raise Abbruch
        for thema in self.themen():
            ui.erledigt(TITEL[thema], self.antwort(thema))
        self.uebernehmen()
        return True


def main(argv: list[str]) -> int:
    plattform.utf8()
    p = argparse.ArgumentParser(add_help=False)
    for name in ("nur-pruefen", "nichts-installieren", "docker-installieren", "ohne-docker", "ohne-webcheck", "ohne-robin",
                 "mythos", "ohne-mythos", "schlicht", "vorschau", "testen"):
        p.add_argument(f"--{name}", action="store_true")
    p.add_argument("--ohne-rueckfragen", "--ja", "-y", action="store_true", dest="ohne_rueckfragen")
    p.add_argument("--env-von")
    p.add_argument("-h", "--hilfe", "--help", action="store_true", dest="hilfe")
    a, unbekannt = p.parse_known_args(argv)
    a.werte, a.anmelden = {}, ""        # füllt nur der Assistent
    if a.hilfe:
        print(__doc__)
        return 0
    if "--ermittlungsmodell" in unbekannt:
        print(f"FEHLER: --ermittlungsmodell gibt es nicht mehr. Wer Mythos 5.2 hat, erklärt das einmal: {SETUP} --mythos\n"
              "        Die Ermittlung schaltet dann von selbst um, der Abschluss bleibt auf Fable 5.2.", file=sys.stderr)
        return 2
    if unbekannt:
        print(f"FEHLER: Unbekannte Option: {' '.join(unbekannt)}   (Hilfe: {SETUP} --hilfe)", file=sys.stderr)
        return 2
    if a.env_von and not Path(a.env_von).expanduser().is_file():
        print(f"FEHLER: --env-von: Datei nicht gefunden: {a.env_von}", file=sys.stderr)
        return 2
    if a.schlicht or ui.zeilenzahl < 10:        # in einem sehr niedrigen Fenster hat keine Liste Platz
        ui.bewegt = False
    fragen = ui.interaktiv and not (a.ohne_rueckfragen or a.nur_pruefen or os.environ.get("CI"))
    if a.vorschau and not fragen:
        print("FEHLER: --vorschau zeigt die Fragen des Assistenten und braucht dafür ein Terminal.", file=sys.stderr)
        return 2
    os.chdir(PROJEKT)
    mythos_wunsch(a)        # eine falsche Angabe soll sofort auffallen, nicht erst nach der halben Einrichtung
    sysinfo = system()
    ui.kopf("OSINT-Ermittlungsarbeitsplatz · Einrichtung"
            + ("   (nur prüfen, es wird nichts verändert)" if a.nur_pruefen else "   (Vorschau, es wird nichts verändert)" if a.vorschau else ""),
            f"{sysinfo['name']} · Paketverwaltung {sysinfo['paketverwaltung'] or 'keine gefunden'} · {PROJEKT}")

    if fragen:
        try:
            with ui.arbeit("Bestandsaufnahme"):
                b = bestand(a, sysinfo)
            weiter = Assistent(a, sysinfo, b).fuehren()
        except Abbruch:
            ui.text("Abgebrochen. Es wurde nichts verändert.")
            return 130
        if weiter is not True:
            return int(weiter)
        if a.vorschau:
            ui.leer()
            ui.text("Vorschau: Es wurde nichts verändert. Ohne --vorschau würde jetzt so eingerichtet.", "matt")
            return 0

    docker = voraussetzungen(a, sysinfo)
    if a.nur_pruefen:
        ui.leer()
        ui.linie()
        if stand.noetig:
            ui.erledigt("Es fehlt Nötiges:", ", ".join(dict.fromkeys(stand.noetig)), FEHLT, breit=0)
        else:
            ui.erledigt("Alles Nötige ist vorhanden.", "", breit=0)
        ui.liste("Das ist zu tun" if stand.noetig else "Noch offen", list(dict.fromkeys(stand.offen)), nummeriert=True)
        ui.paare("Weiter", [("Einrichten", SETUP)])
        return 1 if stand.noetig else 0
    if "venv und pip" in stand.noetig or not python_umgebung():
        return abschluss(1)
    konfiguration(a)
    robin = dienste(a, docker)
    claude_code(a, robin)
    code, fazit = pruefung()
    tests_ok = True
    if code == 0:
        anmelden(a)
        tests_ok = testabfragen(a)
    return abschluss(code, fazit, tests_ok)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print(f"\n  Abgebrochen. {SETUP} lässt sich jederzeit erneut starten.", file=sys.stderr)
        sys.exit(130)
