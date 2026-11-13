#!/usr/bin/env python3
"""Richtet den OSINT-Ermittlungsarbeitsplatz ein. Ohne Rückfragen, beliebig oft wiederholbar.

Aufruf über die Startskripte. Sie sorgen zuerst für ein brauchbares Python und übergeben dann hierher:

    ./setup.sh [Optionen]         Linux, macOS, WSL
    .\\setup.cmd [Optionen]        Windows (startet setup.ps1)

Optionen:
    --nur-pruefen             nur zeigen, was vorhanden ist und was fehlt. Es wird nichts verändert.
    --nichts-installieren     nichts am System installieren (Pakete, Claude Code), nur das Projekt einrichten
    --docker-installieren     Docker mitinstallieren (Debian, Ubuntu, Kali; braucht root oder sudo)
    --ohne-docker             Web-Check und Robin auslassen
    --ohne-robin              nur Robin (Dark Web) auslassen
    --ermittlungsmodell M     Modell der Ermittlungsphase: fable, mythos oder eine Modell-ID
    --env-von DATEI           Schlüssel aus einer vorbereiteten Datei nach .env übernehmen
    --hilfe                   diese Hilfe

Ablauf:
    1. Voraussetzungen prüfen und Fehlendes installieren (Python-venv, Claude Code, pdftotext,
       unter Windows Git for Windows)
    2. Python-Umgebung .venv anlegen, Pakete installieren
    3. Schlüsseldatei .env und Ordner anlegen
    4. Web-Check starten und Robin-Abbild laden, wenn Docker läuft
    5. Claude Code: MCP-Server freischalten, Modelle je Phase setzen, Anmeldung prüfen
    6. Musterfall bauen und Einrichtung prüfen

Rückgabewert 0: einsatzbereit. 1: etwas Nötiges fehlt oder ist fehlgeschlagen. 2: falscher Aufruf.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("FEHLER: Python %d.%d ist zu alt. Nötig ist 3.10 oder neuer." % sys.version_info[:2])

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import urllib.request  # noqa: E402
from pathlib import Path  # noqa: E402

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402
from gateway.plattform import AUS, FEHLT, GUT, NEU, PY, SETUP, WINDOWS  # noqa: E402

MODELLE = {"fable": "claude-fable-5-2", "mythos": "claude-mythos-5-2"}
CLAUDE_MIN = (2, 1, 295)        # ab dieser Version sperrt Claude Code, wenn der Wächter-Hook selbst ausfällt
LOGS = Path(tempfile.gettempdir()) / "osint-setup"
VENV = plattform.venv_python(PROJEKT)
FARBE = sys.stdout.isatty() and "NO_COLOR" not in os.environ and (not WINDOWS or bool(os.environ.get("WT_SESSION")))

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


stand = Stand()


# --------------------------------------------------------------------------- Ausgabe und Befehle

def fett(text: str) -> str:
    return f"\033[1m{text}\033[0m" if FARBE else text


def zeile(zeichen: str, was: str, wie: str = "") -> None:
    farbe = {GUT: "32", NEU: "32", FEHLT: "31"}.get(zeichen)
    z = f"\033[{farbe}m{zeichen}\033[0m" if FARBE and farbe else zeichen
    print(f"  {z} {was:<22} {wie}".rstrip(), flush=True)


def schritt(nr: int, titel: str) -> None:
    print("\n" + fett(f"[{nr}/6] {titel}"), flush=True)


def lauf(befehl: list[str], zeit: int = 900, log: str | None = None, env: dict | None = None) -> tuple[int, str]:
    """Führt einen Befehl aus. Gibt Rückgabewert und Ausgabe zurück, 127 wenn es das Programm nicht gibt."""
    try:
        r = subprocess.run(befehl, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=zeit,
                           env=env, stdin=subprocess.DEVNULL)
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
            print(f"    Für {wofuer} fragt sudo jetzt einmal nach eurem Passwort.", flush=True)
            stand.sudo_gemeldet = True
        return ["sudo"]
    return None


def paket_installieren(was: str, sysinfo: dict, namen: dict[str, list[str]] | None = None) -> tuple[bool, str]:
    """Installiert ein Systempaket. Gibt (versucht, Hinweis) zurück. Ob es geklappt hat, prüft der Aufrufer."""
    verwaltung = sysinfo["paketverwaltung"]
    pakete = (namen or PAKETE[was]).get(verwaltung or "")
    if not verwaltung or not pakete:
        return False, "keine passende Paketverwaltung gefunden"
    if verwaltung == "winget":
        for paket in pakete:
            basis = ["winget", "install", "--id", paket, "-e", "--source", "winget", "--silent",
                     "--accept-package-agreements", "--accept-source-agreements"]
            # ältere winget-Versionen kennen --disable-interactivity nicht: dann ohne
            if lauf(basis + ["--disable-interactivity"], 900, "pakete.log")[0] != 0:
                lauf(basis, 900, "pakete.log")
        return True, "winget install --id " + " ".join(pakete)
    if verwaltung == "brew":
        if os.geteuid() == 0:
            return False, "Homebrew läuft nicht als root: brew install " + " ".join(pakete)
        lauf(INSTALLIEREN["brew"] + pakete, 1800, "pakete.log")
        return True, "brew install " + " ".join(pakete)
    befehl = INSTALLIEREN[verwaltung] + pakete
    vor = root_praefix(f"die Installation von {' '.join(pakete)}")
    if vor is None:
        return False, "sudo " + " ".join(befehl)
    umgebung = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    if verwaltung == "apt" and not stand.apt_aktuell:
        lauf(vor + ["apt-get", "update", "-qq"], 600, "pakete.log", umgebung)
        stand.apt_aktuell = True
    # sudo gibt eine veränderte Umgebung nicht weiter, deshalb über env
    code, _ = lauf(vor + (["env", "DEBIAN_FRONTEND=noninteractive"] if vor else []) + befehl, 1800, "pakete.log", umgebung)
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
                           "irm https://claude.ai/install.ps1 | iex"], 900, "claude.log", umgebung)
    else:
        LOGS.mkdir(parents=True, exist_ok=True)
        skript = LOGS / "claude-install.sh"
        if shutil.which("curl"):
            code, text = lauf(["curl", "-fsSL", "https://claude.ai/install.sh", "-o", str(skript)], 120, "claude.log")
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
        code, text = lauf(["bash", str(skript)], 900, "claude.log")
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
        code, text = lauf([sys.executable, "-m", "venv", "--clear", str(PROJEKT / ".venv")], 600, "venv.log")
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
    code, text = lauf(befehl, 1800, "pip.log")
    if code != 0:      # ein zweiter Versuch fängt kurze Netzstörungen ab
        code, text = lauf(befehl, 1800, "pip.log")
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
    """Trägt Werte in .env ein, an der Stelle, an der der Name schon steht. Gibt die geänderten Namen zurück."""
    zeilen = datei.read_text(encoding="utf-8").splitlines()
    geaendert = []
    for name, wert in werte.items():
        aktiv = next((i for i, z in enumerate(zeilen) if (m := ZUWEISUNG.match(z)) and m.group(2) == name and not m.group(1)), None)
        auskommentiert = next((i for i, z in enumerate(zeilen) if (m := ZUWEISUNG.match(z)) and m.group(2) == name and m.group(1)), None)
        neu = f"{name}={wert}"
        if aktiv is not None:
            if zeilen[aktiv].strip() == neu:
                continue
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
        bekannt = {m.group(2) for z in vorlage.read_text(encoding="utf-8").splitlines() if (m := ZUWEISUNG.match(z))}
        bekannt.add("OSINT_ERMITTLUNGSMODELL")
        werte = {k: w for k, w in env_lesen(quelle).items() if k in bekannt}
        fremd = sorted(set(env_lesen(quelle)) - bekannt)
        geaendert = env_setzen(datei, werte)
        zeile(NEU if geaendert else GUT, "Übernahme", f"{len(geaendert)} Einstellung(en) aus {quelle.name} eingetragen"
              + (f": {', '.join(geaendert)}" if geaendert else " (alles schon aktuell)")
              + (f". Unbekannt und ausgelassen: {', '.join(fremd)}" if fremd else ""))
    for ordner in ("faelle", "protokoll/sitzungen"):
        (PROJEKT / ordner).mkdir(parents=True, exist_ok=True)
    gesetzt = env_lesen(datei)
    schluessel = [n for n in ("SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "SPUR_TOKEN", "ABUSEIPDB_API_KEY", "URLQUERY_API_KEY",
                              "RANSOMWARE_LIVE_API_KEY", "RAPIDAPI_KEY")]
    vorhanden = [n for n in schluessel if gesetzt.get(n)]
    zeile(GUT if vorhanden else AUS, "Schlüssel", f"{len(vorhanden)} von {len(schluessel)} eingetragen"
          + ("" if len(vorhanden) == len(schluessel) else ". Jede Quelle ist für sich optional, sechs laufen ohne Schlüssel."))
    if len(vorhanden) < len(schluessel):
        stand.offen.append("Schlüssel in .env eintragen (welche fehlen und woher man sie bekommt, steht oben unter Quellen). "
                           f"Danach testen: {PY} tools/pruefen.py --live")


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
    if docker["compose"]:
        code, text = lauf(docker["compose"] + ["-f", str(PROJEKT / "docker-compose.yml"), "up", "-d", "webcheck"], 1800, "docker.log", env)
        if code == 0:
            zeile(GUT, "Web-Check", f"läuft auf 127.0.0.1:{env.get('WEBCHECK_PORT', '3000')}")
        else:
            zeile(AUS, "Web-Check", f"liess sich nicht starten (Port belegt? Dann WEBCHECK_PORT setzen). Details: {LOGS / 'docker.log'}")
    else:
        zeile(AUS, "Web-Check", "braucht Docker Compose")
    if a.ohne_robin:
        zeile(AUS, "Robin", "übersprungen (--ohne-robin)")
        return False
    abbild = env.get("ROBIN_IMAGE") or "apurvsg/robin:latest"
    if lauf(docker["vor"] + ["docker", "image", "inspect", abbild], 60)[0] == 0:
        zeile(GUT, "Robin", f"Abbild bereit ({abbild})")
        return True
    if lauf(docker["vor"] + ["docker", "pull", abbild], 3600, "docker.log")[0] == 0:
        zeile(NEU, "Robin", f"Abbild geladen ({abbild})")
        stand.neu.append("Robin-Abbild")
        return True
    zeile(AUS, "Robin", f"Abbild {abbild} liess sich nicht laden. Dark-Web-Suche bleibt aus. Details: {LOGS / 'docker.log'}")
    return False


# --------------------------------------------------------------------------- Schritt 5: Claude Code

def modellwunsch(a: argparse.Namespace) -> str | None:
    """Gewünschtes Modell der Ermittlungsphase: Option, sonst OSINT_ERMITTLUNGSMODELL aus .env, sonst None (unverändert)."""
    wunsch = (a.ermittlungsmodell or env_lesen(PROJEKT / ".env").get("OSINT_ERMITTLUNGSMODELL") or "").strip()
    if not wunsch:
        return None
    modell = MODELLE.get(wunsch.lower(), wunsch)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:\[\]@/-]{1,80}", modell):
        raise SystemExit(f"FEHLER: '{wunsch}' ist kein Modellname. Erlaubt: fable, mythos oder eine Modell-ID wie "
                         f"{MODELLE['mythos']}. (Angabe über --ermittlungsmodell oder OSINT_ERMITTLUNGSMODELL in .env)")
    return modell


def agentenmodelle() -> dict[str, str]:
    modelle = {}
    for datei in sorted((PROJEKT / ".claude" / "agents").glob("*.md")):
        m = re.search(r"^model:\s*(\S+)\s*$", datei.read_text(encoding="utf-8").split("---")[1], re.M)
        modelle[datei.stem] = m.group(1) if m else "inherit"
    return modelle


def lokale_einstellungen(robin: bool, wunsch: str | None) -> tuple[list[str], str, bool]:
    """Schreibt .claude/settings.local.json: freigeschaltete MCP-Server und Modell der Ermittlungsphase.
    Fremde Einträge bleiben erhalten. Gibt (freigeschaltete Server, Modell der Ermittlung, Datei neu angelegt) zurück."""
    datei = PROJEKT / ".claude" / "settings.local.json"
    erstmals = not datei.is_file()
    try:
        daten = json.loads(datei.read_text(encoding="utf-8")) if datei.is_file() else {}
    except json.JSONDecodeError:
        daten = {}
    if not isinstance(daten, dict):
        daten = {}
    an = [s for s in daten.get("enabledMcpjsonServers", []) if s not in ("osint", "robin")] + ["osint"] + (["robin"] if robin else [])
    ab = [s for s in daten.get("disabledMcpjsonServers", []) if s not in ("osint", "robin")] + ([] if robin else ["robin"])
    daten["enabledMcpjsonServers"], daten["disabledMcpjsonServers"] = an, ab

    projektmodell = json.loads((PROJEKT / ".claude" / "settings.json").read_text(encoding="utf-8")).get("model", "")
    if wunsch is not None:
        if wunsch == projektmodell:
            daten.pop("model", None)        # entspricht dem Standard des Projekts: keine lokale Abweichung nötig
        else:
            daten["model"] = wunsch
    ermittlung = daten.get("model") or projektmodell

    plattform.text_schreiben(datei, json.dumps(daten, indent=2, ensure_ascii=False) + "\n")
    return an, ermittlung, erstmals


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


def claude_code(a: argparse.Namespace, robin: bool) -> None:
    schritt(5, "Claude Code")
    an, ermittlung, erstmals = lokale_einstellungen(robin, modellwunsch(a))
    zeile(GUT, "MCP-Server", "freigeschaltet: " + ", ".join(an) + ("" if robin else "   (robin aus: kein Docker oder kein Abbild)"))
    if WINDOWS:
        gateway_python()
    modelle = agentenmodelle()
    analysten = [n for n, m in modelle.items() if m == "inherit"]
    abschluss = sorted({m for m in modelle.values() if m != "inherit"})
    zeile(GUT, "Modell Ermittlung", f"{ermittlung}   (Hauptsitzung und {len(analysten)} Analysten)")
    zeile(GUT, "Modell Abschluss", f"{', '.join(abschluss) or ermittlung}   ({', '.join(n for n, m in modelle.items() if m != 'inherit')}, Rapport und Protokoll)")
    if ermittlung == MODELLE["mythos"]:
        stand.offen.append("Mythos 5.2 steht nur verifizierten Organisationen offen. Meldet Claude Code beim Start, das Modell sei "
                           f"nicht verfügbar: {SETUP} --ermittlungsmodell fable")

    pfad = plattform.programm("claude")
    if not pfad:
        zeile(AUS, "Anmeldung", "nicht prüfbar, Claude Code fehlt")
        return
    code, text = lauf([pfad, "auth", "status", "--json"], 60)
    try:
        status = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except ValueError:
        status = {}
    ueber_umgebung = [n for n in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
                                  "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY") if os.environ.get(n)]
    if status.get("loggedIn"):
        zeile(GUT, "Anmeldung", f"angemeldet ({status.get('authMethod') or 'Konto'})")
    elif ueber_umgebung:
        zeile(GUT, "Anmeldung", f"über die Umgebung gesetzt ({', '.join(ueber_umgebung)})")
    else:
        zeile(AUS, "Anmeldung", "keine Anmeldung gefunden")
        stand.offen.append("Bei Claude Code anmelden: im Projektordner 'claude' starten und der Anmeldung im Browser folgen. "
                           "(Läuft Claude Code bei euch über einen API-Schlüssel oder Cloud-Anbieter, entfällt das.)")
    if erstmals:
        stand.offen.append("Beim ersten Start von 'claude' im Projektordner fragt Claude Code einmal, ob es dem Ordner "
                           "vertrauen soll. Mit Ja bestätigen: Erst dann gelten Wächter, Protokoll und MCP-Server.")


# --------------------------------------------------------------------------- Schritt 6: Musterfall und Prüfung

def pruefung() -> int:
    schritt(6, "Musterfall und Prüfung")
    code, text = lauf([str(VENV), str(PROJEKT / "tools" / "musterfall.py")], 600, "muster.log")
    if code != 0:
        zeile(FEHLT, "Musterfall", "liess sich nicht bauen")
        print(letzte_zeilen(text, 6))
        stand.noetig.append("Musterfall")
        stand.offen.append(f"Meldung oben beheben. Vollständig: {LOGS / 'muster.log'}")
        return 1
    zeile(GUT, "Musterfall", "gebaut: faelle/MUSTER-2026-001/rapport/Abschlussrapport.html")
    sys.stdout.flush()
    return subprocess.call([str(VENV), str(PROJEKT / "tools" / "pruefen.py"), "--eingebettet"])


def abschluss(code: int) -> int:
    if stand.neues_terminal:
        stand.offen.insert(0, "Ein neues Terminal öffnen, bevor ihr 'claude' startet. Erst dort gilt: "
                           + " und ".join(stand.neues_terminal) + ".")
    if stand.neu:
        print("\n" + fett("Neu eingerichtet"))
        for was in stand.neu:
            print(f"  {NEU} {was}")
    if stand.offen:
        print("\n" + fett("Das bleibt für euch"))
        for nr, was in enumerate(dict.fromkeys(stand.offen), 1):
            print(f"  {nr}. {was}")
    if stand.noetig or code:
        print("\n" + fett("NICHT einsatzbereit.") + (f" Es fehlt: {', '.join(dict.fromkeys(stand.noetig))}." if stand.noetig else "")
              + (" Die Prüfung oben meldet Fehler (Zeilen mit " + FEHLT + ")." if code and "Musterfall" not in stand.noetig else ""))
        return 1
    print("\n" + fett("So geht es weiter"))
    print(f"  Musterfall ansehen:  faelle/MUSTER-2026-001/rapport/Abschlussrapport.html\n"
          f"  Fall anlegen:        {PY} tools/fall.py neu 2026-0001 --titel \"…\" --rapport <pseudonymisiertes Dokument>\n"
          f"  Ermitteln:           claude      und dort      /ermittlung 2026-0001\n"
          f"  Stand prüfen:        {PY} tools/pruefen.py      mit Testabfragen: {PY} tools/pruefen.py --live")
    return 0


def main(argv: list[str]) -> int:
    plattform.utf8()
    p = argparse.ArgumentParser(add_help=False)
    for name in ("nur-pruefen", "nichts-installieren", "docker-installieren", "ohne-docker", "ohne-robin"):
        p.add_argument(f"--{name}", action="store_true")
    p.add_argument("--ermittlungsmodell")
    p.add_argument("--env-von")
    p.add_argument("-h", "--hilfe", "--help", action="store_true", dest="hilfe")
    a, unbekannt = p.parse_known_args(argv)
    if a.hilfe:
        print(__doc__)
        return 0
    if unbekannt:
        print(f"FEHLER: Unbekannte Option: {' '.join(unbekannt)}   (Hilfe: {SETUP} --hilfe)", file=sys.stderr)
        return 2
    if a.env_von and not Path(a.env_von).expanduser().is_file():
        print(f"FEHLER: --env-von: Datei nicht gefunden: {a.env_von}", file=sys.stderr)
        return 2
    os.chdir(PROJEKT)
    modellwunsch(a)         # eine falsche Angabe soll sofort auffallen, nicht erst nach der halben Einrichtung
    sysinfo = system()
    print(fett("OSINT-Ermittlungsarbeitsplatz einrichten") + ("   (nur prüfen, es wird nichts verändert)" if a.nur_pruefen else ""))
    print(f"System: {sysinfo['name']}   Paketverwaltung: {sysinfo['paketverwaltung'] or 'keine gefunden'}   Ordner: {PROJEKT}")

    docker = voraussetzungen(a, sysinfo)
    if a.nur_pruefen:
        modellwunsch(a)
        print("\n" + (fett("Es fehlt Nötiges: ") + ", ".join(dict.fromkeys(stand.noetig)) if stand.noetig
                      else "Alles Nötige ist vorhanden."))
        for nr, was in enumerate(dict.fromkeys(stand.offen), 1):
            print(f"  {nr}. {was}")
        print(f"Einrichten: {SETUP}")
        return 1 if stand.noetig else 0
    if "venv und pip" in stand.noetig or not python_umgebung():
        return abschluss(1)
    konfiguration(a)
    robin = dienste(a, docker)
    claude_code(a, robin)
    return abschluss(pruefung())


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print(f"\nAbgebrochen. {SETUP} lässt sich jederzeit erneut starten.", file=sys.stderr)
        sys.exit(130)
