#!/usr/bin/env python3
"""Was zum Arbeitsplatz gehört und gerade läuft: zeigen, abschalten, wieder einschalten.

    python3 tools/dienste.py          zeigt, was läuft
    python3 tools/dienste.py aus      schaltet alles ab: die Oberfläche samt laufender Ermittlung, Robin, Web-Check und Tor
    python3 tools/dienste.py ein      schaltet Web-Check und Tor wieder ein. Die Oberfläche startet: python3 tools/oberflaeche.py

Abgeschaltet wird nur, was zum Arbeitsplatz gehört. Docker selbst läuft weiter: Es kann auch anderem dienen. Tor fasst
das Werkzeug nur an, wenn der Arbeitsplatz es als Proxy nutzt («Tor auf diesem Rechner»), und dafür braucht es einmal
euer Passwort (sudo). In der Oberfläche gibt es dasselbe als Knopf «Alles abschalten». Er lässt Tor laufen: Ein Browser
kann nicht nach dem Passwort fragen.

Gelöscht wird dabei nichts. Fallakten, Schlüssel und Einstellungen bleiben, wie sie sind.

aus und ein verlangen ein Terminal: Das entscheidet ein Mensch. Rückgabewert 0: erledigt. 1: Etwas liess sich nicht
schalten. 2: falscher Aufruf oder kein Terminal.

Eine laufende Oberfläche findet «aus» über einen Merker (Prozessnummer und Port, kein Geheimnis) in einem Ordner des
Kontos im temporären Ordner des Systems. Beendet wird sie über eine Bitte, die sie selbst liest: So hält sie ihre
Ermittlungen an und vermerkt es, auf jedem System. Hart beendet wird ein Prozess erst, wenn sie nicht reagiert, und
nur der, der sich auf dem Port als diese Oberfläche ausweist.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform, robin as robin_antwort  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.plattform import AUS, FEHLT, GUT, PY, SETUP, WINDOWS  # noqa: E402
from tools import einrichten  # noqa: E402

WEBCHECK = "osint-webcheck"         # so heisst der Container in docker-compose.yml
# Bis zum 20.11.2026 hängte .mcp.json dieses Docker-Volume in Robins Container ein: Robin konnte dort eigene Recherchen ablegen,
# ausserhalb der Fallakte. Seither wird es nicht mehr eingehängt. Wo es von früher noch da ist, zeigt der Stand es an. Entfernt
# wird hier nichts: Das tun die Einrichtung (nur ein leeres) und «Alles löschen» (nach dem Sichern), beide über tools/loeschen.py.
ROBIN_VOLUME = "robin-investigations"
Zeile = tuple[str, str, str]        # Zeichen, was, wie
MERKER_BASIS: Path | None = None    # nur für die Selbsttests: Sie legen ihre Merker nicht zu denen einer echten Oberfläche
STUMM: dict = {"stumm": True}       # Antwort von _auskunft(): Auf dem Port hört jemand, antwortet aber nicht rechtzeitig


# --------------------------------------------------------------------------- Stand

def docker_kurz() -> dict:
    """installiert, laeuft, vor (Vorspann sudo, falls Docker nur so erreichbar ist). Wie einrichten.docker_stand(), aber mit
    einem einzigen kurzen Aufruf und ohne Compose: Mehr braucht es zum Zeigen und Schalten nicht."""
    d = {"installiert": bool(shutil.which("docker")), "laeuft": False, "vor": []}
    if not d["installiert"]:
        return d
    frage = ["docker", "version", "--format", "{{.Server.Version}}"]        # scheitert, wenn der Dienst nicht erreichbar ist
    # Kurze Fristen: Hängt Docker, soll die Seite «Arbeitsplatz» nicht lange warten. Ein laufender Dienst antwortet sofort
    if einrichten.lauf(frage, 8)[0] == 0:
        d["laeuft"] = True
    elif not WINDOWS and os.geteuid() != 0 and shutil.which("sudo") and einrichten.lauf(["sudo", "-n"] + frage, 8)[0] == 0:
        d["laeuft"], d["vor"] = True, ["sudo", "-n"]        # der Dienst läuft, aber das Konto ist noch nicht in der Gruppe docker
    return d


def robin_abbild() -> str:
    return plattform.einstellung("ROBIN_IMAGE") or plattform.ROBIN_ABBILD


def webcheck(docker: dict) -> str:
    """Der Container von Web-Check: "laeuft", "aus", "fehlt" (nie eingerichtet) oder "" (Docker ist nicht erreichbar)."""
    if not docker["laeuft"]:
        return ""
    code, text = einrichten.lauf(docker["vor"] + ["docker", "inspect", "-f", "{{.State.Running}}", WEBCHECK], 10)
    if code != 0:
        return "fehlt"
    return "laeuft" if text.strip() == "true" else "aus"


def robin(docker: dict) -> list[str]:
    """Die laufenden Container von Robin. Claude Code startet je Sitzung einen und entfernt ihn an ihrem Ende."""
    if not docker["laeuft"]:
        return []
    code, text = einrichten.lauf(docker["vor"] + ["docker", "ps", "-q", "--filter", f"ancestor={robin_abbild()}"], 10)
    return text.split() if code == 0 else []


def robin_ablage(docker: dict) -> dict | None:
    """Das Docker-Volume aus einer früheren Einrichtung, in das Robin eigene Recherchen ablegen konnte. None: Es gibt keines
    (oder Docker ist nicht erreichbar). Sonst {"dateien": Zahl der Dateien darin, None wenn sie sich nicht zählen lassen}."""
    if not docker["laeuft"] or einrichten.lauf(docker["vor"] + ["docker", "volume", "inspect", ROBIN_VOLUME], 10)[0] != 0:
        return None
    # Zählen kann nur ein Container. Robins Abbild bringt das Nötige mit. Fehlt es, bleibt die Zahl offen
    code, text = einrichten.lauf(docker["vor"] + ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", "-v", f"{ROBIN_VOLUME}:/v:ro",
                                                 robin_abbild(), "-c", "find /v -type f | wc -l"], 60)
    letzte = (text.strip().splitlines() or [""])[-1].strip()
    return {"dateien": int(letzte) if code == 0 and letzte.isdigit() else None}


def robin_bereitschaft(docker: dict, frist: int = 90, maschinen: bool = True, melden=None, pause: float = 5.0) -> dict:
    """Startet Robin so, wie Claude Code es tut, und fragt, ob Tor im Container bereit ist. Es wird nichts gesucht und keine Seite
    gelesen. Dass das Abbild geladen ist, sagt darüber nichts: Lässt das Netz Tor nicht zu, antwortet Robin auf jede Suche mit
    «Tor ist noch nicht bereit» (gesehen am 20.11.2026).

    Rückgabe: {"gestartet", "tor", "sekunden", "maschinen" ("14 von 16" oder None), "fehler"}. `melden(text)` bekommt den Stand,
    solange gewartet wird. `maschinen`: Steht Tor, fragt Robin zusätzlich jede Suchmaschine einmal an. `pause`: Sekunden zwischen
    zwei Fragen nach Tor."""
    aus = {"gestartet": False, "tor": False, "sekunden": 0, "maschinen": None, "fehler": ""}
    name = f"osint-robin-pruefung-{os.getpid()}"
    try:
        p = subprocess.Popen(docker["vor"] + ["docker", "run", "-i", "--rm", "--name", name, robin_abbild(), "mcp"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as e:
        return {**aus, "fehler": f"Der Container liess sich nicht starten ({type(e).__name__}: {e})."}
    antworten: queue.Queue = queue.Queue()

    def lesen() -> None:
        for zeile in p.stdout:
            with contextlib.suppress(ValueError):
                antworten.put(json.loads(zeile))

    threading.Thread(target=lesen, daemon=True).start()
    nummer = 0

    def frage(methode: str, angaben: dict | None = None, warten: float = 30.0) -> dict | None:
        nonlocal nummer
        nummer += 1
        try:
            p.stdin.write((json.dumps({"jsonrpc": "2.0", "id": nummer, "method": methode, **({"params": angaben} if angaben is not None else {})}) + "\n").encode())
            p.stdin.flush()
        except OSError:
            return None
        ende = time.monotonic() + warten
        while time.monotonic() < ende and p.poll() is None:
            try:
                antwort = antworten.get(timeout=min(1.0, max(0.05, ende - time.monotonic())))
            except queue.Empty:
                continue
            if antwort.get("id") == nummer:
                return antwort
        return None

    def bereitschaft(mit_maschinen: bool, warten: float) -> dict | None:
        antwort = frage("tools/call", {"name": "robin_health", "arguments": {"check_engines": True} if mit_maschinen else {}}, warten)
        if not antwort or "result" not in antwort:
            return None
        return robin_antwort.einordnen("robin_health", robin_antwort.text_aus((antwort["result"] or {}).get("content")))

    anfang = time.monotonic()
    try:
        erste = frage("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "osint-pruefung", "version": "1"}}, 60.0)
        if not erste or "result" not in erste:
            return {**aus, "fehler": "Robin hat nach dem Start nicht geantwortet (Abbild beschädigt, oder Docker hat den Container nicht gestartet)."}
        aus["gestartet"] = True
        with contextlib.suppress(OSError):
            p.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode())
            p.stdin.flush()
        while True:
            stand_ = bereitschaft(False, 30.0)
            aus["sekunden"] = int(time.monotonic() - anfang)
            if stand_ is None:
                return {**aus, "fehler": "Robin hat auf die Frage nach der Bereitschaft nicht geantwortet."}
            if stand_.get("tor"):
                aus["tor"] = True
                break
            if time.monotonic() - anfang >= frist:
                return aus
            if melden:
                melden(f"Tor im Container startet ({aus['sekunden']} von höchstens {frist} Sekunden)")
            time.sleep(pause)
        if maschinen:
            if melden:
                melden("Tor steht. Robin fragt die Suchmaschinen an")
            stand_ = bereitschaft(True, 180.0)
            aus["maschinen"] = (stand_ or {}).get("maschinen")
        return aus
    finally:
        with contextlib.suppress(OSError):
            p.stdin.close()
        with contextlib.suppress(OSError):
            p.terminate()
        try:
            p.wait(15)
        except subprocess.TimeoutExpired:
            p.kill()
        einrichten.lauf(docker["vor"] + ["docker", "stop", "-t", "2", name], 30)      # falls der Container das Ende nicht mitbekam. Er entfernt sich danach selbst


def tor() -> dict:
    """gehoert: Der Arbeitsplatz nutzt Tor auf diesem Rechner als Proxy. laeuft: Auf dessen Adresse antwortet etwas."""
    proxy = plattform.einstellung("OSINT_PROXY")
    gehoert = bool(proxy) and plattform.proxy_ist_tor(proxy)
    return {"gehoert": gehoert, "laeuft": bool(gehoert and plattform.proxy_antwortet(proxy))}


def stand(mit_oberflaeche: bool = True) -> dict:
    """Was gerade läuft, in einem Stück: für die Anzeige im Terminal und in der Oberfläche. Die Oberfläche fragt sich dabei
    nicht selbst (mit_oberflaeche=False): Sie weiss, dass sie läuft, und eine Anfrage an sich selbst müsste auf sich warten."""
    docker = docker_kurz()
    return {"docker": docker, "webcheck": webcheck(docker), "robin": robin(docker), "robin_ablage": robin_ablage(docker), "tor": tor(),
            "oberflaechen": oberflaechen() if mit_oberflaeche else None}


def stand_zeilen(s: dict | None = None) -> list[Zeile]:
    s = s or stand()
    zeilen: list[Zeile] = []
    offen = s["oberflaechen"]
    if offen is not None:
        ports = ", ".join(str(o["port"]) + (" (antwortet gerade nicht)" if o.get("stumm") else "") for o in offen)
        zeilen.append((GUT, "Oberfläche", f"läuft auf Port {ports}") if offen else (AUS, "Oberfläche", "läuft nicht"))
    if not s["docker"]["installiert"]:
        zeilen.append((AUS, "Docker", "nicht installiert: Web-Check und Robin gibt es hier nicht"))
    elif not s["docker"]["laeuft"]:
        zeilen.append((AUS, "Docker", "läuft nicht oder ist aus diesem Terminal nicht erreichbar"))
    else:
        zeilen.append({"laeuft": (GUT, "Web-Check", "läuft"), "aus": (AUS, "Web-Check", "abgeschaltet"),
                       "fehlt": (AUS, "Web-Check", "nicht eingerichtet")}[s["webcheck"]])
        zeilen.append((GUT, "Robin", f"{len(s['robin'])} Container, je einer pro laufender Sitzung von Claude Code") if s["robin"]
                      else (AUS, "Robin", "läuft nicht. Es startet mit jeder Ermittlung von selbst"))
        ablage = s.get("robin_ablage")
        if ablage:
            n = ablage["dateien"]
            zeilen.append((AUS, "Ablage von Robin", f"Das Docker-Volume {ROBIN_VOLUME} aus einer früheren Einrichtung gibt es noch ("
                           + ("leer" if n == 0 else f"{n} {'Datei' if n == 1 else 'Dateien'}" if n else "Inhalt nicht gezählt")
                           + f"). Es wird nicht mehr verwendet. {'Entfernen' if n == 0 else 'Ansehen, dann entfernen'}: docker volume rm {ROBIN_VOLUME}"))
    if s["tor"]["gehoert"]:
        zeilen.append((GUT, "Tor (Proxy)", "läuft") if s["tor"]["laeuft"] else (AUS, "Tor (Proxy)", "läuft nicht"))
    return zeilen


# --------------------------------------------------------------------------- Welche Fassung läuft hier?

# Am 20.11.2026 lief am Arbeitsplatz des Eigentümers eine Fassung von vor dem 19.11., ohne dass es irgendwo stand: Die
# Korrekturen lagen im Repository, aber nicht auf dem Rechner. Seither zeigen Oberfläche und Prüfung, welche Fassung hier
# liegt, und die Oberfläche fragt beim Start einmal beim Git-Server nach, ob es eine neuere gibt. Die Anfrage geht direkt
# hinaus, wie «git pull», nicht über OSINT_PROXY: Aus einem Fall steht nichts darin.
STAND_PRUEFEN = "OSINT_STAND_PRUEFEN"       # «0», «nein» oder «aus»: Die Oberfläche fragt beim Start nicht nach einer neueren Fassung
_FASSUNG: dict = {}                         # was fassung_stand() zuletzt festgestellt hat


def fassung(projekt: Path | None = None) -> dict | None:
    """Welche Fassung des Arbeitsplatzes in diesem Ordner liegt, laut Git: {"commit", "datum", "zweig"}. Fragt nichts im Netz.
    None ohne Git oder ausserhalb eines Git-Arbeitsverzeichnisses (zum Beispiel aus einem Archiv entpackt)."""
    ordner = str(projekt or plattform.PROJEKT)
    if not eigenes_git(ordner):
        return None
    code, text = einrichten.lauf(["git", "-C", ordner, "log", "-1", "--format=%h%x09%cI"], 15)
    # Die Zeile mit dem Commit wird an ihrer Form erkannt, nicht an ihrer Stelle: lauf() hängt den Fehlerkanal hinter die Ausgabe, und
    # eine Warnung von Git stand bis zum 23.11.2026 als «letzte Zeile» da. Dann galt die Fassung als nicht feststellbar
    zeile = next((z for z in text.splitlines() if re.fullmatch(r"[0-9a-f]{4,40}\t\S+", z.strip())), "") if code == 0 else ""
    if not zeile:
        return None
    commit, datum = zeile.strip().split("\t", 1)
    code, text = einrichten.lauf(["git", "-C", ordner, "rev-parse", "--abbrev-ref", "HEAD"], 15)
    zweig = next((z.strip() for z in text.splitlines() if re.fullmatch(r"[\w./+@-]{1,200}", z.strip())), "") if code == 0 else ""
    return {"commit": commit, "datum": datum, "zweig": zweig}


def eigenes_git(ordner: str) -> bool:
    """Ist dieser Ordner selbst ein Git-Arbeitsverzeichnis? «git -C» sucht sonst nach oben: Liegt ein entpackter Arbeitsplatz in einem
    Ordner, der einem anderen Repository gehört, nähme er dessen Fassung für die eigene und fragte dessen Server (so bis zum
    23.11.2026). «.git» ist ein Ordner oder, in einem zweiten Arbeitsbaum, eine Datei."""
    return (Path(ordner) / ".git").exists()


def ssh_vorgabe(ordner: str) -> dict[str, str]:
    """Was die Nachfrage beim Git-Server für SSH mitgibt: kein Anmeldedialog und eine kurze Frist. Nur, wenn nichts eingestellt ist.
    GIT_SSH_COMMAND aus der Umgebung geht einer Einstellung core.sshCommand und GIT_SSH vor: Wer dort ein eigenes Programm führt
    (unter Windows oft das SSH von Windows mit dessen Schlüsselagenten, oder «ssh -i <Schlüssel>»), verlöre es sonst für diese eine
    Anfrage, und sie scheiterte (so bis zum 23.11.2026)."""
    if os.environ.get("GIT_SSH_COMMAND") or os.environ.get("GIT_SSH"):
        return {}
    code, text = einrichten.lauf(["git", "-C", ordner, "config", "--get", "core.sshCommand"], 15)
    if code == 0 and text.strip():
        return {}
    return {"GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o ConnectTimeout=5"}


def fassung_fern(projekt: Path | None = None, zeit: int = 8) -> dict | None:
    """Gibt es im Repository, aus dem dieser Ordner stammt, eine neuere Fassung? Eine Anfrage an den Git-Server (origin), ohne
    Anmeldedialog und mit kurzer Frist. Es geht dabei nichts aus einem Fall hinaus. {"commit": Stand des Hauptzweigs dort,
    "neuer": bool}: «neuer» heisst, dieser Stand ist in dem, was hier ausgecheckt ist, noch nicht enthalten (auch wenn er schon
    geholt, aber nicht übernommen wurde). None, wenn es sich nicht feststellen lässt (kein Netz, kein Git, keine Anmeldung
    beim Server)."""
    ordner = str(projekt or plattform.PROJEKT)
    if not eigenes_git(ordner):
        return None
    umgebung = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", **ssh_vorgabe(ordner)}
    code, text = einrichten.lauf(["git", "-C", ordner, "ls-remote", "origin", "HEAD"], zeit, env=umgebung)
    treffer = re.search(r"^([0-9a-f]{40})\s+HEAD\s*$", text, re.M) if code == 0 else None
    if not treffer:
        return None
    commit = treffer.group(1)
    code, _ = einrichten.lauf(["git", "-C", ordner, "merge-base", "--is-ancestor", commit, "HEAD"], 15)      # 0: hier schon enthalten
    return {"commit": commit, "neuer": code != 0}


def fassung_text(f: dict | None) -> str:
    """Die Fassung in einer Zeile: «Fassung vom 20.11.2026 (ac08af8)». Leer, wenn sie sich nicht feststellen lässt."""
    if not f:
        return ""
    try:
        tag = datetime.fromisoformat(f["datum"]).strftime("%d.%m.%Y")
    except (KeyError, ValueError):
        tag = "unbekanntem Datum"
    zweig = f.get("zweig") or ""
    return f"Fassung vom {tag} ({f.get('commit', '?')}" + (f", Zweig {zweig}" if zweig not in ("", "main", "HEAD") else "") + ")"


AKTUALISIEREN = f"Aktualisieren: die Oberfläche beenden, im Projektordner «git pull» ausführen, dann «{SETUP}» («Prüfen und auffrischen»)."


def fassung_stand(fern: bool = False, projekt: Path | None = None) -> dict:
    """Was Oberfläche und Prüfung zur Fassung zeigen: {"text", "neuer" (True, False oder None: nicht gefragt oder nicht feststellbar),
    "hinweis"}. `fern`: beim Git-Server nachfragen. Ohne `fern` kommt, was zuletzt festgestellt wurde."""
    if fern or "text" not in _FASSUNG:
        lokal = fassung(projekt)
        _FASSUNG.update(text=fassung_text(lokal), neuer=_FASSUNG.get("neuer"), hinweis=_FASSUNG.get("hinweis", ""))
        if fern and lokal:
            antwort = fassung_fern(projekt)
            neuer = None if antwort is None else bool(antwort["neuer"])
            _FASSUNG.update(neuer=neuer, hinweis=("Im Repository liegt eine neuere Fassung dieses Arbeitsplatzes. " + AKTUALISIEREN) if neuer else "")
    return dict(_FASSUNG)


def fassung_fragen() -> bool:
    """Darf beim Git-Server nachgefragt werden? Nein, wenn es abgestellt ist (OSINT_STAND_PRUEFEN=0). Das gilt für die Oberfläche
    und für die Prüfung der Einrichtung."""
    return plattform.einstellung(STAND_PRUEFEN, "1").strip().lower() not in ("0", "nein", "aus", "false", "no")


def fassung_beim_start() -> list[str]:
    """Was die Oberfläche beim Start zur Fassung sagt. Fragt beim Git-Server nach, ausser es ist abgestellt (OSINT_STAND_PRUEFEN=0)."""
    s = fassung_stand(fern=fassung_fragen())
    return [satz for satz in (s["text"] and f"{s['text']}.", s["hinweis"]) if satz]


# --------------------------------------------------------------------------- Die Oberfläche finden und beenden

def kennung() -> str:
    """Woran sich die Oberflächen dieses Projekts erkennen: am Ordner des Projekts. Zwei Klone haben zwei Kennungen."""
    return hashlib.sha256(str(plattform.PROJEKT).encode("utf-8")).hexdigest()[:12]


def _merker_ordner() -> Path | None:
    """Wo laufende Oberflächen festhalten, dass es sie gibt: in einem Ordner nur für dieses Konto, nie im Projekt. Unter Linux und
    macOS teilen sich alle Konten den temporären Ordner. Gehört der Ordner dort jemand anderem oder dürfen andere hineinschreiben,
    gilt er nicht: Ein fremder Merker könnte uns sonst einen fremden Prozess zum Beenden unterschieben."""
    basis = Path(MERKER_BASIS or tempfile.gettempdir())
    # Unter Windows gehört der temporäre Ordner dem Konto. Sonst trägt der Name die Nummer des Kontos, und geprüft wird, wem er gehört
    ordner = basis / ("osint-arbeitsplatz" if WINDOWS else f"osint-arbeitsplatz-{os.getuid()}")
    try:
        ordner.mkdir(mode=0o700, exist_ok=True)
        lage = ordner.lstat()
        if not stat.S_ISDIR(lage.st_mode) or (not WINDOWS and (lage.st_uid != os.getuid() or lage.st_mode & 0o022)):
            return None
    except OSError:
        return None
    return ordner


def _merker(port: int | str, endung: str = "json") -> Path | None:
    """Der Merker einer Oberfläche dieses Projekts (Prozessnummer und Port, kein Geheimnis) und, mit der Endung «ende», die Bitte
    an sie, sich zu beenden. So findet «aus» sie, auch aus einem anderen Terminal."""
    ordner = _merker_ordner()
    return ordner / f"oberflaeche-{kennung()}-{port}.{endung}" if ordner is not None else None


def _weg(datei: Path | None) -> None:
    if datei is not None:
        with contextlib.suppress(OSError):
            datei.unlink()


def oberflaeche_merken(port: int) -> None:
    """Hält fest, dass auf diesem Port eine Oberfläche dieses Projekts läuft. Räumt dabei weg, was abgestürzte Oberflächen
    irgendeines Projekts liegen liessen: Merker, die älter sind als eine Minute und hinter denen keine Oberfläche mehr antwortet."""
    datei = _merker(port)
    if datei is None:
        return
    for alt in datei.parent.glob("oberflaeche-*.json"):
        try:
            if time.time() - alt.stat().st_mtime > 60 and _auskunft(int(json.loads(alt.read_text(encoding="utf-8"))["port"])) is None:
                _weg(alt)
                _weg(alt.with_suffix(".ende"))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    _weg(_merker(port, "ende"))        # eine alte Bitte ums Ende gilt der neuen Oberfläche nicht
    with contextlib.suppress(OSError):
        datei.write_text(json.dumps({"pid": os.getpid(), "port": port, "projekt": str(plattform.PROJEKT)}), encoding="utf-8")


def oberflaeche_soll_enden(port: int) -> bool:
    """Hat «aus» diese Oberfläche gebeten, sich zu beenden? Sie fragt das jede halbe Sekunde und endet dann wie mit Strg+C:
    Laufende Ermittlungen hält sie vorher selbst an. Das geht auf jedem System, auch unter Windows. Die Bitte verschwindet
    dabei: Daran sieht «aus», dass sie angenommen ist und die Oberfläche aufräumt."""
    bitte = _merker(port, "ende")
    if bitte is None or not bitte.exists():
        return False
    _weg(bitte)
    return True


def oberflaeche_vergessen(port: int) -> None:
    _weg(_merker(port))
    _weg(_merker(port, "ende"))


def _auskunft(port: int) -> dict | None:
    """Was die Oberfläche auf diesem Port über sich sagt (Prozessnummer, Kennung des Projekts). None: Dort hört niemand, oder es
    antwortet etwas anderes. STUMM: Es hört jemand, antwortet aber nicht rechtzeitig. Gefragt wird nur der eigene Rechner, nie
    über einen Proxy."""
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{port}/api/bedienung", timeout=3) as antwort:
            angaben = json.loads(antwort.read().decode("utf-8", errors="replace"))
    except OSError as e:
        return STUMM if isinstance(getattr(e, "reason", e), TimeoutError) else None
    except ValueError:
        return None
    return angaben if isinstance(angaben, dict) and "aktiv" in angaben else None


def _prozess_lebt(pid: int) -> bool:
    """Gibt es den Prozess noch, und gehört er diesem Konto? Unter Windows lässt sich das ohne Zusatz nicht fragen: dort ja."""
    if WINDOWS:
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _lage(o: dict) -> str:
    """"da": Auf dem Port weist sich dieselbe Oberfläche aus, derselbe Prozess und dasselbe Projekt. Nur dann darf ein Prozess
    beendet werden. "weg": Dort hört niemand mehr, es antwortet etwas anderes, oder den Prozess gibt es nicht mehr. Ein Merker
    von früher, dessen Prozessnummer inzwischen etwas anderem gehört, trifft so niemanden. "stumm": Es hört jemand, antwortet
    aber nicht rechtzeitig. Die Oberfläche ist beschäftigt oder räumt gerade auf."""
    auskunft = _auskunft(o["port"])
    if auskunft is STUMM:
        return "stumm" if _prozess_lebt(o["pid"]) else "weg"
    return "da" if auskunft is not None and auskunft.get("prozess") == o["pid"] and auskunft.get("projekt") == kennung() else "weg"


def oberflaechen() -> list[dict]:
    """Die laufenden Oberflächen dieses Projekts (pid, port, und stumm, wenn sie gerade nicht antwortet). Ein Merker, hinter dem
    keine mehr steht, wird aufgeräumt."""
    ordner = _merker_ordner()
    laufend: list[dict] = []
    for datei in sorted(ordner.glob(f"oberflaeche-{kennung()}-*.json")) if ordner is not None else []:
        try:
            angaben = json.loads(datei.read_text(encoding="utf-8"))
            o = {"pid": int(angaben["pid"]), "port": int(angaben["port"])}
        except (OSError, ValueError, KeyError, TypeError):
            continue
        lage = _lage(o)
        if lage == "weg":
            _weg(datei)
            _weg(datei.with_suffix(".ende"))
        else:
            laufend.append({**o, "stumm": True} if lage == "stumm" else o)
    return laufend


def oberflaeche_beenden(warten: float = 20.0, aufraeumen: float = 60.0) -> list[Zeile]:
    """Beendet die laufenden Oberflächen dieses Projekts. Zuerst die Bitte: Die Oberfläche hält ihre Ermittlungen an, vermerkt es
    und endet selbst. Hat sie die Bitte angenommen, bekommt sie Zeit zum Aufräumen. Antwortet sie nach der Frist weiter, als
    wäre nichts gewesen, beendet das System den Prozess hart: nur den, der sich eben noch als diese Oberfläche ausgewiesen hat."""
    zeilen: list[Zeile] = []
    for o in oberflaechen():
        if o["pid"] == os.getpid():
            continue
        o = {"pid": o["pid"], "port": o["port"]}
        bitte = _merker(o["port"], "ende")
        if bitte is not None:
            with contextlib.suppress(OSError):
                bitte.write_text("", encoding="utf-8")
        beginn = time.monotonic()
        lage = _lage(o)
        while lage != "weg":
            angenommen = bitte is not None and not bitte.exists()
            if time.monotonic() - beginn > warten + (aufraeumen if angenommen else 0):
                break
            time.sleep(0.3)
            lage = _lage(o)
        hart = lage == "da"
        if hart:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                if WINDOWS:
                    subprocess.run(["taskkill", "/PID", str(o["pid"]), "/T", "/F"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=30)
                else:
                    os.kill(o["pid"], signal.SIGKILL)
            time.sleep(1)
            lage = _lage(o)
        if lage != "weg":
            _weg(bitte)
            zeilen.append((FEHLT, "Oberfläche", f"auf Port {o['port']} liess sich nicht beenden. In ihrem Terminal: Strg+C"))
        else:
            oberflaeche_vergessen(o["port"])
            zeilen.append((AUS, "Oberfläche", f"auf Port {o['port']} reagierte nicht und wurde hart beendet. Lief eine Ermittlung, steht ihr "
                                              "Ende nicht im Sitzungsprotokoll") if hart else
                          (GUT, "Oberfläche", f"auf Port {o['port']} beendet. Lief eine Ermittlung, ist sie angehalten"))
    return zeilen


# --------------------------------------------------------------------------- Schalten

def tor_schalten(an: bool) -> tuple[bool, str]:
    """Startet oder stoppt den Dienst Tor. Gibt zurück, ob es gelang, und sonst den Befehl von Hand."""
    wort = "start" if an else "stop"
    if einrichten.system()["art"] == "macos":
        befehl = ["brew", "services", wort, "tor"]
    else:
        vor = einrichten.root_praefix("den Start von Tor" if an else "das Abschalten von Tor")
        if plattform.systemd():
            befehl = ["systemctl", wort, "tor"]
        elif shutil.which("rc-service"):
            befehl = ["rc-service", "tor", wort]
        else:
            befehl = ["service", "tor", wort]
        von_hand = "sudo " + " ".join(befehl)
        if vor is None:
            return False, von_hand
        code, _ = einrichten.lauf(vor + befehl, 120, "tor.log", anzeige="Tor wird gestartet" if an else "Tor wird abgeschaltet")
        return code == 0, von_hand
    code, _ = einrichten.lauf(befehl, 120, "tor.log", anzeige="Tor wird gestartet" if an else "Tor wird abgeschaltet")
    return code == 0, " ".join(befehl)


def aus(mit_tor: bool = True) -> tuple[list[Zeile], bool]:
    """Schaltet ab, was zum Arbeitsplatz gehört und läuft: Robin, Web-Check und, mit mit_tor, Tor. Die Oberfläche beendet der
    Aufrufer (oberflaeche_beenden) oder sie sich selbst. Gibt die Zeilen zurück und ob alles gelang. Gelöscht wird nichts."""
    zeilen: list[Zeile] = []
    gelungen = True
    docker = docker_kurz()
    if not docker["installiert"]:
        zeilen.append((AUS, "Docker", "nicht installiert: Web-Check und Robin gibt es hier nicht"))
    elif not docker["laeuft"]:
        zeilen.append((AUS, "Docker", "läuft nicht oder ist von hier nicht erreichbar. Web-Check und Robin liessen sich nicht prüfen"))
    else:
        container = robin(docker)
        if container:
            code, _ = einrichten.lauf(docker["vor"] + ["docker", "stop", *container], 180, "docker.log", anzeige="Robin wird gestoppt")
            zeilen.append((GUT, "Robin", f"gestoppt ({len(container)} Container)") if code == 0 else
                          (FEHLT, "Robin", f"liess sich nicht stoppen. Details: {einrichten.LOGS / 'docker.log'}"))
            gelungen = gelungen and code == 0
        else:
            zeilen.append((GUT, "Robin", "läuft nicht"))
        lage = webcheck(docker)
        if lage == "laeuft":
            code, _ = einrichten.lauf(docker["vor"] + ["docker", "stop", WEBCHECK], 120, "docker.log", anzeige="Web-Check wird gestoppt")
            zeilen.append((GUT, "Web-Check", "gestoppt. Er bleibt aus, bis ihr ihn wieder einschaltet") if code == 0 else
                          (FEHLT, "Web-Check", f"liess sich nicht stoppen. Details: {einrichten.LOGS / 'docker.log'}"))
            gelungen = gelungen and code == 0
        else:
            zeilen.append((GUT, "Web-Check", "war schon aus") if lage == "aus" else (AUS, "Web-Check", "nicht eingerichtet"))
    t = tor()
    if t["gehoert"] and not t["laeuft"]:
        zeilen.append((GUT, "Tor (Proxy)", "läuft nicht"))
    elif t["gehoert"] and not mit_tor:
        zeilen.append((AUS, "Tor (Proxy)", f"läuft weiter. Tor gehört zum System und braucht euer Passwort: im Terminal {PY} tools/dienste.py aus"))
    elif t["gehoert"]:
        ok, befehl = tor_schalten(False)
        ok = ok and not tor()["laeuft"]
        zeilen.append((GUT, "Tor (Proxy)", "abgeschaltet. Beim nächsten Hochfahren startet es wieder, so richtet es das System ein") if ok else
                      (FEHLT, "Tor (Proxy)", f"liess sich nicht abschalten. Von Hand: {befehl}"))
        gelungen = gelungen and ok
    return zeilen, gelungen


def ein() -> tuple[list[Zeile], bool]:
    """Schaltet wieder ein, was «aus» abgeschaltet hat: Web-Check und Tor. Robin startet mit jeder Ermittlung von selbst."""
    zeilen: list[Zeile] = []
    gelungen = True
    docker = docker_kurz()
    lage = webcheck(docker)
    if lage == "aus":
        code, _ = einrichten.lauf(docker["vor"] + ["docker", "start", WEBCHECK], 120, "docker.log", anzeige="Web-Check wird gestartet")
        zeilen.append((GUT, "Web-Check", "gestartet") if code == 0 else
                      (FEHLT, "Web-Check", f"liess sich nicht starten. Details: {einrichten.LOGS / 'docker.log'}"))
        gelungen = gelungen and code == 0
    elif lage == "laeuft":
        zeilen.append((GUT, "Web-Check", "läuft"))
    elif lage == "fehlt":
        zeilen.append((AUS, "Web-Check", f"nicht eingerichtet. Einrichten: {SETUP}"))
    else:
        zeilen.append((AUS, "Docker", "läuft nicht oder ist von hier nicht erreichbar: Web-Check und Robin bleiben aus"))
    t = tor()
    if t["gehoert"] and t["laeuft"]:
        zeilen.append((GUT, "Tor (Proxy)", "läuft"))
    elif t["gehoert"]:
        ok, befehl = tor_schalten(True)
        ok = ok and einrichten.warten_auf_port(9050, 30)
        zeilen.append((GUT, "Tor (Proxy)", "gestartet. Bis es Verbindungen aufbaut, dauert es bis zu zwei Minuten") if ok else
                      (FEHLT, "Tor (Proxy)", f"liess sich nicht starten. Von Hand: {befehl}"))
        gelungen = gelungen and ok
    return zeilen, gelungen


def beim_start() -> list[str]:
    """Für den Start der Oberfläche: schaltet Web-Check wieder ein, wenn er eingerichtet, aber abgeschaltet ist, und sagt es,
    wenn der Proxy über Tor nicht antwortet. Fragt nie nach einem Passwort. Gibt die Sätze für das Terminal zurück."""
    saetze: list[str] = []
    docker = docker_kurz()
    if webcheck(docker) == "aus":
        code, _ = einrichten.lauf(docker["vor"] + ["docker", "start", WEBCHECK], 120, "docker.log")
        saetze.append("Web-Check war abgeschaltet und läuft wieder." if code == 0 else
                      f"Web-Check ist abgeschaltet und liess sich nicht starten. Einschalten: {PY} tools/dienste.py ein")
    t = tor()
    if t["gehoert"] and not t["laeuft"]:
        saetze.append(f"Tor läuft nicht: Über diesen Proxy käme keine Abfrage durch. Einschalten: {PY} tools/dienste.py ein")
    return saetze


# --------------------------------------------------------------------------- Aufruf

def main(argv: list[str]) -> int:
    if argv[:1] in (["-h"], ["--help"], ["--hilfe"]) or len(argv) > 1 or argv[:1] not in ([], ["stand"], ["aus"], ["ein"]):
        print(__doc__)
        return 0 if argv[:1] in (["-h"], ["--help"], ["--hilfe"]) else 2
    ui = einrichten.ui
    wunsch = argv[0] if argv else "stand"
    if wunsch == "stand":
        ui.kopf("OSINT-Ermittlungsarbeitsplatz · Was läuft", str(plattform.PROJEKT))
        for zeichen, was, wie in stand_zeilen():
            ui.zeile(zeichen, was, wie)
        ui.paare("Schalten", [("Alles abschalten", f"{PY} tools/dienste.py aus"), ("Wieder einschalten", f"{PY} tools/dienste.py ein"),
                              ("Oberfläche starten", f"{PY} tools/oberflaeche.py")])
        return 0
    if not plattform.terminal(sys.stdin, sys.stdout) or os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        print("FEHLER: Abschalten und Einschalten entscheidet ein Mensch am Terminal. Ohne Terminal und aus Claude Code heraus "
              f"läuft nur die Anzeige: {PY} tools/dienste.py", file=sys.stderr)
        return 2
    if wunsch == "aus":
        ui.kopf("OSINT-Ermittlungsarbeitsplatz · Alles abschalten", "Gelöscht wird nichts. Fallakten, Schlüssel und Einstellungen bleiben.")
        zeilen = oberflaeche_beenden()
        gut_oberflaeche = all(zeichen != FEHLT for zeichen, _, _ in zeilen)
        weitere, gelungen = aus(mit_tor=True)
        for zeichen, was, wie in (zeilen or [(GUT, "Oberfläche", "läuft nicht")]) + weitere:
            ui.zeile(zeichen, was, wie)
        ui.paare("Danach", [("Wieder einschalten", f"{PY} tools/dienste.py ein"), ("Oberfläche starten", f"{PY} tools/oberflaeche.py")])
        return 0 if gelungen and gut_oberflaeche else 1
    ui.kopf("OSINT-Ermittlungsarbeitsplatz · Einschalten", str(plattform.PROJEKT))
    zeilen, gelungen = ein()
    for zeichen, was, wie in zeilen:
        ui.zeile(zeichen, was, wie)
    ui.paare("Danach", [("Oberfläche starten", f"{PY} tools/oberflaeche.py")])
    return 0 if gelungen else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
