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
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.plattform import AUS, FEHLT, GUT, PY, SETUP, WINDOWS  # noqa: E402
from tools import einrichten  # noqa: E402

WEBCHECK = "osint-webcheck"         # so heisst der Container in docker-compose.yml
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


def tor() -> dict:
    """gehoert: Der Arbeitsplatz nutzt Tor auf diesem Rechner als Proxy. laeuft: Auf dessen Adresse antwortet etwas."""
    proxy = plattform.einstellung("OSINT_PROXY")
    gehoert = bool(proxy) and plattform.proxy_ist_tor(proxy)
    return {"gehoert": gehoert, "laeuft": bool(gehoert and plattform.proxy_antwortet(proxy))}


def stand(mit_oberflaeche: bool = True) -> dict:
    """Was gerade läuft, in einem Stück: für die Anzeige im Terminal und in der Oberfläche. Die Oberfläche fragt sich dabei
    nicht selbst (mit_oberflaeche=False): Sie weiss, dass sie läuft, und eine Anfrage an sich selbst müsste auf sich warten."""
    docker = docker_kurz()
    return {"docker": docker, "webcheck": webcheck(docker), "robin": robin(docker), "tor": tor(),
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
    if s["tor"]["gehoert"]:
        zeilen.append((GUT, "Tor (Proxy)", "läuft") if s["tor"]["laeuft"] else (AUS, "Tor (Proxy)", "läuft nicht"))
    return zeilen


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
