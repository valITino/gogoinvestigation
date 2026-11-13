#!/usr/bin/env python3
"""Prüft die Einrichtung des Arbeitsplatzes und sagt, was noch fehlt.

    python3 tools/pruefen.py            Umgebung, Konfiguration, Modelle, Quellen, Selbsttests (ohne Netz)
    python3 tools/pruefen.py --live     zusätzlich je eingerichteter Quelle eine harmlose Testabfrage
    python3 tools/pruefen.py --kurz     nur die Übersicht, ohne Selbsttests

Unter Windows heisst der Interpreter python statt python3.

Rückgabewert 0: einsatzbereit (fehlende Schlüssel einzelner Quellen sind kein Fehler). 1: etwas Nötiges fehlt.

Die Live-Abfragen (8.8.8.8, example.com und Ähnliches) landen in der Fallakte SELBSTTEST und werden
dort wie jede Abfrage protokolliert. Sie verbrauchen je Quelle einen Abruf aus eurem Kontingent.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.plattform import AUS, FEHLT, GUT, PY, SETUP, WINDOWS  # noqa: E402
from gateway.quellen import QUELLEN  # noqa: E402
from tools.einrichten import CLAUDE_MIN, MODELLE, agentenmodelle, benutzervariable, claude_stand, git_bash  # noqa: E402

VENV = plattform.venv_python(PROJEKT)
noetig_fehlt: list[str] = []
schritte: list[str] = []


def zeile(zeichen: str, was: str, wie: str = "") -> None:
    print(f"  {zeichen} {was:<34} {wie}")


def env_lesen() -> dict[str, str]:
    werte: dict[str, str] = {}
    datei = PROJEKT / ".env"
    if datei.is_file():
        for z in datei.read_text(encoding="utf-8").splitlines():
            z = z.strip()
            if z and not z.startswith("#") and "=" in z:
                name, _, wert = z.partition("=")
                wert = wert.strip().strip('"').strip("'")
                if wert:
                    werte[name.strip()] = wert
    for name, wert in os.environ.items():
        if wert.strip():
            werte.setdefault(name, wert.strip())
    return werte


def lauf(befehl: list[str], zeit: int = 20) -> tuple[int, str]:
    try:
        r = subprocess.run(befehl, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=zeit,
                           stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def erreichbar(url: str) -> bool:
    teile = urlsplit(url)
    try:
        with socket.create_connection((teile.hostname or "127.0.0.1", teile.port or 80), timeout=2):
            return True
    except OSError:
        return False


def umgebung(env: dict[str, str]) -> None:
    print("\nUmgebung")
    v = sys.version_info
    if v >= (3, 10):
        zeile(GUT, "Python", f"{v.major}.{v.minor}.{v.micro}")
    else:
        zeile(FEHLT, "Python", f"{v.major}.{v.minor} ist zu alt, nötig ist 3.10 oder neuer")
        noetig_fehlt.append("Python 3.10+")
    if VENV.is_file():
        code, _ = lauf([str(VENV), "-c", "import mcp, httpx, pydantic"])
        if code == 0:
            zeile(GUT, "Python-Pakete (.venv)", "mcp, httpx, pydantic")
        else:
            zeile(FEHLT, "Python-Pakete (.venv)", "unvollständig")
            noetig_fehlt.append("Python-Pakete")
            schritte.append(f"{SETUP} ausführen (installiert die Pakete neu)")
    else:
        zeile(FEHLT, "Python-Umgebung (.venv)", "fehlt")
        noetig_fehlt.append(".venv")
        schritte.append(f"{SETUP} ausführen")
    pfad, version, text = claude_stand()
    if not pfad:
        zeile(FEHLT, "Claude Code", "nicht gefunden")
        noetig_fehlt.append("Claude Code")
        schritte.append(f"{SETUP} ausführen (installiert Claude Code), oder von Hand: https://code.claude.com/docs")
    elif version and version < CLAUDE_MIN:
        zeile(AUS, "Claude Code", f"{text}   veraltet")
        schritte.append(f"Claude Code aktualisieren (claude update). Erst ab {'.'.join(map(str, CLAUDE_MIN))} sperrt es "
                        "Werkzeugaufrufe, wenn der Wächter selbst ausfällt.")
    else:
        zeile(GUT, "Claude Code", text or "installiert")
    if WINDOWS:
        bash = git_bash()
        if bash:
            zeile(GUT, "Git for Windows", f"Git Bash: {bash}")
        else:
            zeile(FEHLT, "Git for Windows", "fehlt. Ohne Git Bash laufen Wächter und Protokoll nicht.")
            noetig_fehlt.append("Git for Windows")
            schritte.append(f"{SETUP} ausführen (installiert Git for Windows über winget)")
    if not shutil.which("docker"):
        zeile(AUS, "Docker", "nicht installiert: Web-Check und Robin (Dark Web) bleiben aus")
    else:
        code, _ = lauf(["docker", "info"], 15)
        if code != 0:
            zeile(AUS, "Docker", "installiert, aber der Dienst läuft nicht oder ihr habt keinen Zugriff")
            schritte.append(f"Docker starten, dann {SETUP} erneut (für Web-Check und Robin)")
        else:
            zeile(GUT, "Docker", "läuft")
            abbild = env.get("ROBIN_IMAGE", "apurvsg/robin:latest")
            code, _ = lauf(["docker", "image", "inspect", abbild], 15)
            zeile(GUT if code == 0 else AUS, "Robin-Abbild", abbild if code == 0 else f"{abbild} nicht geladen ({SETUP} holt es)")
    adresse = env.get("WEBCHECK_URL", "http://127.0.0.1:3000")
    if erreichbar(adresse):
        zeile(GUT, "Web-Check", f"erreichbar unter {adresse}")
    else:
        zeile(AUS, "Web-Check", f"nicht erreichbar unter {adresse} (Start: docker compose up -d webcheck)")
    from tools.pdf import browser_finden
    browser = browser_finden()
    if browser:
        zeile(GUT, "Browser für PDF", Path(browser).name)
    else:
        zeile(AUS, "Browser für PDF", "kein Chrome, Chromium, Edge oder Brave: PDF dann über 'Drucken' im Browser")
    if plattform.programm("pdftotext"):
        zeile(GUT, "pdftotext", "PDF-Dokumente können aufgenommen werden")
    else:
        zeile(AUS, "pdftotext", f"fehlt: PDF nicht aufnehmbar ({SETUP} holt es nach). .txt, .md, .docx gehen.")


def konfiguration(env: dict[str, str]) -> None:
    print("\nKonfiguration")
    if (PROJEKT / ".env").is_file():
        zeile(GUT, ".env", "vorhanden")
    else:
        zeile(FEHLT, ".env", "fehlt")
        schritte.append(f"{SETUP} ausführen (legt .env aus .env.example an), dann Schlüssel eintragen")
    for name in (".mcp.json", ".claude/settings.json"):
        try:
            json.loads((PROJEKT / name).read_text(encoding="utf-8"))
            zeile(GUT, name, "gültig")
        except (OSError, json.JSONDecodeError) as e:
            zeile(FEHLT, name, f"fehlerhaft: {e}")
            noetig_fehlt.append(name)
    for hook in ("start.sh", "waechter.py", "protokoll_hook.py"):
        datei = PROJEKT / ".claude" / "hooks" / hook
        if not datei.is_file():
            zeile(FEHLT, f"Hook {hook}", "fehlt")
            noetig_fehlt.append(hook)
    lokal = PROJEKT / ".claude" / "settings.local.json"
    daten: dict = {}
    if lokal.is_file():
        try:
            daten = json.loads(lokal.read_text(encoding="utf-8"))
            zeile(GUT, "MCP-Server freigeschaltet", ", ".join(daten.get("enabledMcpjsonServers") or []) or "keine")
        except json.JSONDecodeError:
            zeile(FEHLT, ".claude/settings.local.json", "kein gültiges JSON")
            schritte.append(f"{SETUP} ausführen (schreibt die Datei neu)")
    else:
        zeile(AUS, "MCP-Server freigeschaltet", f"noch nicht ({SETUP} erledigt das, sonst fragt Claude Code beim Start)")
    if WINDOWS:     # .mcp.json startet das Gateway über OSINT_PYTHON, weil es unter Windows kein python3 gibt
        gesetzt = benutzervariable("OSINT_PYTHON")
        if gesetzt and Path(gesetzt).is_file():
            zeile(GUT, "Python fürs Gateway", f"OSINT_PYTHON = {gesetzt}")
            if os.environ.get("OSINT_PYTHON") != gesetzt:
                schritte.append("Neues Terminal öffnen, bevor ihr 'claude' startet: Dieses Fenster kennt OSINT_PYTHON noch nicht.")
        else:
            zeile(FEHLT, "Python fürs Gateway", "Umgebungsvariable OSINT_PYTHON fehlt oder zeigt ins Leere")
            noetig_fehlt.append("OSINT_PYTHON")
            schritte.append(f"{SETUP} ausführen (setzt die Variable)")
    projekt = json.loads((PROJEKT / ".claude" / "settings.json").read_text(encoding="utf-8")).get("model", "")
    ermittlung = daten.get("model") or projekt
    modelle = agentenmodelle()
    zeile(GUT, "Modell Ermittlung", f"{ermittlung}   (Hauptsitzung, {', '.join(n for n, m in modelle.items() if m == 'inherit')})")
    feste = sorted({m for m in modelle.values() if m != "inherit"})
    zeile(GUT if feste == [MODELLE["fable"]] else FEHLT, "Modell Abschluss",
          f"{', '.join(feste) or 'nicht festgelegt'}   ({', '.join(n for n, m in modelle.items() if m != 'inherit')})")
    if ermittlung != projekt:
        schritte.append(f"Modell der Ermittlung ist lokal auf {ermittlung} gestellt. Zurück auf den Standard: "
                        f"{SETUP} --ermittlungsmodell fable")
    zeile(GUT if env.get("OSINT_PROXY") else AUS, "Proxy für Abfragen",
          "gesetzt" if env.get("OSINT_PROXY") else "keiner: Quellen sehen eure Internetadresse (OSINT_PROXY in .env)")


def quellen(env: dict[str, str]) -> list:
    print("\nQuellen")
    bereit = []
    for q in QUELLEN:
        if q.name == "ransomware.live":
            ok = bool(env.get(q.env)) or env.get("RANSOMWARE_LIVE_V2") == "1"
        elif q.name == "Web-Check":
            ok = erreichbar(env.get("WEBCHECK_URL", "http://127.0.0.1:3000"))
        else:
            ok = q.env is None or bool(env.get(q.env))
        if ok:
            bereit.append(q)
            zeile(GUT, q.name, "bereit" + ("" if q.env else " (kein Schlüssel nötig)"))
        elif q.name == "Web-Check":
            zeile(AUS, q.name, "aus: Instanz läuft nicht")
        else:
            zeile(AUS, q.name, f"aus: {q.env} fehlt in .env  →  {q.woher}")
    fehlend = len(QUELLEN) - len(bereit)
    if fehlend:
        schritte.append(f"Schlüssel für {fehlend} Quelle(n) in .env eintragen (optional, jede Quelle für sich)")
    return bereit


def selbsttests() -> None:
    print("\nSelbsttests (ohne Netz)")
    python = str(VENV) if VENV.is_file() else sys.executable
    r = subprocess.run([python, str(PROJEKT / "tools" / "selbsttest.py")], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=600)
    for z in r.stdout.strip().splitlines():
        if z.strip():
            print(f"  {z}")
    if r.returncode != 0:
        noetig_fehlt.append("Selbsttests")
        if r.stderr.strip():
            print("  " + r.stderr.strip().splitlines()[-1])


def live(bereit: list) -> None:
    print("\nLive-Test (eine harmlose Abfrage je eingerichteter Quelle, Fallakte SELBSTTEST)")
    if not VENV.is_file():
        zeile(FEHLT, "Live-Test", f"braucht .venv ({SETUP})")
        return
    plan = [{"quelle": q.name, "werkzeug": q.test[0], "argumente": q.test[1]} for q in bereit if q.test]
    skript = r'''
import asyncio, json, sys
sys.path.insert(0, sys.argv[1])
from gateway import server, kern
from tools import fall as f
from gateway.akte import FAELLE
pfad = FAELLE / "SELBSTTEST"
if not (pfad / "fall.json").is_file():
    for o in f.UNTERORDNER: (pfad / o).mkdir(parents=True, exist_ok=True)
    f.schreiben(pfad / "fall.json", {"fall_id": "SELBSTTEST", "titel": "Live-Test der Quellen", "freigaben": {}})
werkzeuge = {fn.__name__: fn for fn in kern.REGISTER}
async def alle():
    for p in json.loads(sys.argv[2]):
        try:
            r = await werkzeuge[p["werkzeug"]]("SELBSTTEST", zweck="Live-Test der Einrichtung mit harmlosem Testwert", **p["argumente"])
        except Exception as e:
            r = {"ergebnis": "fehler", "fehler": f"{type(e).__name__}: {e}"}
        print(json.dumps({"quelle": p["quelle"], "werkzeug": p["werkzeug"], "ergebnis": r.get("ergebnis"), "fehler": r.get("fehler"), "id": r.get("protokoll_id")}, ensure_ascii=False), flush=True)
asyncio.run(alle())
'''
    p = subprocess.Popen([str(VENV), "-X", "utf8", "-c", skript, str(PROJEKT), json.dumps(plan)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    for z in p.stdout:
        try:
            e = json.loads(z)
        except json.JSONDecodeError:
            continue
        if e["ergebnis"] in ("ok", "kein_treffer"):
            zeile(GUT, e["quelle"], f"{e['werkzeug']} antwortet ({e['ergebnis']}, {e['id']})")
        else:
            zeile(FEHLT, e["quelle"], f"{e['werkzeug']}: {e['fehler']}")
    p.wait()
    if p.returncode != 0:
        zeile(FEHLT, "Live-Test", (p.stderr.read().strip().splitlines() or ["abgebrochen"])[-1])
    print(f"  Protokoll der Testabfragen: {PY} tools/protokoll.py SELBSTTEST")


def main() -> int:
    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__)
        return 0
    eingebettet = "--eingebettet" in sys.argv     # Aufruf aus der Einrichtung: Sie hat die Umgebung eben selbst gezeigt
    env = env_lesen()
    if eingebettet:
        with contextlib.redirect_stdout(io.StringIO()):
            umgebung(env)
    else:
        print("OSINT-Ermittlungsarbeitsplatz: Prüfung der Einrichtung")
        umgebung(env)
    konfiguration(env)
    bereit = quellen(env)
    if "--kurz" not in sys.argv:
        selbsttests()
    if "--live" in sys.argv:
        live(bereit)
    print()
    if eingebettet:                     # die Einrichtung zieht das Fazit und nennt die nächsten Schritte selbst
        if not noetig_fehlt:
            print(f"Einsatzbereit mit {len(bereit)} von {len(QUELLEN)} Quellen.")
        return 1 if noetig_fehlt else 0
    if noetig_fehlt:
        print(f"NICHT einsatzbereit. Es fehlt: {', '.join(dict.fromkeys(noetig_fehlt))}")
    else:
        print(f"Einsatzbereit mit {len(bereit)} von {len(QUELLEN)} Quellen.")
    if schritte:
        print("Nächste Schritte:")
        for s in dict.fromkeys(schritte):
            print(f"  - {s}")
    if not noetig_fehlt:
        print(f"Loslegen:  {PY} tools/fall.py neu <Fall-ID> --titel \"…\" --rapport <Datei>   dann   claude   und   /ermittlung <Fall-ID>")
    return 1 if noetig_fehlt else 0


if __name__ == "__main__":
    sys.exit(main())
