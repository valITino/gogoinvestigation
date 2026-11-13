#!/usr/bin/env python3
"""Prüft die Einrichtung des Arbeitsplatzes und sagt, was noch fehlt.

    python3 tools/pruefen.py            Umgebung, Konfiguration, Modelle, Quellen, Selbsttests (ohne Netz)
    python3 tools/pruefen.py --live     zusätzlich je eingerichteter Quelle eine harmlose Testabfrage und
                                        je Modell (Fable 5.2, Mythos 5.2 wenn freigeschaltet) ein kurzer Testaufruf
    python3 tools/pruefen.py --kurz     nur die Übersicht, ohne Selbsttests
    python3 tools/pruefen.py --nur-live nur die Testabfragen und Testaufrufe

Unter Windows heisst der Interpreter python statt python3.

Rückgabewert 0: einsatzbereit (fehlende Schlüssel einzelner Quellen sind kein Fehler). 1: etwas Nötiges fehlt.

Die Live-Abfragen (8.8.8.8, example.com und Ähnliches) landen in der Fallakte SELBSTTEST und werden
dort wie jede Abfrage protokolliert. Sie verbrauchen je Quelle einen Abruf aus eurem Kontingent.
"""
from __future__ import annotations

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
from tools.einrichten import (CLAUDE_MIN, MODELLE, anmeldung, benutzervariable, claude_stand, git_bash, modell_testen,  # noqa: E402
                              modellzuteilung, ui)

VENV = plattform.venv_python(PROJEKT)
noetig_fehlt: list[str] = []
schritte: list[str] = []
gemeldet: list[tuple[str, str, str, str]] = []     # alles, was gemeldet wurde: (Abschnitt, gut | aus | fehlt, was, wie)
still = False                                       # nur sammeln, nichts ausgeben (für die Kurzfassung in der Einrichtung)
_abschnitt = ""


def abschnitt(titel: str) -> None:
    global _abschnitt
    _abschnitt = titel.split(" (")[0]
    if not still:
        ui.abschnitt(titel)


def zeile(zeichen: str, was: str, wie: str = "", satz: bool = False) -> None:
    """Meldet eine Zeile. Mit satz=True ist 'was' ein ganzer Satz (Name eines Tests) und 'wie' die Erläuterung darunter."""
    gemeldet.append((_abschnitt, {GUT: "gut", FEHLT: "fehlt"}.get(zeichen, "aus"), was, wie))
    if still:
        return
    if satz:
        ui.punkt(zeichen, was, wie)
    else:
        ui.zeile(zeichen, was, wie, breit=30)


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
    abschnitt("Umgebung")
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
    abschnitt("Konfiguration")
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
    modelle(nur_merken=False)
    zeile(GUT if env.get("OSINT_PROXY") else AUS, "Proxy für Abfragen",
          "gesetzt" if env.get("OSINT_PROXY") else "keiner: Quellen sehen eure Internetadresse (OSINT_PROXY in .env)")


def modelle(nur_merken: bool) -> dict:
    """Zeigt, welches Modell in welcher Phase läuft. Die Zuteilung steht fest in Skills und Agenten.
    Ob Mythos greift, entscheidet die Liste availableModels (siehe tools/einrichten.py)."""
    z = modellzuteilung()
    if nur_merken:
        return z
    fable, mythos = MODELLE["fable"], MODELLE["mythos"]
    if z["mythos_frei"]:
        zeile(GUT, "Mythos 5.2", "freigeschaltet: Die Ermittlung schaltet von selbst um")
    else:
        zeile(AUS, "Mythos 5.2", f"nicht freigeschaltet. Wer es hat: {SETUP} --mythos")
    zeile(GUT, "Modell Ermittlung", f"{mythos if z['mythos_frei'] else z['sitzung']}   ({', '.join(z['ermittlung'])})")
    falsch = sorted(n for n in ("gegenpruefer", "rapportfuehrer") if z["agenten"].get(n) != fable)
    if falsch:
        zeile(FEHLT, "Modell Abschluss", f"nicht auf {fable}: {', '.join(falsch)}")
        noetig_fehlt.append("Modell des Abschlusses")
    elif z["sitzung"] != fable:     # eigene Wahl in .claude/settings.local.json: erlaubt, aber nicht der Zuschnitt des Projekts
        zeile(AUS, "Modell Abschluss", f"Agenten auf {fable}, die Sitzung selbst aber auf {z['sitzung']}")
        schritte.append("In .claude/settings.local.json steht ein eigenes \"model\". Soll ausserhalb der Ermittlung Fable 5.2 "
                        "laufen, diese Zeile entfernen.")
    else:
        zeile(GUT, "Modell Abschluss", f"{fable}   ({', '.join(z['abschluss'])}, und alles ausserhalb der Ermittlung)")
    if not z["ermittlung"]:
        zeile(FEHLT, "Modell Ermittlung", "kein Skill und kein Agent verlangt Mythos: Die Umschaltung fehlt")
        noetig_fehlt.append("Zuteilung der Modelle")
    return z


def quellen(env: dict[str, str]) -> list:
    abschnitt("Quellen")
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
        schritte.append(f"Schlüssel für {fehlend} Quelle(n) eintragen, wenn ihr sie braucht: {SETUP} und «Einstellungen ändern», "
                        "oder direkt in .env. Jede Quelle ist für sich optional.")
    return bereit


def selbsttests() -> tuple[int, int]:
    """Lässt die Selbsttests laufen. Gibt (bestanden, gesamt) zurück."""
    abschnitt("Selbsttests (ohne Netz)")
    python = str(VENV) if VENV.is_file() else sys.executable
    with ui.arbeit(None if still else "Selbsttests laufen"):
        r = subprocess.run([python, str(PROJEKT / "tools" / "selbsttest.py")], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=900, stdin=subprocess.DEVNULL)
    bestanden = gesamt = 0
    zeilen = r.stdout.splitlines()
    for nr, z in enumerate(zeilen):
        for zeichen in (GUT, FEHLT):
            if z.startswith(zeichen + " "):
                gesamt += 1
                bestanden += zeichen == GUT
                grund = zeilen[nr + 1].strip() if zeichen == FEHLT and nr + 1 < len(zeilen) and zeilen[nr + 1].startswith("    ") else ""
                zeile(zeichen, z[len(zeichen) + 1:], grund, satz=True)
    if r.returncode != 0 or not gesamt:
        noetig_fehlt.append("Selbsttests")
        if not gesamt or bestanden == gesamt:       # abgebrochen, bevor ein Test etwas melden konnte
            zeile(FEHLT, "Selbsttests", ((r.stderr.strip() or r.stdout.strip()).splitlines() or ["ohne Ergebnis abgebrochen"])[-1])
    elif not still:
        ui.text(f"{bestanden} von {gesamt} Selbsttests bestanden.", "matt")
    return bestanden, gesamt


def live_modelle() -> None:
    """Je Modell ein kurzer Testaufruf über Claude Code: Darf dieses Konto das Modell nutzen?"""
    abschnitt("Testaufrufe der Modelle (je ein kurzer Aufruf über Claude Code, ausserhalb des Projekts)")
    z = modelle(nur_merken=True)
    angemeldet = anmeldung()[0]
    if not angemeldet:
        zeile(AUS, "Modelle", "nicht getestet: " + ("Claude Code fehlt" if angemeldet is None else "Claude Code ist nicht angemeldet"))
        return
    for modell in [MODELLE["fable"]] + ([MODELLE["mythos"]] if z["mythos_frei"] else []):
        with ui.arbeit(f"{modell} wird gefragt"):
            ergebnis, text = modell_testen(modell)
        if ergebnis == "ok":
            zeile(GUT, modell, "antwortet")
        elif ergebnis == "unbekannt":
            zeile(AUS, modell, f"nicht prüfbar: {text}")
        else:
            zeile(FEHLT, modell, text)
            if modell == MODELLE["mythos"]:
                schritte.append(f"Mythos 5.2 ist freigeschaltet, antwortet aber nicht. Anmeldung prüfen. Hat das Konto keinen "
                                f"Zugang: {SETUP} --ohne-mythos")
    if not z["mythos_frei"]:
        zeile(AUS, MODELLE["mythos"], f"nicht freigeschaltet, deshalb nicht getestet ({SETUP} --mythos)")


def live(bereit: list) -> None:
    abschnitt("Testabfragen (eine harmlose Abfrage je eingerichteter Quelle, Fallakte SELBSTTEST)")
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
                         stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
    offen = [eintrag["quelle"] for eintrag in plan]
    rat = " Netzwerk, Proxy (OSINT_PROXY) und Erreichbarkeit prüfen."      # hängt das Gateway an jeden Verbindungsfehler an
    ohne_verbindung = 0
    while True:
        with ui.arbeit(f"{offen[0]} wird abgefragt" if offen else None):     # die Antworten kommen in der Reihenfolge des Plans
            z = p.stdout.readline()
        if not z:
            break
        try:
            e = json.loads(z)
        except json.JSONDecodeError:
            continue
        if e["quelle"] in offen:
            offen.remove(e["quelle"])
        if e["ergebnis"] in ("ok", "kein_treffer"):
            zeile(GUT, e["quelle"], f"{e['werkzeug']} antwortet ({e['ergebnis']}, {e['id']})")
        else:
            fehler = str(e["fehler"])
            ohne_verbindung += rat in fehler
            zeile(FEHLT, e["quelle"], f"{e['werkzeug']}: {fehler.replace(rat, '')}")
    p.wait()
    if p.returncode != 0:
        zeile(FEHLT, "Testabfragen", (p.stderr.read().strip().splitlines() or ["abgebrochen"])[-1])
    if ohne_verbindung:
        ui.text(f"{ohne_verbindung} Quelle(n) ohne Verbindung:{rat}", "matt")
    ui.text(f"Protokoll der Testabfragen: {PY} tools/protokoll.py SELBSTTEST", "matt")


def kurzfassung(bereit: list, tests: tuple[int, int]) -> list[list[str]]:
    """Die Prüfung in wenigen Zeilen, für die Einrichtung: Was in Ordnung ist, wird zusammengefasst,
    jeder Fehler steht einzeln da."""
    zeilen: list[list[str]] = []
    for bereich, titel, gut in (("Umgebung", "", ""), ("Konfiguration", "Einstellungen", "Wächter, Protokoll, MCP-Server und Modelle sind eingerichtet")):
        fehler = [[art, was, wie] for abschnitt_, art, was, wie in gemeldet if abschnitt_ == bereich and art == "fehlt"]
        zeilen += fehler or ([["gut", titel, gut]] if titel else [])
    fehler = [[art, was, wie] for abschnitt_, art, was, wie in gemeldet if abschnitt_ == "Selbsttests" and art == "fehlt"]
    zeilen.append(["fehlt" if fehler else "gut", "Selbsttests", f"{tests[0]} von {tests[1]} bestanden"])
    zeilen += fehler
    zeilen.append(["gut" if bereit else "aus", "Quellen", f"{len(bereit)} von {len(QUELLEN)} bereit"])
    namen = {q.name for q in bereit}
    ohne = [q.name for q in QUELLEN if q.name not in namen and q.env]
    if ohne:
        zeilen.append(["aus", "Ohne Schlüssel", ", ".join(ohne)])
    if "Web-Check" not in namen:
        zeilen.append(["aus", "Web-Check", "aus: Die Instanz läuft nicht"])
    return zeilen


def main() -> int:
    global still
    if "-h" in sys.argv or "--help" in sys.argv or "--hilfe" in sys.argv:
        print(__doc__)
        return 0
    env = env_lesen()
    if "--eingebettet" in sys.argv:     # Aufruf aus der Einrichtung: Sie zeigt die Kurzfassung und zieht das Fazit selbst
        still = True
        umgebung(env)
        konfiguration(env)
        bereit = quellen(env)
        tests = selbsttests()
        print(json.dumps({"osint_pruefung": 1, "zeilen": kurzfassung(bereit, tests), "fehlt": list(dict.fromkeys(noetig_fehlt)),
                          "bereit": len(bereit), "quellen": len(QUELLEN)}, ensure_ascii=False))
        return 1 if noetig_fehlt else 0
    if "--nur-live" in sys.argv:
        still = True
        bereit = quellen(env)
        still = False
        live(bereit)
        live_modelle()
        return 1 if any(art == "fehlt" for bereich, art, _, _ in gemeldet if bereich.startswith("Test")) else 0
    ui.kopf("OSINT-Ermittlungsarbeitsplatz · Prüfung der Einrichtung")
    umgebung(env)
    konfiguration(env)
    bereit = quellen(env)
    if "--kurz" not in sys.argv:
        selbsttests()
    if "--live" in sys.argv:
        live(bereit)
        live_modelle()
    ui.leer()
    ui.linie()
    if noetig_fehlt:
        ui.erledigt("NICHT einsatzbereit.", f"Es fehlt: {', '.join(dict.fromkeys(noetig_fehlt))}", FEHLT, breit=0)
    else:
        ui.erledigt("Einsatzbereit", f"mit {len(bereit)} von {len(QUELLEN)} Quellen", breit=0)
    ui.liste("Nächste Schritte", list(dict.fromkeys(schritte)), nummeriert=True)
    if not noetig_fehlt:
        ui.paare("Loslegen", [("Fall anlegen", f"{PY} tools/fall.py neu <Fall-ID> --titel \"…\" --rapport <Dokument>"),
                              ("Ermitteln", "claude   und dort   /ermittlung <Fall-ID>"),
                              ("Einstellungen ändern", SETUP)])
    return 1 if noetig_fehlt else 0


if __name__ == "__main__":
    sys.exit(main())
