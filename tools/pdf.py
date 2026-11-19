#!/usr/bin/env python3
"""Wandelt Abschlussrapport und Ermittlungsprotokoll eines Falls in PDF (A4).

    python3 tools/pdf.py <Fall-ID>                 schreibt nach faelle/<Fall-ID>/rapport/
    python3 tools/pdf.py <Fall-ID> --nach ORDNER   schreibt in einen anderen Ordner

Braucht einen installierten Browser der Chromium-Familie (Chrome, Chromium, Edge, Brave). Er läuft
unsichtbar mit einem leeren Wegwerf-Profil und wird so gestartet, dass er nur die lokale Datei druckt
und keine Hintergrunddienste (Updates, Konto, Übersetzer) kontaktiert. Die Dokumente sind in sich geschlossen.
Anderer Browser oder anderer Pfad: Umgebungsvariable OSINT_BROWSER setzen.

Unter WSL druckt auch der Browser von Windows (Edge, Chrome, Brave), wenn in WSL selbst keiner druckt. Dokument und PDF
bleiben dabei im Projektordner: Der Browser liest und schreibt sie unter dem Namen, unter dem Windows das Dateisystem
von WSL zeigt. Nur sein leeres Wegwerf-Profil liegt für die Dauer des Drucks im Ordner TEMP von Windows.

Ohne solchen Browser: die HTML-Datei in einem beliebigen Browser öffnen und als PDF drucken.
Das Ergebnis ist dasselbe, das Druckbild ist in den Dokumenten festgelegt.

Rückgabewert 0: erzeugt. 1: Umwandlung fehlgeschlagen. 2: Fall, Dokument oder Browser fehlt.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PureWindowsPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import fall_pfad  # noqa: E402

DOKUMENTE = ("Abschlussrapport", "Ermittlungsprotokoll")
ZEITLIMIT = 90          # Sekunden je Dokument und Browser
KANDIDATEN = ["chrome-headless-shell", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser",
              "msedge", "chrome",
              "/snap/bin/chromium",       # frisch als Snap installiert: Der PATH dieses Terminals kennt /snap/bin vielleicht noch nicht
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Chromium.app/Contents/MacOS/Chromium",
              "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
              "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]
if plattform.WINDOWS:   # Edge gehört zu Windows, Chrome und Brave liegen an festen Orten
    KANDIDATEN += [str(Path(os.environ[ort]) / programm)
                   for programm in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
                                    r"BraveSoftware\Brave-Browser\Application\brave.exe", r"Chromium\Application\chrome.exe")
                   for ort in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA") if os.environ.get(ort)]


# Unter WSL kann auch der Browser von Windows drucken: Edge gehört zu Windows, Chrome und Brave liegen an festen Orten.
# Die Orte gelten ab dem Laufwerk C:, so wie WSL es einhängt (meist /mnt/c).
WINDOWS_BROWSER = ("Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "Program Files/Microsoft/Edge/Application/msedge.exe",
                   "Program Files/Google/Chrome/Application/chrome.exe", "Program Files (x86)/Google/Chrome/Application/chrome.exe",
                   "Program Files/BraveSoftware/Brave-Browser/Application/brave.exe")
SNAPS = Path("/snap")


def von_windows(browser: str) -> bool:
    """Ein Browser von Windows, aus WSL gestartet. Er sieht die Dateien von WSL unter einem anderen Namen und braucht alle
    Pfade in der Schreibweise von Windows."""
    return browser.lower().endswith(".exe") and plattform.wsl()


def snap_ohne_inhalt(browser: str) -> bool:
    """Ein Browser aus einem Snap, dessen Inhalt dieses Terminal nicht sieht. Der Starter unter /snap/bin ist dann da, starten
    lässt sich damit nichts. So gesehen am 18. und 19.11.2026 unter Ubuntu 26.04 in WSL."""
    pfad = Path(browser)
    return pfad.parent == SNAPS / "bin" and not (SNAPS / pfad.name / "current" / "meta" / "snap.yaml").is_file()


def browser_alle() -> list[str]:
    """Alle Browser, die sich finden lassen, in der Reihenfolge der Versuche: OSINT_BROWSER zuerst, dann die Browser dieses
    Systems, unter WSL danach die von Windows. Ein Snap ohne sichtbaren Inhalt kommt ganz ans Ende: Er druckt hier nicht."""
    gewuenscht = os.environ.get("OSINT_BROWSER", "").strip()
    kandidaten = ([gewuenscht] if gewuenscht else []) + KANDIDATEN
    laufwerk = plattform.windows_laufwerk()         # nur unter WSL
    if laufwerk:
        kandidaten += [str(laufwerk / ort) for ort in WINDOWS_BROWSER]
    gefunden: list[str] = []
    hinten: list[str] = []
    for kandidat in kandidaten:
        pfad = shutil.which(kandidat) or (kandidat if Path(kandidat).is_file() else None)
        if pfad and pfad not in gefunden + hinten:
            (hinten if snap_ohne_inhalt(pfad) else gefunden).append(pfad)
    return gefunden + hinten


def browser_finden() -> str | None:
    return next(iter(browser_alle()), None)


PROBE = ('<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Probe</title></head>'
         "<body><h1>Probe der Einrichtung</h1><p>Aus dieser Seite entsteht ein PDF. Sie enthält nichts aus einem Fall.</p></body></html>")


def probe(browser: str, ordner: Path, zeit: int = 45) -> str | None:
    """Wandelt eine kleine Seite wirklich in ein PDF um und räumt wieder auf. None: Es hat geklappt. Sonst der Grund.
    Der Ordner soll im Projekt liegen, dort entstehen auch die echten Dokumente: Ein Browser aus einem Snap darf nur im
    Benutzerordner lesen und schreiben, und genau das soll die Probe zeigen."""
    try:
        ordner.mkdir(parents=True, exist_ok=True)
        arbeit = Path(tempfile.mkdtemp(prefix="pdf-probe-", dir=ordner))
    except OSError as e:
        return f"Der Ordner für die Probe liess sich nicht anlegen ({e})."
    try:
        quelle = arbeit / "probe.html"
        quelle.write_text(PROBE, encoding="utf-8")
        return umwandeln(browser, quelle, arbeit / "probe.pdf", zeit)
    except OSError as e:
        return f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(arbeit, ignore_errors=True)


def umwandeln(browser: str, quelle: Path, ziel: Path, zeit: int = ZEITLIMIT) -> str | None:
    """Gibt None zurück, wenn das PDF erzeugt wurde, sonst die Fehlermeldung."""
    fremd = von_windows(browser)
    profil_ort = None
    if fremd:
        # Der Browser von Windows braucht sein Profil auf einem Laufwerk von Windows. Dokument und PDF bleiben, wo sie sind.
        profil_ort = plattform.windows_ordner("TEMP")
        if profil_ort is None:
            return ("Der Browser von Windows liess sich von hier nicht ansprechen: Der Ordner TEMP von Windows war nicht zu "
                    "ermitteln. Programme von Windows müssen sich aus WSL starten lassen.")
    # Eigenes, leeres Browserprofil. Beim Aufräumen darf ein Rest liegen bleiben: Unter Windows hält ein Browser, der sich
    # gerade beendet, seine Dateien noch einen Augenblick fest. Das soll kein gelungenes PDF zum Fehler machen.
    with tempfile.TemporaryDirectory(prefix="osint-pdf-", dir=profil_ort, ignore_cleanup_errors=True) as profil, \
            tempfile.TemporaryFile() as meldungen:
        if fremd:
            orte = [plattform.windows_pfad(ort) for ort in (profil, quelle.resolve(), ziel.resolve().parent)]
            if not all(orte):
                return ("Der Browser von Windows liess sich von hier nicht ansprechen: Die Pfade liessen sich nicht in die "
                        "Schreibweise von Windows übersetzen (wslpath).")
            profil_fuer, ziel_fuer, adresse = orte[0], orte[2].rstrip("\\") + "\\" + ziel.name, windows_adresse(orte[1])
        else:
            profil_fuer, ziel_fuer, adresse = profil, str(ziel), quelle.resolve().as_uri()
        befehl = [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--disable-extensions",
                  # Der Browser soll nur die lokale Datei drucken und sich nirgends melden (Updates, Konto, Übersetzer).
                  "--disable-background-networking", "--disable-component-update", "--disable-sync",
                  "--disable-default-apps", "--no-first-run", "--disable-features=Translate,OptimizationHints,MediaRouter",
                  f"--user-data-dir={profil_fuer}", f"--print-to-pdf={ziel_fuer}", adresse]
        if not fremd and hasattr(os, "geteuid") and os.geteuid() == 0:
            befehl.insert(1, "--no-sandbox")       # Chromium startet als root nur so
        marke = Path(profil).name if fremd else ""  # daran sind die Prozesse des Browsers unter Windows zu erkennen
        try:
            # Was der Browser meldet, geht in eine Datei und nicht in eine Leitung: An einer Leitung hinge dieser Aufruf nach dem
            # Zeitlimit weiter, solange ein Kindprozess des Browsers sie offen hält. Auf eine Eingabe wartet er nie. Er läuft in
            # einer eigenen Prozessgruppe, damit sich nach dem Zeitlimit auch seine Kindprozesse beenden lassen.
            prozess = subprocess.Popen(befehl, stdin=subprocess.DEVNULL, stdout=meldungen, stderr=subprocess.STDOUT,
                                       start_new_session=not plattform.WINDOWS)
        except OSError as e:
            return f"Der Browser liess sich nicht starten: {e}"
        try:
            code = prozess.wait(zeit)
        except subprocess.TimeoutExpired:
            beenden(prozess, marke)
            if fremd:
                profil_raeumen(Path(profil))
            return (f"Der Browser {Path(browser).name} hat nach {zeit} Sekunden nicht geantwortet. Das kommt vor, wenn er beim Start "
                    "auf das Netz wartet. Ausweg: einen anderen Browser in OSINT_BROWSER nennen, etwa chrome-headless-shell.")
        except BaseException:       # Strg+C erreicht den Browser in seiner eigenen Gruppe nicht: von hier aus beenden
            beenden(prozess, marke)
            raise
        meldungen.seek(0)
        meldung = meldungen.read().decode("utf-8", errors="replace").strip().splitlines()
        if fremd:
            profil_raeumen(Path(profil))
    if not ziel.is_file() or ziel.stat().st_size < 1000:
        return meldung[-1] if meldung else f"Der Browser hat kein PDF geschrieben (Rückgabewert {code})."
    return None


def windows_adresse(pfad: str) -> str:
    """Die Adresse file://… zu einem Pfad in der Schreibweise von Windows (C:\\… oder \\\\Rechner\\Freigabe\\…)."""
    adresse = PureWindowsPath(pfad).as_uri()
    alt = "file://wsl%24/"      # ältere Fassungen von WSL nennen das Dateisystem \\wsl$\…: Das $ gehört unverändert in die Adresse
    return "file://wsl$/" + adresse[len(alt):] if adresse.startswith(alt) else adresse


def profil_raeumen(profil: Path, versuche: int = 6) -> None:
    """Entfernt das Wegwerf-Profil des Browsers von Windows. Ein Browser, der sich gerade beendet, hält seine Dateien noch
    einen Augenblick fest: Deshalb mehrere Versuche. Bleibt trotzdem ein Rest, liegt er im Ordner TEMP von Windows unter
    einem Namen, der mit osint-pdf- beginnt."""
    for versuch in range(versuche):
        shutil.rmtree(profil, ignore_errors=True)
        if not profil.exists():
            return
        if versuch + 1 < versuche:
            time.sleep(0.4)


def windows_beenden(marke: str) -> None:
    """Beendet unter WSL die Prozesse von Windows, in deren Aufruf die Marke steht: der Name des Wegwerf-Profils. Unter Linux
    läuft nur ein Stellvertreter des Browsers. Ist der beendet, liefe der Browser unter Windows sonst unsichtbar weiter."""
    laufwerk = plattform.windows_laufwerk()
    if not laufwerk or not marke:
        return
    programm = shutil.which("powershell.exe") or str(laufwerk / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    auftrag = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*" + marke + "*' -and $_.ProcessId -ne $PID } | "
               "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run([programm, "-NoProfile", "-NonInteractive", "-Command", auftrag], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, cwd=str(laufwerk))


def beenden(prozess: subprocess.Popen, marke: str = "") -> None:
    """Beendet einen Browser, der nicht antwortet, samt seinen Kindprozessen. Sonst blieben sie liegen und hielten das
    Wegwerf-Profil fest. Aufgerufen wird nur, solange der Browser selbst noch läuft: Seine Gruppe ist dann sicher seine.
    Mit marke ist es ein Browser von Windows, aus WSL gestartet: Dann wird er auch dort beendet."""
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        if plattform.WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(prozess.pid)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
        elif prozess.poll() is None:
            os.killpg(prozess.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        prozess.kill()
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        prozess.wait(10)
    if marke:
        windows_beenden(marke)


def main(argv: list[str]) -> int:
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0 if argv else 2
    nach = None
    if "--nach" in argv:
        i = argv.index("--nach")
        if i + 1 >= len(argv):
            print("FEHLER: --nach verlangt einen Ordner.", file=sys.stderr)
            return 2
        nach = Path(argv[i + 1]).expanduser()
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 1:
        print(f"FEHLER: Genau eine Fall-ID angeben. Hilfe: {plattform.PY} tools/pdf.py --help", file=sys.stderr)
        return 2
    try:
        rapport = fall_pfad(argv[0]) / "rapport"
    except ValueError as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    vorhanden = [n for n in DOKUMENTE if (rapport / f"{n}.html").is_file()]
    if not vorhanden:
        print(f"FEHLER: In {rapport} liegt weder Abschlussrapport.html noch Ermittlungsprotokoll.html.\n"
              f"        Zuerst erzeugen: {plattform.PY} tools/rapport.py {argv[0]}  und  {plattform.PY} tools/protokoll.py {argv[0]}", file=sys.stderr)
        return 2
    browser_liste = browser_alle()
    if not browser_liste:
        print("FEHLER: Kein Chrome, Chromium, Edge oder Brave gefunden.\n"
              "        Entweder einen davon installieren (oder den Pfad in OSINT_BROWSER setzen),\n"
              f"        oder {rapport / 'Abschlussrapport.html'} im Browser öffnen und als PDF drucken.", file=sys.stderr)
        return 2
    ziel = nach or rapport
    ziel.mkdir(parents=True, exist_ok=True)
    code = 0
    for name in vorhanden:
        fehler = None
        while browser_liste:        # scheitert ein Browser, kommt der nächste dran, und er bleibt es für die übrigen Dokumente
            fehler = umwandeln(browser_liste[0], rapport / f"{name}.html", ziel / f"{name}.pdf")
            if not fehler or len(browser_liste) == 1:
                break
            print(f"Hinweis: {fehler} Nächster Versuch mit {Path(browser_liste[1]).name}.", file=sys.stderr)
            browser_liste.pop(0)
        if fehler:
            print(f"FEHLER: {name}.pdf nicht erzeugt. {fehler}", file=sys.stderr)
            code = 1
        else:
            print(f"PDF erzeugt: {ziel / f'{name}.pdf'}")
    for name in DOKUMENTE:
        if name not in vorhanden:
            print(f"Hinweis: {name}.html fehlt noch und wurde ausgelassen.")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
