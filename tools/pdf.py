#!/usr/bin/env python3
"""Wandelt Abschlussrapport und Ermittlungsprotokoll eines Falls in PDF (A4).

    python3 tools/pdf.py <Fall-ID>                 schreibt nach faelle/<Fall-ID>/rapport/
    python3 tools/pdf.py <Fall-ID> --nach ORDNER   schreibt in einen anderen Ordner

Braucht einen installierten Browser der Chromium-Familie (Chrome, Chromium, Edge, Brave). Er läuft
unsichtbar mit einem leeren Wegwerf-Profil und wird so gestartet, dass er nur die lokale Datei druckt
und keine Hintergrunddienste (Updates, Konto, Übersetzer) kontaktiert. Die Dokumente sind in sich geschlossen.
Anderer Browser oder anderer Pfad: Umgebungsvariable OSINT_BROWSER setzen.

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
from pathlib import Path

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


def browser_alle() -> list[str]:
    """Alle Browser, die sich finden lassen, in der Reihenfolge der Versuche. OSINT_BROWSER zuerst."""
    gewuenscht = os.environ.get("OSINT_BROWSER", "").strip()
    gefunden: list[str] = []
    for kandidat in ([gewuenscht] if gewuenscht else []) + KANDIDATEN:
        pfad = shutil.which(kandidat) or (kandidat if Path(kandidat).is_file() else None)
        if pfad and pfad not in gefunden:
            gefunden.append(pfad)
    return gefunden


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
    # Eigenes, leeres Browserprofil. Beim Aufräumen darf ein Rest liegen bleiben: Unter Windows hält ein Browser, der sich
    # gerade beendet, seine Dateien noch einen Augenblick fest. Das soll kein gelungenes PDF zum Fehler machen.
    with tempfile.TemporaryDirectory(prefix="osint-pdf-", ignore_cleanup_errors=True) as profil, tempfile.TemporaryFile() as meldungen:
        befehl = [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--disable-extensions",
                  # Der Browser soll nur die lokale Datei drucken und sich nirgends melden (Updates, Konto, Übersetzer).
                  "--disable-background-networking", "--disable-component-update", "--disable-sync",
                  "--disable-default-apps", "--no-first-run", "--disable-features=Translate,OptimizationHints,MediaRouter",
                  f"--user-data-dir={profil}", f"--print-to-pdf={ziel}", quelle.resolve().as_uri()]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            befehl.insert(1, "--no-sandbox")       # Chromium startet als root nur so
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
            beenden(prozess)
            return (f"Der Browser {Path(browser).name} hat nach {zeit} Sekunden nicht geantwortet. Das kommt vor, wenn er beim Start "
                    "auf das Netz wartet. Ausweg: einen anderen Browser in OSINT_BROWSER nennen, etwa chrome-headless-shell.")
        except BaseException:       # Strg+C erreicht den Browser in seiner eigenen Gruppe nicht: von hier aus beenden
            beenden(prozess)
            raise
        meldungen.seek(0)
        meldung = meldungen.read().decode("utf-8", errors="replace").strip().splitlines()
    if not ziel.is_file() or ziel.stat().st_size < 1000:
        return meldung[-1] if meldung else f"Der Browser hat kein PDF geschrieben (Rückgabewert {code})."
    return None


def beenden(prozess: subprocess.Popen) -> None:
    """Beendet einen Browser, der nicht antwortet, samt seinen Kindprozessen. Sonst blieben sie liegen und hielten das
    Wegwerf-Profil fest. Aufgerufen wird nur, solange der Browser selbst noch läuft: Seine Gruppe ist dann sicher seine."""
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
