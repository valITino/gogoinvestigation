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

import os
import shutil
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
KANDIDATEN = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser",
              "msedge", "chrome",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Chromium.app/Contents/MacOS/Chromium",
              "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
              "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"]
if plattform.WINDOWS:   # Edge gehört zu Windows, Chrome und Brave liegen an festen Orten
    KANDIDATEN += [str(Path(os.environ[ort]) / programm)
                   for programm in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
                                    r"BraveSoftware\Brave-Browser\Application\brave.exe", r"Chromium\Application\chrome.exe")
                   for ort in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA") if os.environ.get(ort)]


def browser_finden() -> str | None:
    gewuenscht = os.environ.get("OSINT_BROWSER", "").strip()
    for kandidat in ([gewuenscht] if gewuenscht else []) + KANDIDATEN:
        pfad = shutil.which(kandidat) or (kandidat if Path(kandidat).is_file() else None)
        if pfad:
            return pfad
    return None


def umwandeln(browser: str, quelle: Path, ziel: Path) -> str | None:
    """Gibt None zurück, wenn das PDF erzeugt wurde, sonst die Fehlermeldung."""
    with tempfile.TemporaryDirectory(prefix="osint-pdf-") as profil:     # eigenes, leeres Browserprofil
        befehl = [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--disable-extensions",
                  # Der Browser soll nur die lokale Datei drucken und sich nirgends melden (Updates, Konto, Übersetzer).
                  "--disable-background-networking", "--disable-component-update", "--disable-sync",
                  "--disable-default-apps", "--no-first-run", "--disable-features=Translate,OptimizationHints,MediaRouter",
                  f"--user-data-dir={profil}", f"--print-to-pdf={ziel}", quelle.resolve().as_uri()]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            befehl.insert(1, "--no-sandbox")       # Chromium startet als root nur so
        try:
            r = subprocess.run(befehl, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        except subprocess.TimeoutExpired:
            return "Der Browser hat nach 120 Sekunden nicht geantwortet."
        except OSError as e:
            return f"Der Browser liess sich nicht starten: {e}"
    if not ziel.is_file() or ziel.stat().st_size < 1000:
        meldung = (r.stderr or r.stdout).strip().splitlines()
        return meldung[-1] if meldung else f"Der Browser hat kein PDF geschrieben (Rückgabewert {r.returncode})."
    return None


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
    browser = browser_finden()
    if not browser:
        print("FEHLER: Kein Chrome, Chromium, Edge oder Brave gefunden.\n"
              "        Entweder einen davon installieren (oder den Pfad in OSINT_BROWSER setzen),\n"
              f"        oder {rapport / 'Abschlussrapport.html'} im Browser öffnen und als PDF drucken.", file=sys.stderr)
        return 2
    ziel = nach or rapport
    ziel.mkdir(parents=True, exist_ok=True)
    code = 0
    for name in vorhanden:
        fehler = umwandeln(browser, rapport / f"{name}.html", ziel / f"{name}.pdf")
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
