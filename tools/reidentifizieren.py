#!/usr/bin/env python3
"""Führt die Platzhalter im fertigen Rapport auf die echten Angaben zurück. Nur im Haus, nur von Hand.

    python3 tools/reidentifizieren.py <Fall-ID> --zuordnung /sicher/zuordnung.csv --ausgabe /sicher/ablage/

Die Zuordnungsdatei stammt aus eurem Pseudonymisierungsschritt und hat zwei Spalten, getrennt durch
Strichpunkt, ohne Kopfzeile:

    [PERSON_01];Hans Muster
    [ORG_01];Muster AG

Das Werkzeug ersetzt die Platzhalter in Abschlussrapport.html und indikatoren.csv und schreibt das Ergebnis
in den Ausgabeordner. Zuordnungsdatei und Ausgabeordner müssen ausserhalb des Projektordners liegen, damit
ein Agent sie nicht lesen kann. Das Werkzeug läuft nur an einem Terminal, nicht aus einem Agenten heraus.
Auf dem Bildschirm erscheinen nur Zahlen, nie die echten Angaben.
"""
from __future__ import annotations

import argparse
import csv
import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import PROJEKT, fall_pfad  # noqa: E402

PLATZHALTER = re.compile(r"\[[A-ZÄÖÜ]{2,20}_\d{1,3}\]")


def innerhalb(pfad: Path) -> bool:
    try:
        pfad.resolve().relative_to(PROJEKT.resolve())
        return True
    except ValueError:
        return False


class Fehler(Exception):
    pass


def zurueckfuehren(fall_id: str, zuordnung: Path, ausgabe: Path) -> dict:
    """Ersetzt die Platzhalter in Abschlussrapport.html und indikatoren.csv und schreibt das Ergebnis in den Ausgabeordner.
    Rückgabe: {"dateien": [Pfad …], "ersetzt": n, "ungenutzt": n, "offen": [Platzhalter …]}. Nennt nie eine echte Angabe.
    Wer das auslöst, entscheidet der Aufrufer: main() verlangt ein Terminal, die Oberfläche das Geheimnis ihres Starts."""
    zuordnung, ausgabe = Path(zuordnung).expanduser(), Path(ausgabe).expanduser()
    if innerhalb(zuordnung) or innerhalb(ausgabe):
        raise Fehler("Zuordnungsdatei und Ausgabeordner müssen ausserhalb des Projektordners liegen.\n"
                     f"        Projektordner: {PROJEKT}")
    try:
        rapport = fall_pfad(fall_id) / "rapport"
    except ValueError as e:
        raise Fehler(str(e)) from e
    quellen = [rapport / "Abschlussrapport.html", rapport / "indikatoren.csv"]
    if not quellen[0].is_file():
        raise Fehler(f"{quellen[0]} fehlt. Zuerst den Rapport erzeugen.")
    if not zuordnung.is_file():
        raise Fehler(f"Zuordnungsdatei nicht gefunden: {zuordnung}")

    paare: dict[str, str] = {}
    with open(zuordnung, newline="", encoding="utf-8-sig") as f:
        for nr, zeile in enumerate(csv.reader(f, delimiter=";"), 1):
            if not zeile or not zeile[0].strip() or zeile[0].lstrip().startswith("#"):
                continue
            if len(zeile) < 2 or not PLATZHALTER.fullmatch(zeile[0].strip()):
                raise Fehler(f"Zeile {nr} der Zuordnung hat nicht die Form [TYP_01];Klartext.")
            paare[zeile[0].strip()] = zeile[1].strip()

    ausgabe.mkdir(parents=True, exist_ok=True)
    offen: set[str] = set()
    genutzt: set[str] = set()
    dateien: list[Path] = []
    for quelle in quellen:
        if not quelle.is_file():
            continue
        text = quelle.read_text(encoding="utf-8")
        ist_html = quelle.suffix == ".html"

        def ersetzen(m: re.Match) -> str:
            if m.group() not in paare:
                offen.add(m.group())
                return m.group()
            genutzt.add(m.group())
            return html.escape(paare[m.group()]) if ist_html else paare[m.group()]

        text = PLATZHALTER.sub(ersetzen, text)
        if ist_html:
            text = text.replace("<div><b>Fassung</b>pseudonymisiert</div>", "<div><b>Fassung</b>mit echten Angaben (im Haus zurückgeführt)</div>")
        ziel = ausgabe / f"{fall_id}_{quelle.name}"
        ziel.write_text(text, encoding="utf-8")
        ziel.chmod(0o600)
        dateien.append(ziel)
    return {"dateien": dateien, "ersetzt": len(genutzt), "ungenutzt": len(paare) - len(genutzt), "offen": sorted(offen)}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("fall")
    p.add_argument("--zuordnung", required=True, help="CSV mit Platzhalter;Klartext, ausserhalb des Projektordners")
    p.add_argument("--ausgabe", required=True, help="Zielordner ausserhalb des Projektordners")
    a = p.parse_args()

    if not sys.stdin.isatty():
        print("FEHLER: Die Rückführung auf echte Angaben macht ein Mensch am Terminal. Ohne Terminal läuft sie nicht.", file=sys.stderr)
        return 2
    try:
        ergebnis = zurueckfuehren(a.fall, Path(a.zuordnung), Path(a.ausgabe))
    except Fehler as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    for ziel in ergebnis["dateien"]:
        print(f"geschrieben: {ziel}")
    print(f"{ergebnis['ersetzt']} Platzhalter ersetzt, {ergebnis['ungenutzt']} Einträge der Zuordnung nicht gebraucht.")
    if ergebnis["offen"]:
        print(f"ACHTUNG: {len(ergebnis['offen'])} Platzhalter ohne Zuordnung blieben stehen: {', '.join(ergebnis['offen'])}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
