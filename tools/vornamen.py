#!/usr/bin/env python3
"""Baut die Vornamenliste für die lokale Pseudonymisierung (tools/vornamen.txt) aus einer Tabelle, die schon auf
diesem Rechner liegt. Lädt nichts herunter. Nur Standardbibliothek.

    python3 tools/vornamen.py stand                                   Zahl der Namen und Kopf der Liste
    python3 tools/vornamen.py bauen maenner.xlsx frauen.xlsx --stand 2025
                              [--ab 20] [--quelle "…"] [--bedingung "…"] [--nach DATEI]

Gedacht für die Vornamenstatistik des Bundesamtes für Statistik (BFS), «Vornamen der Bevölkerung nach Jahrgang,
Schweiz und Sprachgebiete» (BFS-Nummer su-d-01.04.00.11, je eine Tabelle für Männer und Frauen, als .xlsx oder
.csv). Die Dateien lädt ein Mensch von der Seite des BFS herunter. Dort steht auch die Nutzungsbedingung, am
16.11.2026 «OPEN-BY: Freie Nutzung. Quellenangabe ist Pflicht.» Das Werkzeug schreibt Quelle, Ausgabe, Datum der
Kopie und Nutzungsbedingung in den Kopf der Liste.

Gelesen wird jede Zeile, die mit einem Namen beginnt und mindestens eine Zahl enthält. Die Zahlen der Zeile werden
zusammengezählt. `--ab` lässt Namen weg, die seltener vorkommen. Das Werkzeug ist an erfundenen Tabellen geprüft,
nicht an der Datei des BFS: Nach dem Bauen die Zahl der Namen ansehen und neu messen (tools/pseudo_messen.py).
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
import zipfile
from datetime import date
from pathlib import Path
from xml.etree import ElementTree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools import _pseudo as ps  # noqa: E402

NAME = re.compile(r"[^\W\d_][^\W\d_'’-]*(?:[ '’-][^\W\d_]+)*")
KEIN_NAME = frozenset("vorname vornamen prénom prénoms prenom nome nomi name total jahrgang année anno rang insgesamt summe".split())
NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
QUELLE = "Bundesamt für Statistik (BFS), Vornamen der Bevölkerung nach Jahrgang, Schweiz und Sprachgebiete (su-d-01.04.00.11)"
BEDINGUNG = "OPEN-BY: Freie Nutzung. Quellenangabe ist Pflicht."


def _zeilen_xlsx(datei: Path) -> list[list[str]]:
    zeilen: list[list[str]] = []
    with zipfile.ZipFile(datei) as z:
        texte: list[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ElementTree.fromstring(z.read("xl/sharedStrings.xml")).iter(f"{NS}si"):
                texte.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
        for name in sorted(n for n in z.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)):
            for row in ElementTree.fromstring(z.read(name)).iter(f"{NS}row"):
                zeile = []
                for c in row.iter(f"{NS}c"):
                    v = c.find(f"{NS}v")
                    if c.get("t") == "s" and v is not None and v.text and v.text.isdigit() and int(v.text) < len(texte):
                        zeile.append(texte[int(v.text)])
                    elif c.get("t") == "inlineStr":
                        zeile.append("".join(t.text or "" for t in c.iter(f"{NS}t")))
                    else:
                        zeile.append(v.text if v is not None and v.text else "")
                zeilen.append(zeile)
    return zeilen


def _zeilen_csv(datei: Path) -> list[list[str]]:
    text = datei.read_text(encoding="utf-8-sig", errors="replace")
    trenner = max(";,\t", key=lambda t: text[:5000].count(t))
    return list(csv.reader(io.StringIO(text), delimiter=trenner))


def lesen(datei: Path) -> dict[str, float]:
    """Liefert Name -> Häufigkeit aus einer Tabelle (.xlsx oder .csv)."""
    zeilen = _zeilen_xlsx(datei) if datei.suffix.lower() == ".xlsx" else _zeilen_csv(datei)
    namen: dict[str, float] = {}
    for zeile in zeilen:
        zellen = [z.strip() for z in zeile if z and z.strip()]
        if not zellen or not NAME.fullmatch(zellen[0]) or len(zellen[0]) > 30 or zellen[0].casefold() in KEIN_NAME:
            continue
        zahlen = []
        for z in zellen[1:]:
            try:
                zahlen.append(float(z.replace("'", "").replace("’", "").replace(" ", "")))
            except ValueError:
                continue
        if not zahlen:
            continue
        name = zellen[0] if not zellen[0].isupper() else zellen[0].title()
        namen[name] = namen.get(name, 0) + sum(zahlen)
    return namen


def bauen(dateien: list[Path], ab: float, stand: str, quelle: str, bedingung: str, ziel: Path, heute: date | None = None) -> int:
    alle: dict[str, float] = {}
    for datei in dateien:
        for name, zahl in lesen(datei).items():
            alle[name] = alle.get(name, 0) + zahl
    gewaehlt = sorted((n for n, zahl in alle.items() if zahl >= ab), key=ps.falten)
    if not gewaehlt:
        raise ValueError("In den Dateien wurde kein Name gefunden. Erwartet wird eine Tabelle mit dem Namen in der ersten Spalte und Zahlen dahinter.")
    heute = heute or date.today()
    kopf = ["# Vornamenliste für tools/pseudonymisieren.py (Schicht 5, Kandidaten im Fliesstext)",
            "#",
            f"# Quelle: {quelle}, Ausgabe {stand}.",
            f"# Nutzungsbedingung laut Quelle: {bedingung}",
            f"# Kopie vom {heute.strftime('%d.%m.%Y')}, gebaut mit tools/vornamen.py aus: {', '.join(d.name for d in dateien)}.",
            f"# {len(gewaehlt)} Namen" + (f", die mindestens {ab:g}-mal vorkommen." if ab > 0 else "."),
            "#",
            "# Format: Namen durch Leerzeichen, Komma oder Zeilenumbruch getrennt. Gross/klein und Akzente spielen keine Rolle.",
            ""]
    zeilen = [", ".join(gewaehlt[i:i + 8]) for i in range(0, len(gewaehlt), 8)]
    plattform.text_schreiben(ziel, "\n".join(kopf + zeilen) + "\n")
    return len(gewaehlt)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="befehl", required=True)
    sub.add_parser("stand", help="Zahl der Namen und Kopf der Liste")
    b = sub.add_parser("bauen", help="Liste aus Tabellen bauen, die schon auf dem Rechner liegen")
    b.add_argument("dateien", nargs="+")
    b.add_argument("--stand", required=True, help="Ausgabe der Statistik, zum Beispiel 2025")
    b.add_argument("--ab", type=float, default=20, help="Namen, die seltener vorkommen, weglassen (Vorgabe 20)")
    b.add_argument("--quelle", default=QUELLE)
    b.add_argument("--bedingung", default=BEDINGUNG)
    b.add_argument("--nach", default=str(ps.VORNAMEN), help="Zieldatei (Vorgabe tools/vornamen.txt)")
    a = p.parse_args()
    if a.befehl == "stand":
        kopf = [z for z in ps.VORNAMEN.read_text(encoding="utf-8").splitlines() if z.startswith("#")]
        print("\n".join(kopf[:12]))
        print(f"\n{len(ps.vornamen_lesen())} Namen in {ps.VORNAMEN.name}")
        return 0
    try:
        n = bauen([Path(d).expanduser() for d in a.dateien], a.ab, a.stand, a.quelle, a.bedingung, Path(a.nach).expanduser())
    except (OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    print(f"{n} Namen geschrieben nach {a.nach}. Danach neu messen: {plattform.PY} tools/pseudo_messen.py --readme")
    return 0


if __name__ == "__main__":
    sys.exit(main())
