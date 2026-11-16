#!/usr/bin/env python3
"""Anhang für die Akte: alle Datenblätter eines Falls in einem Dokument, als HTML und als PDF.

    python3 tools/anhang.py <Fall-ID>                    schreibt rapport/Datenblaetter.html und rapport/Datenblaetter.pdf
    python3 tools/anhang.py <Fall-ID> --ohne-pdf         nur das HTML
    python3 tools/anhang.py <Fall-ID> --nach <Ordner>    legt das PDF zusätzlich in diesem Ordner ab (HTML bleibt in der Fallakte)

Ein Datenblatt zeigt je Indikator, was die Quellen geliefert haben, in den festen Abschnitten seines Typs. Jede Angabe
nennt Quelle, Abfragezeit, Beleg und Stelle in der Rohdatei. Der Anhang kommt aus denselben Funktionen wie die
Oberfläche (tools/ui), braucht sie aber nicht: kein Server, kein Browserfenster, keine Skripte im Dokument.
Das HTML steht für sich allein. Bilder aus den Rohdaten sind eingebettet, nichts wird nachgeladen.
Das PDF erzeugt derselbe Weg wie tools/pdf.py (ein installierter Chrome, Chromium, Edge oder Brave, ohne Fenster).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools import pdf  # noqa: E402
from tools._html import STATUS, STIL, TYPEN, esc  # noqa: E402
from tools.ui import blaetter, daten, darsteller as ds, seiten  # noqa: E402

NAME = "Datenblaetter"
ZUSATZ = """
section.blatt{break-before:page;page-break-before:always;margin-top:34px}
section.blatt h1{font-size:19px;overflow-wrap:anywhere}
details.lang>summary{display:none} details.lang{display:block}
.hilfe{display:none}
"""


def _stil() -> str:
    """Der Stil des Abschlussrapports, dazu die Regeln der Oberfläche für Felder, Marken und Karten."""
    return STIL + (Path(__file__).resolve().parent / "ui" / "app.css").read_text(encoding="utf-8") + ZUSATZ


def bauen(fall_id: str) -> str:
    """Das ganze Dokument als HTML. Es ändert sich nur, wenn sich die Fallakte ändert: Es nennt keine Erzeugungszeit."""
    fall = daten.Fall(fall_id)
    indikatoren = fall.indikatoren()
    kette = fall.kette()
    b = fall.befunde() or {}
    einbetten, seiten.EINBETTEN = seiten.EINBETTEN, True
    try:
        blatt = [f'<section class="blatt">{seiten.datenblatt(fall, i["id"], fuer_akte=True)}</section>' for i in indikatoren]
    finally:
        seiten.EINBETTEN = einbetten
    inhalt = "".join(
        f'<tr><td class="nw"><a href="#{esc(i["id"])}">{esc(i["id"])}</a></td><td class="nw">{esc(TYPEN.get(i.get("typ"), ("Sonstiges",))[0])}</td>'
        f'<td class="mono">{esc(i.get("wert", ""))}</td><td>{esc(i.get("rolle") or "")}</td>'
        f'<td class="nw">{esc(STATUS.get(i.get("bewertung"), STATUS["unbekannt"])[0])}</td><td class="zahl">{len(fall.zu_indikator(i))}</td></tr>' for i in indikatoren)
    abschnitte = "".join(f"<tr><td>{esc(TYPEN.get(typ, ('Sonstiges',))[0])}</td><td>{esc(', '.join(t for t, _ in teile))}</td></tr>"
                         for typ, teile in blaetter.ABSCHNITTE.items())
    kopf = (
        f"<h1>Datenblätter</h1><p class='unter'>Anhang zum Abschlussrapport · Fall {esc(fall.id)} · {esc(fall.daten.get('titel') or '')}</p>"
        "<p>Ein Datenblatt zeigt zu einem Indikator alles, was die befragten Quellen geliefert haben. Die Angaben stehen in festen Abschnitten, "
        "je nach Art des Indikators immer in derselben Reihenfolge. Jede Angabe nennt die Quelle, die Abfragezeit, den Beleg im Ermittlungsprotokoll "
        "und die Stelle in der Rohdatei, an der sie steht. Die Angaben sind Feststellungen der Quellen und werden hier nicht gedeutet. "
        "Was das Ermittlerteam daraus schliesst, steht im Abschlussrapport und ist hier als «Bewertung des Teams» gekennzeichnet.</p>"
        "<p>«Keine Angabe» heisst: Keine der befragten Quellen hat zu diesem Abschnitt etwas geliefert. Welche Quellen befragt wurden und mit "
        "welchem Ergebnis, steht bei jedem Indikator unter «Befragte Quellen». Nennen zwei Quellen für dasselbe Feld Verschiedenes, steht "
        f"«Widerspruch» dabei. Zeiten stehen in der Zeitzone des Arbeitsplatzes ({esc(str(ds.ZONE))}). Eine IP-Adresse, ein Konto oder eine "
        "Wallet-Adresse identifiziert für sich allein keine Person.</p>"
        "<h2>Inhalt</h2>"
        + (f"<table><thead><tr><th>Nr.</th><th>Typ</th><th>Wert</th><th>Rolle</th><th>Bewertung des Teams</th><th class='zahl'>Protokolleinträge</th></tr></thead>"
           f"<tbody>{inhalt}</tbody></table>" if indikatoren else "<p class='klein'>Der Fall hat noch keine Indikatoren.</p>")
        + f"<h2>Abschnitte je Art des Indikators</h2><table><thead><tr><th>Art</th><th>Abschnitte in dieser Reihenfolge</th></tr></thead><tbody>{abschnitte}</tbody></table>")
    fuss = (f"<h2>Begriffe</h2>{seiten.begriffe()}"
            f"<div class='fuss'>Stand der Daten: {len(fall.eintraege())} Protokolleinträge, Protokollkette {'unversehrt' if kette['ok'] else 'NICHT unversehrt'}. "
            f"Letzter Kettenwert: <span class='mono'>{esc(kette.get('letzter_hash') or '–')}</span><br>"
            f"Prüfsumme befunde.json: <span class='mono'>{esc(b.get('_sha256') or '–')}</span><br>"
            f"Erzeugt mit tools/anhang.py aus der Fallakte. Die Rohdateien und das Ermittlungsprotokoll bleiben massgebend.</div>")
    koerper = kopf + "".join(blatt) + fuss
    koerper = koerper.replace('<details class="lang">', '<details class="lang" open>')        # in der Akte steht jeder Wert ausgeschrieben da
    koerper = re.sub(r' <span class="hilfe"[^>]*>\?</span>', "", koerper)
    return ('<!DOCTYPE html>\n<html lang="de-CH"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>Datenblätter · {esc(fall.id)}</title><style>{_stil()}</style></head>\n<body><main>\n{koerper}\n</main></body></html>\n")


def schreiben(fall_id: str) -> Path:
    fall = daten.Fall(fall_id)
    ziel = fall.pfad / "rapport"
    ziel.mkdir(exist_ok=True)
    plattform.text_schreiben(ziel / f"{NAME}.html", bauen(fall_id))
    return ziel / f"{NAME}.html"


def main(argv: list[str]) -> int:
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0 if argv else 2
    ohne_pdf = "--ohne-pdf" in argv
    argv = [a for a in argv if a != "--ohne-pdf"]
    nach = None
    if "--nach" in argv:
        i = argv.index("--nach")
        if i + 1 >= len(argv):
            print("FEHLER: --nach verlangt einen Ordner.", file=sys.stderr)
            return 2
        nach = Path(argv[i + 1]).expanduser()
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 1:
        print(f"FEHLER: Genau eine Fall-ID angeben. Hilfe: {plattform.PY} tools/anhang.py --help", file=sys.stderr)
        return 2
    try:
        html_datei = schreiben(argv[0])
    except daten.NichtGefunden as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    print(f"Datenblätter erzeugt: {html_datei}")
    if ohne_pdf:
        return 0
    browser_liste = pdf.browser_alle()
    if not browser_liste:
        print("Hinweis: Kein Chrome, Chromium, Edge oder Brave gefunden, deshalb kein PDF.\n"
              f"         Entweder einen davon installieren (oder den Pfad in OSINT_BROWSER setzen),\n"
              f"         oder {html_datei} im Browser öffnen und als PDF drucken.", file=sys.stderr)
        return 1
    ziel = (nach or html_datei.parent) / f"{NAME}.pdf"
    ziel.parent.mkdir(parents=True, exist_ok=True)
    fehler = None
    while browser_liste:
        fehler = pdf.umwandeln(browser_liste[0], html_datei, ziel)
        if not fehler or len(browser_liste) == 1:
            break
        print(f"Hinweis: {fehler} Nächster Versuch mit {Path(browser_liste[1]).name}.", file=sys.stderr)
        browser_liste.pop(0)
    if fehler:
        print(f"FEHLER: {NAME}.pdf nicht erzeugt. {fehler}", file=sys.stderr)
        return 1
    print(f"PDF erzeugt: {ziel}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
