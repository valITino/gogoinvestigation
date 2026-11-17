#!/usr/bin/env python3
"""Prüft die Integrität des Abfrageprotokolls eines Falls: Verkettung, Nummernfolge und die
Hashes aller Rohdateien.

    python3 tools/audit_pruefen.py <Fall-ID>
    python3 tools/audit_pruefen.py <Fall-ID> --erwartet <Kettenwert> [--erwartet <Kettenwert> …]

Rückgabewert 0: unverändert. 1: Abweichungen gefunden. 2: Fall nicht gefunden.

Die Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Eines erkennt sie für sich allein nicht: Wer
die letzten Einträge samt ihren Rohdateien entfernt, hinterlässt wieder eine stimmige, nur kürzere Kette. Dagegen
hilft ein Anker ausserhalb des Systems. Der letzte Kettenwert steht im Ermittlungsprotokoll und im Abschlussrapport.
Wer ihn im Journal, in einer signierten E-Mail oder bei einem Zeitstempeldienst hinterlegt, kann später mit
``--erwartet`` prüfen, ob dieser Stand noch in der Kette steht. Fehlt er, wurde das Protokoll seither gekürzt oder
ersetzt. Die Werte der beiden Protokolle (Gateway und weitere Werkzeuge) lassen sich je mit einem ``--erwartet`` angeben.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import belege_lesen, kette_pruefen  # noqa: E402


def main(argv: list[str]) -> int:
    erwartet: list[str] = []
    while "--erwartet" in argv:
        i = argv.index("--erwartet")
        if i + 1 >= len(argv):
            print("FEHLER: --erwartet verlangt einen Kettenwert (64 Zeichen).", file=sys.stderr)
            return 2
        erwartet.append(argv[i + 1].strip().lower())
        argv = argv[:i] + argv[i + 2:]
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    try:
        ergebnis = kette_pruefen(argv[0])
    except (ValueError, FileNotFoundError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    fehlend = []
    if erwartet:
        vorhanden = {str(e.get("kette") or "").lower() for e in belege_lesen(argv[0])}
        fehlend = [w for w in erwartet if w not in vorhanden]
        for w in fehlend:
            ergebnis["fehler"].append(f"Der erwartete Kettenwert {w[:16]}… steht nicht mehr im Protokoll. Seit er festgehalten wurde, "
                                      "ist das Protokoll gekürzt oder ersetzt worden.")
        ergebnis["ok"] = ergebnis["ok"] and not fehlend
    if ergebnis["anzahl"] + ergebnis["anzahl_extern"] == 0 and not fehlend:
        print(f"Fall {argv[0]}: Das Protokoll ist leer. Es wurde noch nichts abgefragt.")
        return 0
    if ergebnis["ok"]:
        print(f"Fall {argv[0]}: {ergebnis['anzahl']} Abfragen des Gateways, {ergebnis['anzahl_extern']} Antworten "
              "weiterer Werkzeuge. Ketten und Rohdaten unverändert.")
        print(f"Letzter Kettenwert: {ergebnis['letzter_hash']}")
        if ergebnis["letzter_hash_extern"]:
            print(f"Letzter Kettenwert (weitere Werkzeuge): {ergebnis['letzter_hash_extern']}")
        if erwartet:
            print(f"Erwartete Kettenwerte: alle {len(erwartet)} stehen in der Kette. Seit sie festgehalten wurden, ist nichts entfernt worden.")
        return 0
    print(f"Fall {argv[0]}: {len(ergebnis['fehler'])} ABWEICHUNG(EN) in {ergebnis['anzahl'] + ergebnis['anzahl_extern']} Einträgen:")
    for f in ergebnis["fehler"]:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
