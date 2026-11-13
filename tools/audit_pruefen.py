#!/usr/bin/env python3
"""Prüft die Integrität des Abfrageprotokolls eines Falls: Verkettung, Nummernfolge und die
Hashes aller Rohdateien.

    python3 tools/audit_pruefen.py <Fall-ID>

Rückgabewert 0: unverändert. 1: Abweichungen gefunden. 2: Fall nicht gefunden.

Die Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Wer das Protokoll gerichtsfest
verankern will, hinterlegt den letzten Kettenwert ausserhalb des Systems (Journal, signierte
E-Mail, Zeitstempeldienst). Ab dann fällt jede spätere Änderung auf.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.akte import kette_pruefen  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    try:
        ergebnis = kette_pruefen(argv[0])
    except (ValueError, FileNotFoundError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    if ergebnis["anzahl"] + ergebnis["anzahl_extern"] == 0:
        print(f"Fall {argv[0]}: Das Protokoll ist leer. Es wurde noch nichts abgefragt.")
        return 0
    if ergebnis["ok"]:
        print(f"Fall {argv[0]}: {ergebnis['anzahl']} Abfragen des Gateways, {ergebnis['anzahl_extern']} Antworten "
              "weiterer Werkzeuge. Ketten und Rohdaten unverändert.")
        print(f"Letzter Kettenwert: {ergebnis['letzter_hash']}")
        if ergebnis["letzter_hash_extern"]:
            print(f"Letzter Kettenwert (weitere Werkzeuge): {ergebnis['letzter_hash_extern']}")
        return 0
    print(f"Fall {argv[0]}: {len(ergebnis['fehler'])} ABWEICHUNG(EN) in {ergebnis['anzahl'] + ergebnis['anzahl_extern']} Einträgen:")
    for f in ergebnis["fehler"]:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
