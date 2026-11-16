#!/usr/bin/env python3
"""Die Oberfläche: alle Ergebnisse eines Falls an einem Ort. Liest nur, schreibt nie.

    python3 tools/oberflaeche.py                     startet den Server und öffnet den Browser
    python3 tools/oberflaeche.py MUSTER-2026-001     öffnet gleich diesen Fall
    python3 tools/oberflaeche.py --port 9000         anderer Port (Vorgabe 8765, sonst der nächste freie)
    python3 tools/oberflaeche.py --ohne-browser      nur den Server starten, die Adresse steht im Terminal
    python3 tools/oberflaeche.py --selbstpruefung    kurz starten, die Hauptseiten abrufen, wieder beenden (für die CI)

Ein lokaler Server in Python, erreichbar nur über 127.0.0.1. Eine Seite, keine fremden Inhalte, läuft ohne Internet.
Beenden mit Strg+C. Was die Oberfläche zeigt und wie sie geschützt ist: docs/OBERFLAECHE.md.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools.ui import daten, server as ui_server  # noqa: E402


def selbstpruefung(port: int) -> int:
    """Startet, ruft die Hauptseiten ab und beendet sich. Prüft, dass die Oberfläche auf diesem System läuft."""
    server = ui_server.starten(port)
    echt = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    basis = f"http://127.0.0.1:{echt}"
    oeffner = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # nie über einen Proxy: Es geht nur um den eigenen Rechner
    try:
        fehler = []
        wege = ["/", "/app.js", "/app.css", "/basis.css", "/api/faelle", "/api/quellen"]
        for fall in daten.faelle():
            if fall["muster"]:
                wege += [f"/api/fall/{fall['id']}/{a}" for a in ("kopf", "uebersicht", "rapport", "indikatoren", "rohdaten", "dokumente", "spur")]
        for weg in wege:
            try:
                with oeffner.open(basis + weg, timeout=60) as r:
                    inhalt = r.read()
                    if r.status != 200 or not inhalt:
                        fehler.append(f"{weg}: HTTP {r.status}")
                    elif weg.startswith("/api/") and "fehler" in json.loads(inhalt):
                        fehler.append(f"{weg}: {json.loads(inhalt)['fehler']}")
            except Exception as e:      # jede Art von Fehlschlag zählt
                fehler.append(f"{weg}: {type(e).__name__}: {e}")
        anfrage = urllib.request.Request(basis + "/api/faelle", headers={"Host": "fremd.example"})
        try:
            oeffner.open(anfrage, timeout=30)
            fehler.append("Eine Anfrage mit fremdem Host-Kopf wurde beantwortet.")
        except urllib.error.HTTPError as e:
            if e.code != 403:
                fehler.append(f"Fremder Host-Kopf: HTTP {e.code} statt 403")
        for f in fehler:
            print(f"{plattform.FEHLT} {f}")
        if not fehler:
            print(f"{plattform.GUT} Die Oberfläche startet, {len(wege)} Seiten antworten, ein fremder Host-Kopf wird abgewiesen.")
        return 1 if fehler else 0
    finally:
        server.shutdown()
        server.server_close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("fall", nargs="?", help="Fall, der gleich geöffnet wird")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--ohne-browser", action="store_true")
    p.add_argument("--selbstpruefung", action="store_true")
    a = p.parse_args()
    if a.selbstpruefung:
        return selbstpruefung(0)
    if a.fall:
        try:
            daten.Fall(a.fall)
        except daten.NichtGefunden as e:
            print(f"FEHLER: {e}", file=sys.stderr)
            return 2
    try:
        server = ui_server.starten(a.port)
    except OSError as e:
        print(f"FEHLER: Der Server liess sich nicht starten: {e}", file=sys.stderr)
        return 2
    adresse = f"http://127.0.0.1:{server.server_address[1]}/" + (f"#/fall/{a.fall}" if a.fall else "")
    print(f"Oberfläche läuft: {adresse}")
    print("Erreichbar nur von diesem Rechner. Sie liest die Fallakten und schreibt nie. Beenden mit Strg+C.")
    if not a.ohne_browser:
        threading.Timer(0.6, lambda: webbrowser.open(adresse)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
