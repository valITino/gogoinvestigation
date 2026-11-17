#!/usr/bin/env python3
"""Die Oberfläche: alle Ergebnisse eines Falls an einem Ort, und die Bedienung ohne Terminal.

    python3 tools/oberflaeche.py                     startet den Server und öffnet den Browser
    python3 tools/oberflaeche.py MUSTER-2026-001     öffnet gleich diesen Fall
    python3 tools/oberflaeche.py --port 9000         anderer Port (Vorgabe 8765, sonst der nächste freie)
    python3 tools/oberflaeche.py --ohne-browser      nur den Server starten, die Adresse steht im Terminal
    python3 tools/oberflaeche.py --nur-lesen         nur ansehen: Die Oberfläche kann dann nichts ändern
    python3 tools/oberflaeche.py --ablage <Ordner>   Ablage für Klartext und Zuordnungstabellen, ausserhalb des Projektordners
                                                     (Vorgabe: OSINT-Ablage im Benutzerordner)
    python3 tools/oberflaeche.py --selbstpruefung    kurz starten, die Hauptseiten abrufen, wieder beenden (für die CI)
    python3 tools/oberflaeche.py --sitzungsprobe [Fall-ID]
                                                     Probe mit dem echten Claude Code, am Terminal: Zwei kurze Sitzungen starten wie aus der
                                                     Oberfläche und zeigen, dass gesperrte Aufrufe abgelehnt werden und eine Rückfrage ankommt

Ein lokaler Server in Python, erreichbar nur über 127.0.0.1. Eine Seite, keine fremden Inhalte, läuft ohne Internet.
Beenden mit Strg+C. Was die Oberfläche zeigt und wie sie geschützt ist: docs/OBERFLAECHE.md.

Bedienen (Fall anlegen, Ermittlung starten, freigeben, Dokumente erzeugen) lässt sich die Oberfläche nur, wenn ein Mensch
sie an einem Terminal startet, und nur aus dem Browserfenster, das sich dabei öffnet: Beim Start entsteht ein Geheimnis,
das nur im Speicher des Servers und in diesem Browserfenster liegt. Ohne Terminal oder aus Claude Code heraus gestartet,
läuft sie im Modus «nur lesen». Ein Agent kann sich so über die Oberfläche keine Freigabe erteilen.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools.ui import bedienung as bedienung_modul, daten, server as ui_server  # noqa: E402


def nur_lesen_grund(gewollt: bool) -> str:
    """Warum die Oberfläche nichts ändern darf. Leer heisst: Ein Mensch hat sie am Terminal gestartet, sie ist bedienbar."""
    if gewollt:
        return "mit --nur-lesen gestartet"
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        return "aus Claude Code heraus gestartet. Bedienen kann sie nur, wer sie selbst an einem Terminal startet"
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "ohne Terminal gestartet. Bedienen kann sie nur, wer sie selbst an einem Terminal startet"
    return ""


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


def sitzungsprobe(fall: str, grund: str, ablage: str | None) -> int:
    """Der Beweis am eigenen Arbeitsplatz: Eine Sitzung, die über die Oberfläche startet, läuft unter den Berechtigungen des Projekts."""
    from tools.ui import sitzung as sitzung_modul
    if grund:
        print(f"FEHLER: Die Probe läuft nur, wenn ein Mensch sie an einem Terminal startet ({grund}).", file=sys.stderr)
        return 2
    if sitzung_modul.verfuegbar():
        print(f"FEHLER: {sitzung_modul.verfuegbar()}", file=sys.stderr)
        return 2
    try:
        daten.Fall(fall)
    except daten.NichtGefunden as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    print(f"Die Probe startet Claude Code zweimal kurz im Projektordner, auf demselben Weg wie «Ermittlung starten», am Fall {fall}.\n"
          "Erste Sitzung: Claude Code soll zwei gesperrte Befehle versuchen (sich eine Freigabe erteilen, die Schlüsseldatei anfassen).\n"
          "Zweite Sitzung: Claude Code soll ein Werkzeug aufrufen, das eine Rückfrage verlangt. Die Probe lehnt die Rückfrage ab.\n"
          "Erwartet wird: beide Befehle abgelehnt, fall.json unverändert, die Rückfrage kommt bei der Oberfläche an.\n"
          "Das verbraucht etwas Kontingent des angemeldeten Kontos.\n" + sitzung_modul.abrechnung()["text"])
    if input("Starten? Zur Bestätigung «ja» eingeben: ").strip().lower() != "ja":
        print("Nicht gestartet.")
        return 1
    bedienung = bedienung_modul.Bedienung(Path(ablage) if ablage else None)
    server = ui_server.starten(0, bedienung=bedienung)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        code = sitzung_modul.probe(bedienung, server.server_address[1], fall)
    finally:
        server.shutdown()
        server.server_close()
    print("\nErgebnis: " + ("Die Schutzmechanismen haben gegriffen." if code == 0 else "Mindestens ein Punkt ist offen, siehe oben."))
    return code


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("fall", nargs="?", help="Fall, der gleich geöffnet wird")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--ohne-browser", action="store_true")
    p.add_argument("--nur-lesen", action="store_true")
    p.add_argument("--ablage", help="Ordner ausserhalb des Projektordners für Klartext und Zuordnungstabellen")
    p.add_argument("--selbstpruefung", action="store_true")
    p.add_argument("--sitzungsprobe", action="store_true")
    a = p.parse_args()
    if a.selbstpruefung:
        return selbstpruefung(0)
    if a.fall:
        try:
            daten.Fall(a.fall)
        except daten.NichtGefunden as e:
            print(f"FEHLER: {e}", file=sys.stderr)
            return 2
    grund = nur_lesen_grund(a.nur_lesen)
    if a.sitzungsprobe:
        return sitzungsprobe(a.fall or "MUSTER-2026-001", grund, a.ablage)
    bedienung = None
    if not grund:
        try:
            bedienung = bedienung_modul.Bedienung(Path(a.ablage) if a.ablage else None)
        except bedienung_modul.Fehler as e:
            print(f"FEHLER: {e}", file=sys.stderr)
            return 2
    try:
        server = ui_server.starten(a.port, bedienung=bedienung)
    except OSError as e:
        print(f"FEHLER: Der Server liess sich nicht starten: {e}", file=sys.stderr)
        return 2
    basis = f"http://127.0.0.1:{server.server_address[1]}/"
    adresse = basis + (f"#/fall/{a.fall}" if a.fall else "")
    print(f"Oberfläche läuft: {adresse}")
    if bedienung is None:
        print(f"Modus «nur lesen»: {grund}.")
        print("Erreichbar nur von diesem Rechner. Sie liest die Fallakten und schreibt nie. Beenden mit Strg+C.")
    else:
        # Der Startcode gilt einmal: Das Browserfenster tauscht ihn gegen das Geheimnis. Er steht in keiner Datei.
        adresse = basis + f"#start={bedienung.startcode}" + (f"&nach={a.fall}" if a.fall else "")
        print("Bedienbar aus dem Browserfenster, das sich jetzt öffnet, und nur aus diesem. Erreichbar nur von diesem Rechner.")
        print(f"Ablage für Klartext und Zuordnungstabellen: {bedienung.ablage}")
        if a.ohne_browser:
            print(f"Zum Bedienen diese Adresse einmal im Browser öffnen: {adresse}")
        print("Beenden mit Strg+C.")
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
