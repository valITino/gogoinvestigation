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
                                                     Probe mit dem echten Claude Code, am Terminal: Fünf kurze Sitzungen starten wie aus der
                                                     Oberfläche und zeigen, ob der Weg trägt (Ausgabe und Hooks, Fortsetzen, Verbote, Rückfrage,
                                                     Frage an den Sachbearbeiter)

Ein lokaler Server in Python, erreichbar nur über 127.0.0.1. Eine Seite, keine fremden Inhalte, läuft ohne Internet.
Beenden mit Strg+C. Was die Oberfläche zeigt und wie sie geschützt ist: docs/OBERFLAECHE.md.

Bedienen (Akten hochladen, Fall anlegen, Ermittlung starten und im Chat begleiten, freigeben, Ergebnisse holen) lässt sich die Oberfläche nur, wenn ein Mensch
sie an einem Terminal startet, und nur aus dem Browserfenster, das sich dabei öffnet: Beim Start entsteht ein Geheimnis,
das nur im Speicher des Servers und in diesem Browserfenster liegt. Ohne Terminal oder aus Claude Code heraus gestartet,
läuft sie im Modus «nur lesen». Ein Agent kann sich so über die Oberfläche keine Freigabe erteilen.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
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


# Unter WSL gibt es in Linux meist keinen Browser, wohl aber den von Windows. Diese Wege öffnen dort eine Adresse im
# Standardbrowser, ohne dass eine Shell sie zerlegt (in der Adresse stehen # und &). Der erste, der sich starten lässt, gilt.
# Zuerst die beiden Programme, die zu Windows gehören. wslview stammt aus dem Paket wslu, das nicht mehr gepflegt wird: zuletzt.
WINDOWS_ORDNER = ("/mnt/c/Windows/System32", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0")
WSL_WEGE = (("rundll32.exe", "url.dll,FileProtocolHandler", "{adresse}"),
            ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Start-Process '{adresse}'"),
            ("wslview", "{adresse}"))


def _programm(name: str) -> str | None:
    """Ein Programm im PATH, sonst an den festen Orten von Windows (WSL hängt sie nicht in jeder Einstellung an den PATH)."""
    return plattform.programm(name) or next((str(Path(o) / name) for o in WINDOWS_ORDNER if (Path(o) / name).is_file()), None)


def basis_adresse(port: int) -> str:
    """Die Adresse der Oberfläche. Unter WSL mit dem Namen localhost: Unter ihm reicht Windows eine Anfrage aus seinem Browser
    an einen Server in WSL weiter (Microsoft, «Accessing Linux networking apps from Windows»). Der Server hört weiterhin nur
    auf 127.0.0.1 und nimmt beide Namen an."""
    return f"http://{'localhost' if plattform.wsl() else '127.0.0.1'}:{port}/"


def browser_oeffnen(adresse: str) -> bool:
    """Öffnet die Adresse im Browser. Gibt zurück, ob sich einer starten liess. Ob wirklich ein Fenster aufging, weiss unter
    WSL niemand: Deshalb zeigt der Aufrufer dort die Adresse zusätzlich an."""
    if plattform.wsl():
        for programm, *argumente in WSL_WEGE:
            pfad = _programm(programm)
            if not pfad:
                continue
            try:
                r = subprocess.run([pfad, *(x.format(adresse=adresse) for x in argumente)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if r.returncode == 0:
                return True
        return False
    try:
        return bool(webbrowser.open(adresse))
    except webbrowser.Error:
        return False


def oeffnen_oder_zeigen(adresse: str) -> None:
    """Öffnet den Browser. Geht das nicht, oder lässt es sich wie unter WSL nicht feststellen, steht die Adresse im Terminal:
    Niemand soll eine Option kennen müssen, um in die Oberfläche zu kommen."""
    offen = browser_oeffnen(adresse)
    if offen and not plattform.wsl():
        return
    wo = "im Browser von Windows" if plattform.wsl() else "in einem Browser auf diesem Rechner"
    print(("Öffnet sich kein Browserfenster: diese" if offen else "Es liess sich kein Browser öffnen. Diese")
          + f" Adresse einmal {wo} öffnen:\n  {adresse}", flush=True)


def nur_lesen_grund(gewollt: bool) -> str:
    """Warum die Oberfläche nichts ändern darf. Leer heisst: Ein Mensch hat sie am Terminal gestartet, sie ist bedienbar."""
    if gewollt:
        return "mit --nur-lesen gestartet"
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        return "aus Claude Code heraus gestartet. Bedienen kann sie nur, wer sie selbst an einem Terminal startet"
    if not plattform.terminal(sys.stdin, sys.stdout):
        return "ohne Terminal gestartet. Bedienen kann sie nur, wer sie selbst an einem Terminal startet"
    return ""


def ordner_bestaetigen() -> None:
    """Vertraut Claude Code dem Projektordner noch nicht, startet die Oberfläche es einmal dafür: Ein eigener Schritt ist so
    nicht mehr nötig. Die Antwort gibt der Mensch im Dialog von Claude Code, nie die Oberfläche. Fehlt Claude Code, oder
    lässt sich der Stand nicht ablesen, geschieht nichts."""
    claude = plattform.programm("claude")
    if not claude or plattform.ordner_vertraut(plattform.PROJEKT) is not False:
        return
    print("Claude Code vertraut diesem Ordner noch nicht. " + plattform.OHNE_VERTRAUEN + "\n"
          "Es startet jetzt einmal und fragt danach: mit Ja bestätigen, dann /exit eingeben. Danach öffnet die Oberfläche.")
    try:
        antwort = input("Jetzt starten? Enter für Ja, n für Nein: ").strip().lower()
    except EOFError:
        antwort = "n"
    if antwort in ("n", "nein"):
        print("Nicht gestartet. Die Oberfläche fragt beim nächsten Start wieder.")
        return
    try:
        subprocess.call([claude], cwd=str(plattform.PROJEKT))
    except (OSError, KeyboardInterrupt):
        pass
    print("Projektordner in Claude Code bestätigt." if plattform.ordner_vertraut(plattform.PROJEKT) else
          "Keine Bestätigung gefunden. Die Oberfläche öffnet trotzdem. " + plattform.OHNE_VERTRAUEN)


def selbstpruefung(port: int) -> int:
    """Startet, ruft die Hauptseiten ab und beendet sich. Prüft, dass die Oberfläche auf diesem System läuft."""
    server = ui_server.starten(port)
    echt = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    basis = f"http://127.0.0.1:{echt}"
    oeffner = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # nie über einen Proxy: Es geht nur um den eigenen Rechner
    try:
        fehler = []
        wege = ["/", "/app.js", "/app.css", "/bedienung.css", "/basis.css", "/api/faelle", "/api/quellen", "/api/neu", "/api/arbeitsplatz"]
        for fall in daten.faelle():
            if fall["muster"]:
                wege += [f"/api/fall/{fall['id']}/{a}" for a in ("kopf", "uebersicht", "akten", "rapport", "indikatoren", "rohdaten", "dokumente", "ergebnisse", "verlauf", "spur")]
                wege.append(f"/fall/{fall['id']}/paket.zip?teile=unterlagen")
        for weg in wege:
            try:
                with oeffner.open(basis + weg, timeout=60) as r:
                    inhalt = r.read()
                    if r.status != 200 or not inhalt:
                        fehler.append(f"{weg}: HTTP {r.status}")
                    elif weg.endswith("unterlagen") and not inhalt.startswith(b"PK"):
                        fehler.append(f"{weg}: kein ZIP-Archiv")
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
    print(f"Die Probe startet Claude Code fünfmal kurz im Projektordner, auf demselben Weg wie «Ermittlung starten», am Fall {fall}.\n"
          "1. Ablauf: Claude Code ruft einmal fall_status auf. Geprüft wird die Form der Ausgabe, ob das Gateway geladen ist und ob der Protokoll-Hook mitschreibt.\n"
          "2. Fortsetzen: Dieselbe Sitzung wird wieder aufgenommen, wie es eine Nachricht aus dem Chat tut.\n"
          "3. Verbote: Claude Code soll zwei gesperrte Befehle versuchen (sich eine Freigabe erteilen, die Schlüsseldatei lesen).\n"
          "4. Rückfrage: Claude Code soll ein Werkzeug aufrufen, das eine Zustimmung verlangt. Die Probe lehnt jede Rückfrage ab.\n"
          "5. Frage: Claude Code soll dem Sachbearbeiter eine Frage mit zwei Antworten stellen. Die Probe beantwortet sie selbst und prüft, ob die Antwort ankommt.\n"
          "Am Fall ändert die Probe nichts. Sie verbraucht etwas Kontingent des angemeldeten Kontos.\n" + sitzung_modul.abrechnung()["text"])
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
    print("\nErgebnis: " + ("Der Weg trägt: Ausgabe, Hooks, Fortsetzen, Verbote und Rückfrage verhalten sich wie erwartet." if code == 0
                            else "Mindestens ein Punkt ist offen, siehe oben. Bis er geklärt ist, die Ermittlung am Terminal starten."))
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
    # Die Einrichtung hat eben selbst nach dem Ja zum Projektordner gefragt: Dann fragt der Start nicht gleich noch einmal
    p.add_argument("--ordner-gefragt", action="store_true", help=argparse.SUPPRESS)
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
        if not a.ordner_gefragt:
            ordner_bestaetigen()
    try:
        server = ui_server.starten(a.port, bedienung=bedienung)
    except OSError as e:
        print(f"FEHLER: Der Server liess sich nicht starten: {e}", file=sys.stderr)
        return 2
    basis = basis_adresse(server.server_address[1])
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
        threading.Timer(0.6, oeffnen_oder_zeigen, [adresse]).start()
    from tools import dienste
    port = server.server_address[1]
    schluss = threading.Event()

    def anlauf() -> None:                   # was «Alles abschalten» gestoppt hat und kein Passwort braucht, läuft mit ihr wieder an
        for satz in dienste.beim_start():
            print(satz, flush=True)

    def enden(*_: object) -> None:          # von aussen beendet: enden wie mit Strg+C
        threading.Thread(target=server.shutdown, daemon=True).start()

    def wache() -> None:                    # «tools/dienste.py aus» bittet über eine Datei ums Ende. Das geht auch unter Windows
        while not schluss.wait(0.5):
            if dienste.oberflaeche_soll_enden(port):
                return enden()
    if bedienung is not None:               # im Hintergrund: Der Browser soll nicht warten, bis Docker geantwortet hat
        threading.Thread(target=anlauf, daemon=True).start()
    dienste.oberflaeche_merken(port)        # so findet «tools/dienste.py aus» sie, auch aus einem anderen Terminal
    threading.Thread(target=wache, daemon=True).start()
    with contextlib.suppress(ValueError, OSError, AttributeError):
        signal.signal(signal.SIGTERM, enden)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        schluss.set()
        if bedienung is not None:           # eine Sitzung ohne Oberfläche könnte niemanden mehr fragen: anhalten, fortsetzen geht später
            faelle = bedienung.alles_anhalten("Die Oberfläche wurde beendet")
            if faelle:
                print(f"\nErmittlung angehalten: {', '.join(faelle)}. Fortsetzen: Oberfläche starten, dort «Ermittlung».")
        dienste.oberflaeche_vergessen(port)
        server.server_close()
    print("\nBeendet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
