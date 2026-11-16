#!/usr/bin/env python3
"""Prüft die passiven Prüfungen von Web-Check gegen die laufende Instanz, über das Gateway.

    python3 tools/webcheck_live.py                       jede passive Prüfung einmal gegen example.com
    python3 tools/webcheck_live.py --ziel example.org    anderes Ziel (nur eigene oder öffentliche Testdomains)
    python3 tools/webcheck_live.py --warten 120          bis zu so viele Sekunden auf die Instanz warten

Je Prüfung steht da: das Urteil des Gateways (ok, kein Treffer, Fehlschlag), was der Agent davon sieht, und die
Rohantwort von Web-Check. Die Rohantwort ist der Zweck: Aus ihr stammen die Vorlagen des Selbsttests
(tools/_vorlagen.py). Ändert Web-Check eine Antwortform oder den Namen einer Prüfung, fällt es hier auf.

Abgefragt werden nur die Prüfungen, bei denen Dritte oder das DNS befragt werden (gateway/quellen_web.py,
WEBCHECK_PASSIV). Der Webserver des Ziels wird nicht aufgerufen. Aktive Prüfungen laufen hier nie.

Fallakte: faelle/SELBSTTEST, wie bei tools/pruefen.py --live. Die Instanz startet 'docker compose up -d webcheck'.
In GitHub Actions läuft das im Workflow «Web-Check live»: Ein Runner hat freien Zugang zu DNS, WHOIS und den
befragten Diensten. Hinter einem HTTPS-Proxy scheitern die meisten Prüfungen, weil der Container sie nicht erreicht.

Rückgabewert 0: Die Instanz antwortet und kennt jede Prüfung. 1: Instanz nicht erreichbar oder eine Prüfung
gibt es unter diesem Namen nicht mehr. Einzelne Fehlschläge fremder Dienste (Tranco, Have I Been Pwned) sind kein Fehler.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start(venv=True)

try:
    from gateway import kern, quellen_web
    from gateway.akte import FAELLE, jsonl_lesen
    from tools import fall as fallwerkzeug
except ModuleNotFoundError as e:
    sys.exit(f"Paket '{e.name}' fehlt. Bitte zuerst {plattform.SETUP} ausführen.")

FALL = "SELBSTTEST"
ZWECK = "Live-Prüfung der passiven Web-Check-Prüfungen mit einer öffentlichen Testdomain"
ZEICHEN = {"ok": plattform.GUT, "kein_treffer": plattform.AUS, "fehler": plattform.FEHLT}


def erreichbar(adresse: str, warten: int) -> bool:
    teile = urlsplit(adresse)
    ende = time.monotonic() + warten
    while True:
        try:
            with socket.create_connection((teile.hostname or "127.0.0.1", teile.port or 80), timeout=2):
                return True
        except OSError:
            if time.monotonic() >= ende:
                return False
            time.sleep(2)


def gekuerzt(text: str, grenze: int) -> str:
    return text if len(text) <= grenze else text[:grenze] + f"\n… gekürzt, {len(text)} Zeichen insgesamt"


async def alle(ziel: str, grenze: int) -> list[tuple[str, dict, dict]]:
    ergebnisse = []
    for pruefung in quellen_web.WEBCHECK_PASSIV:
        r = await quellen_web.webcheck_passiv(FALL, ZWECK, ziel=ziel, pruefung=pruefung)
        eintrag = next((e for e in reversed(jsonl_lesen(FAELLE / FALL / "protokoll" / "abfragen.jsonl"))
                        if e["id"] == r.get("protokoll_id")), {})
        antwort = eintrag.get("antwort") or {}
        print(f"{ZEICHEN.get(r.get('ergebnis'), plattform.FEHLT)} {pruefung}: {r.get('ergebnis')}, HTTP {antwort.get('status')}, "
              f"{antwort.get('bytes')} Bytes, {antwort.get('dauer_ms')} ms" + (f" (aus dem Fall-Cache, {r['aus_cache']})" if r.get("aus_cache") else ""))
        for feld in ("fehler", "grund"):
            if r.get(feld):
                print(f"    {feld}: {r[feld]}")
        if "befund" in r:
            print("    an den Agenten: " + gekuerzt(json.dumps(r["befund"], ensure_ascii=False), 600))
        roh = FAELLE / FALL / antwort["rohdaten"] if antwort.get("rohdaten") else None
        if roh and roh.is_file():
            text = roh.read_text(encoding="utf-8", errors="replace")
            try:
                text = json.dumps(json.loads(text), ensure_ascii=False, indent=1)
            except json.JSONDecodeError:
                pass
            print("    Rohantwort:\n" + "\n".join("      " + z for z in gekuerzt(text, grenze).splitlines()))
        print(flush=True)
        ergebnisse.append((pruefung, r, antwort))
    return ergebnisse


def main() -> int:
    p = argparse.ArgumentParser(description="Passive Prüfungen von Web-Check über das Gateway prüfen.")
    p.add_argument("--ziel", default="example.com", help="Testdomain (Standard: example.com)")
    p.add_argument("--warten", type=int, default=0, metavar="SEKUNDEN", help="so lange auf die Instanz warten")
    p.add_argument("--zeichen", type=int, default=5000, help="Rohantwort je Prüfung höchstens so lang ausgeben")
    a = p.parse_args()
    adresse = kern.einstellung("WEBCHECK_URL", "http://127.0.0.1:3000")
    if not erreichbar(adresse, a.warten):
        print(f"{plattform.FEHLT} Web-Check ist unter {adresse} nicht erreichbar. Start: docker compose up -d webcheck")
        return 1
    pfad = FAELLE / FALL
    if not (pfad / "fall.json").is_file():
        for ordner in fallwerkzeug.UNTERORDNER:
            (pfad / ordner).mkdir(parents=True, exist_ok=True)
        fallwerkzeug.schreiben(pfad / "fall.json", {"fall_id": FALL, "titel": "Live-Test der Quellen", "freigaben": {}})
    print(f"Web-Check unter {adresse}, Ziel {a.ziel}, {len(quellen_web.WEBCHECK_PASSIV)} passive Prüfungen\n", flush=True)
    ergebnisse = asyncio.run(alle(a.ziel, a.zeichen))
    je = {art: [n for n, r, _ in ergebnisse if r.get("ergebnis") == art] for art in ("ok", "kein_treffer", "fehler")}
    print(f"{len(je['ok'])} mit Ergebnis, {len(je['kein_treffer'])} ohne Treffer, {len(je['fehler'])} Fehlschläge"
          + (f" ({', '.join(je['fehler'])})" if je["fehler"] else "") + ".")
    unbekannt = [n for n, _, antwort in ergebnisse if antwort.get("status") == 404]
    stumm = [n for n, _, antwort in ergebnisse if antwort.get("status") == 0]
    if unbekannt:
        print(f"{plattform.FEHLT} Diese Prüfungen kennt die Instanz nicht mehr (HTTP 404): {', '.join(unbekannt)}. "
              "WEBCHECK_PASSIV in gateway/quellen_web.py nachführen.")
    if stumm:
        print(f"{plattform.FEHLT} Keine Verbindung zur Instanz bei: {', '.join(stumm)}.")
    return 1 if unbekannt or stumm else 0


if __name__ == "__main__":
    sys.exit(main())
