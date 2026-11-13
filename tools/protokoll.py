#!/usr/bin/env python3
"""Erzeugt das Ermittlungsprotokoll eines Falls: wann wurde was, wo, wozu und durch wen
abgefragt, und was kam zurück.

    python3 tools/protokoll.py <Fall-ID>

Ergebnis: faelle/<Fall-ID>/rapport/Ermittlungsprotokoll.html  (lesbar, druckbar)
          faelle/<Fall-ID>/rapport/Ermittlungsprotokoll.csv   (maschinenlesbar, Trennzeichen ;)

Quellen des Protokolls:
  - faelle/<Fall-ID>/protokoll/abfragen.jsonl   jede Abfrage des Gateways, hash-verkettet
  - faelle/<Fall-ID>/protokoll/extern.jsonl     gesicherte Antworten weiterer MCP-Server (Robin)
  - protokoll/sitzungen/*.jsonl                 Sitzungsprotokoll des Hooks: Aufträge des
                                                Sachbearbeiters, Agenten, übrige Werkzeugaufrufe
Rückgabewert 0: erzeugt, Kette unverändert. 1: erzeugt, aber Abweichungen in der Kette. 2: Fall fehlt.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.akte import SITZUNGEN, fall_daten, fall_pfad, jsonl_lesen, kette, kette_pruefen  # noqa: E402
from tools._html import balken, esc, kachel, kuerzen, seite  # noqa: E402

ZONE = ZoneInfo(os.environ.get("OSINT_ZEITZONE", "Europe/Zurich"))


def erstellt() -> datetime:
    """Erstellzeit des Dokuments. Für den Musterfall gestellt, damit er bei jedem Lauf gleich ausfällt."""
    if os.environ.get("OSINT_TESTZEIT"):
        return datetime.strptime(os.environ["OSINT_TESTZEIT"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)
ERGEBNIS = {"ok": ("✓ Treffer", "var(--gut)"), "kein_treffer": ("○ kein Treffer", "var(--neutral)"),
            "fehler": ("✕ Fehler", "var(--kritisch)"), "abgelehnt": ("⊘ abgelehnt", "var(--warnung)")}


def lokal(utc: str | None) -> str:
    if not utc:
        return ""
    try:
        d = datetime.strptime(utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return utc
    return d.astimezone(ZONE).strftime("%d.%m.%Y %H:%M:%S")


def groesse(n: int | None) -> str:
    if not n:
        return "0 B"
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} kB" if n < 1 << 20 else f"{n / (1 << 20):.1f} MB"


KOPFZEILE = ("<thead><tr><th style='width:7.5%'>Nr.</th><th style='width:11%'>Zeit</th><th style='width:27%'>Quelle / Werkzeug</th>"
             "<th>Ziel und Zweck</th><th style='width:19.5%'>Ergebnis / durch</th></tr></thead>")


def eintrag(e: dict, quelle: str, ziel: str, ergebnis: str, durch: str | None, technik: list[str]) -> str:
    """Ein Protokolleintrag: Hauptzeile, darunter die technischen Angaben über die volle Breite.
    Die Bausteine sind bereits HTML und von der aufrufenden Stelle maskiert."""
    zeit = esc(lokal(e.get("zeit_utc"))).replace(" ", "<br>")
    return (f"<tbody class='eintrag' id='{esc(e['id'])}'><tr class='haupt'><td class='beleg'>{esc(e['id'])}</td>"
            f"<td title='{esc(e.get('zeit_utc', ''))} UTC'>{zeit}</td><td>{quelle}</td><td>{ziel}</td>"
            f"<td>{ergebnis}<div class='klein' style='margin-top:3px'>{esc(durch or '–')}</div></td></tr>"
            f"<tr class='technik'><td></td><td colspan='4' class='klein mono'>{'<br>'.join(technik)}</td></tr></tbody>")


def sitzungen_laden(fall_id: str) -> tuple[list[dict], list[str]]:
    """Alle Einträge der Sitzungen, die diesen Fall berührt haben, plus Meldungen zur Kettenprüfung."""
    eintraege: list[dict] = []
    meldungen: list[str] = []
    for datei in sorted(SITZUNGEN.glob("*.jsonl")) if SITZUNGEN.is_dir() else []:
        try:
            zeilen = jsonl_lesen(datei)
        except json.JSONDecodeError:
            meldungen.append(f"Sitzungsprotokoll {datei.name} ist beschädigt und wurde ausgelassen.")
            continue
        if not any(z.get("fall") == fall_id for z in zeilen):
            continue
        vorher = hashlib.sha256(f"sitzung|{datei.stem}".encode()).hexdigest()
        for z in zeilen:
            if z.get("vorher") != vorher or kette(z.get("vorher", ""), z) != z.get("kette"):
                meldungen.append(f"Sitzungsprotokoll {datei.name}: Eintrag {z.get('nr')} wurde verändert oder die Kette ist gebrochen.")
                break
            vorher = z.get("kette", "")
        eintraege.extend(zeilen)
    eintraege.sort(key=lambda z: (z.get("zeit_utc") or "", z.get("nr") or 0))
    return eintraege, meldungen


def eingabe_kurz(eingabe: object, n: int = 160) -> str:
    if isinstance(eingabe, dict):
        if "anfang" in eingabe and "sha256" in eingabe:
            return kuerzen(str(eingabe["anfang"]), n)
        for feld in ("command", "file_path", "pattern", "query", "url", "prompt", "description", "skill"):
            if eingabe.get(feld):
                wert = eingabe[feld]
                return kuerzen(str(wert.get("anfang") if isinstance(wert, dict) else wert), n)
        return kuerzen(json.dumps(eingabe, ensure_ascii=False), n)
    return kuerzen(str(eingabe or ""), n)


def bauen(fall_id: str, fall: dict, abfragen: list[dict], sitzung: list[dict], stand: dict,
          sitzungsmeldungen: list[str], akteure: dict[str, dict], extern: list[dict]) -> str:
    h: list[str] = []
    if fall.get("muster"):
        h.append('<div class="banner">MUSTER – fiktiver Fall mit erfundenen Daten. Dient nur zur Veranschaulichung.</div>')
    h.append(f"<h1>Ermittlungsprotokoll</h1><p class='unter'>{esc(fall.get('titel') or fall_id)}</p>")
    erste = lokal(abfragen[0]["zeit_utc"]) if abfragen else "–"
    letzte = lokal(abfragen[-1]["zeit_utc"]) if abfragen else "–"
    h.append('<div class="kopf">'
             f"<div><b>Fall</b>{esc(fall_id)}</div><div><b>Erste Abfrage</b>{esc(erste)}</div>"
             f"<div><b>Letzte Abfrage</b>{esc(letzte)}</div>"
             f"<div><b>Erstellt</b>{esc(erstellt().astimezone(ZONE).strftime('%d.%m.%Y %H:%M'))}</div>"
             f"<div><b>Zeitzone</b>{esc(str(ZONE))}</div></div>")
    if stand["ok"] and not sitzungsmeldungen:
        h.append(f"<p><span class='marke'><span class='punkt' style='background:var(--gut)'></span>✓ Protokoll unverändert</span> "
                 f"{stand['anzahl'] + stand['anzahl_extern']} Einträge, Verkettung und Prüfsummen aller Rohdateien stimmen.</p>")
    else:
        h.append("<div class='banner'>✕ Die Integritätsprüfung hat Abweichungen ergeben:<ul>"
                 + "".join(f"<li>{esc(f)}</li>" for f in stand["fehler"] + sitzungsmeldungen) + "</ul></div>")

    zaehler = Counter(e.get("ergebnis") for e in abfragen)
    cache = sum(1 for e in abfragen if (e.get("antwort") or {}).get("aus_cache"))
    aktiv = sum(1 for e in abfragen if e.get("art") == "aktiv" and e.get("ergebnis") != "abgelehnt")
    h.append("<div class='kacheln'>")
    h.append(kachel(len(abfragen), "Abfragen", f"{cache} davon aus dem Fall-Cache"))
    h.append(kachel(zaehler["ok"], "mit Treffer"))
    h.append(kachel(zaehler["kein_treffer"], "ohne Treffer"))
    h.append(kachel(zaehler["fehler"], "fehlgeschlagen"))
    h.append(kachel(zaehler["abgelehnt"], "abgelehnt", "Freigabe fehlte"))
    h.append(kachel(aktiv, "aktive Massnahmen", "Ziel wurde kontaktiert"))
    h.append("</div>")
    je_quelle = Counter(e.get("quelle") for e in abfragen)
    if je_quelle:
        h.append("<figure>" + balken([{"name": q or "?", "wert": n, "anzeige": str(n)} for q, n in je_quelle.most_common()],
                                     beschriftung="Abfragen je Quelle") +
                 "<figcaption>Abfragen je Quelle, alle Ergebnisse eingeschlossen.</figcaption></figure>")

    # ---- 1 Aufträge
    auftraege = [z for z in sitzung if z.get("ereignis") == "UserPromptSubmit"]
    h.append("<h2>1 Aufträge des Sachbearbeiters</h2>")
    if auftraege:
        h.append("<table><tr><th>Zeit</th><th>Sitzung</th><th>Eingabe</th></tr>")
        for z in auftraege:
            h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td class='mono'>{esc(kuerzen(z.get('sitzung', ''), 12))}</td>"
                     f"<td>{esc(eingabe_kurz(z.get('eingabe'), 600))}</td></tr>")
        h.append("</table>")
    else:
        h.append("<p class='klein'>Kein Sitzungsprotokoll vorhanden. Es entsteht, sobald mit Claude Code im Projekt gearbeitet wird "
                 "(Hook .claude/hooks/protokoll_hook.py).</p>")

    # ---- 2 Abfragen
    h.append("<h2>2 Abfragen bei externen Quellen</h2>"
             "<p class='klein'>Jede Zeile ist eine Abfrage des OSINT-Gateways. «Passiv» heisst: Es wurde die Datenbank eines "
             "Dritten befragt, das Ziel selbst wurde nicht kontaktiert. «Aktiv» heisst: Das Ziel wurde aufgerufen. "
             "Schlüssel und Zugangsdaten sind in den Adressen unkenntlich gemacht.</p>")
    if abfragen:
        h.append("<div class='tabelle-breit'><table class='eintraege'>" + KOPFZEILE)
        for e in abfragen:
            antwort = e.get("antwort") or {}
            anfrage = e.get("anfrage") or {}
            text, farbe = ERGEBNIS.get(e.get("ergebnis"), ("?", "var(--neutral)"))
            akteur = akteure.get(e["id"]) or {}
            technik = [esc(f"{anfrage.get('methode', '')} {anfrage.get('url', '')}")]
            if antwort:
                technik[0] += esc(f" → HTTP {antwort.get('status')}, {groesse(antwort.get('bytes'))}, {antwort.get('dauer_ms')} ms")
            if antwort.get("rohdaten"):
                technik.append(f"Rohdaten: <a href='../{esc(antwort['rohdaten'])}'>{esc(antwort['rohdaten'])}</a>"
                               f" · SHA-256: {esc(antwort.get('sha256') or '')}")
            if antwort.get("aus_cache"):
                technik.append(f"Aus dem Fall-Cache, ursprüngliche Abfrage: <a href='#{esc(antwort['aus_cache'])}'>{esc(antwort['aus_cache'])}</a>")
            if e.get("fehler"):
                technik.append(f"Meldung: {esc(e['fehler'])}")
            art = "aktiv" if e.get("art") == "aktiv" else "passiv"
            marken = f"<span class='marke'>{art}</span>" + (" <span class='marke'>über Proxy</span>" if anfrage.get("proxy") else "")
            h.append(eintrag(e, f"{esc(e.get('quelle', ''))}<br><span class='mono'>{esc(e.get('werkzeug', ''))}</span><br>{marken}",
                             f"<span class='mono'>{esc(e.get('ziel', ''))}</span><br>{esc(e.get('zweck', ''))}",
                             f"<span class='marke'><span class='punkt' style='background:{farbe}'></span>{esc(text)}</span>",
                             akteur.get("agent"), technik))
        h.append("</table></div>")
    else:
        h.append("<p class='klein'>Noch keine Abfragen.</p>")

    # ---- 3 Weitere Werkzeuge
    h.append("<h2>3 Abfragen über weitere Werkzeuge</h2>"
             "<p class='klein'>Aufrufe von MCP-Servern ausserhalb des Gateways, zum Beispiel die Dark-Web-Suche Robin über Tor. "
             "Der Sitzungs-Hook sichert jede Antwort vollständig in der Fallakte und verkettet sie wie die Abfragen des Gateways.</p>")
    if extern:
        h.append("<div class='tabelle-breit'><table class='eintraege'>" + KOPFZEILE.replace("Ziel und Zweck", "Eingabe"))
        for e in extern:
            antwort = e.get("antwort") or {}
            h.append(eintrag(e, f"{esc(e.get('quelle', ''))}<br><span class='mono'>{esc(e.get('werkzeug', ''))}</span>",
                             f"<span class='mono'>{esc(e.get('ziel', ''))}</span>",
                             "<span class='marke'><span class='punkt' style='background:var(--gut)'></span>✓ gesichert</span>",
                             e.get("agent"),
                             [f"Rohdaten: <a href='../{esc(antwort.get('rohdaten', ''))}'>{esc(antwort.get('rohdaten', ''))}</a>"
                              f" · SHA-256: {esc(antwort.get('sha256') or '')}, {groesse(antwort.get('bytes'))}"]))
        h.append("</table></div>")
    else:
        h.append("<p class='klein'>Keine.</p>")

    # ---- 4 Sitzungsverlauf
    uebrige = [z for z in sitzung if z.get("werkzeug") and not z["werkzeug"].startswith("mcp__")
               or z.get("ereignis") in ("SubagentStart", "SubagentStop")]
    h.append("<h2>4 Sitzungsverlauf</h2>"
             "<p class='klein'>Alle übrigen Schritte der beteiligten Sitzungen: gelesene und geschriebene Dateien, "
             "ausgeführte Befehle, Einsatz der Subagenten.</p>")
    if uebrige:
        grenze = 600
        h.append("<div class='tabelle-breit'><table><tr><th>Zeit</th><th>Durch</th><th>Schritt</th><th>Angabe</th></tr>")
        for z in uebrige[:grenze]:
            schritt = z.get("werkzeug") or {"SubagentStart": "Subagent gestartet", "SubagentStop": "Subagent beendet"}.get(z.get("ereignis"), "")
            fehler = " ✕ fehlgeschlagen" if z.get("ereignis") == "PostToolUseFailure" else ""
            h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td>{esc(z.get('agent') or '')}</td>"
                     f"<td class='mono'>{esc(schritt)}{fehler}</td><td class='klein'>{esc(eingabe_kurz(z.get('eingabe')))}</td></tr>")
        h.append("</table></div>")
        if len(uebrige) > grenze:
            h.append(f"<p class='klein'>{len(uebrige) - grenze} weitere Schritte stehen in den Sitzungsprotokollen unter protokoll/sitzungen/.</p>")
    else:
        h.append("<p class='klein'>Kein Sitzungsprotokoll vorhanden.</p>")

    # ---- 5 Integrität
    h.append("<h2>5 Integrität und Aufbewahrung</h2>"
             "<p>Jeder Eintrag des Abfrageprotokolls enthält die Prüfsumme seines Vorgängers. Wird ein Eintrag nachträglich "
             "verändert, entfernt oder eingefügt, stimmt die Kette ab dieser Stelle nicht mehr. Jede Rohdatei ist über ihre "
             "SHA-256-Prüfsumme an ihren Eintrag gebunden.</p>"
             f"<p class='klein'>Letzter Kettenwert: <span class='mono'>{esc(stand.get('letzter_hash') or '–')}</span><br>"
             + (f"Letzter Kettenwert der weiteren Werkzeuge: <span class='mono'>{esc(stand['letzter_hash_extern'])}</span><br>"
                if stand.get("letzter_hash_extern") else "") +
             f"Prüfung wiederholen: <code>python3 tools/audit_pruefen.py {esc(fall_id)}</code></p>"
             "<p class='klein'>Die Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Wer den Stand verbindlich festhalten "
             "will, hinterlegt den letzten Kettenwert ausserhalb dieses Systems, etwa im Journal oder bei einem Zeitstempeldienst.</p>")
    h.append("<div class='fuss'>Erzeugt aus faelle/" + esc(fall_id) + "/protokoll/abfragen.jsonl und den Sitzungsprotokollen. "
             "Maschinenlesbare Fassung: Ermittlungsprotokoll.csv.</div>")
    return seite(f"Ermittlungsprotokoll {fall_id}", "\n".join(h))


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    fall_id = argv[0]
    try:
        fall = fall_daten(fall_id)
        pfad = fall_pfad(fall_id)
        stand = kette_pruefen(fall_id)
    except (ValueError, FileNotFoundError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    abfragen = jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl")
    sitzung, sitzungsmeldungen = sitzungen_laden(fall_id)
    akteure = {z["protokoll_id"]: z for z in sitzung if z.get("protokoll_id") and z.get("fall") == fall_id}

    extern = jsonl_lesen(pfad / "protokoll" / "extern.jsonl")

    ziel = pfad / "rapport"
    ziel.mkdir(exist_ok=True)
    (ziel / "Ermittlungsprotokoll.html").write_text(
        bauen(fall_id, fall, abfragen, sitzung, stand, sitzungsmeldungen, akteure, extern), encoding="utf-8")
    with open(ziel / "Ermittlungsprotokoll.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["nr", "zeit_utc", "zeit_lokal", "quelle", "werkzeug", "art", "freigabe", "ziel", "ziel_typ", "zweck",
                    "methode", "url", "ueber_proxy", "http_status", "ergebnis", "meldung", "bytes", "sha256", "rohdaten",
                    "dauer_ms", "aus_cache", "durch", "sitzung", "kettenwert"])
        for e in abfragen:
            a, q, wer = e.get("antwort") or {}, e.get("anfrage") or {}, akteure.get(e["id"]) or {}
            w.writerow([e["id"], e.get("zeit_utc"), e.get("zeit_lokal"), e.get("quelle"), e.get("werkzeug"), e.get("art"),
                        e.get("freigabe") or "", e.get("ziel"), e.get("ziel_typ"), e.get("zweck"), q.get("methode"), q.get("url"),
                        "ja" if q.get("proxy") else "nein", a.get("status", ""), e.get("ergebnis"), e.get("fehler") or "",
                        a.get("bytes", ""), a.get("sha256") or "", a.get("rohdaten") or "", a.get("dauer_ms", ""),
                        a.get("aus_cache") or "", wer.get("agent") or "", wer.get("sitzung") or "", e.get("kette")])
        for e in extern:
            a = e.get("antwort") or {}
            w.writerow([e["id"], e.get("zeit_utc"), e.get("zeit_lokal"), e.get("quelle"), e.get("werkzeug"), e.get("art"),
                        e.get("freigabe") or "", e.get("ziel"), e.get("ziel_typ"), "", "", "", "", "", e.get("ergebnis"), "",
                        a.get("bytes", ""), a.get("sha256") or "", a.get("rohdaten") or "", "", "", e.get("agent") or "",
                        e.get("sitzung") or "", e.get("kette")])
    print(f"Protokoll erzeugt: faelle/{fall_id}/rapport/Ermittlungsprotokoll.html ({len(abfragen)} Abfragen)")
    print(f"Maschinenlesbar:   faelle/{fall_id}/rapport/Ermittlungsprotokoll.csv")
    if stand["ok"] and not sitzungsmeldungen:
        print("Integrität:        unverändert. " + (f"Letzter Kettenwert {stand['letzter_hash']}" if stand["letzter_hash"]
                                                    else "Noch keine Abfragen im Protokoll."))
        return 0
    print("Integrität:        ABWEICHUNGEN, siehe Kopf des Protokolls.")
    for m in stand["fehler"] + sitzungsmeldungen:
        print(f"  - {m}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
