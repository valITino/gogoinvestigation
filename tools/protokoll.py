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
                                                Sachbearbeiters, Agenten, übrige Werkzeugaufrufe,
                                                und was verlangt, aber nicht ausgeführt wurde
Rückgabewert 0: erzeugt, Kette unverändert. 1: erzeugt, aber Abweichungen in der Kette. 2: Fall fehlt.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform, robin  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import SITZUNGEN, fall_daten, fall_pfad, ist_abfrage, jsonl_lesen, kette, kette_pruefen  # noqa: E402
from tools._html import balken, csv_sicher, esc, kachel, kuerzen, seite  # noqa: E402

try:
    ZONE = plattform.zeitzone()
except plattform.Zeitzonenfehler as e:
    sys.exit(f"FEHLER: {e}")


def erstellt() -> datetime:
    """Erstellzeit des Dokuments. Für den Musterfall gestellt, damit er bei jedem Lauf gleich ausfällt."""
    if os.environ.get("OSINT_TESTZEIT"):
        return datetime.strptime(os.environ["OSINT_TESTZEIT"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)
ERGEBNIS = {"ok": ("✓ Treffer", "var(--gut)"), "kein_treffer": ("○ kein Treffer", "var(--neutral)"),
            "fehler": ("✕ Fehler", "var(--kritisch)"), "abgelehnt": ("⊘ abgelehnt", "var(--warnung)"),
            "nicht_ausgefuehrt": ("⊘ nicht ausgeführt", "var(--warnung)")}
# Ereignisse des Sitzungsprotokolls vor der Ausführung: was verlangt wurde, und ob Claude Code dafür nachfragte
VORAB = ("PreToolUse", "PermissionRequest")
ENDE = ("PostToolUse", "PostToolUseFailure")
_ERZEUGER = re.compile(r"tools[/\\]+protokoll\.py")


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


def sitzungen_laden(fall_id: str, nur: set[str] | None = None) -> tuple[list[dict], list[str]]:
    """Alle Einträge der Sitzungen, die diesen Fall berührt haben, plus Meldungen zur Kettenprüfung.
    ``nur``: Es zählen allein diese Sitzungen. Das braucht der Musterfall: Er soll bei jedem Bau gleich ausfallen,
    auch wenn auf dem Rechner eine andere Sitzung seinen Ordner berührt hat (etwa beim Weiterbauen des Projekts)."""
    eintraege: list[dict] = []
    meldungen: list[str] = []
    for datei in sorted(SITZUNGEN.glob("*.jsonl")) if SITZUNGEN.is_dir() else []:
        if nur is not None and datei.stem not in nur:
            continue
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


def mcp_eingabe(eingabe: object, n: int = 260) -> str:
    """Die Angaben eines MCP-Aufrufs in einer Zeile: zuerst wonach gefragt wurde, am Schluss der Zweck."""
    if not isinstance(eingabe, dict):
        return kuerzen(str(eingabe or ""), n)
    def wert(v: object) -> str:
        if isinstance(v, dict) and "anfang" in v and "sha256" in v:
            return str(v["anfang"]) + " …"
        return ", ".join(map(str, v)) if isinstance(v, list) else str(v)
    teile = [f"{k}: {wert(v)}" for k, v in eingabe.items() if k not in ("fall", "zweck") and v not in (None, "", [], {})]
    if eingabe.get("zweck"):
        teile.append(f"Zweck: {wert(eingabe['zweck'])}")
    return kuerzen(" · ".join(teile), n)


def nicht_ausgefuehrt(sitzung: list[dict]) -> list[dict]:
    """Was verlangt, aber nicht ausgeführt wurde, aus den Sitzungsprotokollen. Je Versuch ein Eintrag mit zeit_utc, agent, werkzeug,
    eingabe, art und grund. Drei Arten:

        gateway     Das Gateway hat den Aufruf zurückgewiesen, ohne etwas abzufragen (Quelle ausgeschaltet, Schlüssel fehlt, Angabe
                    ungültig, Zweck fehlt). Solche Aufrufe bekommen keine Nummer im Abfrageprotokoll.
        rueckfrage  Claude Code hat für den Aufruf nachgefragt, danach wurde er nicht ausgeführt: abgelehnt oder nicht beantwortet.
        verboten    Der Aufruf wurde ohne Rückfrage nicht ausgeführt: Eine Berechtigung verbot ihn, oder er brach vorher ab.

    Claude Code meldet einen abgelehnten Aufruf nicht eigens (gesehen am 20.11.2026 mit Claude Code 2.1.329). Erkennbar ist er
    daran, dass zu einem angekündigten Aufruf kein Abschluss folgt. Das trifft auch auf einen Aufruf zu, der beim Erzeugen dieses
    Protokolls noch läuft. Sicher nicht mehr läuft er, wenn sein Agent danach einen Schritt abgeschlossen hat oder geendet hat
    (Ende der Antwort bei der Hauptsitzung, Ende des Subagenten). Sonst steht er am offenen Ende seiner Sitzung, und der Eintrag
    sagt das (``am_ende``). Die Sitzung, die dieses Protokoll gerade selbst erzeugt, läuft mit Sicherheit noch: Ihre offenen
    Aufrufe am Ende sind keine Versuche."""
    je: dict[str, list[dict]] = {}
    for z in sitzung:
        je.setdefault(str(z.get("sitzung") or ""), []).append(z)
    aus: list[dict] = []
    for zeilen in je.values():
        zeilen = sorted(zeilen, key=lambda z: z.get("nr") or 0)
        wer = lambda z: str(z.get("agent_id") or "")                          # noqa: E731
        gleich = lambda a, b: (a.get("werkzeug") == b.get("werkzeug") and a.get("eingabe") == b.get("eingabe") and wer(a) == wer(b))  # noqa: E731
        fertig = {z["tool_use_id"] for z in zeilen if z.get("ereignis") in ENDE and z.get("tool_use_id")}
        letzter: dict[str, int] = {}
        beendet: dict[str, int] = {}
        for i, z in enumerate(zeilen):
            if z.get("ereignis") in ENDE:
                letzter[wer(z)] = i
            elif z.get("ereignis") in ("SubagentStop", "Stop"):     # der Subagent ist fertig, oder die Hauptsitzung hat ihre Antwort beendet
                beendet[wer(z)] = i
        offen = [(i, z) for i, z in enumerate(zeilen)
                 if z.get("ereignis") == "PreToolUse" and z.get("tool_use_id") and z["tool_use_id"] not in fertig]
        am_ende = {i for i, z in offen if i > letzter.get(wer(z), -1) and beendet.get(wer(z), -1) < i}
        erzeugt_gerade = any(i in am_ende and z.get("werkzeug") == "Bash" and _ERZEUGER.search(eingabe_kurz(z.get("eingabe"), 2000)) for i, z in offen)
        for i, z in offen:
            if i in am_ende and erzeugt_gerade:
                continue
            gefragt = any(r.get("ereignis") == "PermissionRequest" and gleich(r, z)
                          and not any(v.get("ereignis") == "PreToolUse" and gleich(v, z) for v in zeilen[i + 1:j])
                          for j, r in enumerate(zeilen) if j > i)
            grund = ("Claude Code hat für diesen Aufruf nachgefragt. Er wurde danach nicht ausgeführt: abgelehnt oder nicht beantwortet."
                     if gefragt else
                     "Ohne Rückfrage nicht ausgeführt: Eine Berechtigung des Projekts verbietet den Aufruf, oder er brach vor der Ausführung ab.")
            if i in am_ende:
                grund += " Letzter Schritt dieser Sitzung: Lief der Aufruf noch, als dieses Protokoll entstand, steht sein Ergebnis im nächsten Protokoll."
            aus.append({**z, "art": "rueckfrage" if gefragt else "verboten", "grund": grund, "am_ende": i in am_ende})
        for z in zeilen:
            if (z.get("ereignis") == "PostToolUse" and str(z.get("werkzeug") or "").startswith("mcp__osint__") and not z.get("protokoll_id")
                    and z.get("ergebnis") == "nicht_ausgefuehrt"):
                aus.append({**z, "art": "gateway", "grund": z.get("meldung") or "Das Gateway hat den Aufruf nicht ausgeführt.", "am_ende": False})
    aus.sort(key=lambda z: (z.get("zeit_utc") or "", str(z.get("sitzung") or ""), z.get("nr") or 0))
    return aus


def extern_stand(e: dict, pfad: Path | None = None) -> dict:
    """Was ein Eintrag der weiteren Werkzeuge belegt: {"ergebnis", "text", "farbe", "meldung", "angaben"}.

    Robin antwortet auch dann, wenn es nichts getan hat (Tor noch nicht bereit, Untersuchungsbereich nicht angegeben). Der Eintrag
    sagt seit dem 20.11.2026 selbst, was die Antwort bedeutet. Bei älteren Einträgen wird die gesicherte Antwort gelesen: Dort
    stand bei jedem Aufruf «ok». ``text`` ist leer, wenn sich nichts sagen lässt ausser «gesichert»."""
    name = str(e.get("werkzeug") or "")
    if ((e.get("anfrage") or {}).get("server") or "") != robin.SERVER:
        return {"ergebnis": e.get("ergebnis") or "ok", "text": "", "farbe": "var(--gut)", "meldung": e.get("fehler") or "", "angaben": []}
    stand = {**(e.get("robin") or {}), "ergebnis": e.get("ergebnis"), "fehler": e.get("fehler")} if "robin" in e else None
    if stand is None and pfad is not None:
        roh = (e.get("antwort") or {}).get("rohdaten") or ""
        try:
            inhalt = (pfad / roh).read_text(encoding="utf-8", errors="replace") if roh else ""
        except OSError:
            inhalt = ""
        if inhalt:
            try:
                inhalt = robin.text_aus(json.loads(inhalt)) if roh.endswith(".json") else inhalt
            except ValueError:
                pass
            stand = robin.einordnen(robin.PRAEFIX + name, inhalt)
    if stand is None:
        return {"ergebnis": e.get("ergebnis") or "ok", "text": "", "farbe": "var(--gut)", "meldung": "", "angaben": []}
    ergebnis = stand.get("ergebnis") or "ok"
    text, farbe = ERGEBNIS.get(ergebnis, ("?", "var(--neutral)"))
    if ergebnis == "ok":
        if name == "robin_search":
            text = f"✓ {stand['treffer']} Treffer" if isinstance(stand.get("treffer"), int) else "✓ Treffer"
        elif name == "robin_scrape":
            text = (f"✓ {stand['seiten_gelesen']} von {stand['seiten_verlangt']} Seiten gelesen" if isinstance(stand.get("seiten_gelesen"), int)
                    else "✓ gelesen")
        elif name == "robin_health" and "tor" in stand:
            text, farbe = ("✓ Tor bereit", "var(--gut)") if stand["tor"] else ("⊘ Tor nicht bereit", "var(--warnung)")
        else:
            text = "✓ ausgeführt"
    eingabe = (e.get("anfrage") or {}).get("eingabe")
    aussen = name in robin.NACH_AUSSEN or (name == "robin_health" and isinstance(eingabe, dict) and bool(eingabe.get("check_engines")))
    angaben = ["Über Tor nach aussen" if aussen and ergebnis != "nicht_ausgefuehrt" else
               "Über Tor verlangt, es ging nichts hinaus" if aussen else "Im Container von Robin, ohne Abfrage nach aussen"]
    if stand.get("maschinen"):
        angaben.append(f"Suchmaschinen, die geantwortet haben: {stand['maschinen']}")
    return {"ergebnis": ergebnis, "text": text, "farbe": farbe, "meldung": stand.get("fehler") or stand.get("hinweis") or "", "angaben": angaben}


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


def kennzahlen(abfragen: list[dict], extern: list[dict] | None = None) -> dict:
    """Die Zahlen im Kopf des Ermittlungsprotokolls. Auch die Oberfläche nimmt sie von hier.
    ``extern``: die Einträge der weiteren Werkzeuge (Robin, von Hand Erfasstes). Sie zählen mit, wie im Abschlussrapport. Nicht
    dazu gehört, was Robin im Container erledigt, ohne nach aussen zu gehen, und was Robin nicht ausgeführt hat (akte.ist_abfrage):
    Das steht unter ``ohne_ausfuehrung``. So ergeben Treffer, kein Treffer, Fehlschlag und abgelehnt zusammen die Zahl der Abfragen."""
    auswertungen = [e for e in abfragen if e.get("art") == "auswertung"]
    alle = list(abfragen) + list(extern or [])
    echte = [e for e in alle if ist_abfrage(e)]                                                       # Abfragen bei Quellen
    return {"auswertungen": auswertungen, "echte": echte,
            "ohne_ausfuehrung": [e for e in alle if e.get("ergebnis") == "nicht_ausgefuehrt"],        # mit Beleg, aber es ging nichts hinaus
            "teil_von": {pid: e["id"] for e in auswertungen for pid in e.get("grundlage") or []},
            "ergebnis": Counter(e.get("ergebnis") for e in echte),
            "cache": sum(1 for e in echte if (e.get("antwort") or {}).get("aus_cache")),
            "aktiv": sum(1 for e in echte if e.get("art") == "aktiv" and e.get("ergebnis") != "abgelehnt"),
            "je_quelle": Counter(e.get("quelle") for e in echte)}


def akteure_aus(sitzung: list[dict], abfragen: list[dict], fall_id: str) -> dict[str, dict]:
    """Wer welche Abfrage ausgelöst hat: Nummer im Protokoll → Eintrag des Sitzungsprotokolls. Auch die Oberfläche nimmt es von hier."""
    akteure = {z["protokoll_id"]: z for z in sitzung if z.get("protokoll_id") and z.get("fall") == fall_id}
    for z in sitzung:           # ein gebündeltes Werkzeug, das scheiterte: Es gibt keine Auswertung, nur die Nummern der Abfragen dahinter
        if z.get("fall") == fall_id:
            for pid in z.get("belege") or []:
                akteure.setdefault(pid, z)
    for e in abfragen:          # die Abfragen hinter einer Auswertung hat derselbe Agent ausgelöst wie die Auswertung
        if e.get("art") == "auswertung" and e["id"] in akteure:
            for pid in e.get("grundlage") or []:
                akteure.setdefault(pid, akteure[e["id"]])
    return akteure


def bauen(fall_id: str, fall: dict, abfragen: list[dict], sitzung: list[dict], stand: dict,
          sitzungsmeldungen: list[str], akteure: dict[str, dict], extern: list[dict], pfad: Path | None = None) -> str:
    """``pfad``: der Ordner der Fallakte. Von dort kommen die Rohdateien, aus denen sich lesen lässt, was eine Prüfung gegen die
    Sperrliste ergab und was ein älterer Eintrag von Robin belegt."""
    h: list[str] = []
    versuche = nicht_ausgefuehrt([z for z in sitzung if z.get("fall") == fall_id])
    staende = {e["id"]: extern_stand(e, pfad) for e in extern if e.get("art") != "von_hand"}
    if fall.get("muster"):
        h.append('<div class="banner">MUSTER – fiktiver Fall mit erfundenen Daten. Dient nur zur Veranschaulichung.</div>')
    h.append(f"<h1>Ermittlungsprotokoll</h1><p class='unter'>{esc(fall.get('titel') or fall_id)}</p>")
    # Erste und letzte Abfrage: Robins Suchen und gelesene Seiten zählen dazu. Bis zum 20.11.2026 standen hier nur die Zeiten des Gateways
    zeiten = sorted(str(e["zeit_utc"]) for e in list(abfragen) + [x for x in extern if ist_abfrage(x)] if e.get("zeit_utc"))
    erste = lokal(zeiten[0]) if zeiten else "–"
    letzte = lokal(zeiten[-1]) if zeiten else "–"
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

    k = kennzahlen(abfragen, extern)
    auswertungen, echte, teil_von, zaehler, cache, aktiv = k["auswertungen"], k["echte"], k["teil_von"], k["ergebnis"], k["cache"], k["aktiv"]
    ohne_ausfuehrung = len(k["ohne_ausfuehrung"]) + len(versuche)       # mit Beleg (Abschnitt 3) und ohne (Abschnitt 4)
    h.append("<div class='kacheln'>")
    h.append(kachel(len(echte), "Abfragen", f"{cache} davon aus dem Fall-Cache"))
    h.append(kachel(zaehler["ok"], "mit Treffer"))
    h.append(kachel(zaehler["kein_treffer"], "ohne Treffer"))
    h.append(kachel(zaehler["fehler"], "fehlgeschlagen"))
    h.append(kachel(zaehler["abgelehnt"], "abgelehnt", "Freigabe fehlte"))
    if ohne_ausfuehrung:
        h.append(kachel(ohne_ausfuehrung, "nicht ausgeführt", "verlangt, es ging nichts hinaus"))
    h.append(kachel(aktiv, "aktive Massnahmen", "Ziel wurde kontaktiert"))
    if auswertungen:
        h.append(kachel(len(auswertungen), "Auswertungen", "aus mehreren Abfragen errechnet"))
    h.append("</div>")
    if ohne_ausfuehrung:        # damit die Zahlen aufgehen: Was nicht ausgeführt wurde, steht neben den Abfragen, nicht darin
        mit, ohne = len(k["ohne_ausfuehrung"]), len(versuche)
        wo = (f"{mit} mit Beleg in Abschnitt 3, {ohne} ohne Nummer in Abschnitt 4" if mit and ohne else
              "Es steht mit Beleg in Abschnitt 3" if mit else "Es steht ohne Nummer in Abschnitt 4")
        h.append("<p class='klein'>Treffer, ohne Treffer, fehlgeschlagen und abgelehnt ergeben zusammen die Zahl der Abfragen. "
                 f"Was nicht ausgeführt wurde, zählt nicht dazu: {wo}.</p>")
    je_quelle = k["je_quelle"]
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
             "Schlüssel und Zugangsdaten sind in den Adressen unkenntlich gemacht."
             + (" «Auswertung» heisst: Das Gateway hat aus mehreren Abfragen ein Ergebnis errechnet, zum Beispiel einen Geldfluss. "
                "Der Eintrag nennt die Abfragen, auf denen es beruht, und das Ergebnis liegt wie eine Rohantwort in der Fallakte."
                if auswertungen else "") + "</p>")
    if abfragen:
        h.append("<div class='tabelle-breit'><table class='eintraege'>" + KOPFZEILE)
        for e in abfragen:
            antwort = e.get("antwort") or {}
            anfrage = e.get("anfrage") or {}
            text, farbe = ERGEBNIS.get(e.get("ergebnis"), ("?", "var(--neutral)"))
            if e.get("werkzeug") == "onion_sperrliste" and e.get("ergebnis") == "ok" and pfad is not None:
                # «Treffer» hiesse hier das Gegenteil: Die Liste wurde geladen. Ob die Adresse darauf steht, sagt die gesicherte Liste.
                urteil = robin.sperrliste_urteil(pfad, e)
                text, farbe = {"frei": ("✓ nicht auf der Sperrliste", "var(--gut)"),
                               "gesperrt": ("⊘ auf der Sperrliste", "var(--kritisch)")}.get(urteil, ("✓ Liste geladen", "var(--gut)"))
            akteur = akteure.get(e["id"]) or {}
            if e.get("art") == "auswertung":
                grundlage = e.get("grundlage") or []
                verweise = " ".join(f"<a href='#{esc(p_)}'>{esc(p_)}</a>" for p_ in grundlage[:60])
                technik = [f"Auswertung des Gateways, {groesse(antwort.get('bytes'))}, {antwort.get('dauer_ms')} ms"
                           + (f". Tatsachen aus: {esc(', '.join(e.get('quellen') or []))}" if e.get("quellen") else ""),
                           (f"Beruht auf {len(grundlage)} Abfrage(n): {verweise}" + (f" und {len(grundlage) - 60} weiteren" if len(grundlage) > 60 else ""))
                           if grundlage else "Ohne Abfrage nach aussen"]
            elif e.get("art") == "lokal":
                liste = antwort.get("stand") or {}       # nicht «stand»: So heisst der Stand der Protokollkette, den Abschnitt 6 braucht
                technik = [esc(f"Lokale Liste, keine Anfrage nach aussen. Stand {liste.get('stand', '?')} vom {liste.get('datum', '?')}, "
                               f"{liste.get('eintraege', '?')} Einträge ({liste.get('umfang', '?')}), SHA-256 der Liste: {antwort.get('sha256') or '?'}")]
                if e["id"] in teil_von:
                    technik.append(f"Teil der Auswertung <a href='#{esc(teil_von[e['id']])}'>{esc(teil_von[e['id']])}</a>")
            else:
                technik = [esc(f"{anfrage.get('methode', '')} {anfrage.get('url', '')}")]
                if antwort:
                    technik[0] += esc(f" → HTTP {antwort.get('status')}, {groesse(antwort.get('bytes'))}, {antwort.get('dauer_ms')} ms")
                if e["id"] in teil_von:
                    technik.append(f"Teil der Auswertung <a href='#{esc(teil_von[e['id']])}'>{esc(teil_von[e['id']])}</a>")
            if antwort.get("rohdaten"):
                technik.append(f"Rohdaten: <a href='../{esc(antwort['rohdaten'])}'>{esc(antwort['rohdaten'])}</a>"
                               f" · SHA-256: {esc(antwort.get('sha256') or '')}")
            if antwort.get("aus_cache"):
                technik.append(f"Aus dem Fall-Cache, ursprüngliche Abfrage: <a href='#{esc(antwort['aus_cache'])}'>{esc(antwort['aus_cache'])}</a>")
            if e.get("fehler"):
                technik.append(f"Meldung: {esc(e['fehler'])}")
            art = {"aktiv": "aktiv", "auswertung": "Auswertung", "lokal": "lokale Liste"}.get(e.get("art"), "passiv")
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
             "Der Sitzungs-Hook sichert jede Antwort vollständig in der Fallakte und verkettet sie wie die Abfragen des Gateways. "
             "Bei Robin steht dabei, was die Antwort belegt: Robin antwortet auch dann, wenn es nichts gesucht oder gelesen hat, "
             "etwa weil Tor noch nicht bereit war. Ein solcher Eintrag heisst «nicht ausgeführt» und belegt keine Suche. Zu jeder "
             "gelesenen Seite steht, ob ihre Adresse vorher gegen die Sperrliste geprüft war. Lief ein Aufruf, ohne die Regeln des "
             "Falls einzuhalten (Freigabe, Untersuchungsbereich, Prüfung gegen die Sperrliste), trägt er die Marke «Regel verletzt». "
             "Hier stehen auch Abklärungen, die der Sachbearbeiter von Hand gemacht und mit tools/beleg.py erfasst hat. Sie sind als "
             "«von Hand erfasst» gekennzeichnet: Ihr Inhalt stammt nicht aus einer protokollierten Abfrage.</p>")
    if extern:
        h.append("<div class='tabelle-breit'><table class='eintraege'>" + KOPFZEILE.replace("Ziel und Zweck", "Eingabe"))
        for e in extern:
            antwort = e.get("antwort") or {}
            hand = e.get("art") == "von_hand"
            anfrage = e.get("anfrage") or {}
            s = staende.get(e["id"]) or {}
            technik = [esc(zeile) for zeile in s.get("angaben") or []]
            if s.get("meldung"):
                technik.append(f"{'Meldung' if s.get('ergebnis') in ('fehler', 'nicht_ausgefuehrt') else 'Hinweis'}: {esc(s['meldung'])}")
            if e.get("regel"):      # der Aufruf lief (am Terminal vom Sachbearbeiter zugelassen), hielt aber die Regeln des Falls nicht ein
                technik.append(f"<b>Nicht nach den Regeln für Robin:</b> {esc(e['regel'])}")
            for seite_ in e.get("seiten") or []:        # je Seite, die robin_scrape gelesen oder versucht hat
                gelesen = {"ok": "gelesen", "blocked": "von der Seite abgewiesen", "error": "nicht lesbar",
                           "refused_not_onion": "abgelehnt, keine Onion-Adresse"}.get(seite_.get("stand"), str(seite_.get("stand") or "?"))
                beleg = seite_.get("sperrliste_beleg")
                technik.append(f"Seite {esc(seite_.get('adresse', ''))}: {esc(gelesen)}"
                               + (f" (HTTP {esc(str(seite_['http']))})" if seite_.get("http") else "")
                               + f" · Sperrliste: {esc(seite_.get('sperrliste') or '?')}"
                               + (f" (<a href='#{esc(beleg)}'>{esc(beleg)}</a>)" if beleg else ""))
            technik.append(f"Rohdaten: <a href='../{esc(antwort.get('rohdaten', ''))}'>{esc(antwort.get('rohdaten', ''))}</a>"
                           f" · SHA-256: {esc(antwort.get('sha256') or '')}, {groesse(antwort.get('bytes'))}")
            if hand:
                marke = "<span class='marke'><span class='punkt' style='background:var(--warnung)'></span>✎ von Hand</span>"
            elif s.get("text"):
                marke = f"<span class='marke'><span class='punkt' style='background:{s['farbe']}'></span>{esc(s['text'])}</span>"
            else:
                marke = "<span class='marke'><span class='punkt' style='background:var(--gut)'></span>✓ gesichert</span>"
            h.append(eintrag(e, f"{esc(e.get('quelle', ''))}<br><span class='mono'>{esc(e.get('werkzeug', ''))}</span>"
                             + ("<br><span class='marke'>von Hand erfasst</span>" if hand else "")
                             + ("<br><span class='marke'><span class='punkt' style='background:var(--kritisch)'></span>Regel verletzt</span>" if e.get("regel") else ""),
                             f"<span class='mono'>{esc(e.get('ziel', ''))}</span>"
                             + (f"<br>Abgeklärt am {esc(lokal(anfrage.get('abgeklaert_am')))}, erfasst durch {esc(str(anfrage.get('erfasst_durch') or '?'))}" if hand else ""),
                             marke, (anfrage.get("erfasst_durch") if hand else None) or e.get("agent"), technik))
        h.append("</table></div>")
    else:
        h.append("<p class='klein'>Keine.</p>")

    # ---- 4 Nicht ausgeführt
    h.append("<h2>4 Aufrufe, die nicht ausgeführt wurden</h2>"
             "<p class='klein'>Was verlangt, aber nicht ausgeführt wurde. Das Gateway weist einen Aufruf zurück, wenn die Quelle "
             "ausgeschaltet ist, ihr Schlüssel fehlt, eine Angabe ungültig ist oder der Zweck fehlt: Dann geht nichts hinaus, und "
             "der Aufruf bekommt keine Nummer. Andere Aufrufe verbietet eine Berechtigung des Projekts, oder der Sachbearbeiter lehnt "
             "die Rückfrage ab. Abfragen, die das Gateway wegen fehlender Freigabe ablehnte, stehen mit Nummer in Abschnitt 2, "
             "Aufrufe von Robin, die nichts ausführten, in Abschnitt 3.</p>")
    if versuche:
        grenze = 400
        h.append("<div class='tabelle-breit'><table><tr><th style='width:13%'>Zeit</th><th style='width:15%'>Durch</th>"
                 "<th style='width:34%'>Verlangt</th><th>Weshalb nicht ausgeführt</th></tr>")
        for z in versuche[:grenze]:
            werkzeug = str(z.get("werkzeug") or "")
            angabe = mcp_eingabe(z.get("eingabe")) if werkzeug.startswith("mcp__") else eingabe_kurz(z.get("eingabe"), 260)
            h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td>{esc(z.get('agent') or '')}</td>"
                     f"<td><span class='mono'>{esc(werkzeug)}</span><br><span class='klein'>{esc(angabe or 'ohne Angaben')}</span></td>"
                     f"<td class='klein'>{esc(z.get('grund') or '')}</td></tr>")
        h.append("</table></div>")
        if len(versuche) > grenze:
            h.append(f"<p class='klein'>{len(versuche) - grenze} weitere stehen in den Sitzungsprotokollen unter protokoll/sitzungen/.</p>")
    elif any(z.get("ereignis") in VORAB for z in sitzung):
        h.append("<p class='klein'>Keine.</p>")
    else:
        h.append("<p class='klein'>Keine erfasst. Das Sitzungsprotokoll hält erst seit dem 20.11.2026 fest, was verlangt wurde, bevor es "
                 "ausgeführt wird. In älteren Sitzungen hinterliess ein abgelehnter Aufruf keine Spur.</p>" if sitzung else
                 "<p class='klein'>Kein Sitzungsprotokoll vorhanden.</p>")

    # ---- 5 Sitzungsverlauf
    in_abschnitt_4 = {(z.get("sitzung"), z.get("nr")) for z in versuche}
    ereignisse = ("SubagentStart", "SubagentStop", "PostModelSwitch", "Oberflaeche", "Elicitation", "ElicitationResult")

    def im_verlauf(z: dict) -> bool:
        """Alles, was nicht schon weiter oben steht. Aufrufe über MCP mit Nummer stehen in Abschnitt 2 oder 3. Ohne Nummer gehören sie
        hierher: die Auskunft fall_status, Arbeitsmittel wie andere MCP-Server, und Aufrufe, die scheiterten, bevor sie eine bekamen."""
        if z.get("ereignis") in ereignisse:
            return True
        if z.get("ereignis") in VORAB or not z.get("werkzeug") or (z.get("sitzung"), z.get("nr")) in in_abschnitt_4:
            return False
        return not (z["werkzeug"].startswith("mcp__") and z.get("protokoll_id"))
    uebrige = [z for z in sitzung if im_verlauf(z)]
    h.append("<h2>5 Sitzungsverlauf</h2>"
             "<p class='klein'>Alle übrigen Schritte der beteiligten Sitzungen: gelesene und geschriebene Dateien, "
             "ausgeführte Befehle, Einsatz der Subagenten, Auskünfte des Gateways ohne Abfrage (fall_status) und Rückfragen, "
             "die ein MCP-Server dem Sachbearbeiter selbst stellt.</p>")
    eingesetzt: dict[str, set[str]] = {}
    for z in sitzung:
        if z.get("modell"):
            eingesetzt.setdefault(z.get("agent") or "hauptsitzung", set()).add(z["modell"])
    if eingesetzt:      # welches Sprachmodell welchen Teil der Arbeit gemacht hat, laut den Transkripten von Claude Code
        h.append("<p class='klein'><b>Eingesetzte Sprachmodelle:</b> "
                 + " · ".join(f"{esc(agent)}: <span class='mono'>{esc(', '.join(sorted(modelle)))}</span>"
                              for agent, modelle in sorted(eingesetzt.items())) + "</p>")
    if uebrige:
        grenze = 600
        h.append("<div class='tabelle-breit'><table><tr><th>Zeit</th><th>Durch</th><th>Schritt</th><th>Angabe</th></tr>")
        for z in uebrige[:grenze]:
            schritt = z.get("werkzeug") or {"SubagentStart": "Subagent gestartet", "SubagentStop": "Subagent beendet",
                                            "PostModelSwitch": "Modell der Sitzung gewechselt",
                                            "Oberflaeche": f"Oberfläche: {z.get('schritt') or ''}",
                                            "Elicitation": f"Rückfrage von {z.get('server') or 'einem MCP-Server'} an den Sachbearbeiter",
                                            "ElicitationResult": f"Antwort auf die Rückfrage von {z.get('server') or 'einem MCP-Server'}",
                                            }.get(z.get("ereignis"), "")
            if z.get("ereignis") == "Oberflaeche":      # Entscheide des Sachbearbeiters, die über die Oberfläche kamen
                h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td>{esc(z.get('agent') or '')}</td>"
                         f"<td class='mono'>{esc(schritt)}</td><td class='klein'>{esc(eingabe_kurz(z.get('angabe'), 300))} "
                         "<span class='marke'>über die Oberfläche</span></td></tr>")
                continue
            if z.get("ereignis") in ("Elicitation", "ElicitationResult"):
                entscheid = {"accept": "beantwortet", "decline": "abgelehnt", "cancel": "abgebrochen, nicht beantwortet"}.get(z.get("entscheid"), str(z.get("entscheid") or ""))
                angabe = eingabe_kurz(z.get("frage"), 300) if z.get("ereignis") == "Elicitation" else \
                    entscheid + (f": {eingabe_kurz(z.get('angabe'), 200)}" if z.get("angabe") else "")
                h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td>{esc(z.get('agent') or '')}</td>"
                         f"<td>{esc(schritt)}</td><td class='klein'>{esc(angabe)}</td></tr>")
                continue
            fehler = (" ✕ abgebrochen" if z.get("abgebrochen") else " ✕ fehlgeschlagen") if z.get("ereignis") == "PostToolUseFailure" else ""
            mcp = str(z.get("werkzeug") or "").startswith("mcp__")
            angabe = mcp_eingabe(z.get("eingabe"), 200) if mcp else eingabe_kurz(z.get("eingabe"))
            if z.get("werkzeug") == "mcp__osint__fall_status":
                angabe = "Stand des Falls abgefragt. Keine Abfrage nach aussen."
            if mcp and z.get("ergebnis"):       # das Gateway hat ohne Nummer geantwortet, etwa nach einem Fehler in einem gebündelten Werkzeug
                angabe += f" → {ERGEBNIS.get(z['ergebnis'], (z['ergebnis'],))[0]}" + (f": {kuerzen(str(z.get('meldung') or ''), 200)}" if z.get("meldung") else "")
            elif z.get("ereignis") == "PostToolUseFailure" and z.get("fehler"):
                angabe += f" → {eingabe_kurz(z.get('fehler'), 200)}"
            h.append(f"<tr><td>{esc(lokal(z.get('zeit_utc')))}</td><td>{esc(z.get('agent') or '')}</td>"
                     f"<td class='mono'>{esc(schritt)}{fehler}</td><td class='klein'>{esc(angabe)}"
                     + (f"Modell {esc(z['modell'])}" if z.get("modell") and z.get("ereignis") == "SubagentStop" else "")
                     + (f"von {esc(z.get('modell_vorher') or '?')} auf {esc(z.get('modell') or '?')}"
                        if z.get("ereignis") == "PostModelSwitch" else "") + "</td></tr>")
        h.append("</table></div>")
        if len(uebrige) > grenze:
            h.append(f"<p class='klein'>{len(uebrige) - grenze} weitere Schritte stehen in den Sitzungsprotokollen unter protokoll/sitzungen/.</p>")
    else:
        h.append("<p class='klein'>Kein Sitzungsprotokoll vorhanden.</p>")

    # ---- 6 Integrität
    h.append("<h2>6 Integrität und Aufbewahrung</h2>"
             "<p>Jeder Eintrag des Abfrageprotokolls enthält die Prüfsumme seines Vorgängers. Wird ein Eintrag nachträglich "
             "verändert, entfernt oder eingefügt, stimmt die Kette ab dieser Stelle nicht mehr. Jede Rohdatei ist über ihre "
             "SHA-256-Prüfsumme an ihren Eintrag gebunden. Die Sitzungsprotokolle, aus denen die Abschnitte 1, 4 und 5 stammen, "
             "sind auf dieselbe Weise verkettet.</p>"
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
    # Der Musterfall nennt in fall.json die eine Sitzung, aus der er besteht. Echte Fälle haben den Eintrag nicht:
    # Bei ihnen zählt jede Sitzung, die den Fall berührt hat.
    sitzung, sitzungsmeldungen = sitzungen_laden(fall_id, set(fall["sitzungen"]) if fall.get("muster") and fall.get("sitzungen") else None)
    akteure = akteure_aus(sitzung, abfragen, fall_id)
    extern = jsonl_lesen(pfad / "protokoll" / "extern.jsonl")

    ziel = pfad / "rapport"
    ziel.mkdir(exist_ok=True)
    plattform.text_schreiben(ziel / "Ermittlungsprotokoll.html",
                             bauen(fall_id, fall, abfragen, sitzung, stand, sitzungsmeldungen, akteure, extern, pfad))
    with open(ziel / "Ermittlungsprotokoll.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["nr", "zeit_utc", "zeit_lokal", "quelle", "werkzeug", "art", "freigabe", "ziel", "ziel_typ", "zweck",
                    "methode", "url", "ueber_proxy", "http_status", "ergebnis", "meldung", "bytes", "sha256", "rohdaten",
                    "dauer_ms", "aus_cache", "durch", "sitzung", "kettenwert", "grundlage"])
        for e in abfragen:
            a, q, wer = e.get("antwort") or {}, e.get("anfrage") or {}, akteure.get(e["id"]) or {}
            w.writerow(csv_sicher([
                e["id"], e.get("zeit_utc"), e.get("zeit_lokal"), e.get("quelle"), e.get("werkzeug"), e.get("art"),
                e.get("freigabe") or "", e.get("ziel"), e.get("ziel_typ"), e.get("zweck"), q.get("methode"), q.get("url"),
                "ja" if q.get("proxy") else "nein", a.get("status", ""), e.get("ergebnis"), e.get("fehler") or "",
                a.get("bytes", ""), a.get("sha256") or "", a.get("rohdaten") or "", a.get("dauer_ms", ""),
                a.get("aus_cache") or "", wer.get("agent") or "", wer.get("sitzung") or "", e.get("kette"),
                " ".join(e.get("grundlage") or [])]))
        for e in extern:
            a = e.get("antwort") or {}
            s = extern_stand(e, pfad) if e.get("art") != "von_hand" else {"ergebnis": e.get("ergebnis"), "meldung": ""}
            w.writerow(csv_sicher([
                e["id"], e.get("zeit_utc"), e.get("zeit_lokal"), e.get("quelle"), e.get("werkzeug"), e.get("art"),
                e.get("freigabe") or "", e.get("ziel"), e.get("ziel_typ"), "", "", "", "", "", s["ergebnis"],
                " ".join(teil for teil in (s["meldung"], f"Nicht nach den Regeln für Robin: {e['regel']}" if e.get("regel") else "") if teil),
                a.get("bytes", ""), a.get("sha256") or "", a.get("rohdaten") or "", "", "", e.get("agent") or "",
                e.get("sitzung") or "", e.get("kette"), ""]))
        # Was verlangt, aber nicht ausgeführt wurde (Abschnitt 4): ohne Nummer, denn es steht in keinem der beiden Abfrageprotokolle
        for z in nicht_ausgefuehrt([z for z in sitzung if z.get("fall") == fall_id]):
            werkzeug = str(z.get("werkzeug") or "")
            w.writerow(csv_sicher([
                "", z.get("zeit_utc"), z.get("zeit_lokal"), "", werkzeug, "versuch", "",
                mcp_eingabe(z.get("eingabe"), 400) if werkzeug.startswith("mcp__") else eingabe_kurz(z.get("eingabe"), 400), "", "",
                "", "", "", "", "nicht_ausgefuehrt", z.get("grund") or "", "", "", "", "", "", z.get("agent") or "",
                z.get("sitzung") or "", "", ""]))
    print(f"Protokoll erzeugt: faelle/{fall_id}/rapport/Ermittlungsprotokoll.html ({len(abfragen)} Einträge)")
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
