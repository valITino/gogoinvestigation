#!/usr/bin/env python3
"""Sitzungsprotokoll. Hält fest, was in einer Claude-Code-Sitzung verlangt und ausgeführt wurde:
Eingaben des Sachbearbeiters, jeder Werkzeugaufruf (auch der Subagenten), Start und Ende der
Subagenten, und welches Sprachmodell jeweils gearbeitet hat. Schreibt nach
protokoll/sitzungen/<Sitzung>.jsonl, hash-verkettet.

Das Abfrageprotokoll der Fallakte führt das Gateway selbst. Dieser Hook ergänzt es um das
Wer (welcher Agent, welche Sitzung) und um alles, was nicht über das Gateway läuft.

Aufruf durch Claude Code (siehe .claude/settings.json). Die Ereignisdaten kommen als JSON über stdin.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJEKT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
sys.path.insert(0, str(PROJEKT))

from gateway import plattform, robin  # noqa: E402
from gateway.akte import FAELLE, SITZUNGEN, jsonl_lesen, kette, ursprung_extern  # noqa: E402

plattform.utf8()

# Unter Windows stehen Pfade mit \ in den Ereignisdaten, im JSON-Text verdoppelt. Beides wird wie / gelesen.
FALL_IM_PFAD = re.compile(r"faelle(?:/|\\{1,2})([A-Za-z0-9][A-Za-z0-9._-]{2,63})(?:/|\\)", re.I)
FALL_IM_BEFEHL = re.compile(r"/ermittlung\s+([A-Za-z0-9][A-Za-z0-9._-]{2,63})")
# Nur für Antworten, die sich nicht als JSON lesen lassen. Das Wort muss für sich stehen: «letzte_protokoll_id» aus fall_status
# nennt die jüngste Abfrage des Falls, nicht die dieses Aufrufs.
PROTOKOLL_ID = re.compile(r'(?<![A-Za-z_])protokoll_id\\*"\s*:\s*\\*"(P-\d{4,})')
LANG = 400
# MCP-Server, deren Antworten Beweismaterial sind und als Beleg X-… in die Fallakte kommen. Das Gateway (osint)
# sichert seine Antworten selbst. Alle anderen Server (GitHub, Dokumente, Steuerung der Sitzung) sind Arbeitsmittel:
# Ihre Aufrufe stehen mit Prüfsumme im Sitzungsprotokoll, ihre Antworten kommen nicht in die Fallakte. Sonst
# landet jede Antwort irgendeines Servers als «Beleg» in dem Fall, den die Sitzung zuletzt berührt hat.
# Wer eine weitere Quelle als MCP-Server anbindet, trägt ihren Namen hier ein.
BELEG_SERVER = ("robin",)
# Ereignisse vor der Ausführung: Sie halten fest, was verlangt wurde. Lehnt der Sachbearbeiter einen Aufruf ab oder verbietet ihn
# eine Berechtigung, meldet Claude Code kein Ende dazu (gesehen am 20.11.2026 mit Claude Code 2.1.329: PreToolUse, bei einer
# Rückfrage PermissionRequest, danach nichts). Ohne diese Einträge hinterliesse ein abgelehnter Aufruf keine Spur.
# Dieser Hook prüft dabei nichts und lehnt nichts ab: Er schreibt nur mit.
# Dazu gehört das Ende jeder Antwort der Hauptsitzung (Stop): Ein angekündigter Aufruf ohne Abschluss, auf den ein solches Ende
# folgt, läuft mit Sicherheit nicht mehr. Ohne es liesse sich ein abgelehnter Aufruf am Ende einer Sitzung nicht von einem
# unterscheiden, der noch läuft.
VORAB = ("PreToolUse", "PermissionRequest")


def kuerzen(wert, tiefe: int = 3):
    """Lange Texte durch Anfang, Länge und Hash ersetzen. Das Protokoll soll lesbar bleiben."""
    if isinstance(wert, str):
        if len(wert) <= LANG:
            return wert
        return {"anfang": wert[:LANG], "laenge": len(wert), "sha256": hashlib.sha256(wert.encode()).hexdigest()}
    if tiefe <= 0:
        return "…"
    if isinstance(wert, dict):
        return {k: kuerzen(v, tiefe - 1) for k, v in list(wert.items())[:40]}
    if isinstance(wert, list):
        return [kuerzen(v, tiefe - 1) for v in wert[:40]]
    return wert


def modell_aus(transkript: object) -> str | None:
    """Das Modell der letzten Antwort in einem Transkript von Claude Code (eine JSON-Zeile je Eintrag).
    So hält das Protokoll fest, welches Modell die Hauptsitzung und jeder Subagent tatsächlich benutzt hat."""
    if not isinstance(transkript, str) or not transkript:
        return None
    try:
        with open(os.path.expanduser(transkript), "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 400_000))
            zeilen = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for zeile in reversed(zeilen):
        if '"assistant"' not in zeile:
            continue
        try:
            eintrag = json.loads(zeile)
        except json.JSONDecodeError:
            continue        # angeschnittene erste Zeile
        modell = (eintrag.get("message") or {}).get("model") if eintrag.get("type") == "assistant" else None
        if isinstance(modell, str) and modell.startswith("claude-"):
            return modell
    return None


def fall_erkennen(ereignis: dict, text: str) -> str | None:
    eingabe = ereignis.get("tool_input") or {}
    kandidaten = [eingabe.get("fall")] if isinstance(eingabe, dict) else []
    kandidaten.append(ereignis.get("fall"))         # Schritte aus der Oberfläche nennen ihren Fall selbst
    kandidaten += FALL_IM_BEFEHL.findall(ereignis.get("prompt") or "")
    kandidaten += FALL_IM_PFAD.findall(text)
    for k in kandidaten:
        if isinstance(k, str) and (FAELLE / k / "fall.json").is_file():
            return k
    return None


ZIEL_LANG = 300


def gekappt(text: str, n: int = ZIEL_LANG) -> str:
    """Kürzt sichtbar: Wer die Zeile liest, sieht, dass etwas fehlt."""
    return text if len(text) <= n else text[:n - 1] + "…"


def ziel_aus(eingabe: object, name: str = "") -> str:
    """Wonach gefragt wurde, in einer Zeile. Mehrere Adressen werden nach ganzen Einträgen gekürzt, nie mitten in einer Adresse:
    «a, b und 2 weitere». Bis zum 20.11.2026 brach die Zeile nach 300 Zeichen ab, ohne es zu zeigen. Die ganze Eingabe steht
    unter anfrage.eingabe, und bei Robin nennt der Eintrag jede Seite einzeln (seiten)."""
    if name == "robin_health":
        return "Bereitschaft: Tor" + (" und Suchmaschinen" if isinstance(eingabe, dict) and eingabe.get("check_engines") else "")
    if isinstance(eingabe, dict):
        for feld in ("query", "question", "urls", "ids", "url", "targets", "refined_query"):
            if eingabe.get(feld):
                wert = eingabe[feld]
                if not isinstance(wert, list):
                    return gekappt(str(wert))
                teile, text = [str(w) for w in wert], ""
                for i, teil in enumerate(teile):
                    weiter = f"{text}, {teil}" if text else teil
                    if text and len(weiter) > ZIEL_LANG - 20:        # Platz für «und n weitere»
                        return f"{text} und {len(teile) - i} weitere"
                    text = weiter
                return gekappt(text)
    return gekappt(json.dumps(eingabe, ensure_ascii=False))


def gateway_antwort(antwort: object, antwort_text: str) -> tuple[str | None, str | None, str, list[str]]:
    """Was das Gateway zu einem Aufruf sagte: (Nummer im Abfrageprotokoll, ergebnis, Meldung, Nummern der Abfragen dahinter).

    Das Gateway antwortet mit einem JSON-Objekt. Die Nummer ist sein Feld protokoll_id auf der obersten Ebene, und nur dieses:
    fall_status nennt unter «letzte_protokoll_id» die jüngste Abfrage des Falls. Wer sie als Nummer dieses Aufrufs läse, schriebe
    die Abfrage dem Agenten zu, der danach den Stand abgefragt hat (so geschah es bis zum 20.11.2026).
    Ohne Nummer hat das Gateway nichts abgefragt (Quelle ausgeschaltet, Schlüssel fehlt, Eingabe ungültig, Zweck fehlt) oder nur
    Auskunft gegeben. Dann sagen ergebnis und Meldung, was geschah."""
    try:
        daten = json.loads(robin.text_aus(antwort))
    except ValueError:
        daten = None
    if not isinstance(daten, dict):
        m = PROTOKOLL_ID.search(antwort_text)       # keine lesbare Antwort: Die Nummer wird im Text gesucht
        return (m.group(1) if m else None), None, "", []
    nummer = daten.get("protokoll_id")
    ergebnis = daten.get("ergebnis")
    # Werkzeuge, die mehrere Abfragen bündeln, nennen sie unter «belege». Scheitert ein solches Werkzeug, gibt es keine Auswertung
    # mit eigener Nummer: Dann ordnen nur diese Nummern die Abfragen dem Agenten zu.
    belege = [b for b in daten.get("belege") or [] if isinstance(b, str) and re.fullmatch(r"P-\d{4,}", b)][:400] \
        if isinstance(daten.get("belege"), list) else []
    return (nummer if isinstance(nummer, str) and re.fullmatch(r"P-\d{4,}", nummer) else None,
            ergebnis if isinstance(ergebnis, str) else None, " ".join(str(daten.get("fehler") or "").split())[:LANG], belege)


def seiten_pruefstand(fall: str, text: str) -> list[dict]:
    """Zu jeder Seite, die robin_scrape gelesen oder versucht hat: ob ihre Adresse vorher gegen die Sperrliste geprüft war.
    So zeigt das Protokoll, dass die Pflichtprüfung stattfand, und nicht nur, dass sie aufgetragen war."""
    pfad = FAELLE / fall
    abfragen = jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl")
    aus = []
    for seite in robin.lesen(text)["seiten"]:
        host = robin.onion_host(seite["adresse"])
        stand, beleg = robin.sperrliste_stand(pfad, host, abfragen) if host else (None, None)
        aus.append({"adresse": seite["adresse"][:300], "stand": seite["stand"], **({"http": seite["http"]} if seite["http"] else {}),
                    "sperrliste": stand or ("offenes Netz" if not host else "nicht geprüft"), **({"sperrliste_beleg": beleg} if beleg else {})})
    return aus


def extern_sichern(fall: str, werkzeug: str, eingabe: object, antwort: object, sitzungseintrag: dict,
                   jetzt: datetime) -> dict:
    """Legt die Antwort eines fremden MCP-Servers als Rohdatei ab und verkettet sie in extern.jsonl. Gibt den Eintrag zurück.

    Für Robin steht in der Rohdatei der Text, wie Robin ihn schrieb (Claude Code reicht ihn verpackt weiter), und der Eintrag
    sagt, was die Antwort bedeutet: ausgeführt, nichts gefunden, nicht ausgeführt oder Fehler. Vorher stand bei jeder Antwort
    «ok», auch wenn Robin nichts gesucht hatte (gesehen am 20.11.2026)."""
    pfad = FAELLE / fall
    datei = pfad / "protokoll" / "extern.jsonl"
    datei.parent.mkdir(parents=True, exist_ok=True)
    _, server, name = (werkzeug.split("__", 2) + ["", ""])[:3]
    ist_robin = server == robin.SERVER
    text = robin.text_aus(antwort) if ist_robin else json.dumps(antwort, ensure_ascii=False)
    stand = robin.einordnen(werkzeug, text) if ist_robin else {"ergebnis": "ok"}
    aussen = name in robin.NACH_AUSSEN or (name == "robin_health" and isinstance(eingabe, dict) and bool(eingabe.get("check_engines")))
    inhalt = text.encode("utf-8")
    with plattform.dateisperre(datei):
        bisher = jsonl_lesen(datei)
        nr = bisher[-1]["nr"] + 1 if bisher else 1
        kennung = f"X-{nr:04d}"
        ordner = pfad / "rohdaten" / "extern"
        ordner.mkdir(parents=True, exist_ok=True)
        roh = ordner / f"{kennung}_{re.sub(r'[^A-Za-z0-9_-]', '_', name)}.{'txt' if ist_robin else 'json'}"
        roh.write_bytes(inhalt)
        roh.chmod(0o444)
        e = {"nr": nr, "id": kennung, "zeit_utc": sitzungseintrag["zeit_utc"], "zeit_lokal": sitzungseintrag["zeit_lokal"],
             "fall": fall, "werkzeug": name, "quelle": robin.QUELLE if ist_robin else f"MCP-Server {server}",
             # «tor»: Der Aufruf ging über Tor nach aussen. «robin_lokal»: Robin hat im Container gearbeitet, ohne Abfrage nach aussen
             "art": ("tor" if aussen else "robin_lokal") if ist_robin else "extern", "freigabe": "darkweb" if ist_robin else None,
             "ziel": ziel_aus(eingabe, name), "ziel_typ": "extern", "zweck": None,
             "anfrage": {"server": server, "eingabe": kuerzen(eingabe)},
             "antwort": {"bytes": len(inhalt), "sha256": hashlib.sha256(inhalt).hexdigest(),
                         "rohdaten": f"rohdaten/extern/{roh.name}"},
             "ergebnis": stand["ergebnis"], "fehler": stand.get("fehler"), "agent": sitzungseintrag.get("agent"),
             "sitzung": sitzungseintrag.get("sitzung")}
        if ist_robin:
            e["robin"] = {k: v for k, v in stand.items() if k not in ("ergebnis", "fehler")}
            if name == "robin_scrape" and stand.get("status") == "ok":
                e["seiten"] = seiten_pruefstand(fall, text)
            # Hielt der Aufruf die Regeln des Falls ein (Freigabe, Untersuchungsbereich, Prüfung gegen die Sperrliste)? Die Oberfläche
            # lässt einen Aufruf gar nicht erst zu, der sie verletzt. Am Terminal entscheidet der Sachbearbeiter je Aufruf, und niemand
            # prüft sie vorher: Dann hält der Beleg fest, was nicht stimmte. Der Hook lehnt nichts ab, der Aufruf ist schon gelaufen.
            try:
                daten = json.loads((pfad / "fall.json").read_text(encoding="utf-8"))
                abfragen = jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl")
                regel = robin.verstoss(werkzeug, eingabe, daten, lambda host: robin.sperrliste_stand(pfad, host, abfragen)[0])[0]
            except (OSError, ValueError):
                regel = "Die Fallakte liess sich nicht lesen: Ob der Aufruf die Regeln für Robin einhielt, ist nicht geprüft."
            if regel:
                e["regel"] = regel[:LANG]
        e["vorher"] = bisher[-1]["kette"] if bisher else ursprung_extern(fall)
        e["kette"] = kette(e["vorher"], e)
        plattform.zeile_anhaengen(datei, json.dumps(e, ensure_ascii=False))
    return e


def hinweis_zum_beleg(e: dict, fall: str) -> str:
    """Was der Agent nach einem Aufruf von Robin erfährt: die Belegnummer, und was der Beleg belegt."""
    if e["ergebnis"] == "nicht_ausgefuehrt":
        return (f"Robin hat nichts ausgeführt: {e.get('fehler')} Die Antwort liegt als {e['id']} in der Fallakte {fall}, "
                "sie belegt aber keine Suche und keine gelesene Seite.") + regel_hinweis(e)
    if e["ergebnis"] == "fehler":
        return (f"Der Aufruf ist gescheitert: {e.get('fehler')} Die Antwort liegt als {e['id']} in der Fallakte {fall}. Das ist eine Lücke, "
                "kein «nichts gefunden».") + regel_hinweis(e)
    text = f"Antwort gesichert als Beleg {e['id']} in der Fallakte {fall}. Im Rapport mit dieser Nummer belegen."
    ohne = [s["adresse"] for s in e.get("seiten") or [] if s["stand"] == "ok" and s["sperrliste"] in ("nicht geprüft", "gesperrt")]
    if ohne:
        text += (f" ACHTUNG: {len(ohne)} Seite(n) wurden gelesen, ohne dass die Prüfung mit onion_sperrliste sie freigab "
                 f"({', '.join(ohne)[:300]}). Das steht im Protokoll. Unter Auffälligkeiten melden und künftig zuerst prüfen.")
    return text + regel_hinweis(e, bool(ohne))


def regel_hinweis(e: dict, schon_gewarnt: bool = False) -> str:
    """Der Aufruf lief, hielt aber die Regeln des Falls nicht ein: Der Agent erfährt es, und es steht beim Beleg."""
    if not e.get("regel") or schon_gewarnt:
        return ""
    return f" ACHTUNG: Dieser Aufruf hielt die Regeln für Robin nicht ein. {e['regel']} Das steht im Protokoll. Unter Auffälligkeiten melden."


def main() -> int:
    try:
        ereignis = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0
    sitzung = re.sub(r"[^A-Za-z0-9_-]", "_", str(ereignis.get("session_id") or "unbekannt"))[:80]
    art = ereignis.get("hook_event_name") or "unbekannt"
    eingabe = ereignis.get("tool_input")
    antwort = ereignis.get("tool_response")
    eingabe_text = json.dumps(eingabe, ensure_ascii=False) if eingabe is not None else ""
    antwort_text = json.dumps(antwort, ensure_ascii=False) if antwort is not None else ""

    SITZUNGEN.mkdir(parents=True, exist_ok=True)
    fall = fall_erkennen(ereignis, eingabe_text + (ereignis.get("prompt") or ""))
    merker = SITZUNGEN / f"{sitzung}.fall"
    if fall:
        plattform.text_schreiben(merker, fall)          # der aktive Fall der Sitzung, für Aufrufe, die keinen nennen
    elif merker.is_file():
        fall = merker.read_text(encoding="utf-8").strip() or None

    hinweis = ""
    jetzt = datetime.now(timezone.utc)
    if os.environ.get("OSINT_TESTZEIT"):        # nur für tools/musterfall.py: gestellte Uhr
        jetzt = datetime.strptime(os.environ["OSINT_TESTZEIT"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    try:
        zone = plattform.zeitzone()      # dieselbe Zeitzone wie im Abfrageprotokoll des Gateways
    except plattform.Zeitzonenfehler:
        zone = None                      # Systempython unter Windows ohne Zeitzonendaten: Ortszeit des Rechners
    eintrag: dict = {"zeit_utc": jetzt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "zeit_lokal": jetzt.astimezone(zone).isoformat(timespec="seconds"),
                     "ereignis": art, "sitzung": sitzung, "fall": fall,
                     "agent": ereignis.get("agent_type") or "hauptsitzung",
                     "agent_id": ereignis.get("agent_id")}
    if art == "PostModelSwitch":      # jemand hat das Modell der Sitzung gewechselt, oder Claude Code ist ausgewichen
        modell = ereignis.get("to_model") if isinstance(ereignis.get("to_model"), str) else None
        eintrag["modell_vorher"], eintrag["anlass"] = ereignis.get("from_model"), ereignis.get("source")
    elif art == "SubagentStop":
        modell = modell_aus(ereignis.get("agent_transcript_path"))
    elif ereignis.get("tool_name") and not ereignis.get("agent_id") and art not in VORAB:
        modell = modell_aus(ereignis.get("transcript_path"))        # Schritt der Hauptsitzung
    else:
        modell = None
    if modell:
        eintrag["modell"] = modell
    if art == "UserPromptSubmit":
        eintrag["eingabe"] = kuerzen(ereignis.get("prompt") or "")
    if art == "Oberflaeche":
        # Ein Schritt des Sachbearbeiters in der Oberfläche (tools/ui): Freigabe, Antwort auf eine Rückfrage, Start der Ermittlung.
        # Der Server der Oberfläche ruft dafür diesen Hook auf. So bleibt das Sitzungsprotokoll in einer Hand.
        eintrag.update({"agent": "sachbearbeiter", "weg": "Oberfläche", "schritt": kuerzen(str(ereignis.get("schritt") or "")),
                        "angabe": kuerzen(str(ereignis.get("angabe") or ""))})
    if art in ("Elicitation", "ElicitationResult"):
        # Ein MCP-Server (Robin) stellt dem Sachbearbeiter selbst eine Frage, etwa nach dem Untersuchungsbereich. Frage und
        # Antwort gehören ins Protokoll: Die Antwort bestimmt, was der Server danach tut.
        eintrag["server"] = str(ereignis.get("mcp_server_name") or "")[:80]
        if art == "Elicitation":
            eintrag["frage"] = kuerzen(str(ereignis.get("message") or ""))
        else:
            eintrag["entscheid"] = str(ereignis.get("action") or "")[:40]
            if ereignis.get("content") is not None:
                eintrag["angabe"] = kuerzen(json.dumps(ereignis.get("content"), ensure_ascii=False))
    if ereignis.get("tool_name"):
        werkzeug = ereignis["tool_name"]
        eintrag.update({"werkzeug": werkzeug, "tool_use_id": ereignis.get("tool_use_id"),
                        "eingabe": kuerzen(eingabe), "dauer_ms": ereignis.get("duration_ms")})
        if art == "PostToolUseFailure":
            eintrag["fehler"] = kuerzen(str(ereignis.get("error") or antwort_text or "unbekannt"))
            if ereignis.get("is_interrupt"):        # der Sachbearbeiter hat den laufenden Aufruf abgebrochen
                eintrag["abgebrochen"] = True
        if antwort is not None:
            eintrag["antwort_bytes"] = len(antwort_text.encode())
            eintrag["antwort_sha256"] = hashlib.sha256(antwort_text.encode()).hexdigest()
            if werkzeug.startswith("mcp__osint__"):
                nummer, ergebnis, meldung, belege = gateway_antwort(antwort, antwort_text)
                if nummer:
                    eintrag["protokoll_id"] = nummer
                elif ergebnis:
                    # Kein Eintrag im Abfrageprotokoll. Was das Gateway dazu sagte, hält das Sitzungsprotokoll fest. Sonst tauchte
                    # der Versuch im Ermittlungsprotokoll nirgends auf.
                    eintrag["ergebnis"], eintrag["meldung"] = ergebnis, meldung
                if belege and not nummer:
                    eintrag["belege"] = belege
            # Antworten fremder MCP-Server (z. B. Robin) als Beleg X-… in die Fallakte legen.
            # Das Gateway sieht diese Aufrufe nicht, also übernimmt der Hook Sicherung und Verkettung.
            server = werkzeug.split("__")[1] if werkzeug.startswith("mcp__") and werkzeug.count("__") >= 2 else ""
            if server in BELEG_SERVER and art == "PostToolUse":
                if fall:
                    beleg = extern_sichern(fall, werkzeug, eingabe, antwort, eintrag, jetzt)
                    eintrag["protokoll_id"] = beleg["id"]
                    hinweis = hinweis_zum_beleg(beleg, fall)
                else:
                    ordner = SITZUNGEN / sitzung
                    ordner.mkdir(exist_ok=True)
                    name = re.sub(r"[^A-Za-z0-9_-]", "_", str(ereignis.get("tool_use_id") or jetzt.timestamp()))
                    ist_robin = server == robin.SERVER
                    plattform.text_schreiben(ordner / f"{name}.{'txt' if ist_robin else 'json'}", robin.text_aus(antwort) if ist_robin else antwort_text)
                    eintrag["antwort_datei"] = f"protokoll/sitzungen/{sitzung}/{name}.{'txt' if ist_robin else 'json'}"

    datei = SITZUNGEN / f"{sitzung}.jsonl"
    with plattform.dateisperre(datei):
        bisher = jsonl_lesen(datei)
        eintrag["nr"] = bisher[-1]["nr"] + 1 if bisher else 1
        eintrag["vorher"] = bisher[-1]["kette"] if bisher else hashlib.sha256(f"sitzung|{sitzung}".encode()).hexdigest()
        eintrag["kette"] = kette(eintrag["vorher"], eintrag)
        plattform.zeile_anhaengen(datei, json.dumps(eintrag, ensure_ascii=False))
    if hinweis:   # teilt dem Agenten die Belegnummer mit
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": hinweis}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # Protokollfehler sichtbar machen, die Arbeit aber nicht blockieren
        print(f"Sitzungsprotokoll konnte nicht geschrieben werden: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
