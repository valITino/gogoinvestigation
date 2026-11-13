#!/usr/bin/env python3
"""Sitzungsprotokoll. Hält fest, was in einer Claude-Code-Sitzung verlangt und ausgeführt wurde:
Eingaben des Sachbearbeiters, jeder Werkzeugaufruf (auch der Subagenten), Start und Ende der
Subagenten. Schreibt nach protokoll/sitzungen/<Sitzung>.jsonl, hash-verkettet.

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

try:
    import fcntl
except ImportError:  # Windows ohne fcntl: ohne Dateisperre
    fcntl = None

from gateway.akte import FAELLE, SITZUNGEN, jsonl_lesen, kette, ursprung_extern  # noqa: E402

FALL_IM_PFAD = re.compile(r"faelle/([A-Za-z0-9][A-Za-z0-9._-]{2,63})/")
FALL_IM_BEFEHL = re.compile(r"/ermittlung\s+([A-Za-z0-9][A-Za-z0-9._-]{2,63})")
PROTOKOLL_ID = re.compile(r'protokoll_id\\*"\s*:\s*\\*"(P-\d{4,})')
LANG = 400


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


def fall_erkennen(ereignis: dict, text: str) -> str | None:
    eingabe = ereignis.get("tool_input") or {}
    kandidaten = [eingabe.get("fall")] if isinstance(eingabe, dict) else []
    kandidaten += FALL_IM_BEFEHL.findall(ereignis.get("prompt") or "")
    kandidaten += FALL_IM_PFAD.findall(text)
    for k in kandidaten:
        if isinstance(k, str) and (FAELLE / k / "fall.json").is_file():
            return k
    return None


def ziel_aus(eingabe: object) -> str:
    if isinstance(eingabe, dict):
        for feld in ("query", "question", "urls", "url", "targets", "refined_query"):
            if eingabe.get(feld):
                wert = eingabe[feld]
                return (", ".join(map(str, wert)) if isinstance(wert, list) else str(wert))[:300]
    return json.dumps(eingabe, ensure_ascii=False)[:300]


def extern_sichern(fall: str, werkzeug: str, eingabe: object, antwort_text: str, sitzungseintrag: dict,
                   jetzt: datetime) -> str:
    """Legt die Antwort eines fremden MCP-Servers als Rohdatei ab und verkettet sie in extern.jsonl."""
    pfad = FAELLE / fall
    datei = pfad / "protokoll" / "extern.jsonl"
    datei.parent.mkdir(parents=True, exist_ok=True)
    _, server, name = (werkzeug.split("__", 2) + ["", ""])[:3]
    inhalt = antwort_text.encode("utf-8")
    with open(datei.with_suffix(".lock"), "w") as sperre:
        if fcntl:
            fcntl.flock(sperre, fcntl.LOCK_EX)
        bisher = jsonl_lesen(datei)
        nr = bisher[-1]["nr"] + 1 if bisher else 1
        kennung = f"X-{nr:04d}"
        ordner = pfad / "rohdaten" / "extern"
        ordner.mkdir(parents=True, exist_ok=True)
        roh = ordner / f"{kennung}_{re.sub(r'[^A-Za-z0-9_-]', '_', name)}.json"
        roh.write_bytes(inhalt)
        roh.chmod(0o444)
        e = {"nr": nr, "id": kennung, "zeit_utc": sitzungseintrag["zeit_utc"], "zeit_lokal": sitzungseintrag["zeit_lokal"],
             "fall": fall, "werkzeug": name, "quelle": {"robin": "Robin (Tor)"}.get(server, f"MCP-Server {server}"),
             "art": "tor" if server == "robin" else "extern", "freigabe": "darkweb" if server == "robin" else None,
             "ziel": ziel_aus(eingabe), "ziel_typ": "extern", "zweck": None,
             "anfrage": {"server": server, "eingabe": kuerzen(eingabe)},
             "antwort": {"bytes": len(inhalt), "sha256": hashlib.sha256(inhalt).hexdigest(),
                         "rohdaten": f"rohdaten/extern/{roh.name}"},
             "ergebnis": "ok", "fehler": None, "agent": sitzungseintrag.get("agent"),
             "sitzung": sitzungseintrag.get("sitzung"),
             "vorher": bisher[-1]["kette"] if bisher else ursprung_extern(fall)}
        e["kette"] = kette(e["vorher"], e)
        with open(datei, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return kennung


def main() -> int:
    try:
        ereignis = json.load(sys.stdin)
    except json.JSONDecodeError:
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
        merker.write_text(fall, encoding="utf-8")       # der Wächter liest daraus den aktiven Fall
    elif merker.is_file():
        fall = merker.read_text(encoding="utf-8").strip() or None

    hinweis = ""
    jetzt = datetime.now(timezone.utc)
    if os.environ.get("OSINT_TESTZEIT"):        # nur für tools/musterfall.py: gestellte Uhr
        jetzt = datetime.strptime(os.environ["OSINT_TESTZEIT"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    eintrag: dict = {"zeit_utc": jetzt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "zeit_lokal": jetzt.astimezone().isoformat(timespec="seconds"),
                     "ereignis": art, "sitzung": sitzung, "fall": fall,
                     "agent": ereignis.get("agent_type") or "hauptsitzung",
                     "agent_id": ereignis.get("agent_id")}
    if art == "UserPromptSubmit":
        eintrag["eingabe"] = kuerzen(ereignis.get("prompt") or "")
    if ereignis.get("tool_name"):
        werkzeug = ereignis["tool_name"]
        eintrag.update({"werkzeug": werkzeug, "tool_use_id": ereignis.get("tool_use_id"),
                        "eingabe": kuerzen(eingabe), "dauer_ms": ereignis.get("duration_ms")})
        if art == "PostToolUseFailure":
            eintrag["fehler"] = kuerzen(str(ereignis.get("error") or antwort_text or "unbekannt"))
        if antwort is not None:
            eintrag["antwort_bytes"] = len(antwort_text.encode())
            eintrag["antwort_sha256"] = hashlib.sha256(antwort_text.encode()).hexdigest()
            m = PROTOKOLL_ID.search(antwort_text)
            if m and werkzeug.startswith("mcp__osint__"):
                eintrag["protokoll_id"] = m.group(1)
            # Antworten fremder MCP-Server (z. B. Robin) als Beleg X-… in die Fallakte legen.
            # Das Gateway sieht diese Aufrufe nicht, also übernimmt der Hook Sicherung und Verkettung.
            if werkzeug.startswith("mcp__") and not werkzeug.startswith("mcp__osint__") and art == "PostToolUse":
                if fall:
                    eintrag["protokoll_id"] = extern_sichern(fall, werkzeug, eingabe, antwort_text, eintrag, jetzt)
                    hinweis = (f"Antwort gesichert als Beleg {eintrag['protokoll_id']} in der Fallakte {fall}. "
                               "Im Rapport mit dieser Nummer belegen.")
                else:
                    ordner = SITZUNGEN / sitzung
                    ordner.mkdir(exist_ok=True)
                    name = re.sub(r"[^A-Za-z0-9_-]", "_", str(ereignis.get("tool_use_id") or jetzt.timestamp()))
                    (ordner / f"{name}.json").write_text(antwort_text, encoding="utf-8")
                    eintrag["antwort_datei"] = f"protokoll/sitzungen/{sitzung}/{name}.json"

    datei = SITZUNGEN / f"{sitzung}.jsonl"
    with open(datei.with_suffix(".lock"), "w") as sperre:
        if fcntl:
            fcntl.flock(sperre, fcntl.LOCK_EX)
        bisher = jsonl_lesen(datei)
        eintrag["nr"] = bisher[-1]["nr"] + 1 if bisher else 1
        eintrag["vorher"] = bisher[-1]["kette"] if bisher else hashlib.sha256(f"sitzung|{sitzung}".encode()).hexdigest()
        eintrag["kette"] = kette(eintrag["vorher"], eintrag)
        with open(datei, "a", encoding="utf-8") as f:
            f.write(json.dumps(eintrag, ensure_ascii=False) + "\n")
    if hinweis:   # teilt dem Agenten die Belegnummer mit
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": hinweis}},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # Protokollfehler sichtbar machen, die Arbeit aber nicht blockieren
        print(f"Sitzungsprotokoll konnte nicht geschrieben werden: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
