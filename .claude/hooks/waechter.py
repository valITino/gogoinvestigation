#!/usr/bin/env python3
"""Wächter. Läuft vor Werkzeugaufrufen (PreToolUse) und verhindert drei Dinge:

1. Lesen ungeprüfter Dokumente. Dateien in faelle/<Fall>/eingang/ sind erst lesbar, wenn
   tools/fall.py sie durch die PII-Prüfung gelassen hat (eingang/.freigabe.json, mit Hash).
2. Dark-Web-Recherche ohne Freigabe. Die Werkzeuge des Robin-Servers laufen nur, wenn der
   aktive Fall die Freigabe 'darkweb' hat.
3. Verändern der Grundlagen. Agenten dürfen weder Fallstammdaten und Protokolle noch
   Gateway, Hooks, Einrichtung und Einstellungen überschreiben, und sich keine Freigaben selbst erteilen.

Erlaubte Aufrufe passieren ohne Ausgabe. Abgelehnte bekommen eine Begründung, die der Agent liest.
Im Zweifel wird abgelehnt: Kann der Wächter nicht starten oder seine Eingabe nicht lesen, läuft nichts.

Gilt für Bash ebenso wie für das PowerShell-Werkzeug unter Windows. Pfade werden unabhängig von
Schrägstrich-Richtung und Gross-/Kleinschreibung geprüft.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

PROJEKT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2]).resolve()
sys.path.insert(0, str(PROJEKT))


def ablehnen(grund: str) -> None:
    # ensure_ascii: Die Antwort bleibt lesbar, egal welche Kodierung die Konsole des Systems hat.
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": grund}}))
    sys.exit(0)


try:
    from gateway import plattform
    from gateway.akte import FAELLE, SITZUNGEN, fall_daten, freigabe_erteilt, sha256_datei
    plattform.utf8()
except Exception as e:  # ohne seine Grundlagen kann der Wächter nichts beurteilen
    ablehnen(f"Der Wächter kann nicht starten ({type(e).__name__}: {e}). Aufruf vorsichtshalber abgelehnt.")

GESCHUETZT = (".claude/", "gateway/", "tools/", "protokoll/", ".github/", ".mcp.json", ".env", "claude.md",
              "setup.sh", "setup.ps1", "setup.cmd", "requirements.txt", "docker-compose.yml", ".gitattributes")
GESCHUETZT_IM_FALL = ("fall.json", "protokoll/", "rohdaten/", "eingang/")
SHELLS = ("Bash", "PowerShell", "Monitor")
EINGANG = re.compile(r"(?:^|/)faelle/([^/]+)/eingang(?:/(.+))?$", re.I)
FALLWERKZEUG = re.compile(r"\s*\S*py(thon[\d.]*)?(\.exe)?\s+\S*tools/fall\.py\s[^;&|`$<>]*", re.I)
NETZ = re.compile(r"(^|[\s;&|(`$'\"])(curl|wget|nc|ncat|ssh|scp|sftp|telnet|ftp|iwr|irm|invoke-webrequest|"
                  r"invoke-restmethod|start-bitstransfer|bitsadmin)(\.exe)?(\s|$)"
                  r"|net\.webclient|system\.net\.http|certutil(\.exe)?\s.*-urlcache", re.I)


def relativ(pfad: str, cwd: str) -> str | None:
    """Pfad relativ zum Projekt (mit /), oder None wenn er ausserhalb liegt."""
    text = pfad.strip().strip("\"'")
    if plattform.WINDOWS:   # Git Bash schreibt C:\Users\… als /c/Users/…
        m = re.match(r"^/(?:cygdrive/)?([A-Za-z])/(.*)$", text.replace("\\", "/"))
        if m:
            text = f"{m.group(1)}:/{m.group(2)}"
    p = Path(text).expanduser()
    if not p.is_absolute():
        p = Path(cwd or PROJEKT) / p
    try:
        return p.resolve().relative_to(PROJEKT).as_posix()
    except ValueError:
        return None


def faelle_vorhanden() -> list[str]:
    return [p.name for p in FAELLE.iterdir() if p.is_dir()] if FAELLE.is_dir() else []


def eingang_pruefen(fall: str, nur_datei: str | None = None) -> None:
    """Lehnt ab, wenn eine Datei im Eingang nicht durch die PII-Prüfung freigegeben ist."""
    eingang = FAELLE / fall / "eingang"
    register_datei = eingang / ".freigabe.json"
    register = json.loads(register_datei.read_text(encoding="utf-8")).get("dateien", {}) if register_datei.is_file() else {}
    dateien = [eingang / nur_datei] if nur_datei else [p for p in eingang.rglob("*") if p.is_file()]
    for datei in dateien:
        if datei.name.startswith(".") or not datei.is_file():
            continue
        eintrag = register.get(datei.name)
        if not eintrag or eintrag.get("sha256") != sha256_datei(datei):
            ablehnen(
                f"'{datei.name}' im Eingang von Fall {fall} ist nicht durch die PII-Prüfung freigegeben "
                "(neu, verändert oder von Hand hineinkopiert). Nicht lesen. Der Sachbearbeiter nimmt das "
                f"Dokument so auf: {plattform.PY} tools/fall.py aufnehmen {fall} <Datei>")


def lesen(pfad: str, cwd: str, verzeichnis_erlaubt: bool) -> None:
    rel = relativ(pfad, cwd)
    if rel is None:
        # Der Pfad liess sich dem Projekt nicht zuordnen. Sieht er trotzdem nach einem Eingang aus, gilt die Prüfung.
        m = EINGANG.search(pfad.replace("\\", "/"))
        if m and (FAELLE / m.group(1)).is_dir():
            eingang_pruefen(m.group(1), m.group(2) if m.group(2) and "/" not in m.group(2) else None)
        return
    m = EINGANG.match(rel)
    if m:
        eingang_pruefen(m.group(1), m.group(2) if m.group(2) and "/" not in m.group(2) else None)
    elif verzeichnis_erlaubt and (rel.lower() in ("", ".", "faelle") or re.fullmatch(r"faelle/[^/]+", rel, re.I)):
        faelle = [rel.split("/")[1]] if "/" in rel else faelle_vorhanden()
        for fall in faelle:
            if (FAELLE / fall / "eingang").is_dir():
                eingang_pruefen(fall)


def schreiben(pfad: str, cwd: str) -> None:
    rel = relativ(pfad, cwd)
    if rel is None:
        return
    klein = rel.lower()     # macOS und Windows unterscheiden Gross- und Kleinschreibung nicht
    if any(klein == g.rstrip("/") or klein.startswith(g) for g in GESCHUETZT):
        ablehnen(f"'{rel}' gehört zu den Grundlagen des Arbeitsplatzes und wird von Agenten nicht verändert.")
    m = re.match(r"faelle/([^/]+)/(.+)$", klein)
    if m and any(m.group(2) == g.rstrip("/") or m.group(2).startswith(g) for g in GESCHUETZT_IM_FALL):
        ablehnen(f"'{rel}' ist geschützt. Stammdaten und Freigaben ändert nur tools/fall.py am Terminal, "
                 "Protokoll und Rohdaten schreibt nur das Gateway, den Eingang füllt nur die PII-Prüfung.")


def shell(befehl: str) -> None:
    b = befehl.replace("\\", "/")
    if re.search(r"fall\.py\s+freigabe|--trotzdem", b, re.I):
        ablehnen("Freigaben und das Übersteuern der PII-Prüfung sind Entscheidungen des Sachbearbeiters. "
                 "Er führt den Befehl selbst am Terminal aus.")
    if re.search(r"einrichten\.py|(^|[\s/;&|(])setup\.(sh|ps1|cmd)\b", b, re.I):
        ablehnen("Die Einrichtung des Arbeitsplatzes (Modelle, MCP-Server, Schlüsseldatei) ändert nur der "
                 "Sachbearbeiter am Terminal.")
    if NETZ.search(b):
        ablehnen("Netzwerkzugriffe laufen nur über das OSINT-Gateway (Werkzeuge mcp__osint__…), "
                 "damit sie protokolliert und die Antworten gesichert werden.")
    # Wer in einem Befehl den Eingang anfasst, bekommt ihn nur, wenn jedes Dokument darin geprüft ist.
    # Ausgenommen ist allein tools/fall.py: Es ist die PII-Prüfung.
    if re.search(r"eingang", b, re.I) and not FALLWERKZEUG.fullmatch(b):
        vorhanden = {f.lower(): f for f in faelle_vorhanden()}
        genannt = {vorhanden[f.lower()] for f in re.findall(r"faelle/([A-Za-z0-9][A-Za-z0-9._-]{2,63})", b, re.I)
                   if f.lower() in vorhanden}
        for fall in sorted(genannt or vorhanden.values()):
            eingang_pruefen(fall)


def main() -> None:
    try:
        ereignis = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        ablehnen(f"Der Wächter konnte den Aufruf nicht lesen ({type(e).__name__}). Vorsichtshalber abgelehnt.")
    werkzeug = ereignis.get("tool_name") or ""
    eingabe = ereignis.get("tool_input") or {}
    cwd = ereignis.get("cwd") or str(PROJEKT)
    if not isinstance(eingabe, dict):
        return

    if werkzeug == "Read":
        lesen(str(eingabe.get("file_path") or ""), cwd, verzeichnis_erlaubt=False)
    elif werkzeug == "Grep":
        lesen(str(eingabe.get("path") or "."), cwd, verzeichnis_erlaubt=True)
    elif werkzeug in ("Edit", "Write", "NotebookEdit"):
        schreiben(str(eingabe.get("file_path") or eingabe.get("notebook_path") or ""), cwd)
    elif werkzeug in SHELLS:
        shell(str(eingabe.get("command") or ""))
    elif werkzeug.startswith("mcp__robin__"):
        sitzung = re.sub(r"[^A-Za-z0-9_-]", "_", str(ereignis.get("session_id") or "unbekannt"))[:80]
        merker = SITZUNGEN / f"{sitzung}.fall"
        fall = merker.read_text(encoding="utf-8").strip() if merker.is_file() else ""
        if not fall:
            ablehnen("Dark-Web-Recherche ohne erkennbaren Fall. Zuerst mcp__osint__fall_status für den Fall aufrufen.")
        if not freigabe_erteilt(fall_daten(fall), "darkweb"):
            ablehnen(f"Fall {fall} hat keine Freigabe 'darkweb'. Robin wird nicht ausgeführt. Der Sachbearbeiter "
                     f"erteilt sie am Terminal: {plattform.PY} tools/fall.py freigabe {fall} darkweb --durch … --vermerk …")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # im Zweifel sperren: Ein defekter Wächter darf nichts durchlassen
        ablehnen(f"Wächter-Fehler ({type(e).__name__}: {e}). Aufruf vorsichtshalber abgelehnt. "
                 f"Bitte '{plattform.PY} tools/pruefen.py' ausführen.")
