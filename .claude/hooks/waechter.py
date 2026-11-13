#!/usr/bin/env python3
"""Wächter. Läuft vor Werkzeugaufrufen (PreToolUse) und verhindert drei Dinge:

1. Lesen ungeprüfter Dokumente. Dateien in faelle/<Fall>/eingang/ sind erst lesbar, wenn
   tools/fall.py sie durch die PII-Prüfung gelassen hat (eingang/.freigabe.json, mit Hash).
2. Dark-Web-Recherche ohne Freigabe. Die Werkzeuge des Robin-Servers laufen nur, wenn der
   aktive Fall die Freigabe 'darkweb' hat.
3. Verändern der Grundlagen. Agenten dürfen weder Fallstammdaten und Protokolle noch
   Gateway, Hooks und Einstellungen überschreiben, und sich keine Freigaben selbst erteilen.

Erlaubte Aufrufe passieren ohne Ausgabe. Abgelehnte bekommen eine Begründung, die der Agent liest.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

PROJEKT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2]).resolve()
sys.path.insert(0, str(PROJEKT))

from gateway.akte import FAELLE, SITZUNGEN, fall_daten, freigabe_erteilt, sha256_datei  # noqa: E402

GESCHUETZT = (".claude/", "gateway/", "tools/", "protokoll/", ".mcp.json", ".env", "CLAUDE.md", "setup.sh",
              "docker-compose.yml")
GESCHUETZT_IM_FALL = ("fall.json", "protokoll/", "rohdaten/", "eingang/")


def ablehnen(grund: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": grund}}, ensure_ascii=False))
    sys.exit(0)


def relativ(pfad: str, cwd: str) -> str | None:
    """Pfad relativ zum Projekt, oder None wenn er ausserhalb liegt."""
    p = Path(pfad).expanduser()
    if not p.is_absolute():
        p = Path(cwd or PROJEKT) / p
    try:
        return p.resolve().relative_to(PROJEKT).as_posix()
    except ValueError:
        return None


def eingang_pruefen(fall: str, nur_datei: str | None = None) -> None:
    """Lehnt ab, wenn eine Datei im Eingang nicht durch die PII-Prüfung freigegeben ist."""
    eingang = FAELLE / fall / "eingang"
    register_datei = eingang / ".freigabe.json"
    register = json.loads(register_datei.read_text(encoding="utf-8")).get("dateien", {}) if register_datei.is_file() else {}
    dateien = [eingang / nur_datei] if nur_datei else [p for p in eingang.rglob("*") if p.is_file()]
    for datei in dateien:
        if datei.name.startswith("."):
            continue
        eintrag = register.get(datei.name)
        if not datei.is_file():
            continue
        if not eintrag or eintrag.get("sha256") != sha256_datei(datei):
            ablehnen(
                f"'{datei.name}' im Eingang von Fall {fall} ist nicht durch die PII-Prüfung freigegeben "
                "(neu, verändert oder von Hand hineinkopiert). Nicht lesen. Der Sachbearbeiter nimmt das "
                f"Dokument so auf: python3 tools/fall.py aufnehmen {fall} <Datei>")


def lesen(pfad: str, cwd: str, verzeichnis_erlaubt: bool) -> None:
    rel = relativ(pfad, cwd)
    if rel is None:
        return
    m = re.match(r"faelle/([^/]+)/eingang(?:/(.+))?$", rel)
    if m:
        eingang_pruefen(m.group(1), m.group(2) if m.group(2) and "/" not in m.group(2) else None)
    elif verzeichnis_erlaubt and (rel in ("", ".", "faelle") or re.fullmatch(r"faelle/[^/]+", rel)):
        faelle = [rel.split("/")[1]] if "/" in rel else [p.name for p in FAELLE.iterdir() if p.is_dir()]
        for fall in faelle:
            if (FAELLE / fall / "eingang").is_dir():
                eingang_pruefen(fall)


def schreiben(pfad: str, cwd: str) -> None:
    rel = relativ(pfad, cwd)
    if rel is None:
        return
    if any(rel == g.rstrip("/") or rel.startswith(g) for g in GESCHUETZT):
        ablehnen(f"'{rel}' gehört zu den Grundlagen des Arbeitsplatzes und wird von Agenten nicht verändert.")
    m = re.match(r"faelle/([^/]+)/(.+)$", rel)
    if m and any(m.group(2) == g.rstrip("/") or m.group(2).startswith(g) for g in GESCHUETZT_IM_FALL):
        ablehnen(f"'{rel}' ist geschützt. Stammdaten und Freigaben ändert nur tools/fall.py am Terminal, "
                 "Protokoll und Rohdaten schreibt nur das Gateway, den Eingang füllt nur die PII-Prüfung.")


def main() -> None:
    try:
        ereignis = json.load(sys.stdin)
    except json.JSONDecodeError:
        return
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
    elif werkzeug == "Bash":
        befehl = str(eingabe.get("command") or "")
        if re.search(r"fall\.py\s+freigabe|--trotzdem", befehl):
            ablehnen("Freigaben und das Übersteuern der PII-Prüfung sind Entscheidungen des Sachbearbeiters. "
                     "Er führt den Befehl selbst am Terminal aus.")
        for fall in set(re.findall(r"faelle/([A-Za-z0-9][A-Za-z0-9._-]{2,63})/eingang", befehl)):
            if "fall.py" not in befehl and (FAELLE / fall).is_dir():
                eingang_pruefen(fall)
        if re.search(r"(^|[\s;&|(])(curl|wget|nc|ncat|ssh|scp|telnet|ftp)\s", befehl):
            ablehnen("Netzwerkzugriffe laufen nur über das OSINT-Gateway (Werkzeuge mcp__osint__…), "
                     "damit sie protokolliert und die Antworten gesichert werden.")
    elif werkzeug.startswith("mcp__robin__"):
        sitzung = re.sub(r"[^A-Za-z0-9_-]", "_", str(ereignis.get("session_id") or "unbekannt"))[:80]
        merker = SITZUNGEN / f"{sitzung}.fall"
        fall = merker.read_text(encoding="utf-8").strip() if merker.is_file() else ""
        if not fall:
            ablehnen("Dark-Web-Recherche ohne erkennbaren Fall. Zuerst mcp__osint__fall_status für den Fall aufrufen.")
        if not freigabe_erteilt(fall_daten(fall), "darkweb"):
            ablehnen(f"Fall {fall} hat keine Freigabe 'darkweb'. Robin wird nicht ausgeführt. Der Sachbearbeiter "
                     f"erteilt sie am Terminal: python3 tools/fall.py freigabe {fall} darkweb --durch … --vermerk …")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # im Zweifel sperren: Ein defekter Wächter darf nichts durchlassen
        ablehnen(f"Wächter-Fehler ({type(e).__name__}: {e}). Aufruf vorsichtshalber abgelehnt. "
                 "Bitte 'python3 tools/pruefen.py' ausführen.")
