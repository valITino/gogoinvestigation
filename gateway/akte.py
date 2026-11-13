"""Fallakte und Protokollkette. Nur Standardbibliothek, damit Hooks und Werkzeuge
unter tools/ ohne installierte Pakete laufen.

Aufbau einer Fallakte:

    faelle/<Fall-ID>/
        fall.json                 Stammdaten und Freigaben (schreibt nur tools/fall.py)
        eingang/                  pseudonymisierte Dokumente, .freigabe.json der PII-Prüfung
        protokoll/abfragen.jsonl  jede Abfrage des Gateways, hash-verkettet (Belege P-0001 …)
        protokoll/extern.jsonl    Antworten weiterer MCP-Server wie Robin (Belege X-0001 …)
        rohdaten/                 unveränderte Antworten der Quellen
        arbeitsstand/             Notizen und Zwischenstände des Ermittler-Teams
        befunde.json              strukturierte Befunde, Grundlage des Rapports
        rapport/                  Abschlussrapport und Ermittlungsprotokoll
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

PROJEKT = Path(os.environ.get("OSINT_PROJEKT") or Path(__file__).resolve().parents[1])
FAELLE = PROJEKT / "faelle"
SITZUNGEN = PROJEKT / "protokoll" / "sitzungen"
FREIGABEN = ("aktiv", "darkweb", "personenbezug")
FREIGABE_TEXT = {
    "aktiv": "Aktive Massnahmen: Das Ziel wird aufgerufen und kann das bemerken.",
    "darkweb": "Dark-Web-Recherche über Tor (Robin).",
    "personenbezug": "Abfragen zu Konten und Benutzernamen (Mastodon, Telegram).",
}
FALL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


def kanonisch(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def ursprung(fall_id: str) -> str:
    """Startwert der Kette. Bindet das Protokoll an die Fall-ID."""
    return hashlib.sha256(f"osint-gateway|{fall_id}".encode()).hexdigest()


def kette(vorher: str, eintrag: dict) -> str:
    koerper = {k: v for k, v in eintrag.items() if k != "kette"}
    return hashlib.sha256(vorher.encode() + b"\n" + kanonisch(koerper)).hexdigest()


def jsonl_lesen(datei: Path) -> list[dict]:
    if not datei.is_file():
        return []
    return [json.loads(z) for z in datei.read_text(encoding="utf-8").splitlines() if z.strip()]


protokoll_lesen = jsonl_lesen


def fall_pfad(fall_id: str) -> Path:
    if not FALL_RE.match(fall_id or ""):
        raise ValueError(f"Ungültige Fall-ID '{fall_id}'. Erlaubt: Buchstaben, Ziffern, Punkt, Strich, Unterstrich (3–64 Zeichen).")
    return FAELLE / fall_id


def fall_daten(fall_id: str) -> dict:
    datei = fall_pfad(fall_id) / "fall.json"
    if not datei.is_file():
        raise FileNotFoundError(f"Fall '{fall_id}' existiert nicht (erwartet: {datei}).")
    return json.loads(datei.read_text(encoding="utf-8"))


def freigabe_erteilt(daten: dict, name: str) -> bool:
    e = (daten.get("freigaben") or {}).get(name) or {}
    return bool(e.get("erteilt")) and bool(str(e.get("durch") or "").strip())


def sha256_datei(pfad: Path) -> str:
    h = hashlib.sha256()
    with open(pfad, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def ursprung_extern(fall_id: str) -> str:
    return hashlib.sha256(f"osint-gateway|{fall_id}|extern".encode()).hexdigest()


def _kette_einer_datei(pfad: Path, datei: Path, start: str, kuerzel: str) -> tuple[list[str], int, str | None]:
    eintraege = jsonl_lesen(datei)
    fehler: list[str] = []
    vorher = start
    for i, e in enumerate(eintraege, 1):
        kennung = e.get("id", f"{kuerzel} Zeile {i}")
        if e.get("nr") != i:
            fehler.append(f"{kennung}: Nummernfolge unterbrochen (erwartet {i}, gefunden {e.get('nr')}).")
        if e.get("vorher") != vorher:
            fehler.append(f"{kennung}: Verkettung gebrochen. Davor wurde ein Eintrag verändert, entfernt oder eingefügt.")
        if kette(e.get("vorher", ""), e) != e.get("kette"):
            fehler.append(f"{kennung}: Inhalt passt nicht zum Hash. Der Eintrag wurde nachträglich verändert.")
        antwort = e.get("antwort") or {}
        if antwort.get("rohdaten"):
            roh = pfad / antwort["rohdaten"]
            if not roh.is_file():
                fehler.append(f"{kennung}: Rohdatei fehlt ({antwort['rohdaten']}).")
            elif sha256_datei(roh) != antwort.get("sha256"):
                fehler.append(f"{kennung}: Rohdatei wurde verändert ({antwort['rohdaten']}).")
        vorher = e.get("kette", "")
    return fehler, len(eintraege), (vorher if eintraege else None)


def kette_pruefen(fall_id: str) -> dict:
    """Prüft Verkettung, Nummernfolge und die Hashes aller Rohdateien, für beide Protokolle der Fallakte:
    abfragen.jsonl (Gateway, Belege P-…) und extern.jsonl (weitere MCP-Server wie Robin, Belege X-…).

    Rückgabe: {"ok", "anzahl", "letzter_hash", "anzahl_extern", "letzter_hash_extern", "fehler": [...]}
    """
    pfad = fall_pfad(fall_id)
    f1, n1, h1 = _kette_einer_datei(pfad, pfad / "protokoll" / "abfragen.jsonl", ursprung(fall_id), "P")
    f2, n2, h2 = _kette_einer_datei(pfad, pfad / "protokoll" / "extern.jsonl", ursprung_extern(fall_id), "X")
    return {"ok": not (f1 or f2), "anzahl": n1, "letzter_hash": h1, "anzahl_extern": n2,
            "letzter_hash_extern": h2, "fehler": f1 + f2}


def belege_lesen(fall_id: str) -> list[dict]:
    """Alle belegfähigen Einträge der Fallakte: Gateway-Abfragen (P-…) und externe Antworten (X-…)."""
    pfad = fall_pfad(fall_id) / "protokoll"
    return jsonl_lesen(pfad / "abfragen.jsonl") + jsonl_lesen(pfad / "extern.jsonl")
