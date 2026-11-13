#!/usr/bin/env python3
"""Fallakten verwalten: anlegen, Dokumente aufnehmen, Freigaben erteilen.

    python3 tools/fall.py neu 2026-0412 --titel "Phishing Kundenportal" --rapport rapport.md
    python3 tools/fall.py aufnehmen 2026-0412 nachtrag.docx
    python3 tools/fall.py freigabe 2026-0412 darkweb --durch "Kürzel/Funktion" --vermerk "Verfügung vom …"
    python3 tools/fall.py status 2026-0412
    python3 tools/fall.py liste

Dokumente durchlaufen vor der Aufnahme die PII-Prüfung (tools/pii_pruefung.py).
Freigaben und das Übersteuern der PII-Prüfung verlangen eine Bestätigung am Terminal.
Ein Agent kann sie deshalb nicht selbst erteilen.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import (FAELLE, FREIGABE_TEXT, FREIGABEN, fall_daten, fall_pfad, freigabe_erteilt,  # noqa: E402
                          jsonl_lesen, sha256_datei)
from tools.pii_pruefung import NichtLesbar, bericht, pruefen, text_lesen  # noqa: E402

UNTERORDNER = ("eingang", "protokoll", "rohdaten", "arbeitsstand", "rapport")


class Fehler(Exception):
    pass


def jetzt() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def schreiben(datei: Path, daten: dict) -> None:
    plattform.text_schreiben(datei, json.dumps(daten, ensure_ascii=False, indent=2) + "\n")


def am_terminal_bestaetigen(frage: str, erwartet: str) -> None:
    """Verlangt eine Eingabe am Terminal. Ohne Terminal (Agent, Skript) wird abgelehnt."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Fehler("Diese Entscheidung trifft ein Mensch am Terminal. Ohne Terminal wird sie nicht angenommen.\n"
                     "Bitte den Befehl selbst in einer Shell ausführen."
                     + ("\nUnter Windows in PowerShell oder der Eingabeaufforderung, nicht im Fenster von Git Bash."
                        if plattform.WINDOWS else ""))
    antwort = input(f"{frage}\nZur Bestätigung '{erwartet}' eingeben: ").strip()
    if antwort != erwartet:
        raise Fehler("Nicht bestätigt. Es wurde nichts geändert.")


def aufnehmen(fall_id: str, dateien: list[str], trotzdem: str | None, durch: str | None) -> bool:
    """Prüft Dokumente und legt sie in eingang/ ab. Gibt False zurück, wenn etwas gesperrt blieb."""
    pfad = fall_pfad(fall_id)
    eingang = pfad / "eingang"
    eingang.mkdir(parents=True, exist_ok=True)
    register_datei = eingang / ".freigabe.json"
    register = json.loads(register_datei.read_text(encoding="utf-8")) if register_datei.is_file() else {"dateien": {}}
    alles_gut = True
    for arg in dateien:
        quelle = Path(arg).expanduser()
        if not quelle.is_file():
            raise Fehler(f"Datei nicht gefunden: {arg}")
        try:
            text = text_lesen(quelle)
        except NichtLesbar as e:
            raise Fehler(str(e)) from e
        funde, platzhalter = pruefen(text)
        print(bericht(quelle.name, funde, platzhalter))
        sperren = [f for f in funde if f.stufe == "sperre"]
        ergebnis = "sauber"
        if sperren:
            if not trotzdem:
                print(f"→ {quelle.name} NICHT aufgenommen. Bitte im Haus nachpseudonymisieren und erneut aufnehmen.\n"
                      "  Fehlalarm? Dann am Terminal mit --trotzdem \"Begründung\" --durch \"Kürzel\" übersteuern.\n")
                alles_gut = False
                continue
            if not durch:
                raise Fehler("--trotzdem verlangt --durch (wer übersteuert).")
            am_terminal_bestaetigen(
                f"{len(sperren)} Sperrfund(e) in {quelle.name} werden übersteuert. Das Dokument geht so an das Sprachmodell.",
                fall_id)
            ergebnis = "uebersteuert"
        # Agenten lesen immer die Textfassung. Das Original bleibt daneben liegen.
        ziel = eingang / quelle.name
        if ziel.resolve() != quelle.resolve():
            shutil.copy2(quelle, ziel)
        lesefassung = ziel
        if quelle.suffix.lower() in (".docx", ".pdf"):
            lesefassung = eingang / f"{quelle.name}.txt"
            plattform.text_schreiben(lesefassung, text)
        for datei in {ziel, lesefassung}:
            register["dateien"][datei.name] = {
                "sha256": sha256_datei(datei), "geprueft": jetzt(), "ergebnis": ergebnis,
                "hinweise": sum(1 for f in funde if f.stufe == "hinweis"),
                **({"durch": durch, "begruendung": trotzdem} if ergebnis == "uebersteuert" else {})}
        print(f"→ aufgenommen: faelle/{fall_id}/eingang/{lesefassung.name}\n")
    schreiben(register_datei, register)
    return alles_gut


def cmd_neu(a: argparse.Namespace) -> int:
    pfad = fall_pfad(a.fall)
    if (pfad / "fall.json").exists():
        raise Fehler(f"Fall '{a.fall}' gibt es schon. Weitere Dokumente: {plattform.PY} tools/fall.py aufnehmen {a.fall} DATEI")
    for name in UNTERORDNER:
        (pfad / name).mkdir(parents=True, exist_ok=True)
    schreiben(pfad / "fall.json", {
        "fall_id": a.fall, "titel": a.titel or a.fall, "auftrag": a.auftrag or "",
        "sachbearbeiter": a.kuerzel or "", "klassifizierung": a.klassifizierung, "eroeffnet": jetzt(),
        "freigaben": {n: {"erteilt": False, "durch": "", "am": "", "vermerk": ""} for n in FREIGABEN}})
    print(f"Fall {a.fall} angelegt: {pfad}\n")
    ok = aufnehmen(a.fall, a.rapport or [], None, None) if a.rapport else True
    if not ok:
        print("Der Fall ist angelegt, aber mindestens ein Dokument wurde nicht aufgenommen.\n"
              f"Nach dem Nachpseudonymisieren: {plattform.PY} tools/fall.py aufnehmen {a.fall} <Datei>")
        return 1
    if not a.rapport:
        print(f"Noch kein Dokument im Fall. Aufnehmen: {plattform.PY} tools/fall.py aufnehmen {a.fall} <Datei>")
    print("Nächster Schritt: 'claude' im Projektordner starten und eingeben:\n"
          f"    /ermittlung {a.fall}\n"
          f"Freigaben (aktiv, darkweb, personenbezug) sind aus. Erteilen: {plattform.PY} tools/fall.py freigabe …")
    return 0


def cmd_aufnehmen(a: argparse.Namespace) -> int:
    fall_daten(a.fall)
    return 0 if aufnehmen(a.fall, a.dateien, a.trotzdem, a.durch) else 1


def cmd_freigabe(a: argparse.Namespace) -> int:
    daten = fall_daten(a.fall)
    freigaben = daten.setdefault("freigaben", {})
    if a.entziehen:
        freigaben[a.art] = {"erteilt": False, "durch": "", "am": "", "vermerk": f"entzogen am {jetzt()}"}
        schreiben(fall_pfad(a.fall) / "fall.json", daten)
        print(f"Freigabe '{a.art}' für {a.fall} entzogen.")
        return 0
    if not a.durch or not a.vermerk:
        raise Fehler("Eine Freigabe braucht --durch (wer verantwortet sie) und --vermerk (Grundlage, z. B. Auftrag oder Verfügung).")
    am_terminal_bestaetigen(f"Freigabe '{a.art}' für Fall {a.fall}: {FREIGABE_TEXT[a.art]}", a.fall)
    freigaben[a.art] = {"erteilt": True, "durch": a.durch, "am": jetzt(), "vermerk": a.vermerk}
    schreiben(fall_pfad(a.fall) / "fall.json", daten)
    print(f"Freigabe '{a.art}' für {a.fall} erteilt durch {a.durch}.")
    return 0


def _zeile(fall_id: str) -> str:
    daten = fall_daten(fall_id)
    n = len(jsonl_lesen(fall_pfad(fall_id) / "protokoll" / "abfragen.jsonl"))
    frei = ", ".join(f for f in FREIGABEN if freigabe_erteilt(daten, f)) or "keine"
    return f"{fall_id:<24} {n:>4} Abfragen   Freigaben: {frei:<32} {daten.get('titel', '')}"


def cmd_status(a: argparse.Namespace) -> int:
    daten = fall_daten(a.fall)
    pfad = fall_pfad(a.fall)
    print(_zeile(a.fall))
    print(f"  eröffnet: {daten.get('eroeffnet')}   Sachbearbeiter: {daten.get('sachbearbeiter') or '–'}")
    for name in FREIGABEN:
        e = (daten.get("freigaben") or {}).get(name) or {}
        stand = f"erteilt durch {e.get('durch')} am {e.get('am')} ({e.get('vermerk')})" if freigabe_erteilt(daten, name) else "nicht erteilt"
        print(f"  Freigabe {name:<14} {stand}")
    eingang = [p.name for p in sorted((pfad / "eingang").glob("*")) if p.is_file() and not p.name.startswith(".")]
    print(f"  Eingang: {', '.join(eingang) or 'leer'}")
    for name in ("Abschlussrapport.html", "Ermittlungsprotokoll.html"):
        datei = pfad / "rapport" / name
        print(f"  {name}: {'vorhanden' if datei.is_file() else 'noch nicht erstellt'}")
    return 0


def cmd_liste(_: argparse.Namespace) -> int:
    faelle = sorted(p.parent.name for p in FAELLE.glob("*/fall.json"))
    if not faelle:
        print(f"Noch keine Fälle. Anlegen: {plattform.PY} tools/fall.py neu <Fall-ID> --titel \"…\" --rapport DATEI")
    for f in faelle:
        print(_zeile(f))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Fallakten verwalten.", formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    sub = p.add_subparsers(dest="befehl", required=True)

    n = sub.add_parser("neu", help="Fall anlegen und Dokumente aufnehmen")
    n.add_argument("fall", help="Fall-ID, z. B. 2026-0412")
    n.add_argument("--titel")
    n.add_argument("--auftrag", help="Ermittlungsauftrag in ein bis zwei Sätzen, ohne Personendaten")
    n.add_argument("--kuerzel", help="Kürzel des Sachbearbeiters")
    n.add_argument("--klassifizierung", default="INTERN")
    n.add_argument("--rapport", nargs="+", metavar="DATEI", help="pseudonymisierte Dokumente (.txt .md .docx .pdf)")
    n.set_defaults(func=cmd_neu)

    au = sub.add_parser("aufnehmen", help="weitere Dokumente in einen Fall aufnehmen")
    au.add_argument("fall")
    au.add_argument("dateien", nargs="+")
    au.add_argument("--trotzdem", metavar="BEGRÜNDUNG", help="Sperrfunde der PII-Prüfung übersteuern (nur am Terminal)")
    au.add_argument("--durch", metavar="KÜRZEL")
    au.set_defaults(func=cmd_aufnehmen)

    fr = sub.add_parser("freigabe", help="Freigabe erteilen oder entziehen (nur am Terminal)")
    fr.add_argument("fall")
    fr.add_argument("art", choices=FREIGABEN)
    fr.add_argument("--durch", help="wer die Freigabe verantwortet")
    fr.add_argument("--vermerk", help="Grundlage der Freigabe")
    fr.add_argument("--entziehen", action="store_true")
    fr.set_defaults(func=cmd_freigabe)

    st = sub.add_parser("status", help="Stand eines Falls")
    st.add_argument("fall")
    st.set_defaults(func=cmd_status)

    sub.add_parser("liste", help="alle Fälle").set_defaults(func=cmd_liste)

    a = p.parse_args()
    try:
        return a.func(a)
    except (Fehler, ValueError, FileNotFoundError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
