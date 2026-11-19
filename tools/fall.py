#!/usr/bin/env python3
"""Fallakten verwalten: anlegen, Dokumente aufnehmen, Freigaben erteilen.

    python3 tools/fall.py neu 2026-0412 --titel "Phishing Kundenportal" --rapport rapport.md
    python3 tools/fall.py aufnehmen 2026-0412 nachtrag.docx
    python3 tools/fall.py freigabe 2026-0412 darkweb --durch "Kürzel/Funktion" --vermerk "Verfügung vom …"
    python3 tools/fall.py quellen 2026-0412                         zeigt, welche Quellen sich vorgeben lassen und was vorgegeben ist
    python3 tools/fall.py quellen 2026-0412 --pflicht "Shodan, VirusTotal"      (oder --alle, oder --keine)
    python3 tools/fall.py entfernen 2026-0412 nachtrag.docx --durch "Kürzel" --grund "falsches Dokument"
    python3 tools/fall.py loeschen 2026-0413 --durch "Kürzel"      (nur solange noch nichts abgefragt wurde)
    python3 tools/fall.py status 2026-0412
    python3 tools/fall.py liste

Dokumente durchlaufen vor der Aufnahme die PII-Prüfung (tools/pii_pruefung.py).
Freigaben, Pflichtquellen, das Übersteuern der PII-Prüfung, das Entfernen von Dokumenten und das Löschen eines Falls
verlangen eine Bestätigung am Terminal. Ein Agent kann sie deshalb nicht selbst auslösen. Dieselben Schritte gibt es in der
Oberfläche (tools/oberflaeche.py), dort mit dem Geheimnis ihres Starts.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import pflichtquellen, plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import (FAELLE, FREIGABE_TEXT, FREIGABEN, eingang_stand, fall_daten, fall_pfad, freigabe_erteilt,  # noqa: E402
                          jsonl_lesen, sha256_datei)
from tools.pii_pruefung import GEWANDELT, NichtLesbar, bericht, pruefen, text_lesen  # noqa: E402

UNTERORDNER = ("eingang", "protokoll", "rohdaten", "arbeitsstand", "rapport")
WEGE = ("Terminal", "Oberfläche")       # wie eine Entscheidung des Sachbearbeiters zustande kam


class Fehler(Exception):
    pass


def jetzt() -> str:
    """Jetzt, in der Zeitzone des Arbeitsplatzes (OSINT_ZEITZONE, sonst Europe/Zurich): dieselbe wie in Protokoll und Rapport."""
    try:
        return datetime.now(plattform.zeitzone()).isoformat(timespec="seconds")
    except plattform.Zeitzonenfehler:       # ohne Zeitzonendaten: die Zeit des Systems, wie bisher
        return datetime.now().astimezone().isoformat(timespec="seconds")


def schreiben(datei: Path, daten: dict) -> None:
    plattform.text_schreiben(datei, json.dumps(daten, ensure_ascii=False, indent=2) + "\n")


def am_terminal_bestaetigen(frage: str, erwartet: str) -> None:
    """Verlangt eine Eingabe am Terminal. Ohne Terminal (Agent, Skript) wird abgelehnt."""
    if not plattform.terminal(sys.stdin, sys.stdout):
        raise Fehler("Diese Entscheidung trifft ein Mensch am Terminal. Ohne Terminal wird sie nicht angenommen.\n"
                     "Bitte den Befehl selbst in einer Shell ausführen."
                     + ("\nUnter Windows in PowerShell oder der Eingabeaufforderung, nicht im Fenster von Git Bash."
                        if plattform.WINDOWS else ""))
    antwort = input(f"{frage}\nZur Bestätigung '{erwartet}' eingeben: ").strip()
    if antwort != erwartet:
        raise Fehler("Nicht bestätigt. Es wurde nichts geändert.")


def aufnehmen(fall_id: str, dateien: list[str], trotzdem: str | None, durch: str | None, *, weg: str = "Terminal") -> bool:
    """Prüft Dokumente und legt sie in eingang/ ab. Gibt False zurück, wenn etwas gesperrt blieb. Mit `trotzdem` (Begründung)
    und `durch` nimmt ein Mensch ein Dokument trotz Sperrfund auf und übernimmt damit das Risiko: am Terminal nach einer
    Eingabe von Hand, aus der Oberfläche nach einer Anfrage mit dem Geheimnis (Entscheid des Eigentümers vom 19.11.2026).
    Wer das auslöst, entscheidet dort der Aufrufer. Das Register hält fest, wer es war, warum und auf welchem Weg."""
    if weg not in WEGE:
        raise Fehler(f"Unbekannter Weg '{weg}'.")
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
            if weg == "Terminal":
                am_terminal_bestaetigen(
                    f"{len(sperren)} Sperrfund(e) in {quelle.name} werden übersteuert. Das Dokument geht so an das Sprachmodell.",
                    fall_id)
            ergebnis = "uebersteuert"
        # Agenten lesen immer die Textfassung. Das Original bleibt daneben liegen.
        ziel = eingang / quelle.name
        if ziel.resolve() != quelle.resolve():
            if ziel.exists():
                # Ein Dokument im Eingang wird nie stillschweigend überschrieben: Agenten können es schon gelesen haben
                if sha256_datei(ziel) == sha256_datei(quelle):
                    print(f"→ {quelle.name} liegt schon unverändert im Eingang.\n")
                else:
                    print(f"→ {quelle.name} NICHT aufgenommen: Im Eingang liegt schon ein anderes Dokument mit diesem Namen.\n"
                          f"  Unter anderem Namen aufnehmen, oder das alte zuerst entfernen: {plattform.PY} tools/fall.py entfernen {fall_id} {quelle.name} …\n")
                    alles_gut = False
                continue
            shutil.copy2(quelle, ziel)
        lesefassung = ziel
        if quelle.suffix.lower() in GEWANDELT:
            lesefassung = eingang / f"{quelle.name}.txt"
            plattform.text_schreiben(lesefassung, text)
        for datei in {ziel, lesefassung}:
            register["dateien"][datei.name] = {
                "sha256": sha256_datei(datei), "geprueft": jetzt(), "ergebnis": ergebnis,
                "hinweise": sum(1 for f in funde if f.stufe == "hinweis"),
                **({"durch": durch, "begruendung": trotzdem, "weg": weg, "sperrfunde": len(sperren)} if ergebnis == "uebersteuert" else {})}
        print(f"→ aufgenommen: faelle/{fall_id}/eingang/{lesefassung.name}\n")
    schreiben(register_datei, register)
    return alles_gut


def entfernen(fall_id: str, namen: list[str], *, durch: str, grund: str, weg: str = "Terminal") -> list[str]:
    """Nimmt Dokumente wieder aus dem Eingang eines Falls: die Datei, ihre Lesefassung und den Eintrag im Register.
    Das Register hält unter «entfernt» fest, was wann von wem und warum entfernt wurde: Name und Prüfsumme, nie den Inhalt.
    Auch ein Dokument, das von Hand hineinkopiert wurde, lässt sich so bereinigen. Von ihm bleibt nur die Prüfsumme: Sein Name
    wurde nie geprüft und kann eine Person nennen. Wer das Entfernen auslöst, entscheidet der Aufrufer:
    cmd_entfernen verlangt ein Terminal, die Oberfläche das Geheimnis ihres Starts."""
    if weg not in WEGE:
        raise Fehler(f"Unbekannter Weg '{weg}'.")
    fall_daten(fall_id)
    durch, grund = " ".join((durch or "").split()), " ".join((grund or "").split())
    if not durch or not grund:
        raise Fehler("Entfernen braucht --durch (wer entfernt) und --grund (warum).")
    eingang = fall_pfad(fall_id) / "eingang"
    register_datei = eingang / ".freigabe.json"
    register = json.loads(register_datei.read_text(encoding="utf-8")) if register_datei.is_file() else {"dateien": {}}
    weg_damit: list[Path] = []
    for name in namen:
        if not name or Path(name).name != name or name.startswith("."):
            raise Fehler(f"'{name}' ist kein Dateiname im Eingang.")
        datei = eingang / name
        if not datei.is_file():
            raise Fehler(f"'{name}' liegt nicht im Eingang von Fall {fall_id}.")
        # Original und Lesefassung gehören zusammen: rapport.docx und rapport.docx.txt
        paar = [datei, eingang / f"{name}.txt"] + ([eingang / name[:-4]] if name.endswith(".txt") and (eingang / name[:-4]).suffix.lower() in GEWANDELT else [])
        weg_damit += [d for d in paar if d.is_file() and d not in weg_damit]
    entfernt = []
    for datei in weg_damit:
        eintrag = register.get("dateien", {}).pop(datei.name, None)
        register.setdefault("entfernt", []).append({
            "name": datei.name if eintrag else "(ungeprüftes Dokument)", "sha256": sha256_datei(datei), "am": jetzt(), "durch": durch, "grund": grund,
            "geprueft": bool(eintrag), **({"weg": weg} if weg != "Terminal" else {})})
        datei.unlink()
        entfernt.append(datei.name)
    schreiben(register_datei, register)
    return entfernt


def loeschbar(fall_id: str) -> str:
    """Leer, wenn sich der Fall löschen lässt. Sonst der Grund: Sobald etwas abgefragt wurde, ist die Akte Beweismaterial."""
    daten = fall_daten(fall_id)
    pfad = fall_pfad(fall_id)
    if daten.get("muster"):
        return "Der Musterfall gehört zum Projekt und wird nicht gelöscht."
    eintraege = len(jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl")) + len(jsonl_lesen(pfad / "protokoll" / "extern.jsonl"))
    if eintraege:
        return (f"In Fall {fall_id} stehen {eintraege} Protokolleinträge. Was abgefragt wurde, bleibt als Beleg in der Akte: "
                "Ein solcher Fall wird nicht gelöscht.")
    if (pfad / "rohdaten").is_dir() and any(d.is_file() for d in (pfad / "rohdaten").rglob("*")):
        return f"In Fall {fall_id} liegen Rohdaten. Ein solcher Fall wird nicht gelöscht."
    if (pfad / "befunde.json").is_file():
        return f"Fall {fall_id} hat Befunde. Ein solcher Fall wird nicht gelöscht."
    return ""


def loeschen(fall_id: str, *, durch: str, weg: str = "Terminal") -> None:
    """Löscht einen Fall, in dem noch nichts abgefragt wurde: aus Versehen angelegt, falsche Fall-ID."""
    if weg not in WEGE:
        raise Fehler(f"Unbekannter Weg '{weg}'.")
    if not " ".join((durch or "").split()):
        raise Fehler("Löschen braucht --durch (wer löscht).")
    grund = loeschbar(fall_id)
    if grund:
        raise Fehler(grund)
    plattform.baum_loeschen(fall_pfad(fall_id))


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
    print(f"Nächster Schritt: die Oberfläche starten ({plattform.PY} tools/oberflaeche.py {a.fall}) und dort ermitteln.\n"
          f"Oder am Terminal: 'claude' im Projektordner starten und eingeben:   /ermittlung {a.fall}\n"
          f"Freigaben (aktiv, darkweb, personenbezug) sind aus. Erteilen: in der Oberfläche oder mit {plattform.PY} tools/fall.py freigabe …")
    return 0


def cmd_aufnehmen(a: argparse.Namespace) -> int:
    fall_daten(a.fall)
    return 0 if aufnehmen(a.fall, a.dateien, a.trotzdem, a.durch) else 1


def cmd_entfernen(a: argparse.Namespace) -> int:
    fall_daten(a.fall)
    if not a.durch or not a.grund:
        raise Fehler("Entfernen braucht --durch (wer entfernt) und --grund (warum).")
    am_terminal_bestaetigen(f"{len(a.dateien)} Dokument(e) werden aus dem Eingang von Fall {a.fall} entfernt: {', '.join(a.dateien)}", a.fall)
    for name in entfernen(a.fall, a.dateien, durch=a.durch, grund=a.grund):
        print(f"→ entfernt: faelle/{a.fall}/eingang/{name}")
    return 0


def cmd_loeschen(a: argparse.Namespace) -> int:
    grund = loeschbar(a.fall)
    if grund:
        raise Fehler(grund)
    am_terminal_bestaetigen(f"Fall {a.fall} wird mit allen Dokumenten im Eingang gelöscht. Abgefragt wurde darin noch nichts.", a.fall)
    loeschen(a.fall, durch=a.durch or "")
    print(f"Fall {a.fall} gelöscht.")
    return 0


def freigabe_setzen(fall_id: str, art: str, *, durch: str = "", vermerk: str = "", entziehen: bool = False, weg: str = "Terminal") -> dict:
    """Erteilt oder entzieht eine Freigabe und schreibt fall.json. Die Entscheidung selbst trifft ein Mensch: am Terminal
    (cmd_freigabe fragt dort nach) oder in der Oberfläche (der Server ruft diese Funktion erst, wenn die Anfrage das Geheimnis
    seines Starts trägt). `weg` steht in fall.json, damit sichtbar bleibt, wie die Freigabe zustande kam.
    Der Befehl am Terminal ist für Agenten gesperrt (er verlangt ein Terminal, und die Berechtigungen verbieten ihn). Der Aufruf
    dieser Funktion aus einem Shell-Befehl steht auf keiner Erlaubt-Liste: Claude Code fragt dafür den Menschen."""
    if art not in FREIGABEN:
        raise Fehler(f"Die Freigabe '{art}' gibt es nicht. Möglich: {', '.join(FREIGABEN)}.")
    if weg not in WEGE:
        raise Fehler(f"Unbekannter Weg '{weg}'.")
    daten = fall_daten(fall_id)
    freigaben = daten.setdefault("freigaben", {})
    if entziehen:
        freigaben[art] = {"erteilt": False, "durch": "", "am": "", "vermerk": f"entzogen am {jetzt()}",
                          **({"weg": weg} if weg != "Terminal" else {})}
    else:
        durch, vermerk = " ".join((durch or "").split()), " ".join((vermerk or "").split())
        if not durch or not vermerk:
            raise Fehler("Eine Freigabe braucht --durch (wer verantwortet sie) und --vermerk (Grundlage, z. B. Auftrag oder Verfügung).")
        freigaben[art] = {"erteilt": True, "durch": durch, "am": jetzt(), "vermerk": vermerk, **({"weg": weg} if weg != "Terminal" else {})}
    schreiben(fall_pfad(fall_id) / "fall.json", daten)
    return freigaben[art]


def cmd_freigabe(a: argparse.Namespace) -> int:
    fall_daten(a.fall)
    if a.entziehen:
        freigabe_setzen(a.fall, a.art, entziehen=True)
        print(f"Freigabe '{a.art}' für {a.fall} entzogen.")
        return 0
    if not a.durch or not a.vermerk:
        raise Fehler("Eine Freigabe braucht --durch (wer verantwortet sie) und --vermerk (Grundlage, z. B. Auftrag oder Verfügung).")
    am_terminal_bestaetigen(f"Freigabe '{a.art}' für Fall {a.fall}: {FREIGABE_TEXT[a.art]}", a.fall)
    freigabe_setzen(a.fall, a.art, durch=a.durch, vermerk=a.vermerk)
    print(f"Freigabe '{a.art}' für {a.fall} erteilt durch {a.durch}.")
    return 0


def pflichtquellen_pruefen(daten: dict, namen: list[str]) -> list[str]:
    """Prüft eine Auswahl von Pflichtquellen und gibt sie bereinigt zurück, in der Reihenfolge des Verzeichnisses. Vorgeben lässt
    sich nur, was es gibt, was an diesem Arbeitsplatz bereit ist und wofür der Fall die nötige Freigabe hat."""
    gewuenscht = list(dict.fromkeys(" ".join(str(n).split()) for n in namen if str(n).strip()))
    verzeichnis = {w["name"]: w for w in pflichtquellen.waehlbar(daten)}
    unbekannt = [n for n in gewuenscht if n not in verzeichnis]
    if unbekannt:
        raise Fehler(f"Diese Quelle gibt es nicht: {', '.join(unbekannt)}. Möglich: {', '.join(verzeichnis)}.")
    nicht_bereit = [f"{n} ({verzeichnis[n]['grund']})" for n in gewuenscht if not verzeichnis[n]["bereit"]]
    if nicht_bereit:
        raise Fehler(f"Nicht bereit und deshalb keine Pflichtquelle: {', '.join(nicht_bereit)}. Einrichten oder aus der Auswahl nehmen.")
    ohne = [n for n in gewuenscht if verzeichnis[n]["freigabe_fehlt"]]
    if ohne:
        raise Fehler(f"{', '.join(ohne)} braucht die Freigabe '{verzeichnis[ohne[0]]['freigabe']}' des Falls. Zuerst die Freigabe erteilen oder die Quelle "
                     "aus der Auswahl nehmen. Eine Pflichtquelle ersetzt keine Freigabe.")
    return [n for n in pflichtquellen.reihenfolge() if n in gewuenscht]


def pflichtquellen_setzen(fall_id: str, namen: list[str], *, durch: str = "", weg: str = "Terminal") -> dict:
    """Gibt die Pflichtquellen eines Falls vor und schreibt fall.json. Eine leere Liste hebt die Vorgabe auf. Was vorgegeben ist,
    muss die Ermittlung abfragen (gateway/pflichtquellen.py), und der Rapport lässt sich sonst nicht abschliessen.
    Die Entscheidung trifft ein Mensch, wie bei einer Freigabe: am Terminal (cmd_quellen fragt dort nach) oder in der
    Oberfläche. Ein Agent kann eine Vorgabe weder setzen noch aufheben: Der Befehl verlangt ein Terminal, und die
    Berechtigungen verbieten ihn."""
    if weg not in WEGE:
        raise Fehler(f"Unbekannter Weg '{weg}'.")
    daten = fall_daten(fall_id)
    quellen = pflichtquellen_pruefen(daten, namen)
    if not quellen:
        daten.pop(pflichtquellen.SCHLUESSEL, None)
        schreiben(fall_pfad(fall_id) / "fall.json", daten)
        return {}
    eintrag = {"quellen": quellen, "am": jetzt(), "durch": " ".join((durch or daten.get("sachbearbeiter") or "").split()),
               **({"weg": weg} if weg != "Terminal" else {})}
    daten[pflichtquellen.SCHLUESSEL] = eintrag
    schreiben(fall_pfad(fall_id) / "fall.json", daten)
    return eintrag


def _pflicht_zeile(daten: dict) -> str:
    quellen = pflichtquellen.vorgabe(daten)
    e = daten.get(pflichtquellen.SCHLUESSEL) or {}
    if not quellen:
        return "keine Vorgabe: Das Team wählt die Quellen selbst"
    return (f"{', '.join(quellen)}   (vorgegeben am {e.get('am')}" + (f" durch {e.get('durch')}" if e.get("durch") else "")
            + (f", über die {e.get('weg')}" if e.get("weg") else "") + ")")


def cmd_quellen(a: argparse.Namespace) -> int:
    daten = fall_daten(a.fall)
    verzeichnis = pflichtquellen.waehlbar(daten)
    gewaehlt = sum(1 for x in (a.pflicht is not None, a.alle, a.keine) if x)
    if gewaehlt > 1:
        raise Fehler("Bitte nur eines von --pflicht, --alle und --keine.")
    if not gewaehlt:
        vorgegeben = set(pflichtquellen.vorgabe(daten))
        print(f"Pflichtquellen für {a.fall}: {_pflicht_zeile(daten)}")
        for w in verzeichnis:
            hindernis = (f"nicht bereit: {w['grund']}" if not w["bereit"] else f"braucht die Freigabe {w['freigabe']}" if w["freigabe_fehlt"] else "")
            print(f"  [{'x' if w['name'] in vorgegeben else ' '}] {w['name']:<26} {w['gruppe']:<15} {hindernis or w['faellig']}")
        pfad = fall_pfad(a.fall)
        stand = pflichtquellen.stand_fuer(daten, pfad, jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl") + jsonl_lesen(pfad / "protokoll" / "extern.jsonl"))
        if stand:
            z = stand["zahlen"]
            print(f"  Stand: {z['erfuellt']} von {z['faellig']} fälligen Abfragen erfüllt, {z['fehlgeschlagen']} fehlgeschlagen, {z['offen']} offen."
                  + ("" if stand["bekannt"] else " Die Indikatoren des Falls stehen noch nicht fest."))
            for zeile in stand["zeilen"]:
                if zeile["stand"] in ("offen", "fehlgeschlagen"):
                    wo = "" if zeile["einmal"] else " für " + ", ".join(zeile["offen"] or zeile["fehlgeschlagen"])
                    print(f"    {pflichtquellen.STAND_WORT[zeile['stand']]}: {zeile['quelle']}{wo}" + (f"  ({zeile['grund']})" if zeile["grund"] else ""))
        print(f"  Ändern (nur am Terminal): {plattform.PY} tools/fall.py quellen {a.fall} --pflicht \"Quelle, Quelle\"   oder --alle   oder --keine")
        return 0
    if a.alle:
        namen = [w["name"] for w in verzeichnis if w["bereit"] and not w["freigabe_fehlt"]]
        aus = [f"{w['name']} ({'nicht bereit: ' + w['grund'] if not w['bereit'] else 'Freigabe ' + w['freigabe'] + ' fehlt'})"
               for w in verzeichnis if not w["bereit"] or w["freigabe_fehlt"]]
        if aus:
            print("Nicht dabei: " + ", ".join(aus))
    elif a.keine:
        namen = []
    else:
        namen = [n for n in a.pflicht.split(",") if n.strip()]
        if not namen:
            raise Fehler("--pflicht braucht mindestens einen Namen. Die Vorgabe aufheben: --keine.")
    quellen = pflichtquellen_pruefen(daten, namen)
    am_terminal_bestaetigen(f"Pflichtquellen für Fall {a.fall}: " + (", ".join(quellen) if quellen else "keine. Die Vorgabe wird aufgehoben")
                            + ".\nWas vorgegeben ist, muss die Ermittlung für jeden passenden Indikator abfragen.", a.fall)
    eintrag = pflichtquellen_setzen(a.fall, quellen, durch=a.durch or "")
    print(f"Pflichtquellen für {a.fall}: " + (", ".join(eintrag["quellen"]) if eintrag else "keine Vorgabe mehr."))
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
    print(f"  Pflichtquellen: {_pflicht_zeile(daten)}")
    eingang, ungeprueft = eingang_stand(pfad)
    print(f"  Eingang: {', '.join(eingang) or 'leer'}")
    if ungeprueft:
        print(f"  NICHT GEPRÜFT (von Hand kopiert oder nachträglich verändert): {', '.join(ungeprueft)}\n"
              f"    Aufnehmen mit PII-Prüfung: {plattform.PY} tools/fall.py aufnehmen {a.fall} faelle/{a.fall}/eingang/<Datei>")
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
    n.add_argument("--rapport", nargs="+", metavar="DATEI", help="pseudonymisierte Dokumente (Text, .docx, .pdf, .odt, .xlsx, .pptx, .rtf, .eml)")
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

    qu = sub.add_parser("quellen", help="Pflichtquellen zeigen oder vorgeben (vorgeben nur am Terminal)")
    qu.add_argument("fall")
    qu.add_argument("--pflicht", metavar="NAMEN", help="Quellen, die die Ermittlung abfragen muss, durch Komma getrennt")
    qu.add_argument("--alle", action="store_true", help="alle Quellen vorgeben, die bereit sind und deren Freigabe erteilt ist")
    qu.add_argument("--keine", action="store_true", help="die Vorgabe aufheben: Das Team wählt die Quellen selbst")
    qu.add_argument("--durch", metavar="KÜRZEL", help="wer vorgibt")
    qu.set_defaults(func=cmd_quellen)

    en = sub.add_parser("entfernen", help="Dokumente wieder aus dem Eingang nehmen (nur am Terminal)")
    en.add_argument("fall")
    en.add_argument("dateien", nargs="+", help="Dateinamen im Eingang")
    en.add_argument("--durch", metavar="KÜRZEL", help="wer entfernt")
    en.add_argument("--grund", help="warum")
    en.set_defaults(func=cmd_entfernen)

    lo = sub.add_parser("loeschen", help="einen Fall löschen, in dem noch nichts abgefragt wurde (nur am Terminal)")
    lo.add_argument("fall")
    lo.add_argument("--durch", metavar="KÜRZEL", help="wer löscht")
    lo.set_defaults(func=cmd_loeschen)

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
