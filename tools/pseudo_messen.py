#!/usr/bin/env python3
"""Misst die lokale Pseudonymisierung am Prüfsatz (tools/pseudo_pruefsatz.py). Ohne Netz, ohne echte Daten.

    python3 tools/pseudo_messen.py                 Tabellen auf den Bildschirm
    python3 tools/pseudo_messen.py --formen        dazu: Durchrutschen je Schreibweise
    python3 tools/pseudo_messen.py --readme        Tabellen ins README schreiben (zwischen den Marken «pseudo-messung»)
    python3 tools/pseudo_messen.py --pruefen       prüfen, ob die Tabellen im README zum Stand des Codes passen
    python3 tools/pseudo_messen.py --feldmarken DATEI   mit einer anderen Feldmarken-Liste messen

Massstab ist zuerst die Durchrutschquote: der Anteil der Stellen mit Personendaten, die im Ergebnis stehen
bleiben. Gemessen wird je Typ und nach jeder Schicht, getrennt nach Angaben, die in einem Feld stehen, und
Angaben, die nur im Fliesstext vorkommen. Eine Stelle gilt nur als ersetzt, wenn jeder Buchstabe und jede
Ziffer davon ersetzt ist. Danach die Fehlalarme: was ersetzt wurde, ohne Personendaten zu sein, und ob ein
technischer Indikator verändert wurde.

Die Spalten der Tabelle:
    nach 1        nur die Werte hinter den Feldmarken
    nach 2        dazu die Fortpflanzung dieser Werte im ganzen Dokument
    nach 3        dazu die Muster mit Prüfsumme. Das ist der Stand ohne Zutun des Menschen.
    mit 5         der Mensch bestätigt jeden richtigen Kandidaten, den das Werkzeug vorlegt
    mit 4         der Mensch gibt zusätzlich jeden Namen des Dokuments in die Namensliste ein
«mit 5» und «mit 4» sind obere Grenzen: Sie setzen einen Menschen voraus, der nichts übersieht.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools import _pseudo as ps  # noqa: E402
from tools import pseudo_pruefsatz as satz  # noqa: E402

README = Path(__file__).resolve().parents[1] / "README.md"
ANFANG, ENDE = "<!-- pseudo-messung:anfang -->", "<!-- pseudo-messung:ende -->"
STUFEN = ("nach 1", "nach 2", "nach 3", "mit 5", "mit 4")
TYPNAME = {"PERSON": "Person", "ORG": "Organisation", "ADRESSE": "Adresse", "TEL": "Telefonnummer", "EMAIL": "E-Mail-Adresse",
           "GEBDAT": "Geburtsdatum", "AHV": "AHV-Nummer", "KONTO": "Bankverbindung", "KFZ": "Kontrollschild",
           "AUSWEIS": "Ausweisnummer"}


def _abgedeckt(text: str, start: int, ende: int, spannen: list[tuple[int, int]]) -> bool:
    """Ist jede Stelle mit Buchstabe oder Ziffer zwischen start und ende von einer Spanne überdeckt?"""
    for i in range(start, ende):
        if text[i].isalnum() and not any(a <= i < e for a, e in spannen):
            return False
    return True


def _klartext(s: str) -> str:
    return " ".join(re.sub(r"-\n\s*", "", s).split())


def dokument_messen(d: satz.Dokument, marken: ps.Marken, vornamen: frozenset) -> dict:
    gold = d.gold
    in_feld = d.in_feld()
    taeter_post = [(a, e) for a, e, art in d.technik if art == "E-Mail Täterseite"]

    def seiten(erk: ps.Erkennung, ent: ps.Entscheide) -> int:
        """Der Mensch beantwortet die Rückfragen zu E-Mail-Adressen richtig. Liefert die Zahl der Rückfragen."""
        fragen = set()
        for f in erk.funde:
            if f.frage == "seite":
                fragen.add(f.angabe)
                ent.seite[f.angabe] = "taeter" if any(a < f.ende and f.start < e for a, e in taeter_post) else "geschaedigte"
        return len(fragen)

    v = ps.Vorgang(d.text, marken=marken, vornamen=vornamen)
    ohne_antwort = [(f.start, f.ende) for f in v.erk.funde if ps.stand(f, v.ent) is True]
    rueckfragen = seiten(v.erk, v.ent)
    stufen: dict[str, list[tuple[int, int]]] = {}
    stufen["nach 1"] = [(f.start, f.ende) for f in v.erk.funde if f.schicht == 1]
    stufen["nach 2"] = stufen["nach 1"] + [(f.start, f.ende) for f in v.erk.funde if f.schicht == 2 and f.quelle <= 1 and f.sicher]
    automatisch = [f for f in v.erk.funde if ps.stand(f, v.ent) is True]
    stufen["nach 3"] = [(f.start, f.ende) for f in automatisch]

    # Schicht 5: jeden richtigen Kandidaten bestätigen, bis keiner mehr dazukommt
    vorgelegt = richtig = 0
    gesehen: set[str] = set()
    for _ in range(4):
        kandidaten = [f for f in v.kandidaten() if f.id not in gesehen]
        if not kandidaten:
            break
        neu = False
        for f in kandidaten:
            gesehen.add(f.id)
            vorgelegt += 1
            treffer = next((g for g in gold if g.start < f.ende and f.start < g.ende), None)
            if treffer is None or any(a < f.ende and f.start < e for a, e, _ in d.technik):
                v.verwerfen(f)
                continue
            richtig += 1
            if f.angabe:
                v.ent.fund[f.id] = True
            else:
                v.ent.eingaben.append((treffer.typ if treffer.typ in ("PERSON", "ORG") else f.typ, _klartext(d.text[treffer.start:treffer.ende]), 5))
                neu = True
        if neu:
            v._rechnen()
            seiten(v.erk, v.ent)
        else:
            break
    mit5 = [f for f in v.erk.funde if ps.stand(f, v.ent) is True]
    stufen["mit 5"] = [(f.start, f.ende) for f in mit5]

    # Schicht 4: alle Namen des Dokuments in die Namensliste
    for typ, name in d.namen.values():
        v.ent.eingaben.append((typ, name, 4))
    v._rechnen()
    seiten(v.erk, v.ent)
    stufen["mit 4"] = [(f.start, f.ende) for f in v.erk.funde if ps.stand(f, v.ent) is True]

    zeilen = []
    for g in gold:
        zeilen.append({"typ": g.typ, "feld": g.wer in in_feld, "stelle_im_feld": g.im_feld, "form": g.form,
                       **{s: _abgedeckt(d.text, g.start, g.ende, stufen[s]) for s in STUFEN}})
    # Fehlalarme
    falsch: dict[str, int] = {}
    for f in automatisch:
        if not any(g.start < f.ende and f.start < g.ende for g in gold):
            falsch[f.typ] = falsch.get(f.typ, 0) + 1
    technik_veraendert = sum(1 for a, e, art in d.technik if any(x < e and a < y for x, y in stufen["nach 3"]))
    technik_veraendert_ende = sum(1 for a, e, art in d.technik if any(x < e and a < y for x, y in stufen["mit 4"]))
    post_ohne_antwort = sum(1 for a, e in taeter_post if any(x < e and a < y for x, y in ohne_antwort))
    vor_unbekannt = sum(1 for wer, (typ, name) in d.namen.items() if typ == "PERSON" and ps.falten(name.split()[0].split("-")[0]) not in vornamen)
    return {"zeilen": zeilen, "falsch": falsch, "technik": len(d.technik), "technik_veraendert": technik_veraendert,
            "technik_veraendert_ende": technik_veraendert_ende, "taeter_post": len(taeter_post), "post_ohne_antwort": post_ohne_antwort,
            "rueckfragen": rueckfragen, "vorgelegt": vorgelegt, "richtig": richtig, "ersetzt": len(automatisch),
            "personen": sum(1 for t, _ in d.namen.values() if t == "PERSON"), "vor_unbekannt": vor_unbekannt}


def gegenprobe(dokumente: list, marken: ps.Marken, vornamen: frozenset) -> dict:
    """Was geschieht, wenn die Dokumente Marken tragen, die nicht in der Liste stehen? Die Dokumente bleiben dieselben,
    dem Werkzeug wird jede zweite Marke weggenommen. Gezählt wird der Stand ohne Zutun, für Angaben in einem Feld."""
    halb = ps.Marken(marken.liste[::2])
    stellen = bleibt = 0
    for d in dokumente:
        erk = ps.erkennen(d.text, marken=halb, vornamen=vornamen)
        spannen = [(f.start, f.ende) for f in erk.funde if f.sicher]
        in_feld = d.in_feld()
        for g in d.gold:
            if g.wer in in_feld:
                stellen += 1
                bleibt += not _abgedeckt(d.text, g.start, g.ende, spannen)
    return {"marken": len(halb.liste), "stellen": stellen, "bleibt": bleibt}


def kontrolle(anzahl: int, marken: ps.Marken, vornamen: frozenset) -> dict:
    """Dieselbe Messung an Rapporten, die bei der Entwicklung nie angesehen wurden: die Nummern hinter dem Prüfsatz.
    Die Erkennung wurde an den ersten Rapporten nachgebessert. Hier zeigt sich, was davon auf neue Rapporte trägt."""
    dokumente = satz.pruefsatz(anzahl, marken, ab=satz.ANZAHL + 1)
    einzeln = [dokument_messen(d, marken, vornamen) for d in dokumente]
    zeilen = [z for e in einzeln for z in e["zeilen"]]
    aus = {"dokumente": len(dokumente), "von": satz.ANZAHL + 1, "bis": satz.ANZAHL + len(dokumente),
           "technik": sum(e["technik"] for e in einzeln), "technik_veraendert": sum(e["technik_veraendert_ende"] for e in einzeln)}
    for gruppe in ("feld", "text"):
        passend = [z for z in zeilen if z["feld"] == (gruppe == "feld")]
        aus[gruppe] = {"n": len(passend), **{s: sum(1 for z in passend if not z[s]) for s in STUFEN}}
    return aus


def messen(anzahl: int = satz.ANZAHL, feldmarken: Path | None = None, mit_gegenprobe: bool = True) -> dict:
    marken = ps.feldmarken_lesen(feldmarken)
    vornamen = ps.vornamen_lesen()
    dokumente = satz.pruefsatz(anzahl, marken)
    einzeln = [dokument_messen(d, marken, vornamen) for d in dokumente]
    zeilen = [z for e in einzeln for z in e["zeilen"]]
    tabelle: dict[str, dict] = {}
    for gruppe in ("feld", "text"):
        for typ in TYPNAME:
            passend = [z for z in zeilen if z["typ"] == typ and z["feld"] == (gruppe == "feld")]
            if passend:
                tabelle[f"{gruppe}:{typ}"] = {"n": len(passend), **{s: sum(1 for z in passend if not z[s]) for s in STUFEN}}
        passend = [z for z in zeilen if z["feld"] == (gruppe == "feld")]
        tabelle[f"{gruppe}:alle"] = {"n": len(passend), **{s: sum(1 for z in passend if not z[s]) for s in STUFEN}}
    formen: dict[str, dict] = {}
    for z in zeilen:
        f = formen.setdefault(f"{z['typ']}:{'Feld' if z['feld'] else 'Text'}:{z['form']}", {"n": 0, **{s: 0 for s in STUFEN}})
        f["n"] += 1
        for s in STUFEN:
            f[s] += not z[s]
    falsch: dict[str, int] = {}
    for e in einzeln:
        for typ, n in e["falsch"].items():
            falsch[typ] = falsch.get(typ, 0) + n
    summe = {k: sum(e[k] for e in einzeln) for k in ("technik", "technik_veraendert", "technik_veraendert_ende", "taeter_post", "post_ohne_antwort",
                                                     "rueckfragen", "vorgelegt", "richtig", "ersetzt", "personen", "vor_unbekannt")}
    return {"dokumente": len(dokumente), "stellen": len(zeilen), "marken": len(marken.liste), "vornamen": len(vornamen), "tabelle": tabelle,
            "formen": formen, "falsch": falsch, "gegenprobe": gegenprobe(dokumente, marken, vornamen) if mit_gegenprobe else None,
            "kontrolle": kontrolle(anzahl, marken, vornamen) if mit_gegenprobe else None, **summe}


def _quote(n: int, von: int) -> str:
    if von == 0:
        return "–"
    if n == 0:
        return "0"
    anteil = 100 * n / von
    return f"{n} ({anteil:.1f} %)" if anteil >= 0.05 else f"{n} (< 0.1 %)"


def tabellen(m: dict) -> str:
    """Die Tabellen fürs README. Jede Zahl stammt aus dem Lauf, keine ist von Hand eingetragen."""
    aus = [f"Prüfsatz: {m['dokumente']} synthetische Rapporte, {m['stellen']} Stellen mit Personendaten, {m['technik']} technische "
           f"Indikatoren. Feldmarken: {m['marken']} (vorläufige Liste). Vornamenliste: {m['vornamen']} Namen (vorläufige Liste). "
           f"Von {m['personen']} Personen im Prüfsatz tragen {m['vor_unbekannt']} einen Vornamen, der nicht in der Liste steht.", ""]
    for gruppe, titel in (("feld", "Angaben, die in einem Feld stehen (alle ihre Stellen, auch die im Fliesstext)"),
                          ("text", "Angaben, die nur im Fliesstext stehen (Drittpersonen, weitere Firmen)")):
        aus += [f"**{titel}**: Stellen, die stehen bleiben", "",
                "| Typ | Stellen | nach Schicht 1 | nach 2 | nach 3 (ohne Zutun) | mit 5 (Kandidaten bestätigt) | mit 4 (alle Namen eingegeben) |",
                "|---|---:|---:|---:|---:|---:|---:|"]
        for schluessel, z in m["tabelle"].items():
            g, typ = schluessel.split(":")
            if g != gruppe:
                continue
            name = "**Alle**" if typ == "alle" else TYPNAME[typ]
            aus.append(f"| {name} | {z['n']} | " + " | ".join(_quote(z[s], z["n"]) for s in STUFEN) + " |")
        aus.append("")
    falsch = sum(m["falsch"].values())
    aus += ["**Fehlalarme und technische Indikatoren**", "", "| Was | Zahl |", "|---|---:|",
            f"| Ersetzungen ohne Zutun insgesamt | {m['ersetzt']} |",
            f"| davon keine Personendaten (Fehlalarm) | {_quote(falsch, m['ersetzt'])} |"]
    for typ, n in sorted(m["falsch"].items(), key=lambda x: -x[1]):
        aus.append(f"| … als {TYPNAME.get(typ, typ)} | {n} |")
    aus += [f"| Technische Indikatoren im Prüfsatz | {m['technik']} |",
            f"| davon verändert, ohne Zutun | {m['technik_veraendert']} |",
            f"| davon verändert, nach Bestätigung und Namensliste | {m['technik_veraendert_ende']} |",
            f"| Rückfragen «Täterseite oder Geschädigte?» zu E-Mail-Adressen | {m['rueckfragen']} |",
            f"| E-Mail-Adressen der Täterseite im Prüfsatz | {m['taeter_post']} |",
            f"| davon ersetzt, wenn niemand die Rückfrage beantwortet | {m['post_ohne_antwort']} |",
            f"| Kandidaten, die Schicht 5 vorlegt | {m['vorgelegt']} |",
            f"| davon richtig (Personendaten) | {_quote(m['richtig'], m['vorgelegt'])} |", ""]
    g = m.get("gegenprobe")
    if g:
        aus += [f"**Gegenprobe: Das Dokument trägt Marken, die nicht in der Liste stehen.** Dieselben Dokumente, aber das Werkzeug kennt "
                f"nur jede zweite Marke ({g['marken']} von {m['marken']}). Von {g['stellen']} Stellen der Angaben, die in einem Feld stehen, "
                f"bleiben ohne Zutun {_quote(g['bleibt'], g['stellen'])} stehen.", ""]
    k = m.get("kontrolle")
    if k:
        aus += [f"**Kontrolle an {k['dokumente']} weiteren Rapporten (Nummern {k['von']} bis {k['bis']}), die bei der Entwicklung nie angesehen "
                "wurden.** Stellen, die stehen bleiben:", "",
                "| Angaben | Stellen | nach 3 (ohne Zutun) | mit 5 (Kandidaten bestätigt) | mit 4 (alle Namen eingegeben) |", "|---|---:|---:|---:|---:|",
                f"| in einem Feld | {k['feld']['n']} | " + " | ".join(_quote(k["feld"][s], k["feld"]["n"]) for s in STUFEN[2:]) + " |",
                f"| nur im Fliesstext | {k['text']['n']} | " + " | ".join(_quote(k["text"][s], k["text"]["n"]) for s in STUFEN[2:]) + " |", "",
                f"Technische Indikatoren in der Kontrolle: {k['technik']}, davon verändert: {k['technik_veraendert']}.", ""]
    return "\n".join(aus)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--anzahl", type=int, default=satz.ANZAHL)
    p.add_argument("--feldmarken", metavar="DATEI")
    p.add_argument("--formen", action="store_true", help="Durchrutschen je Schreibweise ausgeben")
    p.add_argument("--json", action="store_true")
    p.add_argument("--readme", action="store_true", help="Tabellen ins README schreiben")
    p.add_argument("--pruefen", action="store_true", help="Tabellen im README mit dem Stand des Codes vergleichen")
    a = p.parse_args()
    beginn = time.monotonic()
    m = messen(a.anzahl, Path(a.feldmarken) if a.feldmarken else None)
    text = tabellen(m)
    if a.json:
        print(json.dumps(m, ensure_ascii=False, indent=1))
        return 0
    if a.readme or a.pruefen:
        inhalt = README.read_text(encoding="utf-8")
        if ANFANG not in inhalt or ENDE not in inhalt:
            print(f"FEHLER: Im README fehlen die Marken {ANFANG} und {ENDE}.", file=sys.stderr)
            return 2
        vor, rest = inhalt.split(ANFANG, 1)
        alt, nach = rest.split(ENDE, 1)
        if a.pruefen:
            if alt.strip() != text.strip():
                print("FEHLER: Die Messwerte im README passen nicht zum Stand des Codes. Neu schreiben: "
                      f"{plattform.PY} tools/pseudo_messen.py --readme", file=sys.stderr)
                return 1
            print(f"{plattform.GUT} Die Messwerte im README stimmen mit dem Lauf überein ({m['dokumente']} Dokumente, {time.monotonic() - beginn:.0f} s).")
            return 0
        plattform.text_schreiben(README, f"{vor}{ANFANG}\n{text}\n{ENDE}{nach}")
        print("README aktualisiert.")
        return 0
    print(text)
    if a.formen:
        print("Durchrutschen je Schreibweise (Typ:Angabe:Form, Stellen, nach 3, mit 5, mit 4)")
        for name, z in sorted(m["formen"].items()):
            if z["nach 3"] or z["mit 5"] or z["mit 4"]:
                print(f"  {name:48} {z['n']:5} {z['nach 3']:5} {z['mit 5']:5} {z['mit 4']:5}")
    print(f"({time.monotonic() - beginn:.1f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
