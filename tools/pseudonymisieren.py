#!/usr/bin/env python3
"""Pseudonymisiert ein Dokument auf diesem Rechner, ohne Sprachmodell und ohne Netz. Der Rückfall, wenn das LLM
im Haus ausfällt. Nur im Haus, nur von Hand, nur am Terminal.

    python3 tools/pseudonymisieren.py /sicher/rapport.docx \\
        --zuordnung /sicher/2026-0412_zuordnung.csv --ausgabe /sicher/pseudonymisiert/

    --zuordnung DATEI   Zuordnungstabelle des Falls. Gibt es sie schon, wird sie fortgeschrieben: Wer im ersten Dokument
                        [PERSON_01] war, bleibt es im Nachtrag. Format wie bei tools/reidentifizieren.py.
    --ausgabe ORDNER    Dorthin kommt das pseudonymisierte Dokument (<Name>_pseudonymisiert.txt).
    --namen DATEI       Namensliste zum Fall, wahlweise. Eine Angabe je Zeile, «Hans Muster» oder «ORG;Muster AG».
    --feldmarken DATEI  andere Feldmarken-Liste als tools/feldmarken.txt

Dokument, Zuordnungstabelle, Namensliste und Ausgabeordner müssen ausserhalb des Projektordners liegen, damit ein
Agent sie nicht lesen kann. Das Werkzeug läuft nur an einem Terminal und nicht aus Claude Code heraus: Was es auf
den Bildschirm schreibt, ist Klartext. Es öffnet keine Netzverbindung.

Der Ablauf: Das Werkzeug liest das Dokument und zeigt, was es gefunden hat. Du entscheidest in vier Schritten:
  1. E-Mail-Adressen: Täterseite (bleibt stehen) oder Geschädigte (wird ersetzt)?
  2. Kandidaten: mögliche Namen und Firmen im Fliesstext. Nichts davon wird ohne dein Ja ersetzt.
  3. Sichere Funde: jede Angabe mit ihren Fundstellen annehmen, einzeln durchgehen, verwerfen oder den Typ ändern.
  4. Ergänzen: was das Werkzeug übersehen hat.
Erst danach wird geschrieben. Am Ende läuft die PII-Prüfung über das Ergebnis.

Kein Werkzeug findet alles. Lies das Ergebnis, bevor du es aufnimmst. Messwerte und Grenzen: docs/PSEUDONYMISIERUNG.md.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import PROJEKT  # noqa: E402
from tools import _pseudo as ps  # noqa: E402
from tools import pii_pruefung  # noqa: E402

KURZ = {"p": "PERSON", "o": "ORG", "a": "ADRESSE", "t": "TEL", "e": "EMAIL", "g": "GEBDAT", "v": "AHV", "k": "KONTO", "z": "KFZ",
        "w": "AUSWEIS", "d": "DOMAIN", "i": "IP"}
TYPWAHL = ", ".join(f"[{k}] {ps.BESCHREIBUNG[t]}" for k, t in KURZ.items())


class Abbruch(Exception):
    pass


def innerhalb(pfad: Path) -> bool:
    try:
        pfad.resolve().relative_to(PROJEKT.resolve())
        return True
    except ValueError:
        return False


def ohne_netz() -> None:
    """Sperrt in diesem Prozess jede Netzverbindung. Das Werkzeug braucht keine, und so kann auch kein Versehen eine öffnen."""
    import socket

    def gesperrt(*_a, **_k):
        raise OSError("tools/pseudonymisieren.py arbeitet ohne Netz.")

    socket.socket = gesperrt                # type: ignore[assignment,misc]
    socket.create_connection = gesperrt     # type: ignore[assignment]
    socket.getaddrinfo = gesperrt           # type: ignore[assignment]


def namensliste_lesen(datei: Path) -> list[tuple[str, str]]:
    eintraege = []
    for nr, zeile in enumerate(datei.read_text(encoding="utf-8-sig").splitlines(), 1):
        zeile = zeile.strip()
        if not zeile or zeile.startswith("#"):
            continue
        typ, _, wert = zeile.partition(";")
        if not wert:
            typ, wert = "PERSON", zeile
        typ = typ.strip().upper()
        if typ not in ps.TYPEN:
            raise ValueError(f"{datei.name}, Zeile {nr}: Typ «{typ}» gibt es nicht. Erlaubt: {', '.join(ps.TYPEN)}.")
        eintraege.append((typ, wert.strip()))
    return eintraege


# --------------------------------------------------------------------------- Der Dialog

class Dialog:
    """Führt den Menschen durch die Bestätigung. Ein- und Ausgabe sind austauschbar, damit der Selbsttest sie spielen kann."""

    def __init__(self, vorgang: ps.Vorgang, lesen=input, zeigen=print, farbe: bool = False):
        self.v, self.lesen, self.zeigen, self.farbe = vorgang, lesen, zeigen, farbe

    def stelle(self, f: ps.Fund, breite: int = 55) -> str:
        davor, wortlaut, danach = self.v.erk.umgebung(f, breite)
        marke = f"\x1b[7m{wortlaut}\x1b[0m" if self.farbe else f"⟦{wortlaut}⟧"
        zeile = self.v.erk.text.count("\n", 0, f.start) + 1
        return f"    Zeile {zeile:>4}: …{davor}{marke}{danach}…"

    def frage(self, text: str, erlaubt: str, vorgabe: str = "") -> str:
        while True:
            try:
                antwort = self.lesen(f"  {text} ").strip().lower()
            except EOFError as e:
                raise Abbruch() from e
            antwort = antwort or vorgabe
            if antwort == "q":
                raise Abbruch()
            if antwort and antwort[0] in erlaubt:
                return antwort[0]
            self.zeigen(f"  Bitte eine der Tasten {', '.join(erlaubt)} und Enter. [q] bricht ab, ohne etwas zu schreiben.")

    def typ_fragen(self, vorgabe: str) -> str:
        self.zeigen(f"  Typen: {TYPWAHL}")
        kurz = {t: k for k, t in KURZ.items()}[vorgabe]
        return KURZ[self.frage(f"Typ [Enter = {ps.BESCHREIBUNG[vorgabe]}]:", "".join(KURZ), kurz)]

    def text_fragen(self, text: str) -> str:
        try:
            return self.lesen(f"  {text} ").strip()
        except EOFError as e:
            raise Abbruch() from e

    # Schritt 1
    def seiten(self) -> None:
        offen = self.v.fragen()
        if not offen:
            return
        self.zeigen(f"\nSchritt 1 von 4: {len(offen)} E-Mail-Adresse(n), bei denen das Werkzeug die Seite nicht kennen kann.")
        self.zeigen("  Die Adresse der Täterseite ist ein Indikator und bleibt stehen. Die Adresse der Geschädigten wird ersetzt.")
        while offen:
            a = offen[0]
            stellen = [f for f in self.v.erk.funde if f.angabe == a.schluessel]
            self.zeigen(f"\n  {a.wert}   ({len(stellen)} Fundstelle(n))")
            for f in stellen[:3]:
                self.zeigen(self.stelle(f))
            antwort = self.frage("[t] Täterseite, bleibt stehen   [g] Geschädigte, ersetzen:", "tg")
            self.v.seite(a.schluessel, "taeter" if antwort == "t" else "geschaedigte")
            offen = self.v.fragen()

    # Schritt 2
    def kandidaten(self) -> None:
        erledigt: set[tuple[str, str]] = set()
        erste = True
        while True:
            gruppen: dict[tuple[str, str], list[ps.Fund]] = {}
            for f in self.v.kandidaten():
                gruppen.setdefault((f.typ, ps.falten(f.wert or self.v.erk.wortlaut(f)) + "|" + f.grund.split(",")[0]), []).append(f)
            gruppen = {k: g for k, g in gruppen.items() if k not in erledigt}
            if not gruppen:
                return
            if erste:
                self.zeigen(f"\nSchritt 2 von 4: {len(gruppen)} Kandidat(en). Das Werkzeug ersetzt davon nichts ohne dein Ja.")
                self.zeigen("  [j] ersetzen   [n] stehen lassen   [t] ersetzen mit anderem Typ   [k] Wortlaut korrigieren und ersetzen")
                self.zeigen("  [r] alle restlichen stehen lassen   [q] abbrechen, ohne etwas zu schreiben")
                erste = False
            schluessel, gruppe = next(iter(gruppen.items()))
            erledigt.add(schluessel)
            f = gruppe[0]
            wert = f.wert or self.v.erk.wortlaut(f)
            self.zeigen(f"\n  {ps.BESCHREIBUNG[f.typ]}?  «{wert}»   ({len(gruppe)} Fundstelle(n), {f.grund})")
            for g in gruppe[:3]:
                self.zeigen(self.stelle(g))
            antwort = self.frage("[j/n/t/k/r]:", "jntkr")
            if antwort == "r":
                for rest in gruppen.values():
                    for g in rest:
                        self.v.verwerfen(g)
                return
            if antwort == "n":
                for g in gruppe:
                    self.v.verwerfen(g)
                continue
            typ = self.typ_fragen(f.typ) if antwort == "t" else f.typ
            if antwort == "k":
                wert = self.text_fragen("Richtiger Wortlaut der Angabe (zum Beispiel der volle Name):") or wert
                typ = self.typ_fragen(f.typ)
            if f.angabe and antwort == "j":
                for g in gruppe:
                    self.v.bestaetigen(g)
                self.zeigen(f"  → {len(gruppe)} Fundstelle(n) werden ersetzt.")
            else:
                n = self.v.bestaetigen(f, typ, wert)
                self.zeigen(f"  → aufgenommen als {ps.BESCHREIBUNG[typ]}. {n} Fundstelle(n) im Dokument werden ersetzt.")

    # Schritt 3
    def sichere(self) -> None:
        erk = self.v.erk
        nach_angabe: dict[str, list[ps.Fund]] = {}
        for f in erk.funde:
            if f.angabe and ps.stand(f, self.v.ent) is True:
                nach_angabe.setdefault(f.angabe, []).append(f)
        if not nach_angabe:
            self.zeigen("\nSchritt 3 von 4: Es gibt keine Fundstellen, die ersetzt würden.")
            return
        gesamt = sum(len(g) for g in nach_angabe.values())
        self.zeigen(f"\nSchritt 3 von 4: {len(nach_angabe)} Angabe(n) mit {gesamt} Fundstelle(n) würden ersetzt.")
        self.zeigen("  [Enter] alle Fundstellen dieser Angabe ersetzen   [e] einzeln durchgehen   [n] stehen lassen   [t] Typ ändern")
        self.zeigen("  [a] alle weiteren Angaben ohne Rückfrage annehmen   [q] abbrechen, ohne etwas zu schreiben")
        for schluessel, funde in nach_angabe.items():
            a = erk.angaben[schluessel]
            herkunft = sorted({ps.SCHICHT[f.schicht] for f in funde})
            hinweis = "  ACHTUNG: passt auf mehrere Personen" if any(f.frage == "mehrdeutig" for f in funde) else ""
            self.zeigen(f"\n  {ps.BESCHREIBUNG[a.typ]}: «{a.wert}»   {len(funde)} Fundstelle(n), gefunden über {', '.join(herkunft)}{hinweis}")
            for f in funde[:4]:
                self.zeigen(self.stelle(f))
            if len(funde) > 4:
                self.zeigen(f"    … und {len(funde) - 4} weitere")
            antwort = self.frage("[Enter/e/n/t/a]:", "jenta", "j")
            if antwort == "a":
                return
            if antwort == "n":
                self.v.angabe_entscheiden(schluessel, False)
            elif antwort == "t":
                self.v.typ_aendern(schluessel, self.typ_fragen(a.typ))
                return self.sichere()       # neu gerechnet: von vorn zeigen
            elif antwort == "e":
                for f in funde:
                    self.zeigen(self.stelle(f, 70))
                    self.zeigen(f"      ({f.grund})")
                    if self.frage("[Enter] ersetzen   [n] stehen lassen:", "jn", "j") == "n":
                        self.v.verwerfen(f)

    # Schritt 4
    def ergaenzen(self) -> None:
        self.zeigen("\nSchritt 4 von 4: Fehlt etwas? Gib ein, was noch ersetzt werden soll: einen Namen, eine Firma, eine Nummer.")
        self.zeigen("  Das Werkzeug sucht die Angabe im ganzen Dokument, in allen Schreibweisen. Leere Eingabe: fertig.")
        while True:
            wert = self.text_fragen("Angabe (leer = fertig):")
            if not wert:
                return
            typ = self.typ_fragen("PERSON")
            vorher = {f.id for f in self.v.erk.funde if ps.stand(f, self.v.ent) is True}
            n = self.v.aufnehmen(wert, typ, 6)
            neu = [f for f in self.v.erk.funde if ps.stand(f, self.v.ent) is True and f.id not in vorher]
            if not n and not neu:
                self.zeigen("  Im Dokument nicht gefunden. Schreibweise prüfen (das Werkzeug sucht nach ganzen Wörtern).")
                continue
            self.zeigen(f"  → {len(neu)} neue Fundstelle(n):")
            for f in neu[:5]:
                self.zeigen(self.stelle(f))

    def alles(self) -> ps.Ergebnis:
        self.seiten()
        self.kandidaten()
        self.seiten()           # eine bestätigte Angabe kann eine neue Adresse zur Frage machen
        self.sichere()
        self.ergaenzen()
        self.seiten()
        return self.v.ergebnis()


def uebersicht(v: ps.Vorgang) -> list[str]:
    erk = v.erk
    zeilen = []
    je_typ: dict[str, list[int]] = {}
    for f in erk.funde:
        z = je_typ.setdefault(f.typ, [0, 0])
        z[0 if f.sicher else 1] += 1
    for typ in ps.TYPEN:
        if typ in je_typ:
            sicher, kandidat = je_typ[typ]
            zeilen.append(f"  {ps.BESCHREIBUNG[typ]:28} {sicher:4} Fundstelle(n)" + (f", {kandidat} Kandidat(en)" if kandidat else ""))
    arten: dict[str, int] = {}
    for s in erk.geschuetzt:
        arten[s.art] = arten.get(s.art, 0) + 1
    if arten:
        zeilen.append("  Geschützt, bleibt stehen:    " + ", ".join(f"{n}× {art}" for art, n in sorted(arten.items())))
    return zeilen


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dokument", help="Klartext-Dokument (.txt, .md, .docx, .pdf mit Text), ausserhalb des Projektordners")
    p.add_argument("--zuordnung", required=True, help="Zuordnungstabelle des Falls, ausserhalb des Projektordners")
    p.add_argument("--ausgabe", required=True, help="Zielordner ausserhalb des Projektordners")
    p.add_argument("--namen", help="Namensliste zum Fall, ausserhalb des Projektordners")
    p.add_argument("--feldmarken", help="andere Feldmarken-Liste")
    a = p.parse_args()

    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        print("FEHLER: Dieses Werkzeug zeigt Klartext. Es läuft nicht aus Claude Code heraus, auch nicht über «!». "
              "Bitte in einem eigenen Terminal starten.", file=sys.stderr)
        return 2
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("FEHLER: Pseudonymisiert wird von einem Menschen am Terminal. Ohne Terminal läuft das Werkzeug nicht.", file=sys.stderr)
        return 2
    dokument, zuordnung, ausgabe = Path(a.dokument).expanduser(), Path(a.zuordnung).expanduser(), Path(a.ausgabe).expanduser()
    namen = Path(a.namen).expanduser() if a.namen else None
    if any(innerhalb(pfad) for pfad in (dokument, zuordnung, ausgabe, namen) if pfad):
        print("FEHLER: Dokument, Zuordnungstabelle, Namensliste und Ausgabeordner müssen ausserhalb des Projektordners liegen.\n"
              f"        Projektordner: {PROJEKT}", file=sys.stderr)
        return 2
    ohne_netz()
    try:
        if not dokument.is_file():
            raise pii_pruefung.NichtLesbar(f"{dokument}: Datei nicht gefunden.")
        text = pii_pruefung.text_lesen(dokument)
        marken = ps.feldmarken_lesen(Path(a.feldmarken)) if a.feldmarken else ps.feldmarken_lesen()
        bestehend = ps.zuordnung_lesen(zuordnung) if zuordnung.is_file() else []
        liste = namensliste_lesen(namen) if namen else []
    except (pii_pruefung.NichtLesbar, ValueError, OSError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    ziel = ausgabe / f"{dokument.stem}_pseudonymisiert.txt"

    print(f"Dokument:          {dokument.name}  ({len(text.splitlines())} Zeilen)")
    print(f"Zuordnungstabelle: {zuordnung}  ({len(bestehend)} bestehende Einträge)" if bestehend else f"Zuordnungstabelle: {zuordnung}  (neu)")
    print(f"Feldmarken:        {len(marken.liste)}" + (f"   Namensliste: {len(liste)} Einträge" if liste else ""))
    v = ps.Vorgang(text, zuordnung=bestehend, namensliste=liste, marken=marken)
    print("\nGefunden:")
    print("\n".join(uebersicht(v)) or "  nichts")
    if not v.erk.funde:
        print("\n  ! Das Werkzeug hat nichts gefunden. Ist das Dokument ein Scan ohne Text, oder schon pseudonymisiert?")
    try:
        ergebnis = Dialog(v, farbe=not os.environ.get("NO_COLOR") and os.environ.get("TERM", "dumb") != "dumb" and not plattform.WINDOWS).alles()
        if ziel.exists() and Dialog(v).frage(f"{ziel.name} gibt es schon. Überschreiben? [j/N]:", "jn", "n") == "n":
            raise Abbruch()
    except (Abbruch, KeyboardInterrupt):
        print("\nAbgebrochen. Es wurde nichts geschrieben.")
        return 1

    ausgabe.mkdir(parents=True, exist_ok=True)
    inhalt = ergebnis.text
    if ergebnis.klaerung:
        inhalt += "\n\n--- ZUR KLÄRUNG ---\n" + "\n".join(f"{ph}, Zeile {zeile}: {grund}" for ph, zeile, grund in ergebnis.klaerung) + "\n"
    ziel.write_text(inhalt, encoding="utf-8")
    try:
        os.chmod(ziel, 0o600)
    except OSError:
        pass
    vorlaeufig = zuordnung.with_name(zuordnung.name + ".neu")
    zuordnung.parent.mkdir(parents=True, exist_ok=True)
    ps.zuordnung_schreiben(vorlaeufig, ergebnis.zuordnung)
    os.replace(vorlaeufig, zuordnung)

    print(f"\ngeschrieben: {ziel}")
    print(f"geschrieben: {zuordnung}  ({len(ergebnis.zuordnung)} Einträge, davon {len(ergebnis.neu)} neu)")
    print("Ersetzt: " + (", ".join(f"{ps.BESCHREIBUNG[t]} ×{n}" for t, n in ergebnis.ersetzt.items()) or "nichts"))
    if ergebnis.offen:
        print(f"Stehen geblieben: {ergebnis.offen} Kandidat(en), über die nicht entschieden wurde.")
    funde, platzhalter = pii_pruefung.pruefen(ergebnis.text)
    print()
    print(pii_pruefung.bericht(ziel.name, funde, platzhalter))
    print("\nKein Werkzeug findet alles. Lies das Ergebnis, bevor du es aufnimmst:")
    print(f"  {plattform.PY} tools/fall.py aufnehmen <Fall-ID> {ziel}")
    print("Die Zuordnungstabelle bleibt ausserhalb des Projektordners. Sie ist der Schlüssel zu den echten Angaben.")
    return 1 if any(f.stufe == "sperre" for f in funde) else 0


if __name__ == "__main__":
    sys.exit(main())
