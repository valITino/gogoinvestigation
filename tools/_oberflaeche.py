"""Bausteine für die Oberfläche im Terminal. Nur Standardbibliothek, damit die Einrichtung
schon läuft, bevor ein einziges Paket installiert ist.

    ui = Oberflaeche()
    ui.kopf("Einrichtung", "Ubuntu 24.04")
    nr = ui.auswahl("Modelle", "Darf euer Konto Mythos nutzen?", [("Nein", "alles auf Fable"), ("Ja", "")])
    ui.erledigt("Modelle", "Ermittlung auf Mythos")
    with ui.arbeit("Pakete werden installiert"):
        ...

Drei Betriebsarten, von selbst erkannt:

    bewegt       Terminal mit Cursorsteuerung: Auswahl mit den Pfeiltasten, die Frage verschwindet
                 nach der Antwort wieder. Laufanzeige bei längeren Arbeiten.
    schlicht     Terminal ohne Cursorsteuerung (TERM=dumb, Option --schlicht, Bildschirmleser):
                 nummerierte Fragen, Antwort mit Zahl und Enter. Nichts wird übermalt.
    ohne Fragen  kein Terminal (CI, Umleitung in eine Datei): Jede Frage liefert ihre Vorgabe.

Farbe ist nie der einzige Träger einer Aussage. Jeder Zustand hat ein Zeichen und ein Wort.
Verdeckte Eingaben (Schlüssel) erscheinen nie auf dem Bildschirm, auch nicht beim Einfügen.
"""
from __future__ import annotations

import atexit
import contextlib
import getpass
import os
import shutil
import sys
import textwrap
import threading
import time
from typing import Callable, Sequence

from gateway import plattform

Segment = tuple[str, str]       # (Text, Stil)

STILE = {"": "", "fett": "1", "matt": "2", "akzent": "36", "akzent-fett": "1;36", "gut": "32", "schlecht": "31", "warn": "33"}

SONDERTASTEN = {b"[A": "hoch", b"OA": "hoch", b"[B": "runter", b"OB": "runter", b"[C": "rechts", b"OC": "rechts",
                b"[D": "links", b"OD": "links", b"[3~": "entf", b"[H": "pos1", b"[F": "ende"}
ZEICHENTASTEN = {"\r": "enter", "\n": "enter", " ": "leer", "\x7f": "rueck", "\x08": "rueck", "\t": "tab",
                 "\x15": "leeren", "\x16": "einfuegen", "\x1b": "esc"}


class Abbruch(Exception):
    """Der Mensch hat eine Frage mit Esc oder Strg+D verlassen."""


class Zeichen:
    """Der Zeichensatz der Oberfläche. Die alte Windows-Konsole kennt weniger Zeichen als ein heutiges Terminal."""

    def __init__(self, modern: bool) -> None:
        self.gut, self.neu, self.aus, self.fehlt = plattform.GUT, plattform.NEU, plattform.AUS, plattform.FEHLT
        self.linie, self.frage = "─", "?"
        if modern:
            self.zeiger, self.an, self.nicht_an, self.haken, self.kein_haken = "›", "●", "○", "[✓]", "[ ]"
            self.dreher, self.verdeckt, self.pfeile, self.marke = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "•", "↑↓", "▏"
        else:
            self.zeiger, self.an, self.nicht_an, self.haken, self.kein_haken = ">", "(*)", "( )", "[x]", "[ ]"
            self.dreher, self.verdeckt, self.pfeile, self.marke = "|/-\\", "*", "Pfeiltasten", "_"


# --------------------------------------------------------------------------- Tastatur

def _vt_einschalten() -> bool:
    """Windows: Schaltet in der Konsole die Steuerzeichen für Farbe und Cursor ein (ab Windows 10)."""
    try:
        import ctypes
        kernel = ctypes.windll.kernel32
        griff = kernel.GetStdHandle(-11)
        modus = ctypes.c_uint32()
        if not kernel.GetConsoleMode(griff, ctypes.byref(modus)):
            return False
        return bool(kernel.SetConsoleMode(griff, modus.value | 0x0004))
    except Exception:
        return False


@contextlib.contextmanager
def _einzeltasten():
    """Stellt das Terminal für die Dauer einer Frage auf einzelne Tasten ohne Echo und danach zurück.
    Das Echo bleibt die ganze Frage über aus: Sonst schriebe das Terminal einen eingefügten Schlüssel
    selbst auf den Bildschirm, sobald er in mehreren Stücken eintrifft. Unter Windows liest msvcrt
    ohnehin ohne Echo."""
    if plattform.WINDOWS:
        yield
        return
    import termios
    import tty
    fd = sys.stdin.fileno()
    vorher = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, vorher)


def _taste_posix() -> str:
    import codecs
    import select
    fd = sys.stdin.fileno()
    erstes = os.read(fd, 1)
    if not erstes or erstes == b"\x04":
        raise Abbruch
    if erstes == b"\x03":
        raise KeyboardInterrupt
    if erstes == b"\x1b":
        # Pfeil- und Sondertasten kommen als Folge: Esc [ … Schlussbyte, oder Esc O und ein Byte.
        # Kommt nach Esc binnen eines Augenblicks nichts, war es die Taste Esc selbst.
        folge = b""
        while len(folge) < 16 and select.select([fd], [], [], 0.03)[0]:
            folge += os.read(fd, 1)
            if folge[:1] not in (b"[", b"O"):
                break                                   # Alt mit einer Taste: wird übergangen
            if len(folge) >= 2 and (folge[:1] == b"O" or 0x40 <= folge[-1] <= 0x7E):
                break
        return SONDERTASTEN.get(folge, "") if folge else "esc"
    dekoder = codecs.getincrementaldecoder("utf-8")("replace")
    zeichen = dekoder.decode(erstes)
    while not zeichen:                  # Umlaute und andere Zeichen aus mehreren Bytes
        zeichen = dekoder.decode(os.read(fd, 1))
    return ZEICHENTASTEN.get(zeichen, zeichen)


def _wartet_posix() -> bool:
    import select
    return bool(select.select([sys.stdin.fileno()], [], [], 0)[0])


def _verwerfen_posix() -> None:
    import termios
    termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)


def _taste_windows() -> str:
    import msvcrt
    zeichen = msvcrt.getwch()
    if zeichen in ("\x00", "\xe0"):
        return {"H": "hoch", "P": "runter", "K": "links", "M": "rechts", "S": "entf", "G": "pos1", "O": "ende"}.get(msvcrt.getwch(), "")
    if zeichen == "\x03":
        raise KeyboardInterrupt
    if zeichen in ("\x04", "\x1a"):
        raise Abbruch
    return ZEICHENTASTEN.get(zeichen, zeichen)


def _wartet_windows() -> bool:
    import msvcrt
    return bool(msvcrt.kbhit())


def _verwerfen_windows() -> None:
    import msvcrt
    for _ in range(4096):
        if not msvcrt.kbhit():
            break
        msvcrt.getwch()


# --------------------------------------------------------------------------- Oberfläche

class Oberflaeche:
    def __init__(self, aus=None, taste: Callable[[], str] | None = None, zeile_lesen: Callable[[str], str] | None = None,
                 interaktiv: bool | None = None, bewegt: bool | None = None, farbe: bool | None = None,
                 modern: bool | None = None, breite: int | None = None, hoehe: int | None = None) -> None:
        self._aus = aus or sys.stdout
        ausgabe_terminal = bool(getattr(self._aus, "isatty", lambda: False)())
        terminal = aus is None and ausgabe_terminal and sys.stdin.isatty()
        stumm = os.environ.get("TERM", "") == "dumb"
        vt = (not plattform.WINDOWS or _vt_einschalten()) if ausgabe_terminal else False
        self.interaktiv = terminal if interaktiv is None else interaktiv
        self.bewegt = (terminal and vt and not stumm if bewegt is None else bewegt) and self.interaktiv
        self.farbe = (ausgabe_terminal and vt and not stumm and "NO_COLOR" not in os.environ) if farbe is None else farbe
        if modern is None:
            modern = not plattform.WINDOWS or bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"))
        self.z = Zeichen(modern)
        self._breite, self._zeilenzahl = breite, hoehe
        # Nur im Terminal wird umbrochen und gekürzt. In einer Datei oder einem CI-Protokoll bleibt jede Zeile ganz.
        self._terminal = ausgabe_terminal or breite is not None
        self._eigene_tasten = taste is None
        self._taste = taste or (_taste_windows if plattform.WINDOWS else _taste_posix)
        self._wartet = (_wartet_windows if plattform.WINDOWS else _wartet_posix) if taste is None else (lambda: False)
        self._verwerfen = (_verwerfen_windows if plattform.WINDOWS else _verwerfen_posix) if taste is None else (lambda: None)
        self._zeile_lesen = zeile_lesen or input
        self._hoehe = 0             # Zeilen des Blocks, der gerade auf dem Bildschirm steht und übermalt werden darf
        self._zeiger_aus = False
        if self.bewegt:
            atexit.register(self._zeiger, True)

    # ----------------------------------------------------------------------- Grundlagen

    @property
    def spalten(self) -> int:
        return self._breite or max(20, shutil.get_terminal_size((96, 24)).columns)

    @property
    def breite(self) -> int:
        """Breite des Satzspiegels. Auf sehr breiten Terminals bleibt der Text lesbar schmal."""
        return min(self.spalten, 104)

    @property
    def zeilenzahl(self) -> int:
        return self._zeilenzahl or shutil.get_terminal_size((96, 24)).lines

    def _stil(self, text: str, stil: str) -> str:
        code = STILE.get(stil, "")
        return f"\033[{code}m{text}\033[0m" if self.farbe and code and text else text

    def _setzen(self, segmente: Sequence[Segment]) -> str:
        """Fügt eine Zeile aus Segmenten zusammen und kürzt sie auf die Breite des Terminals.
        Eine umbrochene Zeile würde das Übermalen aus dem Tritt bringen."""
        rest, teile = (self.spalten - 1 if self._terminal else 10 ** 6), []
        for text, stil in segmente:
            if rest <= 0:
                break
            if len(text) > rest:
                text = text[:max(0, rest - 1)] + "…"
            rest -= len(text)
            teile.append(self._stil(text, stil))
        return "".join(teile).rstrip()

    def _schreiben(self, text: str) -> None:
        self._aus.write(text)
        self._aus.flush()

    def _zeiger(self, sichtbar: bool) -> None:
        if self.bewegt and self._zeiger_aus == sichtbar:
            self._zeiger_aus = not sichtbar
            with contextlib.suppress(Exception):
                self._schreiben("\033[?25h" if sichtbar else "\033[?25l")

    def _zeichnen(self, zeilen: Sequence[Sequence[Segment]]) -> None:
        """Malt einen Block und merkt sich seine Höhe. Der nächste Aufruf übermalt ihn."""
        text = f"\033[{self._hoehe}A\r\033[J" if self._hoehe else ""
        self._schreiben(text + "".join(self._setzen(z) + "\n" for z in zeilen))
        self._hoehe = len(zeilen)

    def _raeumen(self) -> None:
        if self._hoehe:
            self._schreiben(f"\033[{self._hoehe}A\r\033[J")
            self._hoehe = 0

    def _malen(self, kopf: list, rumpf: list, zeiger: int, fuss: list) -> None:
        """Malt eine Frage aus Kopf, Liste und Fusszeile. Passt die Liste nicht auf den Bildschirm, erscheint
        nur der Ausschnitt um den Zeiger: Ein Block, der höher ist als das Terminal, liesse sich nicht übermalen."""
        platz = self.zeilenzahl - 1 - len(kopf) - len(fuss)
        if len(rumpf) > platz:
            innen = max(1, platz - 2)
            start = min(max(0, zeiger - innen // 2), len(rumpf) - innen)
            rumpf = ([[("      " + ("… weiter oben" if start else ""), "matt")]] + list(rumpf[start:start + innen])
                     + [[("      " + ("… weiter unten" if start + innen < len(rumpf) else ""), "matt")]])
        self._zeichnen(list(kopf) + list(rumpf) + list(fuss))

    @contextlib.contextmanager
    def _frage(self):
        """Rahmen einer Frage im bewegten Modus: Zeiger aus, Tasten einzeln und ohne Echo.
        Am Ende verschwindet die Frage vom Bildschirm, und das Terminal ist wieder wie vorher.
        Was vor der Frage getippt wurde, zählt nicht: Niemand soll etwas beantworten, das er noch nicht gesehen hat."""
        self._zeiger(False)
        try:
            with (_einzeltasten() if self._eigene_tasten else contextlib.nullcontext()):
                with contextlib.suppress(Exception):
                    self._verwerfen()
                yield
        finally:
            self._raeumen()
            self._zeiger(True)

    def _umbrechen(self, text: str, einzug: int = 4) -> list[str]:
        return textwrap.wrap(text, width=max(24, min(self.breite, 92) - einzug - 1)) or [""]

    # ----------------------------------------------------------------------- Ausgabe

    def fett(self, text: str) -> str:
        return self._stil(text, "fett")

    def leer(self) -> None:
        self._schreiben("\n")

    def text(self, text: str, stil: str = "", einzug: int = 2) -> None:
        for zeile in text.split("\n"):
            for teil in (self._umbrechen(zeile, einzug) if self._terminal else [zeile]) if zeile else [""]:
                self._schreiben(self._setzen([(" " * einzug + teil, stil)]) + "\n")

    def linie(self, laenge: int = 60) -> None:
        self._schreiben(self._setzen([("  " + self.z.linie * max(8, min(self.breite - 4, laenge)), "matt")]) + "\n")

    def kopf(self, titel: str, unter: str = "") -> None:
        self._schreiben("\n" + self._setzen([("  " + titel, "fett")]) + "\n")
        if unter:
            self._schreiben(self._setzen([("  " + unter, "matt")]) + "\n")
        self.linie(max(len(titel), len(unter), 44))

    def abschnitt(self, titel: str) -> None:
        self._schreiben("\n" + self._setzen([("  " + titel, "fett")]) + "\n")

    def schritt(self, nr: int, von: int, titel: str) -> None:
        self._schreiben("\n" + self._setzen([(f"  {nr}/{von} ", "akzent-fett"), (titel, "fett")]) + "\n")

    def _zeichenstil(self, zeichen: str) -> str:
        return {self.z.gut: "gut", self.z.neu: "gut", self.z.fehlt: "schlecht"}.get(zeichen, "matt")

    def zeile(self, zeichen: str, was: str, wie: str = "", breit: int = 22) -> None:
        """Eine Statuszeile: Zeichen, Gegenstand, Angabe. Im Terminal werden lange Angaben unter sich
        selbst umbrochen. In einer Datei oder einem CI-Protokoll bleibt es bei einer Zeile."""
        stil = self._zeichenstil(zeichen)
        vorn = "  " + zeichen + " "
        mitte = f"{was:<{breit}} "
        einzug = len(vorn) + breit + 1
        platz = min(self.breite, self.spalten) - 1
        if not (wie and self._terminal and platz - einzug >= 24):
            self._schreiben(f"  {self._stil(zeichen, stil)} {mitte}{wie}".rstrip() + "\n")
            return
        teile = textwrap.wrap(wie, width=platz, initial_indent=" " * len(vorn + mitte), subsequent_indent=" " * einzug) or [""]
        self._schreiben(self._setzen([(vorn, stil), (mitte, ""), (teile[0].lstrip(), "")]) + "\n")
        for teil in teile[1:]:
            self._schreiben(self._setzen([(teil, "")]) + "\n")

    def punkt(self, zeichen: str, text: str, unter: str = "") -> None:
        """Ein Zeichen und ein ganzer Satz, etwa das Ergebnis eines Tests. Darunter auf Wunsch eine Erläuterung."""
        stil = self._zeichenstil(zeichen)
        vorn = "  " + zeichen + " "
        tty = self._terminal
        teile = (textwrap.wrap(text, width=max(24, self.breite - len(vorn) - 1)) or [""]) if tty else [text]
        self._schreiben(self._setzen([(vorn, stil), (teile[0], "")]) + "\n" if tty else f"  {self._stil(zeichen, stil)} {text}\n")
        for teil in teile[1:]:
            self._schreiben(self._setzen([(" " * len(vorn) + teil, "")]) + "\n")
        for teil in ((textwrap.wrap(unter, width=max(24, self.breite - len(vorn) - 3)) if tty else [unter]) if unter else []):
            self._schreiben(self._setzen([(" " * len(vorn) + "  " + teil, "matt")]) + "\n" if tty else f"      {teil}\n")

    def erledigt(self, titel: str, antwort: str, zeichen: str | None = None, breit: int = 15) -> None:
        """Was von einer beantworteten Frage stehen bleibt. Immer genau eine Zeile, damit sich der
        Block der Antworten später neu schreiben lässt (siehe zurueck)."""
        zeichen = zeichen or self.z.gut
        self._schreiben(self._setzen([("  " + zeichen + " ", self._zeichenstil(zeichen)), (f"{titel:<{breit}} ", "fett"), (antwort, "")]) + "\n")

    def zurueck(self, zeilen: int) -> None:
        """Nimmt die letzten Zeilen wieder vom Bildschirm, damit sie neu geschrieben werden können.
        Ohne Cursorsteuerung bleibt stehen, was steht."""
        if self.bewegt and zeilen > 0:
            self._schreiben(f"\033[{zeilen}A\r\033[J")

    def liste(self, titel: str, punkte: Sequence[str], nummeriert: bool = False) -> None:
        if not punkte:
            return
        self.abschnitt(titel)
        for nr, punkt in enumerate(punkte, 1):
            marke = f"{nr}." if nummeriert else self.z.neu
            einzug = 2 + len(marke) + 1
            teile = textwrap.wrap(punkt, width=max(24, self.breite - einzug - 1)) if self._terminal else [punkt]
            self._schreiben(self._setzen([(f"  {marke} ", "matt" if nummeriert else "gut"), (teile[0], "")]) + "\n")
            for teil in teile[1:]:
                self._schreiben(self._setzen([(" " * einzug + teil, "")]) + "\n")

    def paare(self, titel: str, paare: Sequence[tuple[str, str]]) -> None:
        """Ein kleiner Block aus Stichwort und Angabe, etwa die Befehle zum Loslegen."""
        self.abschnitt(titel)
        breit = max(len(name) for name, _ in paare) + 3
        for name, angabe in paare:
            teile = (textwrap.wrap(angabe, width=max(24, self.breite - breit - 5)) or [""]) if self._terminal else [angabe]
            self._schreiben(self._setzen([(f"    {name:<{breit}}", "matt"), (teile[0], "")]) + "\n")
            for teil in teile[1:]:
                self._schreiben(self._setzen([(" " * (breit + 4) + teil, "")]) + "\n")

    # ----------------------------------------------------------------------- Fragen

    def _fragekopf(self, titel: str, frage: str, erklaerung: Sequence[str], fortschritt: str, rumpf: int) -> list[list[Segment]]:
        """Kopf einer Frage. rumpf ist die Zahl der Zeilen, die danach noch folgen: Passt nicht alles
        auf den Bildschirm, fällt die Erklärung weg, denn ein zu hoher Block liesse sich nicht übermalen."""
        luecke = max(2, min(self.breite, 92) - 5 - len(titel) - len(fortschritt))
        zeilen: list[list[Segment]] = [[("  " + self.z.frage + " ", "akzent-fett"), (titel, "fett"), (" " * luecke + fortschritt, "matt")]]
        zeilen += [[("    " + teil, "")] for teil in self._umbrechen(frage)]
        erklaert = [[("    " + teil, "matt")] for absatz in erklaerung for teil in self._umbrechen(absatz)]
        if len(zeilen) + len(erklaert) + 1 + rumpf < self.zeilenzahl:
            zeilen += erklaert
        elif len(zeilen) + 1 + min(rumpf, 6) >= self.zeilenzahl:
            del zeilen[1:]          # sehr niedriges Fenster: nur der Titel, damit die Liste Platz hat
        zeilen.append([])
        return zeilen

    def _schlicht_kopf(self, titel: str, frage: str, erklaerung: Sequence[str], fortschritt: str) -> None:
        self._schreiben("\n" + self._setzen([("  " + titel, "fett"), ("   " + fortschritt if fortschritt else "", "matt")]) + "\n")
        self.text(frage, einzug=4)
        for absatz in erklaerung:
            self.text(absatz, "matt", einzug=4)

    def _schlicht_zahl(self, anzahl: int, vorgabe: int) -> int:
        while True:
            antwort = self._zeile_lesen(f"    Auswahl [{vorgabe + 1}]: ").strip()
            if not antwort:
                return vorgabe
            if antwort.isdigit() and 1 <= int(antwort) <= anzahl:
                return int(antwort) - 1
            self._schreiben(f"    Bitte eine Zahl von 1 bis {anzahl}.\n")

    def auswahl(self, titel: str, frage: str, optionen: Sequence[tuple[str, str]], vorgabe: int = 0,
                erklaerung: Sequence[str] = (), fortschritt: str = "") -> int:
        """Genau eine von mehreren Antworten. Gibt die Nummer der Antwort zurück (ab 0)."""
        if not self.interaktiv:
            return vorgabe
        if not self.bewegt:
            self._schlicht_kopf(titel, frage, erklaerung, fortschritt)
            for nr, (name, hinweis) in enumerate(optionen, 1):
                self._schreiben(f"      {nr}) {name}" + (f"   ({hinweis})" if hinweis else "") + "\n")
            return self._schlicht_zahl(len(optionen), vorgabe)
        stelle, breit = vorgabe, max(len(name) for name, _ in optionen)
        with self._frage():
            while True:
                rumpf = []
                for nr, (name, hinweis) in enumerate(optionen):
                    hier = nr == stelle
                    rumpf.append([("    " + (self.z.zeiger if hier else " ") + " ", "akzent-fett"),
                                  (self.z.an if hier else self.z.nicht_an, "akzent" if hier else "matt"),
                                  (f" {name:<{breit}}", "fett" if hier else ""), ("   " + hinweis if hinweis else "", "matt")])
                self._malen(self._fragekopf(titel, frage, erklaerung, fortschritt, len(optionen) + 2), rumpf, stelle,
                            [[], [(f"    {self.z.pfeile} bewegen · Enter übernehmen · Esc abbrechen", "matt")]])
                taste = self._taste()
                if taste in ("hoch", "k"):
                    stelle = (stelle - 1) % len(optionen)
                elif taste in ("runter", "j", "tab"):
                    stelle = (stelle + 1) % len(optionen)
                elif taste.isdigit() and 1 <= int(taste) <= len(optionen):
                    stelle = int(taste) - 1
                elif taste in ("enter", "leer"):
                    return stelle
                elif taste == "esc":
                    raise Abbruch

    def mehrfach(self, titel: str, frage: str, optionen: Sequence[tuple[str, str]], gewaehlt: set[int],
                 erklaerung: Sequence[str] = (), fortschritt: str = "") -> set[int]:
        """Beliebig viele Antworten zum Ankreuzen. Gibt die Nummern der angekreuzten zurück."""
        gewaehlt = set(gewaehlt)
        if not self.interaktiv:
            return gewaehlt
        if not self.bewegt:
            self._schlicht_kopf(titel, frage, erklaerung, fortschritt)
            for nr, (name, hinweis) in enumerate(optionen, 1):
                self._schreiben(f"      {nr}) {name}" + (f"   ({hinweis})" if hinweis else "") + "\n")
            vorgabe = ",".join(str(n + 1) for n in sorted(gewaehlt)) or "0"
            while True:
                antwort = self._zeile_lesen(f"    Nummern mit Komma, 0 für keine [{vorgabe}]: ").strip()
                if not antwort:
                    return gewaehlt
                teile = [t.strip() for t in antwort.split(",") if t.strip()]
                if all(t.isdigit() and 0 <= int(t) <= len(optionen) for t in teile):
                    return {int(t) - 1 for t in teile if int(t)}
                self._schreiben(f"    Bitte Zahlen von 1 bis {len(optionen)}, getrennt mit Komma.\n")
        stelle, breit = 0, max(len(name) for name, _ in optionen)
        with self._frage():
            while True:
                rumpf = []
                for nr, (name, hinweis) in enumerate(optionen):
                    hier, an = nr == stelle, nr in gewaehlt
                    rumpf.append([("    " + (self.z.zeiger if hier else " ") + " ", "akzent-fett"),
                                  (self.z.haken if an else self.z.kein_haken, "gut" if an else "matt"),
                                  (f" {name:<{breit}}", "fett" if hier else ""), ("   " + hinweis if hinweis else "", "matt")])
                self._malen(self._fragekopf(titel, frage, erklaerung, fortschritt, len(optionen) + 2), rumpf, stelle,
                            [[], [(f"    {self.z.pfeile} bewegen · Leertaste an/aus · Enter übernehmen · Esc abbrechen", "matt")]])
                taste = self._taste()
                if taste in ("hoch", "k"):
                    stelle = (stelle - 1) % len(optionen)
                elif taste in ("runter", "j", "tab"):
                    stelle = (stelle + 1) % len(optionen)
                elif taste == "leer":
                    gewaehlt ^= {stelle}
                elif taste.isdigit() and 1 <= int(taste) <= len(optionen):
                    stelle = int(taste) - 1
                    gewaehlt ^= {stelle}
                elif taste == "enter":
                    return gewaehlt
                elif taste == "esc":
                    raise Abbruch

    def menue(self, titel: str, frage: str, eintraege: Sequence[tuple[str, str, str]], stelle: int = 0,
              erklaerung: Sequence[str] = (), fortschritt: str = "", tasten: str = "", bedenkzeit: float = 0.0) -> tuple[int, str]:
        """Eine Liste mit Zustand je Zeile: (Name, Zustand, Stil des Zustands). Ein leerer Name ist eine
        Trennlinie. stelle ist die Zeile, auf der der Zeiger anfangs steht. Gibt (Nummer, Taste) zurück.
        Die Taste ist "enter" oder "entf", im schlichten Modus immer "enter".
        Mit bedenkzeit zählen Tasten erst nach so vielen Sekunden: Ein doppelt gedrücktes Enter aus der Frage
        davor soll nicht bestätigen, was noch niemand lesen konnte."""
        waehlbar = [nr for nr, (name, _, _) in enumerate(eintraege) if name]
        if stelle not in waehlbar:
            stelle = waehlbar[0]
        if not self.interaktiv:
            return stelle, "enter"
        breit = max([len(name) for name, zustand, _ in eintraege if zustand] or [0]) + 3      # Spalte der Zustände
        if not self.bewegt:
            self._schlicht_kopf(titel, frage, erklaerung, fortschritt)
            for lfd, nr in enumerate(waehlbar, 1):
                name, zustand, _ = eintraege[nr]
                self._schreiben(f"      {lfd}) {name:<{breit}}{zustand}".rstrip() + "\n")
            return waehlbar[self._schlicht_zahl(len(waehlbar), waehlbar.index(stelle))], "enter"
        with self._frage():
            while True:
                rumpf = []
                for nr, (name, zustand, stil) in enumerate(eintraege):
                    if not name:
                        rumpf.append([("      " + self.z.linie * max(breit + 6, 28), "matt")])
                        continue
                    hier = nr == stelle
                    rumpf.append([("    " + (self.z.zeiger if hier else " ") + " ", "akzent-fett"),
                                  (f"{name:<{breit}}", "fett" if hier else ""), (zustand, stil)])
                self._malen(self._fragekopf(titel, frage, erklaerung, fortschritt, len(eintraege) + 2), rumpf, stelle,
                            [[], [(f"    {self.z.pfeile} bewegen · Enter wählen" + (" · " + tasten if tasten else "") + " · Esc abbrechen", "matt")]])
                if bedenkzeit and self._eigene_tasten:
                    time.sleep(bedenkzeit)
                    with contextlib.suppress(Exception):
                        self._verwerfen()
                    bedenkzeit = 0.0
                taste = self._taste()
                lage = waehlbar.index(stelle)
                if taste in ("hoch", "k"):
                    stelle = waehlbar[(lage - 1) % len(waehlbar)]
                elif taste in ("runter", "j", "tab"):
                    stelle = waehlbar[(lage + 1) % len(waehlbar)]
                elif taste in ("enter", "entf"):
                    return stelle, taste
                elif taste == "esc":
                    raise Abbruch

    def eingabe(self, titel: str, frage: str, vorgabe: str = "", verdeckt: bool = False, erklaerung: Sequence[str] = (),
                pruefung: Callable[[str], str | None] | None = None, fortschritt: str = "") -> str | None:
        """Eine Zeile Text. Mit verdeckt=True erscheinen statt der Zeichen nur Punkte, und die Antwort steht
        nie auf dem Bildschirm. Gibt None zurück, wenn mit Esc abgebrochen wurde, und "" bei leerer Eingabe."""
        if not self.interaktiv:
            return vorgabe
        if not self.bewegt:
            self._schlicht_kopf(titel, frage, erklaerung, fortschritt)
            while True:
                if verdeckt and self._zeile_lesen is input:
                    antwort = getpass.getpass("    Eingabe (bleibt unsichtbar, leer = überspringen): ")
                else:
                    antwort = self._zeile_lesen(f"    Eingabe [{vorgabe}]: " if vorgabe and not verdeckt else "    Eingabe: ")
                antwort = antwort.strip() or ("" if verdeckt else vorgabe)
                fehler = pruefung(antwort) if pruefung and antwort else None
                if not fehler:
                    return antwort
                self._schreiben(f"    {fehler}\n")
        wert, fehler, zeichnen = ("" if verdeckt else vorgabe), "", True
        with self._frage():
            while True:
                if zeichnen:
                    zeilen = self._fragekopf(titel, frage, erklaerung, fortschritt, 3)
                    if verdeckt:
                        gezeigt, zaehler = self.z.verdeckt * min(len(wert), 32), (f"  {len(wert)} Zeichen" if wert else "")
                    else:
                        platz = self.spalten - 10
                        gezeigt, zaehler = (wert if len(wert) <= platz else "…" + wert[-(platz - 1):]), ""
                    zeilen.append([("    " + self.z.zeiger + " ", "akzent-fett"), (gezeigt, ""), (self.z.marke, "akzent"), (zaehler, "matt")])
                    zeilen.append([("    " + fehler, "schlecht")] if fehler else [])
                    zeilen.append([("    Enter übernehmen · Esc zurück" + (" · Eingabe bleibt unsichtbar" if verdeckt else ""), "matt")])
                    self._zeichnen(zeilen)
                taste = self._taste()
                if taste == "enter":
                    antwort = wert.strip()
                    fehler = (pruefung(antwort) if pruefung and antwort else None) or ""
                    if not fehler:
                        return antwort
                elif taste == "esc":
                    return None
                elif taste == "einfuegen":      # alte Windows-Konsole: Strg+V kommt als Zeichen an statt als Text
                    fehler = "Strg+V kommt in diesem Fenster nicht als Text an. Einfügen mit Rechtsklick."
                elif taste == "rueck":
                    wert, fehler = wert[:-1], ""
                elif taste == "leeren":
                    wert, fehler = "", ""
                elif taste == "leer":
                    wert, fehler = wert + " ", ""
                elif len(taste) == 1 and taste.isprintable():
                    wert, fehler = wert + taste, ""
                zeichnen = not self._wartet()   # beim Einfügen kommen viele Zeichen auf einmal: erst am Ende neu zeichnen

    # ----------------------------------------------------------------------- Laufanzeige

    @contextlib.contextmanager
    def arbeit(self, text: str | None):
        """Zeigt während einer längeren Arbeit eine laufende Zeile mit der verstrichenen Zeit.
        Ohne steuerbares Terminal geschieht nichts: In einem Protokoll hätte die Zeile nichts verloren."""
        if not self.bewegt or not text:
            yield
            return
        ende, beginn = threading.Event(), time.monotonic()

        def drehen() -> None:
            bild = 0
            while not ende.wait(0.09):
                dauer = int(time.monotonic() - beginn)
                self._schreiben("\r\033[2K" + self._setzen([("  " + self.z.dreher[bild % len(self.z.dreher)] + " ", "akzent"),
                                                           (text, ""), (f"   {dauer} s" if dauer >= 3 else "", "matt")]))
                bild += 1
        faden = threading.Thread(target=drehen, daemon=True)
        self._zeiger(False)
        faden.start()
        try:
            yield
        finally:
            ende.set()
            faden.join()
            self._schreiben("\r\033[2K")
            self._zeiger(True)
