#!/usr/bin/env python3
"""Den Arbeitsplatz von diesem Rechner entfernen: zeigen, was dazugehört, und alles löschen.

    python3 tools/loeschen.py                             zeigt, was «Alles löschen» entfernen würde und was bleibt. Ändert nichts
    python3 tools/loeschen.py alles                       löscht den Arbeitsplatz. Sichert vorher die Fallakten und fragt nach
    python3 tools/loeschen.py alles --sicherung <Ordner>  legt die Sicherung in diesen Ordner (Vorgabe: OSINT-Sicherung im Benutzerordner)

Was «alles» tut, in dieser Reihenfolge:

  1. Der Bericht wird angelegt, im Ordner der Sicherung. Lässt er sich nicht schreiben, geschieht nichts.
  2. Was läuft, wird beendet: die Oberfläche samt laufender Ermittlung, Robin und Web-Check.
  3. Die Fallakten und die Sitzungsprotokolle werden gesichert: ein Archiv ausserhalb des Projekts, mit der Prüfsumme jeder
     Datei. Das Archiv wird geprüft, bevor irgendetwas gelöscht wird. Scheitert die Sicherung, bleibt alles, wie es ist.
  4. Gelöscht werden: die Schlüsseldatei, Fallakten und Sitzungsprotokolle im Projekt, die Einstellungen des Arbeitsplatzes,
     die Container und Abbilder von Web-Check und Robin, und am Schluss der Projektordner selbst, mit Code und Python-Umgebung.
     Gibt es aus einer früheren Einrichtung noch das Docker-Volume, in das Robin eigene Recherchen ablegen konnte, kommt sein
     Inhalt in den Sicherungsordner, dann wird es entfernt.

Was bleibt: die Sicherung der Fallakten, die Ablage des Sachbearbeiters (Klartext und Zuordnungstabellen), die
Gesprächsverläufe, die Claude Code selbst führt, und was die Einrichtung im System installiert hat (Claude Code, Docker,
Tor, ein Browser). Der Bericht am Schluss nennt jeden dieser Orte.

Es beginnt gar nicht erst, wenn in den Fallakten ein Verweis auf einen anderen Ort liegt (gelöscht würde nur er) oder
wenn die Ablage im Projektordner liegt (sie würde mit entfernt). Dann steht da, woran es liegt, und nichts ist geändert.

Fallakten und Protokolle sind Beweismittel. Einen Weg, sie ohne Sicherung zu löschen, gibt es deshalb nicht: Wer auch
die Sicherung nicht mehr braucht, entfernt sie selbst und bewusst.

«alles» verlangt ein Terminal und läuft nicht aus Claude Code heraus: Das entscheidet ein Mensch. Zur Bestätigung tippt
er den Namen des Projektordners ein. In der Oberfläche gibt es dasselbe auf der Seite «Arbeitsplatz», nur aus dem
bedienbaren Fenster. Rückgabewert 0: erledigt. 1: Etwas liess sich nicht löschen. 2: nicht ausgeführt (falscher Aufruf,
kein Terminal, abgebrochen, Sicherung gescheitert).

Den Projektordner selbst entfernt ein kleiner Helfer, sobald dieses Werkzeug beendet ist: Ein Programm kann den Ordner,
aus dem es läuft, nicht auf jedem System selbst entfernen. Der Helfer prüft vorher noch einmal, dass der Ordner dieses
Projekt ist und nichts Fremdes.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start(venv=False)     # nur die Standardbibliothek: Das Werkzeug läuft nie aus der Python-Umgebung, die es entfernt

from gateway.plattform import AUS, FEHLT, GUT, PY, WINDOWS  # noqa: E402
from tools import dienste, einrichten  # noqa: E402

PROJEKT = plattform.PROJEKT
Zeile = tuple[str, str, str]        # Zeichen, was, wie
SICHERUNG = "OSINT-Sicherung"       # Vorgabe: dieser Ordner im Benutzerordner
ABLAGE = "OSINT-Ablage"             # die Vorgabe der Oberfläche für Klartext und Zuordnungstabellen. Sie bleibt immer
# Woran der Projektordner erkannt wird, bevor er entfernt wird: Diese Dateien gibt es nur hier
KENNZEICHEN = ("gateway/kern.py", "tools/loeschen.py", "tools/fall.py", ".mcp.json", ".claude/settings.json")
SCHLUESSELDATEIEN = (".env", ".env.local")
# Neben faelle/ gehört in die Sicherung: protokoll/ (die Sitzungsprotokolle aller Fälle liegen dort) und intern/ (ein Ordner,
# den das Repository für eigene Unterlagen ausspart). Beides steht nicht im Repository und verschwände mit dem Projektordner.
SICHERN_AUCH = ("protokoll", "intern")
BLOCK = 1024 * 1024


class Fehler(Exception):
    """Etwas, das dem Menschen gesagt werden muss. Nach einem solchen Fehler ist nichts gelöscht."""


# --------------------------------------------------------------------------- Was dazugehört

def innerhalb(pfad: Path, ordner: Path) -> bool:
    """Liegt `pfad` in `ordner` oder ist er dieser Ordner? Beide werden vorher aufgelöst: Ein Verweis täuscht nicht."""
    try:
        Path(pfad).resolve().relative_to(Path(ordner).resolve())
    except ValueError:
        return False
    return True


def nicht_loeschbar(ordner: Path, bericht: Path | None = None) -> str:
    """Warum sich dieser Ordner nicht als Projektordner entfernen lässt. Leer, wenn nichts dagegen spricht.
    Dieselbe Prüfung macht der Helfer noch einmal, unmittelbar bevor er löscht."""
    ordner = Path(ordner)
    if not ordner.is_absolute() or ordner != ordner.resolve():
        return f"{ordner} ist kein aufgelöster, vollständiger Pfad."
    if not ordner.is_dir() or ordner.is_symlink():
        return f"{ordner} ist kein Ordner."
    if ordner.parent == ordner:
        return "Das ist die Wurzel des Dateisystems."
    fehlend = [k for k in KENNZEICHEN if not (ordner / k).is_file()]
    if fehlend:
        return f"{ordner} ist nicht der Projektordner dieses Arbeitsplatzes: {', '.join(fehlend)} fehlt."
    if innerhalb(Path.home(), ordner):
        return f"Der Benutzerordner liegt in {ordner}."
    if bericht is not None and innerhalb(bericht, ordner):
        return "Der Bericht läge im Ordner, der entfernt wird."
    return ""


def sicherungsordner(wunsch: str | os.PathLike | None, projekt: Path = PROJEKT) -> Path:
    """Wohin die Fallakten gesichert werden. Nie in den Projektordner: Der wird entfernt."""
    ordner = Path(wunsch).expanduser() if wunsch else Path.home() / SICHERUNG
    ordner = ordner if ordner.is_absolute() else Path.cwd() / ordner
    if innerhalb(ordner, projekt):
        raise Fehler(f"Die Sicherung darf nicht im Projektordner liegen ({ordner}): Er wird entfernt. Bitte einen Ordner ausserhalb angeben.")
    if ordner.exists() and not ordner.is_dir():
        raise Fehler(f"{ordner} ist kein Ordner.")
    return ordner


def ist_muster(fall: Path) -> bool:
    """Der Musterfall gehört zum Repository und ist erfunden. Er wird nicht gesichert."""
    try:
        return json.loads((fall / "fall.json").read_text(encoding="utf-8")).get("muster") is True
    except (OSError, ValueError, AttributeError):
        return False


def _zeilenzahl(datei: Path) -> int:
    try:
        with open(datei, "rb") as f:
            return sum(1 for zeile in f if zeile.strip())
    except OSError:
        return 0


def fallakten(projekt: Path = PROJEKT) -> list[dict]:
    """Die Fallakten im Projekt: je Fall die Zahl der Protokolleinträge, der Dateien und die Grösse. Titel und Inhalt
    stehen hier nicht: Der Plan wird gezeigt und in den Bericht geschrieben."""
    aus = []
    wurzel = projekt / "faelle"
    for ordner in sorted(p for p in wurzel.iterdir() if p.is_dir()) if wurzel.is_dir() else []:
        dateien = [d for d in ordner.rglob("*") if d.is_file() and not d.is_symlink()]
        aus.append({"id": ordner.name, "muster": ist_muster(ordner), "dateien": len(dateien), "bytes": sum(d.stat().st_size for d in dateien),
                    "eintraege": _zeilenzahl(ordner / "protokoll" / "abfragen.jsonl") + _zeilenzahl(ordner / "protokoll" / "extern.jsonl")})
    return aus


def zu_sichern(projekt: Path = PROJEKT) -> list[Path]:
    """Jede Datei, die Beweismittel sein kann und nicht zum Repository gehört: alle Fallakten unter faelle/ ausser dem
    Musterfall (auch lose Dateien), die Sitzungsprotokolle unter protokoll/ und, falls vorhanden, der Ordner intern/."""
    dateien: list[Path] = []
    wurzel = projekt / "faelle"
    if wurzel.is_dir():
        muster = [p.resolve() for p in wurzel.iterdir() if p.is_dir() and ist_muster(p)]
        dateien += [d for d in wurzel.rglob("*") if d.is_file() and not d.is_symlink() and d != wurzel / "README.md"
                    and not any(m in d.resolve().parents for m in muster)]
    for name in SICHERN_AUCH:
        if (projekt / name).is_dir():
            dateien += [d for d in (projekt / name).rglob("*") if d.is_file() and not d.is_symlink()]
    return sorted(dateien)


def verweise(projekt: Path = PROJEKT) -> list[str]:
    """Verweise in dem, was gesichert wird: die Ordner selbst (etwa faelle als Verweis auf ein anderes Laufwerk) und alles
    darin. Ein Verweis zeigt irgendwohin: Gelöscht würde nur er, und was hinter ihm liegt, bliebe an seinem Ort."""
    gefunden: list[str] = []
    for name in ("faelle", *SICHERN_AUCH):
        wurzel = projekt / name
        if plattform.ist_verweis(wurzel):
            gefunden.append(name)
        elif wurzel.is_dir():
            gefunden += [d.relative_to(projekt).as_posix() for d in wurzel.rglob("*") if plattform.ist_verweis(d)]
    return sorted(gefunden)


def ablageort(wunsch: str | os.PathLike | None = None) -> Path:
    """Wo die Ablage des Sachbearbeiters liegt, soweit dieses Werkzeug es wissen kann: die der laufenden Oberfläche
    (`wunsch`), sonst OSINT_ABLAGE, sonst die Vorgabe im Benutzerordner."""
    eigen = os.environ.get("OSINT_ABLAGE", "").strip()
    return Path(wunsch).expanduser() if wunsch else Path(eigen).expanduser() if eigen else Path.home() / ABLAGE


def hindernis(projekt: Path, ablage: Path) -> str:
    """Was dagegen spricht, diesen Arbeitsplatz zu löschen, bevor irgendetwas geschieht. Leer, wenn nichts dagegen spricht."""
    grund = nicht_loeschbar(projekt)
    if grund:
        return grund
    if innerhalb(ablage, projekt):      # sie würde mit dem Ordner entfernt, samt den Zuordnungstabellen
        return (f"Die Ablage des Sachbearbeiters liegt im Projektordner ({ablage}). Sie würde mit entfernt, samt den Zuordnungstabellen. "
                "Bitte zuerst an einen Ort ausserhalb verschieben.")
    fremd = verweise(projekt)
    if fremd:                           # die Sicherung nähme mit, was dahinter liegt, das Löschen aber nur den Verweis
        return (f"In den Fallakten liegt ein Verweis auf einen anderen Ort ({', '.join(fremd[:3])}). Bitte zuerst von Hand klären, was dahinter liegt: "
                "Gelöscht würde nur der Verweis.")
    return ""


def schluesselzahl(projekt: Path = PROJEKT) -> int:
    """Wie viele Einträge mit einem Wert die Schlüsseldateien haben. Gelesen wird nur, ob ein Wert dasteht."""
    zahl = 0
    for name in SCHLUESSELDATEIEN:
        zahl += len(einrichten.env_lesen(projekt / name))
    return zahl


def git_offen(projekt: Path = PROJEKT) -> int | None:
    """Wie viele Dateien im Projektordner verändert oder neu sind und nicht im Repository stehen (ohne das, was das
    Repository absichtlich auslässt: Fallakten, Schlüsseldatei, Python-Umgebung). None: lässt sich nicht sagen."""
    if not (projekt / ".git").exists():
        return None
    code, text = einrichten.lauf(["git", "-C", str(projekt), "status", "--porcelain", "--untracked-files=all"], 30)
    return len([z for z in text.splitlines() if z.strip()]) if code == 0 else None


def webcheck_abbild(projekt: Path = PROJEKT) -> str:
    """Das Abbild von Web-Check, wie docker-compose.yml es festlegt."""
    try:
        m = re.search(r"^\s*image:\s*(\S+)", (projekt / "docker-compose.yml").read_text(encoding="utf-8"), re.M)
    except OSError:
        return ""
    return m.group(1) if m else ""


def groesse(n: int) -> str:
    return f"{n} B" if n < 1024 else f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / (1024 * 1024):.1f} MB".replace(".", ",")


def plan(projekt: Path = PROJEKT, sicherung: str | os.PathLike | None = None, mit_oberflaeche: bool = True, laeuft: dict | None = None,
         ablage: str | os.PathLike | None = None) -> dict:
    """Was «Alles löschen» täte, ohne etwas zu ändern: für die Anzeige am Terminal und in der Oberfläche.
    `hindernis`: weshalb es gar nicht ginge (leer, wenn nichts dagegen spricht). `laeuft`: der Stand der Dienste, wenn der
    Aufrufer ihn schon kennt (dienste.stand()). Die Oberfläche fragt sich dabei nicht selbst (mit_oberflaeche=False) und
    nennt ihre eigene Ablage (`ablage`)."""
    projekt = Path(projekt).resolve()
    grund = hindernis(projekt, ablageort(ablage))
    try:
        ordner: Path | None = sicherungsordner(sicherung, projekt)
    except Fehler as e:
        ordner, grund = None, grund or str(e)
    akten = fallakten(projekt)
    dateien = zu_sichern(projekt)
    return {"projekt": str(projekt), "name": projekt.name, "hindernis": grund,
            "sicherung": str(ordner) if ordner else "", "faelle": akten,
            "sichern": {"faelle": [f["id"] for f in akten if not f["muster"]], "dateien": len(dateien), "bytes": sum(d.stat().st_size for d in dateien)},
            "schluessel": schluesselzahl(projekt), "git_offen": git_offen(projekt), "laeuft": laeuft if laeuft is not None else dienste.stand(mit_oberflaeche),
            "abbilder": [a for a in (webcheck_abbild(projekt), dienste.robin_abbild()) if a],
            "bleibt": bleibt(ordner, ablage)}


def bleibt(sicherung: Path | None, ablage: str | os.PathLike | None = None) -> list[tuple[str, str]]:
    """Was nach dem Löschen auf dem Rechner bleibt, mit dem Ort. Nichts davon fasst das Werkzeug an."""
    # Ohne Angabe kennt das Werkzeug nur die Vorgabe: Wer die Oberfläche mit --ablage startet, hat die Ablage an dem dort genannten Ort
    vorgabe = "" if ablage or os.environ.get("OSINT_ABLAGE", "").strip() else " Wer die Oberfläche mit --ablage startet, hat sie am dort genannten Ort."
    konto = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    return [("Sicherung der Fallakten", str(sicherung) if sicherung else "(kein Ordner festgelegt)"),
            ("Ablage des Sachbearbeiters", f"{ablageort(ablage)} (Klartext, Zuordnungstabellen, Fehlerprotokoll).{vorgabe} Ohne die Zuordnungstabellen lassen sich "
                                           "die gesicherten Rapporte nicht mehr zurückführen"),
            ("Claude Code", f"das Programm, eure Anmeldung und seine Gesprächsverläufe ({konto / 'projects'})"),
            ("Im System installiert", "Docker, Tor, ein Browser für PDF, pdftotext: was die Einrichtung dort installiert hat, bleibt")]


def plan_zeilen(p: dict) -> list[Zeile]:
    """Der Plan in Zeilen, für das Terminal und den Bericht."""
    zeilen: list[Zeile] = []
    echt = [f for f in p["faelle"] if not f["muster"]]
    if p["sichern"]["dateien"]:
        abgefragt = sum(1 for f in echt if f["eintraege"])
        wie = (f"{len(echt)} {'Fall' if len(echt) == 1 else 'Fälle'}, davon {abgefragt} mit Abfragen" if echt else "kein Fall, aber Sitzungsprotokolle oder lose Dateien")
        zeilen.append((GUT, "Fallakten und Sitzungsprotokolle", f"{wie} ({p['sichern']['dateien']} Dateien, {groesse(p['sichern']['bytes'])}): "
                                                                "werden gesichert, dann aus dem Projekt gelöscht"))
        zeilen.append((GUT, "Sicherung", f"{p['sicherung']} (Archiv mit Prüfsummen, geprüft vor dem Löschen)"))
    else:
        zeilen.append((AUS, "Fallakten und Sitzungsprotokolle", "keine ausser dem Musterfall: nichts zu sichern"))
    zeilen.append((GUT, "Schlüsseldatei", f"{p['schluessel']} {'Eintrag' if p['schluessel'] == 1 else 'Einträge'}: wird gelöscht, nicht gesichert")
                  if p["schluessel"] else (AUS, "Schlüsseldatei", "kein Schlüssel eingetragen"))
    laeuft = p["laeuft"]
    offen = laeuft.get("oberflaechen")
    if offen:
        zeilen.append((GUT, "Oberfläche", f"läuft auf Port {', '.join(str(o['port']) for o in offen)}: wird beendet, laufende Ermittlungen werden angehalten"))
    docker = laeuft["docker"]
    if not docker["installiert"]:
        zeilen.append((AUS, "Docker", "nicht installiert: keine Container und Abbilder"))
    elif not docker["laeuft"]:
        zeilen.append((FEHLT, "Docker", "läuft nicht oder ist von hier nicht erreichbar: Container und Abbilder von Web-Check und Robin bleiben. "
                                        "Der Bericht nennt die Befehle dafür"))
    else:
        zeilen.append((GUT, "Web-Check und Robin", "Container werden entfernt, die Abbilder ebenso"))
        ablage = laeuft.get("robin_ablage")
        if ablage:      # ein Docker-Volume aus einer früheren Einrichtung: Dort konnte Robin eigene Recherchen ablegen, ausserhalb der Fallakte
            zeilen.append((GUT, "Ablage von Robin", f"Docker-Volume {dienste.ROBIN_VOLUME} aus einer früheren Einrichtung: "
                           + ("leer, wird entfernt" if ablage["dateien"] == 0 else "wird in die Sicherung gelegt und dann entfernt")))
    zeilen.append((GUT, "Projektordner", f"{p['projekt']}: wird am Schluss entfernt, mit Code, Einstellungen und Python-Umgebung"))
    if p["git_offen"]:
        zeilen.append((FEHLT, "Achtung", f"Im Projektordner liegen {p['git_offen']} Dateien, die verändert oder neu sind und nicht im Repository stehen. "
                                         "Sie gehen verloren"))
    elif p["git_offen"] is None:
        zeilen.append((AUS, "Eigene Dateien", "Ob im Projektordner eigene Dateien liegen, lässt sich hier nicht feststellen (kein Git-Arbeitsverzeichnis, oder "
                                              "Git antwortet nicht). Gesichert wird nur, was unter faelle/, protokoll/ und intern/ liegt"))
    return zeilen


# --------------------------------------------------------------------------- Sichern

def _summe(datei: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(datei, "rb") as f:
        while block := f.read(BLOCK):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


LIESMICH = """Sicherung der Fallakten des OSINT-Ermittlungsarbeitsplatzes

Angelegt am {zeit} von «Alles löschen» ({weg}), bevor der Arbeitsplatz von diesem Rechner entfernt wurde.
Projektordner: {projekt}

Inhalt: jede Datei unter faelle/ ausser dem erfundenen Musterfall, die Sitzungsprotokolle aller Fälle unter protokoll/
und, falls vorhanden, der Ordner intern/. INHALT.txt nennt je Datei SHA-256, Grösse und Pfad.
Die Protokollkette jedes Falls ist unverändert: Sie lässt sich nach dem Zurückspielen prüfen.

Zurückspielen in einen neu eingerichteten Arbeitsplatz:
  1. Dieses Archiv im Projektordner entpacken. Die Ordner landen unter faelle/ und protokoll/.
  2. Je Fall prüfen:  python3 tools/audit_pruefen.py <Fall-ID>

Fallakten und Protokolle sind Beweismittel. Wer diese Sicherung löscht, entscheidet das bewusst und nach den Regeln
seiner Dienststelle. Zum Zurückführen der Rapporte braucht es zusätzlich die Zuordnungstabellen aus der Ablage.
"""


def ordner_anlegen(ordner: Path) -> None:
    """Legt den Ordner für Sicherung und Bericht an. Einen neuen nur für das eigene Konto (Linux, macOS). An einem Ordner,
    den es schon gibt, ändert das Werkzeug nichts: Er gehört ihm nicht."""
    neu = not ordner.exists()
    ordner.mkdir(parents=True, exist_ok=True)
    if neu and not WINDOWS:
        os.chmod(ordner, 0o700)


def sichern(projekt: Path, ordner: Path, zeit: datetime, weg: str = "Terminal") -> dict | None:
    """Sichert die Fallakten in ein Archiv im Sicherungsordner und prüft es: Jede Datei im Archiv hat die Prüfsumme ihrer
    Quelle, und die Quelle hat sich seit dem Lesen nicht verändert. Gibt None zurück, wenn es nichts zu sichern gibt.
    Bei jedem Fehler bleibt kein halbes Archiv liegen, und es wird nichts gelöscht."""
    dateien = zu_sichern(projekt)
    fremd = verweise(projekt)
    if fremd:           # die Sicherung nähme mit, was dahinter liegt, das Löschen aber nur den Verweis
        raise Fehler(f"In den Fallakten liegt ein Verweis auf einen anderen Ort ({', '.join(fremd[:3])}). Bitte zuerst von Hand klären, was dahinter liegt.")
    if not dateien:
        return None
    try:
        ordner_anlegen(ordner)
    except OSError as e:
        raise Fehler(f"Der Ordner für die Sicherung liess sich nicht anlegen ({ordner}): {e}") from e
    archiv = ordner / f"fallakten-{zeit.strftime('%Y%m%d-%H%M%S')}.zip"
    if archiv.exists():
        raise Fehler(f"{archiv} gibt es schon. Bitte in einer Sekunde noch einmal versuchen.")
    summen: dict[str, tuple[str, int]] = {}
    try:
        # Unter Linux und macOS von Anfang an nur für das eigene Konto lesbar. Unter Windows gelten die Rechte des Ordners.
        # O_BINARY: Unter Windows verfälschte der Textmodus sonst jeden Zeilenumbruch im Archiv
        griff = os.open(archiv, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(griff, "wb") as roh, zipfile.ZipFile(roh, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            for datei in dateien:
                name = datei.relative_to(projekt).as_posix()
                eintrag = zipfile.ZipInfo.from_file(datei, name, strict_timestamps=False)
                eintrag.compress_type = zipfile.ZIP_DEFLATED
                h, n = hashlib.sha256(), 0
                with open(datei, "rb") as quelle, z.open(eintrag, "w", force_zip64=True) as ziel:
                    while block := quelle.read(BLOCK):
                        h.update(block)
                        n += len(block)
                        ziel.write(block)
                summen[name] = (h.hexdigest(), n)
            inhalt = "".join(f"{summe}  {zahl:>12}  {name}\n" for name, (summe, zahl) in summen.items())
            z.writestr("INHALT.txt", inhalt)
            z.writestr("LIESMICH.txt", LIESMICH.format(zeit=zeit.astimezone().isoformat(timespec="seconds"), weg=weg, projekt=projekt))
        # Prüfen, bevor irgendetwas gelöscht wird: das Archiv gegen die gelesenen Prüfsummen, die Quellen gegen sich selbst
        with zipfile.ZipFile(archiv) as z:
            if sorted(z.namelist()) != sorted([*summen, "INHALT.txt", "LIESMICH.txt"]):
                raise Fehler("Die Sicherung ist unvollständig: Im Archiv stehen nicht dieselben Dateien wie im Projekt.")
            for name, (summe, zahl) in summen.items():
                h, n = hashlib.sha256(), 0
                with z.open(name) as f:
                    while block := f.read(BLOCK):
                        h.update(block)
                        n += len(block)
                if (h.hexdigest(), n) != (summe, zahl):
                    raise Fehler(f"Die Sicherung stimmt nicht: {name} hat im Archiv eine andere Prüfsumme als im Projekt.")
        for datei in dateien:
            name = datei.relative_to(projekt).as_posix()
            if not datei.is_file() or _summe(datei) != summen[name]:
                raise Fehler(f"Während der Sicherung hat sich {name} verändert. Läuft noch eine Ermittlung? Bitte beenden und noch einmal versuchen.")
        if sorted(d.relative_to(projekt).as_posix() for d in zu_sichern(projekt)) != sorted(summen):
            raise Fehler("Während der Sicherung sind in den Fallakten Dateien dazugekommen oder verschwunden. Läuft noch eine Ermittlung? "
                         "Bitte beenden und noch einmal versuchen.")
        gesamt = _summe(archiv)[0]
        plattform.text_schreiben(Path(str(archiv) + ".sha256"), f"{gesamt}  {archiv.name}\n")
    except (OSError, zipfile.BadZipFile, Fehler) as e:
        with contextlib.suppress(OSError):
            archiv.unlink()
        if isinstance(e, Fehler):
            raise
        raise Fehler(f"Die Sicherung liess sich nicht schreiben ({archiv}): {e}") from e
    return {"archiv": str(archiv), "sha256": gesamt, "dateien": len(summen), "bytes": sum(n for _, n in summen.values()),
            "faelle": sorted({name.split("/")[1] for name in summen if name.startswith("faelle/") and name.count("/") >= 2})}


# --------------------------------------------------------------------------- Löschen

def robin_ablage_sichern(docker: dict, ziel: Path) -> str:
    """Sichert den Inhalt des Volumes als tar-Archiv nach `ziel` und prüft, dass es sich lesen lässt. Gibt den Grund zurück, wenn es
    nicht ging, sonst ''."""
    befehl = docker["vor"] + ["docker", "run", "--rm", "--network", "none", "--entrypoint", "tar", "-v", f"{dienste.ROBIN_VOLUME}:/v:ro", dienste.robin_abbild(), "-C", "/v", "-cf", "-", "."]
    try:
        with open(ziel, "wb") as f:
            r = subprocess.run(befehl, stdout=f, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=600)
        if r.returncode != 0:
            raise OSError((r.stderr.decode("utf-8", "replace").strip().splitlines() or ["Docker meldet einen Fehler"])[-1])
        with tarfile.open(ziel) as archiv:
            archiv.getmembers()
    except (OSError, subprocess.TimeoutExpired, tarfile.TarError) as e:
        with contextlib.suppress(OSError):
            ziel.unlink()
        return f"{type(e).__name__}: {e}"
    return ""


def robin_ablage_entfernen(docker: dict) -> bool:
    return einrichten.lauf(docker["vor"] + ["docker", "volume", "rm", dienste.ROBIN_VOLUME], 60, "docker.log")[0] == 0


def docker_entfernen(projekt: Path = PROJEKT, ordner: Path | None = None, zeit: datetime | None = None) -> tuple[list[Zeile], bool]:
    """Entfernt die Container und Abbilder von Web-Check und Robin, und das Docker-Volume, in das Robin früher eigene Recherchen
    ablegen konnte: Was darin liegt, kommt zuerst in den Sicherungsordner (`ordner`). Docker selbst bleibt: Es kann auch anderem dienen."""
    docker = dienste.docker_kurz()
    abbilder = [a for a in (webcheck_abbild(projekt), dienste.robin_abbild()) if a]
    von_hand = f"docker rm -f {dienste.WEBCHECK}; docker image rm {' '.join(abbilder)}"
    if not docker["installiert"]:
        return [(AUS, "Docker", "nicht installiert: keine Container und Abbilder")], True
    if not docker["laeuft"]:
        return [(FEHLT, "Docker", f"läuft nicht oder ist von hier nicht erreichbar. Container und Abbilder bleiben. Später von Hand: {von_hand}")], False
    zeilen: list[Zeile] = []
    gelungen = True
    # Auch angehaltene Container: «rm -f» beendet und entfernt in einem Schritt
    code, text = einrichten.lauf(docker["vor"] + ["docker", "ps", "-aq", "--filter", f"ancestor={dienste.robin_abbild()}"], 20)
    container = (text.split() if code == 0 else []) + ([dienste.WEBCHECK] if dienste.webcheck(docker) in ("laeuft", "aus") else [])
    if container:
        code, _ = einrichten.lauf(docker["vor"] + ["docker", "rm", "-f", *container], 180, "docker.log")
        zeilen.append((GUT, "Container", f"entfernt ({len(container)})") if code == 0 else
                      (FEHLT, "Container", f"liessen sich nicht entfernen. Von Hand: docker rm -f {' '.join(container)}"))
        gelungen = gelungen and code == 0
    else:
        zeilen.append((AUS, "Container", "keine vorhanden"))
    # Die Ablage von Robin: vor den Abbildern, denn sichern lässt sich ein Volume nur mit einem Container
    ablage = dienste.robin_ablage(docker)
    if ablage:
        von_hand_ablage = f"docker volume rm {dienste.ROBIN_VOLUME}"
        grund, archiv = "", None
        if ablage["dateien"] != 0:      # Dateien darin, oder sie liessen sich nicht zählen: sichern, bevor etwas entfernt wird
            if ordner is None:
                grund = "kein Sicherungsordner"
            else:
                archiv = ordner / f"robin-ablage-{(zeit or datetime.now()).strftime('%Y%m%d-%H%M%S')}.tar"
                grund = robin_ablage_sichern(docker, archiv)
        if grund:
            zeilen.append((FEHLT, "Ablage von Robin", f"Das Docker-Volume {dienste.ROBIN_VOLUME} liess sich nicht sichern ({grund}). Es bleibt. "
                                                      f"Später von Hand ansehen und entfernen: {von_hand_ablage}"))
            gelungen = False
        elif robin_ablage_entfernen(docker):
            zeilen.append((GUT, "Ablage von Robin", f"Docker-Volume {dienste.ROBIN_VOLUME} entfernt"
                           + (f", Inhalt gesichert: {archiv} ({groesse(archiv.stat().st_size)})" if archiv else " (es war leer)")))
        else:
            zeilen.append((FEHLT, "Ablage von Robin", f"Das Docker-Volume {dienste.ROBIN_VOLUME} liess sich nicht entfernen"
                           + (f" (sein Inhalt ist gesichert: {archiv})" if archiv else "") + f". Von Hand: {von_hand_ablage}"))
            gelungen = False
    for abbild in abbilder:
        if einrichten.lauf(docker["vor"] + ["docker", "image", "inspect", abbild], 20)[0] != 0:
            continue                    # nie geladen
        code, _ = einrichten.lauf(docker["vor"] + ["docker", "image", "rm", abbild], 180, "docker.log")
        kurz = abbild.split("@")[0]
        zeilen.append((GUT, "Abbild", f"{kurz} entfernt") if code == 0 else
                      (FEHLT, "Abbild", f"{kurz} liess sich nicht entfernen (wird es noch gebraucht?). Von Hand: docker image rm {abbild}"))
        gelungen = gelungen and code == 0
    return zeilen, gelungen


def _weg(pfad: Path) -> str:
    """Entfernt eine Datei oder einen Ordner. Gibt den Grund zurück, wenn es nicht ging, sonst ''."""
    try:
        if pfad.is_dir() and not pfad.is_symlink():
            plattform.baum_loeschen(pfad)
        elif pfad.exists() or pfad.is_symlink():
            pfad.unlink()
    except OSError as e:
        return f"{type(e).__name__}: {e.strerror or e}"
    return "" if not pfad.exists() else "ist noch da"


def daten_loeschen(projekt: Path = PROJEKT) -> tuple[list[Zeile], bool]:
    """Löscht, was schützenswert ist, sofort und in dieser Reihenfolge: Schlüssel, Fallakten, Einstellungen des Arbeitsplatzes.
    Der Rest des Projektordners (Code, Python-Umgebung) folgt mit dem Ordner selbst."""
    zeilen: list[Zeile] = []
    gelungen = True
    for was, pfade in (("Schlüsseldatei", [projekt / n for n in SCHLUESSELDATEIEN]),
                       ("Fallakten und Sitzungsprotokolle im Projekt", [projekt / "faelle", *(projekt / n for n in SICHERN_AUCH)]),
                       ("Einstellungen des Arbeitsplatzes", [projekt / ".claude" / "settings.local.json"]),
                       ("Geladene Listen", [projekt / "listen"])):
        da = [p for p in pfade if p.exists() or p.is_symlink()]
        if not da:
            zeilen.append((AUS, was, "nichts vorhanden"))
            continue
        gruende = [f"{p.name}: {g}" for p in da if (g := _weg(p))]
        zeilen.append((FEHLT, was, "liess sich nicht löschen (" + "; ".join(gruende) + ")") if gruende else (GUT, was, "gelöscht"))
        gelungen = gelungen and not gruende
    if WINDOWS:     # die Einrichtung hat dem Konto gesagt, wo das Python des Gateways liegt. Der Ort verschwindet jetzt
        wert = einrichten.benutzervariable("OSINT_PYTHON")
        if wert and innerhalb(Path(wert), projekt):
            code, _ = einrichten.lauf(["reg", "delete", r"HKCU\Environment", "/v", "OSINT_PYTHON", "/f"], 30)
            zeilen.append((GUT, "Umgebungsvariable OSINT_PYTHON", "entfernt") if code == 0 else
                          (FEHLT, "Umgebungsvariable OSINT_PYTHON", r"liess sich nicht entfernen. Von Hand: reg delete HKCU\Environment /v OSINT_PYTHON /f"))
            gelungen = gelungen and code == 0
    return zeilen, gelungen


# Der Helfer: ein eigenes kleines Programm, das ausserhalb des Projekts liegt und läuft. Es wartet, bis der Prozess beendet ist,
# der es gestartet hat, prüft den Ordner noch einmal und entfernt ihn dann. Was es tat, hängt es an den Bericht.
HELFER = r'''
"""Entfernt den Projektordner des OSINT-Ermittlungsarbeitsplatzes, sobald das Programm beendet ist, das diesen Helfer
gestartet hat. Gestartet von tools/loeschen.py, aus einer Kopie ausserhalb des Projekts."""
import json, os, shutil, stat, sys, threading, time
from pathlib import Path

a = json.loads(sys.argv[1])
ordner, bericht = Path(a["ordner"]), Path(a["bericht"])
selbst = Path(__file__).resolve()


def beendet(sekunden):
    """Wartet, bis das Programm beendet ist, das diesen Helfer gestartet hat. Zwischen beiden liegt eine Leitung, an der
    nie etwas kommt: Endet das Programm, schliesst das System sie, auf jedem System gleich. Das gilt auch für einen
    Prozess, der zwar beendet, aber noch nicht abgeräumt ist. Gibt zurück, ob das Ende in der Frist kam."""
    fertig = threading.Event()

    def lesen():
        try:
            while sys.stdin.buffer.read(4096):
                pass
        except (OSError, ValueError, AttributeError):
            pass
        fertig.set()
    threading.Thread(target=lesen, daemon=True).start()
    return fertig.wait(sekunden)


def drin(pfad, in_ordner):
    try:
        Path(pfad).resolve().relative_to(Path(in_ordner).resolve())
    except ValueError:
        return False
    return True


def hindernis():
    """Dieselbe Prüfung wie vor dem Start, unmittelbar vor dem Löschen: Ist das wirklich der Projektordner, und nichts Fremdes?"""
    if not ordner.is_absolute() or ordner != ordner.resolve():
        return "kein aufgelöster, vollständiger Pfad"
    if not ordner.is_dir() or ordner.is_symlink():
        return "kein Ordner"
    if ordner.parent == ordner:
        return "die Wurzel des Dateisystems"
    fehlend = [k for k in a["kennzeichen"] if not (ordner / k).is_file()]
    if fehlend:
        return "nicht der Projektordner dieses Arbeitsplatzes: " + ", ".join(fehlend) + " fehlt"
    if drin(Path.home(), ordner):
        return "der Benutzerordner liegt darin"
    if drin(bericht, ordner) or drin(selbst, ordner):
        return "der Bericht oder dieses Programm liegt darin"
    return ""


def schreiben(zeile):
    try:
        with open(bericht, "a", encoding="utf-8", newline="\n") as f:
            f.write(zeile + "\n")
    except OSError:
        pass


def verweis(pfad):
    """Ein symbolischer Link oder, unter Windows, eine Verknüpfung des Dateisystems (Junction)."""
    try:
        st = os.lstat(pfad)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                                            and getattr(st, "st_reparse_tag", 0) == getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", -1))


def nochmal(funktion, ziel, fehler):
    """Schreibgeschützt ist kein Hindernis (Rohdaten sind es mit Absicht): Rechte öffnen und noch einmal versuchen. Nur beim
    Entfernen selbst, und nie durch einen Verweis hindurch: Sein Ziel liegt vielleicht ausserhalb und gehört nicht dazu."""
    if funktion not in (os.unlink, os.rmdir) or verweis(ziel):
        raise fehler[1] if isinstance(fehler, tuple) else fehler
    os.chmod(ziel, stat.S_IRWXU if os.path.isdir(ziel) else stat.S_IWRITE | stat.S_IREAD)
    funktion(ziel)


von_hand = ('rmdir /s /q "' + str(ordner) + '"') if os.name == "nt" else ("rm -rf '" + str(ordner) + "'")


def entfernen():
    """Prüft, wartet, prüft noch einmal und entfernt dann den Ordner. Gibt die Zeile für den Bericht zurück."""
    frist = float(a.get("warten", 120))
    grund = hindernis()
    if grund:
        return "NICHT ENTFERNT  Projektordner " + str(ordner) + ": " + grund + ". Es wurde nichts angefasst."
    if not beendet(frist):
        # Das Programm läuft noch: Unter ihm wird nichts weggeräumt. Die Daten sind schon gelöscht, es bleibt der Code
        return ("NICHT ENTFERNT  Projektordner " + str(ordner) + ": Das Programm, das gelöscht hat, lief nach " + str(int(frist))
                + " Sekunden noch. Es beenden und den Ordner von Hand entfernen: " + von_hand)
    grund = hindernis()
    if grund:
        return "NICHT ENTFERNT  Projektordner " + str(ordner) + ": " + grund + ". Es wurde nichts angefasst."
    letzter = ""
    for _versuch in range(int(a.get("versuche", 15))):     # unter Windows gibt ein eben beendeter Prozess seine Dateien nicht sofort frei
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(ordner, onexc=nochmal)
            else:
                shutil.rmtree(ordner, onerror=nochmal)
        except OSError as e:
            letzter = type(e).__name__ + ": " + str(e.strerror or e)
        if not ordner.exists():
            break
        time.sleep(1)
    if not ordner.exists():
        return "ENTFERNT        Projektordner " + str(ordner) + " (mit Code, Einstellungen und Python-Umgebung)"
    rest = sum(1 for _ in ordner.rglob("*"))
    return ("NICHT VOLLSTÄNDIG  Projektordner " + str(ordner) + ": " + str(rest) + " Einträge bleiben (" + (letzter or "in Gebrauch")
            + "). Steht noch ein Terminal in dem Ordner? Dann den Ordner verlassen und von Hand entfernen: " + von_hand)


try:
    ergebnis = entfernen()
except Exception as e:      # was auch immer geschah: Der Bericht sagt es, statt ohne seine letzte Zeile zu enden
    ergebnis = ("NICHT VOLLSTÄNDIG  Projektordner " + str(ordner) + ": unerwarteter Fehler (" + type(e).__name__ + ": " + str(e)
                + "). Nachsehen, ob der Ordner noch da ist, und ihn von Hand entfernen: " + von_hand)
schreiben(ergebnis)
schreiben("Ende des Berichts.")
try:
    selbst.unlink()
except OSError:
    pass
# Nicht über das gewöhnliche Ende von Python: Wartet der Thread noch an der Leitung (die Frist lief ab), endete das Aufräumen
# des Interpreters in einem Absturz, mit Absturzmeldung des Systems
os._exit(0)
'''


def basis_python() -> str:
    """Das Python, mit dem der Helfer läuft: nie das der Python-Umgebung im Projekt, denn die wird entfernt."""
    return getattr(sys, "_base_executable", None) or sys.executable


LAUFENDE_HELFER: list[subprocess.Popen] = []       # solange dieses Programm läuft, bleibt die Leitung zu jedem Helfer offen


def helfer_starten(projekt: Path, bericht: Path, warten: float = 120, versuche: int = 15) -> subprocess.Popen:
    """Startet den Helfer, der den Projektordner entfernt, sobald dieses Programm beendet ist. Woran er das merkt: An seiner
    Eingabe hängt eine Leitung zu diesem Programm, an der nie etwas kommt. Endet das Programm, schliesst das System sie.
    Das trägt auf jedem System und auch dann, wenn der beendete Prozess noch nicht abgeräumt ist.
    Löst Fehler aus, wenn der Ordner nicht der Projektordner ist. Gibt den Prozess des Helfers zurück."""
    grund = nicht_loeschbar(projekt, bericht)
    if grund:
        raise Fehler(f"Der Projektordner wird nicht entfernt: {grund}")
    griff, name = tempfile.mkstemp(prefix="osint-loeschen-", suffix=".py")
    with os.fdopen(griff, "w", encoding="utf-8", newline="\n") as f:
        f.write(HELFER)
    if innerhalb(Path(name), projekt):
        Path(name).unlink()
        raise Fehler("Der temporäre Ordner des Systems liegt im Projektordner. So lässt er sich nicht von selbst entfernen.")
    angaben = {"ordner": str(projekt), "bericht": str(bericht), "kennzeichen": list(KENNZEICHEN), "warten": warten, "versuche": versuche}
    # Nur, was ein Python zum Laufen braucht: Schlüssel aus der Umgebung dieses Terminals erbt der Helfer nicht
    umgebung = {n: w for n, w in os.environ.items() if n.upper() in ("PATH", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
                                                                     "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "COMSPEC", "PATHEXT")}
    mehr = {"creationflags": 0x00000008 | 0x00000200} if WINDOWS else {"start_new_session": True}      # losgelöst vom Terminal: Er überlebt dessen Ende
    helfer = subprocess.Popen([basis_python(), "-I", name, json.dumps(angaben)], cwd=tempfile.gettempdir(), env=umgebung, stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, **mehr)
    LAUFENDE_HELFER.append(helfer)      # nicht loslassen: Räumte Python das Objekt weg, schlösse sich die Leitung zu früh
    return helfer


def _berichtskopf(zeit: datetime, projekt: Path, weg: str) -> list[str]:
    return ["Alles löschen · OSINT-Ermittlungsarbeitsplatz", f"Zeit: {zeit.astimezone().isoformat(timespec='seconds')}", f"Projektordner: {projekt}",
            f"Ausgelöst: {weg}", ""]


def bericht_anlegen(datei: Path, zeit: datetime, projekt: Path, weg: str) -> None:
    """Legt den Bericht an, bevor irgendetwas geschieht: Nach dem Löschen ist er der einzige Beleg dafür. Lässt er sich nicht
    schreiben, wird nicht gelöscht. Unter Linux und macOS von Anfang an nur für das eigene Konto lesbar."""
    try:
        ordner_anlegen(datei.parent)
        # O_BINARY: Unter Windows machte der Textmodus des Systems sonst aus jedem Zeilenende zwei Zeichen
        griff = os.open(datei, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(griff, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(_berichtskopf(zeit, projekt, weg) + ["Begonnen. Gelöscht ist noch nichts. Dieser Bericht wird am Schluss vervollständigt."]) + "\n")
    except FileExistsError as e:
        raise Fehler(f"{datei} gibt es schon. Bitte in einer Sekunde noch einmal versuchen.") from e
    except OSError as e:
        raise Fehler(f"Der Bericht liess sich nicht anlegen ({datei}): {e}") from e


def bericht_schreiben(datei: Path, zeit: datetime, projekt: Path, weg: str, zeilen: list[Zeile], sicherung: dict | None, rest: list[tuple[str, str]]) -> None:
    """Der Bericht im Sicherungsordner: was gelöscht wurde, wo die Sicherung liegt, was bleibt. Den letzten Schritt hängt der Helfer an."""
    wort = {GUT: "ERLEDIGT", FEHLT: "NICHT ERLEDIGT"}
    text = _berichtskopf(zeit, projekt, weg)
    if sicherung:
        text += [f"Sicherung der Fallakten: {sicherung['archiv']}", f"  SHA-256 des Archivs: {sicherung['sha256']}",
                 f"  {sicherung['dateien']} Dateien, {groesse(sicherung['bytes'])}, Fälle: {', '.join(sicherung['faelle']) or '(lose Dateien)'}", ""]
    else:
        text += ["Sicherung der Fallakten: keine. Ausser dem Musterfall gab es weder Fallakten noch Sitzungsprotokolle.", ""]
    text += [f"{wort.get(zeichen, 'HINWEIS'):<15} {was}: {wie}" for zeichen, was, wie in zeilen]
    text += ["", "Was bleibt:"] + [f"  {was}: {wo}" for was, wo in rest] + ["", "Letzter Schritt (der Projektordner selbst):"]
    plattform.text_schreiben(datei, "\n".join(text) + "\n")      # die Datei gibt es schon (bericht_anlegen): Ihre Rechte bleiben


def ausfuehren(projekt: Path = PROJEKT, sicherung: str | os.PathLike | None = None, *, weg: str = "Terminal", aus_oberflaeche: bool = False,
               zeit: datetime | None = None, ablage: str | os.PathLike | None = None) -> dict:
    """Löscht den Arbeitsplatz. Reihenfolge: den Bericht anlegen. Beenden, was läuft. Fallakten sichern und die Sicherung
    prüfen. Container und Abbilder entfernen. Schlüssel, Fallakten und Einstellungen löschen. Den Helfer starten, der den
    Projektordner entfernt.
    Löst Fehler aus, solange noch nichts gelöscht ist (Hindernis, Bericht oder Sicherung gescheitert). Danach berichtet jede Zeile für sich.
    `aus_oberflaeche`: Die Oberfläche ruft selbst auf. Sie hat ihre Ermittlungen schon angehalten und beendet sich danach.
    Weitere Oberflächen desselben Projekts werden in beiden Fällen beendet, die aufrufende nie. `ablage`: die Ablage der
    aufrufenden Oberfläche, für die Angabe, was bleibt."""
    zeit = zeit or datetime.now().astimezone()
    projekt = Path(projekt).resolve()       # der Ordner selbst, nicht ein Verweis auf ihn
    grund = hindernis(projekt, ablageort(ablage))
    if grund:
        raise Fehler(grund)
    ordner = sicherungsordner(sicherung, projekt)
    bericht = ordner / f"bericht-{zeit.strftime('%Y%m%d-%H%M%S')}.txt"
    bericht_anlegen(bericht, zeit, projekt, weg)
    zeilen: list[Zeile] = []
    gelungen = True
    # 1. Beenden, was läuft: Eine Oberfläche hält dabei ihre Ermittlungen an. Erst danach steht fest, was in den Fallakten steht
    beendet = dienste.oberflaeche_beenden()
    zeilen += beendet or ([] if aus_oberflaeche else [(AUS, "Oberfläche", "läuft nicht")])
    gelungen = gelungen and all(zeichen != FEHLT for zeichen, _, _ in beendet)
    # 2. Sichern und prüfen. Scheitert das, endet hier alles: Gelöscht ist noch nichts, und der angefangene Bericht verschwindet wieder
    try:
        gesichert = sichern(projekt, ordner, zeit, weg)
    except Fehler:
        with contextlib.suppress(OSError):
            bericht.unlink()
        raise
    zeilen.append((GUT, "Fallakten gesichert", f"{gesichert['archiv']} ({gesichert['dateien']} Dateien, {groesse(gesichert['bytes'])}, geprüft)") if gesichert else
                  (AUS, "Fallakten gesichert", "nichts zu sichern: Ausser dem Musterfall gab es weder Fallakten noch Sitzungsprotokolle"))
    # 3. Container und Abbilder, dann die Daten: Schlüssel zuerst
    entfernt, ok = docker_entfernen(projekt, ordner, zeit)
    zeilen += entfernt
    gelungen = gelungen and ok
    geloescht, ok = daten_loeschen(projekt)
    zeilen += geloescht
    gelungen = gelungen and ok
    with contextlib.suppress(OSError):
        plattform.baum_loeschen(einrichten.LOGS)        # die Protokolle der Einrichtung im temporären Ordner des Systems
    rest = bleibt(ordner, ablage)
    try:
        bericht_schreiben(bericht, zeit, projekt, weg, zeilen, gesichert, rest)
    except OSError as e:        # gelöscht ist schon: Jetzt wird gemeldet, nicht mehr abgebrochen
        gelungen = False
        zeilen.append((FEHLT, "Bericht", f"liess sich nicht vervollständigen ({bericht}): {e}"))
    # 4. Der Ordner selbst: Das übernimmt der Helfer, sobald dieser Prozess beendet ist
    try:
        helfer_starten(projekt, bericht)
        zeilen.append((GUT, "Projektordner", "wird entfernt, sobald dieses Programm beendet ist (wenige Sekunden). Der Bericht hält das Ergebnis fest"))
    except (Fehler, OSError) as e:
        gelungen = False
        befehl = f'rmdir /s /q "{projekt}"' if WINDOWS else f"rm -rf '{projekt}'"
        zeilen.append((FEHLT, "Projektordner", f"liess sich nicht von selbst entfernen ({e}). Von Hand: {befehl}"))
        with contextlib.suppress(OSError), open(bericht, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"NICHT ENTFERNT  Projektordner {projekt}: {e}. Von Hand: {befehl}\nEnde des Berichts.\n")
    return {"gelungen": gelungen, "zeilen": zeilen, "sicherung": gesichert, "bericht": str(bericht), "ordner": str(ordner), "bleibt": rest}


# --------------------------------------------------------------------------- Aufruf

def main(argv: list[str]) -> int:
    hilfe = argv[:1] in (["-h"], ["--help"], ["--hilfe"])
    sicherung = None
    if "--sicherung" in argv:
        i = argv.index("--sicherung")
        if i + 1 >= len(argv):
            print(__doc__)
            return 2
        sicherung = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if hilfe or len(argv) > 1 or argv[:1] not in ([], ["plan"], ["alles"]):
        print(__doc__)
        return 0 if hilfe else 2
    ui = einrichten.ui
    wunsch = argv[0] if argv else "plan"
    p = plan(PROJEKT, sicherung)
    if wunsch == "plan":
        ui.kopf("OSINT-Ermittlungsarbeitsplatz · Was «Alles löschen» täte", "Diese Anzeige ändert nichts.")
        for zeichen, was, wie in plan_zeilen(p):
            ui.zeile(zeichen, was, wie)
        ui.paare("Was bleibt", p["bleibt"])
        if p["hindernis"]:
            ui.zeile(FEHLT, "So geht es nicht", p["hindernis"])
        ui.paare("Löschen", [("Alles löschen", f"{PY} tools/loeschen.py alles"), ("Nur abschalten, nichts löschen", f"{PY} tools/dienste.py aus")])
        return 0
    if not plattform.terminal(sys.stdin, sys.stdout) or os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_ENTRYPOINT"):
        print("FEHLER: Den Arbeitsplatz löschen entscheidet ein Mensch am Terminal. Ohne Terminal und aus Claude Code heraus "
              f"läuft nur die Anzeige: {PY} tools/loeschen.py", file=sys.stderr)
        return 2
    ui.kopf("OSINT-Ermittlungsarbeitsplatz · Alles löschen", "Der Arbeitsplatz wird von diesem Rechner entfernt. Das lässt sich nicht rückgängig machen.")
    for zeichen, was, wie in plan_zeilen(p):
        ui.zeile(zeichen, was, wie)
    ui.paare("Was bleibt", p["bleibt"])
    if p["hindernis"]:
        ui.zeile(FEHLT, "So geht es nicht", p["hindernis"])
        return 2
    print(f"\n  Zur Bestätigung den Namen des Projektordners eintippen: {p['name']}\n  Alles andere bricht ab, und nichts wird geändert.")
    try:
        antwort = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        antwort = ""
    if antwort != p["name"]:
        print("\n  Abgebrochen. Nichts wurde geändert.")
        return 2
    try:
        r = ausfuehren(PROJEKT, sicherung, weg="Terminal")
    except Fehler as e:
        print(f"\n  FEHLER: {e}\n  Gelöscht wurde nichts.", file=sys.stderr)
        return 2
    print()
    for zeichen, was, wie in r["zeilen"]:
        ui.zeile(zeichen, was, wie)
    ui.paare("Danach", [("Bericht", r["bericht"]), ("Dieses Terminal", "steht noch im Projektordner. Bitte in einen anderen Ordner wechseln: cd ..")])
    return 0 if r["gelungen"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
